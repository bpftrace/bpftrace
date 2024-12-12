#pragma once

#include <atomic>
#include <functional>
#include <memory>
#include <string>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <vector>

#include "util/result.h"

namespace bpftrace::ast {

// PassContext holds the intermediate state of executing passes.
//
// This class is essentially a type-erased generic constant storage.
class PassContext {
public:
  // TypeName is used as a template parameter to work around restrictions on
  // literals passes as template parameters. This is essentially a string
  // literal used to name the type.
  template <size_t N>
  struct TypeName {
    constexpr TypeName(const char (&s)[N])
    {
      std::copy_n(s, N, value);
    }
    char value[N];
    std::string str() const
    {
      return std::string(value, sizeof(value));
    }
  };

  // TypeId is a class which, when specialized, returns the type_id. This
  // works by storing a static variable for each specialization of the class,
  // which effectively memoizes an ID binding for the specific class.
  template <typename T>
  struct TypeId {
    static int type_id()
    {
      // Register by dispatching via `type_name` for the passed type. This is
      // all going to be devirtualized most likely, but this does enforce that
      // the class passed at least implements the static method, which is
      // really all we can ask for.
      //
      // Note that the `static` here is doing all the heavy lifting; this is
      // ensuring that the compiler is linking this symbol at most once, and it
      // will be initialized at most once, giving us a unique identifier for
      // this particular type.
      static_assert(std::is_base_of_v<State, T>,
                    "type must be derived from State<...>");
      static int type_id = PassContext::add_type(T::type_name());
      return type_id;
    }
  };

  // State is an object which is the result of some specific pass.
  //
  // Passes are allowed to mutate the AST, and produce intermediate results
  // that may be consumed by other passes. Each of these results must be a
  // State, and will be immutable once it is produced.
  class State {
  public:
    virtual ~State() = default;
  };

  // get fetches the given type; which must have been previously stored.
  //
  // N.B. In the future, these objects should be made immutable. Right now,
  // this is preserved so that we can pass through the `BPFTrace` object which
  // is consumed by *most* passes in a read-write fashion.
  template <typename T>
  T &get() const
  {
    int type_id = TypeId<T>::type_id();
    auto it = state_.find(type_id);
    if (it != state_.end()) {
      return *static_cast<T *>(it->second.get());
    }
    auto extern_it = extern_state_.find(type_id);
    if (extern_it != extern_state_.end()) {
      return static_cast<T &>(extern_it->second.get());
    }
    no_object_failure(type_id);
  }

  // has indicates whether the given state is present or not.
  template <typename T>
  bool has()
  {
    int type_id = TypeId<T>::type_id();
    return state_.contains(type_id) || extern_state_.contains(type_id);
  }

private:
  // for the failed lookup path, see above.
  [[noreturn]] static void no_object_failure(int type_id);

  // put emplaces the value into the map; it must not exist already. In general
  // this should not be called manually, it should only be called by individual
  // passes during execution (the `run` function below).
  template <typename T>
  void put(T &&t)
  {
    int type_id = TypeId<T>::type_id();
    state_.emplace(type_id, std::make_unique<T>(std::move(t)));
  }

  // put can also provide an external reference for the map; its lifecycle is
  // managed outside the scope of the passes. While passes can produce results
  // that are references, this should be generally discouraged (and this
  // capability should eventually be removed). Like `put`, this should not be
  // called directly and should only be called by `run`, below.
  template <typename T>
  void put(T &t)
  {
    int type_id = TypeId<T>::type_id();
    extern_state_.emplace(type_id, t);
  }

  // Will register the given type id and the name, which is resolvable via
  // the `type_names_` map. This is called exclusively by `type_id` above.
  static int add_type(std::string &&type_name)
  {
    int type_id = next_type_id_++;
    type_names_[type_id] = std::move(type_name);
    return type_id;
  }

  // Provide a short-hand to determine:
  // - Whether the context contains an `ASTContext`, and,
  // - Whether this `ASTContext` has error diagnostics.
  //
  // If both of the above are true, then false is returned. This is a
  // convenience method provided for the `PassManager` below, as passes will
  // stop when an error diagnostic has been generated.
  bool ok() const;

  static std::atomic<int> next_type_id_;
  static std::unordered_map<int, std::string> type_names_;

  std::unordered_map<int, std::unique_ptr<State>> state_;
  std::unordered_map<int, std::reference_wrapper<State>> extern_state_;

  friend class PassManager;
  friend class Pass;
};

// State is the template class used for states that may be stored in a
// PassContext. In order to consume or produce information in a given pass,
// simply override this class with the desired type.
//
// For example:
//
//   class Variables : State<"variables"> {
//     // my fields
//   };
//
// The `Variables` class can then be stored in the pass context.
template <PassContext::TypeName name>
class State : public PassContext::State {
public:
  static std::string type_name()
  {
    return name.str();
  }
};

// Pass is an arbitrary pass.
//
// It is permitted to produce either no output or a single output, which may be
// wrapped in `Result`, and may consume zero, one or multiple inputs.
//
// In general, this type should be constructed automatically, e.g.:
//
//    Pass CreateFooPass() {
//      return Pass::create("mypass", [](MyInput &input) {
//        return MyOutput();
//      });
//    }
//
// Pass functions must already return an `Result` instance.
class Pass {
public:
  Pass(const Pass &) = delete;
  Pass(Pass &&) = default;
  Pass &operator=(const Pass &) = delete;
  Pass &operator=(Pass &&) = default;

  // create is the standard Pass constructor.
  //
  // For convenience, this template is set up to match against lambdas, and the
  // partial specialization versions of `createFn` below are used to match
  // against the resulting std::function. (Of course, a std::function can also
  // be passed here and the same applies, but using a lambda is encouraged.)
  template <typename Func>
  static Pass create(const std::string &name, Func func)
  {
    std::function fn(func);
    return createFn(name, fn);
  }

  // run executes the pass.
  //
  // The inputs must be present in the context.
  Result<> run(PassContext &ctx) const
  {
    return fn_(ctx);
  }

  const std::string &name() const
  {
    return name_;
  }
  const std::vector<int> &inputs() const
  {
    return inputs_;
  }
  const std::vector<int> &outputs() const
  {
    return outputs_;
  }

private:
  template <typename Return, typename... Inputs>
  static Pass createFn(const std::string &name,
                       std::function<Result<Return>(Inputs &...)> fn)
  {
    return createImpl(name, fn);
  }
  template <typename Return, typename... Inputs>
  static Pass createFn(const std::string &name,
                       std::function<Return(Inputs...)> fn)
  {
    // We need to ensure that the arguments are references, but can otherwise
    // simply wrap this in something that returns OK on the user's behalf.
    static_assert((std::is_reference_v<Inputs> && ...),
                  "all arguments must be references");
    if constexpr (std::is_same_v<Return, void>) {
      std::function<Result<OK>(Inputs...)> wrap(
          [fn](Inputs... inputs) -> Result<OK> {
            fn(inputs...);
            return OK();
          });
      return createImpl(name, wrap);
    } else {
      std::function<Result<Return>(Inputs...)> wrap(
          [fn](Inputs... inputs) -> Result<Return> { return fn(inputs...); });
      return createImpl(name, wrap);
    }
  }
  template <typename Return, typename... Inputs>
  static Pass createImpl(const std::string &name,
                         std::function<Result<Return>(Inputs &...)> fn)
  {
    std::vector<int> inputs = { PassContext::TypeId<Inputs>::type_id()... };
    std::vector<int> outputs;
    if constexpr (!std::is_same_v<OK, Return>) {
      // Note that the Return value may be a reference, so we resolve the
      // `type_id` of the underlying type. The Input types are not references,
      // because of the way the template is constructed.
      outputs = { PassContext::TypeId<std::decay_t<Return>>::type_id() };
    }

    return Pass(
        name,
        std::move(inputs),
        std::move(outputs),
        [fn](PassContext &ctx) -> Result<> {
          // Extract a tuple of all input parameters, apply the function
          // and set the result.
          auto args = std::make_tuple(std::ref(ctx.get<Inputs>())...);
          auto result = std::apply(fn, args);
          if (!result) {
            return result.takeError();
          }
          if constexpr (std::is_same_v<Return, OK>) {
            return OK();
          } else {
            static_assert(
                std::is_base_of_v<PassContext::State, std::decay_t<Return>>,
                "return value must be derived from State<...>");
            if constexpr (std::is_reference_v<Return>) {
              // Add the external reference.
              ctx.put(*result);
            } else {
              // Just move the result.
              ctx.put(std::move(*result));
            }
            return OK();
          }
        });
  }

  // N.B. external construction is done via `create`.
  using Fn = std::function<Result<>(PassContext &ctx)>;
  Pass(std::string name,
       std::vector<int> &&inputs,
       std::vector<int> &&outputs,
       Fn fn)
      : name_(std::move(name)),
        inputs_(std::move(inputs)),
        outputs_(std::move(outputs)),
        fn_(std::move(fn))
  {
  }

  std::string name_;
  std::vector<int> inputs_;
  std::vector<int> outputs_;
  Fn fn_;
};

// PassManager holds passes in sequence.
//
// The PassManager is responsible for verifying the inputs and outputs of the
// passes ahead of time, so that the produced graph is sound.
class PassManager {
public:
  // registers the given pass, adding to the current list.
  PassManager &add(Pass &&pass);

  // registers all the given passes.
  PassManager &add(std::vector<Pass> &&passes);

  // foreach executes the given function on every pass.
  //
  // The first pass to encounter errors will result in execution stopping. All
  // warnings from all passes are collected.
  Result<> foreach(std::function<Result<>(const Pass &)> fn);

  // put adds a pass which always pushes the given static data.
  template <typename T>
  PassManager &put(T &t)
  {
    return add(Pass::create(T::type_name(), [&t]() -> T & { return t; }));
  }

  // run all registered passes.
  //
  // This is a canonical example of how to use `foreach` above, in many other
  // cases a direct call will be suitable.
  //
  // Even if the `PassContext` is returned, if an ASTContext is registered, the
  // user should ensure that no error diagnostics have been produced prior to
  // extracting state from the context. In this case, it is possible that not
  // all passes have been run, even if none produced an error.
  Result<PassContext> run()
  {
    PassContext ctx;
    auto err = foreach([&](auto &pass) -> Result<> {
      // See above: for convenience, once error diagnostics have been
      // registered, we skip all remaining passes. This helps to ensure that
      // users are not overwhelmed by diagnostics, and encodes a common pattern
      // without the need for explicit error plumbing.
      if (!ctx.ok())
        return OK();
      return pass.run(ctx);
    });
    if (!err) {
      return err.takeError();
    }
    return ctx;
  }

private:
  // The set of registered passes, in order.
  std::vector<Pass> passes_;

  // The set of registered outputs in aggregate for all other passes. Note that
  // this is filled in and automatically checked by add, above. The value of
  // this map is the index into `passes_` above.
  std::unordered_map<int, int> outputs_;
};

} // namespace bpftrace::ast
