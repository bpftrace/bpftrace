#pragma once

#include <atomic>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <variant>
#include <vector>

#include "util/error.h"

namespace bpftrace {
namespace ast {

// Passes operate on the ASTContext, but the actual pass plumbing is orthogonal
// to the ASTContext. This is passed as an reference to the actual function.
class ASTContext;

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

  // TypeId is a class which, when specialized, returns the type_id. We have a
  // partial specialization of this class which overrides `type_ids` for a
  // tuple, which is used below to enumerate and unpack outputs in this case.
  template <typename T>
  struct TypeId {
    constexpr static int is_tuple = 0;
    static int type_id()
    {
      // Register by dispatching via the vtable for the passed type. This is
      // all going to be devirtualized most likely, but this does enforce that
      // the class passed at least implements the `name()` method, which is
      // really all we can ask for.
      //
      // Note that the `static` here is doing all the heavy lifting; this is
      // ensuring that the compiler is linking this symbol at most once, and it
      // will be initialized at most once, giving us a unique identifier for
      // this particular type.
      static int type_id = PassContext::add_type(T::type_name());
      return type_id;
    }
    static std::vector<int> type_ids()
    {
      return { type_id() };
    }
  };
  template <typename T>
  struct TypeId<std::reference_wrapper<T>> {
    constexpr static int is_tuple = 0;
    static int type_id()
    {
      return TypeId<T>::type_id();
    }
    static std::vector<int> type_ids()
    {
      return TypeId<T>::type_ids();
    }
  };
  template <typename... Args>
  struct TypeId<std::tuple<Args...>> {
    constexpr static int is_tuple = 1;
    static int type_id()
    {
      // This would only occur if the code below attempts to expand tuples
      // recursively, or someone has specified a tuple of tuples, e.g.
      // std::tuple<std::tuple<...>>. Hopefully this is somewhat easy to
      // track down by injecting failure and a BUG at this location.
      fail(add_type("tuple"));
    }
    static std::vector<int> type_ids()
    {
      return { TypeId<Args>::type_id()... };
    }
  };

  // State is an object which is the result of some specific pass.
  //
  // Passes are allowed to mutate the AST, and produce intermediate results
  // that may be consumed by other passes. Each of these results must be a
  // State, and will be immutable once it is produced.
  class State {
  public:
    virtual ~State() {};
  };

  // get fetches the given type; which must have been previously stored.
  //
  // N.B. In the future, these objects should be made immutable. Right now,
  // this is preserved so that we can pass through the `BPFTrace` object which
  // is consumed by *most* passes in a read-write fashion.
  template <typename T>
  T &get()
  {
    int type_id = TypeId<T>::type_id();
    if (state_.contains(type_id)) {
      return *static_cast<T *>(state_[type_id].get());
    } else if (extern_state_.contains(type_id)) {
      return static_cast<T &>(extern_state_.find(type_id)->second.get());
    } else {
      fail(type_id);
    }
  }

private:
  // for the failed lookup path, see above.
  [[noreturn]] static void fail(int type_id);

  // put emplaces the the value into the map; it must not exist already. In
  // general this should not be called manually, it should only be called by
  // individual passes during execution (the `run` function below).
  template <typename T>
  void put(T &&t)
  {
    int type_id = TypeId<T>::type_id();
    state_.emplace(type_id, std::make_unique(std::move(t)));
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

  // Will register the given type id and the name, which is resolvable using
  // lookup_type below. This is called exclusively by `type_id` above.
  static int add_type(std::string &&type_name)
  {
    int type_id = next_type_id_++;
    type_names_[type_id] = std::move(type_name);
    return type_id;
  }

  // Returns the underlying type for this type_id. Note that the type must
  // exist, or this will have undefined behavior. This is called exclusively
  // by the pass manager, when statically checking pass types.
  static const std::string &lookup_type(int type_id)
  {
    return type_names_[type_id];
  }

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

// Pass is a arbitrary pass.
//
// It is permitted to produce a single output, but may consume any number of
// inputs. If multiple outputs are required, it may produce a tuple, which will
// be automatically inserted into the pass context.
//
// Note that the inputs and outputs should be statically verified by the pass
// manager when the pass is registered.
//
// In general, this type should be constructed automatically, e.g.:
//
//    Pass CreateFooPass() {
//      return Pass::create("mypass", [](ASTContext &ctx, MyInput &input) {
//        return MyOutput();
//      });
//    }
//
// Pass functions must already return an `ErrorOr` instance.
class Pass {
public:
  Pass(const Pass &) = delete;
  Pass(Pass &&) = default;
  Pass &operator=(const Pass &) = delete;
  Pass &operator=(Pass &&) = default;

  // create creates the given pass.
  //
  // The passed function must accept an ASTContext& as well as an arbitrary set
  // of inputs. Note that the `type_identity_t` basically makes it so this
  // template will always match, and the types are resolved later.
  //
  // For convenience, this template is set up to match against lambdas, and the
  // partial specialization that is used below will only work with lambdas.
  // Furthermore, the expansion will only work with `ErrorOr<T>` or `Error`
  // types, so the lambda will need to return one of those.  Otherwise, the
  // first argument must be the ASTContext&, but all other arguments will be
  // automatically plumbed.
  template <typename Return, typename... Inputs>
  static Pass create(
      const std::string &name,
      std::function<ErrorOr<Return>(ASTContext &, Inputs &...)> fn)
  {
    // N.B. Inputs does not allow tuple matching, while output potentially does
    // a single level of tuple expansion. See `PassContext::TypeId`.
    std::vector<int> inputs = { PassContext::TypeId<Inputs>::type_id()... };
    std::vector<int> outputs;
    if constexpr (!std::is_same_v<success, Return>) {
      outputs = PassContext::TypeId<Return>::type_ids();
    }

    return Pass(name,
                std::move(inputs),
                std::move(outputs),
                [fn](ASTContext &ast, PassContext &ctx) -> Error {
                  // Extract a tuple of all input parameters, apply the function
                  // and set the result. The partial specializations below do
                  // all the lifting.
                  auto args = std::make_tuple(std::ref(ast),
                                              std::ref(ctx.get<Inputs>())...);

                  // Call the given function with both the given AST as well as
                  // all the fetched input arguments.
                  auto result = std::apply(fn, args);
                  if (!result) {
                    return result.takeError();
                  }
                  if constexpr (std::is_same_v<Return, success>) {
                    return success();
                  } else {
                    if constexpr (PassContext::TypeId<Return>::is_tuple) {
                      // This does not invoke the eval recursively because only
                      // a single level of tuples are supported. All values must
                      // be moved, we do not support a tuple of references.
                      std::apply([&ctx](auto &&v) { ctx.put(std::move(v)); },
                                 std::move(*result));
                    } else {
                      if constexpr (std::is_reference_v<decltype(*result)>) {
                        // Add the external reference.
                        ctx.put(*result);
                      } else {
                        // Just move the result.
                        ctx.put(std::move(*result));
                      }
                    }
                    return success();
                  }
                });
  }
  // Help catch basic errors.
  template <typename Return, typename... Inputs>
  static Pass create(const std::string &name,
                     std::function<Return(Inputs...)> fn)
  {
    // We need to ensure that the arguments are references, but can otherwise
    // simply wrap this in something that returns success on the user's behalf.
    static_assert((std::is_reference_v<Inputs> && ...),
                  "all arguments must be references");
    if constexpr (std::is_same_v<Return, void>) {
      return create(name, [fn](Inputs... inputs) -> Error {
        fn(inputs...);
        return success();
      });
    } else {
      return create(name, [fn](Inputs... inputs) -> ErrorOr<Return> {
        return fn(inputs...);
      });
    }
  }
  // Accept a lambda construct and wrap in a std::function. This is mostly
  // about convincing the type inference system to match against the above,
  // since a lambda is not strictly a std::function. If the lambda is not
  // well-formed (e.g. does not return `ErrorOr`, etc.) then this will still
  // fail to instantiate.
  template <typename Func>
  static Pass create(const std::string &name, Func func)
  {
    std::function fn(func);
    return create(name, fn);
  }

  // run executes the pass.
  //
  // Before we reach this point, the pass manager will have statically verified
  // that all outputs are available and that get<Type> will succeed.
  Error run(ASTContext &ast, PassContext &ctx) const
  {
    return fn_(ast, ctx);
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
  // N.B. external construction is done via `create`.
  using Fn = std::function<Error(ASTContext &ast, PassContext &ctx)>;
  Pass(const std::string &name,
       std::vector<int> &&inputs,
       std::vector<int> &&outputs,
       Fn fn)
      : name_(name),
        inputs_(std::move(inputs)),
        outputs_(std::move(outputs)),
        fn_(fn)
  {
  }

  std::string name_;
  std::vector<int> inputs_;
  std::vector<int> outputs_;
  Fn fn_;
};

// PassManager hold passes in sequence.
//
// The PassManager is responsible for verifying the inputs and outputs of the
// passes ahead of time, so that the produced graph is sound.
class PassManager {
public:
  // registers the given pass, adding to the current list.
  PassManager& add(Pass &&pass);

  // foreach executes the given function on every pass.
  //
  // The first pass to encounter errors will result in execution stopping. All
  // warnings from all passes are collected.
  Error foreach(std::function<Error(const Pass &)> fn);

  // put adds a pass which always pushes the given static data.
  template <typename T>
  PassManager& put(T &t)
  {
    return add(Pass::create(T::type_name(), [&t]([[maybe_unused]] ASTContext &ast) {
      return std::ref(t);
    }));
  }

  // run all registered passes.
  //
  // This is a canonical example of how to use `foreach` above, in many other
  // cases a direct call will be suitable.
  ErrorOr<PassContext> run(ASTContext &ast)
  {
    PassContext ctx;
    auto err = foreach([&](auto &pass) {
      if (!ast.diagnostics().ok())
        return success(); // Skip the pass.
      return pass.run(ast, ctx);
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

} // namespace ast
} // namespace bpftrace
