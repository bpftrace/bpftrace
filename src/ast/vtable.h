#pragma once

#include <stdexcept>
#include <typeindex>
#include <typeinfo>
#include <unordered_map>

namespace bpftrace {
namespace ast {

class Node;

/**
  Dynamic dispatch implementation for AST Nodes

  This implement custom virtual dispatch for AST iteration. The benefit over
  double dispatch is that we can control the passed arguments and return value
  which is hard to do with double dispatch, a different Accept() would have to
  be implement for every new signature needed. Which makes tree modification
  harder to implement.

  The downside is that this way of dispatching is significantly slower.

  The core is a map of Types (using std::type_index) to FunctionPointers. A bit
  of templating makes it reusable for different types of arguments and return
  types.

  The current implementation only supports dispatching on Nodes and only support
  one argument, a Visitor. But this can by extended with some template magic.

  \code
  VTable<std::string, MyVisitor> namer;
  namer.set<Integer>([](Node &n, MyVisitor *V){ return "int"; };
  namer.set<String>([](Node &n, MyVisitor *V){ return "string"; };

  Node * i = Integer();
  Node * s = String();
  MyVisitor visitor; // unused

  std::cout << namer(i, visitor); // outputs: "int"
  std::cout << namer(s, visitor); // outputs: "string"
  \endcode

  \tparam R the return type
  \tparam D type to dispatch on
  \tparam V visitor type
*/
template <typename R, typename D, typename V>
class VTable
{
private:
  typedef R (*FuncPtr)(D &, V *);
  std::unordered_map<std::type_index, FuncPtr> vtable_;

public:
  /**
     Set dispatch for type NT to function F
  */
  template <typename NT>
  void set(FuncPtr F)
  {
    vtable_[std::type_index(typeid(NT))] = F;
  }

  /**
     Dispatch based on the type of n.

     If no entry for type n exists an exception is raised.
  */
  R operator()(D &n, V *v)
  {
    auto itr = vtable_.find(std::type_index(typeid(n)));
    if (itr != vtable_.end())
      return (*itr->second)(n, v);

    throw std::runtime_error(std::string("Unknown node: ") + typeid(n).name());
  }
};

} // namespace ast
} // namespace bpftrace
