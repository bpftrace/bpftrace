class Parent {
  private:
    int a;
  protected:
    int b;
  public:
    int c;
    int d; // Shadowed by Child::d, but should be reachable with a cast

  Parent(int a, int b, int c, int d) : a(a), b(b), c(c), d(d) {}
};

class Child : public Parent {
  public:
    int d;
    int e;
    int f;

  Child(int a, int b, int c, int d, int e, int f) : Parent(a, b, c, d), d(d + 1), e(e), f(f) {}
};

int func_1(Child &c, Parent &p __attribute__((unused)))
{
  return dynamic_cast<Parent&>(c).d;
}

int main(void)
{
  Parent p{1, 2, 3, 4};
  Child c{1, 2, 3, 4, 5, 6};
  func_1(c, p);
  return 0;
}
