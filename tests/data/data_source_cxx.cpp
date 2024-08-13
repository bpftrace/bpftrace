class Parent {
private:
  int a;

protected:
  int b;

public:
  int c;
  int d; // Shadowed by Child::d, but should be reachable with a cast

  Parent(int a, int b, int c, int d) : a(a), b(b), c(c), d(d)
  {
  }
};

class Child : public Parent {
public:
  int d;
  int e;
  int f;

  Child(int a, int b, int c, int d, int e, int f)
      : Parent(a, b, c, d), d(d + 1), e(e), f(f)
  {
  }
};

class GrandChild : public Child {
public:
  int g;

  GrandChild(int a, int b, int c, int d, int e, int f, int g)
      : Child(a, b, c, d, e, f), g(g)
  {
  }
};

struct Top {
  int x;
};

struct Left : public Top {
  int y;
};

struct Right : public Top {
  int z;
};

struct Bottom : public Left, public Right {
  int w;
};

struct Multi : public Parent, public Top {
  int abc;
  int &rabc;

  Multi(int a, int b, int c, int d, int e)
      : Parent{ a, b, c, d }, Top{ e }, abc{ e + 1 }, rabc{ abc }
  {
  }
};

int func_1(Child &c, Parent &p __attribute__((unused)))
{
  return dynamic_cast<Parent &>(c).d;
}

int func_2(GrandChild &lc)
{
  return dynamic_cast<Parent &>(lc).d;
}

int func_3(Multi &m, Bottom &b __attribute__((unused)))
{
  return m.abc;
}

int main()
{
  Parent p{ 1, 2, 3, 4 };
  Child c{ 1, 2, 3, 4, 5, 6 };
  func_1(c, p);

  GrandChild lc{ 1, 2, 3, 4, 5, 6, 7 };
  func_2(lc);

  Multi m{ 1, 2, 3, 4, 5 };
  Bottom b{
    {
        // Left
        { 1 }, // Left's Top
        2      // Left's y
    },
    {
        // Right
        { 3 }, // Right's Top
        4      // Right's z
    },
    5 // Bottom's w
  };
  func_3(m, b);

  return 0;
}
