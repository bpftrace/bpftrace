#pragma once

extern "C"
{
  void __attribute__((noinline)) BEGIN_trigger() { asm (""); }
  void __attribute__((noinline)) END_trigger() { asm (""); }
}
