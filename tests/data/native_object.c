extern void callback(int);

void call_callback(int n)
{
  for (int i = 0; i < n; i++) {
    callback(i);
  }
}
