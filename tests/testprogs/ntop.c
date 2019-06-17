#include <stdio.h>
#include <arpa/inet.h>

void test_ntop(char ipv4[4], char ipv6[16]) { }

int main(int argc, char **argv)
{
  // 127.0.0.1
  char ipv4[4] = { 127, 0, 0, 1 };
  // ffee:ffee:ddcc:ddcc:bbaa:bbaa:c0a8:1
  char ipv6[16] = {
    255, 238,
    255, 238,
    221, 204,
    221, 204,
    187, 170,
    187, 170,
    192, 168,
    0, 1
  };
  test_ntop(ipv4, ipv6);

  // Uncomment to debug this program
  // char buf4[INET_ADDRSTRLEN];
  // char buf6[INET6_ADDRSTRLEN];
  // inet_ntop(AF_INET, ipv4, buf4, INET_ADDRSTRLEN);
  // inet_ntop(AF_INET6, ipv6, buf6, INET6_ADDRSTRLEN);
  // printf("%s\n%s\n", buf4, buf6);

  return 0;
}
