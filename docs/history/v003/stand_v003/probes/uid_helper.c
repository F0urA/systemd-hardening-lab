#include <stdio.h>
#include <unistd.h>

int main(void)
{
    printf("ruid=%ld euid=%ld rgid=%ld egid=%ld\n",
           (long)getuid(), (long)geteuid(),
           (long)getgid(), (long)getegid());
    return 0;
}
