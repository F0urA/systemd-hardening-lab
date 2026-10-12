#define _GNU_SOURCE
#include <sys/prctl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
#ifdef PR_SET_PTRACER
    if (prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0) == -1)
        perror("prctl(PR_SET_PTRACER)");
#endif
    setenv("SYSTEMD_LAB_SECRET", "VICTIM_MARKER", 1);
    printf("lab-target pid=%ld\n", (long)getpid());
    fflush(stdout);
    for (;;)
        pause();
    return 0;
}
