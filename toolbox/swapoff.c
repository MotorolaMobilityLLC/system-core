#include <stdio.h>
#include <unistd.h>
#include <sys/swap.h>

int swapoff_main(int argc, char **argv)
{
    int err = 0;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <filename>\n", argv[0]);
        return -EINVAL;
    }

    err = swapoff(argv[1]);
    if (err) {
        fprintf(stderr, "swapoff failed for %s: %s\n", argv[1], strerror(errno));
    }

    return err;
}
