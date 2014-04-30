#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/swap.h>

void usage(char *name)
{
    fprintf(stderr, "Usage: %s [-p prio] <filename>\n"
        "        prio must be between 0 and %d\n", name, SWAP_FLAG_PRIO_MASK);
}

int parse_prio(char *prio_str)
{
    unsigned long p = strtoul(prio_str, NULL, 10);

    return (p > SWAP_FLAG_PRIO_MASK)? -1 : (int)p;
}

int swapon_main(int argc, char **argv)
{
    int err = 0;
    int flags = 0;
    int prio;

    opterr = 0;
    do {
        int c = getopt(argc, argv, "hp:");
        if (c == -1)
            break;

        switch (c) {
            case 'p':
                if (optarg != NULL)
                    prio = parse_prio(optarg);
                else
                    prio = -1;

                if (prio < 0) {
                    usage(argv[0]);
                    return -EINVAL;
                }
                flags |= SWAP_FLAG_PREFER;
                flags |= (prio << SWAP_FLAG_PRIO_SHIFT) & SWAP_FLAG_PRIO_MASK;
                break;
            case 'h':
                usage(argv[0]);
                return 0;
            case '?':
                fprintf(stderr, "unknown option: %c\n", optopt);
                return -EINVAL;
        }
    } while (1);

    if (optind != argc - 1) {
        usage(argv[0]);
        return -EINVAL;
    }

    err = swapon(argv[argc - 1], flags);
    if (err) {
        fprintf(stderr, "swapon failed for %s: %s\n", argv[argc - 1], strerror(errno));
    }

    return err;
}
