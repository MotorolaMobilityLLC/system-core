/* BEGIN Motorola, a22381, 07-07-2017 IKKRNBSP-4554 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <string.h>

extern int getxattr(const char *, const char *, const void *, size_t);

static int usage(const char *s)
{
    fprintf(stderr, "Usage: %s -n name pathname\n", s);
    fprintf(stderr, "  -n name      name of the extended attribute to get\n");
    fprintf(stderr, "  -h           display this help and exit\n");

    exit(10);
}

int getfattr_main(int argc, char **argv)
{
    int size;
    char *name = NULL, *path = NULL;
    char value[32];

    for (;;) {
        int ret;

        ret = getopt(argc, argv, "n:h");

        if (ret < 0)
            break;

        switch(ret) {
            case 'h':
                usage(argv[0]);
                break;
            case 'n':
                name = optarg;
                break;
        }
    }

    if (!name || optind == argc || !argv[optind])
        usage(argv[0]);

    path = argv[optind];
    size = getxattr(path, name, value, sizeof(value));
    if (size < 0)
        fprintf(stderr, "error reading %s of %s\n", name, path);
    else {
        value[size] = 0;
        fprintf(stderr, "%s of %s: %s\n", name, path, value);
    }

    return 0;
}

/* END Motorola, IKKRNBSP-4554 */
