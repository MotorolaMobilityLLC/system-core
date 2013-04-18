/* BEGIN Motorola, rknize2, 2013-Apr-16, IKJBXLINE-3829 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

extern int setxattr(const char *, const char *, const void *, size_t, int);

static int usage(const char *s)
{
    fprintf(stderr, "Usage: %s -n name -v value pathname\n", s);
    fprintf(stderr, "  -n name      name of the extended attribute to set\n");
    fprintf(stderr, "  -v value     new value of the attribute\n");
    fprintf(stderr, "  -h           display this help and exit\n");

    exit(10);
}

int setfattr_main(int argc, char **argv)
{
    int i;
    char *name = NULL;
    char *valuestr = NULL;
    unsigned long long value = 0;
    size_t valuelen = 0;

    for (;;) {
        int ret;

        ret = getopt(argc, argv, "hn:v:");

        if (ret < 0)
            break;

        switch(ret) {
            case 'h':
                usage(argv[0]);
                break;
            case 'n':
                name = optarg;
                break;
            case 'v':
                valuestr = optarg;
                break;
        }
    }

    if (!name || !valuestr || optind == argc)
        usage(argv[0]);

    /*
     * We are being super lazy here, since setxattr can take an arbitrary
     * amount of binary data.  We assume that the value is numerical and
     * not longer than 8 bytes.  strtoull() detects the numeric base from
     * the string prefix (0x for hexidecimal or 0 for octal).  We also
     * ignore endianness problems because it all works out fine on little
     * endian.  Hey, it's toolbox!
     */
    value = strtoull(valuestr, NULL, 0);
    while ((value >> (valuelen * 8)))
        valuelen++;

    for (i = optind ; i < argc ; i++)
        setxattr(argv[i], name, &value, valuelen, 0);

    return 0;
}

/* END Motorola, IKJBXLINE-3829 */
