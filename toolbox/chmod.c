#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <sys/limits.h>
#include <sys/stat.h>

#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <getopt.h>

void recurse_chmod(char* path, int mode, unsigned int flag)
{
    struct dirent *dp;
    DIR *dir = opendir(path);
    int fd = 0;
    if (dir == NULL) {
        // not a directory, carry on
        return;
    }
    int maxpathlen = sizeof(char)*PATH_MAX;
    char *subpath = malloc(maxpathlen);
    int pathlen = strlen(path);

    while ((dp = readdir(dir)) != NULL) {
        if (strcmp(dp->d_name, ".") == 0 ||
            strcmp(dp->d_name, "..") == 0) continue;

        if (strlen(dp->d_name) + pathlen + 2/*NUL and slash*/ > PATH_MAX) {
            fprintf(stderr, "Invalid path specified: too long\n");
            exit(1);
        }

        strlcpy(subpath, path, maxpathlen);
        strlcat(subpath, "/", maxpathlen);
        strlcat(subpath, dp->d_name, maxpathlen);

        if(((fd = open(subpath, flag|O_RDONLY)) != -1) || ((fd = open(subpath, flag|O_WRONLY)) != -1)) {
            if (fchmod(fd, mode) < 0){
                fprintf(stderr, "Unable to chmod %s: %s\n", subpath, strerror(errno));
                close(fd);
                exit(1);
            }
            close(fd);
        } else {
            fprintf(stderr, "Unable to open %s: %s\n", subpath, strerror(errno));
            exit(1);
        }

        recurse_chmod(subpath, mode, flag);
    }
    free(subpath);
    closedir(dir);
}

static int usage()
{
    fprintf(stderr, "Usage: chmod [OPTION] <MODE> <FILE>\n");
    fprintf(stderr, "  -R, --recursive         change files and directories recursively\n");
    fprintf(stderr, "  -h, --no-dereference    do not follow symlink\n");
    fprintf(stderr, "  --help                  display this help and exit\n");

    return 10;
}

int chmod_main(int argc, char **argv)
{
    int i;
    int noFollow = 0;
    int fd = 0;
    int ch = 0;
    int recursive = 0;
    unsigned int flag =0;
    int help = 0;
    static struct option long_options[] =
        {
            {"help",       no_argument,       0, 'H'},
            {"recursive",  no_argument,       0, 'R'},
            {"no-dereference",  no_argument,  0, 'h'}
        };
    /* getopt_long stores the option index here. */
    int option_index = 0;
    while((ch = getopt_long(argc, argv, "HhR",long_options,&option_index)) != -1)
    switch(ch){
        case 'H':
            help = 1;
            break;
        case 'R':
            recursive = 1;
            break;
        case 'h':
            noFollow = 1;
            break;
        default:
            break;

    }

    if (argc < 3 || help || (recursive && argc < 4)) {
        return usage();
    }

    if (recursive) {
        argc--;
        argv++;
    }
    if (noFollow && argc < 4) {
        return usage();
    }

    if(noFollow) {
        flag = O_NOFOLLOW;
        argc--;
        argv++;
    }
    int mode = 0;
    const char* s = argv[1];
    while (*s) {
        if (*s >= '0' && *s <= '7') {
            mode = (mode<<3) | (*s-'0');
        }
        else {
            fprintf(stderr, "Bad mode\n");
            return 10;
        }
        s++;
    }

    for (i = 2; i < argc; i++) {
        if(((fd = open(argv[i], flag|O_RDONLY )) != -1)||((fd = open(argv[i], flag|O_WRONLY )) != -1)) {
            if (fchmod(fd, mode) < 0){
                fprintf(stderr, "Unable to chmod %s: %s\n", argv[i], strerror(errno));
                close(fd);
                return 10;
            }
            close(fd);
        } else {
            fprintf(stderr, "Unable to open %s: %s\n", argv[i], strerror(errno));
            return 10;
        }
        if (recursive) {
            recurse_chmod(argv[i], mode, flag);
        }
    }
    return 0;
}
