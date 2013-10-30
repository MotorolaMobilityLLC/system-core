#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>

#include <unistd.h>
#include <time.h>
#include <sys/stat.h>
#include <fcntl.h>

static int usage()
{
    fprintf(stderr, "Usage: chown [OPTION] <USER>[:GROUP] <FILE1> [FILE2] ...\n");
    fprintf(stderr, "   -h:                  do not follow symlink\n");
    return 10;
}

int chown_main(int argc, char **argv)
{
    int i;
    int fd = 0;
    unsigned int flag = 0;

    if (argc < 3) {
        return usage();
    }

    // Copy argv[1] to 'user' so we can truncate it at the period
    // if a group id specified.
    char user[32];
    char *group = NULL;
    int noFollow = (strcmp(argv[1], "-h") == 0);
    if (noFollow && argc < 4) {
        return usage();
    }
    if(noFollow) {
        flag = O_NOFOLLOW;
        argc--;
        argv++;
    }

    strncpy(user, argv[1], sizeof(user));
    if ((group = strchr(user, ':')) != NULL) {
        *group++ = '\0';
    } else if ((group = strchr(user, '.')) != NULL) {
        *group++ = '\0';
    }

    // Lookup uid (and gid if specified)
    struct passwd *pw;
    struct group *grp = NULL;
    uid_t uid;
    gid_t gid = -1; // passing -1 to chown preserves current group

    pw = getpwnam(user);
    if (pw != NULL) {
        uid = pw->pw_uid;
    } else {
        char* endptr;
        uid = (int) strtoul(user, &endptr, 0);
        if (endptr == user) {  // no conversion
            fprintf(stderr, "No such user '%s'\n", user);
            return 10;
        }
    }

    if (group != NULL) {
        grp = getgrnam(group);
        if (grp != NULL) {
            gid = grp->gr_gid;
        } else {
            char* endptr;
            gid = (int) strtoul(group, &endptr, 0);
            if (endptr == group) {  // no conversion
                fprintf(stderr, "No such group '%s'\n", group);
                return 10;
            }
        }
    }

    for (i = 2; i < argc; i++) {
        if(((fd = open(argv[i], flag|O_RDONLY)) != -1) ||((fd = open(argv[i], flag|O_WRONLY)) != -1)){
            if (fchown(fd, uid, gid) < 0){
                fprintf(stderr, "Unable to chown %s: %s\n", argv[i], strerror(errno));
                close(fd);
                return 10;
            }
            close(fd);
        } else {
                fprintf(stderr, "Unable to open %s: %s\n", argv[i], strerror(errno));
                return 10;
        }
    }

    return 0;
}
