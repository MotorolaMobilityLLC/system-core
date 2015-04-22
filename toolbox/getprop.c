#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <cutils/properties.h>
#include <signal.h> // Motorola, a5705c, 2013-05-03, IKJB42MAIN-6672
#include "dynarray.h"

//BEGIN MOTOROLA, kgh864, IKASANTISPRINT-1896 port IKSUNFIRE-4142
#ifdef ENABLE_BLACKLIST
static const char * black_list [] = {
    "net.hostname",
    "media.proxy.username",
    "media.proxy.password",
    "media.proxy.http.addr",
    "media.proxy.rtsp.addr"
};

static bool prop_blacklisted(const char * key)
{
    bool ret = false;
    unsigned int i = 0;
    if (key == NULL)
    {
        return ret;
    }
    for (i = 0; i < sizeof(black_list)/sizeof(black_list[0]); i++)
    {
        if (strcmp(black_list[i], key) == 0)
        {
            ret = true;
            break;
        }
        else
        {
            continue;
        }
    }
    return ret;
}
#else
static inline bool prop_blacklisted(const char * key)
{
    return false;
}
#endif
//END IKASANTISPRINT-1896

static void record_prop(const char* key, const char* name, void* opaque)
{
    //BEGIN MOTOROLA, kgh864, 06/06/2012, IKASANTISPRINT-1896
    if (!prop_blacklisted(key)){
        strlist_t* list = opaque;
        char temp[PROP_VALUE_MAX + PROP_NAME_MAX + 16];
        snprintf(temp, sizeof temp, "[%s]: [%s]", key, name);
        strlist_append_dup(list, temp);
    }
    //END IKASANTISPRINT-1896
}

static void list_properties(void)
{
    strlist_t  list[1] = { STRLIST_INITIALIZER };

    /* Record properties in the string list */
    (void)property_list(record_prop, list);

    /* Sort everything */
    strlist_sort(list);

    /* print everything */
    STRLIST_FOREACH(list, str, printf("%s\n", str));

    /* voila */
    strlist_done(list);
}

// BEGIN Motorola, a5705c, 2013-05-03, IKJB42MAIN-6672
static void sigpipe_handler(int n)
{
    (void)n;
    exit(EXIT_FAILURE);
}

static void install_sigpipe_handler()
{
    struct sigaction act;
    memset(&act, 0, sizeof(act));
    act.sa_handler = sigpipe_handler;
    sigaction(SIGPIPE, &act, NULL);
}
// END IKJB42MAIN-6672


int getprop_main(int argc, char *argv[])
{
    install_sigpipe_handler(); // Motorola, a5705c, 2013-05-03, IKJB42MAIN-6672

    if (argc == 1) {
        list_properties();
    } else {
        char value[PROPERTY_VALUE_MAX];
        char *default_value;
        if(argc > 2) {
            default_value = argv[2];
        } else {
            default_value = "";
        }

        //BEGIN MOTOROLA, kgh864, 06/06/2012, IKASANTISPRINT-1896 port IKSUNFIRE-4142
        memset(value, 0, sizeof(value));
        if (!prop_blacklisted(argv[1])) {
            property_get(argv[1], value, default_value);
        }
        //END IKASANTISPRINT-1896
        printf("%s\n", value);
    }
    return 0;
}
