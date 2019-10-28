#include "property_service.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <fcntl.h>
#include <errno.h>
#include <expat.h>
#include <ctype.h>
#include <errno.h>
#include <sys/syscall.h>

#include <android-base/logging.h>
#include <android-base/file.h>
#include <android-base/properties.h>
//#include <cutils/properties.h>
#include <android-base/logging.h>

//#include "log.h"
#include "util.h"

#if defined(pr_debug)
#undef pr_debug
#endif
//#define XML_EXTREME_DEBUG

#if defined(XML_EXTREME_DEBUG)
#define pr_debug LOG(INFO)
#else
#define pr_debug LOG(DEBUG)
#endif

#define PROCFS_HW_RELOAD "/proc/hw/reload"
#define PROP_PATH_OEM_OVERRIDE "/oem/oem.prop"

#define BUFFSIZE 8192
#define MAX_PROPS_NUM 10
#define PROP_VALUE_MAX 96
#define PROP_NAME_MAX 32

namespace android {
namespace init {

typedef struct param_s {
    char *pname;
    char *pdata;
} parameter_t;

typedef struct element_s {
    char *name;
    char *tag;
    int depth;
    char *payload;
    int count;
    parameter_t **parameters;
    struct element_s *child;
    struct element_s *parent;
    struct element_s *next;
} element_t;

typedef struct {
    int node_depth;
    element_t *data;
    element_t *head;
    char *node_to_parse;
    bool parsing_in_progress;
    bool done;
} parse_ctrl_t;

typedef struct {
    char *props[MAX_PROPS_NUM];
    int count;
    char *appendix;
    char *filter;
} append_var_t;

static append_var_t hwVariant;

static element_t *NodesList;
static char Buff[BUFFSIZE];
static int Depth;

static void
hw_property_get(const char *prop_name, char *value)
{
    std::string prop_str = android::base::GetProperty(prop_name, "");
    strncpy(value, prop_str.c_str(), prop_str.length());
}

static void
xml_update_name(parse_ctrl_t *info, const char *name)
{
    element_t *cur = info->data;

    if (!cur) {
        PLOG(ERROR) <<  __FUNCTION__ << ": data pointer is NULL";
        return;
    }
    if (cur->name) {
        pr_debug << "discard default name '" << cur->name << "'\n";
        free(cur->name);
    }
    cur->name = strdup(name);
    pr_debug << "added element's name '" << cur->name << "' of " << strlen(cur->name) << "bytes\n";
}

static void
xml_update_parameter(parse_ctrl_t *info, const char *title, const char *data)
{
    element_t *cur = info->data;

    if (!cur) {
        PLOG(ERROR) << __FUNCTION__ << ": data pointer is NULL";
        return;
    }
    cur->parameters = (parameter_t **)realloc(cur->parameters,
                sizeof(parameter_t *) * (cur->count + 1));
    if (!cur->parameters) {
        PLOG(ERROR) << __FUNCTION__ << ": data pointer is NULL";
        return;
    }
    cur->parameters[cur->count] = (parameter_t *)calloc(1, sizeof(parameter_t));
    if (!cur->parameters[cur->count]) {
        PLOG(ERROR) << __FUNCTION__ << ": data pointer is NULL";
        return;
    }
    cur->parameters[cur->count]->pname = strdup(title);
    cur->parameters[cur->count]->pdata = strdup(data);
    cur->count++;
    pr_debug << __FUNCTION__ << ": count=" << cur->count << ", param ptr=" << cur->parameters << "\n";
}

static char
*xml_update_payload(parse_ctrl_t *info, const char *data, int len)
{
    element_t *cur = info->data;

    if (!cur) {
        PLOG(ERROR) << __FUNCTION__ << ": data pointer is NULL";
        return NULL;
    }
    cur->payload = (char *)calloc(1, len + 1);
    strncpy(cur->payload, data, len);
    pr_debug << __FUNCTION__ << ": updating element ptr " << cur << "\n";
    return(cur->payload);
}

typedef struct {
    char *tag_name;
    char *tag_value;
} tag_val_t;

static tag_val_t tagValuesTable[MAX_PROPS_NUM];

static int xml_get_value_method(char *tag, tag_val_t *tval)
{
    bool data_ready = false;
    char tagvalue[PROP_VALUE_MAX];
    /* If value in tag contains '.', then it's a property */
    /* Property has to be one of the properties exported */
    /* from kernel cmdline, since this code is executed */
    /* prior the rest of system properties get loaded */
    if (strchr(tag, '.')) {
        hw_property_get(tag, tagvalue);
        pr_debug << "property '" << tag << "'='" << tagvalue << "'\n";
        data_ready = true;
    } else { /* otherwise, it's utag or file */
        int vfd, rbytes;
        char tagname[PROP_VALUE_MAX];
        if (*tag == '/') /* absolute path to file */
            snprintf(tagname, PROP_VALUE_MAX-1, "%s", tag);
        else    /* constructing path to HW UTAG file */
            snprintf(tagname, PROP_VALUE_MAX-1, "/proc/hw/%s/ascii", tag);
        pr_debug << "opening: '" << tagname << "'\n";
        vfd = open(tagname, O_RDONLY | O_CLOEXEC);
        if (vfd != -1) {
            rbytes = read(vfd, tagvalue, PROP_VALUE_MAX);
            close(vfd);
            if (rbytes != -1) {
                tagvalue[rbytes-1] = 0;
                data_ready = true;
            }
        }
    }
    if (data_ready) {
        tval->tag_value = strdup(tagvalue);
        tval->tag_name = strdup(tag);
        return 0;
    }
    return -1;
}

static char
*xml_tag_get_value(char *tag)
{
    char *value = NULL;
    for (int i = 0; i < MAX_PROPS_NUM; i++) {
        tag_val_t *tval = &tagValuesTable[i];
        if (!tval->tag_name) {
            int rc = xml_get_value_method(tag, tval);
            if (!rc) {
                value = tval->tag_value;
                pr_debug << "[" << i << "] added value '" << tval->tag_value << "' for utag '" << tval->tag_name << "'\n";
            }
            break;
        } else if (!strncmp(tval->tag_name, tag, strlen(tag))) {
            value = tval->tag_value;
            pr_debug << "[" << i << "] value for utag '" << tag << "' already fetched\n";
            break;
        }
    }

    return value;
}

static void xml_find_parameter(element_t *el, const char *token, char **data_ptr);
static int xml_build_append_array(char *source);

typedef struct {
    bool inited;
    char *export_prop_name;
    char *export_prop;
    char *default_v;
    int append_cnt;
} map_outs_t;

static void
xml_extract_outs(element_t *el, map_outs_t *mouts)
{
    char *append_param;
    /* extract export parameter */
    xml_find_parameter(el, "export", &mouts->export_prop_name);
    if (mouts->export_prop_name) {
        pr_debug << "export_prop_name '" << mouts->export_prop_name << "'\n";
        mouts->inited = true;
    }
    /* extract optional append parameter */
    xml_find_parameter(el, "append", &append_param);
    if (append_param)
        mouts->append_cnt = xml_build_append_array(append_param);
    /* extract optional default parameter */
    xml_find_parameter(el, "default", &mouts->default_v);
}

static bool
xml_match_multiple_choices(element_t *head, map_outs_t *mouts)
{
    bool match = false;
    char *name_to_return = NULL;
    element_t *node, *choice;
    for (node = head->child; node; node = node->next) {
        if (!node->child)
            continue;
        if (!mouts->inited) {
            xml_extract_outs(node, mouts);
            if (mouts->inited)
                pr_debug << "export_prop_name '" << mouts->export_prop_name << "'\n";
        }
        match = true;
        name_to_return = node->name;
        for (choice = node->child; choice; choice = choice->next) {
            char *value = xml_tag_get_value(choice->name);
            if (!value ||
                strncmp(choice->payload, value, strlen(choice->payload))) {
                pr_debug << "[" << choice->name << "]: '" << choice->payload << "' != '" << value << "'\n";
                match = false;
                break;
            }
        }

        if (match)
            break;
        else
            name_to_return = NULL;
    }

    if (name_to_return)
        mouts->export_prop = strdup(name_to_return);
    else
        mouts->export_prop = NULL;

    for (int i = 0; i < MAX_PROPS_NUM; i++) {
        tag_val_t *tval = &tagValuesTable[i];
        if (tval->tag_name) {
            free(tval->tag_name);
            tval->tag_name = NULL;
        }
        if (tval->tag_value) {
            free(tval->tag_value);
            tval->tag_value = NULL;
        }
    }

    return match;
}

#define BY_NAME    0
#define BY_TAG    1

static element_t
*search_node(element_t *head, const char *token, int by)
{
    element_t *branch;

    for (branch = head->child; branch; branch = branch->next) {
        pr_debug << "matching token '" << token << "' to name='" << branch->name << "' tag='" << branch->tag << "' payload='" << branch->payload << "'\n";
        /* effectively, searching a substring in case of BY_NAME */
        if (by == BY_NAME && branch->name && !strncmp(branch->name, token, strlen(branch->name)))
            break;
        else if (by == BY_TAG && !strncmp(branch->tag, token, strlen(token)))
            break;
    }
    return branch;
}

static void
xml_find_parameter(element_t *el, const char *token, char **data_ptr)
{
    *data_ptr = NULL;
    for (int i = 0; i < el->count; i++) {
        parameter_t *parm = el->parameters[i];
        pr_debug << "parameter[" << i << "]: '" << parm->pname << "'->'" << parm->pdata << "'\n";
        if (!strncmp(parm->pname, token, strlen(token))) {
            *data_ptr = parm->pdata;
            break;
        }
    }
}

static append_var_t inline *xml_preload_get_ptr(void) {
    return &hwVariant;
}

static int inline xml_preload_get_count(void) {
    append_var_t *append = xml_preload_get_ptr();
    return append->count;
}

static void inline xml_preload_set_count(int count) {
    append_var_t *append = xml_preload_get_ptr();
    append->count = count;
}

static int inline xml_preload_set_prop(char *prop) {
    append_var_t *append = xml_preload_get_ptr();
    if ((append->count + 1) <= MAX_PROPS_NUM)
        append->props[append->count++] = prop;
    return append->count;
}

static void xml_preload_build_filter(void)
{
    append_var_t *append = xml_preload_get_ptr();
    char *s0, *sn;
    int bytes_counter = 0;

    if (!append->count)
        return;
    for (s0 = append->props[0]; *s0; s0++) {
        bool no_match = false;
        int offset = s0 - append->props[0];
        for (int i = 1; i < append->count; i++) {
            sn = append->props[i] + offset;
            if (*s0 != *sn) {
                no_match = true;
                pr_debug <<"diff character in pos " << offset << "\n";
                break;
            }
        }
        if (no_match)
            break;
        bytes_counter++;
    }

    if (bytes_counter) {
        char *filter = (char *)malloc(bytes_counter+2);
        pr_debug << bytes_counter << "  common character(s) found\n";
        if (filter) {
            memcpy(filter, append->props[0], bytes_counter);
            *(filter + bytes_counter) = '*';
            *(filter + bytes_counter + 1) = '\0';
            append->filter = filter;
            pr_debug << "allocated filter '" << filter << "'\n";
        }
    }
}

static int
xml_build_append_array(char *source)
{
    int counter;
    char *ptr, *dup, *begin = source;

    xml_preload_set_count(0);
    for (int i = 0; i < MAX_PROPS_NUM; i++) {
        if ((ptr = strchr(begin, ',')))
            *ptr = 0;
        dup = strdup(begin);
        if (dup) {
            xml_preload_set_prop(dup);
            pr_debug << "allocated prop[" << i << " ]: '" << dup << "'\n";
        }
        if (ptr)
            begin = ++ptr;
        else
            break;
    }

    xml_preload_build_filter();

    counter = xml_preload_get_count();
    pr_debug << "need to append to " << counter << " props\n";

    return counter;
}

static int
xml_handle_mappings(parse_ctrl_t *info,  std::map<std::string, std::string> &properties_map)
{
    char *ptr, value[PROP_NAME_MAX] = {0};
    char prop_value[PROP_VALUE_MAX] = {0};
    char *boot_prop_name, *boot_prop;
    element_t *search_head, *cur = NULL;

    /* retrieve boot property name */
    xml_find_parameter(info->head, "match", &boot_prop_name);
    if (!boot_prop_name) {
        PLOG(ERROR) << "Unable to find boot property";
        return 1;
    }

    hw_property_get(boot_prop_name, value);
    pr_debug << "original boot device name '" << value << "'\n";
    /* normalize boot device name */
    for (ptr = value; *ptr; ptr++)
        if (!isalpha(*ptr)) {
            *ptr = 0;
            break;
        } else if (*ptr >= 'A' && *ptr <= 'Z') {
            *ptr += 0x20;
        }
    pr_debug << "normalized boot device name '" << value << "'\n";

    boot_prop = strdup(value);
    if (!boot_prop) {
        PLOG(ERROR) << "Unable to match device";
        return 1;
    }

    /* search matching device section */
    search_head = search_node(info->head, boot_prop, BY_NAME);
    if (!search_head) {
        PLOG(ERROR) << "No device section matching " << boot_prop << " found";
        free(boot_prop);
        return 1;
    }
    pr_debug << "found section 'device name=\"" << search_head->name << "\"'\n";

    /* search in device section */
    search_head = search_node(search_head, "mappings", BY_TAG);
    if (!search_head) {
        PLOG(ERROR) << "No section 'mappings' found";
        return 1;
    }
    pr_debug << "found section 'mappings'\n";

    for (cur = search_head->child; cur; cur = cur->next) {
        map_outs_t mouts;

        memset(&mouts, 0, sizeof(mouts));
        xml_extract_outs(cur, &mouts);

        /* match multiple choices */
        bool found = xml_match_multiple_choices(cur, &mouts);
        if (found) {
            if (!mouts.export_prop)
                continue;

            properties_map[mouts.export_prop_name] = mouts.export_prop;
            pr_debug << "Match found '" << mouts.export_prop << "'";
            pr_debug << "exported '" << mouts.export_prop_name
                << "'=>'" << mouts.export_prop << "'";
            /* if matched result needs to be appended */
            if (mouts.append_cnt) {
                for(int i=0; i < hwVariant.count;i++) {
                    snprintf(prop_value, PROP_VALUE_MAX, "%s%s",
                        boot_prop, mouts.export_prop);
                    if(properties_map[hwVariant.props[i]].empty())
                        properties_map[hwVariant.props[i]] = prop_value;
                    else
                        properties_map[hwVariant.props[i]] += mouts.export_prop;
                    pr_debug << "Set '" << hwVariant.props[i] <<
                        "' to '" << prop_value << "'";
                }
            }
        } else {
            if (mouts.default_v) {
                properties_map[mouts.export_prop_name] = mouts.default_v;
                pr_debug << "Applying default '" << mouts.default_v << "'";
                pr_debug << "exported '" << mouts.export_prop_name <<
                    "'=>'" << mouts.default_v << "'";
            } else
                pr_debug << "no match found in section '" << cur->tag << "'\n";
        }

        pr_debug << "Processed section '" << cur->tag << "'";
    }
    free(boot_prop);
    return 0;
}

static element_t
*xml_add_node(parse_ctrl_t *info, const char *el, int depth)
{
    element_t *new_el, *cur = info->data;

    new_el = (element_t *)calloc(1, sizeof(element_t));
    if (!new_el) {
        PLOG(ERROR) <<  __FUNCTION__ << ": data pointer is NULL";
        return NULL;
    }
    if (!NodesList) {
        NodesList = new_el;
        info->head = NodesList;
        pr_debug << __FUNCTION__ << ": head ptr " << info->head << "\n";
    }
    if (!cur)
        goto fill_in;
    if (cur->depth < depth) {
        /* for child, save ptr to parent */
        cur->child = new_el;
        new_el->parent = cur;
        //pr_debug << __FUNCTION__ << ": added child ptr " << new_el << " to '" << cur->name << "'\n";
    } else {
        /* for brother, propagate parent */
        cur->next = new_el;
        new_el->parent = cur->parent;
        //pr_debug << __FUNCTION__ << ": added brother ptr " << new_el << " to '" << << "'\n", __FUNCTION__, new_el,
        //    (cur->parent && cur->parent->name) ?
        //    cur->parent->name : cur->parent->tag);
    }
fill_in:
    new_el->depth = depth;
    new_el->tag = strdup(el);
//    pr_debug  << __FUNCTION__ << ": ptr " << cur << " depth " << cur ? cur->depth : -1 << "; adding " << new_el << " depth " << depth << " tag '" << new_el->tag << "'\n";
    info->data = new_el;
    return(new_el);
}

static void
xml_update_parent(parse_ctrl_t *info, int depth)
{
    element_t *cur = info->data;

    if (!cur) {
        PLOG(ERROR) <<  __FUNCTION__ << ": data pointer is NULL";
        return;
    }
    if (cur->depth > depth && cur->parent)
        info->data = cur->parent;
    pr_debug << __FUNCTION__ << ": ptr " << cur << " depth " << cur->depth << "; moving to " << info->data << " depth " << depth << "\n";
}

static void
xml_free_list(element_t *head)
{
    int i;
    element_t *cur, *next;

    for (cur = head; cur; cur = next) {
        next = cur->next;
        if (cur->name) {
            pr_debug << "name '" << cur->name << "' " << cur->name << "\n";
            free(cur->name);
        }
        if (cur->tag) {
            pr_debug << "tag '" << cur->tag << "' " << cur->tag << "\n";
            free(cur->tag);
        }
        if (cur->payload) {
            pr_debug << "payload '" << cur->payload << "' " << cur->payload << "\n";
            free(cur->payload);
        }
        if (cur->count) {
            for (i = 0; i < cur->count; i++) {
                pr_debug << "param[" << i << "]: '" << cur->parameters[i]->pname << "'='" << cur->parameters[i]->pdata << "'\n";
                if (cur->parameters[i]->pname)
                    free(cur->parameters[i]->pname);
                if (cur->parameters[i]->pdata)
                    free(cur->parameters[i]->pdata);
                free(cur->parameters[i]);
            }
            free(cur->parameters);
        }
        if (cur->child)
            xml_free_list(cur->child);
        free(cur);
    }
}

static void XMLCALL
drop(void *userData, const XML_Char *s)
{
    pr_debug << "dropped comment <" << s << ">\n";
}

static void XMLCALL
chardata(void *userData, const XML_Char *s, int len)
{
    parse_ctrl_t *info = (parse_ctrl_t *)userData;
    char *buffer = NULL;

    if (*s == '\n' || *s == '\t' || *s == ' ') /* skip meaningless data */
        return;
    buffer = xml_update_payload(info, s, len);
    pr_debug << ">-(len=" << len << ") '" << buffer << "'-<\n";
}

static void XMLCALL
start(void *userData, const char *el, const char **attr)
{
    parse_ctrl_t *info = (parse_ctrl_t *)userData;
    bool has_name = false;
    int i, count = 0;

    for (i = 0; attr[i]; i += 2) {
        if (!strcmp(attr[i], "name"))
            has_name = true;
    }
    count = i/2;
    //pr_debug << "["" << Depth << "]-->{" << el << "} parameters=" << count << ", named '" has_name ? "yes" : "no" "'\n";
    xml_add_node(info, el, Depth);

    for (i = 0; attr[i]; i += 2) {
        //pr_debug < " {" << attr[i] << "}='" << attr[i + 1] << "'\n";
        if (!strcmp(attr[i], "name"))
            xml_update_name(info, attr[i + 1]);
        xml_update_parameter(info, attr[i], attr[i + 1]);
    }
    Depth++;
}

static void XMLCALL
end(void *userData, const char *el)
{
    parse_ctrl_t *info = (parse_ctrl_t *)userData;
    Depth--;
    xml_update_parent(info, Depth);
}

// For some devices that present HW variants, we need to read its utags to
// determine it variant. For this we need utags.ko module loaded.
static Result<Success> insmod(const std::string& path_name, const std::string& args) {
    base::unique_fd fd(
            TEMP_FAILURE_RETRY(open(path_name.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC)));
    if (fd == -1) return ErrnoError() << "Could not open module '" << path_name << "'";

    int ret = syscall(__NR_finit_module, fd.get(), args.c_str(), 0);
    if (ret != 0) {
        if (errno == EEXIST) {
            // Module already loaded
            return Success();
        }
        return ErrnoError() << "Failed to insmod '" << path_name << "' with args '" << args << "'";
    }

    LOG(INFO) << "Loaded kernel module " << path_name;
    return Success();
}

int process_hw_mappings(const char *xml_name,
    std::map<std::string, std::string> &properties_map)
{
    parse_ctrl_t info;
    int retry, fin, freload, error = 0;
    char command[3];
    XML_Parser p;

    if (auto result = insmod("vendor/lib/modules/utags.ko", ""); !result) {
        LOG(INFO) << "utags module not loaded from root";
    }

    LOG(WARNING) << "Processing HW mappings\n";

    freload = open(PROCFS_HW_RELOAD, O_RDWR | O_CLOEXEC);
    pr_debug << "file '" << PROCFS_HW_RELOAD << "' opened fd=" << freload << "\n";
    if (freload == -1) {
        error = errno;
        PLOG(ERROR) << "Cannot open HW descriptor: ";
        goto just_exit;
    }

    /* read reload status */
    error = read(freload, command, 1);
    if (error == -1) {
        LOG(ERROR) << "Unable to read HW descriptor status";
        close(freload);
        goto just_exit;
    } else {
        lseek(freload, 0L, SEEK_SET);
        LOG(WARNING) << "HW descriptor status=" << command[0];
    }

    /* HW init script should have started reload already, thus */
    /* status has to be "reload in progress". However, in case */
    /* init script has not done so, sending reload command here */
    if (command[0] == '2') {
        strcpy(command, "1\n");
        error = write(freload, command, 2);
        LOG(WARNING) << "Sent HW descriptor reload command rc=" << error;
        if (error != 2) {
            LOG(ERROR) << "Unable to read HW descriptor reload";
            close(freload);
            goto just_exit;
        }
    }

    memset( &info, 0, sizeof(info));

    fin = open(xml_name, O_RDONLY | O_CLOEXEC);
    pr_debug << "file '" << xml_name << "' opened fd=" << fin << "\n";
    if (fin == -1) {
        error = errno;
        if (errno == ENOENT)
            LOG(ERROR) << "File " << xml_name << " not found";
        else
            PLOG(ERROR) << "Failed to open  " << xml_name << ": ";
        close(freload);
        goto just_exit;
    }

    p = XML_ParserCreate(NULL);
    if (!p) {
        LOG(ERROR) << "Failed to allocate memory for parser";
        error = ENOMEM;
        goto cleanup_and_exit;
    }
    pr_debug << "XML parser init-ed\n";

    XML_SetElementHandler(p, start, end);
    XML_SetCommentHandler(p, drop);
    XML_SetCharacterDataHandler(p, chardata);
    XML_SetUserData(p, &info);

    for (;;) {
        int len, done;

        len = read(fin, Buff, BUFFSIZE-1);
        if (len == 0)
            break;
        done = len < BUFFSIZE-1 ? 1 : 0;
        if (XML_Parse(p, Buff, len, done) == XML_STATUS_ERROR) {
            LOG(ERROR) << "Parse error at line " << XML_GetCurrentLineNumber(p)
                << ":" << XML_ErrorString(XML_GetErrorCode(p));
            break;
        }
        if (done)
            break;
    }
    XML_ParserFree(p);
    pr_debug << "XML parsing done\n";

    for (retry = 0; retry < 10; retry++) {
        lseek(freload, 0L, SEEK_SET);
        error = read(freload, command, 1);
        if (error == -1) {
            LOG(ERROR) << "Unable to confirm HW descriptor reload";
            break;
        } else if (command[0] == '1') {
            LOG(WARNING) << "HW descriptor reload is in progress...";
            usleep(50000);
        } else if (command[0] == '0') {
            LOG(WARNING) << "HW descriptor reload completed with rc=" << command[0];
            break;
        }
    }
    close(freload);

    if (info.head && command[0] == '0')
        error = xml_handle_mappings(&info, properties_map);
    else
        LOG(WARNING) << "Not ready to process HW mappings";

    xml_free_list(NodesList);
    NodesList = NULL;
cleanup_and_exit:
    close(fin);
just_exit:
    return(error);
}

} //namespace init
} //namespace android
