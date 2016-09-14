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

#include <cutils/android_reboot.h>

#define _REALLY_INCLUDE_SYS__SYSTEM_PROPERTIES_H_
#include <sys/_system_properties.h>

#include "log.h"
#include "util.h"
#include "hw_tags.h"

//#define DEBUG
#define pr_debug(fmt, args...)	if(debug_on) NOTICE(fmt, ##args)

#if defined(DEBUG)
static bool debug_on = 1;
#else
static bool debug_on;
#endif

#define PROCFS_HW_RELOAD "/proc/hw/reload"
#define PROP_PATH_OEM_OVERRIDE "/oem/oem.prop"

#define BUFFSIZE 8192

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

#define MAX_PROPS_NUM 10

typedef struct {
	char *props[MAX_PROPS_NUM];
	int count;
	char *appendix;
	char *filter;
} append_var_t;

static append_var_t hwVariant;
static void xml_load_properties_from_file(const char* , const char* );

static element_t *NodesList;
static char Buff[BUFFSIZE];
static int Depth;

static void
hw_property_get(const char *prop_name, char *value)
{
	std::string prop_str = property_get(prop_name);
	strncpy(value, prop_str.c_str(), prop_str.length());
}

static void
xml_update_name(parse_ctrl_t *info, const char *name)
{
	element_t *cur = info->data;

	if (!cur) {
		ERROR("%s: data pointer is NULL\n", __func__);
		return;
	}
	if (cur->name) {
		pr_debug("discard default name '%s'\n", cur->name);
		free(cur->name);
	}
	cur->name = strdup(name);
	pr_debug("added element's name '%s' of %zu bytes\n",
		cur->name, strlen(cur->name));
}

static void
xml_update_parameter(parse_ctrl_t *info, const char *title, const char *data)
{
	element_t *cur = info->data;

	if (!cur) {
		ERROR("%s: data pointer is NULL\n", __func__);
		return;
	}
	cur->parameters = (parameter_t **)realloc(cur->parameters,
				sizeof(parameter_t *) * (cur->count + 1));
	if (!cur->parameters) {
		ERROR("%s: data pointer is NULL\n", __func__);
		return;
	}
	cur->parameters[cur->count] = (parameter_t *)calloc(1, sizeof(parameter_t));
	if (!cur->parameters[cur->count]) {
		ERROR("%s: data pointer is NULL\n", __func__);
		return;
	}
	cur->parameters[cur->count]->pname = strdup(title);
	cur->parameters[cur->count]->pdata = strdup(data);
	cur->count++;
	pr_debug("%s: count=%d, param ptr=%p\n", __func__,
			cur->count, cur->parameters);
}

static char
*xml_update_payload(parse_ctrl_t *info, const char *data, int len)
{
	element_t *cur = info->data;

	if (!cur) {
		ERROR("%s: data pointer is NULL\n", __func__);
		return NULL;
	}
	cur->payload = (char *)calloc(1, len + 1);
	strncpy(cur->payload, data, len);
	pr_debug("%s: updating element ptr %p\n", __func__, cur);
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
		pr_debug("property '%s'='%s'\n", tag, tagvalue);
		data_ready = true;
	} else { /* otherwise, it's utag */
		int vfd, rbytes;
		char tagname[PROP_NAME_MAX];
		snprintf(tagname, PROP_NAME_MAX-1, "/proc/hw/%s/ascii", tag);
		pr_debug("opening: '%s'\n", tagname);
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
				pr_debug("[%d] added value '%s' for utag '%s'\n",
					i, tval->tag_value, tval->tag_name);
			}
			break;
		} else if (!strncmp(tval->tag_name, tag, strlen(tag))) {
			value = tval->tag_value;
			pr_debug("[%d] value for utag '%s' already fetched\n", i, tag);
			break;
		}
	}

	return value;
}

static bool
xml_match_multiple_choices(element_t *head, char **data_ptr)
{
	bool match = false;
	char *name_to_return = NULL;
	element_t *node, *choice;
	for (node = head->child; node; node = node->next) {
		if (!node->child)
			continue;

		match = true;
		name_to_return = node->name;
		for (choice = node->child; choice; choice = choice->next) {
			char *value = xml_tag_get_value(choice->name);
			if (!value ||
				strncmp(choice->payload, value, strlen(choice->payload))) {
				pr_debug("[%s]: '%s' != '%s'\n", choice->name, choice->payload, value);
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
		*data_ptr = strdup(name_to_return);
	else
		*data_ptr = NULL;

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

#define BY_NAME	0
#define BY_TAG	1

static element_t
*search_node(element_t *head, const char *token, int by)
{
	element_t *branch;

	for (branch = head->child; branch; branch = branch->next) {
		pr_debug("matching token '%s' to name='%s'"\
			" tag='%s' payload='%s'\n",
			token, branch->name ? branch->name : "noname",
			branch->tag, branch->payload);
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
		pr_debug("parameter[%d]: '%s'->'%s'\n", i, parm->pname, parm->pdata);
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

static char inline *xml_preload_get_filter(void) {
	append_var_t *append = xml_preload_get_ptr();
	return append->filter;
}

static void inline xml_preload_set_count(int count) {
	append_var_t *append = xml_preload_get_ptr();
	append->count = count;
}

static void inline xml_preload_set_appendix(char *appendix) {
	append_var_t *append = xml_preload_get_ptr();
	append->appendix = appendix;
}

static int inline xml_preload_set_prop(char *prop) {
	append_var_t *append = xml_preload_get_ptr();
	if ((append->count + 1) <= MAX_PROPS_NUM)
		append->props[append->count++] = prop;
	return append->count;
}

static void
xml_preload_clear_all(void)
{
	append_var_t *append = xml_preload_get_ptr();
	for (int i = 0; i < append->count; i++) {
		free(append->props[i]);
		append->props[i] = NULL;
	}

	append->count = 0;

	if (append->appendix)
		free(append->appendix);
	append->appendix = NULL;

	if (append->filter)
		free(append->filter);
	append->filter = NULL;
}

static void
xml_preload_apply(char *key, char *value)
{
    append_var_t *append = xml_preload_get_ptr();
    for (int i = 0; i < append->count; i++)
	if (!strncmp(key, append->props[i], strlen(append->props[i]))) {
		char new_value[PROP_VALUE_MAX];
		int rc;
		snprintf(new_value, PROP_VALUE_MAX-1, "%s%s", value, append->appendix);
		rc = property_set(append->props[i], new_value);
		if (rc != -1)
			NOTICE("added hw variant: '%s'=>'%s'\n", append->props[i], new_value);
	}
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
				pr_debug("diff character in pos %d\n", offset);
				break;
			}
		}
		if (no_match)
			break;
		bytes_counter++;
	}

	if (bytes_counter) {
		char *filter = (char *)malloc(bytes_counter+2);
		pr_debug("%d common character(s) found\n", bytes_counter);
		if (filter) {
			memcpy(filter, append->props[0], bytes_counter);
			*(filter + bytes_counter) = '*';
			*(filter + bytes_counter + 1) = '\0';
			append->filter = filter;
			pr_debug("allocated filter '%s'\n", filter);
		}
	}
}

static void
xml_load_properties(char *data, const char *filter)
{
    char *key, *value, *eol, *sol, *tmp, *fn;
    size_t flen = 0;

    if (filter) {
        flen = strlen(filter);
    }

    sol = data;
    while ((eol = strchr(sol, '\n'))) {
        key = sol;
        *eol++ = 0;
        sol = eol;

        while (isspace(*key)) key++;
        if (*key == '#') continue;

        tmp = eol - 2;
        while ((tmp > key) && isspace(*tmp)) *tmp-- = 0;

        if (!strncmp(key, "import ", 7) && flen == 0) {
            fn = key + 7;
            while (isspace(*fn)) fn++;

            key = strchr(fn, ' ');
            if (key) {
                *key++ = 0;
                while (isspace(*key)) key++;
            }

            xml_load_properties_from_file(fn, key);

        } else {
            value = strchr(key, '=');
            if (!value) continue;
            *value++ = 0;

            tmp = value - 2;
            while ((tmp > key) && isspace(*tmp)) *tmp-- = 0;

            while (isspace(*value)) value++;

            if (flen > 0) {
                if (filter[flen - 1] == '*') {
                    if (strncmp(key, filter, flen - 1)) continue;
                } else {
                    if (strcmp(key, filter)) continue;
                }
            }

            xml_preload_apply(key, value);
        }
    }
}

static void
xml_load_properties_from_file(const char* filename, const char* filter)
{
    std::string data;
    int no_error = read_file(filename, &data);
    pr_debug("reading file '%s' rc=%d\n", filename, no_error);
    if (no_error) {
        data.push_back('\n');
        xml_load_properties(&data[0], filter);
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
			pr_debug("allocated prop[%d]: '%s'\n", i, dup);
		}
		if (ptr)
			begin = ++ptr;
		else
			break;
	}

	xml_preload_build_filter();

	counter = xml_preload_get_count();
	pr_debug("need to append to %d props\n", counter);

	return counter;
}

static int
xml_handle_mappings(parse_ctrl_t *info)
{
	char *ptr, value[PROP_NAME_MAX] = {0};
	char *boot_prop_name, *boot_prop;
	char *export_prop_name, *export_prop, *default_v;
	element_t *search_head, *cur = NULL;

	/* retrieve boot property name */
	xml_find_parameter(info->head, "match", &boot_prop_name);
	if (!boot_prop_name) {
		ERROR("Unable to find boot property\n");
		return 1;
	}

	hw_property_get(boot_prop_name, value);
	pr_debug("original boot device name '%s'\n", value);
	/* normalize boot device name */
	for (ptr = value; *ptr; ptr++)
		if (!isalpha(*ptr)) {
			*ptr = 0;
			break;
		} else if (*ptr >= 'A' && *ptr <= 'Z') {
			*ptr += 0x20;
		}
	pr_debug("normalized boot device name '%s'\n", value);

	boot_prop = strdup(value);
	if (!boot_prop) {
		ERROR("Unable to match device\n");
		return 1;
	}

	/* search matching device section */
	search_head = search_node(info->head, boot_prop, BY_NAME);
	if (!search_head) {
		ERROR("No device section matching '%s' found\n", boot_prop);
		return 1;
	}
	pr_debug("found section 'device name=\"%s\"'\n", search_head->name);

	/* search in device section */
	search_head = search_node(search_head, "mappings", BY_TAG);
	if (!search_head) {
		ERROR("No section 'mappings' found\n");
		return 1;
	}
	pr_debug("found section 'mappings'\n");

	for (cur = search_head->child; cur; cur = cur->next) {
		char *append_param;
		int rc, append_cnt = 0;

		append_param = export_prop_name = export_prop = default_v = NULL;

		/* extract mandatory export parameter */
		xml_find_parameter(cur, "export", &export_prop_name);
		if (!export_prop_name) {
			NOTICE("Section'%s' has no export property; skipped\n", cur->tag);
			continue;
		}
		pr_debug("export_prop_name '%s'\n", export_prop_name);
		/* extract optional append parameter */
		xml_find_parameter(cur, "append", &append_param);
		if (append_param)
			append_cnt = xml_build_append_array(append_param);
		/* match multiple choices */
		bool found = xml_match_multiple_choices(cur, &export_prop);
		if (found) {
			if (!export_prop)
				continue;

			rc = property_set(export_prop_name, export_prop);
			NOTICE("Match found '%s'\n", export_prop);
			if (rc != -1)
				NOTICE("exported '%s'=>'%s'\n", export_prop_name, export_prop);
			/* if matched result needs to be appended */
			if (append_cnt) {
				xml_preload_set_appendix(export_prop);
				if (access(PROP_PATH_OEM_OVERRIDE, R_OK) == 0)
					xml_load_properties_from_file(PROP_PATH_OEM_OVERRIDE, xml_preload_get_filter());
				xml_load_properties_from_file(PROP_PATH_SYSTEM_BUILD, xml_preload_get_filter());
				xml_preload_clear_all();
			}
		} else {
			/* extract optional default parameter */
			xml_find_parameter(cur, "default", &default_v);
			if (default_v) {
				rc = property_set(export_prop_name, default_v);
				NOTICE("Applying default '%s'\n", default_v);
				if (rc != -1)
					NOTICE("exported '%s'=>'%s'\n", export_prop_name, default_v);
			} else
				pr_debug("no match found in section '%s'\n", cur->tag);
		}

		NOTICE("Processed section '%s'\n", cur->tag);
	}

	return 0;
}

static element_t
*xml_add_node(parse_ctrl_t *info, const char *el, int depth)
{
	element_t *new_el, *cur = info->data;

	new_el = (element_t *)calloc(1, sizeof(element_t));
	if (!new_el) {
		ERROR("%s: data pointer is NULL\n", __func__);
		return NULL;
	}
	if (!NodesList) {
		NodesList = new_el;
		info->head = NodesList;
		pr_debug("%s: head ptr %p\n", __func__, info->head);
	}
	if (!cur)
		goto fill_in;
	if (cur->depth < depth) {
		/* for child, save ptr to parent */
		cur->child = new_el;
		new_el->parent = cur;
		pr_debug("%s: added child ptr %p to '%s'\n", __func__,
				new_el, cur->name ? cur->name : cur->tag);
	} else {
		/* for brother, propagate parent */
		cur->next = new_el;
		new_el->parent = cur->parent;
		pr_debug("%s: added brother ptr %p to '%s'\n", __func__, new_el,
			(cur->parent && cur->parent->name) ?
			cur->parent->name : cur->parent->tag);
	}
fill_in:
	new_el->depth = depth;
	new_el->tag = strdup(el);
	pr_debug("%s: ptr %p depth %d; adding %p depth %d tag '%s'\n", __func__,
		cur, cur ? cur->depth : -1, new_el, depth, new_el->tag);
	info->data = new_el;
	return(new_el);
}

static void
xml_update_parent(parse_ctrl_t *info, int depth)
{
	element_t *cur = info->data;

	if (!cur) {
		ERROR("%s: data pointer is NULL\n", __func__);
		return;
	}
	if (cur->depth > depth && cur->parent)
		info->data = cur->parent;
	pr_debug("%s: ptr %p depth %d; moving to %p depth %d\n", __func__,
			cur, cur->depth, info->data, depth);
}

static void
xml_free_list(element_t *head)
{
	int i;
	element_t *cur, *next;

	for (cur = head; cur; cur = next) {
		next = cur->next;
		if (cur->name) {
			pr_debug("name '%s' %p\n", cur->name, cur->name);
			free(cur->name);
		}
		if (cur->tag) {
			pr_debug("tag '%s' %p\n", cur->tag, cur->tag);
			free(cur->tag);
		}
		if (cur->payload) {
			pr_debug("payload '%s' %p\n", cur->payload, cur->payload);
			free(cur->payload);
		}
		if (cur->count) {
			for (i = 0; i < cur->count; i++) {
				pr_debug("param[%d]: '%s'='%s'\n", i, cur->parameters[i]->pname, cur->parameters[i]->pdata);
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
	pr_debug("dropped comment <%s>\n", s);
}

static void XMLCALL
chardata(void *userData, const XML_Char *s, int len)
{
	parse_ctrl_t *info = (parse_ctrl_t *)userData;
	char *buffer = NULL;

	if (*s == '\n' || *s == '\t' || *s == ' ') /* skip meaningless data */
		return;
	buffer = xml_update_payload(info, s, len);
	pr_debug(">-(len=%d) '%s'-<\n", len, buffer);
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
	pr_debug("[%d]-->{%s} parameters=%d, named '%s'\n", Depth, el, count,
					has_name ? "yes" : "no");
	xml_add_node(info, el, Depth);

	for (i = 0; attr[i]; i += 2) {
		pr_debug(" {%s}='%s'\n", attr[i], attr[i + 1]);
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

int process_hw_mappings(const char *xml_name)
{
	parse_ctrl_t info;
	int retry, fin, freload, error = 0;
	char command[3];
	XML_Parser p;

	freload = open(PROCFS_HW_RELOAD, O_RDWR | O_CLOEXEC);
	pr_debug("file '%s' opened fd=%d\n", PROCFS_HW_RELOAD, freload);
	if (freload == -1) {
		error = errno;
		ERROR("Cannot open HW descriptor: %s\n", strerror(errno));
		goto just_exit;
	}

	/* read reload status */
	error = read(freload, command, 1);
	if (error == -1) {
		ERROR("Unable to read HW descriptor status\n");
		close(freload);
		goto just_exit;
	} else {
		lseek(freload, 0L, SEEK_SET);
		NOTICE("HW descriptor status=%c\n", command[0]);
	}

	/* HW init script should have started reload already, thus */
	/* status has to be "reload in progress". However, in case */
	/* init script has not done so, sending reload command here */
	if (command[0] == '2') {
		strcpy(command, "1\n");
		error = write(freload, command, 2);
		NOTICE("Sent HW descriptor reload command rc=%d\n", error);
		if (error != 2) {
			ERROR("Unable to start HW descriptor reload\n");
			close(freload);
			goto just_exit;
		}
	}

	memset( &info, 0, sizeof(info));

	fin = open(xml_name, O_RDONLY | O_CLOEXEC);
	pr_debug("file '%s' opened fd=%d\n", xml_name, fin);
	if (fin == -1) {
		error = errno;
		if (errno == ENOENT)
			ERROR("File '%s' not found\n", xml_name);
		else
			ERROR("Failed to open '%s': %s\n", xml_name, strerror(errno));
		close(freload);
		goto just_exit;
	}

	p = XML_ParserCreate(NULL);
	if (!p) {
		ERROR("Failed to allocate memory for parser\n");
		error = ENOMEM;
		goto cleanup_and_exit;
	}
	pr_debug("XML parser init-ed\n");

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
			ERROR("Parse error at line %lu:\n%s\n",
				XML_GetCurrentLineNumber(p),
				XML_ErrorString(XML_GetErrorCode(p)));
			break;
		}
		if (done)
			break;
	}
	XML_ParserFree(p);
	pr_debug("XML parsing done\n");

	for (retry = 0; retry < 10; retry++) {
		lseek(freload, 0L, SEEK_SET);
		error = read(freload, command, 1);
		if (error == -1) {
			ERROR("Unable to confirm HW descriptor reload\n");
			break;
		} else if (command[0] == '1') {
			NOTICE("HW descriptor reload is in progress...\n");
			usleep(50000);
		} else if (command[0] == '0') {
			NOTICE("HW descriptor reload completed with rc=%c\n", command[0]);
			break;
		}
	}
	close(freload);

	if (info.head && command[0] == '0')
		error = xml_handle_mappings(&info);
	else
		NOTICE("Not ready to process HW mappings\n");

	xml_free_list(NodesList);
	NodesList = NULL;
cleanup_and_exit:
	close(fin);
just_exit:
	return(error);
}

#define CARRIER_RO_PROP "ro.carrier"
#define CARRIER_SUBSIDY_PROP "ro.carrier.subsidized"
#define CARRIER_OEM_PROP "ro.carrier.oem"

#define CARRIER_MSG_FILE "/system/etc/unauthorizedsw.txt"

static const char *default_msg = "WE HAVE DETECTED AN ATTEMPT TO FLASH UNAUTHORIZED SW ON YOUR DEVICE. CONTACT CUSTOMER SERVICE FOR ASSISTANCE";
static const char *command = "--show_text\n--show_notes=notes\n";

static char *get_property(const char *prop_name)
{
	char value[PROP_VALUE_MAX];
	hw_property_get(prop_name, value);
	return value[0] ? strdup(value) : NULL;
}

static int create_notes_file(void)
{
	int fo = open("/cache/recovery/notes", O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC, 0600);
	if (fo == -1) {
		ERROR("could not open /cache/recovery/notes\n");
		return -1;
	}
	int fi = open(CARRIER_MSG_FILE, O_RDONLY|O_CLOEXEC);
	if (fi != -1) {
		char buffer[PATH_MAX];
		ssize_t nbytes;
		while ((nbytes = read(fi, buffer, sizeof(buffer))) != 0)
			write(fo, buffer, nbytes);
		close(fi);
	} else
		write(fo, default_msg, strlen(default_msg));
	close(fo);
	return 0;
}

static int reboot_recovery(void)
{
	mkdir("/cache/recovery", 0700);
	if (create_notes_file() == -1)
		return -1;
	int fd = open("/cache/recovery/command", O_RDWR|O_CREAT|O_TRUNC|O_CLOEXEC, 0600);
	if (fd >= 0) {
		write(fd, command, strlen(command) + 1);
		close(fd);
	} else {
		ERROR("could not open /cache/recovery/command\n");
		return -1;
	}
	android_reboot(ANDROID_RB_RESTART2, 0, "recovery");
	while (1) { pause(); }  // never reached
}

#define IS_EMPTY(s) (!s || !strlen(s))

void verify_carrier_compatibility(void)
{
	char *carrier_ro;
	char *oem_carriers;
	char *subsidized_carriers;

	carrier_ro = get_property(CARRIER_RO_PROP);
	if (IS_EMPTY(carrier_ro)) {
		/* ro.carrier is empty - allow to boot */
		pr_debug("property [%s] is empty\n", CARRIER_RO_PROP);
		return;
	}

	oem_carriers = get_property(CARRIER_OEM_PROP);
	subsidized_carriers = get_property(CARRIER_SUBSIDY_PROP);

	if (IS_EMPTY(subsidized_carriers) || !strstr(subsidized_carriers, carrier_ro)) {
		/* ro.carrier is not blacklisted in ro.carrier.subsidized - allow to boot */
		pr_debug("did not find [%s] in [%s]\n", carrier_ro, subsidized_carriers);
                return;
	}

	/* ro.carrier is blacklisted - it must be whitelisted for boot to be allowed */
	if (!IS_EMPTY(oem_carriers) && strstr(oem_carriers, carrier_ro)) {
		/* ro.carrier is whitelisted in ro.carrier.oem - allow to boot */
		pr_debug("found [%s] in [%s]\n", carrier_ro, oem_carriers);
		return;
	}

	NOTICE("[%s] compatibility check failed; rebooting to recovery...\n", carrier_ro);
	reboot_recovery();
}
