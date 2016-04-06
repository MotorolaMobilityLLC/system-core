#ifndef _INIT_HW_TAGS_H_
#define _INIT_HW_TAGS_H_

#include <sys/system_properties.h>

int process_hw_mappings(const char *xml_name);

extern int __system_property_get(const char *name, char *value);
extern int property_set(const char *name, const char *value);

#endif
