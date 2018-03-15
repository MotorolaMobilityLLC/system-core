#ifndef _INIT_HW_TAGS_H_
#define _INIT_HW_TAGS_H_

#include "property_service.h"

namespace android {
namespace init {

#if defined(NO_HW_MAPPING)
static inline int process_hw_mappings(const char *xml_name) {
	return 0;
}
#else
int process_hw_mappings(const char *xml_name);
#endif

void verify_carrier_compatibility(void);

} //namesapce init
} //namespace android
#endif
