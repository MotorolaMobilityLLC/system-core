#ifndef _INIT_HW_TAGS_H_
#define _INIT_HW_TAGS_H_

#include "property_service.h"

namespace android {
namespace init {

int process_hw_mappings(const char *xml_name);
void verify_carrier_compatibility(void);

} //namesapce init
} //namespace android
#endif
