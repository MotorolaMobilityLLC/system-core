#include <modprobe/module_config.h>

#include "module_config_test.h"

std::string ModuleConfig::GetKernelCmdline(void) {
    return kernel_cmdline;
}
