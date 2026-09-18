#include <modprobe/module_config.h>

#include <android-base/file.h>
#include <android-base/logging.h>

std::string ModuleConfig::GetKernelCmdline() {
    std::string cmdline;
    if (android::base::ReadFileToString("/proc/cmdline", &cmdline)) {
        return cmdline;
    }
    PLOG(ERROR) << "Could not read kernel command line from /proc/cmdline";
    return "";
}
