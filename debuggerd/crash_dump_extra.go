package libcrashdump

import (
    "android/soong/android"
    "android/soong/cc"
)

func init() {
    android.RegisterModuleType("mtk_crash_dump_extra_defaults", mtkCrashdumpExtraDefaultsFactory)
    android.RegisterModuleType("mtk_crash_dump_extra_simple", mtkCrashdumpExtraSimpleFactory)
}

func mtkCrashdumpExtraDefaultsFactory() android.Module {
    module := cc.DefaultsFactory()
    android.AddLoadHook(module, preferBuildAeeforCrashdump)
    return module
}

func mtkCrashdumpExtraSimpleFactory() android.Module {
    module := cc.DefaultsFactory()
    android.AddLoadHook(module, preferBuildAeeforTombstone)
    return module
}

func preferBuildAeeforCrashdump(ctx android.LoadHookContext) {
    type props struct {
        Cflags       []string
        Include_dirs []string
        Header_libs  []string
        Static_libs  []string
        Shared_libs  []string
    }
    vars := ctx.Config().VendorConfig("mtkPlugin")
    if vars.Bool("MSSI_HAVE_AEE_FEATURE") {
        p := &props{}
        p.Cflags = append(p.Cflags, "-DMSSI_HAVE_AEE_FEATURE")
        p.Header_libs = append(p.Header_libs, "libaed_minidump_headers")
        p.Static_libs = append(p.Static_libs, "libaed_crashdump_static_mtk")
        p.Shared_libs = append(p.Shared_libs, "libz")
        ctx.AppendProperties(p)
    }
}

func preferBuildAeeforTombstone(ctx android.LoadHookContext) {
    type props struct {
        Cflags       []string
    }
    vars := ctx.Config().VendorConfig("mtkPlugin")
    if vars.Bool("MSSI_HAVE_AEE_FEATURE") {
        p := &props{}
        p.Cflags = append(p.Cflags, "-DMSSI_HAVE_AEE_FEATURE")
        ctx.AppendProperties(p)
    }
}
