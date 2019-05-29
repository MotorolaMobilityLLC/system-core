package libinit

import (
    "android/soong/android"
    "android/soong/cc"
)

func init() {
    android.RegisterModuleType("mtk_init_extra_defaults", mtkInitExtraDefaultsFactory)
}

func mtkInitExtraDefaultsFactory() android.Module {
    module := cc.DefaultsFactory()
    android.AddLoadHook(module, preferBuildAee)
    return module
}

func preferBuildAee(ctx android.LoadHookContext) {
    type props struct {
        Cflags       []string
        Include_dirs []string
        Header_libs  []string
    }
    vars := ctx.Config().VendorConfig("mtkPlugin")
    if vars.Bool("MSSI_HAVE_AEE_FEATURE") {
        p := &props{}
        p.Cflags = append(p.Cflags, "-DMSSI_HAVE_AEE_FEATURE")
        p.Header_libs = append(p.Header_libs, "libaed_headers")
        ctx.AppendProperties(p)
    }
}
