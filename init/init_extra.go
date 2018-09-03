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
    android.AddLoadHook(module, preferBuildRoot)
    android.AddLoadHook(module, preferBuildAee)
    return module
}

func preferBuildRoot(ctx android.LoadHookContext) {
    if envYes(ctx, "MTK_BUILD_ROOT") {
        type props struct {
            Cflags       []string
            Include_dirs []string
        }
        p := &props{}
        p.Cflags = append(p.Cflags, "-DMTK_BUILD_ROOT")
        p.Include_dirs = append(p.Include_dirs, "vendor/mediatek/internal/system/core/init/")
        ctx.AppendProperties(p)
    }
}

func preferBuildAee(ctx android.LoadHookContext) {
    type props struct {
        Cflags       []string
        Include_dirs []string
    }
    vars := ctx.Config().VendorConfig("mtkPlugin")
    if vars.Bool("HAVE_AEE_FEATURE") {
        p := &props{}
        p.Cflags = append(p.Cflags, "-DHAVE_AEE_FEATURE")
        p.Include_dirs = append(p.Include_dirs, "vendor/mediatek/proprietary/external/aee/binary/inc/")
        ctx.AppendProperties(p)
    }
}

//get FO from command line
func envYes(ctx android.BaseContext, key string) bool {
    return ctx.AConfig().Getenv(key) == "yes"
}

func envNo(ctx android.BaseContext, key string) bool {
    return ctx.AConfig().Getenv(key) == "no"
}
