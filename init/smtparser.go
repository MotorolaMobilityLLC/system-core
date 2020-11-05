package  smtparser

import (
        "android/soong/android"
        "android/soong/cc"
)

func init() {
    // resister a module "smtparser_defaults"
    android.RegisterModuleType("smtparser_defaults", smtdroidDefaultsFactory)
}

func smtdroidDefaultsFactory() (android.Module) {
    module := cc.DefaultsFactory()
    android.AddLoadHook(module, smtdroidDefaults)
    return module
}

func smtdroidDefaults(ctx android.LoadHookContext) {
   type props struct {
        Cflags []string
    }
    p := &props{}
    p.Cflags = globalDefaults(ctx)
    ctx.AppendProperties(p)
}

func globalDefaults(ctx android.BaseContext) ([]string) {
    var cppflags []string
    if ctx.AConfig().Getenv("BUILD_SMT") == "YES" {
          cppflags = append(cppflags,"-DSMT_MODE")
    }
    return cppflags
}


