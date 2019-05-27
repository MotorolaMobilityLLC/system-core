package gatekeeper

import (
        "android/soong/android"
        "android/soong/cc"
        "fmt"
)

func init() {
    android.RegisterModuleType("gatekeeper_cppflags", gatekeeperDefaultsFactory)
}

func gatekeeperDefaultsFactory() (android.Module) {
    module := cc.DefaultsFactory()
    android.AddLoadHook(module, gatekeeperDefaults)
    return module
}

func gatekeeperDefaults(ctx android.LoadHookContext) {
    type props struct {
        Cppflags []string
    }
    p := &props{}
    p.Cppflags = globalDefaults(ctx)
    ctx.AppendProperties(p)
}

func globalDefaults(ctx android.BaseContext) ([]string) {
    var cppflags []string

    vars := ctx.Config().VendorConfig("gatekeeper")
    if vars.Bool("software") {
      fmt.Println("software gatekeeper")
      cppflags = append(cppflags,"-DUSE_SOFTWARE_GATEKEEPER=1")
    }else{
      fmt.Println("hardware gatekeeper")
    }
    return cppflags
}