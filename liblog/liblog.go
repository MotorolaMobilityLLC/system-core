package mtkLogEnhance

import (
	"os"

	"android/soong/android"
	"android/soong/cc"
)

func mtkLogEnhanceDefaults(ctx android.LoadHookContext) {
	type props struct {
		Target struct {
			Android struct {
				Cflags []string
			}
		}
	}
	p := &props{}
	vars := ctx.Config().VendorConfig("mtkPlugin")

	if !vars.Bool("MTK_LOGD_ENHANCE_DISABLE") {
		p.Target.Android.Cflags = append(p.Target.Android.Cflags, "-DMTK_LOGD_ENHANCE")
		if !vars.Bool("MTK_LOGDW_SOCK_BLOCK_DISABLE") {
			p.Target.Android.Cflags = append(p.Target.Android.Cflags, "-DMTK_LOGDW_SOCK_BLOCK")
		}
		if !vars.Bool("MTK_LOGD_FILTER_DISABLE") {
			p.Target.Android.Cflags = append(p.Target.Android.Cflags, "-DMTK_LOGD_FILTER")
		}
		if _, err := os.Stat("vendor/mediatek/internal/mtklog_enable"); err == nil {
			p.Target.Android.Cflags = append(p.Target.Android.Cflags, "-DANDROID_LOG_MUCH_COUNT")
		}
	}
	ctx.AppendProperties(p)
}

func init() {
	android.RegisterModuleType("mtk_log_enhance_defaults", mtkLogEnhanceDefaultsFactory)
}

func mtkLogEnhanceDefaultsFactory() android.Module {
	module := cc.DefaultsFactory()
	android.AddLoadHook(module, mtkLogEnhanceDefaults)
	return module
}
