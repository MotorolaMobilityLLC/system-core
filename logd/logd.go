package mtkLogEnhance
import (
	"os"
	"path/filepath"
	"android/soong/android"
	"android/soong/cc"
)

func mtkLogdEnhanceDefaults(ctx android.LoadHookContext) {
	type props struct {
		Cflags           []string
		Include_dirs     []string
		Shared_libs      []string
		Init_rc          []string
		Header_libs      []string
	}
	p := &props{}

	vars := ctx.Config().VendorConfig("mtkPlugin")
	if vars.Bool("MSSI_HAVE_AEE_FEATURE") {
		p.Cflags = append(p.Cflags, "-DMSSI_HAVE_AEE_FEATURE")
		p.Header_libs = append(p.Header_libs, "libaed_headers")
		p.Shared_libs = append(p.Shared_libs, "libaed")
	}

	mtkLogEnable := filepath.Join(".", "vendor/mediatek/internal/mtklog_enable")
	if _, err := os.Stat(mtkLogEnable); err == nil {

		p.Init_rc = append(p.Init_rc, "logd_e.rc")
		if (vars.String("TARGET_BUILD_VARIANT") == "eng") {
			p.Cflags = append(p.Cflags, "-DANDROID_LOG_MUCH_COUNT=" + "4000")
		} else {
			p.Cflags = append(p.Cflags, "-DANDROID_LOG_MUCH_COUNT=" + "500")
		}
	}

	if (vars.String("TARGET_BUILD_VARIANT") == "eng") {
		p.Cflags = append(p.Cflags, "-DMTK_LOGD_DEBUG")
	}

	if (vars.String("TARGET_BUILD_VARIANT") == "eng") {
		p.Cflags = append(p.Cflags, "-DCONFIG_MT_DEBUG_BUILD")
		p.Cflags = append(p.Cflags, "-DLOGD_FORCE_DIRECTCOREDUMP")
	} else if (vars.String("TARGET_BUILD_VARIANT") == "userdebug") {
		p.Cflags = append(p.Cflags, "-DCONFIG_MT_DEBUG_BUILD")
		p.Cflags = append(p.Cflags, "-DLOGD_FORCE_DIRECTCOREDUMP")
	}

	if (vars.String("MTK_LOGD_ENHANCE_DISABLE") == "") ||
		(vars.String("MTK_LOGD_ENHANCE_DISABLE") != "yes") {
		p.Cflags = append(p.Cflags, "-DMTK_LOGD_ENHANCE")
		p.Cflags = append(p.Cflags, "-DMTK_LOGD_FILTER")
	}

	ctx.AppendProperties(p)
}
func init() {
	android.RegisterModuleType("mtk_logdEnhance_defaults", mtkLogdEnhanceDefaultsFactory)
}

func mtkLogdEnhanceDefaultsFactory() android.Module {
	module := cc.DefaultsFactory()
	android.AddLoadHook(module, mtkLogdEnhanceDefaults)
	return module
}
