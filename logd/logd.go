package mtkLogEnhance
import (
	"os"
	"path/filepath"
	"android/soong/android"
	"android/soong/cc"
	"android/soong/android/mediatek"

	"github.com/google/blueprint/proptools"
)

func mtkLogdEnhanceDefaults(ctx android.LoadHookContext) {
	type props struct {
		Cflags           []string
		Include_dirs     []string
		Shared_libs      []string
		Init_rc          []string
	}
	p := &props{}
	//featureValue := android.MtkFeatureValues

	if mediatek.GetFeature("HAVE_AEE_FEATURE") == "" {
		p.Cflags = append(p.Cflags, "-DHAVE_AEE_FEATURE")
		p.Include_dirs = append(p.Include_dirs, "vendor/mediatek/proprietary/external/aee/binary/inc/")
		p.Shared_libs = append(p.Shared_libs, "libaed")
	}

	mtkLogEnable := filepath.Join(".", "vendor/mediatek/internal/mtklog_enable")
	if _, err := os.Stat(mtkLogEnable); err == nil {
		/*
		if v, found := featureValue["MTK_ANDROID_LOG_MUCH_COUNT"]; found {
			if v != "" {
				p.Cflags = append(p.Cflags, "-DANDROID_LOG_MUCH_COUNT")
				p.Init_rc = append(p.Init_rc, "logd_e.rc")
				if v1, found := featureValue["TARGET_BUILD_VARIANT"]; found {
					if v1 == "eng" {
						p.Cflags = append(p.Cflags, "-DANDROID_LOG_MUCH_COUNT=" + v)
					} else {
						p.Cflags = append(p.Cflags, "-DANDROID_LOG_MUCH_COUNT=" + "500")
					}
				}
			}
		}*/
		if v := mediatek.GetFeature("MTK_ANDROID_LOG_MUCH_COUNT"); v != "" {
			p.Init_rc = append(p.Init_rc, "logd_e.rc")
			if proptools.Bool(ctx.AConfig().ProductVariables.Eng) {
				p.Cflags = append(p.Cflags, "-DANDROID_LOG_MUCH_COUNT=" + v)
			} else {
				p.Cflags = append(p.Cflags, "-DANDROID_LOG_MUCH_COUNT=" + "500")
			}
		} else {
			p.Init_rc = append(p.Init_rc, "logd.rc")
		}
	}

	if proptools.Bool(ctx.AConfig().ProductVariables.Eng) {
		p.Cflags = append(p.Cflags, "-DMTK_LOGD_DEBUG")
	}

	if (mediatek.GetFeature("MTK_LOGD_ENHANCE_DISABLE") == "") ||
		(mediatek.GetFeature("MTK_LOGD_ENHANCE_DISABLE") != "yes") {
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

