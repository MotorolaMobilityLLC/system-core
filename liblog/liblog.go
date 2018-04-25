package mtkLogEnhance
import (
	"os"
	"path/filepath"
	"android/soong/android"
	"android/soong/cc"
	"android/soong/android/mediatek"
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

	if mtkFoFalse("MTK_LOGD_ENHANCE_DISABLE") {
		p.Target.Android.Cflags = append(p.Target.Android.Cflags, "-DMTK_LOGD_ENHANCE")
		if mtkFoFalse("MTK_LOGDW_SOCK_BLOCK_DISABLE") {
			p.Target.Android.Cflags = append(p.Target.Android.Cflags, "-DMTK_LOGDW_SOCK_BLOCK")
		}
		if mtkFoFalse("MTK_LOGD_FILTER_DISABLE") {
			p.Target.Android.Cflags = append(p.Target.Android.Cflags, "-DMTK_LOGD_FILTER")
		}
		mtkLogEnable := filepath.Join(".", "vendor/mediatek/internal/mtklog_enable")
		if _, err := os.Stat(mtkLogEnable); err == nil {
			if mediatek.GetFeature("MTK_ANDROID_LOG_MUCH_COUNT") != "" {
				p.Target.Android.Cflags = append(p.Target.Android.Cflags, "-DANDROID_LOG_MUCH_COUNT")
			}
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

func mtkFoTure(key string) bool {
	return mediatek.GetFeature(key) == "yes"
}

func mtkFoFalse(key string) bool {
	return mediatek.GetFeature(key) != "yes"
}

