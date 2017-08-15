package mtkLogEnhance
import (
	"os"
	"path/filepath"
	"android/soong/android"
	"android/soong/cc"
	"github.com/google/blueprint"
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
	featureValue := android.MtkFeatureValues
	mtkLogEnable := filepath.Join(".", "vendor/mediatek/internal/mtklog_enable")
	if _, err := os.Stat(mtkLogEnable); err == nil { 
		if v, found := featureValue["MTK_ANDROID_LOG_MUCH_COUNT"]; found {
			if v != "" { 
				p.Target.Android.Cflags = append(p.Target.Android.Cflags, "-DANDROID_LOG_MUCH_COUNT")
			}
		}
	}

	if v, found := featureValue["MTK_LOGD_ENHANCE_DISABLE"]; found {
		if v != "yes" { 
			p.Target.Android.Cflags = append(p.Target.Android.Cflags, "-DMTK_LOGD_ENHANCE")
		}
	} else {
		p.Target.Android.Cflags = append(p.Target.Android.Cflags, "-DMTK_LOGD_ENHANCE")
	}
	ctx.AppendProperties(p)
}
func init() {
	android.RegisterModuleType("mtk_log_enhance_defaults", mtkLogEnhanceDefaultsFactory)
}
 
func mtkLogEnhanceDefaultsFactory() (blueprint.Module, []interface{}) {
	module, props := cc.DefaultsFactory()
	android.AddLoadHook(module, mtkLogEnhanceDefaults)
	return module, props
}