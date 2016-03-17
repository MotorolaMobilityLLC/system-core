#if !defined(_XLOG_H)
#define _XLOG_H

#include <cutils/log.h>
#include <cutils/alelog.h>

#ifdef __cplusplus
extern "C" {
#endif

int xlogf_java_tag_is_on(const char *name, int level);
int xlogf_native_tag_is_on(const char *name, int level);

int xlogf_java_xtag_is_on(const char *name, int level);
int xlogf_native_xtag_is_on(const char *name, int level);

extern int is_xlog_enable();

#ifndef XLOG_TAG
#define XLOG_TAG NULL
#endif


struct xlog_record {
	const char *tag_str;
	const char *fmt_str;
	int prio;
};

#if defined(__cplusplus)
extern "C" {
#endif

int __xlog_buf_printf(int bufid, const struct xlog_record *rec, ...);

#if defined(__cplusplus)
}
#endif

#if !defined(HAVE_ALE_FEATURE)

#define xlog_buf_printf(bufid, prio, tag, fmt, ...)			\
	({								\
		static const struct xlog_record _xlog_rec =		\
			{tag, fmt, prio};				\
		__xlog_buf_printf(bufid, &_xlog_rec, ##__VA_ARGS__);	\
	})

#else

#define xlog_buf_printf(bufid, prio, tag, fmt, ...)			\
  ({									\
      static const struct ale_convert ____xlog_ale_rec____ =		\
          { tag, fmt, __FILE__, prio, 0, "" };				\
      ale_log_output(bufid, prio, &____xlog_ale_rec____,		\
                     ##__VA_ARGS__);                                    \
  })

#endif

#define XLOG_PRI(priority, tag, ...)                            \
    xlog_buf_printf(LOG_ID_MAIN, priority, tag, __VA_ARGS__)

#define SXLOG_PRI(priority, tag, ...)                           \
    xlog_buf_printf(LOG_ID_MAIN, priority, tag, __VA_ARGS__)

#define xlog_printf(priority, tag, ...)                         \
    xlog_buf_printf(LOG_ID_MAIN, priority, tag, __VA_ARGS__)

#define sxlog_printf(priority, tag, ...)                        \
    xlog_buf_printf(LOG_ID_SYSTEM, priority, tag, __VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif
