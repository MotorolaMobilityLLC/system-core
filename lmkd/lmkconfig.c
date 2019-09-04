#define LOG_TAG "lowmemorykiller"
#define LOG_NDEBUG 0

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/cdefs.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#include <cutils/properties.h>
#include <cutils/log.h>

#define LMKD_PARAMETER_NAME 		"/vendor/etc/lmkd_param.conf"

#define TITLE_KEY_WORDS			"####TITLE_"
#define MAX_LMKD_PARAM_COUNT 		8
#define MAX_TITLE_LEN 			64
#define MAX_PROC_PARAM_COUNT 		32
#define MAX_PROC_NAME_LEN 		128

/* different config will be add as ####TITLE_****** */
#define CONFIG_LMKD_SKILL_PROCESS_LIST          "LMKD_SKILL_PROCESS_LIST"
#define CONFIG_OTHER				"OTHER"

typedef struct procinfo {
	int proc_count;
	char task_info[MAX_PROC_NAME_LEN] ;
}PROC_INFO, *PPROC_INFO;

typedef struct paraminfo {
	int proc_count;
	int para_number;
	char param_title[MAX_TITLE_LEN];
	PROC_INFO proc_info[MAX_PROC_PARAM_COUNT];
}PARAM_INFO, *PPARAM_INFO;

typedef struct cfginfo{
    int cfg_count;
    PARAM_INFO param_info[MAX_LMKD_PARAM_COUNT];
}CFG_INFO, *PCFG_INFO;

extern ssize_t read_all(int fd, char *buf, size_t max_len);

static CFG_INFO g_cfg_info;

static bool get_param_info(PARAM_INFO *param_info, char *title)
{
	int count = 0;
	int number = 0;
	CFG_INFO *cfg_info = &g_cfg_info;

	if (!param_info || !title)
		return false;

	count = cfg_info->cfg_count;
	while(count) {
		number = count - 1;
		if (!memcmp(cfg_info->param_info[number].param_title,
				       title, strlen(cfg_info->param_info[number].param_title))) {
			memcpy(param_info, &cfg_info->param_info[number], sizeof(PARAM_INFO));
			return true;
		}
		count --;
	}

	return false;
}

static void dump_cfg_info()
{
	int count = 0;
	int num_param = 0;
	int num_proc = 0;
	CFG_INFO *cfg_info = &g_cfg_info;
	PARAM_INFO *param_info;
	PROC_INFO *proc_info;

	ALOGE("############# dump cfg info %d #############", cfg_info->cfg_count);
	for  (count=0;count<cfg_info->cfg_count; count++) {
		param_info = &cfg_info->param_info[count];
		num_param = param_info->para_number;
		ALOGD("param_info->proc_count %d, %d:%s\n", param_info->proc_count, param_info->para_number, param_info->param_title);
		for (num_proc =0; num_proc<param_info->proc_count;num_proc++) {
			proc_info  = &param_info->proc_info[num_proc];
			ALOGE("%d:%s\n", num_proc,proc_info ->task_info);
		}
	}
	ALOGE("############# dump cfg info end #############");
}

static bool lmkd_config_is_title(char *line, char *title)
{
	char *ret = line;
	int linelen = 0;
	int reallen = 0;

	if (!ret || !title)
		return false;

	ret = strstr(line, TITLE_KEY_WORDS);
	if (ret) {
		ALOGE("new title is %s, %zu, %zu, %s",
			 ret, strlen(ret), strlen(TITLE_KEY_WORDS),ret+strlen(TITLE_KEY_WORDS));
		linelen = strlen(ret)-strlen(TITLE_KEY_WORDS);
		reallen =  (MAX_TITLE_LEN-1)>linelen?linelen:MAX_TITLE_LEN-1;
		memcpy(title, ret+strlen(TITLE_KEY_WORDS), reallen);
		title[reallen] = '\0';
		return true;
	}
	return false;
}

static void lmkd_config_parse_line(char *line, CFG_INFO *cfg_info, int line_number)
{
    char *string = line;
    int count = 0;
    int number = 0;
    int reallen = 0;
    char *temp_ptr;
    char title_name[MAX_TITLE_LEN];
    char *proc_name;

    memset(title_name, 0, sizeof(title_name));

    if (lmkd_config_is_title(line, title_name)) {
	/* it is item */
	if (!cfg_info) {
		ALOGE("title_name is %s but param_info is NULL", title_name);
		return;
	}
	count = cfg_info->cfg_count;
	memcpy(cfg_info->param_info[count].param_title, title_name, sizeof(title_name));
	cfg_info->param_info[count].para_number = count;
	cfg_info->cfg_count++;
	ALOGD("num %d tilte is:%s",  cfg_info->cfg_count, title_name);
    } else {
	/*it is string */
	if (!cfg_info) {
		ALOGE("string is %s but there is no buffer", title_name);
		return;
	}
	if (cfg_info->cfg_count < 1)  {
		ALOGE("there is no title before line(%d), ignore this string: %s", line_number, line);
		return;
	}
	count = cfg_info->param_info[cfg_info->cfg_count -1].proc_count;
	number = count;
	cfg_info->param_info[cfg_info->cfg_count -1].proc_info[number].proc_count = number;
	proc_name = cfg_info->param_info[cfg_info->cfg_count -1].proc_info[number].task_info;
	reallen = MAX_PROC_NAME_LEN > strlen(line)? strlen(line):(MAX_PROC_NAME_LEN-1);
	memcpy(proc_name, line, reallen);
	count ++;
	cfg_info->param_info[cfg_info->cfg_count -1].proc_count = count;
	return;
    }
}

static int lmkd_config_load(CFG_INFO *cfg_info)
{
    int fd;
    int line_number = 0;
    ssize_t size;
    char buf[PAGE_SIZE];
    char *save_ptr;
    char *line;

    fd = open(LMKD_PARAMETER_NAME, O_RDONLY | O_CLOEXEC);
    if (fd == -1) {
        ALOGE("%s open: errno=%d", LMKD_PARAMETER_NAME, errno);
        return -1;
    }

    size = read_all(fd, buf, sizeof(buf) - 1);
    if (size < 0) {
        ALOGE("%s read: errno=%d", LMKD_PARAMETER_NAME, errno);
        close(fd);
        return -1;
    }
    buf[size] = '\0';

    line = strtok_r(buf, "\n", &save_ptr);
    while(line) {
	ALOGE("file %s line %d string is %s", LMKD_PARAMETER_NAME, line_number, line);
	line = strtok_r(NULL, "\n", &save_ptr);
	if (line)
		lmkd_config_parse_line(line, cfg_info, line_number);
	line_number++;
    }

    close(fd);
    return 0;
}

/* For CONFIG_LMKD_SKILL_PROCESS_LIST */
bool lmkd_config_skip_kill(char *task_name)
{
	PARAM_INFO param_info;
	int count = 0;
	int number = 0;

	memset(&param_info, 0, sizeof(param_info));
	if (get_param_info(&param_info, CONFIG_LMKD_SKILL_PROCESS_LIST) == true) {
		count = param_info.proc_count;
		while(count) {
			number = count - 1;
			if (!memcmp(param_info.proc_info[number].task_info, task_name, strlen(param_info.proc_info[number].task_info) -1))
				return true;
			count --;
		}
	}
	return false;
}

int lmkd_config_init(void)
{
	CFG_INFO *cfg_info = &g_cfg_info;
	ALOGE("lmkd_config_init");
	memset(cfg_info, 0, sizeof(cfg_info));
	lmkd_config_load(cfg_info);
	dump_cfg_info();
	return 0;
}
