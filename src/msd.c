/*-
 * Copyright (c) 2011 - 2021 Rozhuk Ivan <rozhuk.im@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * Author: Rozhuk Ivan <rozhuk.im@gmail.com>
 *
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/tcp.h>

#include <err.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h> /* snprintf, fprintf */
#include <time.h>
#include <string.h> /* bcopy, bzero, memcpy, memmove, memset, strerror... */
#include <stdlib.h> /* malloc, exit */
#include <unistd.h> /* close, write, sysconf */
#include <fcntl.h> /* open, fcntl */

#include "utils/mem_utils.h"
#include "utils/str2num.h"
#include "utils/strh2num.h"
#include "proto/http.h"
#include "utils/xml.h"

#include "utils/macro.h"
#include "utils/io_buf.h"
#include "net/socket.h"
#include "net/socket_address.h"
#include "net/utils.h"
#include "threadpool/threadpool_task.h"
#include "utils/buf_str.h"
#include "utils/sys.h"
#include "utils/log.h"
#include "proto/http_server.h"
#include "utils/info.h"
#include "utils/cmd_line_daemon.h"
#include "utils/sys_res_limits_xml.h"

#include "msd_stat_text.h"
#include "stream_hub.h"

#include <config.h>
#define CFG_FILE_MAX_SIZE	(10 * 1024 * 1024)



typedef struct prog_service_s {
	uint32_t		enabled;
	str_hub_settings_t	hub_params; /* Stream hub params. */
	str_src_settings_t	src_params; /* Stream hub source params. */
	str_src_conn_params_t	src_conn_params; /* Stream hub source connection params. */
} prog_service_t, *prog_service_p;

typedef struct prog_settings {
	tp_p		tp;
	tp_udata_t	load_tmr;
	http_srv_p	http_srv;	/* HTTP server. */
	str_hubs_bckt_p shbskt;		/* Stream hubs. */

	uint8_t		sysinfo[1024];	/* System info */
	uint8_t		syslimits[1024]; /* System limits */
	size_t		sysinfo_size;	/* System info size */
	size_t		syslimits_size;	/* System limits size */
	info_sysres_t	sysres;	/* System resources statistic data. */

	/* HTTP Multicast client request limits and defaults. */
	size_t		cli_precache_min;
	size_t		cli_precache_max;
	size_t		cli_snd_block_min;
	size_t		cli_snd_block_max;

	prog_service_t	multicast;
	prog_service_t	http;
	prog_service_t	transparent;

	uintptr_t	log_fd;		// log file descriptor
	uint8_t		*cfg_file_buf;
	size_t		cfg_file_buf_size;
	time_t		licence_eol;
	cmd_line_data_t	cmd_line_data;	/*  */
} prog_settings_t, *prog_settings_p;
static prog_settings_t g_data;


int	msd_xxx_profile_find(const uint8_t *buf, size_t buf_size, const char *xxx1,
	    const char *xxx2, const uint8_t *name, size_t name_size,
	    const uint8_t **data_ret, size_t *data_size_ret);
int	msd_hub_profile_load(const uint8_t *buf, size_t buf_size,
	    const uint8_t *name, size_t name_size, str_hub_settings_p params);
int	msd_src_profile_load(const uint8_t *buf, size_t buf_size,
	    const uint8_t *name, size_t name_size, uint32_t type, str_src_settings_p params);
int	msd_src_conn_profile_load(const uint8_t *buf, size_t buf_size,
	    const uint8_t *name, size_t name_size, uint32_t type, void *conn_params);
int	msd_prog_service_load(const uint8_t *buf, size_t buf_size, const char *name,
	    uint32_t type, prog_service_p srv);
int	msd_channel_load(prog_settings_p ps, const uint8_t *cfg_file_buf,
	    size_t cfg_file_buf_size, const uint8_t *data, size_t data_size);
void	msd_load_timer_cb(tp_event_p ev, tp_udata_p tp_udata);


int	msd_hub_cli_alloc_from_http(http_srv_cli_p cli, uint32_t cli_sub_type,
	    str_hub_cli_p *strh_cli_ret);
int	msd_hub_attach_cli(str_hubs_bckt_p shbskt, const uint8_t *name, size_t name_size,
	    http_srv_cli_p cli, uint32_t cli_sub_type, str_hub_settings_p hub_s,
	    uint32_t src_type, str_src_settings_p src_s);
uint32_t msd_http_req_url_parse(int type, http_srv_req_p req,
	    const uint8_t **str_addr, size_t *str_addr_size,
	    sockaddr_storage_p ssaddr,
	    uint32_t *if_index, uint32_t *rejoin_time,
	    uint8_t *hub_name, size_t hub_name_size,
	    size_t *hub_name_size_ret);
#define REQ_URL_TYPE_UDP	1
#define REQ_URL_TYPE_HTTP	2
#define REQ_URL_TYPE_HTTP_TRANSP 3

int	msd_http_srv_on_conn_cb(http_srv_bind_p acc, void *srv_udata,
	    uintptr_t skt, sockaddr_storage_p addr,
	    tpt_p *tpt, http_srv_cli_ccb_p ccb, void **udata);
void	msd_http_srv_on_destroy_cb(http_srv_cli_p cli, void *udata, http_srv_resp_p resp);
int	msd_http_srv_on_req_rcv_cb(http_srv_cli_p cli, void *udata,
	    http_srv_req_p req, http_srv_resp_p resp);
int	msd_http_srv_on_rep_snd_cb(http_srv_cli_p cli, void *udata, http_srv_resp_p resp);

int	msd_str_hub_cli_free_cb(str_hub_cli_p strh_cli, tp_task_p tptask,
	    void *udata);


#define MSD_CFG_CALC_VAL_COUNT(args...)					\
	xml_calc_tag_count_args(cfg_file_buf, cfg_file_buf_size,	\
	    (const uint8_t*)"msd", ##args)
#define MSD_CFG_GET_VAL_DATA(next_pos, data, data_size, args...)	\
	xml_get_val_args(cfg_file_buf, cfg_file_buf_size, next_pos,	\
	    NULL, NULL, data, data_size, (const uint8_t*)"msd", ##args)
#define MSD_CFG_GET_VAL_UINT(next_pos, val_ret, args...)		\
	xml_get_val_uint32_args(cfg_file_buf, cfg_file_buf_size, next_pos, \
	    val_ret, (const uint8_t*)"msd", ##args)
#define MSD_CFG_GET_VAL_SIZE(next_pos, val_ret, args...)		\
	xml_get_val_size_t_args(cfg_file_buf, cfg_file_buf_size, next_pos, \
	    val_ret, (const uint8_t*)"msd", ##args)



int
msd_xxx_profile_find(const uint8_t *buf, size_t buf_size,
    const char *xxx1, const char *xxx2, 
    const uint8_t *name, size_t name_size, const uint8_t **data_ret, size_t *data_size_ret) {
	const uint8_t *data, *ptm, *cur_pos;
	size_t data_size, tm;
	int found;

	if (NULL == buf || 0 == buf_size || NULL == xxx1 || NULL == xxx2 ||
	    NULL == name || 0 == name_size)
		return (EINVAL);

	found = 0;
	cur_pos = NULL;
	while (0 == xml_get_val_args(buf, buf_size, &cur_pos, NULL, NULL,
	    &data, &data_size, (const uint8_t*)"msd", xxx1, xxx2, NULL)) {
		if (0 != xml_get_val_args(data, data_size, NULL, NULL, NULL,
		    &ptm, &tm, (const uint8_t*)"name", NULL) ||
		    0 != mem_cmpn(ptm, tm, name, name_size))
			continue;
		found = 1;
		break;
	}
	if (0 == found)
		return (ENOENT);

	if (NULL != data_ret) {
		(*data_ret) = data;
	}
	if (NULL != data_size_ret) {
		(*data_size_ret) = data_size;
	}
	return (0);
}

int
msd_hub_profile_load(const uint8_t *buf, size_t buf_size,
    const uint8_t *name, size_t name_size, str_hub_settings_p params) {
	const uint8_t *data;
	size_t data_size;
	int error;

	if (NULL == buf || 0 == buf_size || NULL == params)
		return (EINVAL);

	if (NULL == name || 0 == name_size) {
		data = buf;
		data_size = buf_size;
	} else { /* Try find and load by name. */
		error = msd_xxx_profile_find(buf, buf_size, "hubProfileList",
		    "hubProfile", name, name_size, &data, &data_size);
		if (0 != error)
			return (error);
	}

	return (str_hub_xml_load_settings(data, data_size, params));
}

int
msd_src_profile_load(const uint8_t *buf, size_t buf_size,
    const uint8_t *name, size_t name_size,
    uint32_t type __unused, str_src_settings_p s) {
	const uint8_t *data;
	size_t data_size;
	int error;

	if (NULL == buf || 0 == buf_size || NULL == s)
		return (EINVAL);

	if (NULL == name || 0 == name_size) {
		data = buf;
		data_size = buf_size;
	} else { /* Try find and load by name. */
		error = msd_xxx_profile_find(buf, buf_size, "sourceProfileList",
		    "sourceProfile", name, name_size, &data, &data_size);
		if (0 != error)
			return (error);
	}

	return (str_src_xml_load_settings(data, data_size, s));
}

int
msd_src_conn_profile_load(const uint8_t *buf, size_t buf_size,
    const uint8_t *name, size_t name_size, uint32_t type, void *conn) {
	const uint8_t *data;
	size_t data_size;
	int error;

	if (NULL == buf || 0 == buf_size || NULL == conn)
		return (EINVAL);

	/* Try find and load by name. */
	if (NULL == name || 0 == name_size) {
		data = buf;
		data_size = buf_size;
	} else { /* Try find and load by name. */
		error = msd_xxx_profile_find(buf, buf_size, "sourceProfileList",
		    "sourceProfile", name, name_size, &data, &data_size);
		if (0 != error)
			return (error);
	}
	return (str_src_conn_xml_load_settings(data, data_size, type, conn));
}


int
msd_prog_service_load(const uint8_t *buf, size_t buf_size, const char *name,
    uint32_t type, prog_service_p srv) {
	const uint8_t *ptm;
	size_t tm;

	if (NULL == buf || 0 == buf_size || NULL == srv)
		return (EINVAL);
	mem_bzero(srv, sizeof(prog_service_t));

	/* Read from config. */
	if (0 == xml_get_val_args(buf, buf_size, NULL, NULL, NULL, &ptm, &tm,
	    (const uint8_t*)"msd", "streamProxy", name, "fEnable", NULL)) {
		yn_set_flag32(ptm, tm, 1, &srv->enabled);
	}
	/* Stream hub params. */
	str_hub_settings_def(&srv->hub_params);
	/* hubProfileName - load hub params from template. */
	if (0 == xml_get_val_args(buf, buf_size, NULL, NULL, NULL,
	    &ptm, &tm,
	    (const uint8_t*)"msd", "streamProxy", name, "hubProfileName", NULL)) {
		msd_hub_profile_load(buf, buf_size,
		    ptm, tm, &srv->hub_params);
	}
	/* Stream source params. */
	str_src_settings_copy(&srv->src_params, &srv->hub_params.str_src_settings);
	str_src_conn_def(type, &srv->src_conn_params);
	/* sourceProfileName - load source params from template. */
	if (0 == xml_get_val_args(buf, buf_size,
	    NULL, NULL, NULL, &ptm, &tm,
	    (const uint8_t*)"msd", "streamProxy", name, "sourceProfileName", NULL)) {
		msd_src_profile_load(buf, buf_size,
		    ptm, tm, type, &srv->src_params);
		msd_src_conn_profile_load(buf, buf_size,
		   ptm, tm, type, &srv->src_conn_params);
		if (STR_SRC_TYPE_TCP_HTTP == type) { /* Do some cleanup. */
			srv->src_conn_params.tcp.host = NULL;
			srv->src_conn_params.tcp.host_size = 0;
			srv->src_conn_params.http.url_path = NULL;
			srv->src_conn_params.http.url_path_size = 0;
		}
	}

	return (0);
}

int
msd_channel_load(prog_settings_p ps, const uint8_t *cfg_file_buf, size_t cfg_file_buf_size,
    const uint8_t *data, size_t data_size) {
	int error;
	const uint8_t *ptm, *src_data, *cur_pos;
	size_t tm, hub_name_size, src_data_size;
	uint32_t tm32;
	uint8_t hub_name[STR_HUB_NAME_MAX_SIZE];
	str_hub_settings_p hub_params;
	str_src_settings_p src_params;
	str_src_settings_t src_s_local;
	str_src_conn_params_p src_conn_params;

	if (NULL == ps || NULL == cfg_file_buf || 0 == cfg_file_buf_size ||
	    NULL == data || 0 == data_size)
		return (EINVAL);
	hub_params = zalloc(sizeof(str_hub_settings_t));
	if (NULL == hub_params) {
		error = ENOMEM;
		goto err_out;
	}
	/* name */
	if (0 != xml_get_val_args(data, data_size, NULL, NULL, NULL,
	    &ptm, &tm, (const uint8_t*)"name", NULL) ||
	    (STR_HUB_NAME_MAX_SIZE - 10) < tm) {
		error = EINVAL;
		goto err_out;
	}
	tm = MIN(tm, (sizeof(hub_name) - 10));
	memcpy(hub_name, "/channel/", 9);
	memcpy((hub_name + 9), ptm, tm);
	hub_name_size = (tm + 9);
	hub_name[hub_name_size] = 0;
	LOG_INFO_FMT("Channel name: %s", hub_name);

	/* Stream hub params. */
	str_hub_settings_def(hub_params);
	/* hubProfileName - load hub params from template. */
	if (0 == xml_get_val_args(data, data_size, NULL, NULL, NULL,
	    &ptm, &tm, (const uint8_t*)"hubProfileName", NULL)) {
		msd_hub_profile_load(cfg_file_buf, cfg_file_buf_size,
		    ptm, tm, hub_params);
	}
	/* Load hub params from channel section. */
	str_hub_xml_load_settings(data, data_size, hub_params);
	/* Save copy. */
	str_src_settings_copy(&src_s_local, &hub_params->str_src_settings);
	/* Overwrite some stream hub flags. */
	hub_params->flags |= (STR_HUB_S_F_ZERO_CLI_PERSISTENT | STR_HUB_S_F_ZERO_SRC_BITRATE_PERSISTENT);
	/* Create and set. */
	error = str_hub_send_msg(ps->shbskt, hub_name, hub_name_size,
	    STR_HUB_CMD_CREATE, hub_params, sizeof(hub_params));
	if (0 != error) {
		LOG_ERR_FMT(error, "%s: str_hub_send_msg(STR_HUB_CMD_CREATE)", hub_name);
		goto err_out;
	}

	/* Stream hub sources. */
	cur_pos = NULL;
	while (0 == xml_get_val_args(data, data_size, &cur_pos, NULL, NULL,
	    &src_data, &src_data_size,
	    (const uint8_t*)"sourceList", "source", NULL)) {
		/* type */
		if (0 != xml_get_val_args(src_data, src_data_size,
		    NULL, NULL, NULL, &ptm, &tm,
		    (const uint8_t*)"type", NULL))
			continue;
		tm32 = str_src_get_type_from_str((char*)ptm, tm);
		if (STR_SRC_TYPE_UNKNOWN == tm32)
			continue;

		src_params = malloc(sizeof(str_src_settings_t));
		src_conn_params = malloc(sizeof(str_src_conn_params_t));
		if (NULL == src_params || NULL == src_conn_params) {
			free(src_params);
			free(src_conn_params);
			error = ENOMEM;
			LOG_ERR_FMT(error, "%s: malloc(src_params) fail.", hub_name);
			continue;
		}
		/* Stream source params. */
		str_src_settings_copy(src_params, &src_s_local);
		str_src_conn_def(tm32, src_conn_params);
		/* sourceProfileName - load source params from template. */
		if (0 == xml_get_val_args(src_data, src_data_size,
		    NULL, NULL, NULL, &ptm, &tm,
		    (const uint8_t*)"sourceProfileName", NULL)) {
			msd_src_profile_load(cfg_file_buf, cfg_file_buf_size,
			    ptm, tm, tm32, src_params);
			msd_src_conn_profile_load(cfg_file_buf, cfg_file_buf_size,
			    ptm, tm, tm32, src_conn_params);
		}
		/* Load source params from channel/source section. */
		str_src_xml_load_settings(src_data, src_data_size,
		    src_params);
		str_src_conn_xml_load_settings(src_data, src_data_size,
		    tm32, src_conn_params);
		src_params->src_conn_params = src_conn_params;
		if (STR_SRC_TYPE_TCP_HTTP == tm32 &&
		    0 != str_src_conn_http_gen_request(NULL, 0, NULL, 0, NULL, 0,
		    &src_conn_params->http))
			continue;
		error = str_hub_send_msg(ps->shbskt, hub_name, hub_name_size,
		    STR_HUB_CMD_SRC_ADD, src_params, (size_t)tm32);
		if (0 != error) {
			LOG_ERR_FMT(error, "%s: str_hub_send_msg(STR_HUB_CMD_SRC_ADD)", hub_name);
			continue;
		}
	} /* End channel sources load. */
	str_src_settings_free_data(&src_s_local);


	return (0);

err_out:
	str_src_settings_free_data(&src_s_local);
	str_hub_settings_free_data(hub_params);
	free(hub_params);
	return (error);
}

void
msd_load_timer_cb(tp_event_p ev, tp_udata_p tp_udata) {
	int error;
	prog_settings_p ps = (prog_settings_p)tp_udata->ident;
	const uint8_t *cfg_file_buf = ps->cfg_file_buf;
	const uint8_t *data, *ptm, *cur_pos, *cur_pos2;
	size_t tm, data_size, cfg_file_buf_size = ps->cfg_file_buf_size;
	char strbuf[1024];


	tpt_ev_del(ev, &ps->load_tmr);

	/* Load channels. */
	/* From main config. */
	LOG_INFO("Load channels: from main config.");
	cur_pos = NULL;
	while (0 == MSD_CFG_GET_VAL_DATA(&cur_pos, &data, &data_size,
	    "channelList", "channel", NULL)) {
		msd_channel_load(ps, cfg_file_buf, cfg_file_buf_size, data, data_size);
	}
	/* From included configs. */
	LOG_INFO("Load channels: from included configs.");
	cur_pos = NULL;
	while (0 == MSD_CFG_GET_VAL_DATA(&cur_pos, &ptm, &tm,
	    "channelList", "includeFile", NULL)) {
		data_size = MIN((sizeof(strbuf) - 1), tm);
		memcpy(strbuf, ptm, data_size);
		strbuf[data_size] = 0;
		LOG_INFO_FMT("Load channels: from \"%s\"", strbuf);
		error = read_file((const char*)ptm, tm, 0, 0, CFG_FILE_MAX_SIZE,
		    (uint8_t**)&data, &data_size);
		if (0 != error) {
			LOG_ERR_FMT(error, "Load channels: FAIL from \"%s\"", strbuf);
			error = 0;
			continue;
		}
		cur_pos2 = NULL;
		while (0 == xml_get_val_args(data, data_size, &cur_pos2, NULL, NULL,
		    &ptm, &tm, (const uint8_t*)"channel", NULL)) {
			msd_channel_load(ps, cfg_file_buf, cfg_file_buf_size,
			    ptm, tm);
		}
		free((void*)data);
	}
	/* End channels load. */
}


int
main(int argc, char *argv[]) {
	int error = 0;
	int log_fd = -1;
	uint8_t *cfg_file_buf = NULL;
	size_t tm, cfg_file_buf_size = 0;
	tp_p tp;
	http_srv_p http_srv;
	str_hubs_bckt_p shbskt;
	cmd_line_data_t cmd_line_data;

	mem_bzero(&g_data, sizeof(g_data));
	if (0 != cmd_line_parse(argc, argv, &cmd_line_data)) {
		cmd_line_usage(PACKAGE_DESCRIPTION, PACKAGE_VERSION,
		    "Rozhuk Ivan <rozhuk.im@gmail.com>",
		    PACKAGE_URL);
		return (0);
	}
	if (0 != cmd_line_data.daemon) {
		make_daemon();
	}

    { // process config file
	const uint8_t *data;
	char strbuf[1024];
	size_t data_size;
	tp_settings_t tp_s;
	http_srv_settings_t http_s;

	g_log_fd = (uintptr_t)open("/dev/stderr", (O_WRONLY | O_APPEND));
	error = read_file(cmd_line_data.cfg_file_name, 0, 0, 0,
	    CFG_FILE_MAX_SIZE, &cfg_file_buf, &cfg_file_buf_size);
	if (0 != error) {
		LOG_ERR(error, "config read_file()");
		goto err_out;
	}
	if (0 != xml_get_val_args(cfg_file_buf, cfg_file_buf_size,
	    NULL, NULL, NULL, NULL, NULL,
	    (const uint8_t*)"msd", NULL)) {
		LOG_INFO("Config file XML format invalid.");
		goto err_out;
	}
	g_data.cfg_file_buf = cfg_file_buf;
	g_data.cfg_file_buf_size = cfg_file_buf_size;

	/* Log file */
	if (0 == cmd_line_data.verbose &&
	    0 == MSD_CFG_GET_VAL_DATA(NULL, &data, &data_size,
	    "log", "file", NULL)) {
		if (sizeof(strbuf) > data_size) {
			memcpy(strbuf, data, data_size);
			strbuf[data_size] = 0;
			log_fd = open(strbuf,
			    (O_WRONLY | O_APPEND | O_CREAT), 0644);
			if (-1 == log_fd) {
				LOG_ERR(errno, "Fail to open log file.");
			}
		} else {
			LOG_ERR(EINVAL, "Log file name too long.");
		}
	} else if (0 != cmd_line_data.verbose) {
		log_fd = open("/dev/stdout", (O_WRONLY | O_APPEND));
	}
	close((int)g_log_fd);
	g_log_fd = (uintptr_t)log_fd;
	fd_set_nonblocking(g_log_fd, 1);
	log_write("\n\n\n\n", 4);
	LOG_INFO(PACKAGE_STRING": started");
#ifdef DEBUG
	LOG_INFO("Build: "__DATE__" "__TIME__", DEBUG");
#else
	LOG_INFO("Build: "__DATE__" "__TIME__", Release");
#endif
	LOG_INFO_FMT("CPU count: %d", get_cpu_count());
	LOG_INFO_FMT("descriptor table size: %d (max files)", getdtablesize());
	
	/* System resource limits. */
	if (0 == MSD_CFG_GET_VAL_DATA(NULL, &data, &data_size,
	    "systemResourceLimits", NULL)) {
		sys_res_limits_xml(data, data_size);
	}

	/* Thread pool settings. */
	tp_settings_def(&tp_s);
	if (0 == MSD_CFG_GET_VAL_DATA(NULL, &data, &data_size,
	    "threadPool", NULL)) {
		tp_settings_load_xml(data, data_size, &tp_s);
	}
	error = tp_create(&tp_s, &tp);
	if (0 != error) {
		LOG_ERR(error, "tp_create()");
		goto err_out;
	}
	tp_threads_create(tp, 1);// XXX exit rewrite


	error = str_hubs_bckt_create(tp, PACKAGE_NAME"/"PACKAGE_VERSION, &shbskt);
	if (0 != error) {
		LOG_ERR(error, "str_hubs_bckt_create()");
		goto err_out;
	}

	/* HTTP server settings. */
	/* Read from config. */
	if (0 != MSD_CFG_GET_VAL_DATA(NULL, &data, &data_size, "HTTP", NULL)) {
		LOG_INFO("No HTTP server settings, nothink to do...");
		goto err_out;
	}
	http_srv_def_settings(1, PACKAGE_NAME"/"PACKAGE_VERSION, 1, &http_s);
	http_s.rcv_io_buf_init_size = 4;
	http_s.rcv_io_buf_max_size = 4;
	http_s.snd_io_buf_init_size = 4;
	http_s.req_p_flags = (HTTP_SRV_REQ_P_F_CONNECTION | HTTP_SRV_REQ_P_F_HOST);
	http_s.resp_p_flags = (HTTP_SRV_RESP_P_F_CONN_CLOSE | HTTP_SRV_RESP_P_F_SERVER | HTTP_SRV_RESP_P_F_CONTENT_LEN);

	error = http_srv_xml_load_start(data, data_size, tp,
	    NULL, NULL, &http_s, &g_data, &http_srv);
 	if (0 != error) {
		LOG_ERR(error, "http_srv_xml_load_start()");
		goto err_out;
	}
   

	g_data.tp = tp;
	g_data.http_srv = http_srv;
	g_data.shbskt = shbskt;
	http_srv_tp_set(http_srv, tp);
	http_srv_on_conn_cb_set(http_srv, msd_http_srv_on_conn_cb);
	http_srv_on_destroy_cb_set(http_srv, msd_http_srv_on_destroy_cb);
	http_srv_on_req_rcv_cb_set(http_srv, msd_http_srv_on_req_rcv_cb);
	http_srv_on_rep_snd_cb_set(http_srv, msd_http_srv_on_rep_snd_cb);


	/* Stream hub defaults. */
	/* HTTP Multicast client request limits and defaults. */
	/* Default settings. */
	g_data.cli_precache_min = 0;
	g_data.cli_precache_max = ~((size_t)0);
	g_data.cli_snd_block_min = 0;
	g_data.cli_snd_block_max = ~((size_t)0);
	/* Read from config. */
	MSD_CFG_GET_VAL_SIZE(NULL, &g_data.cli_precache_min,
	    "limits", "precacheMin", NULL);
	MSD_CFG_GET_VAL_SIZE(NULL, &g_data.cli_precache_max,
	    "limits", "precacheMax", NULL);
	MSD_CFG_GET_VAL_SIZE(NULL, &g_data.cli_snd_block_min,
	    "limits", "sndBlockSizeMin", NULL);
	MSD_CFG_GET_VAL_SIZE(NULL, &g_data.cli_snd_block_max,
	    "limits", "sndBlockSizeMax", NULL);

	/* Load defaults. */
	msd_prog_service_load(cfg_file_buf, cfg_file_buf_size, "multicast",
	    STR_SRC_TYPE_MULTICAST, &g_data.multicast);
	msd_prog_service_load(cfg_file_buf, cfg_file_buf_size, "http",
	    STR_SRC_TYPE_TCP_HTTP, &g_data.http);
	msd_prog_service_load(cfg_file_buf, cfg_file_buf_size, "transparent",
	    STR_SRC_TYPE_TCP_HTTP, &g_data.transparent);

	/* Timer */
	g_data.load_tmr.cb_func = msd_load_timer_cb;
	g_data.load_tmr.ident = (uintptr_t)&g_data;
	error = tpt_ev_add_args(tp_thread_get(tp, 0), TP_EV_TIMER,
	    (TP_F_ONESHOT), 0, 100, &g_data.load_tmr);
	if (0 != error) {
		LOGD_ERR(error, "tpt_ev_add_args()");
		goto err_out;
	}
    } /* Done with config. */


	if (0 == info_limits((char*)g_data.syslimits,
	    (sizeof(g_data.syslimits) - 1), &tm)) {
		g_data.syslimits_size = tm;
	}
	if (0 == info_sysinfo((char*)g_data.sysinfo,
	    sizeof(g_data.sysinfo), &tm)) {
		g_data.sysinfo_size = tm;
	}
	info_sysres(&g_data.sysres, NULL, 0, NULL);

	tp_signal_handler_add_tp(g_data.tp);
	signal_install(tp_signal_handler);

	write_pid(cmd_line_data.pid_file_name); /* Store pid to file. */
	set_user_and_group(cmd_line_data.pw_uid, cmd_line_data.pw_gid); /* Drop rights. */

#if 0
#include "dvb_fe.h"

	dvb_fe_settings_t dvb_fe_s;
	dvb_fe_p src_dvb_fe;

	dvb_fe_settings_def(&dvb_fe_s);
	
	dvb_fe_s.delivery_sys = SYS_DVBT;
	dvb_fe_s.frequency = 578000000;
	dvb_fe_s.frequency = 562000000;
	//dvb_fe_s.frequency = 498000000;

	error = dvb_fe_create(0, 0, tp_thread_get_rr(g_data.tp),
	    NULL, NULL, &src_dvb_fe);
	error = dvb_fe_set_settings(src_dvb_fe, &dvb_fe_s);
	error = dvb_fe_start(src_dvb_fe);
#endif

	/* Receive and process packets. */
	tp_thread_attach_first(g_data.tp);
	tp_shutdown_wait(g_data.tp);

	/* Deinitialization... */
	http_srv_shutdown(g_data.http_srv); /* No more new clients. */
	http_srv_destroy(g_data.http_srv);
	str_hubs_bckt_destroy(g_data.shbskt);
	if (NULL != cmd_line_data.pid_file_name) {
		unlink(cmd_line_data.pid_file_name); // Remove pid file
	}

	tp_destroy(g_data.tp);
	LOG_INFO("exiting.");
	close((int)g_data.log_fd);
	free(cfg_file_buf);

err_out:
	return (error);
}



/*
 * precache = kb
 * blocksize = kb
 * tcpcc = congestion ctrl name
 */
int
msd_hub_cli_alloc_from_http(http_srv_cli_p cli, uint32_t cli_sub_type,
    str_hub_cli_p *strh_cli_ret) {
	str_hub_cli_p strh_cli;
	const uint8_t *ptm;
	size_t tm;
	http_srv_req_p req;

	if (NULL == cli || NULL == strh_cli_ret)
		return (EINVAL);
	strh_cli = str_hub_cli_alloc(STR_HUB_CLI_T_TCP_HTTP, cli_sub_type);
	if (NULL == strh_cli)
		return (ENOMEM);
	(*strh_cli_ret) = strh_cli;
	/*
	 * Set stream hub client data: some form http server client other from
	 * http request.
	 */
	strh_cli->tptask = http_srv_cli_get_tptask(cli);
	strh_cli->free_cb = msd_str_hub_cli_free_cb;
	http_srv_cli_get_addr(cli, &strh_cli->remonte_addr);

	if (STR_HUB_CLI_ST_NONE != cli_sub_type) /* Do not extract and apply additional params. */
		return (0);
	/* Extract precache, blocksize, tcpCC, "User-Agent". */
	req = http_srv_cli_get_req(cli);
	/* precache. */
	if (0 == http_query_val_get(req->line.query, req->line.query_size,
	    (uint8_t*)"precache", 8, &ptm, &tm)) {
		strh_cli->precache = ustr2usize(ptm, tm);
		strh_cli->precache = limit_val(strh_cli->precache,
		    g_data.cli_precache_min, g_data.cli_precache_max);
	}
	/* blocksize. */
	if (0 == http_query_val_get(req->line.query, req->line.query_size,
	    (uint8_t*)"blocksize", 9, &ptm, &tm)) {
		strh_cli->snd_block_min_size = ustr2usize(ptm, tm);
		strh_cli->snd_block_min_size = limit_val(strh_cli->snd_block_min_size,
		    g_data.cli_snd_block_min, g_data.cli_snd_block_max);
	}
	/* tcpcc. */
	if (0 == http_query_val_get(req->line.query, req->line.query_size,
	    (uint8_t*)"tcpcc", 5, &ptm, &tm)) {
		skt_set_tcp_cc(tp_task_ident_get(http_srv_cli_get_tptask(cli)),
		    (char*)ptm, tm);
	}
	/* Extract "User-Agent". */
	if (0 == http_hdr_val_get(req->hdr, req->hdr_size,
	    (uint8_t*)"user-agent", 10, &ptm, &tm)) {
		str_hub_cli_set_user_agent(strh_cli, (const char*)ptm, tm);
	}
	/* Client IP: get "X-Real-IP" from headers. */
	if (0 != http_hdr_val_get(req->hdr, req->hdr_size,
	    (uint8_t*)"x-real-ip", 9, &ptm, &tm) ||
	    0 != sa_addr_from_str(&strh_cli->xreal_addr, (char*)ptm, tm) ||
	    0 != sa_addr_is_loopback(&strh_cli->xreal_addr)) { /* No or bad addr. */
		sa_copy(&strh_cli->remonte_addr, &strh_cli->xreal_addr);
	}

	return (0);
}

int
msd_hub_attach_cli(str_hubs_bckt_p shbskt, const uint8_t *name, size_t name_size,
    http_srv_cli_p cli, uint32_t cli_sub_type, str_hub_settings_p hub_s,
    uint32_t src_type, str_src_settings_p src_s) {
	int error;
	size_t tm;
	str_hub_cli_p strh_cli;
	str_hub_cli_attach_data_p attach_data = NULL;
	uint8_t hub_name[STR_HUB_NAME_MAX_SIZE];

	LOGD_EV("...");

	if (NULL == name || 0 == name_size || NULL == cli)
		return (EINVAL);
	if (NULL != hub_s && NULL != src_s) {
		attach_data = malloc(sizeof(str_hub_cli_attach_data_t));
		if (NULL == attach_data)
			return (ENOMEM);
		attach_data->free_flags = STR_HUB_CLI_ATTACH_DATA_F_SRC;
		attach_data->hub_s = hub_s;
		attach_data->src_type = src_type;
		attach_data->src_s = src_s;
	}
	error = msd_hub_cli_alloc_from_http(cli, cli_sub_type, &strh_cli);
	if (0 != error) {
		free(attach_data);
		return (error);
	}

	if (0 != LOGD_IS_ENABLED()) {
		tm = MIN((sizeof(hub_name) - 1), name_size);
		memcpy(hub_name, name, tm);
		hub_name[tm] = 0;

		LOGD_INFO_FMT("%s - : attach..., snd_block_min_size = %zu, precache = %zu",
		    hub_name, strh_cli->snd_block_min_size, strh_cli->precache);
	}

	if (NULL == attach_data) {
		error = str_hub_send_msg(shbskt, name, name_size,
		    STR_HUB_CMD_CLI_ADD, strh_cli, sizeof(strh_cli));
	} else {
		attach_data->strh_cli = strh_cli;
		error = str_hub_send_msg(shbskt, name, name_size,
		    STR_HUB_CMD_CREATE_CLI_ADD, attach_data, sizeof(attach_data));
	}
	if (0 != error) {
		strh_cli->tptask = NULL;
		str_hub_cli_destroy(strh_cli);
		free(attach_data);
		tm = MIN((sizeof(hub_name) - 1), name_size);
		memcpy(hub_name, name, tm);
		hub_name[tm] = 0;
		LOG_ERR_FMT(error, "%s: str_hub_send_msg(STR_HUB_CMD_CLI_ADD)", hub_name);
		return (error);
	}
	/* Do not read/write to stream hub client, stream hub is new owner! */
	http_srv_cli_export_tptask(cli);
	http_srv_cli_free(cli);

	return (0);
}

uint32_t
msd_http_req_url_parse(int type, http_srv_req_p req,
    const uint8_t **str_addr, size_t *str_addr_size, sockaddr_storage_p ssaddr,
    uint32_t *if_index, uint32_t *rejoin_time,
    uint8_t *hub_name, size_t hub_name_size, size_t *hub_name_size_ret) {
	const uint8_t *ptm;
	size_t tm = 0, tm2;
	uint32_t ifindex, rejointime;
	char straddr[STR_ADDR_LEN], ifname[(IFNAMSIZ + 1)];
	sockaddr_storage_t ss;

	LOGD_EV("...");

	if (NULL == req || NULL == hub_name || 0 == hub_name_size)
		return (500);
	switch (type) {
	case REQ_URL_TYPE_UDP:
		/* Get multicast address. */
		if (0 != sa_addr_port_from_str(&ss, (const char*)(req->line.abs_path + 5),
		    (req->line.abs_path_size - 5)))
			return (400);
		if (0 == sa_port_get(&ss)) { /* Def udp port. */
			sa_port_set(&ss, 1234);
		}
		/* ifname, ifindex. */
		if (0 == http_query_val_get(req->line.query, req->line.query_size,
		    (uint8_t*)"ifname", 6, &ptm, &tm) && IFNAMSIZ > tm) {
			memcpy(ifname, ptm, tm);
			ifname[tm] = 0;
			ifindex = if_nametoindex(ifname);
		} else {
			if (0 == http_query_val_get(req->line.query, 
			    req->line.query_size, (uint8_t*)"ifindex", 7,
			    &ptm, &tm)) {
				ifindex = ustr2u32(ptm, tm);
			} else { /* Default value. */
				if (NULL != if_index) {
					ifindex = (*if_index);
				} else {
					ifindex = (uint32_t)-1;
				}
			}
			ifname[0] = 0;
			if_indextoname(ifindex, ifname);
		}
		/* rejoin_time. */
		if (0 == http_query_val_get(req->line.query, 
		    req->line.query_size, (const uint8_t*)"rejoin_time", 11,
		    &ptm, &tm)) {
			rejointime = ustr2u32(ptm, tm);
		} else { /* Default value. */
			if (NULL != if_index) {
				rejointime = (*rejoin_time);
			} else {
				rejointime = 0;
			}
		}

		if (0 != sa_addr_port_to_str(&ss, straddr, sizeof(straddr), NULL))
			return (400);
		tm = (size_t)snprintf((char*)hub_name, hub_name_size,
		    "/udp/%s@%s", straddr, ifname);
		if (NULL != str_addr) {
			(*str_addr) = (req->line.abs_path + 5);
		}
		if (NULL != str_addr_size) {
			(*str_addr_size) = (req->line.abs_path_size - 5);
		}
		if (NULL != ssaddr) {
			sa_copy(&ss, ssaddr);
		}
		if (NULL != if_index) {
			(*if_index) = ifindex;
		}
		if (NULL != rejoin_time) {
			(*rejoin_time) = rejointime;
		}
		break;
	case REQ_URL_TYPE_HTTP_TRANSP:
		ptm = req->line.abs_path; /* Point to url path. */
		if (0 != (HTTP_SRV_RD_F_HOST_IS_STR & req->flags)) {
			return (400); /* XXX not yet! */
		}
		if (0 != sa_addr_port_from_str(&ss, (const char*)req->host,
		    req->host_size))
			return (500); /* Error. */
		goto http_hub_name_gen_bin_addr;
	case REQ_URL_TYPE_HTTP:
		/* Get address. */
		/* '/http/' = 6 */
		ptm = mem_chr_off(6, req->line.abs_path, req->line.abs_path_size, '/'); /* '/' - after addr. */
		if (NULL == ptm) {
			ptm = (req->line.abs_path + req->line.abs_path_size);
		}
		if (0 != sa_addr_port_from_str(&ss, (const char*)(req->line.abs_path + 6),
		    (size_t)(ptm - (req->line.abs_path + 6)))) /* Possible dns name here. */
			return (400); /* XXX not yet! */
http_hub_name_gen_bin_addr:
		if (0 == sa_port_get(&ss)) { /* Def http port. */
			sa_port_set(&ss, HTTP_PORT);
		}
		if (0 != sa_addr_port_to_str(&ss, straddr, sizeof(straddr), NULL))
			return (400);
		tm = (size_t)snprintf((char*)hub_name, hub_name_size, "/http/%s/", straddr);
		if ((req->line.abs_path + req->line.abs_path_size) > ptm) { /* url path after dst address. */
			tm2 = (size_t)((req->line.abs_path + req->line.abs_path_size) - (ptm + 1));
			tm2 = MIN(tm2, (hub_name_size - (tm + 4)));
			memcpy((hub_name + tm), (ptm + 1), tm2);
			tm += tm2;
		}
		hub_name[tm] = 0;
		if (NULL != str_addr) {
			(*str_addr) = (req->line.abs_path + 6);
		}
		if (NULL != str_addr_size) {
			(*str_addr_size) = (size_t)(ptm - (req->line.abs_path + 6));
		}
		if (NULL != ssaddr) {
			sa_copy(&ss, ssaddr);
		}
		break;
	}

	if (NULL != hub_name_size_ret) {
		(*hub_name_size_ret) = tm;
	}
	return (200);
}



/* New connection received. */
int
msd_http_srv_on_conn_cb(http_srv_bind_p acc __unused, void *srv_udata __unused,
    uintptr_t skt __unused, sockaddr_storage_p addr __unused,
    tpt_p *tpt __unused, http_srv_cli_ccb_p ccb __unused, void **udata __unused) {

	LOGD_EV("...");

	return (HTTP_SRV_CB_CONTINUE);
}

void
msd_http_srv_on_destroy_cb(http_srv_cli_p cli __unused, void *udata,
    http_srv_resp_p resp __unused) {

	LOGD_EV("...");

	if (NULL != udata) {
		((str_hub_cli_p)udata)->udata = NULL;
		str_hub_cli_destroy((str_hub_cli_p)udata);
	}
}

/* http request from client is received now, process it. */
/* http_srv_on_req_rcv_cb */
int
msd_http_srv_on_req_rcv_cb(http_srv_cli_p cli, void *udata __unused,
    http_srv_req_p req, http_srv_resp_p resp) {
	int error;
	const uint8_t *ptm, *str_addr;
	size_t buf_size, tm, str_addr_size;
	uint8_t buf[STR_HUB_NAME_MAX_SIZE];
	uint32_t src_type;
	prog_service_p prog_service = NULL;
	str_src_settings_p src_params;
	str_src_conn_params_p src_conn_params;
	static const char *cttype = 	"Content-Type: text/plain\r\n"
					"Pragma: no-cache";

	LOGD_EV("...");

	if (HTTP_REQ_METHOD_GET != req->line.method_code &&
	    HTTP_REQ_METHOD_HEAD != req->line.method_code) {
		resp->status_code = 400;
		return (HTTP_SRV_CB_CONTINUE);
	}
#if 0
	if (0 == (req->flags & HTTP_SRV_RD_F_HOST_IS_LOCAL)) {
		if (0 == g_data.transparent.enabled)
			return (403);
		return (500);
		prog_service = &g_data.transparent;
		/* Default value. */
		memcpy(&src_conn_params, &prog_service->src_conn_params, sizeof(src_conn_params));
		/* Get dst ip address, host name, hub name. */
		error = msd_http_req_url_parse(REQ_URL_TYPE_HTTP_TRANSP, req, &str_addr,
		    &str_addr_size, &src_conn_params.tcp.addr[0], NULL, buf, sizeof(buf),
		    &buf_size);
		goto http_dyn_proxy;
	}
#endif

	/* Statistic request. */
	if (HTTP_REQ_METHOD_GET == req->line.method_code &&
	    0 == mem_cmpin_cstr("/stat", req->line.abs_path, req->line.abs_path_size)) {
		error = gen_stat_text(PACKAGE_DESCRIPTION, PACKAGE_VERSION,
		    g_data.shbskt, &g_data.sysres,
		    (uint8_t*)g_data.sysinfo, g_data.sysinfo_size,
		    (uint8_t*)g_data.syslimits, g_data.syslimits_size, cli);
		if (0 == error) {
			resp->status_code = 200;
			resp->hdrs_count = 1;
			resp->hdrs[0].iov_base = MK_RW_PTR(cttype);
			resp->hdrs[0].iov_len = 42;
		} else {
			resp->status_code = 500;
		}
		return (HTTP_SRV_CB_CONTINUE);
	}
	/* Stream Hub statistic request. */
	if (HTTP_REQ_METHOD_GET == req->line.method_code &&
	    7 < req->line.abs_path_size &&
	    0 == mem_cmpi_cstr("/hubstat", req->line.abs_path)) {
		error = gen_hub_stat_text_send_async(g_data.shbskt, cli);
		if (0 != error) {
			resp->status_code = 500;
			return (HTTP_SRV_CB_CONTINUE);
		}
		/* Will send reply later... */
		return (HTTP_SRV_CB_NONE);
	}

	if (0 != g_data.multicast.enabled &&
	    12 < req->line.abs_path_size &&
	    STR_HUB_NAME_MAX_SIZE > req->line.abs_path_size &&
	    (0 == memcmp(req->line.abs_path, "/udp/", 5) ||
	    0 == memcmp(req->line.abs_path, "/rtp/", 5))) {
		src_type = STR_SRC_TYPE_MULTICAST;
		prog_service = &g_data.multicast;
handle_dyn_client:
		if (HTTP_REQ_METHOD_HEAD == req->line.method_code) { /* HEAD allways return 200 OK. */
			/* Send HTTP headers only... */
			resp->status_code = 200;
			resp->p_flags &= ~HTTP_SRV_RESP_P_F_CONTENT_LEN;
			if (6 < prog_service->hub_params.cust_http_hdrs_size) {
				resp->hdrs_count = 1;
				resp->hdrs[0].iov_base = prog_service->hub_params.cust_http_hdrs;
				resp->hdrs[0].iov_len = prog_service->hub_params.cust_http_hdrs_size;
			}
			return (HTTP_SRV_CB_CONTINUE);
		}
		src_params = malloc(sizeof(str_src_settings_t));
		src_conn_params = malloc(sizeof(str_src_conn_params_t));
		if (NULL == src_params || NULL == src_conn_params) {
			resp->status_code = 500;
err_out_dyn_client:
			free(src_params);
			free(src_conn_params);
			return (HTTP_SRV_CB_CONTINUE);
		}

		/* Default value. */
		memcpy(src_conn_params, &prog_service->src_conn_params, sizeof(str_src_conn_params_t));
		if (STR_SRC_TYPE_MULTICAST == src_type) {
			/* Get multicast address, ifindex, hub name. */
			resp->status_code = msd_http_req_url_parse(
			    REQ_URL_TYPE_UDP, req,
			    NULL, NULL,
			    &src_conn_params->udp.addr,
			    &src_conn_params->mc.if_index,
			    &src_conn_params->mc.rejoin_time,
			    buf, sizeof(buf), &buf_size);
			if (200 != resp->status_code)
				goto err_out_dyn_client;
		} else {
			/* Get dst ip address, host name, hub name. */
			resp->status_code = msd_http_req_url_parse(
			    REQ_URL_TYPE_HTTP, req,
			    &str_addr, &str_addr_size,
			    &src_conn_params->tcp.addr[0],
			    NULL, NULL,
			    buf, sizeof(buf), &buf_size);
			if (200 != resp->status_code)
				goto err_out_dyn_client;
			/* Generate http request */
			ptm = (str_addr + str_addr_size + 1); /* URL path */
			tm = (size_t)(req->line.abs_path_size - (size_t)(ptm - req->line.abs_path));
			error = str_src_conn_http_gen_request(str_addr, str_addr_size,
			    ptm, tm,  NULL, 0, &src_conn_params->http);
			if (0 != error) {
				LOG_ERR_FMT(error, "%s: str_src_conn_http_gen_request()", buf);
				resp->status_code = 503;
				goto err_out_dyn_client;
			}
		}
		/* Default value. */
		str_src_settings_copy(src_params, &prog_service->src_params);
		src_params->src_conn_params = src_conn_params;
		if (0 != msd_hub_attach_cli(g_data.shbskt, buf, buf_size,
		    cli, STR_HUB_CLI_ST_NONE,
		    &prog_service->hub_params, src_type,
		    src_params)) {
			resp->status_code = 500;
			goto err_out_dyn_client;
		}
		/* Will send reply later... */
		return (HTTP_SRV_CB_NONE);
	} /* "/udp/" / "/rtp/" */

	if (0 != g_data.http.enabled &&
	    13 < req->line.abs_path_size &&
	    STR_HUB_NAME_MAX_SIZE > req->line.abs_path_size &&
	    0 == memcmp(req->line.abs_path, "/http/", 6)) {
		src_type = STR_SRC_TYPE_TCP_HTTP;
		prog_service = &g_data.http;
		goto handle_dyn_client;
	} /* "/http/" */

	if (9 < req->line.abs_path_size &&
	    STR_HUB_NAME_MAX_SIZE > req->line.abs_path_size &&
	    0 == memcmp(req->line.abs_path, "/channel/", 9)) {
		if (0 != msd_hub_attach_cli(g_data.shbskt,
		    req->line.abs_path, req->line.abs_path_size,
		    cli, ((HTTP_REQ_METHOD_HEAD == req->line.method_code) ?
		        STR_HUB_CLI_ST_TCP_HTTP_HEAD : STR_HUB_CLI_ST_NONE),
		    NULL, STR_SRC_TYPE_UNKNOWN, NULL)) {
			resp->status_code = 500;
			return (HTTP_SRV_CB_CONTINUE);
		}
		/* Will send reply later... */
		return (HTTP_SRV_CB_NONE);
	} /* "/channel/" */

	/* URL not found. */
	resp->status_code = 404;

	return (HTTP_SRV_CB_CONTINUE);
}


int
msd_http_srv_on_rep_snd_cb(http_srv_cli_p cli __unused, void *udata,
    http_srv_resp_p resp __unused) {

	LOGD_EV("...");

	if (NULL != udata) {
		((str_hub_cli_p)udata)->tptask = NULL;
	}

	return (HTTP_SRV_CB_NONE);
}


int
msd_str_hub_cli_free_cb(str_hub_cli_p strh_cli __unused, tp_task_p tptask __unused,
    void *udata) {

	LOGD_EV("...");

	if (NULL != udata) {
		http_srv_cli_set_udata((http_srv_cli_p)udata, NULL);
		http_srv_cli_free((http_srv_cli_p)udata);
	}

	return (0);
}

