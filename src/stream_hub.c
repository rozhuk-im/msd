/*-
 * Copyright (c) 2012 - 2021 Rozhuk Ivan <rozhuk.im@gmail.com>
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

#include <stdlib.h> /* malloc, exit */
#include <unistd.h> /* close, write, sysconf */
#include <string.h> /* bcopy, bzero, memcpy, memmove, memset, strerror... */
#include <stdio.h> /* snprintf, fprintf */
#include <time.h>
#include <errno.h>

#include "utils/macro.h"
#include "net/socket.h"
#include "net/socket_address.h"
#include "net/utils.h"
#include "utils/buf_str.h"
#include "threadpool/threadpool.h"
#include "threadpool/threadpool_msg_sys.h"
#include "threadpool/threadpool_task.h"
#include "utils/io_buf.h"
#include "proto/http_server.h"
#include "utils/info.h"
#include "utils/sys.h"
#include "utils/ring_buffer.h"
#include "utils/log.h"
#include "crypto/hash/md5.h"
#include "utils/xml.h"
#include "proto/http.h"

#include "stream_src.h"
#include "stream_hub.h"


#define STR_HUBS_HTTP_CONN_CLOSE	"\r\nConnection: close"


/* Per thread data */
typedef struct str_hub_thread_data_s {
	struct str_hub_head	hub_head;	/* List with stream hubs per thread. */
	iovec_t			iov[IOV_MAX];	/* iov array for send to clients. */
	str_hubs_stat_t		stat;
} str_hub_thrd_t, *str_hub_thrd_p;


typedef struct str_hubs_bckt_s {
	tp_p		tp;
	struct timespec	last_tmr_time;	/* For baud rate calculation. */
	struct timespec	last_tmr_time_next; /* For baud rate calculation. */
	tp_udata_t	service_tmr;	/* Service timer. */
	str_hub_thrd_p	thr_data;	/* Per thread hubs + stat. */
	size_t		base_http_hdrs_size;
	uint8_t		base_http_hdrs[512];
} str_hubs_bckt_t;


typedef struct str_hubs_bckt_enum_data_s { /* thread message sync data. */
	str_hubs_bckt_p		shbskt;
	str_hubs_bckt_enum_cb	enum_cb;
	void			*udata;
	tpt_msg_done_cb	done_cb;
} str_hubs_bckt_enum_data_t, *str_hubs_bckt_enum_data_p;


tpt_p	str_hub_tpt_get_by_name(tp_p tp, const uint8_t *name,
	    size_t name_size);

void	str_hubs_bckt_destroy_msg_cb(tpt_p tpt, void *udata);

void	str_hubs_bckt_enum_msg_cb(tpt_p tpt, void *udata);
void	str_hubs_bckt_enum_done_cb(tpt_p tpt, size_t send_msg_cnt,
	    size_t error_cnt, void *udata);

void	str_hubs_bckt_timer_service(str_hubs_bckt_p shbskt,
	    str_hub_p str_hub, str_hubs_stat_p stat);
void	str_hubs_bckt_timer_msg_cb(tpt_p tpt, void *udata);
void	str_hubs_bckt_timer_cb(tp_event_p ev, tp_udata_p tp_udata);

str_hub_p str_hub_find(str_hubs_bckt_p shbskt, tpt_p tpt, int move_up,
	    uint8_t *name, size_t name_size);
int	str_hub_create(str_hubs_bckt_p shbskt, tpt_p tpt,
	    uint8_t *name, size_t name_size, str_hub_p *str_hub_ret);
void	str_hub_destroy(str_hub_p str_hub);
int	str_hub_settings_set(str_hub_p str_hub, str_hub_settings_p s);


int	str_hub_cli_attach(str_hub_p str_hub, str_hub_cli_p strh_cli);
int	str_hub_cli_send_http_hdr(str_hubs_bckt_p shbskt,
	    str_hub_cli_p strh_cli, uint32_t http_status_code,
	    int conn_close, size_t *send_size);

void	str_hub_send_msg_cb(tpt_p tpt, void *udata);

int	str_hub_src_add(str_hub_p str_hub, uint32_t type, str_src_settings_p s);
size_t	str_hub_src_index_get(str_hub_p str_hub, str_src_p src);
int	str_hub_src_switch(str_hub_p str_hub, size_t src_current_new);
void	str_hub_src_remove(str_src_p src);



int	str_hub_send_to_client(str_hub_cli_p strh_cli, struct timespec *ts,
	    size_t data2send);
int	str_hub_send_to_clients(str_hub_p str_hub, struct timespec *ts);
int 	strh_cli_send_ready_cb(tp_task_p tptask, int error, int eof,
	    size_t data2send, void *arg);

int	str_hub_src_on_data(str_src_p src, struct timespec *ts, void *udata);
int	str_hub_src_on_state(str_src_p src, void *udata, uint32_t state,
	    uint32_t status);






/* XXX Thread pool balancer */
tpt_p
str_hub_tpt_get_by_name(tp_p tp, const uint8_t *name, size_t name_size) {
	size_t thread_num, thread_cnt;
	uint8_t hash[MD5_HASH_SIZE];

	md5_get_digest((void*)name, name_size, hash);

	thread_cnt = tp_thread_count_max_get(tp);
	//thread_num = (/*(hash / thread_cnt) ^*/ (hash % thread_cnt));
	thread_num = thread_cnt;
	thread_num *= data_xor8(hash, sizeof(hash));
	thread_num /= 256;
	if (thread_cnt < thread_num)
		thread_num = (thread_cnt - 1);

	return (tp_thread_get(tp, thread_num));
}


void
str_hub_settings_def(str_hub_settings_p s_ret) {

	LOGD_EV_FMT("... %zx", s_ret);

	if (NULL == s_ret)
		return;
	mem_bzero(s_ret, sizeof(str_hub_settings_t));
	skt_opts_init(STR_HUB_S_SKT_OPTS_INT_MASK,
	    STR_HUB_S_SKT_OPTS_INT_VALS, &s_ret->skt_opts);
	s_ret->skt_opts.mask |= SO_F_NONBLOCK;
	s_ret->skt_opts.bit_vals |= SO_F_NONBLOCK;
	s_ret->skt_opts.rcv_buf = STR_HUB_S_SKT_OPTS_RCVBUF;

	/* Default settings. */
	s_ret->flags = STR_HUB_S_DEF_FLAGS;
	s_ret->skt_opts.mask |= STR_HUB_S_DEF_SKT_OPTS_MASK;
	s_ret->skt_opts.bit_vals |= STR_HUB_S_DEF_SKT_OPTS_VALS;
	s_ret->skt_opts.snd_buf = STR_HUB_S_DEF_SKT_OPTS_SND_BUF;
	s_ret->skt_opts.snd_lowat = STR_HUB_S_DEF_SKT_OPTS_SNDLOWAT;
	s_ret->skt_opts.snd_timeout = STR_HUB_S_DEF_SKT_OPTS_SNDTIMEO;
	s_ret->skt_opts.tcp_cc_size = (sizeof(STR_HUB_S_DEF_SKT_OPTS_TCP_CONGESTION) - 1);
	memcpy(s_ret->skt_opts.tcp_cc, 
	    STR_HUB_S_DEF_SKT_OPTS_TCP_CONGESTION,
	    s_ret->skt_opts.tcp_cc_size);
	s_ret->zero_cli_timeout = STR_HUB_S_DEF_NO_CLI_TIMEOUT;
	str_src_settings_def(&s_ret->str_src_settings);
	s_ret->precache = STR_HUB_S_DEF_PRECAHE;
}

int
str_hub_xml_load_settings(const uint8_t *buf, size_t buf_size,
    str_hub_settings_p params) {
	const uint8_t *data;
	size_t data_size;

	LOGD_EV_FMT("... %zx", params);

	if (NULL == buf || 0 == buf_size || NULL == params)
		return (EINVAL);

	/* Read from config. */
	if (0 == xml_get_val_args(buf, buf_size, NULL, NULL, NULL,
	    &data, &data_size, (const uint8_t*)"fZeroCliPersistent", NULL)) {
		yn_set_flag32(data, data_size, STR_HUB_S_F_ZERO_CLI_PERSISTENT,
		    &params->flags);
	}
	if (0 == xml_get_val_args(buf, buf_size, NULL, NULL, NULL,
	    &data, &data_size, (const uint8_t*)"fZeroSrcBitratePersistent", NULL)) {
		yn_set_flag32(data, data_size, STR_HUB_S_F_ZERO_SRC_BITRATE_PERSISTENT,
		    &params->flags);
	}
	if (0 == xml_get_val_args(buf, buf_size, NULL, NULL, NULL,
	    &data, &data_size, (const uint8_t*)"fPrecacheWait", NULL)) {
		yn_set_flag32(data, data_size, STR_HUB_S_F_PRECACHE_WAIT,
		    &params->flags);
	}
	if (0 == xml_get_val_args(buf, buf_size, NULL, NULL, NULL,
	    &data, &data_size, (const uint8_t*)"fUsePollingForSend", NULL)) {
		yn_set_flag32(data, data_size, STR_HUB_S_F_USE_SEND_POLLING,
		    &params->flags);
	}
	if (0 == xml_get_val_args(buf, buf_size, NULL, NULL, NULL,
	    &data, &data_size, (const uint8_t*)"fDropSlowClients", NULL)) {
		yn_set_flag32(data, data_size, STR_HUB_S_F_DROP_SLOW_CLI,
		    &params->flags);
	}
	if (0 == xml_get_val_args(buf, buf_size, NULL, NULL, NULL,
	    &data, &data_size, (const uint8_t*)"fZeroCopyOnSend", NULL)) {
		yn_set_flag32(data, data_size, STR_HUB_S_F_ZERO_COPY_ON_SEND,
		    &params->flags);
	}
	xml_get_val_uint64_args(buf, buf_size, NULL, &params->zero_cli_timeout,
	    (const uint8_t*)"zeroCliTimeout", NULL);

	/* Socket options. */
	if (0 == xml_get_val_args(buf, buf_size, NULL, NULL, NULL,
	    &data, &data_size, (const uint8_t*)"skt", NULL)) {
		skt_opts_xml_load(data, data_size,
		    STR_HUB_S_SKT_OPTS_LOAD_MASK, &params->skt_opts);
	}

	xml_get_val_size_t_args(buf, buf_size, NULL, &params->precache,
	    (const uint8_t*)"precache", NULL);
	    
	/* Load custom http headers. */
	if (0 == xml_get_val_args(buf, buf_size, NULL, NULL, NULL,
	    &data, &data_size, (const uint8_t*)"headersList", NULL)) {
		str_src_cust_hdrs_load(data, data_size,
		    &params->cust_http_hdrs, &params->cust_http_hdrs_size);
	}

	/* Load src~s defaults. */
	if (0 == xml_get_val_args(buf, buf_size, NULL, NULL, NULL,
	    &data, &data_size, (const uint8_t*)"sourceProfile", NULL)) {
		str_src_xml_load_settings(data, data_size,
		    &params->str_src_settings);
	}
	return (0);
}

int
str_hub_settings_copy(str_hub_settings_p dst, str_hub_settings_p src) {

	LOGD_EV_FMT("... %zx <- %zx", dst, src);

	if (NULL == dst || NULL == src)
		return (EINVAL);

	memcpy(dst, src, sizeof(str_hub_settings_t));
	/* Extra copy */
	str_src_settings_copy(&dst->str_src_settings, &src->str_src_settings);
	/* Copy custom HTTP headers to new buffer. */
	if (NULL == dst->cust_http_hdrs || 0 == dst->cust_http_hdrs_size) {
		dst->cust_http_hdrs = NULL;
		dst->cust_http_hdrs_size = 0;
	} else {
		dst->cust_http_hdrs = malloc((dst->cust_http_hdrs_size + 16));
		if (NULL == dst->cust_http_hdrs)
			return (ENOMEM);
		memcpy(dst->cust_http_hdrs, src->cust_http_hdrs,
		    dst->cust_http_hdrs_size);
		dst->cust_http_hdrs[dst->cust_http_hdrs_size] = 0;
	}

	return (0);
}

void
str_hub_settings_free_data(str_hub_settings_p s) {

	LOGD_EV_FMT("... %zx", s);

	if (NULL == s)
		return;
	if (NULL != s->cust_http_hdrs) {
		free(s->cust_http_hdrs);
		s->cust_http_hdrs = NULL;
		s->cust_http_hdrs_size = 0;
	}
	/* Extra free */
	str_src_settings_free_data(&s->str_src_settings);

	mem_filld(s, sizeof(str_hub_settings_t));
}


int
str_hubs_bckt_create(tp_p tp, const char *app_ver,
    str_hubs_bckt_p *shbskt_ret) {
	int error;
	str_hubs_bckt_p shbskt;
	char osver[128];
	size_t i, thread_count_max;

	if (NULL == shbskt_ret)
		return (EINVAL);
	shbskt = zalloc(sizeof(str_hubs_bckt_t));
	if (NULL == shbskt)
		return (ENOMEM);
	thread_count_max = tp_thread_count_max_get(tp);
	shbskt->thr_data = zalloc((sizeof(str_hub_thrd_t) * thread_count_max));
	if (NULL == shbskt->thr_data) {
		error = ENOMEM;
		goto err_out;
	}
	for (i = 0; i < thread_count_max; i ++) {
		TAILQ_INIT(&shbskt->thr_data[i].hub_head);
	}
	/* Base HTTP headers. */
	if (0 != info_get_os_ver("/", 1, osver,
	    (sizeof(osver) - 1), NULL))
		memcpy(osver, "Generic OS/1.0", 15);
	shbskt->base_http_hdrs_size = (size_t)snprintf((char*)shbskt->base_http_hdrs,
	    sizeof(shbskt->base_http_hdrs),
	    "Server: %s %s HTTP stream hub by Rozhuk Ivan"
	    STR_HUBS_HTTP_CONN_CLOSE, /* Keep it last!!! -19 */
	    osver, app_ver);
	/* Timer */
	shbskt->tp = tp;
	shbskt->service_tmr.cb_func = str_hubs_bckt_timer_cb;
	shbskt->service_tmr.ident = (uintptr_t)shbskt;
	error = tpt_ev_add_args(tp_thread_get_rr(shbskt->tp),
	    TP_EV_TIMER, 0, 0, 1000 /* 1 sec. */, &shbskt->service_tmr);
	if (0 != error) {
		LOGD_ERR(error, "tpt_ev_add_args()");
		goto err_out;
	}

	(*shbskt_ret) = shbskt;
	return (0);

err_out:
	free(shbskt->thr_data);
	free(shbskt);
	return (error);
}

void
str_hubs_bckt_destroy(str_hubs_bckt_p shbskt) {
	tp_event_t ev;

	if (NULL == shbskt)
		return;
	memset(&ev, 0x00, sizeof(ev));
	ev.event = TP_EV_TIMER;
	tpt_ev_del(&ev, &shbskt->service_tmr);
	/* Broadcast to all threads. */
	tpt_msg_bsend(shbskt->tp, NULL,
	    (TP_MSG_F_SELF_DIRECT | TP_MSG_F_FORCE | TP_MSG_F_FAIL_DIRECT | TP_BMSG_F_SYNC),
	    str_hubs_bckt_destroy_msg_cb, shbskt);

	free(shbskt->thr_data);
	mem_filld(shbskt, sizeof(str_hubs_bckt_t));
	free(shbskt);
}
void
str_hubs_bckt_destroy_msg_cb(tpt_p tpt, void *udata) {
	str_hubs_bckt_p shbskt = (str_hubs_bckt_p)udata;
	str_hub_p str_hub, str_hub_temp;

	//LOGD_EV("...");

	TAILQ_FOREACH_SAFE(str_hub,
	    &shbskt->thr_data[tp_thread_get_num(tpt)].hub_head,
	    next, str_hub_temp) {
		str_hub_destroy(str_hub);
	}
}


int
str_hubs_bckt_enum(str_hubs_bckt_p shbskt, str_hubs_bckt_enum_cb enum_cb,
    void *udata, tpt_msg_done_cb done_cb) {
	int error;
	str_hubs_bckt_enum_data_p enum_data;

	if (NULL == shbskt || NULL == enum_cb)
		return (EINVAL);
	enum_data = malloc(sizeof(str_hubs_bckt_enum_data_t));
	if (NULL == enum_data)
		return (ENOMEM);
	enum_data->shbskt = shbskt;
	enum_data->enum_cb = enum_cb;
	enum_data->udata = udata;
	enum_data->done_cb = done_cb;

	error = tpt_msg_cbsend(shbskt->tp, NULL,
	    (TP_CBMSG_F_ONE_BY_ONE), str_hubs_bckt_enum_msg_cb,
	    enum_data, str_hubs_bckt_enum_done_cb);
	if (0 != error)
		free(enum_data);
	return (error);
}
void
str_hubs_bckt_enum_msg_cb(tpt_p tpt, void *udata) {
	str_hubs_bckt_enum_data_p enum_data = udata;
	str_hubs_bckt_p shbskt = enum_data->shbskt;
	str_hub_p str_hub, str_hub_temp;

	//LOGD_EV("...");

	TAILQ_FOREACH_SAFE(str_hub,
	    &shbskt->thr_data[tp_thread_get_num(tpt)].hub_head,
	    next, str_hub_temp) {
		enum_data->enum_cb(tpt, str_hub, enum_data->udata);
	}
}
void
str_hubs_bckt_enum_done_cb(tpt_p tpt, size_t send_msg_cnt,
    size_t error_cnt, void *udata) {
	str_hubs_bckt_enum_data_p enum_data = udata;

	if (NULL != enum_data->done_cb) {
		enum_data->done_cb(tpt, send_msg_cnt, error_cnt,
		    enum_data->udata);
	}
	free(enum_data);
}


int
str_hubs_bckt_stat_thread(str_hubs_bckt_p shbskt, size_t thread_num,
    str_hubs_stat_p stat) {

	if (NULL == shbskt || NULL == stat ||
	    tp_thread_count_max_get(shbskt->tp) <= thread_num)
		return (EINVAL);
	memcpy(stat, &shbskt->thr_data[thread_num].stat,
	    sizeof(str_hubs_stat_t));

	return (0);
}

int
str_hubs_bckt_stat_summary(str_hubs_bckt_p shbskt, str_hubs_stat_p stat) {
	size_t i, j, thread_cnt;

	if (NULL == shbskt || NULL == stat)
		return (EINVAL);
	thread_cnt = tp_thread_count_max_get(shbskt->tp);
	mem_bzero(stat, sizeof(str_hubs_stat_t));
	for (i = 0; i < thread_cnt; i ++) {
		stat->str_hub_count += shbskt->thr_data[i].stat.str_hub_count;
		stat->cli_count += shbskt->thr_data[i].stat.cli_count;
		stat->poll_cli_count += shbskt->thr_data[i].stat.poll_cli_count;
		for (j = 0; j < STR_SRC_STATE_MAX; j ++)
			stat->srcs_state[j] += shbskt->thr_data[i].stat.srcs_state[j];
		stat->srcs_cnt += shbskt->thr_data[i].stat.srcs_cnt;
		stat->pids_cnt += shbskt->thr_data[i].stat.pids_cnt;
		stat->baud_rate_in += shbskt->thr_data[i].stat.baud_rate_in;
		stat->baud_rate_out += shbskt->thr_data[i].stat.baud_rate_out;
		stat->error_rate += shbskt->thr_data[i].stat.error_rate;
		stat->error_rate_total += shbskt->thr_data[i].stat.error_rate_total;
	}
	return (0);
}


void
str_hubs_bckt_timer_service(str_hubs_bckt_p shbskt, str_hub_p str_hub,
    str_hubs_stat_p stat) {
	str_hub_cli_p strh_cli, strh_cli_temp;
	struct timespec *ts = &shbskt->last_tmr_time_next;
	size_t j;
	uint64_t tm64;

	/* Disconnect timedout clients. */
	if (0 != str_hub->s.skt_opts.snd_timeout) {
		TAILQ_FOREACH_SAFE(strh_cli, &str_hub->cli_head, next, strh_cli_temp) {
			if (((time_t)str_hub->s.skt_opts.snd_timeout + strh_cli->last_snd_time) <
			    ts->tv_sec) { /* Report about send timeout. */
				strh_cli_send_ready_cb(strh_cli->tptask,
				    ETIMEDOUT, 0, 0, strh_cli);
				LOGD_EV_FMT("ETIMEDOUT: snd_timeout = %zu, tv_sec = %lu, last_snd_time = %lu",
				    str_hub->s.skt_opts.snd_timeout,
				    ts->tv_sec,
				    strh_cli->last_snd_time);
			}
		}
	}

	/* No clients check. */
	if (0 == (STR_HUB_S_F_ZERO_CLI_PERSISTENT & str_hub->s.flags) &&
	    0 == str_hub->cli_count &&
	    (str_hub->zero_cli_time + (time_t)str_hub->s.zero_cli_timeout) < ts->tv_sec) { /* No more clients, selfdestroy. */
		LOG_EV_FMT("%s: No more clients, selfdestroy.", str_hub->name);
		str_hub_destroy(str_hub);
		return;
	}

	/* Stat update. */
	/* Update stream hub clients baud rate. */
	if (0 == (ts->tv_sec & 1)) { /* every 2 second */
		if (0 != str_hub->sended_count) {
			tm64 = (1000000000 * ((uint64_t)ts->tv_sec - (uint64_t)shbskt->last_tmr_time.tv_sec));
			tm64 += ((uint64_t)ts->tv_nsec - (uint64_t)shbskt->last_tmr_time.tv_nsec);
			if (0 == tm64) /* Prevent division by zero. */
				tm64 ++;
			str_hub->baud_rate = ((str_hub->sended_count * 4000000000) / tm64);
			str_hub->sended_count = 0;
		} else {
			str_hub->baud_rate = 0;
		}
	}
	/* Per Thread stat. */
	stat->str_hub_count ++;
	stat->cli_count += str_hub->cli_count;
	stat->poll_cli_count += str_hub->poll_cli_count;
	stat->srcs_cnt += str_hub->src_cnt;
	stat->baud_rate_out += str_hub->baud_rate;
	if (str_hub->src_current < str_hub->src_cnt &&
	    NULL != str_hub->src[str_hub->src_current])
		stat->error_rate += str_hub->src[str_hub->src_current]->error_rate;
	/* Sources updates. */
	for (j = 0; j < str_hub->src_cnt; j ++) {
		if (NULL == str_hub->src[j])
			continue;
		if (0 != str_src_timer_proc(str_hub->src[j], ts, &shbskt->last_tmr_time))
			break;
		/* Per Thread stat. */
		//stat->pids_cnt += str_hub->src[j]->ts_pids_cnt;
		if (STR_SRC_STATE_MAX > str_hub->src[j]->state)
			stat->srcs_state[str_hub->src[j]->state] ++;
		stat->baud_rate_in += str_hub->src[j]->baud_rate;
		stat->error_rate_total += str_hub->src[j]->error_rate;
	}
}
void
str_hubs_bckt_timer_msg_cb(tpt_p tpt, void *udata) {
	str_hubs_bckt_p shbskt = (str_hubs_bckt_p)udata;
	str_hub_p str_hub, str_hub_temp;
	str_hubs_stat_t stat;
	size_t thread_num;

	//LOGD_EV("...");

	thread_num = tp_thread_get_num(tpt);
	mem_bzero(&stat, sizeof(str_hubs_stat_t));

	/* Enum all Stream Hubs associated with this thread. */
	TAILQ_FOREACH_SAFE(str_hub, &shbskt->thr_data[thread_num].hub_head,
	    next, str_hub_temp) {
		str_hubs_bckt_timer_service(shbskt, str_hub, &stat);
	}
	/* Update stat. */
	memcpy(&shbskt->thr_data[thread_num].stat, &stat,
	    sizeof(str_hubs_stat_t));
}
void
str_hubs_bckt_timer_cb(tp_event_p ev __unused, tp_udata_p tp_udata) {
	str_hubs_bckt_p shbskt = (str_hubs_bckt_p)tp_udata->ident;

	//LOGD_EV("...");
	if (NULL == shbskt)
		return;
	memcpy(&shbskt->last_tmr_time, &shbskt->last_tmr_time_next,
	    sizeof(struct timespec));
	clock_gettime(CLOCK_MONOTONIC_FAST, &shbskt->last_tmr_time_next);
	/* Broadcast to all threads. */
	tpt_msg_bsend(shbskt->tp, tp_udata->tpt,
	    TP_MSG_F_SELF_DIRECT, str_hubs_bckt_timer_msg_cb, shbskt);
}




str_hub_p
str_hub_find(str_hubs_bckt_p shbskt, tpt_p tpt, int move_up,
    uint8_t *name, size_t name_size) {
	str_hub_p str_hub = NULL;
	struct str_hub_head *hub_head;

	if (NULL == shbskt || NULL == name || 0 == name_size ||
	   STR_HUB_NAME_MAX_SIZE <= name_size)
		return (NULL);
	if (NULL == tpt) {
		tpt = str_hub_tpt_get_by_name(shbskt->tp, name, name_size);
	}
	hub_head = &shbskt->thr_data[tp_thread_get_num(tpt)].hub_head;
	TAILQ_FOREACH(str_hub, hub_head, next) {
		if (str_hub->name_size != name_size) {
			continue;
		}
		if (0 == memcmp(str_hub->name, name, name_size)) {
			if (0 != move_up) {
				/* Move hub to hubs list head. */
				TAILQ_REMOVE(hub_head, str_hub, next);
				TAILQ_INSERT_HEAD(hub_head, str_hub, next);
			}
			return (str_hub);
		}
	}

	return (NULL);
}

int
str_hub_create(str_hubs_bckt_p shbskt, tpt_p tpt,
    uint8_t *name, size_t name_size, str_hub_p *str_hub_ret) {
	str_hub_p str_hub;

	LOGD_EV("...");

	if (NULL == shbskt ||
	    NULL == name || 0 == name_size ||
	    STR_HUB_NAME_MAX_SIZE <= name_size ||
	    NULL == str_hub_ret)
		return (EINVAL);
	if (NULL == tpt) {
		tpt = str_hub_tpt_get_by_name(shbskt->tp,
		    name, name_size);
	}
	str_hub = str_hub_find(shbskt, tpt, 0, name, name_size);
	if (NULL != str_hub) { /* Return existing. */
		(*str_hub_ret) = str_hub;
		return (EEXIST);
	}
	/* Create new. */
	str_hub = zalloc((sizeof(str_hub_t) + name_size + sizeof(void*)));
	if (NULL == str_hub)
		return (ENOMEM);
	str_hub->shbskt = shbskt;
	str_hub->name = (uint8_t*)(str_hub + 1);
	str_hub->name_size = name_size;
	memcpy(str_hub->name, name, name_size);
	str_hub->status = SH_STATUS_OK;
	TAILQ_INIT(&str_hub->cli_head);
	//str_hub->cli_count = 0;
	str_hub->zero_cli_time = gettime_monotonic();
	str_hub->tpt = tpt;
	//str_hub->src = NULL;
	//str_hub->src_cnt = 0;
	//mem_bzero(&str_hub->s, sizeof(str_hub_settings_t));

	TAILQ_INSERT_HEAD(&shbskt->thr_data[tp_thread_get_num(tpt)].hub_head,
	    str_hub, next);

	LOG_INFO_FMT("%s: Created.", str_hub->name);

	(*str_hub_ret) = str_hub;
	return (0);
}

void
str_hub_destroy(str_hub_p str_hub) {
	size_t i;
	str_hub_cli_p strh_cli, strh_cli_temp;

	LOGD_EV("...");

	if (NULL == str_hub)
		return;

	/* Remove all sources. */
	for (i = 0; i < str_hub->src_cnt; i ++) {
		str_hub_src_remove(str_hub->src[i]);
	}
	/* Remove hub from thread hubs list. */
	TAILQ_REMOVE(&str_hub->shbskt->thr_data[tp_thread_get_num(str_hub->tpt)].hub_head,
	    str_hub, next);

	/* Destroy all connected clients. */
	TAILQ_FOREACH_SAFE(strh_cli, &str_hub->cli_head, next, strh_cli_temp) {
		str_hub_cli_destroy(strh_cli);
	}

	LOG_INFO_FMT("%s: Destroyed.", str_hub->name);

	str_hub_settings_free_data(&str_hub->s);

	mem_filld(str_hub, (sizeof(str_hub_t) + str_hub->name_size));
	free(str_hub);
}

int
str_hub_settings_set(str_hub_p str_hub, str_hub_settings_p s) {

	LOGD_EV_FMT("... %zx", s);

	if (NULL == str_hub || NULL == s)
		return (EINVAL);
	/* Unset / free previous. */
	str_hub_settings_free_data(&str_hub->s);
	/* Set new. */
	memcpy(&str_hub->s, s, sizeof(str_hub_settings_t));
	/* Extra copy */
	str_src_settings_copy(&str_hub->s.str_src_settings, &s->str_src_settings);
	/* Copy custom HTTP headers to new buffer. */
	if (NULL == s->cust_http_hdrs || 0 == s->cust_http_hdrs_size) {
		s->cust_http_hdrs = NULL;
		s->cust_http_hdrs_size = 0;
	}
	str_hub->s.cust_http_hdrs = malloc((s->cust_http_hdrs_size + 16));
	if (NULL == str_hub->s.cust_http_hdrs) {
		s->cust_http_hdrs_size = 0;
		return (ENOMEM);
	}
	if (NULL != s->cust_http_hdrs) {
		/* Add start CRLF. */
		memcpy(str_hub->s.cust_http_hdrs, "\r\n", 2);
		/* Custom headers body. */
		memcpy((str_hub->s.cust_http_hdrs + 2), s->cust_http_hdrs,
		    s->cust_http_hdrs_size);
		str_hub->s.cust_http_hdrs_size = (s->cust_http_hdrs_size + 2);
		str_hub->s.cust_http_hdrs[str_hub->s.cust_http_hdrs_size] = 0;
	}
	/* Add final CRLFCRLF. */
	memcpy((str_hub->s.cust_http_hdrs + str_hub->s.cust_http_hdrs_size),
	    "\r\n\r\n", 5);
	str_hub->s.cust_http_hdrs_size += 4;

	s = &str_hub->s; /* Use short name. */

	/* sec->ms, kb -> bytes */
	skt_opts_cvt(SKT_OPTS_MULT_K, &s->skt_opts);
	s->skt_opts.snd_timeout /= 1000; // In seconds!
	/* Correct values. */
	if (s->skt_opts.snd_lowat > s->skt_opts.snd_buf)
		s->skt_opts.snd_lowat = s->skt_opts.snd_buf;
	s->precache *= 1024;
	//s->zero_cli_timeout =; // In seconds!
	return (0);
}


str_hub_cli_p
str_hub_cli_alloc(uint32_t cli_type, uint32_t cli_sub_type) {
	str_hub_cli_p strh_cli;

	LOGD_EV("...");

	strh_cli = zalloc(sizeof(str_hub_cli_t));
	if (NULL == strh_cli)
		return (NULL);
	/* Set. */
	strh_cli->cli_type = cli_type;
	strh_cli->cli_sub_type = cli_sub_type;

	return (strh_cli);
}

void
str_hub_cli_destroy(str_hub_cli_p strh_cli) {
	int error;
	str_hub_p str_hub;
	char straddr[STR_ADDR_LEN];
	size_t tm;

	LOGD_EV("...");

	if (NULL == strh_cli)
		return;
	tp_task_stop(strh_cli->tptask);
	str_hub = strh_cli->str_hub;
	/* str_hub specified only if client attached to stream hub. */
	if (NULL != str_hub) {
		if (0 != LOG_IS_ENABLED()) {
			sa_addr_port_to_str(&strh_cli->remonte_addr,
			    straddr, sizeof(straddr), NULL);
			LOG_INFO_FMT("%s - %s: deattached, cli_count = %zu",
			    str_hub->name, straddr, (str_hub->cli_count - 1));
		}
		/* Remove from stream hub. */
		TAILQ_REMOVE(&str_hub->cli_head, strh_cli, next);
		/* Update counters. */
		if (0 != (STR_HUB_CLI_STATE_F_POLL & strh_cli->state)) {
			str_hub->poll_cli_count --;
		}
		str_hub->cli_count --;
		if (0 == str_hub->cli_count) {
			str_hub->zero_cli_time = gettime_monotonic();
		}
		/* Send HTTP headers if needed. */
		if (STR_HUB_CLI_T_TCP_HTTP == strh_cli->cli_type &&
		    0 == (STR_HUB_CLI_STATE_F_HTTP_HDRS_SENDED & strh_cli->state) &&
		    0 == strh_cli->rpos.iov_off) {
			error = str_hub_cli_send_http_hdr(str_hub->shbskt,
			    strh_cli, 503, 1, &tm);
			if (0 == error || EAGAIN == error) {
				str_hub->sended_count += tm; /* Hub stat update. */
			}
		}
	}

	if (NULL != strh_cli->free_cb) {
		strh_cli->free_cb(strh_cli, strh_cli->tptask, strh_cli->udata);
	}
	tp_task_destroy(strh_cli->tptask);

	if (NULL != strh_cli->user_agent)
		free(strh_cli->user_agent);
	mem_filld(strh_cli, sizeof(str_hub_cli_t));
	free(strh_cli);
}

int
str_hub_cli_set_user_agent(str_hub_cli_p strh_cli, const char *ua,
    const size_t ua_size) {

	if (NULL == strh_cli)
		return (EINVAL);
	if (NULL != strh_cli->user_agent) { /* Remove prevous value. */
		free(strh_cli->user_agent);
		strh_cli->user_agent = NULL;
		strh_cli->user_agent_size = 0;
	}
	if (NULL == ua || 0 == ua_size) /* Empty value. */
		return (0);
	strh_cli->user_agent = mem_dup2(ua, ua_size, 1);
	if (NULL == strh_cli->user_agent)
		return (ENOMEM);
	strh_cli->user_agent_size = ua_size;

	return (0);
}

tp_task_p
str_hub_cli_export_tptask(str_hub_cli_p strh_cli) {
	tp_task_p tptask;

	if (NULL == strh_cli)
		return (NULL);
	tptask = strh_cli->tptask;
	strh_cli->tptask = NULL;
	return (tptask);
}

int
str_hub_cli_import_tptask(str_hub_cli_p strh_cli, tp_task_p tptask,
    tpt_p tpt) {

	if (NULL == strh_cli || NULL == tptask)
		return (EINVAL);
	/* Convert to "ready to write notifier". */
	tp_task_stop(tptask);
	tp_task_udata_set(tptask, strh_cli);
	tp_task_tp_cb_func_set(tptask, tp_task_notify_handler);
	tp_task_flags_set(tptask, TP_TASK_F_CLOSE_ON_DESTROY);
	tp_task_tpt_set(tptask, tpt);
	strh_cli->tptask = tptask;

	return (0);
}

int
str_hub_cli_attach(str_hub_p str_hub, str_hub_cli_p strh_cli) {
	int error;
	char straddr[STR_ADDR_LEN];

	LOGD_EV("...");

	if (NULL == str_hub || NULL == strh_cli)
		return (EINVAL);

	/* kb -> bytes */
	strh_cli->precache *= 1024;
	strh_cli->snd_block_min_size *= 1024;
	/* Set. */
	strh_cli->str_hub = str_hub;
	if (0 == strh_cli->precache) { /* Hub default. */
		strh_cli->precache = str_hub->s.precache;
	}
	if (0 == strh_cli->snd_block_min_size) { /* Hub default. */
		strh_cli->snd_block_min_size = str_hub->s.skt_opts.snd_lowat;
	}
	strh_cli->conn_time = gettime_monotonic();
	strh_cli->last_snd_time = strh_cli->conn_time;
	/* Correct values. */
	strh_cli->snd_block_min_size = MIN(strh_cli->snd_block_min_size,
	    str_hub->s.skt_opts.snd_buf);

	/* Apply some hub setting/s to new client. */
	if (0 == (STR_HUB_S_F_PRECACHE_WAIT & str_hub->s.flags)) {
		strh_cli->state |= STR_HUB_CLI_STATE_F_PRECACHE_DONE;
	}

	/* Convert to "ready to write notifier". */
	str_hub_cli_import_tptask(strh_cli, strh_cli->tptask, str_hub->tpt);

	/* Tune socket. */
	error = skt_opts_apply_ex(tp_task_ident_get(strh_cli->tptask),
	    SO_F_TCP_ES_CONN_MASK, &str_hub->s.skt_opts, 0, NULL);
	if (0 != LOG_IS_ENABLED()) {
		sa_addr_port_to_str(&strh_cli->remonte_addr, straddr,
		    sizeof(straddr), NULL);
		if (0 != error) {
			sa_addr_port_to_str(&strh_cli->remonte_addr,
			    straddr, sizeof(straddr), NULL);
			LOG_ERR_FMT(error, "%s - %s: skt_opts_apply_ex()",
			    str_hub->name, straddr);
		}
		LOG_INFO_FMT("%s - %s: attached, cli_count = %zu",
		    str_hub->name, straddr, (str_hub->cli_count + 1));
		LOGD_INFO_FMT("%s - %s: attached, snd_block_min_size = %zu, precache = %zu",
		    str_hub->name, straddr, strh_cli->snd_block_min_size,
		    strh_cli->precache);
	}
	TAILQ_INSERT_HEAD(&str_hub->cli_head, strh_cli, next);
	str_hub->cli_count ++;

	error = str_hub_send_to_client(strh_cli, NULL, UINT64_MAX);
	if (0 != error) {
		str_hub_cli_destroy(strh_cli);
	}

	return (0);
}

int
str_hub_cli_send_http_hdr(str_hubs_bckt_p shbskt, str_hub_cli_p strh_cli,
    uint32_t http_status_code, int conn_close, size_t *send_size) {
	iovec_t iov[4];
	struct msghdr mhdr;
	ssize_t ios;
	uint8_t buf[1024];
	str_hub_p str_hub;

	if (NULL == strh_cli || NULL == shbskt)
		return (EINVAL);
	str_hub = strh_cli->str_hub;
	mem_bzero(&mhdr, sizeof(mhdr));
	/* Gen HTTP resp line + headers. */
	mhdr.msg_iov = (struct iovec*)iov;
	mhdr.msg_iovlen = 3;
	if (200 == http_status_code) {
		iov[0].iov_base = (uint8_t*)"HTTP/1.1 200 OK\r\n";
		iov[0].iov_len = 17;
		if (NULL != str_hub) {
			iov[2].iov_base = str_hub->s.cust_http_hdrs;
			iov[2].iov_len = str_hub->s.cust_http_hdrs_size;
		} else {
			iov[2].iov_base = (uint8_t*)"\r\n";
			iov[2].iov_len = 2;	
		}
	} else {
		iov[0].iov_base = (uint8_t*)buf;
		iov[0].iov_len = (size_t)snprintf((char*)buf, sizeof(buf), 
		    "HTTP/1.1 %"PRIu32" %s\r\n",
		    http_status_code,
		    http_get_err_descr(http_status_code, NULL));
		iov[2].iov_base = (uint8_t*)"\r\n";
		iov[2].iov_len = 2;
	}
	iov[1].iov_base = (uint8_t*)shbskt->base_http_hdrs;
	iov[1].iov_len = shbskt->base_http_hdrs_size;
	if (0 == conn_close) {
		iov[1].iov_len -= (sizeof(STR_HUBS_HTTP_CONN_CLOSE) - 1);
	}

	/* Skip allready sended data. */
	iovec_set_offset(mhdr.msg_iov, (size_t)mhdr.msg_iovlen, strh_cli->rpos.iov_off);
	ios = sendmsg((int)tp_task_ident_get(strh_cli->tptask), &mhdr,
	    (MSG_DONTWAIT | MSG_NOSIGNAL));
	if (-1 == ios) /* Error happen. */
		return (errno);
	if (NULL != send_size) {
		(*send_size) = (size_t)ios;
	}
	LOGD_EV_FMT("HTTP hdr: %zu", ios);
	strh_cli->rpos.iov_off += (size_t)ios;
	if (iovec_calc_size(mhdr.msg_iov, (size_t)mhdr.msg_iovlen) > (size_t)ios) /* Not all HTTP headers sended. */
		return (EAGAIN); /* Try to send next headers part later. */
	strh_cli->rpos.iov_off = 0;

	return (0);
}


int
str_hub_send_msg(str_hubs_bckt_p shbskt, const uint8_t *name, size_t name_size,
    uint32_t cmd, void *arg1, size_t arg2) {
	int error;
	str_hub_msg_data_p msg_data;
	tpt_p tpt;

	if (NULL == shbskt || NULL == name ||
	    0 == name_size || STR_HUB_NAME_MAX_SIZE <= name_size)
		return (EINVAL);
	msg_data = zalloc(sizeof(str_hub_msg_data_t) + name_size + sizeof(void*));
	if (NULL == msg_data)
		return (ENOMEM);
	msg_data->shbskt = shbskt;
	msg_data->name = (uint8_t*)(msg_data + 1);
	memcpy(msg_data->name, name, name_size);
	msg_data->name[name_size] = 0;
	msg_data->name_size = name_size;
	msg_data->cmd = cmd;
	msg_data->arg1 = arg1;
	msg_data->arg2 = arg2;

	LOGD_EV_FMT("%s:...", msg_data->name);

	tpt = str_hub_tpt_get_by_name(shbskt->tp, name, name_size);
	error = tpt_msg_send(tpt, NULL, TP_MSG_F_SELF_DIRECT,
	    str_hub_send_msg_cb, msg_data);
	if (0 != error)
		free(msg_data);
	return (error);
	
}
void
str_hub_send_msg_cb(tpt_p tpt, void *udata) {
	int error = 0;
	str_hub_msg_data_p msg_data = (str_hub_msg_data_p)udata;
	str_hub_p str_hub;
	str_hub_cli_p strh_cli;
	str_hub_cli_attach_data_p attach_data = NULL;

	LOGD_EV_FMT("%s:...", msg_data->name);

	str_hub = str_hub_find(msg_data->shbskt, tpt, 1,
	    msg_data->name, msg_data->name_size);

	switch (msg_data->cmd) {
	case STR_HUB_CMD_CREATE: /* arg1: otional: str_hub_settings_p */
		if (NULL != str_hub) {
			LOG_ERR_FMT(EEXIST, "%s: str_hub_create() - allready exist!!!", msg_data->name);
			free(msg_data->arg1);
			break;
		}
		error = str_hub_create(msg_data->shbskt, tpt,
		    msg_data->name, msg_data->name_size, &str_hub);
		if (0 != error) {
			LOG_ERR_FMT(error, "%s: str_hub_create() fail.",
			    msg_data->name);
			free(msg_data->arg1);
			break;
		}
		/* Passtrouth. */
	case STR_HUB_CMD_SETTING_SET: /* arg1: str_hub_settings_p */
		if (NULL == msg_data->arg1)
			break;
		error = str_hub_settings_set(str_hub,
		    (str_hub_settings_p)msg_data->arg1);
		str_hub_settings_free_data((str_hub_settings_p)msg_data->arg1);
		free(msg_data->arg1);
		LOG_ERR_FMT(error, "%s: str_hub_settings_set() fail.",
		    msg_data->name);
		break;
	case STR_HUB_CMD_SRC_ADD: /* arg1: str_src_settings_p, arg2: type */
		if (NULL == str_hub) {
			LOG_ERR_FMT(EINVAL, "%s: str_hub_src_add() - HUB NOT FOUND!!!", msg_data->name);
			free(msg_data->arg1);
			break;
		}
		error = str_hub_src_add(str_hub, (uint32_t)msg_data->arg2,
		    (str_src_settings_p)msg_data->arg1);
		free(msg_data->arg1);
		LOG_ERR_FMT(error, "%s: str_hub_src_add() fail.",
		    msg_data->name);
		break;
	case STR_HUB_CMD_CLI_ADD: /* arg1: str_hub_cli_p */
		strh_cli = (str_hub_cli_p)msg_data->arg1;
		if (NULL == strh_cli)
			break;
		tp_task_tpt_set(strh_cli->tptask, tpt);
		if (NULL == str_hub) {
			if (STR_HUB_CLI_T_TCP_HTTP == strh_cli->cli_type) {
				strh_cli->state |= STR_HUB_CLI_STATE_F_HTTP_HDRS_SENDED;
				str_hub_cli_send_http_hdr(msg_data->shbskt, strh_cli, 404, 1, NULL);
			}
			str_hub_cli_destroy(strh_cli);
			break;
		}
		error = str_hub_cli_attach(str_hub, strh_cli);
		if (0 != error) {
			LOG_ERR_FMT(error, "%s: str_hub_cli_attach() fail.", msg_data->name);
			str_hub_cli_destroy(strh_cli);
		}
		break;
	case STR_HUB_CMD_CREATE_CLI_ADD:
		attach_data = (str_hub_cli_attach_data_p)msg_data->arg1;
		strh_cli = attach_data->strh_cli;
		if (NULL == str_hub) { /* Create new hub, set settins, add source. */
			error = str_hub_create(msg_data->shbskt, tpt,
			    msg_data->name, msg_data->name_size, &str_hub);
			LOG_ERR_FMT(error, "%s: str_hub_create() fail.",
			    msg_data->name);
			if (0 == error) {
				error = str_hub_settings_set(str_hub,
				    attach_data->hub_s);
				LOG_ERR_FMT(error, "%s: str_hub_settings_set() fail.", msg_data->name);
			}
			if (0 == error) {
				error = str_hub_src_add(str_hub,
				    attach_data->src_type,
				    attach_data->src_s);
				LOG_ERR_FMT(error, "%s: str_hub_src_add() fail.", msg_data->name);
			}
		}
		if (0 == error &&
		    NULL != strh_cli) {
			tp_task_tpt_set(strh_cli->tptask, tpt);
			error = str_hub_cli_attach(str_hub, strh_cli);
			LOG_ERR_FMT(error, "%s: str_hub_cli_attach() fail.", msg_data->name);
		}
		if (0 != error) { /* CleanUp on errors. */
			str_hub_cli_destroy(strh_cli);
			str_hub_destroy(str_hub);
		}
		if (0 != (STR_HUB_CLI_ATTACH_DATA_F_HUB & attach_data->free_flags)) {
			str_hub_settings_free_data(attach_data->hub_s);
			free(attach_data->hub_s);
		}
		if (0 != (STR_HUB_CLI_ATTACH_DATA_F_SRC & attach_data->free_flags)) {
			str_src_settings_free_data(attach_data->src_s);
			free(attach_data->src_s);
		}
		free(msg_data->arg1);
		break;
	}

	free(msg_data);
}


int
str_hub_send_to_client(str_hub_cli_p strh_cli, struct timespec *ts,
    size_t data2send) {
	int error = 0;
	str_hub_p str_hub;
	str_hub_thrd_p thr_data;
	r_buf_p r_buf;
	mpeg2_ts_data_p m2ts;
	size_t i = 0, iov_cnt, drop_size, data_avail2send, transfered_size, loop_cnt;
	ssize_t ios;
	off_t sbytes = 0;
	uintptr_t ident, r_buf_fd;
	struct msghdr mhdr;
	char straddr[STR_ADDR_LEN];


	if (NULL == strh_cli || NULL == strh_cli->str_hub)
		return (EINVAL);
	str_hub = strh_cli->str_hub;
	loop_cnt = 0;
	transfered_size = 0;
	data_avail2send = 0;
	if (NULL == str_hub->src[str_hub->src_current])
		goto send_done;
	r_buf_fd = str_hub->src[str_hub->src_current]->r_buf_fd;
	r_buf = str_hub->src[str_hub->src_current]->r_buf;
	if (NULL == r_buf)
		goto send_done;
	thr_data = &str_hub->shbskt->thr_data[tp_thread_get_num(str_hub->tpt)];
	ident = tp_task_ident_get(strh_cli->tptask);

send_start:
	/* Send HTTP headers if needed. */
	if (0 == (STR_HUB_CLI_STATE_F_HTTP_HDRS_SENDED & strh_cli->state) &&
	    STR_HUB_CLI_T_TCP_HTTP == strh_cli->cli_type) {
		error = str_hub_cli_send_http_hdr(str_hub->shbskt,
		    strh_cli, 200,
		    1, /* Disable "Connection: close" for hls data req. */
		    &transfered_size);
		if (EAGAIN == error) {
			data_avail2send = UINT64_MAX; /* Activate polling. */
			goto send_done; /* Try to send next headers part later. */
		}
		if (0 != error) { /* Error happen. */
			strh_cli->last_error = error;
			/* Supress some errors. */
			error = SKT_ERR_FILTER(error);
			return (error);
		}
		strh_cli->rpos.iov_off = 0;
		strh_cli->state |= STR_HUB_CLI_STATE_F_HTTP_HDRS_SENDED;
		if (STR_HUB_CLI_ST_TCP_HTTP_HEAD == strh_cli->cli_sub_type)
			return (-1); /* Destroy me. */
	}
	/* Send MPEG2-TS DVB PIDs data. */
	if (0 == (STR_HUB_CLI_STATE_F_MPEG2TS_HDRS_SENDED & strh_cli->state) &&
	    0 != (STR_SRC_S_F_M2TS_ANALYZING & str_hub->src[str_hub->src_current]->s.flags) &&
	    NULL != str_hub->src[str_hub->src_current]->m2ts) {
		m2ts = str_hub->src[str_hub->src_current]->m2ts;
		mem_bzero(&mhdr, sizeof(mhdr));
		mhdr.msg_iov = (struct iovec*)thr_data->iov;
		mhdr.msg_iovlen = (int)(2 + m2ts->prog_cnt);
		thr_data->iov[0].iov_base = m2ts->pat.ts_psi_packets;
		thr_data->iov[0].iov_len = m2ts->pat.ts_psi_packets_size;
		thr_data->iov[1].iov_base = m2ts->cat.ts_psi_packets;
		thr_data->iov[1].iov_len = m2ts->cat.ts_psi_packets_size;
		/* Add: PMT PIDs. */
		for (i = 0; i < m2ts->prog_cnt && (IOV_MAX - 2) > i; i ++) {
			thr_data->iov[(2 + i)].iov_base =
			    m2ts->progs[i].pmt.ts_psi_packets;
			thr_data->iov[(2 + i)].iov_len =
			    m2ts->progs[i].pmt.ts_psi_packets_size;
		}
		/* Add: EIT PIDs. */
		thr_data->iov[mhdr.msg_iovlen].iov_base = m2ts->eit.ts_psi_packets;
		thr_data->iov[mhdr.msg_iovlen].iov_len = m2ts->eit.ts_psi_packets_size;
		mhdr.msg_iovlen ++;
		/* Skip allready sended data. */
		iovec_set_offset(mhdr.msg_iov, (size_t)mhdr.msg_iovlen, strh_cli->rpos.iov_off);
		ios = sendmsg((int)ident, &mhdr, (MSG_DONTWAIT | MSG_NOSIGNAL));
		if (-1 == ios) { /* Error happen. */
			strh_cli->last_error = errno;
			/* Supress some errors. */
			error = SKT_ERR_FILTER(errno);
			return (error);
		}
		transfered_size = (size_t)ios;
		data_avail2send = iovec_calc_size(mhdr.msg_iov, (size_t)mhdr.msg_iovlen);
		strh_cli->rpos.iov_off += transfered_size;
		LOGD_EV_FMT("DVB hdr: %zu / %zu", transfered_size, data_avail2send);
		if (data_avail2send > transfered_size) { /* Not all PIDs data sended. */
			data_avail2send = UINT64_MAX; /* Activate polling. */
			goto send_done; /* Try to send next headers part later. */
		}
		strh_cli->rpos.iov_off = 0;
		strh_cli->state |= STR_HUB_CLI_STATE_F_MPEG2TS_HDRS_SENDED;
	}
	/* Init uninitialized client rpos. */
	if (0 == (STR_HUB_CLI_STATE_F_RPOS_INITIALIZED & strh_cli->state)) {
		/* Correct values. */
		strh_cli->precache = MIN(strh_cli->precache, (r_buf->size - 1024));
		if (0 != (STR_SRC_S_F_M2TS_ANALYZING & str_hub->src[str_hub->src_current]->s.flags) &&
		    NULL != str_hub->src[str_hub->src_current]->m2ts &&
		    0 != str_hub->src[str_hub->src_current]->m2ts->key_frames_cnt) { /* Smart precache: from nearest key frame. */
			m2ts = str_hub->src[str_hub->src_current]->m2ts;
			r_buf_rpos_init_near(r_buf, &strh_cli->rpos,
			    strh_cli->precache,
			    m2ts->key_frames_rpos,
			    m2ts->key_frames_cnt);
		} else { /* Simple precache. */
			r_buf_rpos_init(r_buf, &strh_cli->rpos,
			    strh_cli->precache);
		}
		strh_cli->state |= STR_HUB_CLI_STATE_F_RPOS_INITIALIZED;
		LOGD_EV_FMT("Precache: %zu",
		    r_buf_data_avail_size(r_buf, &strh_cli->rpos, NULL));
	}

	/* Get data avail for client. */
	data_avail2send = r_buf_data_avail_size(r_buf, &strh_cli->rpos, &drop_size);

	/* PreCache processing. */
	if (0 == (STR_HUB_CLI_STATE_F_PRECACHE_DONE & strh_cli->state)) {
		/* Correct values. */
		strh_cli->precache = MIN(strh_cli->precache, (r_buf->size - 1024));
		if (0 == data_avail2send &&
		    0 != drop_size) {
			/* Do not drop new clients. */
			/* Reinit pos. */
			strh_cli->state &= ~STR_HUB_CLI_STATE_F_RPOS_INITIALIZED;
			loop_cnt ++;
			if (1 < loop_cnt)
				return (0); /* Avoid loop. */
			goto send_start;
		} else {
			if (strh_cli->precache > data_avail2send)
				goto send_done; /* Not enough data for this client. */
		}
		strh_cli->state |= STR_HUB_CLI_STATE_F_PRECACHE_DONE;
	} else {
		if (0 == data_avail2send &&
		    0 != drop_size) {
			str_hub->dropped_count ++;
			if (0 != (STR_HUB_S_F_DROP_SLOW_CLI & str_hub->s.flags)) {
				if (0 != LOG_IS_ENABLED()) {
					sa_addr_port_to_str(&strh_cli->remonte_addr, straddr, sizeof(straddr), NULL);
					LOG_EV_FMT("%s - %s: Drop lagged client, dropped = %zu",
					    str_hub->name, straddr, drop_size);
				}
				return (ESPIPE); /* Destroy me. */
			} else {
				if (0 != LOG_IS_ENABLED()) {
					sa_addr_port_to_str(&strh_cli->remonte_addr, straddr, sizeof(straddr), NULL);
					LOG_EV_FMT("%s - %s: Restart lagged client, dropped = %zu",
					    str_hub->name, straddr, drop_size);
				}
				/* Reset state flags to restart client. */
				strh_cli->state &= ~(
				    STR_HUB_CLI_STATE_F_MPEG2TS_HDRS_SENDED |
				    STR_HUB_CLI_STATE_F_RPOS_INITIALIZED |
				    STR_HUB_CLI_STATE_F_PRECACHE_DONE);
				loop_cnt ++;
				if (1 < loop_cnt)
					return (0); /* Avoid loop. */
				goto send_start;
			}
		}
	}
	if (strh_cli->snd_block_min_size > data_avail2send)
		goto send_done; /* Not enough data for this client. */

	/* This fix for linux: data2send = UINT64_MAX (in threadpool/threadpool.c). */
	if (data2send > data_avail2send) {
		data2send = data_avail2send;
	}

	iov_cnt = r_buf_data_get(r_buf, &strh_cli->rpos, data2send,
	    thr_data->iov, IOV_MAX, NULL, NULL);
	if (0 == iov_cnt) /* Nothink to send? */
		goto send_done;

	/* Send. */
	if (0 != (STR_HUB_S_F_ZERO_COPY_ON_SEND & str_hub->s.flags)) { /* Zero Copy send. */
		r_buf_data_get_conv2off(r_buf, thr_data->iov, iov_cnt);
		for (i = 0; i < iov_cnt; i ++) {
			error = skt_sendfile(r_buf_fd, ident,
			    (off_t)thr_data->iov[i].iov_base, thr_data->iov[i].iov_len,
			    (SKT_SF_F_NODISKIO), &sbytes);
			transfered_size += (size_t)sbytes;
			if (0 != error)
				break;
		}
	} else { /* Old way. */
		mem_bzero(&mhdr, sizeof(mhdr));
		mhdr.msg_iov = (struct iovec*)thr_data->iov;
		mhdr.msg_iovlen = (int)iov_cnt;
		ios = sendmsg((int)ident, &mhdr, (MSG_DONTWAIT | MSG_NOSIGNAL));
		if (-1 == ios) {
			error = errno;
		} else {
			transfered_size = (size_t)ios;
		}
	}
	strh_cli->last_error = error;
	/* Supress some errors. */
	error = SKT_ERR_FILTER(error);
	if (0 != error &&
	    0 != (STR_HUB_S_F_ZERO_COPY_ON_SEND & str_hub->s.flags)) {
		LOG_ERR_FMT(error, "skt_sendfile(): i = %zu, off = %zu, size = %zu, sbytes = %zu, transfered_size = %zu",
		    i, (size_t)thr_data->iov[i].iov_base,
		    thr_data->iov[i].iov_len, (size_t)sbytes, transfered_size);
	}
	/* Update client read pos. */
	r_buf_rpos_inc(r_buf, &strh_cli->rpos, transfered_size);


send_done: /* Update: last send time, polling status, send counter. */
#if 0
	LOGD_INFO_FMT("data2send = %zu, iov2snd = %zu, transfered_size = %zu",
	     data2send, iovec_calc_size(thr_data->iov, iov_cnt), transfered_size);
	/*if (0 != strh_cli->rpos.iov_off)
		LOGD_EV_FMT("iov_off = %i", strh_cli->rpos.iov_off); //*/
	/*LOGD_EV_FMT("%s: transfered_size = %zu, data2send = %zu, snd_block_min_size = %i",
	    str_hub->name, transfered_size, data2send, strh_cli->snd_block_min_size);//*/
#endif
	/* Update last send time. */
	if (NULL != ts) {
		strh_cli->last_snd_time = ts->tv_sec;
	} else {
		strh_cli->last_snd_time = gettime_monotonic();
	}
	/* Hub stat update. */
	str_hub->sended_count += transfered_size;
	if (0 != error)
		return (error);

	/* Polling handle. */
	if (0 == (STR_HUB_CLI_STATE_F_POLL & strh_cli->state)) {
		if (data_avail2send > transfered_size &&
		    (data_avail2send - transfered_size) > strh_cli->snd_block_min_size &&
		    0 != (STR_HUB_S_F_USE_SEND_POLLING & str_hub->s.flags)) {
			if (0 != LOG_IS_ENABLED())
				sa_addr_port_to_str(&strh_cli->remonte_addr, straddr, sizeof(straddr), NULL);
			LOGD_EV_FMT("%s - %s: switch to POLL: transfered_size = %zu, data2send = %zu, iov_off = %i",
			    str_hub->name, straddr, transfered_size, data2send, strh_cli->rpos.iov_off);
			strh_cli->state |= STR_HUB_CLI_STATE_F_POLL;
			error = tp_task_start(strh_cli->tptask, TP_EV_WRITE, 0,
			    /*str_hub->s.snd_timeout*/ 0, 0, NULL,
			    (tp_task_cb)strh_cli_send_ready_cb);
			if (0 != error) {
				strh_cli->state &= ~STR_HUB_CLI_STATE_F_POLL;
				LOG_ERR_FMT(error, "%s - %s: fail on switch to POLL mode",
				    str_hub->name, straddr);
			} else {
				str_hub->poll_cli_count ++;
			}
		}
	} else {
		if (0 == transfered_size) {// || strh_cli->snd_block_min_size > data_avail2send) {
			if (0 != LOGD_IS_ENABLED()) {
				sa_addr_port_to_str(&strh_cli->remonte_addr, straddr, sizeof(straddr), NULL);
				LOGD_EV_FMT("%s - %s: switch to normal: data2send = %zu",
				    str_hub->name, straddr, data2send);
			}
			str_hub->poll_cli_count --;
			strh_cli->state &= ~STR_HUB_CLI_STATE_F_POLL;
			tp_task_stop(strh_cli->tptask);
		}
	}

	return (0);
}

int
strh_cli_send_ready_cb(tp_task_p tptask __unused, int error, int eof __unused,
    size_t data2send, void *arg) {
	str_hub_cli_p strh_cli = arg;
	str_hub_p str_hub = strh_cli->str_hub;
	char straddr[STR_ADDR_LEN];

	if (0 != error) {
		if (0 != LOG_IS_ENABLED()) {
			sa_addr_port_to_str(&strh_cli->remonte_addr, straddr, sizeof(straddr), NULL);
			LOG_ERR_FMT(error, "%s - %s: on send", str_hub->name, straddr);
		}
	} else {
		error = str_hub_send_to_client(strh_cli, NULL, data2send);
		if (0 != LOG_IS_ENABLED()) {
			sa_addr_port_to_str(&strh_cli->remonte_addr, straddr, sizeof(straddr), NULL);
			LOG_ERR_FMT(error, "%s - %s: str_hub_send_to_client(), dropped = %zu",
			    str_hub->name, straddr);
		}
	}
	if (0 != error) {
		str_hub_cli_destroy(strh_cli);
		return (TP_TASK_CB_NONE);
	}
	if (0 == (STR_HUB_CLI_STATE_F_POLL & strh_cli->state)) {
		return (TP_TASK_CB_NONE); /* Polling disabled. */
	}
	return (TP_TASK_CB_CONTINUE);
}

int
str_hub_send_to_clients(str_hub_p str_hub, struct timespec *ts) {
	int error;
	str_hub_cli_p strh_cli, strh_cli_temp;

	if (NULL == str_hub->src[str_hub->src_current] ||
	    NULL == str_hub->src[str_hub->src_current]->r_buf)
		return (0);

	TAILQ_FOREACH_SAFE(strh_cli, &str_hub->cli_head, next, strh_cli_temp) {
		if (0 != (STR_HUB_CLI_STATE_F_POLL & strh_cli->state))
			continue; /* Skip polling clients. */
		error = str_hub_send_to_client(strh_cli, ts, UINT64_MAX);
		if (0 != error) {
			str_hub_cli_destroy(strh_cli);
		}
	} /* TAILQ_FOREACH_SAFE() */
	return (0);
}


int
str_hub_src_add(str_hub_p str_hub, uint32_t type, str_src_settings_p s) {
	str_src_p src;
	int error;

	LOGD_EV("...");

	if (NULL == str_hub || NULL == s ||
	    STR_HUB_SRC_MAX_CNT == str_hub->src_cnt)
		return (EINVAL);

	/* Overwrite some s. */
	if (0 != (STR_HUB_S_F_ZERO_COPY_ON_SEND & str_hub->s.flags))
		s->flags |= STR_SRC_S_F_ENABLE_RING_BUF_IN_FILE;

	error = str_src_create(type, s, str_hub->tpt,
	    str_hub_src_on_state, str_hub_src_on_data, str_hub, &src);
	if (0 != error)
		return (error);
	if (0 == str_hub->src_cnt) { /* Auto start first source. */
		error = str_src_start(src);
		if (0 != error && EALREADY != error) {
			str_src_destroy(src);
			return (error);
		}
		str_hub->src_current = 0;
	}
	str_hub->src[str_hub->src_cnt] = src;
	str_hub->src_cnt ++;

	return (0);
}

size_t
str_hub_src_index_get(str_hub_p str_hub, str_src_p src) {
	size_t i;

	if (NULL == str_hub || NULL == src)
		return ((size_t)~0);
	for (i = 0; i < str_hub->src_cnt; i ++) {
		if (src == str_hub->src[i])
			return (i);
	}
	return ((size_t)~0);
}

int
str_hub_src_switch(str_hub_p str_hub, size_t src_current_new) {
	size_t i;
	int error;

	LOGD_EV("...");

	if (NULL == str_hub || src_current_new >= str_hub->src_cnt)
		return (EINVAL);

	/* Stop secondary sources. */
	for (i = (src_current_new + 1); i < str_hub->src_cnt; i ++) {
		str_src_stop(str_hub->src[i]);
	}
	/* Start. */
	for (i = src_current_new; i < str_hub->src_cnt; i ++) {
		error = str_src_start(str_hub->src[i]);
		if (0 != error && EALREADY != error)
			continue;
		str_hub->src_current = i;
		str_hub->status = SH_STATUS_OK; // XXX
		break;
	}
	
	return (0);
}

void
str_hub_src_remove(str_src_p src) {
	size_t i;
	str_hub_p str_hub;

	LOGD_EV("...");

	if (NULL == src)
		return;
	str_hub = src->udata;
	for (i = 0; i < str_hub->src_cnt; i ++) {
		if (str_hub->src[i] == src) {
			str_hub->src[i] = NULL;
			if (i == str_hub->src_cnt)
				str_hub->src_cnt --;
			break;
		}
	}
	str_src_destroy(src);
}


/* After data received. */
int
str_hub_src_on_data(str_src_p src, struct timespec *ts, void *udata) {
	str_hub_p str_hub;

	if (NULL == src)
		return (EINVAL);
	str_hub = udata;
	if (src != str_hub->src[str_hub->src_current])
		return (0);
	/* Clients send. */
	str_hub_send_to_clients(str_hub, ts);
	
	return (0);
}

/* State and/or Status changed. */
int
str_hub_src_on_state(str_src_p src, void *udata, uint32_t state, uint32_t status) {
	str_hub_p str_hub;
	str_hub_cli_p strh_cli, strh_cli_temp;
	char stat_str[1024];
	size_t i, tm, src_current;

	if (NULL == src)
		return (EINVAL);
	str_hub = udata;
	src_current = str_hub_src_index_get(str_hub, src);

	if (0 != LOG_IS_ENABLED()) {
		tm = 0;
		if (0 == status)
			tm += (size_t)snprintf((stat_str + tm), (sizeof(stat_str) - tm), "OK ");
		if (0 != (status & STR_SRC_STATUS_ERROR))
			tm += (size_t)snprintf((stat_str + tm), (sizeof(stat_str) - tm), "ERROR ");
		if (0 != (status & STR_SRC_STATUS_ENCRYPTED))
			tm += (size_t)snprintf((stat_str + tm), (sizeof(stat_str) - tm), "ENCRYPTED ");
		if (0 != (status & STR_SRC_STATUS_ZERO_BITRATE))
			tm += (size_t)snprintf((stat_str + tm), (sizeof(stat_str) - tm), "ZERO_BITRATE ");
		if (0 != (status & STR_SRC_STATUS_LOW_BITRATE))
			tm += (size_t)snprintf((stat_str + tm), (sizeof(stat_str) - tm), "LOW_BITRATE ");
		if (0 != (status & STR_SRC_STATUS_STREAM_ERRORS))
			tm += (size_t)snprintf((stat_str + tm), (sizeof(stat_str) - tm), "STREAM_ERRORS ");
		LOG_INFO_FMT("%s - %zu/%zu: %s [%"PRIu32": %s]...",
		    str_hub->name, (src_current + 1), str_hub->src_cnt, str_src_states[state], status, stat_str);
	}

	switch (state) {
	case STR_SRC_STATE_STOP:
	case STR_SRC_STATE_RUNNING:
	case STR_SRC_STATE_MONITORING:
	case STR_SRC_STATE_CONNECTING:
	case STR_SRC_STATE_DATA_REQ:
	case STR_SRC_STATE_DATA_WAITING:
	case STR_SRC_STATE_RECONNECTING:
		break;
	case STR_SRC_STATE_CURRENT:
		break;
	default:
		break;
	}

	if (STR_SRC_STATE_RUNNING == state ||
	    STR_SRC_STATE_DATA_WAITING == state) {
		if (0 == status) {
			/* Switch back to main. */
			if (str_hub->src_current > src_current) {
				LOG_INFO_FMT("%s: switch src from %zu to %zu - restored",
				    str_hub->name, (str_hub->src_current + 1), (src_current + 1));
				str_hub_src_switch(str_hub, src_current);
			}
		} else { /* Try to backup src. */
			for (tm = 1, i = 0; i <= str_hub->src_current; i ++) {
				if (NULL == str_hub->src[i])
					continue;
				if (0 == str_hub->src[i]->status) {
					tm = 0;
					break;
				}
			}
			if (tm) {
				str_hub_src_switch(str_hub, (src_current + 1));
				LOG_INFO_FMT("%s: switch src from %zu to %zu - backup",
				    str_hub->name, (str_hub->src_current + 1), (src_current + 2));
			}
		}
	}


	/* Do not update hub status from not current source. */
	if (str_hub->src_current != src_current)
		return (0);

	if (0 == status) {
		str_hub->status = SH_STATUS_OK;
	} else {
		str_hub->status = 0;
		if (0 != (status & STR_SRC_STATUS_ERROR))
			str_hub->status |= SH_STATUS_ERROR;
		if (0 != (status & STR_SRC_STATUS_ENCRYPTED))
			str_hub->status |= SH_STATUS_ENCRYPTED;
		if (0 != (status & STR_SRC_STATUS_ZERO_BITRATE))
			str_hub->status |= SH_STATUS_ZERO_BITRATE;
		if (0 != (status & STR_SRC_STATUS_LOW_BITRATE))
			str_hub->status |= SH_STATUS_LOW_BITRATE;
		if (0 != (status & STR_SRC_STATUS_STREAM_ERRORS))
			str_hub->status |= SH_STATUS_STREAM_ERRORS;
	}

	/* No traffic check. */
	if (0 != (str_hub->status & SH_STATUS_ZERO_BITRATE)) { /* No traffic... */
		if (0 == (STR_HUB_S_F_ZERO_SRC_BITRATE_PERSISTENT & str_hub->s.flags)) {
			LOG_INFO_FMT("%s: No more traffic, selfdestroy.", str_hub->name);
			str_hub_destroy(str_hub);
			return (-1);
		}
		/* Disconnect all. */
		if (0 != str_hub->cli_count) {
			TAILQ_FOREACH_SAFE(strh_cli, &str_hub->cli_head, next, strh_cli_temp)
				str_hub_cli_destroy(strh_cli);
		}
	}

	return (0);
}


