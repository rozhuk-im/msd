/*-
 * Copyright (c) 2012-2024 Rozhuk Ivan <rozhuk.im@gmail.com>
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
#include <sys/time.h>
#include <sys/mman.h>
#include <sys/stat.h> /* For mode constants */
#include <sys/file.h> /* flock */
#include <net/if.h>

#include <stdlib.h> /* malloc, exit */
#include <pthread.h>
#include <stdio.h> /* snprintf, fprintf */
#include <unistd.h> /* close, write, sysconf */
#include <fcntl.h> /* For O_* constants */
#include <string.h> /* bcopy, bzero, memcpy, memmove, memset, strerror... */
#include <time.h>
#include <errno.h>
#include <syslog.h>

#include "utils/macro.h"
#include "threadpool/threadpool.h"
#include "threadpool/threadpool_task.h"
#include "net/socket.h"
#include "net/socket_address.h"
#include "net/utils.h"
#include "utils/buf_str.h"
#include "utils/ring_buffer.h"
#include "proto/rtp.h"
#include "proto/mpeg2ts.h"
#include "utils/mem_utils.h"
#include "proto/http.h"
#include "crypto/hash/md5.h"
#include "utils/xml.h"

#include "stream_mpeg2ts.h"
#include "stream_src.h"


#define STR_SRC_UDP_PKT_SIZE_STD	1500
#define STR_SRC_UDP_PKT_SIZE_MAX	65612 /* 349 * 188 */


void	str_src_init(str_src_p src);
int	str_src_connect(str_src_p src, int retry);
/* retry:
 * 0: First connect attempt: conn_try = 0, addr_index = 0;
 * 1: Retry connect to selected addr: conn_try ++
 * other: Try connect to other addr: conn_try = 0, addr_index ++;
 */
int	str_src_connect_retry(str_src_p src);
static int str_src_connected(tp_task_p tptask, int error, void *arg);
static int str_src_send_http_req_done_cb(tp_task_p tptask, int error,
	    io_buf_p buf, uint32_t eof, size_t transfered_size, void *arg);
static int str_src_recv_http_cb(tp_task_p tptask, int error, uint32_t eof,
	    size_t data2transfer_size, void *arg);
static int str_src_recv_tcp_cb(tp_task_p tptask, int error, uint32_t eof,
	    size_t data2transfer_size, void *arg);
static int str_src_recv_mc_cb(tp_task_p tptask, int error, uint32_t eof,
	    size_t data2transfer_size, void *arg);

void	str_src_r_buf_f_name_gen(str_src_p src);
int	str_src_r_buf_alloc(str_src_p src);
void	str_src_r_buf_free(str_src_p src);
int	str_src_r_buf_add(str_src_p src, struct timespec *ts,
	    uint8_t *buf, size_t buf_size);

int	str_src_state_update(str_src_p src, uint32_t state, int sset, uint32_t status);
#define SRC_STATUS_CLR_BIT	1 /* Clear bits. */
#define SRC_STATUS_SET_BIT	2 /* Set bits. */
#define SRC_STATUS_SET_VAL	3 /* Set value. */



uint32_t
str_src_get_type_from_str(const char *str, size_t str_size) {
	uint32_t ret = STR_SRC_TYPE_UNKNOWN, i;

	for (i = 1; i <= STR_SRC_TYPE___COUNT__; i ++) {
		if (str_size != str_src_types_sizes[i] ||
		    0 != memcmp(str, str_src_types[i], str_size))
			continue;
		ret = i;
		break;
	}
	return (ret);
}


int
str_src_timer_proc(str_src_p src, struct timespec *ts_now, struct timespec *ts_prev) {
	uint64_t tm64;
	time_t tmt;
	int error;

	if (NULL == src)
		return (EINVAL);

	switch (src->state) {
	case STR_SRC_STATE_RUNNING:
		break; /* Process. */
	case STR_SRC_STATE_MONITORING:
	case STR_SRC_STATE_DATA_WAITING: /* For timeout handling */
		src->baud_rate = 0;
		break; /* Process. */
	case STR_SRC_STATE_RECONNECTING:
		if (0 != (src->s.src_conn_params->tcp.retry_interval)) {
			tmt = (src->last_recv_time.tv_sec +
			    (time_t)src->s.src_conn_params->tcp.retry_interval);
			if (tmt > ts_now->tv_sec ||
			    (tmt == ts_now->tv_sec &&
			    src->last_recv_time.tv_nsec > ts_now->tv_nsec))
				return (0); /* Reconnect later (not yet). */
		}
		str_src_connect(src, 1);
		/* Passtrouth. */
	default: /* No process. */
		src->baud_rate = 0;
		return (0);
	}
	/* No traffic check. */
	if (0 != src->s.skt_opts.rcv_timeout) {
		tmt = (src->last_recv_time.tv_sec + (time_t)src->s.skt_opts.rcv_timeout);
		if (tmt < ts_now->tv_sec ||
		    (tmt == ts_now->tv_sec && src->last_recv_time.tv_nsec < ts_now->tv_nsec)) {
			if (STR_SRC_TYPE_TCP == src->type ||
			    STR_SRC_TYPE_TCP_HTTP == src->type) {
				if (STR_SRC_STATE_DATA_WAITING == src->state) {
					/* Timeout first data receive, reconnect. */
					str_src_connect(src, 1);
					return (0);
				}
			}
			error = str_src_state_update(src, STR_SRC_STATE_CURRENT,
			    SRC_STATUS_SET_BIT, STR_SRC_STATUS_ZERO_BITRATE);
		} else {
			error = str_src_state_update(src, STR_SRC_STATE_CURRENT,
			    SRC_STATUS_CLR_BIT, STR_SRC_STATUS_ZERO_BITRATE);
		}
		if (0 != error)
			return (error);
	}
	/* Re join multicast group timer. */
	if ((STR_SRC_TYPE_MULTICAST == src->type ||
	     STR_SRC_TYPE_MULTICAST_RTP == src->type) &&
	    0 != src->s.src_conn_params->mc.rejoin_time &&
	    src->next_rejoin_time < ts_now->tv_sec) {
		src->next_rejoin_time = (ts_now->tv_sec + (time_t)src->s.src_conn_params->mc.rejoin_time);
		for (int join = 0; join < 2; join ++) {
		    error = skt_mc_join(tp_task_ident_get(src->tptask),
		        join,
			src->s.src_conn_params->mc.if_index,
			&src->s.src_conn_params->mc.udp.addr);
		    SYSLOG_ERR(LOG_ERR, error, "skt_mc_join().");
		}
	}

	/* Stat update. */
	/* Source updates. */
	/* Update stream source baud rate. */
	if (0 == (ts_now->tv_sec & 1)) { /* every 2 second */
		if (0 != src->received_count) {
			tm64 = (1000000000 * ((uint64_t)src->last_recv_time.tv_sec - (uint64_t)ts_prev->tv_sec));
			tm64 += ((uint64_t)src->last_recv_time.tv_nsec - (uint64_t)ts_prev->tv_nsec);
			if (0 == tm64) /* Prevent division by zero. */
				tm64 ++;
			src->baud_rate = ((src->received_count * 4000000000) / tm64);
			src->received_count = 0;
		} else {
			src->baud_rate = 0;
		}
		/* Update status: encrypted? */
#if 0 /* XXX not yet */
		tm64 = 0; /* un encrypted. */
		for (i = 0; i < src->ts_pids_cnt; i ++) {
			if (0 != src->ts_pids[i].sc) {
				tm64 ++;
				break;
			}
		}
		if (0 != tm64) {
			error = str_src_state_update(src, STR_SRC_STATE_CURRENT,
			    SRC_STATUS_SET_BIT, SH_STATUS_ENCRYPTED);
		} else {
			error = str_src_state_update(src, STR_SRC_STATE_CURRENT,
			    SRC_STATUS_CLR_BIT, SH_STATUS_ENCRYPTED);
		}
		if (0 != error)
			return (error);
#endif
	}
	/* Update stream source error rate. */
	if (0 != src->s.error_rate_interval && ts_prev->tv_sec >=
	    (src->last_err_calc_time.tv_sec + (time_t)src->s.error_rate_interval)) {
		src->error_rate = src->error_count; /* per 'error_rate_interval' seconds. */
		src->error_count = 0;
		memcpy(&src->last_err_calc_time, ts_now, sizeof(struct timespec));
		if (src->error_rate >= src->s.error_rate_max) {
			error = str_src_state_update(src, STR_SRC_STATE_CURRENT,
			    SRC_STATUS_SET_BIT, STR_SRC_STATUS_STREAM_ERRORS);
		} else {
			error = str_src_state_update(src, STR_SRC_STATE_CURRENT,
			    SRC_STATUS_CLR_BIT, STR_SRC_STATUS_STREAM_ERRORS);
		}
		if (0 != error)
			return (error);
	}

	return (0);
}



int
str_src_cust_hdrs_load(const uint8_t *buf, size_t buf_size,
    uint8_t **hdrs, size_t *hdrs_size_ret) {
	const uint8_t *cur_pos, *ptm;
	uint8_t *cur_w_pos;
	size_t tm, hdrs_size;

	if (NULL == buf || 0 == buf_size || NULL == hdrs || NULL == hdrs_size_ret)
		return (EINVAL);

	/* First pass: calc buffer size for headers. */
	hdrs_size = 0;
	cur_pos = NULL;
	while (0 == xml_get_val_args(buf, buf_size, &cur_pos, NULL, NULL,
	    &ptm, &tm, (const uint8_t*)"header", NULL)) {
		hdrs_size += (tm + 2); /* 2 = crlf. */
	}

	if (0 == hdrs_size) { /* No custom headers. */
		(*hdrs) = NULL;
		(*hdrs_size_ret) = 0;
		return (ESPIPE);
	}

	hdrs_size -= 2; /* Remove last crlf. */
	(*hdrs) = malloc((hdrs_size + sizeof(void*)));
	if (NULL == (*hdrs))
		return (ENOMEM);
	/* Second pass: copy headers to buffer. */
	cur_pos = NULL;
	cur_w_pos = (*hdrs);
	while (0 == xml_get_val_args(buf, buf_size, &cur_pos, NULL, NULL,
	    &ptm, &tm, (const uint8_t*)"header", NULL)) {
		memcpy(cur_w_pos, ptm, tm);
		cur_w_pos += tm;
		memcpy(cur_w_pos, "\r\n", 2);
		cur_w_pos += 2;
	}
	(*hdrs)[hdrs_size] = 0;
	(*hdrs_size_ret) = hdrs_size;
	return (0);
}


void
str_src_settings_def(str_src_settings_p s_ret) {

	SYSLOGD_EX(LOG_DEBUG, "... %zx", (size_t)s_ret);

	if (NULL == s_ret)
		return;
	memset(s_ret, 0x00, sizeof(str_src_settings_t));

	skt_opts_init(STR_SRC_S_SKT_OPTS_INT_MASK,
	    STR_SRC_S_SKT_OPTS_INT_VALS, &s_ret->skt_opts);
	s_ret->skt_opts.mask |= SO_F_NONBLOCK;
	s_ret->skt_opts.bit_vals |= SO_F_NONBLOCK;
	s_ret->skt_opts.rcv_buf = STR_SRC_S_SKT_OPTS_SNDBUF;

	/* Default settings. */
	s_ret->flags = STR_SRC_S_DEF_FLAGS;
	s_ret->skt_opts.mask |= STR_SRC_S_DEF_SKT_OPTS_MASK;
	s_ret->skt_opts.bit_vals |= STR_SRC_S_DEF_SKT_OPTS_VALS;
	s_ret->skt_opts.rcv_buf = STR_SRC_S_DEF_SKT_OPTS_RCV_BUF;
	s_ret->skt_opts.rcv_lowat = STR_SRC_S_DEF_SKT_OPTS_RCVLOWAT;
	s_ret->skt_opts.rcv_timeout = STR_SRC_S_DEF_SKT_OPTS_RCVTIMEO;
	mpeg2_ts_def_settings(&s_ret->m2ts_s);
	s_ret->ring_buf_size = STR_SRC_S_DEF_RING_BUF_SIZE;
	s_ret->error_rate_interval = STR_SRC_S_DEF_ERR_RATE_INTVL;
	s_ret->error_rate_max = STR_SRC_S_DEF_ERR_RATE_MAX;
	memcpy(s_ret->r_buf_f_path, STR_SRC_S_DEF_R_BUF_F_PATH, sizeof(STR_SRC_S_DEF_R_BUF_F_PATH));
	s_ret->src_conn_params = NULL;
}

int
str_src_xml_load_settings(const uint8_t *buf, size_t buf_size,
    str_src_settings_p s) {
	const uint8_t *data;
	size_t data_size;

	SYSLOGD_EX(LOG_DEBUG, "... %zx", (size_t)s);

	if (NULL == buf || 0 == buf_size || NULL == s)
		return (EINVAL);

	/* Read from config. */
	if (0 == xml_get_val_args(buf, buf_size, NULL, NULL, NULL,
	    &data, &data_size, (const uint8_t*)"MPEG2TS", "fEnable", NULL)) {
		yn_set_flag32(data, data_size, STR_SRC_S_F_M2TS_ANALYZING, &s->flags);
	}
	if (0 == xml_get_val_args(buf, buf_size, NULL, NULL, NULL,
	    &data, &data_size, (const uint8_t*)"MPEG2TS", NULL)) {
		mpeg2_ts_xml_load_settings(data, data_size, &s->m2ts_s);
	}

	xml_get_val_size_t_args(buf, buf_size, NULL, &s->ring_buf_size,
	    (const uint8_t*)"ringBufSize", NULL);
	if (0 == xml_get_val_args(buf, buf_size, NULL, NULL, NULL,
	    &data, &data_size, (const uint8_t*)"ringBufStorePath", NULL) &&
	    (sizeof(s->r_buf_f_path) - 1) > data_size) {
		memcpy(s->r_buf_f_path, data, data_size);
		s->r_buf_f_path[data_size] = 0;
	}
	xml_get_val_uint64_args(buf, buf_size, NULL, &s->error_rate_interval,
	    (const uint8_t*)"errorRateInterval", NULL);
	xml_get_val_uint64_args(buf, buf_size, NULL, &s->error_rate_max,
	    (const uint8_t*)"errorRateMax", NULL);
	/* Socket options. */
	if (0 == xml_get_val_args(buf, buf_size, NULL, NULL, NULL,
	    &data, &data_size, (const uint8_t*)"skt", NULL)) {
		skt_opts_xml_load(data, data_size,
		    STR_SRC_S_SKT_OPTS_LOAD_MASK, &s->skt_opts);
	}

	return (0);
}

void
str_src_conn_def(uint32_t type, str_src_conn_params_p src_conn_params) {

	if (NULL == src_conn_params)
		return;
	memset(src_conn_params, 0x00, sizeof(str_src_conn_params_t));

	switch (type) {
	case STR_SRC_TYPE_UDP:
	case STR_SRC_TYPE_UDP_RTP:
		break;
	case STR_SRC_TYPE_MULTICAST:
	case STR_SRC_TYPE_MULTICAST_RTP:
		src_conn_params->mc.if_index = STR_SRC_CONN_DEF_IFINDEX;
		src_conn_params->mc.rejoin_time = 0;
		break;
	case STR_SRC_TYPE_TCP_HTTP:
	case STR_SRC_TYPE_TCP:
		src_conn_params->tcp.conn_timeout = STR_SRC_CONN_DEF_CONN_TIMEOUT;
		src_conn_params->tcp.retry_interval = STR_SRC_CONN_DEF_RETRY_INTERVAL;
		src_conn_params->tcp.conn_try_count = STR_SRC_CONN_DEF_TRY_COUNT;
		break;
	default:
		break;
	}
}

int
str_src_conn_xml_load_settings(const uint8_t *buf, size_t buf_size,
    uint32_t type, void *conn) {
	const uint8_t *data;
	size_t data_size;
	char if_name[(IFNAMSIZ + 1)];

	if (NULL == buf || 0 == buf_size || NULL == conn)
		return (EINVAL);

	/* Read from config. */
	switch (type) {
	case STR_SRC_TYPE_UDP:
	case STR_SRC_TYPE_UDP_RTP:
	case STR_SRC_TYPE_MULTICAST:
	case STR_SRC_TYPE_MULTICAST_RTP:
		if (0 == xml_get_val_args(buf, buf_size, NULL, NULL, NULL,
		    &data, &data_size, (const uint8_t*)"udp", "address", NULL)) {
			sa_addr_port_from_str(&((str_src_conn_udp_p)conn)->addr,
			    (const char*)data, data_size);
		}
		if (STR_SRC_TYPE_UDP == type ||
		    STR_SRC_TYPE_UDP_RTP == type)
			break;
		if (0 == xml_get_val_args(buf, buf_size, NULL, NULL, NULL,
		    &data, &data_size, (const uint8_t*)"multicast", "ifName", NULL)) {
			memcpy(if_name, data, MIN(IFNAMSIZ, data_size));
			if_name[MIN(IFNAMSIZ, data_size)] = 0;
			((str_src_conn_mc_p)conn)->if_index = if_nametoindex(if_name);
		}
		xml_get_val_uint32_args(data, data_size, NULL,
		    &((str_src_conn_mc_p)conn)->rejoin_time,
		    (const uint8_t*)"multicast", "rejoinTime", NULL);
		break;
	case STR_SRC_TYPE_TCP:
	case STR_SRC_TYPE_TCP_HTTP:
		xml_get_val_uint64_args(buf, buf_size, NULL,
		    &((str_src_conn_tcp_p)conn)->conn_timeout,
		    (const uint8_t*)"tcp", "connectTimeout", NULL);
		xml_get_val_uint64_args(buf, buf_size, NULL,
		    &((str_src_conn_tcp_p)conn)->retry_interval,
		    (const uint8_t*)"tcp", "reconnectInterval", NULL);
		xml_get_val_uint64_args(buf, buf_size, NULL,
		    &((str_src_conn_tcp_p)conn)->conn_try_count,
		    (const uint8_t*)"tcp", "reconnectCount", NULL);

		// XXX
		((str_src_conn_tcp_p)conn)->addr_count = 0;
		if (0 == xml_get_val_args(buf, buf_size, NULL, NULL, NULL,
		    &data, &data_size, (const uint8_t*)"tcp", "remonteHostname", NULL)) {
			((str_src_conn_tcp_p)conn)->host = data;
			((str_src_conn_tcp_p)conn)->host_size = data_size;
			if (0 == sa_addr_port_from_str(&((str_src_conn_tcp_p)conn)->addr[((str_src_conn_tcp_p)conn)->addr_count],
			    (const char*)data, data_size))
				((str_src_conn_tcp_p)conn)->addr_count ++;
			// STR_SRC_CONN_TCP_MAX_ADDRS
		}
		if (STR_SRC_TYPE_TCP == type)
			break;

		if (0 == xml_get_val_args(buf, buf_size, NULL, NULL, NULL,
		    &data, &data_size, (const uint8_t*)"http", "urlPath", NULL)) {
			((str_src_conn_http_p)conn)->url_path = data;
			((str_src_conn_http_p)conn)->url_path_size = data_size;
		}
		/* Load custom http headers. */
		if (0 == xml_get_val_args(buf, buf_size, NULL, NULL, NULL,
		    &data, &data_size, (const uint8_t*)"http", "headersList", NULL)) {
			str_src_cust_hdrs_load(data, data_size,
			    (uint8_t**)&((str_src_conn_http_p)conn)->cust_http_hdrs,
			    &((str_src_conn_http_p)conn)->cust_http_hdrs_size);
		}
		break;
	default:
		break;
	}
	return (0);
}

int
str_src_settings_copy(str_src_settings_p dst, str_src_settings_p src) {
	int error;

	SYSLOGD_EX(LOG_DEBUG, "... %zx <- %zx", (size_t)dst, (size_t)src);

	if (NULL == dst || NULL == src)
		return (EINVAL);

	memcpy(dst, src, sizeof(str_src_settings_t));
	/* Extra copy. */
	error = mpeg2_ts_settings_copy(&dst->m2ts_s, &src->m2ts_s);

	return (error);
}

void
str_src_settings_free_data(str_src_settings_p s) {

	SYSLOGD_EX(LOG_DEBUG, "... %zx", (size_t)s);

	if (NULL == s)
		return;
	/* Extra free */
	mpeg2_ts_settings_free_data(&s->m2ts_s);
	/*if (NULL != s->cust_http_hdrs)
		free(s->cust_http_hdrs);*/
}


/* Generate http request */
int
str_src_conn_http_gen_request(const uint8_t *host, size_t host_size,
    const uint8_t *url_path, size_t url_path_size,
    const uint8_t *cust_http_hdrs, size_t cust_http_hdrs_size,
    str_src_conn_http_p conn_http) {
	const uint8_t *ptm;

	if (NULL == conn_http)
		return (EINVAL);
	if (NULL == host || 0 == host_size) {
		host = conn_http->tcp.host;
		host_size = conn_http->tcp.host_size;
	}
	if (NULL == url_path || 0 == url_path_size) {
		url_path = conn_http->url_path;
		url_path_size = conn_http->url_path_size;
	}
	if (NULL == host || 0 == host_size ||
	    (NULL == url_path && 0 != url_path_size))
		return (EINVAL);
	if (NULL == cust_http_hdrs || 0 == cust_http_hdrs_size) {
		cust_http_hdrs = conn_http->cust_http_hdrs;
		cust_http_hdrs_size = conn_http->cust_http_hdrs_size;
	}

	conn_http->req_buf = io_buf_alloc(IO_BUF_FLAGS_STD,
	    (1024 + host_size + url_path_size + cust_http_hdrs_size));
	if (NULL == conn_http->req_buf)
		return (ENOMEM);
	IO_BUF_COPYIN_CSTR(conn_http->req_buf, "GET /");

	ptm = IO_BUF_FREE_GET(conn_http->req_buf);
	io_buf_copyin(conn_http->req_buf, url_path, url_path_size);
	conn_http->url_path = (ptm - 1); /* Include slash. */
	conn_http->url_path_size = (url_path_size + 1);
	IO_BUF_COPYIN_CSTR(conn_http->req_buf, " HTTP/1.1\r\n");

	IO_BUF_COPYIN_CSTR(conn_http->req_buf, "Host: ");
	ptm = IO_BUF_FREE_GET(conn_http->req_buf);
	io_buf_copyin(conn_http->req_buf, host, host_size);
	conn_http->tcp.host = ptm;
	conn_http->tcp.host_size = host_size;
	IO_BUF_COPYIN_CSTR(conn_http->req_buf, "\r\n");

	if (NULL != cust_http_hdrs && 0 != cust_http_hdrs_size) {
		io_buf_copyin(conn_http->req_buf, cust_http_hdrs,
		    cust_http_hdrs_size);
		if (0 != memcmp((cust_http_hdrs + (cust_http_hdrs_size - 2)),
		    "\r\n", 2)) {
			IO_BUF_COPYIN_CSTR(conn_http->req_buf, "\r\n");
		}
	}

	IO_BUF_COPYIN_CSTR(conn_http->req_buf,
	    "Connection: close\r\n"
	    "\r\n");

	(*((uint8_t*)IO_BUF_FREE_GET(conn_http->req_buf))) = 0;
	SYSLOGD_EX(LOG_DEBUG, "req out: size=%zu"
	    "\n==========================================="
	    "\n%s"
	    "\n===========================================",
	    conn_http->req_buf->used, conn_http->req_buf->data);

	return (0);
}


int
str_src_create(uint32_t type, str_src_settings_p s, tpt_p tpt,
    str_src_on_state_cb on_state, str_src_on_data_rcvd_cb on_data,
    void *udata, str_src_p *src_ret) {
	int error;
	str_src_p src;

	SYSLOGD_EX(LOG_DEBUG, "...");

	if (NULL == udata || NULL == tpt || NULL == src_ret)
		return (EINVAL);

	switch (type) {
	case STR_SRC_TYPE_UDP:
	case STR_SRC_TYPE_UDP_RTP:
	case STR_SRC_TYPE_MULTICAST:
	case STR_SRC_TYPE_MULTICAST_RTP:
	case STR_SRC_TYPE_TCP:
	case STR_SRC_TYPE_TCP_HTTP:
		break;
	default:
		return (EINVAL);
	}
	src = calloc(1, (sizeof(str_src_t) + sizeof(str_src_conn_params_t) + 64));
	if (NULL == src)
		return (ENOMEM);
	/* Settings. */
	if (NULL == s) {
		str_src_settings_def(&src->s);
	} else {
		str_src_settings_copy(&src->s, s);
	}
	/* Safe connection data localy. */
	src->s.src_conn_params = (void*)(src + 1);
	memcpy(src->s.src_conn_params, s->src_conn_params, sizeof(str_src_conn_params_t));
	/* Use short name. */
	s = &src->s;
	/* sec->ms, kb -> bytes */
	skt_opts_cvt(SKT_OPTS_MULT_K, &s->skt_opts);
	s->skt_opts.rcv_timeout /= 1000; // In seconds!
	s->ring_buf_size *= 1024;
	/* Correct values. */
	if (s->skt_opts.rcv_lowat > s->skt_opts.rcv_buf) {
		s->skt_opts.rcv_lowat = s->skt_opts.rcv_buf;
	}

	/* MPEG2TS */
	error = mpeg2_ts_data_alloc(&src->m2ts, &s->m2ts_s);
	mpeg2_ts_settings_free_data(&s->m2ts_s);
	if (0 != error) {
		free(src);
		return (error);
	}
	/* Init src. */
	src->type = type;
	src->r_buf_fd = (uintptr_t)-1;
	if (0 == memcmp(src->s.r_buf_f_path, "shm", 4))
		src->s.flags |= STR_SRC_S_F_ENABLE_RING_BUF_SHM_FILE;

	src->tpt = tpt;
	src->on_state = on_state;
	src->on_data = on_data;
	src->udata = udata;
	str_src_init(src);

	(*src_ret) = src;
	return (0);
}

void
str_src_init(str_src_p src) {

	SYSLOGD_EX(LOG_DEBUG, "...");

	if (NULL == src)
		return;
	
	src->r_buf_w_off = 0;
	clock_gettime(CLOCK_MONOTONIC_FAST, &src->last_recv_time);
	src->received_count = 0;
	src->baud_rate = 0;
	memcpy(&src->last_err_calc_time, &src->last_recv_time, sizeof(struct timespec));
	src->error_count = 0;
	src->error_rate = 0;
	src->state = STR_SRC_STATE_STOP;
	src->status = STR_SRC_STATUS_OK;
	src->last_err = 0;
	src->http_resp_code = 0;
	//src->rtp_sn = 0;
	//src->rtp_sn_errors = 0;
}

void
str_src_destroy(str_src_p src) {

	SYSLOGD_EX(LOG_DEBUG, "...");

	if (NULL == src)
		return;

	str_src_stop(src);

	switch (src->type) {
	case STR_SRC_TYPE_TCP:
		if (NULL != src->s.src_conn_params->tcp.host) {
			free((void*)src->s.src_conn_params->tcp.host);
		}
		break;
	case STR_SRC_TYPE_TCP_HTTP:
		io_buf_free(src->s.src_conn_params->http.req_buf);
		break;
	}
	mpeg2_ts_data_free(src->m2ts);
	free(src);
}


int
str_src_start(str_src_p src) {
	uintptr_t skt;
	str_src_settings_p s;
	str_src_conn_udp_p conn_udp;
	int error;

	SYSLOGD_EX(LOG_DEBUG, "...");

	if (NULL == src)
		return (EINVAL);
	if (STR_SRC_STATE_STOP != src->state)
		return (EALREADY);
	/* Use short name. */
	s = &src->s;
	str_src_init(src);

	switch (src->type) {
	case STR_SRC_TYPE_UDP:
	case STR_SRC_TYPE_UDP_RTP:
		/* Passtrouth. */
	case STR_SRC_TYPE_MULTICAST:
	case STR_SRC_TYPE_MULTICAST_RTP:
		conn_udp = &s->src_conn_params->udp;
		error = skt_bind(&conn_udp->addr, SOCK_DGRAM, IPPROTO_UDP,
		    (SO_F_NONBLOCK | SKT_OPTS_GET_FLAGS_VALS(&s->skt_opts, SKT_BIND_FLAG_MASK)),
		    &skt);
		if (0 != error) { /* Bind to mc addr fail, try bind inaddr_any. */
			error = skt_bind_ap(conn_udp->addr.ss_family,
			    NULL, sa_port_get(&conn_udp->addr),
			    SOCK_DGRAM, IPPROTO_UDP,
			    (SO_F_NONBLOCK | SKT_OPTS_GET_FLAGS_VALS(&s->skt_opts, SKT_BIND_FLAG_MASK)),
			    &skt);
		}
		if (0 != error) {
			skt = (uintptr_t)-1;
			SYSLOG_ERR(LOG_ERR, error, "skt_mc_bind().");
			goto err_out;
		}
		if (STR_SRC_TYPE_MULTICAST == src->type ||
		    STR_SRC_TYPE_MULTICAST_RTP == src->type) {
			/* Join to multicast group. */
			error = skt_mc_join(skt, 1,
			    s->src_conn_params->mc.if_index,
			    &conn_udp->addr);
			if (0 != error) {
				SYSLOG_ERR(LOG_ERR, error, "skt_mc_join().");
				goto err_out;
			}
		}
		/* Tune socket. */
		error = skt_opts_apply_ex(skt, SO_F_UDP_BIND_AF_MASK,
		    &s->skt_opts, conn_udp->addr.ss_family, NULL);
		if (0 != error) {
			SYSLOG_ERR(LOG_ERR, error,
			    "skt_opts_apply_ex(SO_F_UDP_BIND_AF_MASK) fail.");
			goto err_out;
		}
		/* Create IO task for socket. */
		error = tp_task_notify_create(src->tpt, skt,
		    TP_TASK_F_CLOSE_ON_DESTROY, TP_EV_READ, 0, str_src_recv_mc_cb,
		    src, &src->tptask);
		if (0 != error) {
			SYSLOG_ERR(LOG_ERR, error, "tp_task_notify_create().");
			goto err_out;
		}
		return (str_src_state_update(src, STR_SRC_STATE_DATA_WAITING, 0, 0));
	case STR_SRC_TYPE_TCP:
	case STR_SRC_TYPE_TCP_HTTP:
		return (str_src_connect(src, 0));
	}
	return (0);
err_out:
	/* Error. */
	close((int)skt);
	str_src_init(src);
	src->last_err = error;
	str_src_state_update(src, STR_SRC_STATE_STOP,
	    SRC_STATUS_SET_BIT, STR_SRC_STATUS_ERROR);
	SYSLOG_ERR_EX(LOG_ERR, error, "...");
	return (error);
}

/* Close, free and reset all. */
void
str_src_stop(str_src_p src) {
	str_src_settings_p s;
	int error;

	SYSLOGD_EX(LOG_DEBUG, "...");

	if (NULL == src)
		return;
	if (STR_SRC_STATE_STOP == src->state)
		return;
	/* Use short name. */
	s = &src->s;
	
	str_src_init(src);

	switch (src->type) {
	case STR_SRC_TYPE_UDP:
	case STR_SRC_TYPE_UDP_RTP:
		break;
	case STR_SRC_TYPE_MULTICAST:
	case STR_SRC_TYPE_MULTICAST_RTP:
		/* Leave multicast group. */
		error = skt_mc_join(tp_task_ident_get(src->tptask), 0,
		    s->src_conn_params->mc.if_index,
		    &s->src_conn_params->udp.addr);
		SYSLOG_ERR(LOG_ERR, error, "skt_mc_join().");
		break;
	case STR_SRC_TYPE_TCP:
	case STR_SRC_TYPE_TCP_HTTP:
		break;
	}
	tp_task_destroy(src->tptask);
	src->tptask = NULL;
	/*if (NULL != src->ts_pids) {
		free(src->ts_pids);
		src->ts_pids = NULL;
	}*/
	str_src_r_buf_free(src);
}

int
str_src_restart(str_src_p src) {

	SYSLOGD_EX(LOG_DEBUG, "...");

	if (NULL == src)
		return (EINVAL);
	str_src_stop(src);
	return (str_src_start(src));
}


int
str_src_connect(str_src_p src, int retry) {
	uintptr_t skt = (uintptr_t)-1;
	str_src_conn_tcp_p conn_tcp;
	int error;
	char straddr[STR_ADDR_LEN];
	sockaddr_storage_t addr, *cur_addr;

	SYSLOGD_EX(LOG_DEBUG, "...");

	if (NULL == src)
		return (EINVAL);
	if (STR_SRC_TYPE_TCP != src->type &&
	    STR_SRC_TYPE_TCP_HTTP != src->type)
		return (EINVAL); /* Only for tcp connections. */
	switch (src->state) {
	case STR_SRC_STATE_STOP:
	case STR_SRC_STATE_RECONNECTING:
		break;
	default:
		return (EINVAL);
	}

	conn_tcp = &src->s.src_conn_params->tcp;
	switch (retry) {
	case 0: /* First connect attempt. */
		conn_tcp->conn_try = 0;
		conn_tcp->addr_index = 0;
		sa_addr_port_to_str(&conn_tcp->addr[conn_tcp->addr_index], straddr,
		    sizeof(straddr), NULL);
		syslog(LOG_INFO, "Connecting to %s...", straddr);
		break;
	case 1:  /* Retry connect to selected addr. */
		sa_addr_port_to_str(&conn_tcp->addr[conn_tcp->addr_index], straddr,
		    sizeof(straddr), NULL);
		syslog(LOG_INFO, "Retry %"PRIu64"/%"PRIu64" connect to %s...",
		    conn_tcp->conn_try, conn_tcp->conn_try_count, straddr);
		conn_tcp->conn_try ++;
		if (conn_tcp->conn_try < conn_tcp->conn_try_count)
			break;
		/* Tryes connect to addr exeed. */
		/* Passtrouth. */
	default:  /* Try connect to other addr. */
		conn_tcp->addr_index ++;
		if (conn_tcp->addr_index >= conn_tcp->addr_count) {
			syslog(LOG_INFO, "Cant connect.");
			error = EADDRNOTAVAIL;
			goto err_out;
		}
		conn_tcp->conn_try = 0;
		sa_addr_port_to_str(&conn_tcp->addr[conn_tcp->addr_index], straddr,
		    sizeof(straddr), NULL);
		syslog(LOG_INFO, "Try connect to other addr: %s...", straddr);
	}

	/* Check addr. */
	cur_addr = &conn_tcp->addr[conn_tcp->addr_index];
	if (STR_SRC_TYPE_TCP_HTTP == src->type) {
		if (0 == sa_port_get(cur_addr)) {
			memcpy(&addr, cur_addr, sizeof(addr));
			cur_addr = &addr;
			sa_port_set(cur_addr, HTTP_PORT);
		}
	}

	error = skt_connect(cur_addr, SOCK_STREAM, IPPROTO_TCP,
	    (SO_F_NONBLOCK), &skt);
	if (0 != error) {
		SYSLOG_ERR(LOG_ERR, error, "skt_connect().");
		goto err_out;
	}
	/* Create IO task for socket. */
	error = tp_task_connect_create(src->tpt, skt,
	    TP_TASK_F_CLOSE_ON_DESTROY, (conn_tcp->conn_timeout * 1000),
	    str_src_connected, src, &src->tptask);
	if (0 != error) {
		SYSLOG_ERR(LOG_ERR, error, "tp_task_connect_create().");
		goto err_out;
	}
	return (str_src_state_update(src, STR_SRC_STATE_CONNECTING, 0, 0));
err_out:
	/* Error: no retry here. */
	close((int)skt);
	str_src_init(src);
	src->last_err = error;
	str_src_state_update(src, STR_SRC_STATE_STOP,
	    SRC_STATUS_SET_BIT, STR_SRC_STATUS_ERROR);
	SYSLOG_ERR_EX(LOG_ERR, error, "...");
	return (error);
}

int
str_src_connect_retry(str_src_p src) {

	SYSLOGD_EX(LOG_DEBUG, "...");

	if (NULL == src)
		return (EINVAL);
	if (STR_SRC_TYPE_TCP != src->type &&
	    STR_SRC_TYPE_TCP_HTTP != src->type)
		return (EINVAL); /* Only for tcp connections. */
	if (STR_SRC_STATE_CONNECTING != src->state)
		return (EINVAL);
	str_src_stop(src);
	clock_gettime(CLOCK_MONOTONIC_FAST, &src->last_recv_time);
	
	return (str_src_state_update(src, STR_SRC_STATE_RECONNECTING, 0, 0));
}


static int
str_src_connected(tp_task_p tptask, int error, void *arg) {
	str_src_p src = arg;
	str_src_conn_http_p conn_http;

	SYSLOGD_EX(LOG_DEBUG, "...");

	if (0 != error) { /* Fail to connect. */
		SYSLOG_ERR_EX(LOG_ERR, error, "...");
		str_src_connect_retry(src);
		src->last_err = error;
		return (0);
	}
	/* Connected! */
	/* Tune socket. */
	error = skt_opts_apply_ex(tp_task_ident_get(tptask),
	    (SO_F_TCP_ES_CONN_MASK & ~SO_F_HALFCLOSE_RDWR),
	    &src->s.skt_opts, 0, NULL);
	if (0 != error) {
		SYSLOG_ERR(LOG_NOTICE, error,
		    "skt_opts_apply_ex(SO_F_TCP_ES_CONN_MASK & ~SO_F_HALFCLOSE_RDWR) fail.");
		goto err_out;
	}

	tp_task_stop(tptask);
	switch (src->type) {
	case STR_SRC_TYPE_TCP:
		str_src_send_http_req_done_cb(tptask, 0, NULL, 0, 0, src);
		break;
	case STR_SRC_TYPE_TCP_HTTP:
		conn_http = &src->s.src_conn_params->http;

		/* Convert to "ready to read notifier". */
		tp_task_tp_cb_func_set(tptask, tp_task_sr_handler);
		/* Start new IO task for socket. */
		IO_BUF_MARK_TRANSFER_ALL_USED(conn_http->req_buf);
		error = tp_task_start(tptask, TP_EV_WRITE, 0,
		    (conn_http->tcp.conn_timeout * 1000), 0, conn_http->req_buf,
		    str_src_send_http_req_done_cb);
		if (0 != error) {
			SYSLOG_ERR(LOG_ERR, error, "tp_task_start().");
			goto err_out;
		}
		str_src_state_update(src, STR_SRC_STATE_DATA_REQ, 0, 0);
		return (TP_TASK_CB_NONE);
	default: /* Should never happen. */
		error = EINVAL;
		goto err_out;
	}
	return (TP_TASK_CB_NONE);
err_out:
	/* Error. */
	SYSLOG_ERR_EX(LOG_ERR, error, "...");
	str_src_stop(src);
	src->last_err = error;
	return (TP_TASK_CB_NONE);
}

static int
str_src_send_http_req_done_cb(tp_task_p tptask, int error, io_buf_p buf __unused,
    uint32_t eof, size_t transfered_size __unused, void *arg) {
	str_src_p src = arg;

	//SYSLOGD_EX(LOG_DEBUG, "...");

	if (0 != error || 0 != eof) {
err_out:
		SYSLOG_ERR(LOG_DEBUG, error, "On receive.");
		if (0 != eof) {
			SYSLOGD_EX(LOG_DEBUG, "eof...");
		}
		src->last_err = error;
		str_src_connect_retry(src);
		return (TP_TASK_CB_NONE); /* Receiver destroyed. */
	}
	
	tp_task_stop(tptask);

	error = skt_opts_apply_ex(tp_task_ident_get(tptask),
	    SO_F_HALFCLOSE_WR, &src->s.skt_opts, 0, NULL);
	SYSLOG_ERR(LOG_NOTICE, error,
	    "skt_opts_apply_ex(SO_F_HALFCLOSE_WR) fail, not fatal.");

	/* Convert to "ready to read notifier". */
	tp_task_tp_cb_func_set(tptask, tp_task_notify_handler);
	/* Start new IO task for socket. */
	error = tp_task_start(tptask, TP_EV_READ, 0, 0, 0, NULL,
	    (tp_task_cb)((STR_SRC_TYPE_TCP_HTTP == src->type) ?
	    str_src_recv_http_cb : str_src_recv_tcp_cb));
	if (0 != error) {
		SYSLOG_ERR(LOG_ERR, error, "tp_task_start().");
		goto err_out;
	}
	str_src_state_update(src, STR_SRC_STATE_DATA_WAITING, 0, 0);
	return (TP_TASK_CB_NONE);
}

static int
str_src_recv_http_cb(tp_task_p tptask, int error, uint32_t eof,
    size_t data2transfer_size, void *arg) {
	str_src_p src = arg;
	uintptr_t ident;
	ssize_t ios;
	uint8_t *buf, *ptm, *ptm2;
	size_t transfered_size = 0, buf_size;
	http_resp_line_data_t resp_data;
	struct timespec	ts;

	SYSLOGD_EX(LOG_DEBUG, "...");

	if (0 != error || 0 != eof) {
err_out:
		SYSLOG_ERR(LOG_DEBUG, error, "On receive.");
		if (0 != eof) {
			SYSLOGD_EX(LOG_DEBUG, "eof...");
		}
		src->last_err = error;
		//str_src_restart(src);
		str_src_stop(src);
		src->last_err = error;
		str_src_state_update(src, STR_SRC_STATE_STOP,
		    SRC_STATUS_SET_BIT, STR_SRC_STATUS_ERROR);
		return (TP_TASK_CB_NONE); /* Receiver destroyed. */
	}
	if (NULL == src->r_buf) { /* Delay ring buf allocation. */
		error = str_src_r_buf_alloc(src);
		if (0 != error)
			goto err_out;
		error = str_src_state_update(src, STR_SRC_STATE_RUNNING, 0, 0);
		if (0 != error)
			return (TP_TASK_CB_NONE); /* Receiver destroyed. */
	}

	ident = tp_task_ident_get(tptask);
	while (transfered_size < data2transfer_size) { /* recv loop. */
		buf_size = r_buf_wbuf_get(src->r_buf, MPEG2_TS_PKT_SIZE_MAX, &buf);
		ios = recv((int)ident, (buf + src->r_buf_w_off),
		    (buf_size - src->r_buf_w_off), MSG_DONTWAIT);
		if (-1 == ios) {
			error = errno;
			if (0 == error) {
				error = EINVAL;
			}
			error = SKT_ERR_FILTER(error);
			break;
		}
		if (0 == ios)
			break;
		transfered_size += (size_t)ios;
		src->r_buf_w_off += (size_t)ios;
		ptm = mem_find_cstr(buf, src->r_buf_w_off, "\r\n\r\n");
		if (NULL == ptm)
			continue;
		// XXX
		error = http_parse_resp_line(buf, (size_t)(ptm - buf), &resp_data);
		if (0 != error)
			break;
		src->http_resp_code = resp_data.status_code;

		ptm[0] = 0;
		ptm += 4;
		SYSLOGD_EX(LOG_DEBUG, "ans in: size = %zu, off = %zu"
		    "\n==========================================="
		    "\n%s"
		    "\n===========================================",
		    src->r_buf_w_off, ios, buf);
		ptm2 = ptm;
		if (0 != mpeg2_ts_pkt_get_next(buf, src->r_buf_w_off,
		    (size_t)(ptm - buf), MPEG2_TS_PKT_SIZE_188, &ptm)) {
			if (ptm != ptm2) {
				SYSLOGD_EX(LOG_DEBUG, "!!!!!!!!ptm != ptm2!!!!!!!!!!");
			}
			buf_size = (size_t)((buf + src->r_buf_w_off) - ptm);
			memmove(buf, ptm, buf_size);
			clock_gettime(CLOCK_MONOTONIC_FAST, &ts);
			str_src_r_buf_add(src, &ts, buf, buf_size);
		} else { /* Drop data. */
			src->r_buf_w_off = 0;
		}
		tp_task_cb_func_set(tptask, (tp_task_cb)str_src_recv_tcp_cb);
		break;
	} /* end recv while */
	if (0 != error) {
		SYSLOG_ERR(LOG_NOTICE, error, "recv().");
		src->last_err = error;
		if (0 == transfered_size)
			goto rcv_next;
	}
	/* Calc speed. */
	src->received_count += transfered_size;
	clock_gettime(CLOCK_MONOTONIC_FAST, &src->last_recv_time);

rcv_next:
	return (TP_TASK_CB_CONTINUE);
}

static int
str_src_recv_tcp_cb(tp_task_p tptask, int error, uint32_t eof,
    size_t data2transfer_size, void *arg) {
	str_src_p src = arg;
	uintptr_t ident;
	ssize_t ios;
	uint8_t *buf;
	size_t transfered_size = 0, buf_size, tm;
	struct timespec	ts;

	if (0 != error || 0 != eof) {
err_out:
		src->last_err = error;
		SYSLOG_ERR(LOG_DEBUG, error, "On receive.");
		if (0 != eof) {
			SYSLOGD_EX(LOG_DEBUG, "eof...");
		}
		str_src_restart(src);
		//str_src_stop(src);
		src->last_err = error;
		str_src_state_update(src, STR_SRC_STATE_STOP,
		    SRC_STATUS_SET_BIT, STR_SRC_STATUS_ERROR);
		return (TP_TASK_CB_NONE); /* Receiver destroyed. */
	}
	if (NULL == src->r_buf) { /* Delay ring buf allocation. */
		error = str_src_r_buf_alloc(src);
		if (0 != error)
			goto err_out;
		error = str_src_state_update(src, STR_SRC_STATE_RUNNING, 0, 0);
		if (0 != error)
			return (TP_TASK_CB_NONE); /* Receiver destroyed. */
	}

	clock_gettime(CLOCK_MONOTONIC_FAST, &ts);
	ident = tp_task_ident_get(tptask);
	while (transfered_size < data2transfer_size) { /* recv loop. */
		buf_size = r_buf_wbuf_get(src->r_buf, MPEG2_TS_PKT_SIZE_MAX, &buf);
		tm = buf_size;
		buf_size -= (src->r_buf_w_off + (buf_size % MPEG2_TS_PKT_SIZE_188));
		ios = recv((int)ident, (buf + src->r_buf_w_off), buf_size, MSG_DONTWAIT);
		if (-1 == ios) {
			error = errno;
			if (0 == error) {
				error = EINVAL;
			}
			error = SKT_ERR_FILTER(error);
			if (0 == error)
				break;
			goto err_out;
		}
		if (0 == ios) {
			if (0 == buf_size) {
				syslog(LOG_NOTICE, "buf_size calc BUG, please report!");
				SYSLOGD_EX(LOG_DEBUG,
				    "0 == ios, error = %i, buf_size = %zu, r_buf_w_off = %zu, subb = %zu, res = %zu...",
				    errno, tm, src->r_buf_w_off, (tm % MPEG2_TS_PKT_SIZE_188), buf_size);
				str_src_restart(src);
				return (TP_TASK_CB_NONE); /* Receiver destroyed. */
			}
			break;
		}
		transfered_size += (size_t)ios;
		ios += src->r_buf_w_off;
		if (MPEG2_TS_PKT_SIZE_188 > (size_t)ios) {
			src->r_buf_w_off = (size_t)ios;
			SYSLOGD_EX(LOG_DEBUG, "...r_buf_w_off = %zu.",
			    src->r_buf_w_off);
			continue; /* Packet to small, continue receive. */
		}
		str_src_r_buf_add(src, &ts, buf, (size_t)ios);
	} /* end recv while */

	/* Calc speed. */
	src->received_count += transfered_size;
	memcpy(&src->last_recv_time, &ts, sizeof(struct timespec));
	if (NULL != src->on_data) {
		src->on_data(src, &src->last_recv_time, src->udata);
	}

	return (TP_TASK_CB_CONTINUE);
}


/* MPEG payload-type constants - adopted from VLC 0.8.6 */
#define P_MPGA		0x0E /* MPEG audio */
#define P_MPGV		0x20 /* MPEG video */

static int
str_src_recv_mc_cb(tp_task_p tptask, int error, uint32_t eof __unused,
    size_t data2transfer_size, void *arg) {
	str_src_p src = arg;
	uintptr_t ident;
	ssize_t ios;
	uint8_t *buf;
	size_t transfered_size = 0, req_buf_size, buf_size, start_off = 0, end_off = 0;
	struct timespec	ts;

	if (0 != error) {
err_out:
		SYSLOG_ERR(LOG_DEBUG, error, "On receive.");
		str_src_stop(src);
		src->last_err = error;
		str_src_state_update(src, STR_SRC_STATE_STOP,
		    SRC_STATUS_SET_BIT, STR_SRC_STATUS_ERROR);
		return (TP_TASK_CB_NONE); /* Receiver destroyed. */
	}
	if (NULL == src->r_buf) { /* Delay ring buf allocation. */
		error = str_src_r_buf_alloc(src);
		if (0 != error)
			goto err_out;
		error = str_src_state_update(src, STR_SRC_STATE_RUNNING, 0, 0);
		if (0 != error)
			return (TP_TASK_CB_NONE); /* Receiver destroyed. */
	}

	clock_gettime(CLOCK_MONOTONIC_FAST, &ts);
	ident = tp_task_ident_get(tptask);
	req_buf_size = STR_SRC_UDP_PKT_SIZE_STD;
	while (transfered_size < data2transfer_size) { /* recv loop. */
		buf_size = r_buf_wbuf_get(src->r_buf, req_buf_size, &buf);
		ios = recv((int)ident, buf, buf_size, MSG_DONTWAIT);
		if (-1 == ios) {
			error = errno;
			if (0 == error) {
				error = EINVAL;
			}
			error = SKT_ERR_FILTER(error);
			if (0 == error && STR_SRC_UDP_PKT_SIZE_MAX > buf_size) {
				/* Possible not enough buf space. */
				req_buf_size = STR_SRC_UDP_PKT_SIZE_MAX;
				continue; /* Retry! */
			}
			break;
		}
		if (0 == ios)
			break;
		transfered_size += (size_t)ios;
		if (MPEG2_TS_PKT_SIZE_MIN > (size_t)ios)
			continue; /* Packet to small, drop. */
		if (MPEG2_TS_HDR_IS_VALID((mpeg2_ts_hdr_p)buf)) { /* Test_ for RTP. */
			buf_size = (size_t)ios;
		} else if (0 == rtp_payload_get(buf, (size_t)ios, &start_off, &end_off)) {
			//SYSLOGD_EX(LOG_DEBUG, "RTP sn = %i.", ((rtp_hdr_p)buf)->seq);
			/* XXX skip payload bulk data. */
			if (P_MPGA == ((rtp_hdr_p)buf)->pt ||
			    P_MPGV == ((rtp_hdr_p)buf)->pt) {
				start_off += 4;
			}
			/* RTP sn check. */
			src->rtp_sn ++;
			if (RTP_HDR_SN_MAX < src->rtp_sn) {
				src->rtp_sn = 0;
			}
			if (src->rtp_sn != ((rtp_hdr_p)buf)->seq) {
				//LOG_EV_FMT("RTP SN MISSMATCH!!! src id: %zu, expected: %i, RTP sn = %i", src, src->rtp_sn, ((rtp_hdr_p)buf)->seq);
				src->rtp_sn = ((rtp_hdr_p)buf)->seq;
				src->rtp_sn_errors ++;
			}
			src->rtp_sn = ((rtp_hdr_p)buf)->seq;
			/* Payload size check. */
			buf_size = (size_t)((size_t)ios - (start_off + end_off));
			if (MPEG2_TS_PKT_SIZE_MIN > buf_size)
				continue; /* Packet to small, drop. */
			/* Prevent fragmentation, zero move: buf += start_off; */
			/* Remove rtp header. */
			memmove(buf, (buf + start_off), buf_size);
		} else {
			src->error_count ++;
			continue; /* Packet unknown, drop. */
		}
		str_src_r_buf_add(src, &ts, buf, buf_size);
	} /* end recv while */
	if (0 != error) {
		SYSLOG_ERR(LOG_NOTICE, error, "recv().");
		if (0 == transfered_size)
			goto rcv_next;
	}
	/* Calc speed. */
	src->received_count += transfered_size;
	memcpy(&src->last_recv_time, &ts, sizeof(struct timespec));
#if 0 /* TODO: port from msd_lite or remove. */
#ifdef __linux__ /* Linux specific code. */
	/* Ring buf LOWAT emulator. */
	src->r_buf_rcvd += transfered_size;
	if (src->r_buf_rcvd < src->s.skt_rcv_lowat)
		goto rcv_next;
	src->r_buf_rcvd = 0;
#endif /* Linux specific code. */
#endif
	if (NULL != src->on_data) {
		src->on_data(src, &src->last_recv_time, src->udata);
	}

rcv_next:
	return (TP_TASK_CB_CONTINUE);
}


void
str_src_r_buf_f_name_gen(str_src_p src) {
	char hash[(MD5_HASH_STR_SIZE + 1)];
	struct timespec ts_now;

	if (NULL == src)
		return;
	clock_gettime(CLOCK_MONOTONIC_FAST, &ts_now);
	md5_get_digest_str((char*)&ts_now, sizeof(ts_now), (char*)hash);
	if (0 != (STR_SRC_S_F_ENABLE_RING_BUF_SHM_FILE & src->s.flags)) {
		snprintf(src->r_buf_f_name, sizeof(src->r_buf_f_name),
		    "/msd-%zu-%s.tmp",
		    (size_t)getpid(), hash);
	} else { /* Normal file. */
		snprintf(src->r_buf_f_name, sizeof(src->r_buf_f_name),
		    "%s/msd-%zu-%s.tmp",
		    src->s.r_buf_f_path, (size_t)getpid(), hash);
	}
	SYSLOGD_EX(LOG_DEBUG, "r_buf_f_name: %s.", src->r_buf_f_name);
}

int
str_src_r_buf_alloc(str_src_p src) {
	int error;

	if (NULL == src)
		return (EINVAL);
	if (0 != (STR_SRC_S_F_ENABLE_RING_BUF_IN_FILE & src->s.flags)) {
shm_open_retry:
		str_src_r_buf_f_name_gen(src);
		if (0 != (STR_SRC_S_F_ENABLE_RING_BUF_SHM_FILE & src->s.flags)) {
			src->r_buf_fd = (uintptr_t)shm_open(src->r_buf_f_name,
			    (O_CREAT | O_EXCL | O_RDWR), 0600);
		} else {
			src->r_buf_fd = (uintptr_t)open(src->r_buf_f_name,
			    (O_CREAT | O_EXCL | O_RDWR), 0600);
		}
		if ((uintptr_t)-1 == src->r_buf_fd) {
			error = errno;
			if (EEXIST == error) /* Try genereate another name. */
				goto shm_open_retry;
			SYSLOG_ERR(LOG_ERR, error, "shm_open(%s).", src->r_buf_f_name);
			return (error);
		}
		/* Lock mem in real file. */
		if (0 == (STR_SRC_S_F_ENABLE_RING_BUF_SHM_FILE & src->s.flags)) {
			if (0 != flock((int)src->r_buf_fd, LOCK_EX)) {
				SYSLOG_ERR(LOG_NOTICE, errno, "flock(%s).",
				    src->r_buf_f_name);
			}
		}

		/* Truncate it to the correct size */
		if (0 != ftruncate((int)src->r_buf_fd, (off_t)src->s.ring_buf_size)) {
			error = errno;
			SYSLOG_ERR(LOG_ERR, error, "ftruncate(%s, %zu).",
			    src->r_buf_f_name, src->s.ring_buf_size);
err_out:
			flock((int)src->r_buf_fd, LOCK_UN);
			close((int)src->r_buf_fd);
			src->r_buf_fd = (uintptr_t)-1;
			if (0 != (STR_SRC_S_F_ENABLE_RING_BUF_SHM_FILE & src->s.flags)) {
				shm_unlink(src->r_buf_f_name);
			} else {
				unlink(src->r_buf_f_name);
			}
			return (error);
		}
	}
	src->r_buf = r_buf_alloc(src->r_buf_fd, src->s.ring_buf_size,
	    MPEG2_TS_PKT_SIZE_MIN);
	if (NULL == src->r_buf) {
		error = ENOMEM;
		SYSLOG_ERR(LOG_ERR, error, "r_buf_alloc().");
		goto err_out;
	}
	return (0);
}

void
str_src_r_buf_free(str_src_p src) {

	if (NULL == src)
		return;
	if (0 != (STR_SRC_S_F_ENABLE_RING_BUF_IN_FILE & src->s.flags)) {
		flock((int)src->r_buf_fd, LOCK_UN);
		close((int)src->r_buf_fd);
		src->r_buf_fd = (uintptr_t)-1;
		if (0 != (STR_SRC_S_F_ENABLE_RING_BUF_SHM_FILE & src->s.flags)) {
			shm_unlink(src->r_buf_f_name);
		} else {
			unlink(src->r_buf_f_name);
		}
	}
	r_buf_free(src->r_buf);
	src->r_buf = NULL;
}

int
str_src_r_buf_add(str_src_p src, struct timespec *ts,
    uint8_t *buf, size_t buf_size) {
	int pkt_added;
	uint8_t *cur_pkt, *expected_pkt, *buf_end;
	size_t tm;

	if (MPEG2_TS_PKT_SIZE_188 > buf_size) { /* Data to small? */
		src->r_buf_w_off = buf_size;
		return (0);
	}
	cur_pkt = buf;
	expected_pkt = buf;
	buf_end = (buf + buf_size);
	while (0 != mpeg2_ts_pkt_get_next(buf, buf_size,
	    (size_t)(cur_pkt - buf), MPEG2_TS_PKT_SIZE_188, &cur_pkt)) {
		if (expected_pkt < cur_pkt) { /* Damaged stream. */
			memmove(expected_pkt, cur_pkt, (size_t)(buf_end - cur_pkt));
			tm = (size_t)(cur_pkt - expected_pkt);
			buf_end -= tm;
			buf_size -= tm;
			cur_pkt = expected_pkt;
			src->error_count ++;
		}
		if (0 != (STR_SRC_S_F_M2TS_ANALYZING & src->s.flags)) {
			pkt_added = 0;
			src->error_count += mpeg2_ts_pkt_analize(src->m2ts,
			    src->r_buf, ts,
			    cur_pkt, MPEG2_TS_PKT_SIZE_188, &pkt_added);
			if (0 == pkt_added) { /* Packet skiped. */
				if (buf_end <= (cur_pkt + MPEG2_TS_PKT_SIZE_188)) {
					src->r_buf_w_off = 0;
					return (0);
				}
				memmove(cur_pkt, (cur_pkt + MPEG2_TS_PKT_SIZE_188),
				    (size_t)(buf_end - (cur_pkt + MPEG2_TS_PKT_SIZE_188)));
				buf_end -= MPEG2_TS_PKT_SIZE_188;
				buf_size -= MPEG2_TS_PKT_SIZE_188;
				continue;
			}
		} else {
			r_buf_wbuf_set2(src->r_buf, cur_pkt, MPEG2_TS_PKT_SIZE_188, NULL);
		}
		cur_pkt += MPEG2_TS_PKT_SIZE_188;
		expected_pkt += MPEG2_TS_PKT_SIZE_188;
	}
	src->r_buf_w_off = (size_t)(buf_end - cur_pkt);
	return (0);
}


int
str_src_state_update(str_src_p src, uint32_t state, int sset, uint32_t status) {
	int report = 0;

	if (NULL == src)
		return (EINVAL);

	switch (state) {
	case STR_SRC_STATE_STOP:
	case STR_SRC_STATE_RUNNING:
	case STR_SRC_STATE_MONITORING:
	case STR_SRC_STATE_CONNECTING:
	case STR_SRC_STATE_DATA_REQ:
	case STR_SRC_STATE_DATA_WAITING:
	case STR_SRC_STATE_RECONNECTING:
		if (src->state != state) {
			src->state = state;
			report ++;
		}
		break;
	case STR_SRC_STATE_CURRENT:
		break;
	default:
		return (0);
	}

	switch (sset) {
	case SRC_STATUS_CLR_BIT: /* Clear bits. */
		if (0 != (src->status & status)) {
			report ++;
			src->status &= ~status;
		}
		break;
	case SRC_STATUS_SET_BIT: /* Set bits. */
		if (0 == (src->status & status)) {
			report ++;
			src->status |= status;
		}
		break;
	case SRC_STATUS_SET_VAL: /* Set value. */
		if (src->status != status) {
			report ++;
			src->status = status;
		}
		break;
	default:
		break;
	}
	if (0 != report && NULL != src->on_state)
		return (src->on_state(src, src->udata, src->state, src->status));
	return (0);
}
