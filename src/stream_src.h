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

#ifndef __STREAM_SOURCE_H__
#define __STREAM_SOURCE_H__

#include <time.h>
#include "utils/macro.h"
#include "utils/io_buf.h"
#include "threadpool/threadpool_task.h"
#include "utils/ring_buffer.h"
#include "stream_mpeg2ts.h"


typedef struct str_src_s	*str_src_p;

/* After data received. */
typedef int (*str_src_on_data_rcvd_cb)(str_src_p src, struct timespec *ts, void *udata);
/* State and/or Status changed. */
typedef int (*str_src_on_state_cb)(str_src_p src, void *udata, uint32_t state, uint32_t status);
/* Ret value: 0: OK, non zero - stop processing, src possible destroyed. */


/* Connection info */
/* UDP source */
typedef struct str_src_conn_udp_s {
	struct sockaddr_storage	addr;
} str_src_conn_udp_t, *str_src_conn_udp_p;

/* Multicast [rtp] source */
typedef struct str_src_conn_mc_s {
	str_src_conn_udp_t udp;
	uint32_t	if_index;
} str_src_conn_mc_t, *str_src_conn_mc_p;

#define STR_SRC_CONN_TCP_MAX_ADDRS	8
/* TCP source */
typedef struct str_src_conn_tcp_s {
	const uint8_t	*host;		/* Point to mem in req_buf for conn_http. */
	size_t		host_size;
	uint64_t	conn_timeout;	/* Connect timeout. */
	uint64_t	retry_interval;	/* Connect re try time. */
	uint64_t	conn_try_count;	/* Reconnect try count. */
	uint64_t	conn_try;	/* Connect try number. */
	size_t		addr_index;
	size_t		addr_count;
	struct sockaddr_storage	addr[STR_SRC_CONN_TCP_MAX_ADDRS];
} str_src_conn_tcp_t, *str_src_conn_tcp_p;

/* HTTP source */
typedef struct str_src_conn_http_s {
	str_src_conn_tcp_t tcp; /* host - point inside req_buf. */
	io_buf_p	req_buf; /* Hold full http request. All pointers - point here. */
	const uint8_t	*url_path;
	size_t		url_path_size;
	const uint8_t	*cust_http_hdrs;
	size_t		cust_http_hdrs_size;
} str_src_conn_http_t, *str_src_conn_http_p;

#define STR_SRC_CONN_DEF_IFINDEX	((uint32_t)-1)
#define STR_SRC_CONN_DEF_CONN_TIMEOUT	(10)	/* s */
#define STR_SRC_CONN_DEF_RETRY_INTERVAL	(5)	/* s */
#define STR_SRC_CONN_DEF_TRY_COUNT	(~((uint64_t)0))


typedef union str_src_conn_params_s {
	str_src_conn_udp_t	udp;
	str_src_conn_mc_t	mc;
	str_src_conn_tcp_t	tcp;
	str_src_conn_http_t	http;
} str_src_conn_params_t, *str_src_conn_params_p;


#define STR_SRC_R_BUF_PATH_MAX	255
typedef struct str_src_settings_s {
	uint32_t	flags;
	skt_opts_t	skt_opts;
	mpeg2_ts_settings_t m2ts_s;
	size_t		ring_buf_size;	/* Size of ring buf. */
	uint64_t	error_rate_interval; /* Error rate calc interval (in seconds) */
	uint64_t	error_rate_max;	/* Set status STR_SRC_STATUS_STREAM_ERRORS if error rate >= */
	char		r_buf_f_path[STR_SRC_R_BUF_PATH_MAX]; /* Path for file to hold ring buf, not used if STR_SRC_S_F_ENABLE_RING_BUF_SHM_FILE set. "shm" = set STR_SRC_S_F_ENABLE_RING_BUF_SHM_FILE. */
	str_src_conn_params_p src_conn_params;	/* Point to str_src_conn_XXX */
} str_src_settings_t, *str_src_settings_p;
/* Flags. */
#define STR_SRC_S_F_M2TS_ANALYZING		(((uint32_t)1) <<  0) /* Enable MPEG2-TS analizer. */
#define STR_SRC_S_F_ENABLE_RING_BUF_IN_FILE	(((uint32_t)1) <<  1) /* Enable use file for ring buf, for Zero Copy on send in stream hub. */
#define STR_SRC_S_F_ENABLE_RING_BUF_SHM_FILE	(((uint32_t)1) << 16) /* INTERNAL: Enable use posix shared mem file for ring buf. */

#define STR_SRC_S_SKT_OPTS_LOAD_MASK	(SO_F_HALFCLOSE_WR |		\
					SO_F_RCV_MASK)
#define STR_SRC_S_SKT_OPTS_INT_MASK	(SO_F_REUSEADDR |		\
					SO_F_REUSEPORT |		\
					SO_F_SNDBUF |			\
					SO_F_KEEPALIVE |		\
					SO_F_TCP_NODELAY)
#define STR_SRC_S_SKT_OPTS_INT_VALS	(SO_F_REUSEADDR | SO_F_REUSEPORT | SO_F_TCP_NODELAY)
#define STR_SRC_S_SKT_OPTS_SNDBUF	(4) /* Reduce kernel memory usage. */

/* Default values. */
#define STR_SRC_S_DEF_FLAGS		(STR_SRC_S_F_M2TS_ANALYZING)
#define STR_SRC_S_DEF_SKT_OPTS_MASK	(SO_F_RCVBUF |			\
					SO_F_RCVLOWAT |			\
					SO_F_RCVTIMEO) /* Opts that have def values. */
#define STR_SRC_S_DEF_SKT_OPTS_VALS	(0)
#define STR_SRC_S_DEF_SKT_OPTS_RCV_BUF	(1024)	/* kb */
#define STR_SRC_S_DEF_SKT_OPTS_RCVLOWAT	(48)	/* kb */
#define STR_SRC_S_DEF_SKT_OPTS_RCVTIMEO (10)	/* s */

#define STR_SRC_S_DEF_RING_BUF_SIZE	(32 * 1024) /* kb */
#define STR_SRC_S_DEF_ERR_RATE_INTVL	(60)	/* s */
#define STR_SRC_S_DEF_ERR_RATE_MAX	(10)	/* err count */
#define STR_SRC_S_DEF_R_BUF_F_PATH	"shm"





typedef struct str_src_s {
	tp_task_p	tptask;		/* Data/Packets receiver. */
	uint32_t	type;		/* STR_SRC_TYPE_* */
	r_buf_p		r_buf;		/* Ring buf, write pos. */
	size_t		r_buf_w_off;	/* Write offset in r_buf, used in TCP recv. */
#ifdef __linux__ /* Linux specific code. */
	size_t		r_buf_rcvd;	/* Ring buf LOWAT emulator. */
#endif /* Linux specific code. */
	/* Baud rate calculation. */
	struct timespec	last_recv_time;	/* For baud rate calculation and status. */
	uint64_t	received_count;	/* Accumulator for baud rate calculation. */
	uint64_t	baud_rate;	/* Calculated baud rate. */
	/* Error rate calculation. */
	struct timespec	last_err_calc_time;/* For error rate calculation and status. */
	uint64_t	error_count;	/* Accumulator for error rate calculation. */
	uint64_t	error_rate;	/* Error rate per 'error_rate_interval' seconds. */
	/* -- Error rate calculation. -- */
	uint32_t	status;		/* Source Status: STR_SRC_STATUS_*. */
	uint32_t	state;		/* Source State. */
	int		last_err;	/* Last errno. */
	uint32_t	http_resp_code;	/* Last http error code. */
	uint32_t	rtp_sn;		/* Continuity/Sequence number. */
	uint64_t	rtp_sn_errors;	/* Count Continuity/Sequence number errors. */

	mpeg2_ts_data_p	m2ts;		/* MPEG2-TS data. */

	uintptr_t	r_buf_fd;	/* r_buf shared memory file descriptor, then STR_SRC_S_F_ENABLE_RING_BUF_IN_FILE set */
	char		r_buf_f_name[(STR_SRC_R_BUF_PATH_MAX + 64)]; /* r_buf shared memory file name, then STR_SRC_S_F_ENABLE_RING_BUF_IN_FILE set */
	tpt_p		tpt;		/* Thread data for all IO operations. */
	str_src_on_state_cb	on_state;
	str_src_on_data_rcvd_cb	on_data;
	void		*udata;		/* Pointer to stream hub data or other. */
	str_src_settings_t s;		/* Settings. */
} str_src_t;

#define STR_SRC_TYPE_UNKNOWN		0
#define STR_SRC_TYPE_UDP		1
#define STR_SRC_TYPE_UDP_RTP		2
#define STR_SRC_TYPE_MULTICAST		3
#define STR_SRC_TYPE_MULTICAST_RTP	4
#define STR_SRC_TYPE_TCP		5
#define STR_SRC_TYPE_TCP_HTTP		6
#define STR_SRC_TYPE___COUNT__		7
static const char *str_src_types[] = {
	"unknown",
	"udp",
	"udp-rtp",
	"multicast-udp",
	"multicast-udp-rtp",
	"tcp",
	"tcp-http",
	NULL
};
static const size_t str_src_types_sizes[] = {
	7,
	3,
	7,
	13,
	17,
	3,
	8,
	0
};


#define STR_SRC_STATE_STOP		0
#define STR_SRC_STATE_RUNNING		1
#define STR_SRC_STATE_MONITORING	2 /* Receive to temp buf and analize. */
#define STR_SRC_STATE_CONNECTING	3
#define STR_SRC_STATE_DATA_REQ		4 /* Sending http request. */
#define STR_SRC_STATE_DATA_WAITING	5 /* Wait for data in first time. */
#define STR_SRC_STATE_RECONNECTING	6 /* Set this state for wait unlill next try. */
#define STR_SRC_STATE_MAX		STR_SRC_STATE_RECONNECTING
#define STR_SRC_STATE_CURRENT		0xff /* internal, state not changed */
static const char *str_src_states[] = {
	"stop",
	"running",
	"monitoring",
	"connecting",
	"requesting for data",
	"waiting for data",
	"reconnecting",
	NULL
};

#define STR_SRC_STATUS_OK		(0) 			/* OK. */
#define STR_SRC_STATUS_ERROR		(((uint32_t)1) << 0) /* Error. */
#define STR_SRC_STATUS_ENCRYPTED	(((uint32_t)1) << 1) /* One or more pids encrypted. */
#define STR_SRC_STATUS_ZERO_BITRATE	(((uint32_t)1) << 2) /* No bitrate. */
#define STR_SRC_STATUS_LOW_BITRATE	(((uint32_t)1) << 3) /* Low bitrate. */
#define STR_SRC_STATUS_STREAM_ERRORS	(((uint32_t)1) << 4) /* To many errors in stream. */


uint32_t str_src_get_type_from_str(const char *str, size_t str_size);

int	str_src_timer_proc(str_src_p src, struct timespec *tv_now,
	    struct timespec *tv_prev);
/* Ret value: 0: OK, non zero - stop processing, src possible destroyed. */

int	str_src_cust_hdrs_load(const uint8_t *buf, size_t buf_size,
	    uint8_t **hdrs, size_t *hdrs_size_ret);
void	str_src_settings_def(str_src_settings_p s_ret);
int	str_src_xml_load_settings(const uint8_t *buf, size_t buf_size,
	    str_src_settings_p s);
void	str_src_conn_def(uint32_t type, str_src_conn_params_p src_conn_params);
int	str_src_conn_xml_load_settings(const uint8_t *buf, size_t buf_size,
	    uint32_t type, void *conn);
int	str_src_settings_copy(str_src_settings_p dst, str_src_settings_p src);
void	str_src_settings_free_data(str_src_settings_p s);
int	str_src_conn_http_gen_request(const uint8_t *host, size_t host_size,
	    const uint8_t *url_path, size_t url_path_size,
	    const uint8_t *cust_http_hdrs, size_t cust_http_hdrs_size,
	    str_src_conn_http_p conn_http);

int	str_src_create(uint32_t type, str_src_settings_p s, tpt_p tpt,
	    str_src_on_state_cb on_state, str_src_on_data_rcvd_cb on_data,
	    void *udata, str_src_p *src_ret);
void	str_src_destroy(str_src_p src);
int	str_src_start(str_src_p src);
void	str_src_stop(str_src_p src);
int	str_src_restart(str_src_p src);


#endif /* __STREAM_SOURCE_H__ */
