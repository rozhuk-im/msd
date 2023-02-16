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

#ifndef __STREAM_HUB_H__
#define __STREAM_HUB_H__

#include <sys/queue.h>
#include <time.h>

#include "utils/macro.h"
#include "threadpool/threadpool_task.h"
#include "utils/ring_buffer.h"
#include "stream_src.h"


typedef struct str_hub_s	*str_hub_p;
typedef struct str_hub_client_s	*str_hub_cli_p;
typedef struct str_hubs_bckt_s	*str_hubs_bckt_p;


/* On client destroy. */
typedef int (*str_hub_cli_free_cb)(str_hub_cli_p strh_cli, tp_task_p tptask, void *udata);

typedef struct str_hub_client_s {
	TAILQ_ENTRY(str_hub_client_s) next; /* For list. */
	tp_task_p	tptask;		/* Used for send to client, and socket container. */
	r_buf_rpos_t	rpos;		/* Ring buf read pos. */
	str_hub_p	str_hub;	/* Pointer to multicast receiver. */
	uint32_t	cli_type;	/* STR_HUB_CLI_T_* */
	uint32_t	cli_sub_type;	/* STR_HUB_CLI_ST_* */
	uint32_t	state;		/* State flags. */
	size_t		snd_block_min_size; /* Min Send block size. */
	size_t		precache;	/* Precache size. */
	time_t		conn_time;	/* Connection start time. */
	time_t		last_snd_time;	/* For POLL mode: last send time. */
	int		last_error;
	void		*udata;		/* Associated data */
	str_hub_cli_free_cb free_cb;	/* Call back on cli destroy. */
	/* HTTP specific data. */
	uint8_t		*user_agent;
	size_t		user_agent_size;
	struct sockaddr_storage	xreal_addr;
	struct sockaddr_storage remonte_addr; /* Client address. */
} str_hub_cli_t;
TAILQ_HEAD(str_hub_cli_head, str_hub_client_s);

/* Client types. */
#define STR_HUB_CLI_T_TCP			0
#define STR_HUB_CLI_T_TCP_HTTP			1
/* Client sub types. */
#define STR_HUB_CLI_ST_NONE			0 /* Universal client sub type. */
#define STR_HUB_CLI_ST_TCP_HTTP_HEAD		1
/* State flags. */
#define STR_HUB_CLI_STATE_F_RPOS_INITIALIZED	(((uint32_t)1) <<  0)
#define STR_HUB_CLI_STATE_F_PRECACHE_DONE	(((uint32_t)1) <<  1)
#define STR_HUB_CLI_STATE_F_HTTP_HDRS_SENDED	(((uint32_t)1) <<  8)
#define STR_HUB_CLI_STATE_F_MPEG2TS_HDRS_SENDED	(((uint32_t)1) <<  9)
#define STR_HUB_CLI_STATE_F_POLL		(((uint32_t)1) << 31)
/* Limit for User-Agent len. */
#define STR_HUB_CLI_USER_AGENT_MAX_SIZE	256


/*
 * 1. Client connect via http, create/find mc receiver, ref_count ++;
 * 2. Client send http headers, add self to add_cli_list_head and ref_count --;
 * 3. Mc receiver move client from add_cli_list_head to cli_list_head and start
 * send stream.
 */

typedef struct str_hub_settings_s {
	uint32_t	flags;
	skt_opts_t	skt_opts;
	uint64_t	zero_cli_timeout; /* Self destroy time if no clients. */
	str_src_settings_t str_src_settings; /* Settings for sources - defaults */
	/* Client settings and defaults. */
	size_t		precache;
	/* End Client settings and defaults. */
	uint8_t		*cust_http_hdrs;
	size_t		cust_http_hdrs_size;
} str_hub_settings_t, *str_hub_settings_p;
/* Flags. */
#define STR_HUB_S_F_ZERO_CLI_PERSISTENT		(((uint32_t)1) <<  0) /* Do not destroy hub if no connected clients, othertwice  self destroy after zero_cli_timeout seconds. */
#define STR_HUB_S_F_ZERO_SRC_BITRATE_PERSISTENT	(((uint32_t)1) <<  1) /* Do not destroy hub if no data received from all sources. */
#define STR_HUB_S_F_PRECACHE_WAIT		(((uint32_t)1) <<  2) /* For new clients: wait untill data in ring buf less than client want to receive in first time. */
#define STR_HUB_S_F_USE_SEND_POLLING		(((uint32_t)1) <<  3) /* Add lagged client socket descriptor to OS io polling (kqueue/epoll). */
#define STR_HUB_S_F_DROP_SLOW_CLI		(((uint32_t)1) <<  4) /* Disconnect lagged clients. */
#define STR_HUB_S_F_ZERO_COPY_ON_SEND		(((uint32_t)1) << 16) /* Enable Zero Copy on send to clients flag. */

#define STR_HUB_S_SKT_OPTS_LOAD_MASK	(SO_F_HALFCLOSE_RD |		\
					SO_F_SND_MASK |			\
					SO_F_TCP_NODELAY |		\
					SO_F_TCP_NOPUSH |		\
					SO_F_TCP_CONGESTION)
#define STR_HUB_S_SKT_OPTS_INT_MASK	(SO_F_RCVBUF | SO_F_KEEPALIVE)
#define STR_HUB_S_SKT_OPTS_INT_VALS	(0)
#define STR_HUB_S_SKT_OPTS_RCVBUF	(4) /* Reduce kernel memory usage. */

/* Default values. */
#define STR_HUB_S_DEF_FLAGS		(STR_HUB_S_F_USE_SEND_POLLING | STR_HUB_S_F_DROP_SLOW_CLI)
#define STR_HUB_S_DEF_SKT_OPTS_MASK	(SO_F_SNDBUF |			\
					SO_F_SNDLOWAT |			\
					SO_F_SNDTIMEO |			\
					SO_F_TCP_NODELAY |		\
					SO_F_TCP_NOPUSH |		\
					SO_F_TCP_CONGESTION)  /* Opts that have def values. */
#define STR_HUB_S_DEF_SKT_OPTS_VALS	(0)
#define STR_HUB_S_DEF_SKT_OPTS_SND_BUF	(1024)	/* kb */
#define STR_HUB_S_DEF_SKT_OPTS_SNDLOWAT	(64)	/* kb */
#define STR_HUB_S_DEF_SKT_OPTS_SNDTIMEO (30)	/* s */
#define STR_HUB_S_DEF_SKT_OPTS_TCP_CONGESTION	"htcp"
#define STR_HUB_S_DEF_NO_CLI_TIMEOUT	(60)	/* s */
#define STR_HUB_S_DEF_PRECAHE		(4 * 1024) /* kb */



/*
 * Auto generated channel name:
 * /tcp/IPv4:PORT
 * /udp/IPv4:PORT
 * /udp/IPv4MC:PORT@IF_NAME
 * /http/HOST:PORT/url
 * /http/IPv4:PORT/url
 * /http/[IPv6]:PORT/url
 * /channel/NAME
 */

#define STR_HUB_SRC_MAX_CNT	16
typedef struct str_hub_s {
	TAILQ_ENTRY(str_hub_s) next;
	str_hubs_bckt_p	shbskt;
	uint8_t		*name;		/* Stream hub unique name. */
	size_t		name_size;	/* Name size. */
	uint32_t	status;		/* Hub Status */
	struct str_hub_cli_head cli_head; /* List with clients. */
	size_t		cli_count;	/* Count clients. */
	/* For stat */
	size_t		poll_cli_count;	/* Total clients count with pollig. */
	uint64_t	sended_count;	/* Accumulator for baud rate calculation. */
	uint64_t	baud_rate;	/* Calculated baud rate. */
	uint64_t	dropped_count;	/* Dropped clients count. */
	/* -- stat */
	time_t		zero_cli_time;	/* No connected clients time. */
	tpt_p		tpt;		/* Thread data for all IO operations. */
	str_src_p	src[STR_HUB_SRC_MAX_CNT];	/* Data sources. */
	size_t		src_cnt;	/* Data sources count. */
	size_t		src_current;	/* Current data source. */
	str_hub_settings_t s;		/* Settings. */
} str_hub_t;
TAILQ_HEAD(str_hub_head, str_hub_s);

#define STR_HUB_NAME_MAX_SIZE	1024

#define SH_STATUS_OK		(0)			/* OK. */
#define SH_STATUS_ERROR		(((uint32_t)1) << 0) /* Error. */
#define SH_STATUS_ENCRYPTED	(((uint32_t)1) << 1) /* One or more pids encrypted. */
#define SH_STATUS_ZERO_BITRATE	(((uint32_t)1) << 2) /* No bitrate. */
#define SH_STATUS_LOW_BITRATE	(((uint32_t)1) << 3) /* Low bitrate. */
#define SH_STATUS_STREAM_ERRORS	(((uint32_t)1) << 4) /* To many errors in stream. */



/* Per thread and summary stats. */
typedef struct str_hubs_stat_s {
	size_t		str_hub_count;	/* Stream hubs count. */
	size_t		cli_count;	/* Total clients count. */
	size_t		poll_cli_count;	/* Total clients count with pollig. */
	size_t		srcs_cnt;	/* Total data sources count. */
	size_t		srcs_state[STR_SRC_STATE_MAX];
	size_t		pids_cnt;	/* Total PIDs count. */
	uint64_t	baud_rate_in;	/* Total rate in (megabit per sec). */
	uint64_t	baud_rate_out;	/* Total rate out (megabit per sec). */
	uint64_t	error_rate;	/* Error rate for cur src. */
	uint64_t	error_rate_total; /* Total error rate for all active src. */
} str_hubs_stat_t, *str_hubs_stat_p;





void	str_hub_settings_def(str_hub_settings_p p_ret);
int	str_hub_xml_load_settings(const uint8_t *buf, size_t buf_size, str_hub_settings_p params);
int	str_hub_settings_copy(str_hub_settings_p dst, str_hub_settings_p src);
void	str_hub_settings_free_data(str_hub_settings_p s);

int	str_hubs_bckt_create(tp_p tp, const char *app_ver, str_hubs_bckt_p *shbskt_ret);
void	str_hubs_bckt_destroy(str_hubs_bckt_p shbskt);

typedef void (*str_hubs_bckt_enum_cb)(tpt_p tpt, str_hub_p str_hub, void *udata);
int	str_hubs_bckt_enum(str_hubs_bckt_p shbskt, str_hubs_bckt_enum_cb enum_cb,
	    void *udata, tpt_msg_done_cb done_cb);
int	str_hubs_bckt_stat_thread(str_hubs_bckt_p shbskt, size_t thread_num, str_hubs_stat_p stat);
int	str_hubs_bckt_stat_summary(str_hubs_bckt_p shbskt, str_hubs_stat_p stat);


str_hub_cli_p str_hub_cli_alloc(uint32_t cli_type, uint32_t cli_sub_type);
void	str_hub_cli_destroy(str_hub_cli_p strh_cli);
int	str_hub_cli_set_user_agent(str_hub_cli_p strh_cli, const char *ua,
	    const size_t ua_size);
tp_task_p str_hub_cli_export_tptask(str_hub_cli_p strh_cli);
int	str_hub_cli_import_tptask(str_hub_cli_p strh_cli, tp_task_p tptask,
	    tpt_p tpt);

/* Usage:
 * str_hub_cli_alloc()
 * set some data: snd_block_min_size, precache, remonte_addr, user_agent, xreal_addr
 * str_hub_cli_attach()
 * ... forgot about str_hub_cli from str_hub_cli_alloc() and dont use it in future!
 * you may call str_hub_cli_destroy() only before str_hub_cli_attach()!
 */


int
str_hub_send_msg(str_hubs_bckt_p shbskt, const uint8_t *name, size_t name_size,
    uint32_t cmd, void *arg1, size_t arg2);
#define STR_HUB_CMD_CREATE		1	/* arg1: otional: str_hub_settings_p */
#define STR_HUB_CMD_SETTING_SET		2	/* arg1: str_hub_settings_p */
#define STR_HUB_CMD_SRC_ADD		3	/* arg1: str_src_settings_p, arg2: type */
#define STR_HUB_CMD_CLI_ADD		4	/* arg1: str_hub_cli_p */
#define STR_HUB_CMD_CREATE_CLI_ADD	5	/* arg1: str_hub_cli_attach_data_p */
#define STR_HUB_CMD_
#define STR_HUB_CMD_
#define STR_HUB_CMD_

typedef struct str_hub_message_data_s {
	str_hubs_bckt_p	shbskt;
	uint8_t		*name;
	size_t		name_size;
	uint32_t	cmd;
	void		*arg1;
	size_t		arg2;
} str_hub_msg_data_t, *str_hub_msg_data_p;

typedef struct str_hub_cli_attach_data_s {
	str_hub_cli_p		strh_cli;
	uint32_t		free_flags;
	str_hub_settings_p	hub_s;
	uint32_t		src_type;
	str_src_settings_p	src_s;
} str_hub_cli_attach_data_t, *str_hub_cli_attach_data_p;
#define STR_HUB_CLI_ATTACH_DATA_F_HUB	(((uint32_t)1) << 0)
#define STR_HUB_CLI_ATTACH_DATA_F_SRC	(((uint32_t)1) << 1)
#define STR_HUB_CLI_ATTACH_DATA_F_ALL	(STR_HUB_CLI_ATTACH_DATA_F_HUB | STR_HUB_CLI_ATTACH_DATA_F_SRC)


#endif /* __STREAM_HUB_H__ */
