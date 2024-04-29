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
//#include <sys/stat.h> /* For mode constants */
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/tcp.h>


#include <err.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h> /* snprintf, fprintf */
#include <time.h>
#include <string.h> /* bcopy, bzero, memcpy, memmove, memset, strerror... */

#include "utils/macro.h"
#include "utils/io_buf.h"
#include "utils/sys.h"
#include "threadpool/threadpool_task.h"
#include "net/socket.h"
#include "net/socket_address.h"
#include "net/utils.h"
#include "utils/buf_str.h"
#include "proto/http_server.h"
#include "stream_hub.h"
#include "stream_src.h"
#include "utils/info.h"
#include "msd_stat_text.h"


void	gen_hub_stat_text_entry_enum_cb(tpt_p tpt, str_hub_p str_hub,
	    void *udata);
void	gen_hub_stat_text_enum_done_cb(tpt_p tpt, size_t send_msg_cnt,
	    size_t error_cnt, void *udata);


int
gen_hub_stat_text_send_async(str_hubs_bckt_p shbskt, http_srv_cli_p cli) {
	int error;
	size_t tm;
	str_hubs_stat_t hstat;

	error = str_hubs_bckt_stat_summary(shbskt, &hstat);
	if (0 != error)
		return (error);
	tm = (16384 +
	    (hstat.str_hub_count * 1024) +
	    (hstat.srcs_cnt * 1024) +
	    (hstat.pids_cnt * 256) +
	    (hstat.cli_count * (160 + 256 + 1024))
	    );
	error = http_srv_cli_buf_realloc(cli, 0, tm);
	if (0 != error) /* Need more space! */
		return (error);

	error = str_hubs_bckt_enum(shbskt, gen_hub_stat_text_entry_enum_cb, cli,
	    gen_hub_stat_text_enum_done_cb);

	return (error);
}
void
gen_hub_stat_text_entry_enum_cb(tpt_p tpt, str_hub_p str_hub, void *udata) {
	http_srv_cli_p cli = (http_srv_cli_p)udata;
	io_buf_p buf = http_srv_cli_get_buf(cli);
	r_buf_p r_buf;
	str_src_p src;
	str_hub_cli_p strh_cli, strh_cli_temp;
	time_t cur_time, time_conn;
	char straddr[STR_ADDR_LEN], straddr2[STR_ADDR_LEN], ifname[(IFNAMSIZ + 1)], str_time[64];
	size_t stm, j;
	int itm;
	//str_hub_src_conn_udp_tcp_p conn_udp_tcp;
	str_src_conn_mc_p conn_mc;
	str_src_conn_http_p conn_http;

	cur_time = gettime_monotonic();
	io_buf_printf(buf,
	    "\r\n"
	    "Stream hub: %s		[status: %"PRIu32", thread: %zu @ cpu %i, sources: %zu, clients: %zu, dropped clients: %"PRIu64", no clients time: %zu]\r\n",
	    str_hub->name, str_hub->status,
	    tp_thread_get_num(tpt), tp_thread_get_cpu_id(tpt),
	    str_hub->src_cnt, str_hub->cli_count, str_hub->dropped_count,
	    (size_t)((0 != str_hub->cli_count) ? 0 : (cur_time - str_hub->zero_cli_time)));
	/* Sources. */
	for (j = 0; j < str_hub->src_cnt; j ++) {
		src = str_hub->src[j];
		io_buf_printf(buf, "  Source %zu: %s", j, str_src_types[src->type]);
		switch (src->type) {
		case STR_SRC_TYPE_UDP:
		case STR_SRC_TYPE_UDP_RTP:
		case STR_SRC_TYPE_MULTICAST:
		case STR_SRC_TYPE_MULTICAST_RTP:
			conn_mc = &src->s.src_conn_params->mc;
			if (0 != sa_addr_port_to_str(&conn_mc->udp.addr, straddr,
			    sizeof(straddr), NULL)) {
				memcpy(straddr, "<unable to format>", 19);
			}
			if (STR_SRC_TYPE_MULTICAST == src->type ||
			    STR_SRC_TYPE_MULTICAST_RTP == src->type) {
				ifname[0] = 0;
				if_indextoname(conn_mc->if_index, ifname);
				io_buf_printf(buf, " %s@%s	",
				    straddr, ifname);
			} else {
				io_buf_printf(buf, " %s	",
				    straddr);
			}
			break;
		case STR_SRC_TYPE_TCP:
		case STR_SRC_TYPE_TCP_HTTP:
			conn_http = &src->s.src_conn_params->http;
			if (0 != skt_get_tcp_maxseg(
			    tp_task_ident_get(src->tptask), &itm)) {
				itm = 0;
			}
			if (0 != sa_addr_port_to_str(
			    &conn_http->tcp.addr[conn_http->tcp.addr_index],
			    straddr, sizeof(straddr), NULL)) {
				memcpy(straddr, "<unable to format>", 19);
			}
			if (STR_SRC_TYPE_TCP_HTTP == src->type) {
				IO_BUF_COPYIN_CSTR(buf, " http://");
				io_buf_copyin(buf, conn_http->tcp.host, conn_http->tcp.host_size);
				io_buf_copyin(buf, conn_http->url_path, conn_http->url_path_size);
			}
			io_buf_printf(buf, " [IP: %s, maxseg: %i, index = %zu]	",
			    straddr, itm, conn_http->tcp.addr_index);
			break;
		}
		io_buf_printf(buf,
		    "[state: %s, status: %"PRIu32", rate: %"PRIu64", error rate: %zu, pids: %zu, no data recv time: %zu]\r\n",
		    str_src_states[src->state], src->status,
		    src->baud_rate, src->error_rate, (size_t)0/*src->ts_pids_cnt*/,
		    (size_t)(cur_time - src->last_recv_time.tv_sec));
		if (STR_SRC_STATE_STOP == src->state)
			continue;
		if (STR_SRC_TYPE_TCP == src->type ||
		    STR_SRC_TYPE_TCP_HTTP == src->type) {
			/* Add soscket TCP stat. */
			if (0 == skt_tcp_stat_text(tp_task_ident_get(src->tptask),
			    "    ",
			    (char*)IO_BUF_FREE_GET(buf),
			    IO_BUF_FREE_SIZE(buf), &stm)) {
				IO_BUF_USED_INC(buf, stm);
			}
		}
		if (0 == mpeg2_ts_txt_dump(src->m2ts, IO_BUF_FREE_GET(buf),
		    IO_BUF_FREE_SIZE(buf), &stm)) {
			IO_BUF_USED_INC(buf, stm);
		}
	}

	/* Clients. */
	r_buf = NULL;
	src = str_hub->src[str_hub->src_current];
	if (NULL != src) {
		r_buf = src->r_buf;
	}
	TAILQ_FOREACH_SAFE(strh_cli, &str_hub->cli_head, next, strh_cli_temp) {
		if (0 != sa_addr_port_to_str(&strh_cli->remonte_addr,
		    straddr, sizeof(straddr), NULL)) {
			memcpy(straddr, "<unable to format>", 19);
		}
		if (0 != sa_addr_port_to_str(&strh_cli->xreal_addr,
		    straddr2, sizeof(straddr2), NULL)) {
			memcpy(straddr, "<unable to format>", 19);
		}
		//&cli_ud->xreal_addr
		time_conn = (cur_time - strh_cli->conn_time);
		fmt_as_uptime(&time_conn, str_time, sizeof(str_time));

		if (0 != skt_get_tcp_cc(tp_task_ident_get(strh_cli->tptask),
		    ifname, sizeof(ifname), NULL)) {
			memcpy(ifname, "<unable to get>", 16);
		}
		if (0 != skt_get_tcp_maxseg(tp_task_ident_get(strh_cli->tptask), &itm)) {
			itm = 0;
		}

		io_buf_printf(buf,
		    "	%s (%s)	[conn time: %s, state: %u, cc: %s, maxseg: %i, snd_block_min_size: %zu kb, precache: %zu kb, data to send: %zu kb, last send: %zu, last error: %i]	[user agent: %s]\r\n",
		    straddr, straddr2, str_time, strh_cli->state, ifname, itm,
		    (strh_cli->snd_block_min_size / 1024), (strh_cli->precache / 1024),
		    (r_buf_data_avail_size(r_buf, &strh_cli->rpos, NULL) / 1024),
		    (size_t)(cur_time - strh_cli->last_snd_time),
		    strh_cli->last_error,
		    (char*)strh_cli->user_agent
		);
		/* Add soscket TCP stat. */
		if (0 == skt_tcp_stat_text(tp_task_ident_get(strh_cli->tptask),
		    "	    ",
		    (char*)IO_BUF_FREE_GET(buf),
		    IO_BUF_FREE_SIZE(buf), &stm)) {
			IO_BUF_USED_INC(buf, stm);
		}
	}
}
void
gen_hub_stat_text_enum_done_cb(tpt_p tpt __unused, size_t send_msg_cnt __unused,
    size_t error_cnt, void *udata) {
	http_srv_cli_p cli = udata;
	http_srv_resp_p	resp = http_srv_cli_get_resp(cli);
	static const char *cttype = 	"Content-Type: text/plain\r\n"
					"Pragma: no-cache";

	if (0 == error_cnt) {
		resp->status_code = 200;
		resp->p_flags |= HTTP_SRV_RESP_P_F_CONTENT_LEN;
		resp->hdrs_count = 1;
		resp->hdrs[0].iov_base = MK_RW_PTR(cttype);
		resp->hdrs[0].iov_len = 42;
	} else {
		resp->status_code = 500;
	}
	http_srv_resume_responce(cli);
}


int
gen_stat_text(const char *package_name, const char *package_version,
    str_hubs_bckt_p shbskt, info_sysres_p sysres,
    uint8_t *sysinfo, size_t sysinfo_size, uint8_t *syslimits, size_t syslimits_size,
    http_srv_cli_p cli) {
	int error;
	char straddr[STR_ADDR_LEN], start_time[64];
	time_t time_work;
	size_t i, thread_cnt, tm;
	http_srv_p http_srv;
	tp_p tp;
	io_buf_p buf;
	struct tm stime;
	str_hubs_stat_t hstat, tstat;
	http_srv_stat_t http_srv_stat;

	error = str_hubs_bckt_stat_summary(shbskt, &hstat);
	if (0 != error)
		return (error);
	http_srv = http_srv_cli_get_srv(cli);
	error = http_srv_stat_get(http_srv, &http_srv_stat);
	if (0 != error)
		return (error);
	tp = http_srv_tp_get(http_srv);
	thread_cnt = tp_thread_count_max_get(tp);
	tm = (4096 + (4096 * thread_cnt) + syslimits_size + sysinfo_size);
	error = http_srv_cli_buf_realloc(cli, 0, tm);
	if (0 != error) /* Need more space! */
		return (error);
	buf = http_srv_cli_get_buf(cli);

	time_work = (gettime_monotonic() - http_srv_stat.start_time_abs);
	if (0 == time_work) { /* Prevent division by zero. */
		time_work ++;
	}
	/* Server stat. */
	localtime_r(&http_srv_stat.start_time, &stime);
	strftime(start_time, sizeof(start_time),
	    "%d.%m.%Y %H:%M:%S", &stime);
	fmt_as_uptime(&time_work, straddr, (sizeof(straddr) - 1));
	io_buf_printf(buf,
	    "Server: %s %s ("__DATE__" "__TIME__")\r\n"
	    "start time: %s\r\n"
	    "running time: %s\r\n"
	    "connections online: %"PRIu64"\r\n"
	    "timeouts: %"PRIu64"\r\n"
	    "errors: %"PRIu64"\r\n"
	    "HTTP errors: %"PRIu64"\r\n"
	    "insecure requests: %"PRIu64"\r\n"
	    "unhandled requests (404): %"PRIu64"\r\n"
	    "requests per sec: %"PRIu64"\r\n"
	    "requests total: %"PRIu64"\r\n"
	    "\r\n\r\n",
	    package_name, package_version,
	    start_time, straddr,
	    http_srv_stat.connections,
	    http_srv_stat.timeouts,
	    http_srv_stat.errors,
	    http_srv_stat.http_errors,
	    http_srv_stat.insecure_requests,
	    http_srv_stat.unhandled_requests,
	    (http_srv_stat.requests_total / (uint64_t)time_work),
	    http_srv_stat.requests_total);
	io_buf_printf(buf, "Per Thread stat\r\n");
	for (i = 0; i < thread_cnt; i ++) {
		/* Per Thread stat. */
		str_hubs_bckt_stat_thread(shbskt, i, &tstat);
		io_buf_printf(buf,
		    "Thread: %zu @ cpu %i\r\n"
		    "Stream hub count: %zu\r\n"
		    "Sources count: %zu\r\n",
		    i, tp_thread_get_cpu_id(tp_thread_get(tp, i)),
		    tstat.str_hub_count, tstat.srcs_cnt);
		for (tm = 0; tm < STR_SRC_STATE_MAX; tm ++) {
			io_buf_printf(buf,
			    "    %s: %zu\r\n",
			    str_src_states[tm], tstat.srcs_state[tm]);
			
		}
		io_buf_printf(buf,
		    "PIDs count: %zu\r\n"
		    "Clients count: %zu\r\n"
		    "Clients count with POLL state: %zu\r\n"
		    "Error rate in: %"PRIu64"/%"PRIu64"\r\n"
		    "Rate in: %"PRIu64" mbps\r\n"
		    "Rate out: %"PRIu64" mbps\r\n"
		    "Total rate: %"PRIu64" mbps\r\n"
		    "\r\n",
		    tstat.pids_cnt,
		    tstat.cli_count,
		    tstat.poll_cli_count,
		    tstat.error_rate, tstat.error_rate_total,
		    (tstat.baud_rate_in / (1024 * 1024)),
		    (tstat.baud_rate_out / (1024 * 1024)),
		    ((tstat.baud_rate_in + tstat.baud_rate_out) / (1024 * 1024)));
	}
	/* Total stat. */
	io_buf_printf(buf,
	    "Summary\r\n"
	    "Stream hub count: %zu\r\n"
	    "Sources count: %zu\r\n",
	    hstat.str_hub_count,
	    hstat.srcs_cnt);
	for (tm = 0; tm < STR_SRC_STATE_MAX; tm ++) {
		io_buf_printf(buf,
		    "    %s: %zu\r\n",
		    str_src_states[tm],
		    hstat.srcs_state[tm]);
		
	}
	io_buf_printf(buf,
	    "PIDs count: %zu\r\n"
	    "Clients count: %zu\r\n"
	    "Clients count with POLL state: %zu\r\n"
	    "Error rate in: %"PRIu64"/%"PRIu64"\r\n"
	    "Rate in: %"PRIu64" mbps\r\n"
	    "Rate out: %"PRIu64" mbps\r\n"
	    "Total rate: %"PRIu64" mbps\r\n"
	    "\r\n\r\n",
	    hstat.pids_cnt,
	    hstat.cli_count,
	    hstat.poll_cli_count,
	    hstat.error_rate, hstat.error_rate_total,
	    (hstat.baud_rate_in / (1024 * 1024)),
	    (hstat.baud_rate_out / (1024 * 1024)),
	    ((hstat.baud_rate_in + hstat.baud_rate_out) / (1024 * 1024)));

	error = info_sysres(sysres, (char*)IO_BUF_FREE_GET(buf),
	    IO_BUF_FREE_SIZE(buf), &tm);
	if (0 != error) /* Err... */
		return (error);
	IO_BUF_USED_INC(buf, tm);

	io_buf_copyin(buf, syslimits, syslimits_size);

	IO_BUF_COPYIN_CRLFCRLF(buf);
	io_buf_copyin(buf, sysinfo, sysinfo_size);
	return (0);
}

