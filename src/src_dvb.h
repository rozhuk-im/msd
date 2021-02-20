/*-
 * Copyright (c) 2016 - 2021 Rozhuk Ivan <rozhuk.im@gmail.com>
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

#ifndef __SRC_DVB_H__
#define __SRC_DVB_H__

#include <time.h>
#include "utils/macro.h"
#include "threadpool/threadpool_task.h"
#include "proto/mpeg2ts.h"
#include "dvb_fe.h"


typedef struct src_dvb_s	*src_dvb_p;

/* After data received. */
typedef int (*src_dvb_on_data_rcvd_cb)(src_dvb_p src, struct timespec *ts, void *udata);
/* State and/or Status changed. */
typedef int (*src_dvb_on_state_cb)(src_dvb_p src, void *udata, uint32_t state, uint32_t status);
/* Ret value: 0: OK, non zero - stop processing, src possible destroyed. */


/* Settings. */
typedef struct src_dvb_settings_s {
	uint32_t	dmx_buf_size;	/* ioctl(DMX_SET_BUFFER_SIZE) */
	uint32_t	adapter_idx;	/* DVB adapter index. */
	uint32_t	fe_idx;		/* DVB frontend index. */
	uint32_t	dmx_idx;	/* DVB demux index. */
	dvb_fe_settings_t fe_s;		/* DVB frontend settings. */
} src_dvb_settings_t, *src_dvb_settings_p;
/* Default values. */
#define SRC_DVB_S_DEF_FLAGS		(src_dvb_S_F_M2TS_ANALYZING)


typedef struct src_dvb_filter_s {
	tp_task_p	tptask;		/* System PIDs receiver. */
	uint16_t	pnr;		/* Program num. */
	uint16_t	pmt_pid;	/* Packet ID / PMT PID. */
	uintptr_t	fd;		/* /dev/dvb/adapterX/demuxY descriptor. */
	tpt_p		tpt;		/* Thread data for all IO operations. */
	void		*udata;		/* Pointer to stream hub data or other. */
	src_dvb_on_state_cb	on_state;
	src_dvb_on_data_rcvd_cb	on_data;
} src_dvb_filter_t, *src_dvb_filter_p;


typedef struct src_dvb_s {
	dvb_fe_p	dvb_fe;		/* DVB frontend. */
	uint16_t	nit_pid;	/* NIT PID. */
	src_dvb_filter_p pids_tbl[MPEG2_TS_PID__COUNT__]; /* Fast map PID to filter. */
	src_dvb_settings_t s;		/* Settings. */
} src_dvb_t;


void	src_dvb_settings_def(src_dvb_settings_p s_ret);
int	src_dvb_xml_load_settings(const uint8_t *buf, size_t buf_size,
	    src_dvb_settings_p s);

int	src_dvb_create(src_dvb_settings_p s, tpt_p tpt, src_dvb_p *src_dvb_ret);
void	src_dvb_destroy(src_dvb_p src_dvb);
int	src_dvb_start(src_dvb_p src_dvb);
void	src_dvb_stop(src_dvb_p src_dvb);
int	src_dvb_restart(src_dvb_p src_dvb);


#endif /* __SRC_DVB_H__ */
