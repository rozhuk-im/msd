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

#ifndef __SRC_DVB_FE_H__
#define __SRC_DVB_FE_H__

#include <sys/param.h>
#include <sys/types.h>
#include <sys/ioccom.h>
#include <linux/dvb/version.h>
#include <linux/dvb/frontend.h>

#include "utils/macro.h"
#include "threadpool/threadpool_task.h"

#ifdef DVB_API_VERSION_MINOR
/* kernel headers >=2.6.28 have version 5.
 *
 * Version 5 is also called S2API, it adds support for tuning to S2 channels
 * and is extensible for future delivery systems. Old API is deprecated.
 * StreamID-implementation only supported since API >=5.2.
 * At least DTV_ENUM_DELSYS requires 5.5.
 */
#	if (DVB_API_VERSION == 5 && DVB_API_VERSION_MINOR >= 5)
#		define DVB_USE_S2API 1

/* This had a different name until API 5.8. */
#		ifndef DTV_STREAM_ID
#			define DTV_STREAM_ID DTV_ISDBS_TS_ID
#		endif
#	endif

/* This is only defined, for convenience, since API 5.8. */
#	ifndef NO_STREAM_ID_FILTER
#		define NO_STREAM_ID_FILTER (~0U)
#	endif

#	if (DVB_API_VERSION == 3 && DVB_API_VERSION_MINOR >= 1) || DVB_API_VERSION == 5
#		define DVB_ATSC 1
#	endif
#endif

/* Keep in sync with enum fe_delivery_system. */
#ifndef DVB_USE_S2API
#	define SYS_DVBC_ANNEX_A		1
#	define SYS_DVBT			3
#	define SYS_DVBS			5
#	define SYS_DVBS2		6
#	define SYS_ATSC			11
#	define SYS_DVBT2		16
#	define SYS_DVBC_ANNEX_C		18
#endif
#define SYS_DVB__COUNT__			(SYS_DVBC_ANNEX_C + 1)



typedef struct dvb_fe_s	*dvb_fe_p;



typedef struct dvb_fe_state_s {
	struct dvb_frontend_info info;	/* ioctl(FE_GET_INFO) */
	uint32_t	dvb_api_ver;	/* ioctl(FE_GET_PROPERTY, DTV_API_VERSION) */
	uint32_t	delivery_sys_mask; /* ioctl(FE_GET_PROPERTY, DTV_FE_CAPABILITY) */
	fe_delivery_system_t delivery_sys; /* current ioctl(FE_GET_PROPERTY, DTV_DELIVERY_SYSTEM) */

	fe_status_t	status;		/* ioctl(FE_READ_STATUS) / ioctl(FE_GET_EVENT) */
	struct dvb_frontend_parameters parameters; /* ioctl(FE_GET_FRONTEND) / ioctl(FE_GET_EVENT) */
	uint32_t	ber;		/* ioctl(FE_READ_BER) */
	int16_t		snr;		/* ioctl(FE_READ_SNR) */
	int16_t		strength;	/* ioctl(FE_READ_SIGNAL_STRENGTH) */
	uint32_t	ublocks;	/* ioctl(FE_READ_UNCORRECTED_BLOCKS) */
} dvb_fe_state_t, *dvb_fe_state_p;

/* State and/or Status changed. */
typedef int (*dvb_fe_on_state_cb)(dvb_fe_p dvb_fe, void *udata, const dvb_fe_state_p status);
/* Ret value: 0: OK, non zero - stop processing, dvb_fe possible destroyed. */


/* DVB FE settings. */
typedef struct dvb_fe_settings_s {
	uint64_t	timeout;
	fe_delivery_system_t delivery_sys; /* DTV_DELIVERY_SYSTEM */
	uint32_t	frequency;	/* DTV_FREQUENCY */
	fe_modulation_t	modulation;	/* DTV_MODULATION */
	uint32_t	symbol_rate;	/* DTV_SYMBOL_RATE */
	fe_code_rate_t	fec;		/* DTV_INNER_FEC */
	fe_spectral_inversion_t spec_inv; /* DTV_INVERSION */
	fe_rolloff_t	rolloff;	/* DTV_ROLLOFF */
	fe_bandwidth_t	bandwidth;	/* DTV_BANDWIDTH_HZ */
	uint32_t	stream_id;	/* DTV_STREAM_ID */
} dvb_fe_settings_t, *dvb_fe_settings_p;



typedef struct dvb_fe_s {
	tp_task_p	tptask;		/* Events receiver. */
	tp_task_p	iotimer;	/* Events receiver. */
	/* Information visible to the client - don't override those values */
	uint32_t	adapter_idx;	/* DVB adapter index. */
	uint32_t	fe_idx;		/* DVB frontend index. */
	uint32_t	frequency;
	uint32_t	bandwidth_hz;	/* For DVBv5 API. */
	dvb_fe_state_t	state;

	tpt_p		tpt;		/* Thread data for all IO operations. */
	dvb_fe_on_state_cb on_state;
	void		*udata;		/* Pointer to stream hub data or other. */
	dvb_fe_settings_t s;		/* Settings. */
} dvb_fe_t;


int	dvb_fe_create(uint32_t adapter_idx, uint32_t fe_idx, tpt_p tpt,
	    dvb_fe_on_state_cb on_state, void *udata, dvb_fe_p *dvb_fe_ret);
void	dvb_fe_destroy(dvb_fe_p dvb_fe);

void	dvb_fe_settings_def(dvb_fe_settings_p s_ret);
int	dvb_fe_settings_xml_load(const uint8_t *buf, size_t buf_size,
	    dvb_fe_settings_p s);
int	dvb_fe_set_settings(dvb_fe_p dvb_fe, dvb_fe_settings_p s);

int	dvb_fe_start(dvb_fe_p dvb_fe);
void	dvb_fe_stop(dvb_fe_p dvb_fe);
int	dvb_fe_restart(dvb_fe_p dvb_fe);


#endif /* __SRC_DVB_FE_H__ */
