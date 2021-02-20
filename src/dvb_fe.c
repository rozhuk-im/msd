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


#include <sys/param.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <sys/stat.h> /* For mode constants */
#include <sys/file.h> /* flock */

#include <stdlib.h> /* malloc, exit */
#include <stdio.h> /* snprintf, fprintf */
#include <unistd.h> /* close, write, sysconf */
#include <fcntl.h> /* For O_* constants */
#include <string.h> /* bcopy, bzero, memcpy, memmove, memset, strerror... */
#include <time.h>
#include <errno.h>

#include "utils/macro.h"
#include "utils/mem_utils.h"
#include "threadpool/threadpool.h"
#include "threadpool/threadpool_task.h"
#include "utils/sys.h"
#include "utils/log.h"
#include "utils/xml.h"

#include "dvb_fe.h"


#define SATELLITE_MASK (						\
		DELSYS_BIT(SYS_DVBS) |					\
		DELSYS_BIT(SYS_DVBS2) |					\
		DELSYS_BIT(SYS_TURBO) |					\
		DELSYS_BIT(SYS_ISDBS) |					\
		DELSYS_BIT(SYS_DSS) |					\
	)

#define CABLE_MASK (							\
		DELSYS_BIT(SYS_DVBC_ANNEX_A) |				\
		DELSYS_BIT(SYS_DVBC_ANNEX_C) |				\
	)

#define TER_MASK (							\
		DELSYS_BIT(SYS_DVBT) |					\
		DELSYS_BIT(SYS_DVBT2) |					\
		DELSYS_BIT(SYS_ISDBT) |					\
		DELSYS_BIT(SYS_DTMB) |					\
	)

#define ATSC_MASK (							\
		DELSYS_BIT(SYS_ATSC) |					\
		DELSYS_BIT(SYS_ATSCMH) |				\
		DELSYS_BIT(SYS_DVBC_ANNEX_B) |				\
	)


/* Keep in sync with enum fe_delivery_system. */
static const char *dvb_delsys_str[] = {
	"UNDEFINED",
	"DVB-C ANNEX A",
	"DVB-C ANNEX B",
	"DVB-T",
	"DSS",
	"DVB-S",
	"DVB-S2",
	"DVB-H",
	"ISDBT",
	"ISDBS",
	"ISDBC",
	"ATSC",
	"ATSCMH",
	"DTMB",
	"CMMB",
	"DAB",
	"DVB-T2",
	"TURBO",
	"DVB-C ANNEX C",
	NULL
};


int	dvb_fe_tune(dvb_fe_p dvb_fe);




static inline void
dvb_fe_props_clr(struct dtv_properties *cmdseq) {

	if (NULL == cmdseq)
		return;
	cmdseq->num = 0;
	mem_bzero(cmdseq->props, (sizeof(struct dtv_property) * DTV_IOCTL_MAX_MSGS));
}

static inline void
dvb_fe_props_add(struct dtv_properties *cmdseq, uint32_t cmd) {

	if (NULL == cmdseq)
		return;
	cmdseq->props[cmdseq->num].cmd = cmd;
	cmdseq->num ++;
}

static inline void
dvb_fe_props_add_u32(struct dtv_properties *cmdseq, uint32_t cmd, uint32_t data) {

	if (NULL == cmdseq)
		return;
	cmdseq->props[cmdseq->num].cmd = cmd;
	cmdseq->props[cmdseq->num].u.data = data;
	cmdseq->num ++;
}


static const char *
get_dvb_delsys(uint32_t delsys) {

	if (SYS_DVB__COUNT__ <= delsys)
		return (dvb_delsys_str[0]);
	return (dvb_delsys_str[delsys]);
}

static uint32_t
dvb_fe_info_to_delsys_mask(uint32_t dvb_api_ver, struct dvb_frontend_info *fe_info) {
	uint32_t ret_mask = 0;

	if (NULL == fe_info)
		return (ret_mask);

	switch (fe_info->type) {
	case FE_QPSK:
		ret_mask |= UINT32_BIT(SYS_DVBS);
		if (dvb_api_ver < 0x0500)
			break;
		if (FE_CAN_2G_MODULATION & fe_info->caps) {
			ret_mask |= UINT32_BIT(SYS_DVBS2);
		}
		if (FE_CAN_TURBO_FEC & fe_info->caps) {
			ret_mask |= UINT32_BIT(SYS_TURBO);
		}
		break;
	case FE_QAM:
		ret_mask |= UINT32_BIT(SYS_DVBC_ANNEX_A);
		ret_mask |= UINT32_BIT(SYS_DVBC_ANNEX_C);
		break;
	case FE_OFDM:
		ret_mask |= UINT32_BIT(SYS_DVBT);
		if (dvb_api_ver < 0x0500)
			break;
		if (FE_CAN_2G_MODULATION & fe_info->caps) {
			ret_mask |= UINT32_BIT(SYS_DVBT2);
		}
		break;
	case FE_ATSC:
		if ((FE_CAN_8VSB | FE_CAN_16VSB) & fe_info->caps) {
			ret_mask |= UINT32_BIT(SYS_ATSC);
		}
		if ((FE_CAN_QAM_64 | FE_CAN_QAM_256 | FE_CAN_QAM_AUTO) & fe_info->caps) {
			ret_mask |= UINT32_BIT(SYS_DVBC_ANNEX_B);
		}
		break;
	}

	return (ret_mask);
}

static void
dvb_fe_flush_events(uintptr_t fd) {
	struct dvb_frontend_event ev;

	if (((uintptr_t)-1) == fd)
		return;
	/* Discard stale events. */
	for (;;) {
		if (-1 == ioctl((int)fd, FE_GET_EVENT, &ev))
			break;
	}
}

static int
dvb_fe_clear(uintptr_t fd) {
	struct dtv_property prop[DTV_IOCTL_MAX_MSGS];
	struct dtv_properties cmdseq = { .num = 0, .props = prop };

	if (((uintptr_t)-1) == fd)
		return (EINVAL);

	/* Clear tunner settings. */
	dvb_fe_props_clr(&cmdseq);
	dvb_fe_props_add(&cmdseq, DTV_CLEAR);
	if (-1 == ioctl((int)fd, FE_SET_PROPERTY, &cmdseq))
		return (errno);
	/* Receive FE_REINIT event. */

	return (0);
}





static int
dvb_fe_event_recv_cb(tp_task_p tptask, int error, uint32_t eof __unused,
    size_t data2transfer_size __unused, void *arg) {
	dvb_fe_p dvb_fe = arg;
	uintptr_t ident;
	//struct timespec ts;
	struct dvb_frontend_event ev;

	if (0 != error) {
err_out:
		dvb_fe_stop(dvb_fe);
		//dvb_fe->last_err = error;
		//str_src_state_update(dvb_fe, STR_SRC_STATE_STOP,
		//    SRC_STATUS_SET_BIT, STR_SRC_STATUS_ERROR);
		return (TP_TASK_CB_NONE); /* Receiver destroyed. */
	}

	//clock_gettime(CLOCK_MONOTONIC_FAST, &tp);
	ident = tp_task_ident_get(tptask);
	while (-1 != ioctl((int)tp_task_ident_get(dvb_fe->tptask), FE_GET_EVENT, &ev)) { /* recv loop. */
		/* Update state. */
		memcpy(&dvb_fe->state.status, &ev.status, sizeof(fe_status_t));
		memcpy(&dvb_fe->state.parameters, &ev.parameters, sizeof(struct dvb_frontend_parameters));

		LOG_INFO("Event process...");
		if (FE_HAS_SIGNAL & ev.status) {
			LOG_INFO("FE_HAS_SIGNAL");
		}
		if (FE_HAS_CARRIER & ev.status) {
			LOG_INFO("FE_HAS_CARRIER");
		}
		if (FE_HAS_VITERBI & ev.status) {
			LOG_INFO("FE_HAS_VITERBI");
		}
		if (FE_HAS_SYNC & ev.status) {
			LOG_INFO("FE_HAS_SYNC");
		}
		if (FE_HAS_LOCK & ev.status) {
			LOG_INFO("FE_HAS_LOCK");
		}
		if (FE_TIMEDOUT & ev.status) {
			LOG_INFO("FE_TIMEDOUT");
		}
		if (FE_REINIT & ev.status) {
			LOG_INFO("FE_REINIT");
		}

		/* Report about state. */
		if (NULL != dvb_fe->on_state) {
			if (0 != dvb_fe->on_state(dvb_fe, dvb_fe->udata, &dvb_fe->state))
				goto err_out;
		}
	} /* end recv while */

	return (TP_TASK_CB_CONTINUE);
}



int
dvb_fe_create(uint32_t adapter_idx, uint32_t fe_idx, tpt_p tpt,
    dvb_fe_on_state_cb on_state, void *udata, dvb_fe_p *dvb_fe_ret) {
	dvb_fe_p dvb_fe;

	if (NULL == tpt || NULL == dvb_fe_ret)
		return (EINVAL);
	dvb_fe = zalloc(sizeof(dvb_fe_t));
	if (NULL == dvb_fe)
		return (ENOMEM);
	dvb_fe->adapter_idx = adapter_idx;
	dvb_fe->fe_idx = fe_idx;
	dvb_fe->tpt = tpt;
	dvb_fe->on_state = on_state;
	dvb_fe->udata = udata;

	(*dvb_fe_ret) = dvb_fe;

	return (0);
}

void
dvb_fe_destroy(dvb_fe_p dvb_fe) {

	if (NULL == dvb_fe)
		return;

	mem_filld(dvb_fe, sizeof(dvb_fe_t));
}


void
dvb_fe_settings_def(dvb_fe_settings_p s_ret) {

	if (NULL == s_ret)
		return;
	mem_bzero(s_ret, sizeof(dvb_fe_settings_t));
	s_ret->delivery_sys = SYS_UNDEFINED;
	//s_ret->frequency;
	s_ret->modulation = QAM_AUTO;
	//s_ret->symbol_rate;
	s_ret->fec = FEC_AUTO;
	s_ret->spec_inv = INVERSION_AUTO;
	s_ret->rolloff = ROLLOFF_AUTO;
	s_ret->bandwidth = BANDWIDTH_AUTO;
	s_ret->stream_id = NO_STREAM_ID_FILTER;
}

int
dvb_fe_settings_xml_load(const uint8_t *buf, size_t buf_size,
    dvb_fe_settings_p s) {
	const uint8_t *data;
	size_t data_size;

	if (NULL == buf || 0 == buf_size || NULL == s)
		return (EINVAL);

	/* Read from config. */

	return (0);
}

int
dvb_fe_set_settings(dvb_fe_p dvb_fe, dvb_fe_settings_p s) {

	if (NULL == dvb_fe || NULL == s)
		return (EINVAL);
	/* Settings. */
	memcpy(&dvb_fe->s, s, sizeof(dvb_fe_settings_t));
	/* Use short name. */
	s = &dvb_fe->s;

	/* Correct values. */
	dvb_fe->frequency = s->frequency;
	switch (s->delivery_sys) {
	case SYS_DVBS:
	case SYS_DVBS2:
#if 0
		if (lnb_type.high_val) {
			if (lnb_type.switch_val) {
				/* Voltage-controlled switch */
				hiband = 0;
				if (s->frequency >= lnb_type.switch_val)
					hiband = 1;
				if (hiband) {
					dvb_fe->frequency = abs(s->frequency - lnb_type.high_val);
				} else {
					dvb_fe->frequency = abs(s->frequency - lnb_type.low_val);
				}
			} else {
				/* C-Band Multipoint LNBf */
				dvb_fe->frequency = abs(s->frequency - (s->polarisation == POLARISATION_VERTICAL ? 
					lnb_type.low_val: lnb_type.high_val));
			}
		} else {
			/* Monopoint LNBf without switch */
			dvb_fe->frequency = abs(s->frequency - lnb_type.low_val);
		}
#endif
		break;
	case SYS_DVBT:
	case SYS_DVBT2:
		if (dvb_fe->frequency < (uint32_t)1000000) {
			dvb_fe->frequency *= ((uint32_t)1000);
		}

		switch (s->bandwidth) {
		case BANDWIDTH_5_MHZ:
			dvb_fe->bandwidth_hz = 5000000;
			break;
		case BANDWIDTH_6_MHZ:
			dvb_fe->bandwidth_hz = 6000000;
			break;
		case BANDWIDTH_7_MHZ:
			dvb_fe->bandwidth_hz = 7000000;
			break;
		case BANDWIDTH_8_MHZ:
			dvb_fe->bandwidth_hz = 8000000;
			break;
		case BANDWIDTH_10_MHZ:
			dvb_fe->bandwidth_hz = 10000000;
			break;
		case BANDWIDTH_AUTO:
			if (dvb_fe->frequency < 474000000) {
				dvb_fe->bandwidth_hz = 7000000;
			} else {
				dvb_fe->bandwidth_hz = 8000000;
			}
			break;
		case BANDWIDTH_1_712_MHZ:
			dvb_fe->bandwidth_hz = 0;
			break;
		}
		break;
	}

	return (0);
}

int
dvb_fe_start(dvb_fe_p dvb_fe) {
	int error;
	uint32_t i;
	uintptr_t fd;
	char frontend_devname[PATH_MAX];
	struct dtv_property prop[DTV_IOCTL_MAX_MSGS];
	struct dtv_properties cmdseq = { .num = 0, .props = prop };

	if (NULL == dvb_fe)
		return (EINVAL);
	if (NULL != dvb_fe->tptask)
		return (EEXIST);
	/* Open frontend. */
	snprintf(frontend_devname, sizeof(frontend_devname),
	    "/dev/dvb/adapter%"PRIu32"/frontend%"PRIu32,
	    dvb_fe->adapter_idx, dvb_fe->fe_idx);
	fd = (uintptr_t)open(frontend_devname, O_RDWR);
	if (((uintptr_t)-1) == fd) {
		error = errno;
		LOG_ERR_FMT(error, "failed to open '%s'", frontend_devname);
		return (error);
	}
	/* Make nonblocking. */
	error = fd_set_nonblocking(fd, 1);
	if (0 != error) {
		LOG_ERR_FMT(error, "failed to fd_set_nonblocking() for '%s'", frontend_devname);
		goto err_out;
	}

	LOGD_INFO_FMT("Tuner %"PRIu32", frontend %"PRIu32"...",
	    dvb_fe->adapter_idx, dvb_fe->fe_idx);

	/* Get DVB API version. */
	dvb_fe_props_clr(&cmdseq);
	dvb_fe_props_add(&cmdseq, DTV_API_VERSION);
	if (-1 == ioctl((int)fd, FE_GET_PROPERTY, &cmdseq)) {
		LOGD_INFO("DVBv3: FE_GET_PROPERTY(DTV_API_VERSION) fail, assume DVB API 3.");
		prop[0].u.data = 0x0300;
	}
	dvb_fe->state.dvb_api_ver = prop[0].u.data;
	LOG_INFO_FMT("Tuner %"PRIu32", frontend %"PRIu32": DVB API ver: %"PRIu8".%"PRIu8,
	    dvb_fe->adapter_idx, dvb_fe->fe_idx,
	    ((dvb_fe->state.dvb_api_ver >> 8) & 0xff),
	    (dvb_fe->state.dvb_api_ver & 0xff));

	/* Get frontend info. */
	if (-1 == ioctl((int)fd, FE_GET_INFO, &dvb_fe->state.info)) {
		LOG_ERR_FMT(errno, "Tuner %"PRIu32", frontend %"PRIu32": FE_GET_INFO fail.",
		    dvb_fe->adapter_idx, dvb_fe->fe_idx);
		goto err_out;
	}
	LOG_INFO_FMT("Tuner %"PRIu32", frontend %"PRIu32": name: '%s'",
	    dvb_fe->adapter_idx, dvb_fe->fe_idx, dvb_fe->state.info.name);

	/* Get delivery system mask.*/
#ifdef DVB_USE_S2API
	dvb_fe_props_clr(&cmdseq);
	dvb_fe_props_add(&cmdseq, DTV_ENUM_DELSYS);
	if (-1 == ioctl((int)fd, FE_GET_PROPERTY, &cmdseq)) {
		LOG_ERR_FMT(errno, "Tuner %"PRIu32", frontend %"PRIu32": DVBv5: FE_GET_PROPERTY(DTV_ENUM_DELSYS) fail.",
		    dvb_fe->adapter_idx, dvb_fe->fe_idx);
	} else { /* Store result to mask. */
		for (i = 0; i < prop[0].u.buffer.len; i ++) {
			dvb_fe->state.delivery_sys_mask |= UINT32_BIT(((uint32_t)prop[0].u.buffer.data[i]));
		}
	}
#endif
	/* Fallback to DVBv3 API delivery system detection. */
	if (0 == dvb_fe->state.delivery_sys_mask) {
		dvb_fe->state.delivery_sys_mask |= dvb_fe_info_to_delsys_mask(dvb_fe->state.dvb_api_ver, &dvb_fe->state.info);
	}
	if (0 == dvb_fe->state.delivery_sys_mask) {
		error = EINVAL;
		LOG_ERR_FMT(error, "Tuner %"PRIu32", frontend %"PRIu32": delivery system detection fail.",
		    dvb_fe->adapter_idx, dvb_fe->fe_idx);
		goto err_out;
	}
	/* Verbose result. */
	for (i = 0; i < SYS_DVB__COUNT__; i ++) {
		if (0 == UINT32_BIT_IS_SET(dvb_fe->state.delivery_sys_mask, i))
			continue; /* Skip unsupported. */
		LOG_INFO_FMT("Tuner %"PRIu32", frontend %"PRIu32": delivery system: %s",
		    dvb_fe->adapter_idx, dvb_fe->fe_idx, get_dvb_delsys(i));
	}

	/* Remove all events. */
	dvb_fe_flush_events(fd);

	/* Create IO task for socket. */
	error = tp_task_notify_create(dvb_fe->tpt, fd,
	    TP_TASK_F_CLOSE_ON_DESTROY, TP_EV_READ, 0,
	    dvb_fe_event_recv_cb, dvb_fe, &dvb_fe->tptask);
	if (0 != error) {
		LOG_ERR_FMT(error, "Tuner %"PRIu32", frontend %"PRIu32" - tp_task_notify_create() failed.",
		    dvb_fe->adapter_idx, dvb_fe->fe_idx);
		goto err_out;
	}

	/* Reset tuner. */
	error = dvb_fe_clear(fd);
	if (0 != error) {
		LOG_ERR_FMT(error, "Tuner %"PRIu32", frontend %"PRIu32" - dvb_fe_clear() failed.",
		    dvb_fe->adapter_idx, dvb_fe->fe_idx);
		goto err_out;
	}
	/* Current delivery system. */
	dvb_fe->state.delivery_sys = SYS_UNDEFINED;

	/* Start tuning. */
	error = dvb_fe_tune(dvb_fe);
	if (0 != error)
		goto err_out;

	return (0);

err_out:
	/* Error. */
	close((int)fd);
	dvb_fe_stop(dvb_fe);
	return (error);
}

void
dvb_fe_stop(dvb_fe_p dvb_fe) {

	if (NULL == dvb_fe)
		return;
	if (NULL == dvb_fe->tptask)
		return;

	tp_task_destroy(dvb_fe->tptask);
	dvb_fe->tptask = NULL;
}

int
dvb_fe_restart(dvb_fe_p dvb_fe) {

	if (NULL == dvb_fe)
		return (EINVAL);

	return (0);
}


int
dvb_fe_tune(dvb_fe_p dvb_fe) {
	int error = 0;
	struct dvb_frontend_parameters feparams;

	if (NULL == dvb_fe)
		return (EINVAL);
	if (NULL == dvb_fe->tptask)
		return (EINVAL);

	if (0 == UINT32_BIT_IS_SET(dvb_fe->state.delivery_sys_mask, dvb_fe->s.delivery_sys)) {
		error = EINVAL;
		LOG_ERR_FMT(error, "Tuner %"PRIu32", frontend %"PRIu32" - does not support delivery system %i - %s.",
		    dvb_fe->adapter_idx, dvb_fe->fe_idx,
		    dvb_fe->s.delivery_sys, get_dvb_delsys(dvb_fe->s.delivery_sys));
		return (error);
	}

#ifdef DVB_USE_S2API
	struct dtv_property prop[DTV_IOCTL_MAX_MSGS];
	struct dtv_properties cmdseq = { .num = 0, .props = prop };

	dvb_fe_props_clr(&cmdseq);
	dvb_fe_props_add_u32(&cmdseq, DTV_DELIVERY_SYSTEM, dvb_fe->s.delivery_sys);
	dvb_fe_props_add_u32(&cmdseq, DTV_FREQUENCY, dvb_fe->frequency);
	dvb_fe_props_add_u32(&cmdseq, DTV_MODULATION, dvb_fe->s.modulation);
	dvb_fe_props_add_u32(&cmdseq, DTV_SYMBOL_RATE, dvb_fe->s.symbol_rate);
	dvb_fe_props_add_u32(&cmdseq, DTV_INNER_FEC, dvb_fe->s.fec);
	dvb_fe_props_add_u32(&cmdseq, DTV_INVERSION, dvb_fe->s.spec_inv);
	dvb_fe_props_add_u32(&cmdseq, DTV_ROLLOFF, dvb_fe->s.rolloff);
	dvb_fe_props_add_u32(&cmdseq, DTV_BANDWIDTH_HZ, dvb_fe->bandwidth_hz);
	dvb_fe_props_add_u32(&cmdseq, DTV_PILOT, PILOT_AUTO);
	dvb_fe_props_add_u32(&cmdseq, DTV_STREAM_ID, dvb_fe->s.stream_id);
	dvb_fe_props_add(&cmdseq, DTV_TUNE);
	if (-1 != ioctl((int)tp_task_ident_get(dvb_fe->tptask), FE_SET_PROPERTY, &cmdseq))
		return (0); /* Ok. */
	/* Error. */
	LOG_ERR_FMT(error, "Tuner %"PRIu32", frontend %"PRIu32" - DVBv5 FE_SET_PROPERTY DTV_TUNE fail.",
	    dvb_fe->adapter_idx, dvb_fe->fe_idx);
	/* Fallback to old API. */
#endif
	if (dvb_fe->s.stream_id != NO_STREAM_ID_FILTER &&
	    dvb_fe->s.stream_id != 0) {
		error = EINVAL;
		LOG_ERR_FMT(error, "Tuner %"PRIu32", frontend %"PRIu32" - DVBv3 does not support stream_id (PLP).",
		    dvb_fe->adapter_idx, dvb_fe->fe_idx);
		return (error);
	}
	mem_bzero(&feparams, sizeof(struct dvb_frontend_parameters));
	feparams.frequency = dvb_fe->frequency;
	feparams.inversion = dvb_fe->s.spec_inv;

	switch (dvb_fe->s.delivery_sys) {
	case SYS_DVBT:
	case SYS_DVBT2:
		feparams.u.ofdm.bandwidth = dvb_fe->s.bandwidth;
		feparams.u.ofdm.code_rate_HP = dvb_fe->s.fec;
		feparams.u.ofdm.code_rate_LP = FEC_AUTO; // XXX
		feparams.u.ofdm.constellation = dvb_fe->s.modulation;
		feparams.u.ofdm.transmission_mode = TRANSMISSION_MODE_AUTO; // XXX
		feparams.u.ofdm.guard_interval = GUARD_INTERVAL_AUTO; // XXX
		feparams.u.ofdm.hierarchy_information = HIERARCHY_AUTO; // XXX
		break;
	case SYS_DVBS:
	case SYS_DVBS2:
		feparams.u.qpsk.symbol_rate = dvb_fe->s.symbol_rate;
		feparams.u.qpsk.fec_inner = dvb_fe->s.fec;
		break;
	case SYS_DVBC_ANNEX_A:
	case SYS_DVBC_ANNEX_C:
		feparams.u.qam.symbol_rate = dvb_fe->s.symbol_rate;
		feparams.u.qam.fec_inner = dvb_fe->s.fec;
		feparams.u.qam.modulation = dvb_fe->s.modulation;
		break;
	case SYS_ATSC:
	case SYS_ATSCMH:
	case SYS_DVBC_ANNEX_B:
		feparams.u.vsb.modulation = dvb_fe->s.modulation;
		break;
	default:
		error = EINVAL;
		LOG_ERR_FMT(error, "Tuner %"PRIu32", frontend %"PRIu32" - DVBv3 does not support delivery system %i - %s.",
		    dvb_fe->adapter_idx, dvb_fe->fe_idx,
		    dvb_fe->s.delivery_sys, get_dvb_delsys(dvb_fe->s.delivery_sys));
		return (error);
	}

	if (-1 != ioctl((int)tp_task_ident_get(dvb_fe->tptask), FE_SET_FRONTEND, &feparams))
		return (0); /* Ok. */
	/* Error. */
	error = errno;
	LOG_ERR_FMT(error, "Tuner %"PRIu32", frontend %"PRIu32" - DVBv3 FE_SET_FRONTEND fail.",
	    dvb_fe->adapter_idx, dvb_fe->fe_idx);

	return (error);
}




