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
#include <sys/time.h>
#include <netinet/in.h> /* ntohs */

#include <inttypes.h>
#include <stdlib.h> /* malloc, exit */
#include <string.h> /* bcopy, bzero, memcpy, memmove, memset, strerror... */
#include <stdio.h> /* snprintf, fprintf */
#include <time.h>
#include <errno.h>

#include "utils/mem_utils.h"
#include "proto/mpeg2ts.h"
#include "math/crc32.h"
#include "utils/log.h"
#include "stream_mpeg2ts.h"

#ifdef MPEG2TS_XML_CONFIG
#include "utils/str2num.h"
#include "utils/xml.h"
#endif



#define STR_M2TS_PROC_ALLOC_CNT		1
#define STR_M2TS_PID_ALLOC_CNT		4
#define STR_M2TS_PID_IDX_ALLOC_CNT	128
#define STR_M2TS_KEY_FRAME_IDX_ALLOC_CNT 16


int	mpeg2_ts_data_progs_realloc(mpeg2_ts_data_p m2ts, size_t count);
void	mpeg2_ts_prog_data_free(mpeg2_ts_prog_p prog);

int	mpeg2_ts_data_pids_realloc(mpeg2_ts_data_p m2ts, size_t count);
int	mpeg2_ts_data_pids_add(mpeg2_ts_data_p m2ts, uint16_t pid);
int	mpeg2_ts_data_pids_cleanup(mpeg2_ts_data_p m2ts);
int	mpeg2_ts_pid_idx_add(mpeg2_ts_pid_p ts_pid, r_buf_p r_buf,
	    r_buf_rpos_p rpos);

void	mpeg2_ts_pid_data_free(mpeg2_ts_pid_p ts_pid);

mpeg2_ts_psi_tbl_p	mpeg2_ts_pid_psi_tbl_get(mpeg2_ts_pid_p ts_pid,
			    uint8_t tid, uint16_t tid_ext);
int	mpeg2_ts_pid_psi_tbls_realloc(mpeg2_ts_pid_p ts_pid, size_t count);
int	mpeg2_ts_pid_psi_tbl_add(mpeg2_ts_pid_p ts_pid, uint8_t tid,
	    uint16_t tid_ext, mpeg2_ts_psi_tbl_p *psi_tbl);
void	mpeg2_ts_psi_tbl_data_free(mpeg2_ts_psi_tbl_p psi_tbls);


mpeg2_ts_prog_p	mpeg2_ts_data_get_prog(mpeg2_ts_data_p m2ts, uint16_t pid, int *is_psi);
mpeg2_ts_pid_p	mpeg2_ts_data_get_pid(mpeg2_ts_data_p m2ts, uint16_t pid,
		    int *is_psi, mpeg2_ts_prog_p *prog_ret);


int	mpeg2_ts_psi_tbl_chk_by_pid(uint16_t pid, uint16_t nit_pid,
	    uint16_t pmt_pid, uint16_t tid);
int	mpeg2_ts_psi_tbl_reassemble(mpeg2_ts_data_p m2ts, mpeg2_ts_prog_p prog,
	    mpeg2_ts_pid_p ts_pid, int cc_incorrect, r_buf_rpos_p rpos,
	    mpeg2_ts_hdr_p ts_hdr, uint8_t *buf_pos,
	    mpeg2_ts_psi_tbl_p *psi_tbl_ret, mpeg2_ts_psi_tbl_sec_p *psi_sect_ret);
int	mpeg2_ts_psi_analize(mpeg2_ts_data_p m2ts, mpeg2_ts_prog_p prog,
	    mpeg2_ts_pid_p ts_pid, int cc_incorrect, r_buf_rpos_p rpos,
	    mpeg2_ts_hdr_p ts_hdr, uint8_t *buf_pos);
int	mpeg2_ts_pid_psi_serialize(mpeg2_ts_data_p m2ts, mpeg2_ts_pid_p ts_pid);

int	mpeg2_ts_key_frames_idx_add(mpeg2_ts_data_p m2ts,
	    struct timespec *ts, r_buf_p r_buf, r_buf_rpos_p rpos);

int	mpeg2_ts_descriptors_dump(uint8_t *data, size_t data_size,
	    uint8_t *buf, size_t buf_size, size_t *buf_size_ret);

int	mpeg2_ts_txt_dump_pid(mpeg2_ts_data_p m2ts, mpeg2_ts_pid_p pid,
	    uint8_t *buf, size_t buf_size, size_t *buf_size_ret);
int	mpeg2_ts_txt_dump_prog(mpeg2_ts_data_p m2ts, mpeg2_ts_prog_p prog,
	    uint8_t *buf, size_t buf_size, size_t *buf_size_ret);




#define M2TS_DUMP_MPEG2TS_HDR(ts_hdr)					\
    LOGD_EV_FMT("MPEG2 TS header: TE = %hhi, PUS = %hhi, TP = %hhi, "	\
    "PID = %"PRIu16", SC = %hhi, CP = %hhi, AFE = %hhi, CC = %hhi",	\
    (ts_hdr)->te, (ts_hdr)->pus, (ts_hdr)->tp, MPEG2_TS_PID((ts_hdr)),	\
    (ts_hdr)->sc, (ts_hdr)->cp, (ts_hdr)->afe, (ts_hdr)->cc)

#define M2TS_DUMP_MPEG2TS_PSI_HDR(psi_hdr)				\
    LOGD_EV_FMT("MPEG2 TS PSI header: tid = %"PRIu8", ss = %hhi, pr = %hhi, " \
        "r0 = %hhi, sec_len = %"PRIu16"",				\
	(psi_hdr)->tid, (psi_hdr)->ss, (psi_hdr)->pr, (psi_hdr)->r0,	\
	MPEG2_PSI_TBL_SEC_LEN((psi_hdr)))

#define M2TS_DUMP_MPEG2TS_PSI_SNTX(sntx)				\
    LOGD_EV_FMT("MPEG2 TS PSI syntax: tid ext = %"PRIu16"(%"PRIu16"), "	\
        "r0 = %hhi, ver = %hhi, cn = %hhi, sn = %"PRIu8", lsn = %"PRIu8"", \
	(sntx)->tid_ext, ntohs((sntx)->tid_ext), (sntx)->r0, (sntx)->ver, \
	(sntx)->cn, (sntx)->sn,	(sntx)->lsn)

#define M2TS_DUMP_MPEG2TS_PES_HDR(pes_hdr)				\
    LOGD_EV_FMT("MPEG2 TS PES header: sid = %x, len = %"PRIu16"",	\
	(pes_hdr)->sid, (pes_hdr)->len)





void
mpeg2_ts_def_settings(mpeg2_ts_settings_p s) {

	LOGD_EV_FMT("... %zx", s);

	if (NULL == s)
		return;
	/* Init. */
	mem_bzero(s, sizeof(mpeg2_ts_settings_t));

	/* Default settings. */
	s->pids_flt.pids_count = 0;
	s->pids_flt.pids = NULL;
}

#ifdef MPEG2TS_XML_CONFIG
int
mpeg2_ts_xml_load_settings(const uint8_t *buf, size_t buf_size, mpeg2_ts_settings_p s) {
	const uint8_t *data, *cur_pos;
	size_t data_size;
	uint32_t tm32, *pids_new;

	LOGD_EV_FMT("... %zx", s);

	if (NULL == buf || 0 == buf_size || NULL == s)
		return (EINVAL);
	/* Read from config. */
	cur_pos = NULL;
	while (0 == xml_get_val_args(buf, buf_size, &cur_pos, NULL, NULL,
	    &data, &data_size, (const uint8_t*)"filterPIDList", "PID", NULL)) {
		if (0 == mem_cmpin_cstr("reset", data, data_size)) {
			s->pids_flt.pids_count = 0;
			//s->pids_flt.pids;
			s->pids_flt.pid_null = 0;
			s->pids_flt.pid_nit = 0;
			s->pids_flt.pid_unknown = 0;
			continue;
		} else if (0 == mem_cmpin_cstr("unknown", data, data_size)) {
			s->pids_flt.pid_unknown = 1;
			continue;
		} else if (0 == mem_cmpin_cstr("null", data, data_size)) {
			s->pids_flt.pid_null = 1;
			continue;
		} else if (0 == mem_cmpin_cstr("nit", data, data_size)) {
			s->pids_flt.pid_nit = 1;
			continue;
		} else if (0 == mem_cmpin_cstr("sdt", data, data_size)) {
			tm32 = MPEG2_TS_PID_SDT;
		} else { /* Number. */
			tm32 = ustr2u32(data, data_size);
			switch (tm32) {
			case 0: /* Do not filter PAT PID. */
				continue;
			case MPEG2_TS_PID_NIT_DEF:
				s->pids_flt.pid_nit = 1;
				continue;
			case MPEG2_TS_PID_NULL:
				s->pids_flt.pid_null = 1;
				continue;
			}
		}
		LOG_EV_FMT("Try to add filtering PID %i, mem=%zx, count=%zu",
		    tm32, s->pids_flt.pids, s->pids_flt.pids_count);
		pids_new = reallocarray(s->pids_flt.pids,
		    (s->pids_flt.pids_count + 2), sizeof(uint32_t));
		if (NULL == pids_new) {
			LOG_ERR_FMT(errno, "fail to add filtering PID %i", tm32);
			continue;
		}
		s->pids_flt.pids = pids_new;
		s->pids_flt.pids[s->pids_flt.pids_count] = tm32;
		s->pids_flt.pids_count ++;
		LOG_EV_FMT("Added filtering PID %i, mem=%zx, count=%zu",
		    tm32, s->pids_flt.pids, s->pids_flt.pids_count);
	}

	return (0);
}
#endif /* MPEG2TS_XML_CONFIG */

int
mpeg2_ts_settings_copy(mpeg2_ts_settings_p dst, mpeg2_ts_settings_p src) {

	LOGD_EV_FMT("... %zx <- %zx", dst, src);

	if (NULL == dst || NULL == src)
		return (EINVAL);

	memcpy(dst, src, sizeof(mpeg2_ts_settings_t));
	/* Copy PIDs list to new buffer. */
	if (NULL == dst->pids_flt.pids || 0 == dst->pids_flt.pids_count) {
		dst->pids_flt.pids = NULL;
		dst->pids_flt.pids_count = 0;
	} else {
		LOG_EV_FMT("mem=%zx, count=%zu",
		    dst->pids_flt.pids, dst->pids_flt.pids_count);
		dst->pids_flt.pids = mallocarray(dst->pids_flt.pids_count,
		    sizeof(uint32_t));
		if (NULL == dst->pids_flt.pids) {
			dst->pids_flt.pids_count = 0;
			return (ENOMEM);
		}
		memcpy(dst->pids_flt.pids, src->pids_flt.pids,
		    (dst->pids_flt.pids_count * sizeof(uint32_t)));
	}

	return (0);
}

void
mpeg2_ts_settings_free_data(mpeg2_ts_settings_p s) {

	LOGD_EV_FMT("... %zx", s);

	if (NULL == s)
		return;
	if (NULL != s->pids_flt.pids) {
		free(s->pids_flt.pids);
		s->pids_flt.pids = NULL;
		s->pids_flt.pids_count = 0;
	}
	mem_filld(s, sizeof(mpeg2_ts_settings_t));
}



int
mpeg2_ts_data_alloc(mpeg2_ts_data_p *m2ts_ret, mpeg2_ts_settings_p s) {
	mpeg2_ts_data_p m2ts;

	LOGD_EV("...");

	m2ts = zalloc(sizeof(mpeg2_ts_data_t));
	if (NULL == m2ts)
		return (ENOMEM);
	m2ts->mpeg2_ts_pkt_size = MPEG2_TS_PKT_SIZE_188;
	m2ts->pat.pid = MPEG2_TS_PID_NULL; /* For fix err counter in first time. */
	m2ts->nit.pid = MPEG2_TS_PID_NIT_DEF; /* Network Information Table. Default PID value. */

	/* Set new. */
	if (NULL == s) { /* Default. */
		mpeg2_ts_def_settings(&m2ts->s);
	} else {
		mpeg2_ts_settings_copy(&m2ts->s, s);
	}

	(*m2ts_ret) = m2ts;
	return (0);
}

void
mpeg2_ts_data_free(mpeg2_ts_data_p m2ts) {
	size_t i;

	LOGD_EV("...");

	if (NULL == m2ts)
		return;
	mpeg2_ts_pid_data_free(&m2ts->pat);
	mpeg2_ts_pid_data_free(&m2ts->cat);
	mpeg2_ts_pid_data_free(&m2ts->tsdt);
	mpeg2_ts_pid_data_free(&m2ts->ipmpcit);
	mpeg2_ts_pid_data_free(&m2ts->nit);
	mpeg2_ts_pid_data_free(&m2ts->sdt);
	mpeg2_ts_pid_data_free(&m2ts->eit);

	if (NULL != m2ts->progs) {
		for (i = 0; i < m2ts->prog_allocated; i ++) {
			mpeg2_ts_prog_data_free(&m2ts->progs[i]);
		}
		free(m2ts->progs);
		m2ts->progs = NULL;
	}
	if (NULL != m2ts->data_pids) {
		for (i = 0; i < m2ts->data_pids_allocated; i ++) {
			mpeg2_ts_pid_data_free(&m2ts->data_pids[i]);
		}
		free(m2ts->data_pids);
		m2ts->data_pids = NULL;
	}
	if (NULL != m2ts->key_frames_rpos) {
		free(m2ts->key_frames_rpos);
		m2ts->key_frames_rpos = NULL;
	}
	if (NULL != m2ts->key_frames_time) {
		free(m2ts->key_frames_time);
		m2ts->key_frames_time = NULL;
	}
	mpeg2_ts_settings_free_data(&m2ts->s);
	mem_filld(m2ts, sizeof(mpeg2_ts_data_t));
	free(m2ts);
}





int
mpeg2_ts_data_progs_realloc(mpeg2_ts_data_p m2ts, size_t count) {
	size_t i;
	mpeg2_ts_prog_p progs;

	if (NULL == m2ts)
		return (EINVAL);
	if (m2ts->prog_allocated == count)
		return (0);
	if (count < m2ts->prog_allocated) { /* DeInit progs. */
		for (i = count; i < m2ts->prog_allocated; i ++) {
			mpeg2_ts_prog_data_free(&m2ts->progs[i]);
		}
	}
	progs = reallocarray(m2ts->progs, count, sizeof(mpeg2_ts_prog_t));
	if (NULL == progs) /* Realloc fail! */
		return (ENOMEM);
	if (count > m2ts->prog_allocated) { /* Init progs. */
		mem_bzero(&progs[m2ts->prog_allocated],
		    ((count - m2ts->prog_allocated) * sizeof(mpeg2_ts_prog_t)));
	}
	m2ts->progs = progs;
	m2ts->prog_allocated = count;

	return (0);
}

void
mpeg2_ts_prog_data_free(mpeg2_ts_prog_p prog) {

	if (NULL == prog)
		return;
	mpeg2_ts_pid_data_free(&prog->pmt);
	if (NULL != prog->pids) {
		free(prog->pids);
		prog->pids = NULL;
	}
}


int
mpeg2_ts_data_pids_realloc(mpeg2_ts_data_p m2ts, size_t count) {
	size_t i;
	mpeg2_ts_pid_p pids;

	if (NULL == m2ts)
		return (EINVAL);
	if (m2ts->data_pids_allocated == count)
		return (0);
	if (count < m2ts->data_pids_allocated) { /* DeInit pids. */
		for (i = count; i < m2ts->data_pids_allocated; i ++) {
			mpeg2_ts_pid_data_free(&m2ts->data_pids[i]);
		}
	}
	pids = reallocarray(m2ts->data_pids, count, sizeof(mpeg2_ts_pid_t));
	if (NULL == pids) /* Realloc fail! */
		return (ENOMEM);
	if (count > m2ts->data_pids_allocated) { /* Init pids. */
		mem_bzero(&pids[m2ts->data_pids_allocated],
		    ((count - m2ts->data_pids_allocated) * sizeof(mpeg2_ts_pid_t)));
	}
	m2ts->data_pids = pids;
	m2ts->data_pids_allocated = count;

	return (0);
}

int
mpeg2_ts_data_pids_add(mpeg2_ts_data_p m2ts, uint16_t pid) {
	int error;

	if (NULL == m2ts)
		return (EINVAL);
	if (NULL != mpeg2_ts_data_get_prog(m2ts, pid, NULL))
		return (0);
	error = mpeg2_ts_data_pids_realloc(m2ts, (m2ts->data_pids_cnt + 1));
	if (0 != error)
		return (error);
	//if (NULL != psi_tbl)
	//	(*psi_tbl) = &m2ts->data_pids[m2ts->data_pids_cnt];
	m2ts->data_pids[m2ts->data_pids_cnt].pid = pid;
	m2ts->data_pids[m2ts->data_pids_cnt].seg_cnt = 0;
	m2ts->data_pids[m2ts->data_pids_cnt].psi_tbls_cnt = 0;
	m2ts->data_pids_cnt ++;

	return (0);
}

int
mpeg2_ts_data_pids_cleanup(mpeg2_ts_data_p m2ts) {
	size_t i, count;

	if (NULL == m2ts)
		return (EINVAL);
	count = m2ts->data_pids_cnt;
	for (i = 0; i < count; ) {
		if (NULL != mpeg2_ts_data_get_prog(m2ts, m2ts->data_pids[i].pid, NULL)) {
			i ++;
			continue;
		}
		mpeg2_ts_pid_data_free(&m2ts->data_pids[i]);
		memmove(&m2ts->data_pids[i], &m2ts->data_pids[(i + 1)],
		    ((count - (i + 1)) * sizeof(mpeg2_ts_pid_t)));
		count --;
		mem_bzero(&m2ts->data_pids[count], sizeof(mpeg2_ts_pid_t));
	}
	m2ts->data_pids_cnt = count;
	return (mpeg2_ts_data_pids_realloc(m2ts, count));
}


int
mpeg2_ts_pid_idx_add(mpeg2_ts_pid_p ts_pid, r_buf_p r_buf,
    r_buf_rpos_p rpos) {
	int error;
	size_t i;

	if (NULL == ts_pid || NULL == r_buf || NULL == rpos)
		return (EINVAL);
	error = realloc_items((void**)&ts_pid->seg_rpos, sizeof(r_buf_rpos_t),
	    &ts_pid->seg_allocated, STR_M2TS_PID_IDX_ALLOC_CNT, ts_pid->seg_cnt);
	if (0 != error)
		return (error);
	/* Remove old. */
	for (i = 0; i < ts_pid->seg_cnt; i ++) {
		if (0 != r_buf_rpos_check_fast(r_buf, &ts_pid->seg_rpos[i]))
			break;
	}
	if (0 != i) {
		memmove(ts_pid->seg_rpos, &ts_pid->seg_rpos[i],
		    (ts_pid->seg_cnt - i) * sizeof(r_buf_rpos_t));
		ts_pid->seg_cnt -= i;
	}
	/* Add new. */
	memcpy(&ts_pid->seg_rpos[ts_pid->seg_cnt], rpos, sizeof(r_buf_rpos_t));
	ts_pid->seg_cnt ++;

	return (0);
}

mpeg2_ts_prog_p
mpeg2_ts_data_get_prog(mpeg2_ts_data_p m2ts, uint16_t pid, int *is_psi) {
	int psi = 1;
	size_t i, j;
	mpeg2_ts_prog_p prog = NULL, cur_prog;

	if (NULL == m2ts)
		goto ok_exit;

	switch (pid) {
	case MPEG2_TS_PID_PAT: /* Program Association Table. */
	case MPEG2_TS_PID_CAT: /* Conditional Access Table. */
	case MPEG2_TS_PID_TSDT: /* Transport Stream Description Table. */
	case MPEG2_TS_PID_IPMPCIT: /* IPMP Control Information Table. */
	case MPEG2_TS_PID_SDT: /* Service Description Table. */
	case MPEG2_TS_PID_EIT: /* Event Information Table. */
		break;
	case MPEG2_TS_PID_NULL: /* Null packets. */
		psi = 0;
		break;
	default:
		if (pid == m2ts->nit.pid)
			break;
		/* XXX: optimize in future. */
		for (i = 0; i < m2ts->prog_cnt; i ++) {
			cur_prog = &m2ts->progs[i];
			if (pid == cur_prog->pmt.pid) { /* Found. */
				prog = cur_prog;
				goto ok_exit;
			}
			for (j = 0; j < cur_prog->pids_cnt; j ++) {
				if (pid == cur_prog->pids[j]) { /* Found. */
					prog = cur_prog;
					goto ok_exit;
				}
			}
		}
	}
ok_exit:
	if (NULL != is_psi) {
		(*is_psi) = psi;
	}
	return (prog);
}

mpeg2_ts_pid_p
mpeg2_ts_data_get_pid(mpeg2_ts_data_p m2ts, uint16_t pid, int *is_psi,
    mpeg2_ts_prog_p *prog_ret) {
	int psi = 1;
	size_t i;
	mpeg2_ts_pid_p ts_pid = NULL;
	mpeg2_ts_prog_p prog = NULL;

	if (NULL == m2ts)
		goto ok_exit;

	switch (pid) {
	case MPEG2_TS_PID_PAT: /* Program Association Table. */
		ts_pid = &m2ts->pat;
		break;
	case MPEG2_TS_PID_CAT: /* Conditional Access Table. */
		ts_pid = &m2ts->cat;
		break;
	case MPEG2_TS_PID_TSDT: /* Transport Stream Description Table. */
		ts_pid = &m2ts->tsdt;
		break;
	case MPEG2_TS_PID_IPMPCIT: /* IPMP Control Information Table. */
		ts_pid = &m2ts->ipmpcit;
		break;
	case MPEG2_TS_PID_SDT: /* Service Description Table. */
		ts_pid = &m2ts->sdt;
		break;
	case MPEG2_TS_PID_EIT: /* Event Information Table. */
		ts_pid = &m2ts->eit;
		break;
	case MPEG2_TS_PID_NULL: /* Null packets. */
		psi = 0;
		break;
	default:
		if (pid == m2ts->nit.pid) {
			ts_pid = &m2ts->nit;
			break;
		}
		/* XXX: optimize in future. */
		for (i = 0; i < m2ts->data_pids_cnt; i ++) {
			if (pid == m2ts->data_pids[i].pid) { /* Found. */
				psi = 0;
				//prog = NULL;
				ts_pid = &m2ts->data_pids[i];
				goto ok_exit;
			}
		}
		for (i = 0; i < m2ts->prog_cnt; i ++) {
			if (pid == m2ts->progs[i].pmt.pid) { /* Found. */
				prog = &m2ts->progs[i];
				ts_pid = &m2ts->progs[i].pmt;
				goto ok_exit;
			}
		}
	}
ok_exit:
	if (NULL != is_psi) {
		(*is_psi) = psi;
	}
	if (NULL != prog_ret) {
		(*prog_ret) = prog;
	}
	return (ts_pid);
}


void
mpeg2_ts_pid_data_free(mpeg2_ts_pid_p ts_pid) {
	size_t i;

	if (NULL == ts_pid)
		return;
	if (NULL != ts_pid->seg_rpos) {
		free(ts_pid->seg_rpos);
		ts_pid->seg_rpos = NULL;
	}
	if (NULL != ts_pid->psi_tbls) {
		for (i = 0; i < ts_pid->psi_tbls_allocated; i ++) {
			mpeg2_ts_psi_tbl_data_free(&ts_pid->psi_tbls[i]);
		}
		free(ts_pid->psi_tbls);
		ts_pid->psi_tbls = NULL;
	}
	if (NULL != ts_pid->ts_psi_packets) {
		free(ts_pid->ts_psi_packets);
		ts_pid->ts_psi_packets = NULL;
	}
}





mpeg2_ts_psi_tbl_p
mpeg2_ts_pid_psi_tbl_get(mpeg2_ts_pid_p ts_pid, uint8_t tid, uint16_t tid_ext) {
	size_t i;

	if (NULL == ts_pid)
		return (NULL);
	if (NULL == ts_pid->psi_tbls || 0 == ts_pid->psi_tbls_cnt)
		return (NULL);

	/* XXX: optimize in future. */
	for (i = 0; i < ts_pid->psi_tbls_cnt; i ++) {
		if (tid == ts_pid->psi_tbls[i].tid &&
		    tid_ext == ts_pid->psi_tbls[i].tid_ext) /* Found. */
			return (&ts_pid->psi_tbls[i]);
	}
	return (NULL);
}

int
mpeg2_ts_pid_psi_tbls_realloc(mpeg2_ts_pid_p ts_pid, size_t count) {
	size_t i;
	mpeg2_ts_psi_tbl_p psi_tbls;

	if (NULL == ts_pid)
		return (EINVAL);
	if (ts_pid->psi_tbls_allocated == count)
		return (0);
	if (count < ts_pid->psi_tbls_allocated) { /* DeInit tables. */
		for (i = count; i < ts_pid->psi_tbls_allocated; i ++) {
			mpeg2_ts_psi_tbl_data_free(&ts_pid->psi_tbls[i]);
		}
	}
	psi_tbls = reallocarray(ts_pid->psi_tbls, count, sizeof(mpeg2_ts_psi_tbl_t));
	if (NULL == psi_tbls) /* Realloc fail! */
		return (ENOMEM);
	if (count > ts_pid->psi_tbls_allocated) { /* Init psi_tbls. */
		mem_bzero(&psi_tbls[ts_pid->psi_tbls_allocated],
		    ((count - ts_pid->psi_tbls_allocated) * sizeof(mpeg2_ts_psi_tbl_t)));
	}
	ts_pid->psi_tbls = psi_tbls;
	ts_pid->psi_tbls_allocated = count;

	return (0);
}

int
mpeg2_ts_pid_psi_tbl_add(mpeg2_ts_pid_p ts_pid, uint8_t tid, uint16_t tid_ext,
    mpeg2_ts_psi_tbl_p *psi_tbl) {
	int error;

	if (NULL == ts_pid)
		return (EINVAL);
	error = mpeg2_ts_pid_psi_tbls_realloc(ts_pid, (ts_pid->psi_tbls_cnt + 1));
	if (0 != error)
		return (error);
	if (NULL != psi_tbl) {
		(*psi_tbl) = &ts_pid->psi_tbls[ts_pid->psi_tbls_cnt];
	}
	ts_pid->psi_tbls[ts_pid->psi_tbls_cnt].tid = tid;
	ts_pid->psi_tbls[ts_pid->psi_tbls_cnt].tid_ext = tid_ext;
	ts_pid->psi_tbls_cnt ++;

	return (0);
}

void
mpeg2_ts_psi_tbl_data_free(mpeg2_ts_psi_tbl_p psi_tbl) {

	if (NULL == psi_tbl)
		return;
	if (NULL != psi_tbl->sects) {
		free(psi_tbl->sects);
		psi_tbl->sects = NULL;
	}
}









int
mpeg2_ts_descriptors_dump(uint8_t *data, size_t data_size,
    uint8_t *buf, size_t buf_size, size_t *buf_size_ret) {
	mpeg2_ts_descr_hdr_p hdr, hdr_last;
	size_t i, tm, buf_used = 0;
	uint8_t str[1024];

	if (NULL == buf || 0 == buf_size)
		return (EINVAL);
	if (NULL == data || 0 == data_size) {
		buf[0] = 0;
		if (NULL != buf_size_ret) {
			(*buf_size_ret) = buf_used;
		}
		return (EINVAL);
	}
	hdr = (mpeg2_ts_descr_hdr_p)data;
	hdr_last = (mpeg2_ts_descr_hdr_p)(data + data_size);
	for (; hdr < hdr_last && MPEG2_DESCR_NEXT(hdr) <= hdr_last;
	    hdr = MPEG2_DESCR_NEXT(hdr)) {
		tm = MPEG2_DESCR_DATA_LEN(hdr);
		memcpy(str, MPEG2_DESCR_DATA(hdr), tm);
		str[tm] = 0;
		for (i = 0; i < tm; i ++) {
			if (str[i] < ' ') {
				str[i] = ' ';
			}
		}
		buf_used += (size_t)snprintf((char*)(buf + buf_used), (buf_size - buf_used),
		    "Descriptor: type: %"PRIu8", data size: %zu, data: %s\r\n",
		    MPEG2_DESCR_TAG(hdr), tm, str);
	}
	buf[buf_used] = 0;
	if (NULL != buf_size_ret) {
		(*buf_size_ret) = buf_used;
	}
	return (0);
}



/* Check PID<->TID to filter invalid/incorrect tables. */
int
mpeg2_ts_psi_tbl_chk_by_pid(uint16_t pid, uint16_t nit_pid, uint16_t pmt_pid, uint16_t tid) {

	if (MPEG2_PSI_TID_STUFF == tid) /* Stuffing, bytes may be discarded by a decoder. */
		return (0);
	switch (pid) {
	case MPEG2_TS_PID_PAT: /* Program Association Table. */
		return (MPEG2_PSI_TID_PAT == tid);
	case MPEG2_TS_PID_CAT: /* Conditional Access Table. */
		return (MPEG2_PSI_TID_CAT == tid);
	//case MPEG2_TS_PID_TSDT: /* Transport Stream Description Table. */
	//	return (MPEG2_PSI_TID_PAT == tid);
	//case MPEG2_TS_PID_IPMPCIT: /* IPMP Control Information Table. */
	//	return (MPEG2_PSI_TID_PAT == tid);
	case MPEG2_TS_PID_SDT: /* Service Description Table. */
		return (MPEG2_PSI_TID_SDT == tid || MPEG2_PSI_TID_SDT_OTH == tid);
	case MPEG2_TS_PID_EIT: /* Event Information Table. */
		return (MPEG2_PSI_TID_EIT_A <= tid && MPEG2_PSI_TID_EIT_OS_MAX >= tid);
	//case MPEG2_TS_PID_RST: /* Running Status Table. */
	//	return (MPEG2_PSI_TID_EIT_A <= tid && MPEG2_PSI_TID_EIT_OS_MAX >= tid);
	case MPEG2_TS_PID_TDT: /* Time and Date Table. */
		return (MPEG2_PSI_TID_TDT == tid || MPEG2_PSI_TID_TOT == tid);
	//case MPEG2_TS_PID_EPG: /* EPG Table. */
	//	return (MPEG2_PSI_TID_EIT_A <= tid && MPEG2_PSI_TID_EIT_OS_MAX >= tid);
	case MPEG2_TS_PID_NULL: /* Null packets. */
		return (0);
	default:
		if (pid == nit_pid)
			return (MPEG2_PSI_TID_NIT == tid || MPEG2_PSI_TID_NIT_OTH == tid);
		if (pid == pmt_pid)
			return (MPEG2_PSI_TID_PMT == tid);
	}

	return (1);
}

int
mpeg2_ts_psi_tbl_reassemble(mpeg2_ts_data_p m2ts, mpeg2_ts_prog_p prog,
    mpeg2_ts_pid_p ts_pid, int cc_incorrect, r_buf_rpos_p rpos __unused,
    mpeg2_ts_hdr_p ts_hdr, uint8_t *buf_pos,
    mpeg2_ts_psi_tbl_p *psi_tbl_ret, mpeg2_ts_psi_tbl_sec_p *psi_sect_ret) {
	int error;
	size_t i, tm, sec_size, data_size;
	uint8_t *buf_end;
	/* PID payload analize. */
	mpeg2_psi_tbl_hdr_p tbl_hdr;
	mpeg2_psi_tbl_sntx_p tbl_sntx = NULL;
	mpeg2_ts_psi_tbl_p psi_tbl;
	mpeg2_ts_psi_tbl_sec_p psi_sect;


	(*psi_tbl_ret) = NULL;
	(*psi_sect_ret) = NULL;

	buf_end = (((uint8_t*)ts_hdr) + m2ts->mpeg2_ts_pkt_size);
	if (0 != ts_hdr->pus) { /* pointer_field: table section start. */
		/* Skip packet alignment padding bytes before
		 * the start of tabled payload data. */
		buf_pos += ((*buf_pos) + 1); /* Move pointer */
		if (buf_pos > buf_end) { /* Out of range. */
			ts_hdr->te = 1; /* Mark packet as bad. */
			ts_pid->data_errors ++;
			LOGD_EV_FMT("Out of range.");
			return (EINVAL);
		}
		data_size = (size_t)(buf_end - buf_pos);
		/* Packet formal checks. */
		tbl_hdr = (mpeg2_psi_tbl_hdr_p)buf_pos;
		if (0 != tbl_hdr->ss) { /* Table has a syntax part. */
			tbl_sntx = (mpeg2_psi_tbl_sntx_p)(tbl_hdr + 1);
			if (0 == tbl_sntx->cn) /* XXX: Next table version, skip. */
				return (0);
			if (tbl_sntx->sn > tbl_sntx->lsn) { /* Is table section num valid? */
				ts_hdr->te = 1; /* Mark packet as bad. */
				ts_pid->data_errors ++;
				LOGD_EV_FMT("Out of range: sn > lsn");
				return (EINVAL);
			}
		}
		sec_size = (sizeof(mpeg2_psi_tbl_hdr_t) + MPEG2_PSI_TBL_SEC_LEN(tbl_hdr));
		if ((0 != tbl_hdr->pr && sec_size > 1024) ||
		    (0 == tbl_hdr->pr && sec_size > 4096) ||
		    (0 != tbl_hdr->ss && (sizeof(mpeg2_psi_tbl_hdr_t) +
		    sizeof(mpeg2_psi_tbl_sntx_t)) > sec_size)) { /* Out of range. */
			ts_hdr->te = 1; /* Mark packet as bad. */
			ts_pid->data_errors ++;
			LOGD_EV_FMT("Out of range: TBL_SEC_LEN = %zu", sec_size);
			return (EINVAL);
		}
		psi_tbl = mpeg2_ts_pid_psi_tbl_get(ts_pid, tbl_hdr->tid,
		    ((NULL != tbl_sntx) ? tbl_sntx->tid_ext : 0xffff));
		if (NULL != psi_tbl) { /* Table already known. */
			if (0 != psi_tbl->done)
				return (0);
			/* Is table updated/changed? */
			tm = MIN(sec_size, data_size);
			if (NULL != tbl_sntx) {
				if (psi_tbl->ver == tbl_sntx->ver &&
				    (psi_tbl->sects_cnt >= tbl_sntx->sn &&
				    NULL != psi_tbl->sects &&
				    0 == memcmp(psi_tbl->sects[tbl_sntx->sn].data, tbl_hdr, tm)))
					return (0);
				if (psi_tbl->ver != tbl_sntx->ver && NULL != psi_tbl->sects) {
					/* Reset all sections. */
					for (i = 0; i < psi_tbl->sects_cnt; i ++) {
						psi_tbl->sects[i].done = 0;
						psi_tbl->sects[i].data_w_off = 0;
						psi_tbl->sects[i].data_size = 0;
					}
				}
			} else {
				if (psi_tbl->sects_cnt == 1 &&
				    NULL != psi_tbl->sects &&
				    0 == memcmp(psi_tbl->sects[0].data, tbl_hdr, tm))
					return (0);
				if (NULL != psi_tbl->sects) {
					/* Reset section. */
					psi_tbl->sects[0].done = 0;
					psi_tbl->sects[0].data_w_off = 0;
					psi_tbl->sects[0].data_size = 0;
				}
			}
		} else {
			/* XXX: Check table ID before add. */
			if (0 == mpeg2_ts_psi_tbl_chk_by_pid(ts_pid->pid,
			    m2ts->nit.pid, ((NULL != prog) ? prog->pmt.pid : 0),
			    tbl_hdr->tid)) {
				ts_hdr->te = 1; /* Mark packet as bad. */
				ts_pid->data_errors ++;
				LOGD_EV_FMT("This type of PID must not contain this TID");
#if 1
				M2TS_DUMP_MPEG2TS_HDR(ts_hdr);
				M2TS_DUMP_MPEG2TS_PSI_HDR(tbl_hdr);
				if (NULL != tbl_sntx) {
					M2TS_DUMP_MPEG2TS_PSI_SNTX(tbl_sntx);
				}
#endif
				return (EINVAL);
			}
			error = mpeg2_ts_pid_psi_tbl_add(ts_pid, tbl_hdr->tid,
			    ((NULL != tbl_sntx) ? tbl_sntx->tid_ext : 0xffff),
			    &psi_tbl);
			if (0 != error)
				return (error);
		}
		/* Update table. */
		psi_tbl->sect_syntax = tbl_hdr->ss;
		psi_tbl->done = 0;
		if (NULL != tbl_sntx) {
			psi_tbl->ver = tbl_sntx->ver;
			tm = (tbl_sntx->lsn + 1);
		} else {
			tm = 1;
		}
		if (psi_tbl->sects_cnt != tm || NULL == psi_tbl->sects) {
			psi_sect = reallocarray(psi_tbl->sects, tm,
			    sizeof(mpeg2_ts_psi_tbl_sec_t));
			if (NULL == psi_sect)
				return (ENOMEM);
			psi_tbl->sects_cnt = tm;
			psi_tbl->sects = psi_sect;
			/* Reset all sections. */
			for (i = 0; i < psi_tbl->sects_cnt; i ++) {
				psi_tbl->sects[i].done = 0;
				psi_tbl->sects[i].data_w_off = 0;
				psi_tbl->sects[i].data_size = 0;
			}
		}

		/* Start section update. */
		psi_sect = &psi_tbl->sects[((NULL != tbl_sntx) ? tbl_sntx->sn : 0)];
		psi_sect->done = 0;
		psi_sect->data_w_off = 0;
		psi_sect->data_size = (uint16_t)sec_size; /* No owerflow, size checked. */
		/* Shedule: receive other section segments. */
		ts_pid->psi_tbl_last = psi_tbl;
		ts_pid->psi_sect_last = psi_sect;
	} else { /* Table section data part. */
		psi_tbl = ts_pid->psi_tbl_last;
		psi_sect = ts_pid->psi_sect_last;
		if (NULL == psi_tbl || NULL == psi_sect)
			return (0);
		if (0 != cc_incorrect) { /* Lost part of table section. */
			psi_sect->data_w_off = 0;
			ts_pid->psi_tbl_last = NULL;
			ts_pid->psi_sect_last = NULL;
			return (0);
		}
		if (0 != psi_sect->done)
			return (0); /* XXX: here we also can check and restore corrupted data. */
		tbl_hdr = (mpeg2_psi_tbl_hdr_p)buf_pos;
		tbl_sntx = (mpeg2_psi_tbl_sntx_p)(tbl_hdr + 1);
		data_size = (size_t)(buf_end - buf_pos);
	}

	/* Store new table section data in persisten buffer. */
	tm = MIN(((size_t)(psi_sect->data_size - psi_sect->data_w_off)), data_size);
	memcpy(&psi_sect->data[psi_sect->data_w_off], buf_pos, tm);
	psi_sect->data_w_off += tm;
	if (psi_sect->data_size > psi_sect->data_w_off) /* Is full section stored? */
		return (0);
	/* Section reassembled, check it. */
	ts_pid->psi_tbl_last = NULL;
	ts_pid->psi_sect_last = NULL;
	/* CRC32 check. */
	if (0 != crc32_be((uint8_t*)psi_sect->data, psi_sect->data_size)) {
		psi_sect->done = 0;
		psi_sect->data_w_off = 0;
		ts_hdr->te = 1; /* Mark packet as bad. */
		ts_pid->crc_errors ++;
		LOGD_EV_FMT("CRC32 = %"PRIu32"", crc32_be((uint8_t*)psi_sect->data, psi_sect->data_size));
#if 1
		M2TS_DUMP_MPEG2TS_HDR(ts_hdr);
		M2TS_DUMP_MPEG2TS_PSI_HDR(tbl_hdr);
		if (NULL != tbl_sntx) {
			M2TS_DUMP_MPEG2TS_PSI_SNTX(tbl_sntx);
		}
#endif
		return (EINVAL);
	}
	/* Full section received and stored. */
	psi_sect->done = 1;
	for (i = 0, tm = 0; i < psi_tbl->sects_cnt; i ++) {
		if (0 != psi_tbl->sects[i].done) {
			tm ++;
		}
	}
	if (tm == psi_tbl->sects_cnt) {
		psi_tbl->done = 1;
	}

	(*psi_tbl_ret) = psi_tbl;
	(*psi_sect_ret) = psi_sect;

	return (0);
}



int
mpeg2_ts_psi_analize(mpeg2_ts_data_p m2ts, mpeg2_ts_prog_p prog,
    mpeg2_ts_pid_p ts_pid, int cc_incorrect, r_buf_rpos_p rpos,
    mpeg2_ts_hdr_p ts_hdr, uint8_t *buf_pos) {
	int error;
	uint16_t tm16;
	size_t i, tm;
	uint8_t *pos_max;
	mpeg2_psi_tbl_hdr_p tbl_hdr;
	mpeg2_psi_tbl_sntx_p tbl_sntx;
	mpeg2_ts_psi_tbl_p psi_tbl;
	mpeg2_ts_psi_tbl_sec_p psi_sect;
	/* PID payload analize. */
	mpeg2_psi_pat_sntx_p pat_sntx;
	mpeg2_psi_pat_sec_p pat_sec;
	mpeg2_psi_pmt_sntx_p pmt_sntx;
	mpeg2_psi_pmt_sec_p pmt_sec;
	mpeg2_psi_sdt_sntx_p sdt_sntx;
	mpeg2_psi_sdt_sec_p sdt_sec;
	uint8_t str[1024];


	error = mpeg2_ts_psi_tbl_reassemble(m2ts, prog, ts_pid, cc_incorrect,
	    rpos, ts_hdr, buf_pos, &psi_tbl, &psi_sect);
	if (0 != error) {
		return (error);
	}
	if (NULL == psi_tbl || NULL == psi_sect)
		return (0);

	switch (ts_pid->pid) {
	case MPEG2_TS_PID_PAT: /* Program Association Table. */
		m2ts->prog_cnt = 0;
		for (i = 0; i < psi_tbl->sects_cnt; i ++) {
			psi_sect = &psi_tbl->sects[i];
			tbl_hdr = (mpeg2_psi_tbl_hdr_p)psi_sect->data;
			tbl_sntx = (mpeg2_psi_tbl_sntx_p)(tbl_hdr + 1);

			if (0 == MPEG2_PSI_IS_PAT_HDR(tbl_hdr)) {
				ts_hdr->te = 1; /* Mark packet as bad. */
				ts_pid->data_errors ++;
				M2TS_DUMP_MPEG2TS_PSI_HDR(tbl_hdr);
				return (EINVAL);
			}
			pat_sntx = (mpeg2_psi_pat_sntx_p)tbl_sntx;
#if 1
			M2TS_DUMP_MPEG2TS_HDR(ts_hdr);
			M2TS_DUMP_MPEG2TS_PSI_HDR(tbl_hdr);
			M2TS_DUMP_MPEG2TS_PSI_SNTX(tbl_sntx);
#endif
			/* Add/update all programms. */
			tm = ((psi_sect->data_size - (sizeof(mpeg2_psi_tbl_hdr_t) +
			    sizeof(mpeg2_psi_pat_sntx_t) + sizeof(uint32_t)))); /* CRC32 */
			pat_sec = (mpeg2_psi_pat_sec_p)(pat_sntx + 1);
			pos_max = (((uint8_t*)pat_sec) + tm);
			error = mpeg2_ts_data_progs_realloc(m2ts, (m2ts->prog_cnt +
			    (tm / sizeof(mpeg2_psi_pat_sec_t))));
			if (0 != error) {
				LOG_ERR(error, "mpeg2_ts_data_progs_realloc()");
				return (ENOMEM);
			}
			for (; (uint8_t*)pat_sec < pos_max; pat_sec ++) {
				tm16 = MPEG2_PSI_PAT_SEC_PID(pat_sec);
				LOGD_EV_FMT("%zu: prog = %"PRIu16", PID = %"PRIu16", r0 = %hhi",
				    m2ts->prog_cnt, ntohs(pat_sec->pn), tm16, pat_sec->r0);//*/
				if (0 == pat_sec->pn) {
					/* Network Information Table:
					 * Owervrite default PID value. */
					m2ts->nit.pid = tm16;
				} else {
					m2ts->progs[m2ts->prog_cnt].pn = pat_sec->pn;
					m2ts->progs[m2ts->prog_cnt].pmt.pid = tm16;
					m2ts->progs[m2ts->prog_cnt].pmt.seg_cnt = 0;
					m2ts->progs[m2ts->prog_cnt].pmt.psi_tbls_cnt = 0;
					m2ts->progs[m2ts->prog_cnt].pids_cnt = 0;
					m2ts->prog_cnt ++;
				}
			}
		} /* for(...) */
		mpeg2_ts_pid_psi_serialize(m2ts, ts_pid);
		break;
	case MPEG2_TS_PID_CAT: /* Conditional Access Table. */
		//LOGD_EV_FMT("CAT...");
		mpeg2_ts_pid_psi_serialize(m2ts, ts_pid);
		break;
	case MPEG2_TS_PID_TSDT: /* Transport Stream Description Table. */
		break;
	case MPEG2_TS_PID_IPMPCIT: /* IPMP Control Information Table. */
		break;
	case MPEG2_TS_PID_SDT: /* Service Description Table. */
		for (i = 0; i < psi_tbl->sects_cnt; i ++) {
			psi_sect = &psi_tbl->sects[i];
			tbl_hdr = (mpeg2_psi_tbl_hdr_p)psi_sect->data;
			tbl_sntx = (mpeg2_psi_tbl_sntx_p)(tbl_hdr + 1);

			if (0 == MPEG2_PSI_IS_SDT_HDR(tbl_hdr)) {
				ts_hdr->te = 1; /* Mark packet as bad. */
				ts_pid->data_errors ++;
				M2TS_DUMP_MPEG2TS_PSI_HDR(tbl_hdr);
				return (EINVAL);
			}
			sdt_sntx = (mpeg2_psi_sdt_sntx_p)tbl_sntx;
			sdt_sec = (mpeg2_psi_sdt_sec_p)(sdt_sntx + 1);
#if 0
			M2TS_DUMP_MPEG2TS_HDR(ts_hdr);
			M2TS_DUMP_MPEG2TS_PSI_HDR(tbl_hdr)
			LOGD_EV_FMT("transport_stream_id = %i, r0 = %hhi, ver = %hhi, cn = %hhi, sn = %hhi, lsn = %hhi, onid = %i, r1 = %hhi",
			    sdt_sntx->tsid,
			    sdt_sntx->r0, sdt_sntx->ver, sdt_sntx->cn,
			    sdt_sntx->sn, sdt_sntx->lsn, sdt_sntx->onid, sdt_sntx->r1);
#endif
			tm = ((psi_sect->data_size - (sizeof(mpeg2_psi_tbl_hdr_t) +
			    sizeof(mpeg2_psi_pmt_sntx_t) + sizeof(uint32_t)))); /* CRC32 */
			pos_max = (((uint8_t*)sdt_sec) + tm);
			for (; ((uint8_t*)sdt_sec) < pos_max;) {
				tm = MPEG2_PSI_SDT_SEC_DESCRS_LEN(sdt_sec);
				LOGD_EV_FMT("sid = %"PRIu16", r0 = %hhi, eit_shed = %hhi, eit_pf = %hhi, rstatus = %hhi, free_ca = %hhi, descrs_len = %zu",
				    sdt_sec->sid, sdt_sec->r0, sdt_sec->eit_shed, sdt_sec->eit_pf, sdt_sec->rstatus, sdt_sec->free_ca, tm);
				mpeg2_ts_descriptors_dump((uint8_t*)(sdt_sec + 1), tm,
				    str, sizeof(str), NULL);
				LOGD_EV_FMT("Service Description descriptors:\r\n%s", str);

				sdt_sec = (mpeg2_psi_sdt_sec_p)
				    (((uint8_t*)(sdt_sec + 1)) + tm);
			}
		}
		break;
	case MPEG2_TS_PID_EIT: /* Event Information Table. */
		//MPEG2_PSI_IS_EIT_HDR(hdr)
		mpeg2_ts_pid_psi_serialize(m2ts, ts_pid);
		break;
	default:
		if (ts_pid->pid == m2ts->nit.pid) {
			LOGD_EV_FMT("NIT: PID = %"PRIu32"", ts_pid->pid);
		} else if (NULL != prog && ts_pid->pid == prog->pmt.pid) {
			prog->pids_cnt = 0;
			for (i = 0; i < psi_tbl->sects_cnt; i ++) {
				psi_sect = &psi_tbl->sects[i];
				tbl_hdr = (mpeg2_psi_tbl_hdr_p)psi_sect->data;
				tbl_sntx = (mpeg2_psi_tbl_sntx_p)(tbl_hdr + 1);

				if (0 == MPEG2_PSI_IS_PMT_HDR(tbl_hdr)) {
					ts_hdr->te = 1; /* Mark packet as bad. */
					ts_pid->data_errors ++;
					M2TS_DUMP_MPEG2TS_PSI_HDR(tbl_hdr);
					return (EINVAL);
				}
				LOGD_EV_FMT("PMT: PID = %"PRIu32"", ts_pid->pid);
				pmt_sntx = (mpeg2_psi_pmt_sntx_p)tbl_sntx;
#if 0
				M2TS_DUMP_MPEG2TS_HDR(ts_hdr);
				M2TS_DUMP_MPEG2TS_PSI_HDR(tbl_hdr)
				LOGD_EV_FMT("pnum = %i, r0 = %hhi, ver = %hhi, cn = %hhi, sn = %hhi, lsn = %hhi, r1 = %hhi, PCR_PID = %i, r2 = %hhi, info len = %i",
				    pmt_sntx->pnum,
				    pmt_sntx->r0, pmt_sntx->ver, pmt_sntx->cn,
				    pmt_sntx->sn, pmt_sntx->lsn, pmt_sntx->r1,
				    MPEG2_PSI_PMT_PCR_PID(pmt_sntx), pmt_sntx->r2,
				    MPEG2_PSI_PMT_P_INFO_LEN(pmt_sntx));
#endif
				tm = MPEG2_PSI_PMT_P_INFO_LEN(pmt_sntx);
				mpeg2_ts_descriptors_dump((uint8_t*)(pmt_sntx + 1), tm,
				    str, sizeof(str), NULL);
				LOGD_EV_FMT("program_info: size %zu\r\n%s", tm, str);

				/* Add/update all PIDs. */
				pmt_sec = (mpeg2_psi_pmt_sec_p)(((uint8_t*)(pmt_sntx + 1)) + tm);
				tm = ((psi_sect->data_size -
				    (sizeof(mpeg2_psi_tbl_hdr_t) +
				    sizeof(mpeg2_psi_pmt_sntx_t) +
				    MPEG2_PSI_PMT_P_INFO_LEN(pmt_sntx) +
				    sizeof(uint32_t)))); /* CRC32 */
				error = realloc_items((void**)&prog->pids, sizeof(uint16_t),
				    &prog->pids_allocated, STR_M2TS_PID_ALLOC_CNT,
				    (prog->pids_cnt + (tm / sizeof(mpeg2_psi_pmt_sec_t))));
				if (0 != error) {
					LOG_ERR(error, "realloc_items(prog->pids)");
					return (ENOMEM);
				}
				pos_max = (((uint8_t*)pmt_sec) + tm);
				for (; ((uint8_t*)pmt_sec) < pos_max; prog->pids_cnt ++) {
					tm16 = MPEG2_PSI_PMT_SEC_EPID(pmt_sec);
					prog->pids[prog->pids_cnt] = tm16;
					error = mpeg2_ts_data_pids_add(m2ts, tm16);
					if (0 != error) {
						LOG_ERR(error, "mpeg2_ts_data_pids_add()");
						//return (ENOMEM);
					}

					tm = MPEG2_PSI_PMT_SEC_ES_INFO_LEN(pmt_sec);
					LOGD_EV_FMT("%zu: s_type = %"PRIu16", EPID = %"PRIu16", r0 = %hhi, r1 = %hhi, es info len = %zu",
					    prog->pids_cnt, pmt_sec->s_type, tm16, pmt_sec->r0, pmt_sec->r1, tm);
					mpeg2_ts_descriptors_dump((uint8_t*)(pmt_sec + 1), tm,
					    str, sizeof(str), NULL);
					LOGD_EV_FMT("Elementary stream descriptors:\r\n%s", str);

					pmt_sec = (mpeg2_psi_pmt_sec_p)
					    (((uint8_t*)(pmt_sec + 1)) + tm);
				}
			}
			mpeg2_ts_data_pids_cleanup(m2ts);
			mpeg2_ts_pid_psi_serialize(m2ts, ts_pid);
		} else {
			LOGD_EV_FMT("XXXX WTF!?");
		}
		break;
	} /* switch (pid) */

	return (0);
}



int
mpeg2_ts_pid_psi_serialize(mpeg2_ts_data_p m2ts, mpeg2_ts_pid_p ts_pid) {
	uint8_t cc;
	size_t i, j, buf_size, tm;
	mpeg2_ts_hdr_p ts_hdr;
	mpeg2_ts_psi_tbl_p tbl;
	mpeg2_ts_psi_tbl_sec_p sect;

	if (NULL == ts_pid)
		return (EINVAL);
	if (NULL == ts_pid->psi_tbls || 0 == ts_pid->psi_tbls_cnt)
		return (0);

	/* Calculate buf size. */
	buf_size = m2ts->mpeg2_ts_pkt_size; /* Additional space. */
	for (i = 0; i < ts_pid->psi_tbls_cnt; i ++) {
		tbl = &ts_pid->psi_tbls[i];
		if (NULL == tbl->sects)
			continue;
		for (j = 0; j < tbl->sects_cnt; j ++) {
			sect = &tbl->sects[j];
			if (0 == sect->done)
				continue;
			mpeg2_ts_serialize_calc_size(0, 1, sect->data_size,
			    m2ts->mpeg2_ts_pkt_size, &tm, NULL);
			buf_size += tm;
		}
	}

	//LOGD_EV_FMT("PID = %"PRIu32": realloc(%zu, %zu)", ts_pid->pid, ts_pid->ts_psi_packets, buf_size);
	ts_hdr = realloc(ts_pid->ts_psi_packets, buf_size);
	if (NULL == ts_hdr)
		return (ENOMEM);
	ts_pid->ts_psi_packets = (uint8_t*)ts_hdr;
	ts_pid->ts_psi_packets_size = 0;
	cc = 0;

	for (i = 0; i < ts_pid->psi_tbls_cnt; i ++) {
		tbl = &ts_pid->psi_tbls[i];
		if (NULL == tbl->sects)
			continue;
		for (j = 0; j < tbl->sects_cnt; j ++) {
			sect = &tbl->sects[j];
			if (0 == sect->done)
				continue;
			mpeg2_ts_serialize_data(ts_pid->pid, ts_pid->sc, cc, NULL,
			    0, 1, sect->data, sect->data_size, m2ts->mpeg2_ts_pkt_size,
			    (ts_pid->ts_psi_packets + ts_pid->ts_psi_packets_size),
			    (buf_size - ts_pid->ts_psi_packets_size), &tm, NULL, &cc);
			ts_pid->ts_psi_packets_size += tm;
		}
	}
	//LOGD_EV_FMT("PID = %"PRIu32": size = %zu)", ts_pid->pid, ts_pid->ts_psi_packets_size);
	return (0);
}



int
mpeg2_ts_key_frames_idx_add(mpeg2_ts_data_p m2ts, struct timespec *ts,
    r_buf_p r_buf, r_buf_rpos_p rpos) {
	int error;
	size_t i, allocated;

	if (NULL == m2ts || NULL == r_buf || NULL == rpos)
		return (EINVAL);
	allocated = m2ts->key_frames_allocated;
	error = realloc_items((void**)&m2ts->key_frames_rpos, sizeof(r_buf_rpos_t),
	    &allocated, STR_M2TS_KEY_FRAME_IDX_ALLOC_CNT, m2ts->key_frames_cnt);
	if (0 != error)
		return (error);
	allocated = m2ts->key_frames_allocated;
	error = realloc_items((void**)&m2ts->key_frames_time, sizeof(time_t),
	    &allocated, STR_M2TS_KEY_FRAME_IDX_ALLOC_CNT, m2ts->key_frames_cnt);
	if (0 != error)
		return (error);
	m2ts->key_frames_allocated = allocated;
	/* Remove old. */
	for (i = 0; i < m2ts->key_frames_cnt; i ++) {
		if (0 != r_buf_rpos_check_fast(r_buf, &m2ts->key_frames_rpos[i]))
			break;
	}
	if (0 != i) {
		memmove(m2ts->key_frames_rpos, &m2ts->key_frames_rpos[i],
		    (m2ts->key_frames_cnt - i) * sizeof(r_buf_rpos_t));
		m2ts->key_frames_cnt -= i;
	}
	/* Add new. */
	m2ts->key_frames_rpos[m2ts->key_frames_cnt] = (*rpos); /* memcpy */
	m2ts->key_frames_time[m2ts->key_frames_cnt] = ts->tv_sec;
	m2ts->key_frames_cnt ++;

	return (0);
}






size_t
mpeg2_ts_pkt_analize(mpeg2_ts_data_p m2ts, r_buf_p r_buf, struct timespec *ts,
    uint8_t *buf, size_t buf_size, int *pkt_added) {
	int error, cc_incorrect = 0, is_psi = 0;
	uint16_t pid;
	size_t i, error_count = 0;
	r_buf_rpos_t rpos;
	uint8_t *buf_pos;
	mpeg2_ts_pids_flt_p pids_flt = &m2ts->s.pids_flt;
	mpeg2_ts_pid_p ts_pid;
	mpeg2_ts_prog_p prog = NULL;
	mpeg2_ts_hdr_p ts_hdr;
	mpeg2_ts_adapt_field_p af = NULL;
	mpeg2_pes_hdr_p pes_hdr;


	ts_hdr = (mpeg2_ts_hdr_p)buf;
	buf_pos = (buf + sizeof(mpeg2_ts_hdr_t));
	/* Check packet. */
	if (m2ts->mpeg2_ts_pkt_size > buf_size ||
	    0 == MPEG2_TS_HDR_IS_VALID(ts_hdr)) {
		error_count ++;
		LOGD_EV_FMT("Invalid TS packet");
		M2TS_DUMP_MPEG2TS_HDR(ts_hdr);
		m2ts->dropped_count ++;
		return (error_count);
	}

	/* Preprocess and filtering. */
	//M2TS_DUMP_MPEG2TS_HDR(ts_hdr);
	pid = MPEG2_TS_PID(ts_hdr);
	if (MPEG2_TS_PID_NULL == pid) { /* NULL PID. */
		LOGD_EV_FMT("NULL PID found.");
		m2ts->null_pid_count ++;
		if (0 != pids_flt->pid_null) 
			return (error_count);
		ts_pid = NULL; /* No process, only add to ring buf. */
	} else { /* Non NULL PID. */
		ts_pid = mpeg2_ts_data_get_pid(m2ts, pid, &is_psi, &prog);
		if (NULL == ts_pid) { /* Unknown PIDs. */
			//LOGD_EV_FMT("Skip unknown and PID = %i", pid);
			m2ts->unknown_pid_count ++;
			if (0 != pids_flt->pid_unknown)
				return (error_count);
		} else { /* Filter packets by PID. */
			if (0 != pids_flt->pid_nit &&
			    m2ts->nit.pid == pid) /* Drop NIT packet. */
				return (error_count);
			for (i = 0; i < pids_flt->pids_count; i ++) {
				if (pids_flt->pids[i] == pid)
					return (error_count);
			}
		}
	}

	/* Add packet to ring buf. */
	if (NULL != r_buf) {
		error = r_buf_wbuf_set2(r_buf, (uint8_t*)ts_hdr,
		    m2ts->mpeg2_ts_pkt_size, &rpos);
		if (0 != error) {
			LOG_ERR(error, "r_buf_wbuf_set2()");
			return (error_count);
		}
		if (NULL != pkt_added) {
			(*pkt_added) = 1;
		}
	}

	if (NULL == ts_pid) /* Do not process packet. */
		return (error_count);


	/* CC check. */
	if (ts_pid->pid != pid) { /* First time fix. */
		ts_pid->pid = pid;
		ts_pid->cc = ts_hdr->cc;
	} else if (0 != ts_hdr->cp) {
		ts_pid->cc = MPEG2_TS_CC_GET_NEXT(ts_pid->cc);
		if (ts_pid->cc != ts_hdr->cc) {
			ts_pid->cc_errors ++;
			error_count ++;
			cc_incorrect = 1;
		} else {
			cc_incorrect = 0;
		}
		ts_pid->cc = ts_hdr->cc;
	}
	/* Update PID stat. */
	ts_pid->sc = ts_hdr->sc;
	ts_pid->pkt_count ++;
	if (0 != ts_hdr->te) { /* Skip bad packets analize. */
		ts_pid->te_count ++;
		error_count ++;
		return (error_count); /* No drop, keep CC sequence. */
	}

	if (0 != ts_hdr->pus) { /* Payload Unit Start: remember index */
		mpeg2_ts_pid_idx_add(ts_pid, r_buf, &rpos);
	}

	if (0 != ts_hdr->afe) { /* Adapt feild. */
		af = (mpeg2_ts_adapt_field_p)buf_pos;
		if ((af->len > (m2ts->mpeg2_ts_pkt_size - 6) && 0 != ts_hdr->cp) ||
		    (af->len > (m2ts->mpeg2_ts_pkt_size - 5) && 0 == ts_hdr->cp)) {
			ts_hdr->te = 1; /* Mark packet as bad. */
			ts_pid->data_errors ++;
			error_count ++;
			LOGD_EV_FMT("Out of range.");
			return (error_count);
		}
		buf_pos += (1 + af->len); /* Move pointer */
		
	}
	/* End of Transport stream packet headers. */

	/* PSI: Program specific information processing. */
	if (0 != is_psi) {
		if (0 != mpeg2_ts_psi_analize(m2ts, prog, ts_pid,
		    cc_incorrect, &rpos, ts_hdr, buf_pos)) {
			error_count ++;
		}
		return (error_count);
	}

	/* PES */
	//uint8_t str[1024];
	if (0 != ts_hdr->pus) {
		pes_hdr = (mpeg2_pes_hdr_p)buf_pos;
		if (NULL != af && 0 != af->rai &&
		    MPEG2_PES_SID_IS_VIDEO(pes_hdr->sid)) { /* Possible Key frame start! */
			mpeg2_ts_key_frames_idx_add(m2ts, ts, r_buf, &rpos);
		}
#if 0
		//M2TS_DUMP_MPEG2TS_HDR(ts_hdr);
		//M2TS_DUMP_MPEG2TS_PES_HDR(pes_hdr);
		if (0 == MPEG2_TS_PES_IS_VALID(pes_hdr)) {
			LOGD_EV_FMT("pes_hdr - PSCP invalid = %x!!!, key framre: %i",
			    pes_hdr->pscp, ((NULL != af && 0 != af->rai) ? 1 : 0));
		}
		if (MPEG2_PES_SID_IS_AUDIO(pes_hdr->sid)) {
			LOGD_EV_FMT("pes_hdr - AUDIO, key framre: %i",
			    ((NULL != af && 0 != af->rai) ? 1 : 0));
		} else if (MPEG2_PES_SID_IS_VIDEO(pes_hdr->sid)) {
			LOGD_EV_FMT("pes_hdr - VIDEO");
		} else {
			LOGD_EV_FMT("pes_hdr - sid = %i, key framre: %i",
			    pes_hdr->sid, ((NULL != af && 0 != af->rai) ? 1 : 0));
		}
#endif
	}

	return (error_count);
}



int
mpeg2_ts_txt_dump_pid(mpeg2_ts_data_p m2ts, mpeg2_ts_pid_p pid,
    uint8_t *buf, size_t buf_size, size_t *buf_size_ret) {
	size_t size_ret;

	if (NULL == pid || NULL == buf || 0 == buf_size)
		return (EINVAL);
	
	size_ret = (size_t)snprintf((char*)buf, buf_size,
	    "	    PID: %"PRIu16
	    " [Packets: %"PRIu64", Size: %"PRIu64", Scrambling: %"PRIu8
	    ", TE count: %"PRIu64", CC errors: %"PRIu64
	    ", CRC32 errors: %"PRIu64", Data errors: %"PRIu64"]\r\n",
	    pid->pid,
	    pid->pkt_count, (pid->pkt_count * m2ts->mpeg2_ts_pkt_size), pid->sc,
	    pid->te_count, pid->cc_errors,
	    pid->crc_errors, pid->data_errors);

#if 0 /* Dump pid iov indexes from ring buf. */
	size_t i;

	size_ret += snprintf((char*)(buf + size_ret), (buf_size - size_ret),
	    "	    PID: %"PRIu16
	    " [seg_cnt: %zu]\r\n",
	    pid->pid, pid->seg_cnt);
	for (i = 0; i < pid->seg_cnt; i ++) {
		size_ret += snprintf((char*)(buf + size_ret), (buf_size - size_ret),
		    "%zu: %zu; ", i, pid->seg_rpos[i].iov_index);
	}
	size_ret += snprintf((char*)(buf + size_ret), (buf_size - size_ret), "\r\n");
#endif
#if 0 /* Dump pid tables and sections. */
	size_t i, j;
	mpeg2_ts_psi_tbl_p psi_tbls;
	mpeg2_ts_psi_tbl_sec_p psi_sect;

	size_ret += snprintf((char*)(buf + size_ret), (buf_size - size_ret),
	    "		[tbls_cnt: %zu, tbls_allocated: %zu]\r\n",
	    pid->psi_tbls_cnt, pid->psi_tbls_allocated);
	psi_tbls = pid->psi_tbls;
	for (i = 0; i < pid->psi_tbls_cnt; i ++) {
		size_ret += snprintf((char*)(buf + size_ret), (buf_size - size_ret),
		    "		Table: %zu [tid: %"PRIu8", tid_ext: %"PRIu16", ver: %"PRIu8", section syntax: %"PRIu8", done: %"PRIu8", sects_cnt: %zu]\r\n",
		    i, psi_tbls[i].tid, ntohs(psi_tbls[i].tid_ext), psi_tbls[i].ver, psi_tbls[i].sect_syntax, psi_tbls[i].done, psi_tbls[i].sects_cnt);
		if (NULL == psi_tbls[i].sects)
			continue;
		for (j = 0; j < psi_tbls[i].sects_cnt; j ++) {
			psi_sect = &psi_tbls[i].sects[j];
			size_ret += snprintf((char*)(buf + size_ret), (buf_size - size_ret),
			    "			Table section: %zu [done: %"PRIu8", data_w_off: %"PRIu16", data_size: %"PRIu16"]\r\n",
			    j, psi_sect->done, psi_sect->data_w_off, psi_sect->data_size);
		
		}
	}
	size_ret += snprintf((char*)(buf + size_ret), (buf_size - size_ret), "\r\n");
#endif
	
	if (NULL != buf_size_ret) {
		(*buf_size_ret) = size_ret;
	}
	return (0);
}

int
mpeg2_ts_txt_dump_prog(mpeg2_ts_data_p m2ts, mpeg2_ts_prog_p prog, uint8_t *buf, size_t buf_size,
    size_t *buf_size_ret) {
	size_t size_ret = 0, tm = 0, i;
	mpeg2_ts_pid_p ts_pid;

	if (NULL == prog || NULL == buf || 0 == buf_size)
		return (EINVAL);
	
	size_ret = (size_t)snprintf((char*)buf, buf_size,
	    "	Programm: %"PRIu32" [PID: %"PRIu16", Data PIDs count: %zu]\r\n",
	    ntohs(prog->pn), prog->pmt.pid, prog->pids_cnt);
	if (0 != prog->pmt.pkt_count &&
	    0 == mpeg2_ts_txt_dump_pid(m2ts, &prog->pmt,
	    (buf + size_ret), (buf_size - size_ret), &tm))
		size_ret += tm;
	for (i = 0; i < prog->pids_cnt; i ++) {
		ts_pid = mpeg2_ts_data_get_pid(m2ts, prog->pids[i], NULL, NULL);
		if (NULL == ts_pid) {
			size_ret += (size_t)snprintf((char*)(buf + size_ret), (buf_size - size_ret),
			    "	    PID: %"PRIu16"\r\n",
			    prog->pids[i]);
		} else if (0 != ts_pid->pkt_count &&
		    0 == mpeg2_ts_txt_dump_pid(m2ts, ts_pid,
		    (buf + size_ret), (buf_size - size_ret), &tm)) {
			size_ret += tm;
		}
	}
	
	if (NULL != buf_size_ret) {
		(*buf_size_ret) = size_ret;
	}
	return (0);
}

int
mpeg2_ts_txt_dump(mpeg2_ts_data_p m2ts, uint8_t *buf, size_t buf_size,
    size_t *buf_size_ret) {
	size_t size_ret = 0, tm = 0, i;

	if (NULL == m2ts || NULL == buf || 0 == buf_size)
		return (EINVAL);

	if (0 != m2ts->null_pid_count ||
	    0 != m2ts->dropped_count ||
	    0 != m2ts->key_frames_cnt) {
		size_ret += (size_t)snprintf((char*)(buf + size_ret), (buf_size - size_ret),
		   "	null pid count: %zu, dropped count: %zu, key frames count: %zu\r\n",
		    m2ts->null_pid_count, m2ts->dropped_count, m2ts->key_frames_cnt);
	}
	if (0 != m2ts->pat.pkt_count && 0 == mpeg2_ts_txt_dump_pid(m2ts, &m2ts->pat,
	    (buf + size_ret), (buf_size - size_ret), &tm)) {
		size_ret += tm;
	}
	if (0 != m2ts->cat.pkt_count && 0 == mpeg2_ts_txt_dump_pid(m2ts, &m2ts->cat,
	    (buf + size_ret), (buf_size - size_ret), &tm)) {
		size_ret += tm;
	}
	if (0 != m2ts->tsdt.pkt_count && 0 == mpeg2_ts_txt_dump_pid(m2ts, &m2ts->tsdt,
	    (buf + size_ret), (buf_size - size_ret), &tm)) {
		size_ret += tm;
	}
	if (0 != m2ts->ipmpcit.pkt_count && 0 == mpeg2_ts_txt_dump_pid(m2ts, &m2ts->ipmpcit,
	    (buf + size_ret), (buf_size - size_ret), &tm)) {
		size_ret += tm;
	}
	if (0 != m2ts->nit.pkt_count && 0 == mpeg2_ts_txt_dump_pid(m2ts, &m2ts->nit,
	    (buf + size_ret), (buf_size - size_ret), &tm)) {
		size_ret += tm;
	}
	if (0 != m2ts->sdt.pkt_count && 0 == mpeg2_ts_txt_dump_pid(m2ts, &m2ts->sdt,
	    (buf + size_ret), (buf_size - size_ret), &tm)) {
		size_ret += tm;
	}
	if (0 != m2ts->eit.pkt_count && 0 == mpeg2_ts_txt_dump_pid(m2ts, &m2ts->eit,
	    (buf + size_ret), (buf_size - size_ret), &tm)) {
		size_ret += tm;
	}

	/* Programms */
	for (i = 0; i < m2ts->prog_cnt; i ++) {
		if (0 == mpeg2_ts_txt_dump_prog(m2ts, &m2ts->progs[i], (buf + size_ret),
		    (buf_size - size_ret), &tm)) {
			size_ret += tm;
		}
	}
	if (0 != m2ts->data_pids_cnt) {
		size_ret += (size_t)snprintf((char*)(buf + size_ret), (buf_size - size_ret),
		   "	data_pids_cnt: %zu\r\n",
		    m2ts->data_pids_cnt);
	}

	if (NULL != buf_size_ret) {
		(*buf_size_ret) = size_ret;
	}
	return (0);
}
