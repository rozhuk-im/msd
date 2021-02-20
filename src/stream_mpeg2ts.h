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

#ifndef __STREAM_MPEG2TS_H__
#define __STREAM_MPEG2TS_H__

//#include <time.h>
#include "utils/macro.h"
#include "utils/ring_buffer.h"
#include "proto/mpeg2ts.h"

/*
 * - MPEG2-TS
 * -- PSI
 * --- Tables
 * ---- Sections
 * -- PES
 */


typedef struct mpeg2_ts_psi_table_section_s {
	uint8_t		done;		/* Table is received. */
	uint16_t	data_w_off;	/* Data write offset. */
	uint16_t	data_size;	/* Section length */
	uint8_t		data[sizeof(mpeg2_psi_tbl_hdr_t) + MPEG2_PSI_SEC_LEN_PRIV_MAX]; /* Table section data, including PSI header. */
} mpeg2_ts_psi_tbl_sec_t, *mpeg2_ts_psi_tbl_sec_p;

typedef struct mpeg2_ts_psi_table_s {
	uint8_t		tid;		/* Table ID */
	uint8_t		sect_syntax;	/* Table section syntax: 0 = 1 section, 1 = many */
	uint16_t	tid_ext;	/* Table ID extension */
	uint8_t		ver;		/* Table Version number */
	uint8_t		done;		/* Table is received. */
	size_t		sects_cnt;	/* Section number = index in array. */
	mpeg2_ts_psi_tbl_sec_p sects;	/* Array of tables sections. */
} mpeg2_ts_psi_tbl_t, *mpeg2_ts_psi_tbl_p;



typedef struct mpeg2_ts_pid_s {
	uint16_t	pid;		/* PID: 13 bits */
	uint8_t		cc;		/* Continuity number: 4 bits. */
	uint8_t		sc;		/* Scrambling control: 1 bit. */
	size_t		seg_cnt;
	size_t		seg_allocated;
	r_buf_rpos_p	seg_rpos;	/* Array index to ts packets with: pus = 1. */
	size_t		psi_tbls_cnt;
	size_t		psi_tbls_allocated;
	mpeg2_ts_psi_tbl_p psi_tbls;

	mpeg2_ts_psi_tbl_p	psi_tbl_last;
	mpeg2_ts_psi_tbl_sec_p	psi_sect_last;

	uint8_t		*ts_psi_packets; /* MPEG2-TS packets with data. */
	size_t		ts_psi_packets_size;

	//time_t		last_recv_time;	/* Connection start time. */
	uint64_t	pkt_count;	/* Packets Count. */
	uint64_t	te_count;	/* Count Transport Error Indicator errors. */
	uint64_t	cc_errors;	/* Count Continuity number errors. */
	uint64_t	crc_errors;	/* CRC32 errors. */
	uint64_t	data_errors;	/* Data format errors. */
} mpeg2_ts_pid_t, *mpeg2_ts_pid_p;



typedef struct mpeg2_ts_prog_s { /* Programm: pmt + data pids. */
	uint32_t	pn;		/* Prog num. */
	mpeg2_ts_pid_t	pmt;		/* Program map table Table. PID = any */
	size_t		pids_cnt;
	size_t		pids_allocated;
	uint16_t	*pids;		/* PID, some PIDs may be shared beetwin some programs. */
} mpeg2_ts_prog_t, *mpeg2_ts_prog_p;



typedef struct mpeg2_ts_pids_filter_s {
	size_t		pids_count;	/*  */
	uint32_t	*pids;		/* PIDs to filter */
	int		pid_null;	/* Filter: PID = 0x00. */
	int		pid_nit;	/* Filter: PID = 0x10 or any: Network Information Table. */
	int		pid_unknown;	/* Filter: unknown pid packets. */
} mpeg2_ts_pids_flt_t, *mpeg2_ts_pids_flt_p;

typedef struct mpeg2_ts_pid_map_s {
	uint32_t	pid_orig;	/*  */
	uint32_t	pid_new;	/*  */
} mpeg2_ts_pid_map_t, *mpeg2_ts_pid_map_p;

typedef struct mpeg2_ts_pids_map_s {
	size_t		maps_count;	/*  */
	mpeg2_ts_pid_map_p maps;	/* PIDs map */
	int		auto_map;	/* Auto pid remap. */
	uint32_t	pid_pmt;	/* PMT PID start num */
	uint32_t	pid_video;	/* Video PID start num */
	uint32_t	pid_audio;	/* Audio PID start num */
	uint32_t	pid_other;	/* Other PID start num */
} mpeg2_ts_pids_map_t, *mpeg2_ts_pids_map_p;


typedef struct mpeg2_ts_settings_s {
	mpeg2_ts_pids_flt_t	pids_flt;	/*  */
	mpeg2_ts_pids_map_t	pids_map;	/*  */
} mpeg2_ts_settings_t, *mpeg2_ts_settings_p;



typedef struct mpeg2_ts_data_s {
	size_t		mpeg2_ts_pkt_size; /* 188, 192, 204, 208 byte packets. */
	mpeg2_ts_pid_t	pat;		/* PID = 0x00: Program Association Table. */
	mpeg2_ts_pid_t	cat;		/* PID = 0x01: Conditional Access Table. */
	mpeg2_ts_pid_t	tsdt;		/* PID = 0x02: Transport Stream Description Table. */
	mpeg2_ts_pid_t	ipmpcit;	/* PID = 0x03: IPMP Control Information Table. */
	mpeg2_ts_pid_t	nit;		/* PID = 0x10 or any: Network Information Table. */
	mpeg2_ts_pid_t	sdt;		/* PID = 0x11: Service Description Table. */
	mpeg2_ts_pid_t	eit;		/* PID = 0x12: Event Information Table. */
	size_t		prog_cnt;
	size_t		prog_allocated;
	mpeg2_ts_prog_p	progs;		/* Programms */
	size_t		data_pids_cnt;
	size_t		data_pids_allocated;
	mpeg2_ts_pid_p	data_pids;	/* Pids with data */
	size_t		key_frames_cnt;
	size_t		key_frames_allocated;
	r_buf_rpos_p	key_frames_rpos;/* Array index to ts packets with: rai = 1. */
	time_t		*key_frames_time;/* Array of timestamp ts packets with: rai = 1. */
	uint64_t	null_pid_count; /* Dropped MPEG2-TS NULL packets count. */
	uint64_t	unknown_pid_count; /* Dropped MPEG2-TS unknown pid packets count. */
	uint64_t	dropped_count; /* Dropped MPEG2-TS packets count. */
	mpeg2_ts_settings_t s;
} mpeg2_ts_data_t, *mpeg2_ts_data_p;




void	mpeg2_ts_def_settings(mpeg2_ts_settings_p s);
#ifdef MPEG2TS_XML_CONFIG
int	mpeg2_ts_xml_load_settings(const uint8_t *buf, size_t buf_size,
	     mpeg2_ts_settings_p s);
#endif /* MPEG2TS_XML_CONFIG */
int	mpeg2_ts_settings_copy(mpeg2_ts_settings_p dst, mpeg2_ts_settings_p src);
void	mpeg2_ts_settings_free_data(mpeg2_ts_settings_p s);



int	mpeg2_ts_data_alloc(mpeg2_ts_data_p *m2ts_ret, mpeg2_ts_settings_p s);
void	mpeg2_ts_data_free(mpeg2_ts_data_p m2ts);

size_t	mpeg2_ts_pkt_analize(mpeg2_ts_data_p m2ts, r_buf_p r_buf,
	    struct timespec *ts, uint8_t *buf, size_t buf_size, int *pkt_added);


int	mpeg2_ts_txt_dump(mpeg2_ts_data_p m2ts, uint8_t *buf, size_t buf_size,
	    size_t *buf_size_ret);





#if 0
typedef struct mpeg2_stream_data_s { /* Parameters for evaluation. */
	/* 5.2.1 First priority: necessary for de-codability (basic monitoring) */
	volatile uint64_t TS_sync_loss;
	volatile uint64_t Sync_byte_error;
	volatile uint64_t PAT_error;
	//volatile uint64_t Continuity_count_error; /* - per PID. */
	volatile uint64_t PMT_error;
	volatile uint64_t PID_error;

	/* 5.2.2 Second priority: recommended for continuous or periodic monitoring */
	//volatile uint64_t Transport_error; /* - per PID. */
	CRC_error;
	PCR_error;
	PCR_repetition_error;
	PCR_discontinuity_indicator_error;
	PCR_accuracy_error;
	PTS_error;
	CAT_error;

	/* 5.2.3 Third priority: application dependant monitoring */
	NIT_error;
	NIT_actual_error;
	NIT_other_error;
	SI_repetition_error;
	Buffer_error;
	Unreferenced_PID;
	SDT_error;
	SDT_actual_error;
	SDT_other_error;
	EIT_error;
	EIT_actual_error;
	EIT_other_error;
	EIT_PF_error;
	RST_error;
	TDT_error;
	Empty_buffer_error;
	Data_delay_error;


	uint16_t	pids_cnt;	/* PIDs count. */
	uint16_t	pids_allocated; /* Allocated PIDs count. */
	mpeg2_ts_pid_data_p pids;	/* PIDs array. */
} mpeg2_stream_data_t, *mpeg2_stream_data_p;
#endif


#endif /* __STREAM_MPEG2TS_H__ */
