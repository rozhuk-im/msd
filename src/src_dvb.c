/*-
 * Copyright (c) 2016-2024 Rozhuk Ivan <rozhuk.im@gmail.com>
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
//#include "utils/helpers.h"
#include "proto/mpeg2ts.h"
#include "utils/mem_utils.h"
#include "utils/xml.h"

#include "stream_mpeg2ts.h"
#include "src_dvb.h"





void
src_dvb_settings_def(src_dvb_settings_p s_ret) {
	
	if (NULL == s_ret)
		return;
	memset(s_ret, 0x00, sizeof(dvb_fe_settings_t));
	dvb_fe_settings_def(&s_ret->fe_s);
}

int
src_dvb_xml_load_settings(const uint8_t *buf, size_t buf_size,
    src_dvb_settings_p s) {
	const uint8_t *data;
	size_t data_size;

	if (NULL == buf || 0 == buf_size || NULL == s)
		return (EINVAL);

	/* Read from config. */

	return (0);
}


int
src_dvb_fe_on_state_cb(dvb_fe_p dvb_fe, void *udata, const dvb_fe_state_p status) {
	
	return (0);
}


int
src_dvb_create(src_dvb_settings_p s, tpt_p tpt, src_dvb_p *src_dvb_ret) {
	int error = 0;
	src_dvb_p src_dvb;

	if (NULL == s || NULL == tpt || NULL == src_dvb_ret)
		return (EINVAL);
	src_dvb = calloc(1, sizeof(src_dvb_t));
	if (NULL == src_dvb)
		return (ENOMEM);
	/* Settings. */
	memcpy(&src_dvb->s, s, sizeof(src_dvb_settings_t));
	/* Use short name. */
	s = &src_dvb->s;

	/* Create frontend. */
	error = dvb_fe_create(s->adapter_idx, s->fe_idx, tpt,
	    src_dvb_fe_on_state_cb, src_dvb, &src_dvb->dvb_fe);
	if (0 != error)
		goto err_out;


	(*src_dvb_ret) = src_dvb;
	
	return (0);

err_out:
	/* Error. */
	src_dvb_destroy(src_dvb);
	return (error);
}

void
src_dvb_destroy(src_dvb_p src_dvb) {
	
	if (NULL == src_dvb)
		return;

	dvb_fe_destroy(src_dvb->dvb_fe);
}

int
src_dvb_start(src_dvb_p src_dvb) {
	
}

void
src_dvb_stop(src_dvb_p src_dvb) {
	
}

int
src_dvb_restart(src_dvb_p src_dvb) {
	
}




