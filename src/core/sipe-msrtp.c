/**
 * @file sipe-msrtp.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2016 SIPE Project <http://sipe.sourceforge.net/>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <string.h>

#include <glib.h>

#include "sipe-core.h"

#define _SIPE_WRITE(where, idx, size, shift, value) \
    ((guint8 *) where)[idx] = (((guint##size)value) >> shift) & 0xff

#define SIPE_WRITE_UINT8(where, value) \
	_SIPE_WRITE(where++, 0, 8, 0, value);

#define SIPE_WRITE_UINT16_BE(where, value) \
	_SIPE_WRITE(where, 0, 16, 8, value); \
	_SIPE_WRITE(where, 1, 16, 0, value); \
	where += 2;

#define SIPE_WRITE_UINT32_BE(where, value) \
	_SIPE_WRITE(where, 0, 32, 24, value); \
	_SIPE_WRITE(where, 1, 32, 16, value); \
	_SIPE_WRITE(where, 2, 32,  8, value); \
	_SIPE_WRITE(where, 3, 32,  0, value); \
	where += 4;

enum
{
	VSR_FLAG_NONE = 0,
	VSR_FLAG_H264_CGS_REWRITE = 1,
	VSR_FLAG_H264_CONSTRAINED_PROFILE_ONLY = 2,
	VSR_FLAG_RT_NO_SP_FRAMES = 4,
	VSR_FLAG_H264_NO_SEAMLESS_RESOLUTION_CHANGE = 8
};

enum
{
	VSR_ASPECT_4_BY_3 = 1,
	VSR_ASPECT_16_BY_9 = 2,
	VSR_ASPECT_1_BY_1 = 4,
	VSR_ASPECT_3_BY_4 = 8,
	VSR_ASPECT_9_BY_16 = 16,
	VSR_ASPECT_20_BY_3 = 32,
};

enum
{
	VSR_FPS_7_5 = 1,
	VSR_FPS_12_5 = 2,
	VSR_FPS_15 = 4,
	VSR_FPS_25 = 8,
	VSR_FPS_30 = 16,
	VSR_FPS_50 = 32,
	VSR_FPS_60 = 64
};

void
sipe_core_msrtp_write_video_source_request(guint8 *buffer,
					   guint8 payload_type)
{
	static guint8 bit_rate_histogram[] = {
		0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	};

	static guint8 quality_report_histogram[] = {
		0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	};

	/* VSR FCI field - from [MS-RTP] 2.2.12.2 */

	/* Header */

	SIPE_WRITE_UINT16_BE(buffer, 0x1); // AFB Type
	// Length
	SIPE_WRITE_UINT16_BE(buffer, SIPE_MSRTP_VSR_HEADER_LEN +
			     SIPE_MSRTP_VSR_ENTRY_LEN);
	// Requested Media Source ID
	SIPE_WRITE_UINT32_BE(buffer, SIPE_MSRTP_VSR_SOURCE_ANY);
	SIPE_WRITE_UINT16_BE(buffer, 1); // Request Id
	SIPE_WRITE_UINT16_BE(buffer, 0); // Reserve1
	SIPE_WRITE_UINT8(buffer, 0); // Version
	SIPE_WRITE_UINT8(buffer, 0 << 7); // Keyframe (1bit) + Reserve2
	SIPE_WRITE_UINT8(buffer, 1); // Number of Entries
	SIPE_WRITE_UINT8(buffer, SIPE_MSRTP_VSR_ENTRY_LEN); // Entry Length
	SIPE_WRITE_UINT32_BE(buffer, 0x0); // Reserve3

	/* Entry */

	SIPE_WRITE_UINT8(buffer, payload_type); // Payload Type
	SIPE_WRITE_UINT8(buffer, 1); // UCConfig Mode
	SIPE_WRITE_UINT8(buffer, VSR_FLAG_NONE); // Flags
	SIPE_WRITE_UINT8(buffer, VSR_ASPECT_4_BY_3); // Aspect Ratio Bit Mask
	SIPE_WRITE_UINT16_BE(buffer, 432); // Maximum Width
	SIPE_WRITE_UINT16_BE(buffer, 432); // Maximum Height
	SIPE_WRITE_UINT32_BE(buffer, 350000); // Minimum bit rate
	SIPE_WRITE_UINT32_BE(buffer, 0); // Reserve
	SIPE_WRITE_UINT32_BE(buffer, 10000); // Bit rate per level
	// Bit rate Histogram
	memcpy(buffer, bit_rate_histogram, sizeof (bit_rate_histogram));
	buffer += sizeof (bit_rate_histogram);
	SIPE_WRITE_UINT32_BE(buffer, VSR_FPS_15); // Frame rate bit mask
	SIPE_WRITE_UINT16_BE(buffer, 0); // Number of MUST instances
	SIPE_WRITE_UINT16_BE(buffer, 1); // Number of MAY instances
	// Quality Report Histogram
	memcpy(buffer, quality_report_histogram,
	       sizeof (quality_report_histogram));
	buffer += sizeof (quality_report_histogram);
	SIPE_WRITE_UINT32_BE(buffer, 103680); // Maximum number of pixels
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
