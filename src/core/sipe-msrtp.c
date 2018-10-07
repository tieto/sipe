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

#define SIPE_WRITE_UINT64_BE(where, value) \
	_SIPE_WRITE(where, 0, 64, 56, value); \
	_SIPE_WRITE(where, 1, 64, 48, value); \
	_SIPE_WRITE(where, 2, 64, 40, value); \
	_SIPE_WRITE(where, 3, 64, 32, value); \
	_SIPE_WRITE(where, 4, 64, 24, value); \
	_SIPE_WRITE(where, 5, 64, 16, value); \
	_SIPE_WRITE(where, 6, 64,  8, value); \
	_SIPE_WRITE(where, 7, 64,  0, value); \
	where += 8;

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

enum
{
	NAL_UNIT_TYPE_SEI = 6,
	NAL_UNIT_TYPE_PACSI = 30
};

enum
{
	MS_LD_FPS_IDX_7_5 = 0,
	MS_LD_FPS_IDX_12_5 = 1,
	MS_LD_FPS_IDX_15 = 2,
	MS_LD_FPS_IDX_25 = 3,
	MS_LD_FPS_IDX_30 = 4,
	MS_LD_FPS_IDX_50 = 5,
	MS_LD_FPS_IDX_60 = 6
};

void
sipe_core_msrtp_write_video_source_request(guint8 *buffer,
					   guint8 payload_type,
					   guint32 media_source_id)
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
	SIPE_WRITE_UINT32_BE(buffer, media_source_id);
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

static void
write_nal_unit_header(guint8 *dest, gboolean f_bit, guint8 nal_ref_idc,
		      guint8 type)
{
	*dest = f_bit ? 0x80 : 0x00;
	*dest |= nal_ref_idc << 5;
	*dest |= type;
}

static void
write_ms_layer_description(guint8 *buffer, guint16 width, guint16 height,
			   guint32 bitrate, guint8 framerate_idx,
			   gboolean base_layer, guint16 prid,
			   gboolean constrained_baseline)
{
	// Coded width and height
	SIPE_WRITE_UINT16_BE(buffer, width);
	SIPE_WRITE_UINT16_BE(buffer, height);

	// Display width and height
	SIPE_WRITE_UINT16_BE(buffer, width);
	SIPE_WRITE_UINT16_BE(buffer, height);

	SIPE_WRITE_UINT32_BE(buffer, bitrate);

	*buffer = framerate_idx << 3;
	*buffer |= base_layer ? 0 : 1;
	++buffer;

	*buffer = prid << 2;
	*buffer |= (constrained_baseline ? 1 : 0) << 1;
}

gsize
sipe_core_msrtp_write_video_scalability_info(guint8 *buffer, guint8 nal_count)
{
	static const guint8 MS_STREAM_LAYOUT_SEI_UUID[] = {
		0x13, 0x9f, 0xb1, 0xa9, 0x44, 0x6a, 0x4d, 0xec, 0x8c, 0xbf,
		0x65, 0xb1, 0xe1, 0x2d, 0x2c, 0xfd
	};

	static const guint8 MS_BITSTREAM_INFO_SEI_UUID[] = {
		0x05, 0xfb, 0xc6, 0xb9, 0x5a, 0x80, 0x40, 0xe5, 0xa2, 0x2a,
		0xab, 0x40, 0x20, 0x26, 0x7e, 0x26
	};

	guint8 *ptr = buffer;

	// Write PACSI (RFC6190 section 4.9)
	SIPE_WRITE_UINT32_BE(ptr, 77); // Length of the NAL

	write_nal_unit_header(ptr++, FALSE, 3, NAL_UNIT_TYPE_PACSI);

	*ptr = 1 << 7; // Reserved bit = 1
	*ptr |= 1 << 6; // I-bit = 1 if any aggregated unit has it set to 1
	*ptr |= 0; // Priority = 0
	++ptr;

	*ptr = 1 << 7; // No Inter Layer Prediction = True
	*ptr |= 0 << 4; // Dependency ID = 0
	*ptr |= 0; // Quality ID
	++ptr;

	*ptr = 0; // Temporal ID
	*ptr |= 0 << 4; // Use Ref Base Picture = False
	*ptr |= 0 << 3; // Discardable = False
	*ptr |= 1 << 2; // Output = True
	*ptr |= 3; // Reserved
	++ptr;

	// X|Y|T|A|P|C|S|E flags: DONC & First NAL = True
	SIPE_WRITE_UINT8(ptr, 0x22);

	SIPE_WRITE_UINT16_BE(ptr, 1); // Cross Session Decoder Order Number

	// Stream Layout SEI Message (MS-H264PF section 2.2.5)
	SIPE_WRITE_UINT16_BE(ptr, 45); // Size of the NAL

	write_nal_unit_header(ptr++, FALSE, 0, NAL_UNIT_TYPE_SEI);

	SIPE_WRITE_UINT8(ptr, 5); // Payload type (user data unregistered)
	SIPE_WRITE_UINT8(ptr, 42); // Payload size

	memcpy(ptr, MS_STREAM_LAYOUT_SEI_UUID,
	       sizeof (MS_STREAM_LAYOUT_SEI_UUID));
	ptr += sizeof (MS_STREAM_LAYOUT_SEI_UUID);

	// Layer Presence - layer with PRID 0 present
	SIPE_WRITE_UINT64_BE(ptr, 0x0100000000000000);

	SIPE_WRITE_UINT8(ptr, 1); // Layer Description Present = True
	SIPE_WRITE_UINT8(ptr, 16); // Layer Description Size

	write_ms_layer_description(ptr, 212, 160, 50250, MS_LD_FPS_IDX_7_5,
				   TRUE, 0, TRUE);
	ptr += 16;

	// MS Bitstream Info SEI Message ([MS-H264PF] section 2.2.7)
	SIPE_WRITE_UINT16_BE(ptr, 21); // Size of the NAL

	write_nal_unit_header(ptr++, FALSE, 0, NAL_UNIT_TYPE_SEI);

	SIPE_WRITE_UINT8(ptr, 5); // Payload type (user data unregistered)
	SIPE_WRITE_UINT8(ptr, 18); // Payload size

	memcpy(ptr, MS_BITSTREAM_INFO_SEI_UUID,
	       sizeof (MS_BITSTREAM_INFO_SEI_UUID));
	ptr += sizeof (MS_BITSTREAM_INFO_SEI_UUID);

	/* Reference frame count. This should increment with each reference
	 * frame, but clients apparently don't care about the value. */
	SIPE_WRITE_UINT8(ptr, 1);
	// Number of NAL units described by this PACSI NAL unit.
	SIPE_WRITE_UINT8(ptr, nal_count);

	return ptr - buffer;
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
