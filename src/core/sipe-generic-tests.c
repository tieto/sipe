/**
 * @file sipe-generic-tests.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2019 SIPE Project <http://sipe.sourceforge.net/>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include <glib.h>

#include "sipe-common.h"
#include "sipe-backend.h"
#include "sipe-crypt.h"
#include "sipe-utils.h"
#include "sip-transport.h"

/*
 * Stubs
 */
gboolean sipe_backend_debug_enabled(void)
{
	return(TRUE);
}

void sipe_backend_debug_literal(sipe_debug_level level,
				const gchar *msg)
{
	printf("DEBUG(%d): %s\n", level, msg);
}

void sipe_backend_debug(sipe_debug_level level,
			const gchar *format,
			...)
{
	va_list ap;
	gchar *newformat = g_strdup_printf("DEBUG(%d): %s\n", level, format);

	va_start(ap, format);
	vprintf(newformat, ap);
	va_end(ap);

	g_free(newformat);
}

const gchar *sip_transport_epid(SIPE_UNUSED_PARAMETER struct sipe_core_private *sipe_private)
{
	return(NULL);
}

/* needed when linking against NSS */
void md4sum(const uint8_t *data, uint32_t length, uint8_t *digest);
void md4sum(SIPE_UNUSED_PARAMETER const uint8_t *data,
	    SIPE_UNUSED_PARAMETER uint32_t length,
	    SIPE_UNUSED_PARAMETER uint8_t *digest)
{
}

/*
 * Tester code
 */
static guint succeeded = 0;
static guint failed    = 0;

static void assert_equal_str(const char *expected, const gchar *got)
{
	if (sipe_strequal(expected, got)) {
		succeeded++;
	} else {
		printf("FAILED: %s\n        %s\n", got, expected);
		failed++;
	}
}

static void assert_equal_uint(gsize expected, gsize got)
{
	if (expected == got) {
		succeeded++;
	} else {
		printf("FAILED: %" G_GSIZE_FORMAT "\n        %" G_GSIZE_FORMAT "\n",
		       got, expected);
		failed++;
	}
}

static void tests_sipe_utils_time(void) {
	gchar *result_str;
	time_t result_time;

#define UNIX_EPOCH_IN_ISO8601_UTC "1970-01-01T00:00:00Z"

	result_str = sipe_utils_time_to_str(0);
	assert_equal_str(result_str, UNIX_EPOCH_IN_ISO8601_UTC);
	g_free(result_str);

	result_time = sipe_utils_str_to_time(NULL);
	assert_equal_uint(result_time, 0);
	result_time = sipe_utils_str_to_time(UNIX_EPOCH_IN_ISO8601_UTC);
	assert_equal_uint(result_time,                   0);
	/* handle missing "Z" */
	result_time = sipe_utils_str_to_time("1970-01-01T00:00:01");
	assert_equal_uint(result_time,                   1);
	result_time = sipe_utils_str_to_time("1970-01-01T00:00:20Z");
	assert_equal_uint(result_time,                  20);
	result_time = sipe_utils_str_to_time("1970-01-01T00:03:00");
	assert_equal_uint(result_time,              3 * 60);
	result_time = sipe_utils_str_to_time("1970-01-01T00:40:00Z");
	assert_equal_uint(result_time,             40 * 60);
	result_time = sipe_utils_str_to_time("1970-01-01T05:00:00");
	assert_equal_uint(result_time,         5 * 60 * 60);
	result_time = sipe_utils_str_to_time("1970-01-01T23:00:00Z");
	assert_equal_uint(result_time,        23 * 60 * 60);
	/* 6th day after epoch */
	result_time = sipe_utils_str_to_time("1970-01-07T00:00:00");
	assert_equal_uint(result_time,    6 * 24 * 60 * 60);
	/* 17th day after epoch */
	result_time = sipe_utils_str_to_time("1970-01-18T00:00:00Z");
	assert_equal_uint(result_time,   17 * 24 * 60 * 60);
	result_time = sipe_utils_str_to_time("1970-02-01T00:00:00");
	assert_equal_uint(result_time,   31 * 24 * 60 * 60);
	result_time = sipe_utils_str_to_time("1970-12-01T00:00:00Z");
	/* 365 - 31 days */
	assert_equal_uint(result_time,  334 * 24 * 60 * 60);
	result_time = sipe_utils_str_to_time("1971-01-01T00:00:00");
	assert_equal_uint(result_time,  365 * 24 * 60 * 60);
}

static void generic_tests(void) {
	tests_sipe_utils_time();
}

int main(SIPE_UNUSED_PARAMETER int argc,
	 SIPE_UNUSED_PARAMETER char *argv[])
{
	/* Initialization for crypto backend (test mode) */
	sipe_crypto_init(FALSE);

	generic_tests();

	printf("Result: %d PASSED %d FAILED\n", succeeded, failed);
	return(failed);
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
