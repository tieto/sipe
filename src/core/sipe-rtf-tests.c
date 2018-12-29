/**
 * @file sipe-rtf-tests.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2018 SIPE Project <http://sipe.sourceforge.net/>
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
 *
 * Tests for sipe-rtf.c
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <glib.h>

#include "sipe-common.h"
#include "sipe-backend.h"
#include "sipe-rtf.h"

void sipe_backend_debug_literal(sipe_debug_level level,
				const gchar *msg)
{
	printf("DEBUG %d: %s", level, msg);
}
void sipe_backend_debug(sipe_debug_level level,
			const gchar *format,
			...)
{
	va_list args;
	gchar *msg;
	va_start(args, format);
	msg = g_strdup_vprintf(format, args);
	va_end(args);

	sipe_backend_debug_literal(level, msg);
	g_free(msg);
}

static const struct test_data {
  const gchar *input;
  const gchar *expected;
} tests[] = {
	{
		"{\\rtf1\\fbidis\\ansi\\ansicpg1252\\deff0\\nouicompat\\deflang1033{\\fonttbl{\\f0\\fnil\\fcharset0 Segoe UI;}{\\f1\\fswiss\\fcharset177 Arial;}{\\f2\\fnil Segoe UI;}}{\\colortbl ;\\red0\\green0\\blue0;}{\\*\\generator Riched20 15.0.4420}{\\*\\mmathPr\\mwrapIndent1440 }\\viewkind4\\uc1\\pard\\ltrpar\\cf1\\outl\\f0\\fs20\\u8235?\\f1\\par\n"
		"\\par\n"
		"Enter 0 For SAP, ... issues \\par\n"
		"\\par\n"
		"For all non-SAP issues, select your preferred language:\\par\n"
		"1 English\\par\n"
		"2 Deutsch\\par\n"
		"...\\par\n"
		"11 for all other languages\\par\n"
		"\\outl0\\f2\\ltrch\\lang1033\\par{\\*\\lyncflags rtf=1}}\n",
		// \u8235 == U+202B == UTF-8 0xE2 0x80 0xAB (RIGHT-TO-LEFT EMBEDDING)
		"\xE2\x80\xAB<br/><br/>Enter 0 For SAP, ... issues <br/><br/>"
		"For all non-SAP issues, select your preferred language:<br/>"
		"1 English<br/>"
		"2 Deutsch<br/>"
		"...<br/>"
		"11 for all other languages<br/><br/>",
	},
	{
		"{\\rtf1\\ansi\\deff3\\adeflang1025\n"
		"{\\fonttbl{\\f0\\froman\\fprq2\\fcharset0 Times New Roman;}{\\f1\\froman\\fprq2\\fcharset2 Symbol;}{\\f2\\fswiss\\fprq2\\fcharset0 Arial;}{\\f3\\froman\\fprq2\\fcharset0 Liberation Serif{\\*\\falt Times New Roman};}{\\f4\\fswiss\\fprq2\\fcharset0 Liberation Sans{\\*\\falt Arial};}{\\f5\\fnil\\fprq2\\fcharset0 Noto Sans CJK SC Regular;}{\\f6\\fnil\\fprq2\\fcharset0 Lohit Devanagari;}{\\f7\\fnil\\fprq0\\fcharset128 Lohit Devanagari;}}\n"
		"{\\colortbl;\\red0\\green0\\blue0;\\red0\\green0\\blue255;\\red0\\green255\\blue255;\\red0\\green255\\blue0;\\red255\\green0\\blue255;\\red255\\green0\\blue0;\\red255\\green255\\blue0;\\red255\\green255\\blue255;\\red0\\green0\\blue128;\\red0\\green128\\blue128;\\red0\\green128\\blue0;\\red128\\green0\\blue128;\\red128\\green0\\blue0;\\red128\\green128\\blue0;\\red128\\green128\\blue128;\\red192\\green192\\blue192;}\n"
		"{\\stylesheet{\\s0\\snext0\\widctlpar\\hyphpar0\\cf0\\kerning1\\dbch\\af8\\langfe2052\\dbch\\af6\\afs24\\alang1081\\loch\\f3\\hich\\af3\\fs24\\lang1033 Normal;}\n"
		"{\\s15\\sbasedon0\\snext16\\sb240\\sa120\\keepn\\dbch\\af5\\dbch\\af6\\afs28\\loch\\f4\\fs28 Heading;}\n"
		"{\\s16\\sbasedon0\\snext16\\sl276\\slmult1\\sb0\\sa140 Text Body;}\n"
		"{\\s17\\sbasedon16\\snext17\\sl276\\slmult1\\sb0\\sa140\\dbch\\af7 List;}\n"
		"{\\s18\\sbasedon0\\snext18\\sb120\\sa120\\noline\\i\\dbch\\af7\\afs24\\ai\\fs24 Caption;}\n"
		"{\\s19\\sbasedon0\\snext19\\noline\\dbch\\af7 Index;}\n"
		"}{\\*\\generator LibreOffice/6.1.2.1$Linux_X86_64 LibreOffice_project/10$Build-1}{\\info{\\creatim\\yr2018\\mo12\\dy10\\hr8\\min25}{\\revtim\\yr2018\\mo12\\dy10\\hr8\\min26}{\\printim\\yr0\\mo0\\dy0\\hr0\\min0}}{\\*\\userprops}\\deftab709\n"
		"\\viewscale100\n"
		"{\\*\\pgdsctbl\n"
		"{\\pgdsc0\\pgdscuse451\\pgwsxn12240\\pghsxn15840\\marglsxn1134\\margrsxn1134\\margtsxn1134\\margbsxn1134\\pgdscnxt0 Default Style;}}\n"
		"\\formshade\\paperh15840\\paperw12240\\margl1134\\margr1134\\margt1134\\margb1134\\sectd\\sbknone\\sectunlocked1\\pgndec\\pgwsxn12240\\pghsxn15840\\marglsxn1134\\margrsxn1134\\margtsxn1134\\margbsxn1134\\ftnbj\\ftnstart1\\ftnrstcont\\ftnnar\\aenddoc\\aftnrstcont\\aftnstart1\\aftnnrlc\n"
		"{\\*\\ftnsep\\chftnsep}\\pgndec\\pard\\plain \\s0\\widctlpar\\hyphpar0\\cf0\\kerning1\\dbch\\af8\\langfe2052\\dbch\\af6\\afs24\\alang1081\\loch\\f3\\hich\\af3\\fs24\\lang1033{\\rtlch \\ltrch\\loch\n"
		"\\\\\\{The quick brown fox jumped over jumps over the lazy dog\\\\\\}}\n"
		"\\par \\pard\\plain \\s0\\widctlpar\\hyphpar0\\cf0\\kerning1\\dbch\\af8\\langfe2052\\dbch\\af6\\afs24\\alang1081\\loch\\f3\\hich\\af3\\fs24\\lang1033\\rtlch \\ltrch\\loch\n"
		"\n"
		"\\par }\n",
		"\\{The quick brown fox jumped over jumps over the lazy dog\\}<br/><br/>",
	},
	{
		"{\\u228\\'e4\\u246\\'f6\\u252\\'fc\\u196\\'c4\\u214\\'d6\\u220\\'dc\\u229\\'e5\\u197\\'c5\\u8364\\'80\\u163\\'a3$}",
		"äöüÄÖÜåÅ€£$",
	},
	{
		"{\\u256\\'3f\\u512\\'3f\\u999\\'3f\\u1000\\'3f}{\\cf0\\kerning1\\dbch\\af5\\langfe1033\\dbch\\af5\\rtlch \\ltrch\\loch\\fs24\\lang1033\\loch\\f5\\hich\\af5\n"
		"\\uc2 \\u9839\\'81\\'f2\\uc1 }{\\cf0\\kerning1\\dbch\\af6\\langfe1033\\dbch\\af6\\rtlch \\ltrch\\loch\\fs24\\lang1033\\loch\\f5\\hich\\af5\n"
		"\\u11360\\'3f}",
		"ĀȀϧϨ♯Ⱡ",
	},
	{
		NULL,
		NULL,
	},
};

int main(SIPE_UNUSED_PARAMETER int argc,
	 SIPE_UNUSED_PARAMETER char *argv[])
{
	guint succeeded           = 0;
	guint failed              = 0;
	const struct test_data *t = tests;

	for (; t->input; t++) {
		char *html = sipe_rtf_to_html(t->input);

		if (strcmp(html, t->expected) == 0) {
			succeeded++;
		} else {
			printf("FAILED: %s\n        %s\n",
			       html, t->expected);
			failed++;
		}

		g_free(html);
	}

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
