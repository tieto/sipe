/************************ tell Emacs this is a -*-C-*- file *************
 * @file sipe-rtf.l
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
 *
 * Simple parser to extract plain text from RTF and transform it to HTML
 */

/* generated module */
%option outfile="sipe-rtf.c"
%option prefix="sipe_rtf_lexer_"

/* flex configuration options */
%option 8bit
%option bison-bridge
%option full
%option nodefault
%option noinput
%option nointeractive
%option pointer
%option reentrant
%option nounput
%option warn
%option noyyalloc
%option noyyfree
%option noyyrealloc
%option noyywrap

%{
#include <glib.h>

#include "sipe-common.h"
#include "sipe-rtf.h"

/*
 * small string buffer to avoid memory allocations
 *
 * Must be length of longest interesting keyword + 1
 * Currently that would be "par"
 */
#define SIPE_RTF_LEXER_KEYWORD_SIZE 3 + 1 + 1

/* lexer token value type */
struct parser_lval_type {
	guint number;
	gchar keyword_buffer[SIPE_RTF_LEXER_KEYWORD_SIZE];
};
#define YYSTYPE struct parser_lval_type

/* lexer tokens */
#define KEYWORD           256
#define KEYWORD_PARAMETER 257
#define KEYWORD_END       258
#define LEXER_ERROR       259

/* parser state */
struct parser_state {
	GString                 *text;
	guint                    unicode_ignore_length;
	guint                    ignore;
	struct parser_lval_type  lval;
};

static void sipe_rtf_add_char(struct parser_state *state, gchar c);
static void sipe_rtf_add_text(struct parser_state *state, const gchar *text);
static void sipe_rtf_add_unichar(struct parser_state *state, gunichar c);
%}

DIGIT  [0-9]
HEX    [0-9a-fA-F]
LETTER [a-zA-Z]

%x keyword

%%
                      /* stuff that we simply throw away   */
[\r\n]+               /* line endings                      */
"{"\\\*[^}]*"}"       /* comments                          */
                      /* font definitions                  */
"{"\\f{DIGIT}+\\[^;]+;"}"
"{"                   /* section start                     */
"}"                   /* section end                       */

                      /* pass plain text to output buffer  */
                      /* escaped special characters        */
\\\\                  { sipe_rtf_add_char(yyextra, '\\'); }
\\"{"                 { sipe_rtf_add_char(yyextra, '{');  }
\\"}"                 { sipe_rtf_add_char(yyextra, '}');  }
\\\'{HEX}{2}          { /* 2 digit hex to 8-bit character  */
	                unsigned int c;
                        sscanf(yytext + 2, "%x", &c);
                        sipe_rtf_add_char(yyextra, c);
                      }
\\u{DIGIT}+           { /* Unicode character               */
                        gunichar c;
                        sscanf(yytext + 2, "%d", &c);
                        sipe_rtf_add_unichar(yyextra, c);
                      }
                      /* all other plain text              */
[^{}\\\n\r]+          { sipe_rtf_add_text(yyextra, yytext); }

                      /* stuff passed to parser for further processing */
\\{LETTER}+           {
                        BEGIN(keyword);
                        g_strlcpy(yylval->keyword_buffer,
                                  yytext + 1,
                                  SIPE_RTF_LEXER_KEYWORD_SIZE);
                        return(KEYWORD);
                      }
<keyword>{DIGIT}+     {
                        sscanf(yytext, "%d", &yylval->number);
                        return(KEYWORD_PARAMETER);
                      }
<keyword>(;|[^0-9][^;\\]*;|[ ])? {
                        /* reset <keyword start condition and throw away */
                        BEGIN(INITIAL);
			return(KEYWORD_END);
                      }
<keyword>.|\n         { /* reset <keyword> start condition */
                        BEGIN(INITIAL);
                        yyless(0);
			return(KEYWORD_END);
                      }

                      /* indicate anything else as error to parser */
<INITIAL,keyword>.|\n { return(LEXER_ERROR); }
%%

/* memory allocation for flex code */
void *sipe_rtf_lexer_alloc(yy_size_t size,
			   SIPE_UNUSED_PARAMETER yyscan_t yyscanner)
{
	return g_malloc(size);
}

void *sipe_rtf_lexer_realloc(void *ptr, yy_size_t size,
			     SIPE_UNUSED_PARAMETER yyscan_t yyscanner)
{
	return g_realloc(ptr, size);
}

void sipe_rtf_lexer_free(void *ptr,
			 SIPE_UNUSED_PARAMETER yyscan_t yyscanner)
{
	g_free(ptr);
}

/* add text to buffer */
static void sipe_rtf_add_char(struct parser_state *state, gchar c)
{
  /* ignored characters after unicode sequence */
  if (state->ignore) {
    state->ignore--;
  } else {
    g_string_append_c(state->text, c);
  }
}

static void sipe_rtf_add_text(struct parser_state *state, const gchar *text)
{
  /* ignored characters after unicode sequence */
  if (state->ignore) {
    while (*text && state->ignore--) text++;
  }
  if (!*text)
    return;

  /* add the remainder to the text buffer */
  g_string_append(state->text, text);
}

static void sipe_rtf_add_unichar(struct parser_state *state, gunichar c)
{
  /* ignored characters after unicode sequence */
  state->ignore = state->unicode_ignore_length;

  g_string_append_unichar(state->text, c);
}

gchar *sipe_rtf_to_html(const gchar *rtf)
{
        // @TODO
	(void)rtf;
	return g_strdup("");
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
