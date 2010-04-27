#include <stdio.h>
#include <glib.h>
#include <windows.h>
#include <process.h>

#include "sipe-miranda.h"

#include <newpluginapi.h>
#include <m_system.h>
#include <m_database.h>

#include "sipe-common.h"
#include "sipe-backend.h"

extern "C" void
sipe_backend_debug(sipe_debug_level level,
		   const gchar *format,
		   ...) G_GNUC_PRINTF(2, 3)
{
	va_list va;
	char szText[32768];
	FILE *fh;

	va_start(va,format);
	vsnprintf(szText,sizeof(szText),format,va);
	va_end(va);

	char *str = DBGetString( NULL, SIPSIMPLE_PROTOCOL_NAME, "debuglog");
	if (!str)
		str = mir_strdup("c:/sipsimple.log");

	if (!fopen_s(&fh, str, "a")) {
		fprintf(fh, "<[%d]> %s", _getpid(), szText);
		fclose(fh);
	}
	mir_free(str);
}

extern "C" const gchar *
sipe_backend_network_ip_address(void)
{
	return "127.0.0.1";
}

