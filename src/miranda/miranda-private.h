#ifdef _MSC_VER
#define __func__ __FUNCTION__
#endif

#define SIPSIMPLE_PROTOCOL_NAME LPGEN("Office Communicator")
#define SIP_UNIQUEID "sip_screenname"

#define SIPE_EVENTTYPE_ERROR_NOTIFY 2002
#define SIPE_DB_GETEVENTTEXT_ERROR_NOTIFY "SIP/SIMPLE/GetEventTextErrorNotify"
#define SIPE_EVENTTYPE_INFO_NOTIFY 2003
#define SIPE_DB_GETEVENTTEXT_INFO_NOTIFY "SIP/SIMPLE/GetEventTextInfoNotify"
#define SIPE_EVENTTYPE_IM_TOPIC 2010
#define SIPE_DB_GETEVENTTEXT_IM_TOPIC "SIP/SIMPLE/GetEventTextIMTopic"

#define SIPE_MIRANDA_IP_LOCAL 0
#define SIPE_MIRANDA_IP_MANUAL 1
#define SIPE_MIRANDA_IP_PROG 2

typedef enum
{
        SIPE_MIRANDA_DISCONNECTED = 0, /**< Disconnected. */
        SIPE_MIRANDA_CONNECTED,        /**< Connected.    */
        SIPE_MIRANDA_CONNECTING        /**< Connecting.   */

} sipe_miranda_ConnectionState;

struct sipe_miranda_connection_info;

typedef struct sipe_backend_private
{
	PROTO_INTERFACE proto;
	struct sipe_core_public *sip;
	CRITICAL_SECTION CriticalSection; 
	HANDLE m_hServerNetlibUser;
	sipe_miranda_ConnectionState state;
	gboolean valid;
	gboolean disconnecting;
	HANDLE disconnect_timeout;
	GSList *contactMenuChatItems;
	DWORD main_thread_id;
	char _SIGNATURE[16];
} SIPPROTO;

struct sipe_backend_chat_session {
	SIPPROTO *pr;
	gchar *conv;
};

typedef enum
{
	SIPE_MIRANDA_INPUT_READ  = 1 << 0,  /**< A read condition.  */
	SIPE_MIRANDA_INPUT_WRITE = 1 << 1   /**< A write condition. */

} sipe_miranda_input_condition;

/** The type of callbacks to handle events on file descriptors, as passed to
 *  sipe_miranda_input_add().  The callback will receive the @c user_data
 *  passed to sipe_miranda_input_add(), the file descriptor on which the event
 *  occurred, and the condition that was satisfied to cause the callback to be
 *  invoked.
 */
typedef void (*sipe_miranda_input_function)(gpointer, gint, sipe_miranda_input_condition);

typedef struct sipe_miranda_sel_entry;

#define CONTACTS_FOREACH(list) {               \
	GSList *entry = list;                  \
	while (entry) {                        \
		HANDLE hContact = entry->data; \
		entry = entry->next;
#define CONTACTS_FOREACH_END }}


typedef INT_PTR (*SipSimpleServiceFunc)( SIPPROTO*, WPARAM, LPARAM );
typedef int     (*SipSimpleEventFunc)( SIPPROTO*, WPARAM, LPARAM );
typedef void    (*SipSimpleThreadFunc)( SIPPROTO*, void* );

#define _NI(string) SIPE_DEBUG_INFO( "%s:%s (%d) ##NOT IMPLEMENTED## %s", __FILE__, __FUNCTION__, __LINE__, #string )
#define _NIF() _NI("")

#define _LOCK(crit) do { SIPE_DEBUG_INFO("[L:%08x] About to lock", crit); EnterCriticalSection(crit); SIPE_DEBUG_INFO("[L:%08x] Locked", crit); } while (0)
#define _UNLOCK(crit) do { SIPE_DEBUG_INFO("[L:%08x] About to unlock", crit); LeaveCriticalSection(crit); SIPE_DEBUG_INFO("[L:%08x] Unlocked", crit); } while (0)
#define LOCK _LOCK(&pr->CriticalSection)
#define UNLOCK _UNLOCK(&pr->CriticalSection)

#define _TRACE do { SIPE_DEBUG_INFO_NOFORMAT("TRACE") } while (0);

void sipe_miranda_close( SIPPROTO *pr);

TCHAR* CHAR2TCHAR( const char *chr );
char* TCHAR2CHAR( const TCHAR *tchr );
HANDLE sipe_miranda_AddEvent(const SIPPROTO *pr, HANDLE hContact, WORD wType, DWORD dwTime, DWORD flags, DWORD cbBlob, PBYTE pBlob);

gchar*		sipe_miranda_getContactString(const SIPPROTO *pr, HANDLE hContact, const gchar* name);
gchar*		sipe_miranda_getString(const SIPPROTO *pr, const gchar* name);
int		sipe_miranda_getStaticString(const SIPPROTO *pr, HANDLE hContact, const gchar* valueName, gchar* dest, unsigned dest_len);
gchar*		sipe_miranda_getGlobalString(const gchar* name);
WORD		sipe_miranda_getGlobalWord(const gchar* name, WORD* rv);
WORD		sipe_miranda_getWord(const SIPPROTO *pr, HANDLE hContact, const gchar* name, WORD* rv);
DWORD		sipe_miranda_getDword( const SIPPROTO *pr, HANDLE hContact, const gchar* name, DWORD* rv);
gboolean	sipe_miranda_getBool(const SIPPROTO *pr, const gchar *name, gboolean defval);

void sipe_miranda_setContactString(const SIPPROTO *pr, HANDLE hContact, const gchar* name, const gchar* value);
void sipe_miranda_setContactStringUtf(const SIPPROTO *pr, HANDLE hContact, const gchar* valueName, const gchar* parValue );
void sipe_miranda_setString(const SIPPROTO *pr, const gchar* name, const gchar* value);
void sipe_miranda_setStringUtf(const SIPPROTO *pr, const gchar* name, const gchar* value);
void sipe_miranda_setGlobalString(const gchar* name, const gchar* value);
void sipe_miranda_setGlobalStringUtf(const gchar* valueName, const gchar* parValue );
int sipe_miranda_setGlobalWord(const gchar* szSetting, WORD wValue);
int sipe_miranda_setWord(const SIPPROTO *pr, HANDLE hContact, const gchar* szSetting, WORD wValue);
int sipe_miranda_setBool(const SIPPROTO *pr, const gchar *name, gboolean value);

struct sipe_miranda_sel_entry* sipe_miranda_input_add(HANDLE fd, sipe_miranda_input_condition cond, sipe_miranda_input_function func, gpointer user_data);
gboolean sipe_miranda_input_remove(struct sipe_miranda_sel_entry *entry);

int sipe_miranda_SendBroadcast(SIPPROTO *pr, HANDLE hContact,int type,int result,HANDLE hProcess,LPARAM lParam);
void sipe_miranda_SendProtoAck( SIPPROTO *pr, HANDLE hContact, DWORD dwCookie, int nAckResult, int nAckType, const char* pszMessage);
void sipe_miranda_msgbox(const char *msg, const char *caption);
gchar *sipe_miranda_uri_self(SIPPROTO *pr);

void sipe_miranda_login(SIPPROTO *pr);
struct sipe_miranda_connection_info *sipe_miranda_connect(SIPPROTO *pr, const gchar *host, int port, gboolean tls, int timeout, void (*callback)(HANDLE fd, void *data, const gchar *reason), void *data);
gboolean sipe_miranda_cmd(gchar *cmd, gchar *buf, DWORD *maxlen);

gchar* sipe_miranda_eliminate_html(const gchar *string, int len);
gchar* sipe_miranda_html2rtf(const gchar *text);
unsigned short sipe_miranda_network_get_port_from_fd( HANDLE fd );
const gchar *sipe_miranda_get_local_ip(void);
void sipe_miranda_connection_destroy(SIPPROTO *pr);
void sipe_miranda_connection_error_reason(SIPPROTO *pr, sipe_connection_error error, const gchar *msg);
gpointer sipe_miranda_schedule_mseconds(void (*callback)(gpointer), guint timeout, gpointer data);

/* Buddy utility functions */
sipe_backend_buddy sipe_miranda_buddy_find(SIPPROTO *pr, const gchar *name, const gchar *group);
GSList* sipe_miranda_buddy_find_all(SIPPROTO *pr, const gchar *buddy_name, const gchar *group_name);

/* Plugin interface functions */
int sipe_miranda_SetStatus( SIPPROTO *pr, int iNewStatus );
int sipe_miranda_SendMsg(SIPPROTO *pr, HANDLE hContact, int flags, const char* msg);
int sipe_miranda_RecvMsg(SIPPROTO *pr, HANDLE hContact, PROTORECVEVENT* pre);
int sipe_miranda_SetAwayMsg(SIPPROTO *pr, int m_iStatus, const PROTOCHAR* msg);
HANDLE sipe_miranda_GetAwayMsg( SIPPROTO *pr, HANDLE hContact );
HANDLE sipe_miranda_SendFile( SIPPROTO *pr, HANDLE hContact, const PROTOCHAR* szDescription, PROTOCHAR** ppszFiles );
int sipe_miranda_RecvFile( SIPPROTO *pr, HANDLE hContact, PROTOFILEEVENT* evt );
int sipe_miranda_FileDeny( SIPPROTO *pr, HANDLE hContact, HANDLE hTransfer, const PROTOCHAR* szReason );
HANDLE sipe_miranda_FileAllow( SIPPROTO *pr, HANDLE hContact, HANDLE hTransfer, const PROTOCHAR* szPath );
int sipe_miranda_UserIsTyping( SIPPROTO *pr, HANDLE hContact, int type );
int sipe_miranda_GetInfo( SIPPROTO *pr, HANDLE hContact, int infoType );
HANDLE sipe_miranda_SearchByEmail( SIPPROTO *pr, const PROTOCHAR* email );
HANDLE sipe_miranda_SearchByName( SIPPROTO *pr, const PROTOCHAR* nick, const PROTOCHAR* firstName, const PROTOCHAR* lastName);
HWND sipe_miranda_SearchAdvanced( SIPPROTO *pr, HWND owner );

/* Plugin event functions */
int sipe_miranda_buddy_delete(SIPPROTO *pr, WPARAM wParam, LPARAM lParam);

int SipeStatusToMiranda(guint activity);
guint MirandaStatusToSipe(int status);

