#define SIPSIMPLE_PROTOCOL_NAME LPGEN("SIP/SIMPLE")
#define SIP_UNIQUEID "sip_screenname"

#define snprintf sprintf_s

typedef struct sipe_backend_private
{
	PROTO_INTERFACE proto;
	struct sipe_core_public *sip;
	HANDLE m_hServerNetlibUser;
} SIPPROTO;

struct miranda_sipe_ack_args
{
        HANDLE hContact;
        int    nAckType;
        int    nAckResult;
        HANDLE hSequence;
        LPARAM pszMessage;
		SIPPROTO *pr;
};

typedef enum
{
	SIPE_MIRANDA_INPUT_READ  = 1 << 0,  /**< A read condition.  */
	SIPE_MIRANDA_INPUT_WRITE = 1 << 1   /**< A write condition. */

} sipe_miranda_input_condition;

/** The type of callbacks to handle events on file descriptors, as passed to
 *  sipe_input_add().  The callback will receive the @c user_data passed to
 *  sipe_input_add(), the file descriptor on which the event occurred, and the
 *  condition that was satisfied to cause the callback to be invoked.
 */
typedef void (*sipe_miranda_input_function)(gpointer, gint, sipe_miranda_input_condition);

typedef struct sipe_miranda_sel_entry
{
	int sig;
	HANDLE fd;
	sipe_miranda_input_function func;
	gpointer user_data;
};


typedef INT_PTR (*SipSimpleServiceFunc)( SIPPROTO*, WPARAM, LPARAM );
typedef int     (*SipSimpleEventFunc)( SIPPROTO*, WPARAM, LPARAM );
typedef void    (*SipSimpleThreadFunc)( void* );

#define _PVTDATAI(sip) ((struct miranda_sipe_private_data*)sip->sipe_public.backend_private)
#define _PVTDATA ((struct miranda_sipe_private_data*)sip->sipe_public.backend_private)

#define _NIF()

char* sipe_miranda_getContactString(const SIPPROTO *pr, HANDLE hContact, const char* name);
char* sipe_miranda_getString(const SIPPROTO *pr, const char* name);
int sipe_miranda_getStaticString(const SIPPROTO *pr, HANDLE hContact, const char* valueName, char* dest, unsigned dest_len);
DWORD sipe_miranda_getDword( const SIPPROTO *pr, HANDLE hContact, const char* name, DWORD* rv);
gboolean sipe_miranda_get_bool(const SIPPROTO *pr, const char *name, gboolean defval);

void sipe_miranda_setContactString(const SIPPROTO *pr, HANDLE hContact, const char* name, const char* value);
void sipe_miranda_setContactStringUtf(const SIPPROTO *pr, HANDLE hContact, const char* valueName, const char* parValue );
void sipe_miranda_setString(const SIPPROTO *pr, const char* name, const char* value);
void sipe_miranda_setStringUtf(const SIPPROTO *pr, const char* name, const char* value);
int sipe_miranda_setWord(const SIPPROTO *pr, HANDLE hContact, const char* szSetting, WORD wValue);

struct sipe_miranda_sel_entry* sipe_miranda_input_add(HANDLE fd, sipe_miranda_input_condition cond, sipe_miranda_input_function func, gpointer user_data);
gboolean sipe_miranda_input_remove(struct sipe_miranda_sel_entry *entry);

int SendBroadcast(SIPPROTO *pr, HANDLE hContact,int type,int result,HANDLE hProcess,LPARAM lParam);

char* sipe_miranda_eliminate_html(const char *string, int len);
unsigned short sipe_miranda_network_get_port_from_fd( HANDLE fd );
