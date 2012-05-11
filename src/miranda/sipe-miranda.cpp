#include <glib.h>
#include "sipe-miranda.h"
#include "sipe-common.h"
#include "sipe-core.h"

#pragma warning(disable : 4996)
#pragma warning(disable : 4101)

HINSTANCE hInst;
PLUGINLINK* pluginLink;
MM_INTERFACE mmi;

/****************************************************************************
 * Struct that defines our interface with miranda
 ****************************************************************************/
PLUGININFOEX pluginInfo = {
	sizeof(PLUGININFOEX),
	"SIP/Simple Protocol",
	PLUGIN_MAKE_VERSION(9,12,19,12),
	"Support for SIP/Simple as used by Communicator 2007.",
	"See homepage",
	"",
	"(C)2010",
	"https://sourceforge.net/projects/sipe",
	UNICODE_AWARE,
	0,   //doesn't replace anything built-in
    #if defined( _UNICODE )
	{ 0x842395ed, 0x4e56, 0x40e5, { 0x94, 0x25, 0x28, 0x29, 0xd8, 0xab, 0xae, 0xa5 } } // {842395ED-4E56-40e5-9425-2829D8ABAEA5}
    #else
	{ 0x1ef8af37, 0xdec1, 0x4757, { 0x89, 0x78, 0xe8, 0xad, 0xd0, 0xd8, 0x6e, 0x7f } } // {1EF8AF37-DEC1-4757-8978-E8ADD0D86E7F}
    #endif
};

extern "C" PLUGININFOEX __declspec(dllexport) *MirandaPluginInfoEx(DWORD mirandaVersion)
{
	// Only load for 0.8.0.29 or greater
	// We need the core stubs for PS_GETNAME and PS_GETSTATUS
	if (mirandaVersion < PLUGIN_MAKE_VERSION(0, 8, 0, 29))
	{
		MessageBoxA( NULL, "SIP/Simple plugin cannot be loaded. It requires Miranda IM 0.8.0.29 or later.", "SIP/Simple Plugin",
			MB_OK|MB_ICONWARNING|MB_SETFOREGROUND|MB_TOPMOST );
		return NULL;
	}

	return &pluginInfo;
}

static const MUUID interfaces[] = {MIID_PROTOCOL, MIID_LAST};
extern "C" __declspec(dllexport) const MUUID* MirandaPluginInterfaces(void)
{
	return interfaces;
}

extern "C" BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason,LPVOID lpvReserved)
{
	hInst = hinstDLL;
	return TRUE;
}

/////////////////////////////////////////////////////////////////////////////////////////

static PROTO_INTERFACE* sipsimpleProtoInit( const char* pszProtoName, const TCHAR* tszUserName )
{
	return new CSipSimpleProto( pszProtoName, tszUserName );
}

static int sipsimpleProtoUninit( PROTO_INTERFACE* ppro )
{
	delete ( CSipSimpleProto* )ppro;
	return 0;
}

static int OnModulesLoaded( WPARAM, LPARAM )
{
	return 0;
}

extern "C" int __declspec(dllexport) Load(PLUGINLINK *link)
{
	pluginLink = link;

	sipe_core_init();
	mir_getMMI( &mmi );

	// Register the module
	PROTOCOLDESCRIPTOR pd = {0};
	pd.cbSize   = sizeof(pd);
	pd.szName   = SIPSIMPLE_PROTOCOL_NAME;
	pd.type     = PROTOTYPE_PROTOCOL;
	pd.fnInit   = sipsimpleProtoInit;
	pd.fnUninit = sipsimpleProtoUninit;
	CallService(MS_PROTO_REGISTERMODULE, 0, (LPARAM)&pd);

	return 0;
}

extern "C" int __declspec(dllexport) Unload(void)
{
	return 0;
}

/****************************************************************************
 * Implementation of the CSipSimpleProto class methods
 ****************************************************************************/
CSipSimpleProto::CSipSimpleProto( const char* aProtoName, const TCHAR* aUserName )
{
	m_szModuleName = mir_strdup(aProtoName);
	m_tszUserName = mir_tstrdup(aUserName);
	m_szProtoName = mir_strdup(aProtoName);

}

CSipSimpleProto::~CSipSimpleProto()
{
}

HANDLE CSipSimpleProto::AddToList( int flags, PROTOSEARCHRESULT* psr )
{
	return NULL;
}

HANDLE CSipSimpleProto::AddToListByEvent( int flags, int iContact, HANDLE hDbEvent )
{
	return NULL;
}

int CSipSimpleProto::Authorize( HANDLE hContact )
{
	return 0;
}

int CSipSimpleProto::AuthDeny( HANDLE hContact, const char* szReason )
{
	return 0;
}

int CSipSimpleProto::AuthRecv( HANDLE hContact, PROTORECVEVENT* )
{
	return 0;
}

int CSipSimpleProto::AuthRequest( HANDLE hContact, const char* szMessage )
{
	return 0;
}

HANDLE CSipSimpleProto::ChangeInfo( int iInfoType, void* pInfoData )
{
	return NULL;
}

HANDLE CSipSimpleProto::FileAllow( HANDLE hContact, HANDLE hTransfer, const char* szPath )
{
	return NULL;
}

int CSipSimpleProto::FileCancel( HANDLE hContact, HANDLE hTransfer )
{
	return 0;
}

int CSipSimpleProto::FileDeny( HANDLE hContact, HANDLE hTransfer, const char* szReason )
{
	return 0;
}

int CSipSimpleProto::FileResume( HANDLE hTransfer, int* action, const char** szFilename )
{
	return 0;
}

DWORD_PTR CSipSimpleProto::GetCaps( int type, HANDLE hContact )
{
	switch (type) {
		case PFLAGNUM_1:
			return PF1_IM | PF1_CHAT | PF1_USERIDISEMAIL | PF1_SEARCHBYNAME
				| PF1_AUTHREQ | PF1_SERVERCLIST | PF1_ADDSEARCHRES;

		case PFLAGNUM_2:
			return PF2_ONLINE | PF2_INVISIBLE | PF2_SHORTAWAY | PF2_LONGAWAY | PF2_LIGHTDND | PF2_HEAVYDND
				| PF2_OUTTOLUNCH | PF2_ONTHEPHONE;

		case PFLAGNUM_3:
			return 0;

		case PFLAGNUM_4:
			return PF4_NOCUSTOMAUTH | PF4_IMSENDUTF | PF4_SUPPORTTYPING;

		case PFLAGNUM_5:
			return 0;

		case PFLAG_UNIQUEIDSETTING:
			return (DWORD_PTR) SIP_UNIQUEID;
			break;
		default:
			return 0;
	}

	return 0;
}

HICON CSipSimpleProto::GetIcon( int iconIndex )
{
	return NULL;
}

int CSipSimpleProto::GetInfo( HANDLE hContact, int infoType )
{
	return 0;
}

HANDLE CSipSimpleProto::SearchBasic( const char* id )
{
	return NULL;
}

HANDLE CSipSimpleProto::SearchByEmail( const char* email )
{
	return NULL;
}

HANDLE CSipSimpleProto::SearchByName(const char *nick, const char *firstName, const char *lastName)
{
	return NULL;
}

HWND CSipSimpleProto::SearchAdvanced( HWND owner )
{
	return NULL;
}

HWND CSipSimpleProto::CreateExtendedSearchUI( HWND owner )
{
	return NULL;
}

int CSipSimpleProto::RecvContacts( HANDLE hContact, PROTORECVEVENT* )
{
	return 0;
}

int CSipSimpleProto::RecvFile( HANDLE hContact, PROTORECVFILE* )
{
	return 0;
}

int CSipSimpleProto::RecvMsg(HANDLE hContact, PROTORECVEVENT* pre)
{
	return 0;
}

int CSipSimpleProto::RecvUrl( HANDLE hContact, PROTORECVEVENT* )
{
	return 0;
}

int CSipSimpleProto::SendContacts( HANDLE hContact, int flags, int nContacts, HANDLE* hContactsList )
{
	return 0;
}

HANDLE CSipSimpleProto::SendFile( HANDLE hContact, const char* szDescription, char** ppszFiles )
{
	return 0;
}

int CSipSimpleProto::SendMsg( HANDLE hContact, int flags, const char* msg )
{
	return 1;
}

int CSipSimpleProto::SendUrl( HANDLE hContact, int flags, const char* url )
{
	return 0;
}

int CSipSimpleProto::SetApparentMode( HANDLE hContact, int mode )
{
	return 0;
}

int CSipSimpleProto::SetStatus( int iNewStatus )
{
	return 0;
}

HANDLE CSipSimpleProto::GetAwayMsg( HANDLE hContact )
{
	return NULL;
}

int CSipSimpleProto::RecvAwayMsg( HANDLE hContact, int mode, PROTORECVEVENT* evt )
{
	return 0;
}

int CSipSimpleProto::SendAwayMsg( HANDLE hContact, HANDLE hProcess, const char* msg )
{
	return 0;
}

int CSipSimpleProto::SetAwayMsg( int m_iStatus, const char* msg )
{
	return 0;
}

int CSipSimpleProto::UserIsTyping( HANDLE hContact, int type )
{
	return 1;
}

int CSipSimpleProto::OnEvent( PROTOEVENTTYPE eventType, WPARAM wParam, LPARAM lParam )
{
	return 0;
}

