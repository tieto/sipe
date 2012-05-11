;NSIS Modern User Interface
;Basic Example Script
;Written by Joost Verburg

;--------------------------------
;Include Modern UI

!include "MUI.nsh"

;--------------------------------
;General

;Name and file
Name "Pidgin SIPE Plugin"
OutFile "pidgin-sipe-${VERSION}.exe"

;Default installation folder
InstallDir "$PROGRAMFILES\Pidgin"

;Get installation folder from registry if available
InstallDirRegKey HKLM "Software\pidgin" ""

;
SetCompressor /FINAL /SOLID lzma
SetCompressorDictSize 64

;--------------------------------
;Interface Settings

!define MUI_ABORTWARNING

;--------------------------------
;Pages

;!insertmacro MUI_PAGE_LICENSE "Basic.nsi"
;!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

;--------------------------------
;Languages

!insertmacro MUI_LANGUAGE "English"

;--------------------------------
;Installer Sections

Section "PidginSIPE" SecPidginSIPE
SetOutPath "$INSTDIR"
File "${TREETOP}\..\win32-dev\mingw\bin\libiconv-2.dll"
SetOutPath "$INSTDIR\plugins"
File "${TREETOP}\win32-install-dir\plugins\libsipe.dll"
SetOutPath "$INSTDIR\locale\ar\LC_MESSAGES"
File "${TREETOP}\win32-install-dir\locale\ar\LC_MESSAGES\pidgin-sipe.mo"
SetOutPath "$INSTDIR\locale\cs\LC_MESSAGES"
File "${TREETOP}\win32-install-dir\locale\cs\LC_MESSAGES\pidgin-sipe.mo"
SetOutPath "$INSTDIR\locale\da\LC_MESSAGES"
File "${TREETOP}\win32-install-dir\locale\da\LC_MESSAGES\pidgin-sipe.mo"
SetOutPath "$INSTDIR\locale\de\LC_MESSAGES"
File "${TREETOP}\win32-install-dir\locale\de\LC_MESSAGES\pidgin-sipe.mo"
SetOutPath "$INSTDIR\locale\es\LC_MESSAGES"
File "${TREETOP}\win32-install-dir\locale\es\LC_MESSAGES\pidgin-sipe.mo"
SetOutPath "$INSTDIR\locale\fi\LC_MESSAGES"
File "${TREETOP}\win32-install-dir\locale\fi\LC_MESSAGES\pidgin-sipe.mo"
SetOutPath "$INSTDIR\locale\fr\LC_MESSAGES"
File "${TREETOP}\win32-install-dir\locale\fr\LC_MESSAGES\pidgin-sipe.mo"
SetOutPath "$INSTDIR\locale\hi\LC_MESSAGES"
File "${TREETOP}\win32-install-dir\locale\hi\LC_MESSAGES\pidgin-sipe.mo"
SetOutPath "$INSTDIR\locale\hu\LC_MESSAGES"
File "${TREETOP}\win32-install-dir\locale\hu\LC_MESSAGES\pidgin-sipe.mo"
SetOutPath "$INSTDIR\locale\it\LC_MESSAGES"
File "${TREETOP}\win32-install-dir\locale\it\LC_MESSAGES\pidgin-sipe.mo"
SetOutPath "$INSTDIR\locale\ja\LC_MESSAGES"
File "${TREETOP}\win32-install-dir\locale\ja\LC_MESSAGES\pidgin-sipe.mo"
SetOutPath "$INSTDIR\locale\ko\LC_MESSAGES"
File "${TREETOP}\win32-install-dir\locale\ko\LC_MESSAGES\pidgin-sipe.mo"
SetOutPath "$INSTDIR\locale\nb\LC_MESSAGES"
File "${TREETOP}\win32-install-dir\locale\nb\LC_MESSAGES\pidgin-sipe.mo"
SetOutPath "$INSTDIR\locale\nl\LC_MESSAGES"
File "${TREETOP}\win32-install-dir\locale\nl\LC_MESSAGES\pidgin-sipe.mo"
SetOutPath "$INSTDIR\locale\pl\LC_MESSAGES"
File "${TREETOP}\win32-install-dir\locale\pl\LC_MESSAGES\pidgin-sipe.mo"
SetOutPath "$INSTDIR\locale\pt_BR\LC_MESSAGES"
File "${TREETOP}\win32-install-dir\locale\pt_BR\LC_MESSAGES\pidgin-sipe.mo"
SetOutPath "$INSTDIR\locale\ru\LC_MESSAGES"
File "${TREETOP}\win32-install-dir\locale\ru\LC_MESSAGES\pidgin-sipe.mo"
SetOutPath "$INSTDIR\locale\sv\LC_MESSAGES"
File "${TREETOP}\win32-install-dir\locale\sv\LC_MESSAGES\pidgin-sipe.mo"
SetOutPath "$INSTDIR\locale\ta\LC_MESSAGES"
File "${TREETOP}\win32-install-dir\locale\ta\LC_MESSAGES\pidgin-sipe.mo"
SetOutPath "$INSTDIR\locale\zh_CN\LC_MESSAGES"
File "${TREETOP}\win32-install-dir\locale\zh_CN\LC_MESSAGES\pidgin-sipe.mo"
SetOutPath "$INSTDIR\locale\zh_TW\LC_MESSAGES"
File "${TREETOP}\win32-install-dir\locale\zh_TW\LC_MESSAGES\pidgin-sipe.mo"
SetOutPath "$INSTDIR\pixmaps\pidgin\protocols\16"
File "${TREETOP}\win32-install-dir\pixmaps\pidgin\protocols\16\sipe.png"
SetOutPath "$INSTDIR\pixmaps\pidgin\protocols\22"
File "${TREETOP}\win32-install-dir\pixmaps\pidgin\protocols\22\sipe.png"
SetOutPath "$INSTDIR\pixmaps\pidgin\protocols\48"
File "${TREETOP}\win32-install-dir\pixmaps\pidgin\protocols\48\sipe.png"

;Create uninstaller
WriteUninstaller "$INSTDIR\Uninstall-pidgin-sipe.exe"

SectionEnd

;--------------------------------
;Descriptions

;Language strings
LangString DESC_SecPidginSIPE ${LANG_ENGLISH} "The Pidgin SIPE Plugin."

;Assign language strings to sections
;!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
;	!insertmacro MUI_DESCRIPTION_TEXT ${SecPidginPP} $(DESC_SecPidginPP)
;!insertmacro MUI_FUNCTION_DESCRIPTION_END

;--------------------------------
;Uninstaller Section

Section "Uninstall"

;ADD YOUR OWN FILES HERE...

Delete "$INSTDIR\Uninstall-pidgin-sipe.exe"
Delete "$INSTDIR\libiconv-2.dll"
Delete "$INSTDIR\plugins\libsipe.dll"
Delete "$INSTDIR\locale\ar\LC_MESSAGES\pidgin-sipe.mo"
Delete "$INSTDIR\locale\cs\LC_MESSAGES\pidgin-sipe.mo"
Delete "$INSTDIR\locale\da\LC_MESSAGES\pidgin-sipe.mo"
Delete "$INSTDIR\locale\de\LC_MESSAGES\pidgin-sipe.mo"
Delete "$INSTDIR\locale\es\LC_MESSAGES\pidgin-sipe.mo"
Delete "$INSTDIR\locale\fi\LC_MESSAGES\pidgin-sipe.mo"
Delete "$INSTDIR\locale\fr\LC_MESSAGES\pidgin-sipe.mo"
Delete "$INSTDIR\locale\hi\LC_MESSAGES\pidgin-sipe.mo"
Delete "$INSTDIR\locale\hu\LC_MESSAGES\pidgin-sipe.mo"
Delete "$INSTDIR\locale\it\LC_MESSAGES\pidgin-sipe.mo"
Delete "$INSTDIR\locale\ja\LC_MESSAGES\pidgin-sipe.mo"
Delete "$INSTDIR\locale\ko\LC_MESSAGES\pidgin-sipe.mo"
Delete "$INSTDIR\locale\nb\LC_MESSAGES\pidgin-sipe.mo"
Delete "$INSTDIR\locale\nl\LC_MESSAGES\pidgin-sipe.mo"
Delete "$INSTDIR\locale\output\LC_MESSAGES\pidgin-sipe.mo"
Delete "$INSTDIR\locale\pl\LC_MESSAGES\pidgin-sipe.mo"
Delete "$INSTDIR\locale\pt_BR\LC_MESSAGES\pidgin-sipe.mo"
Delete "$INSTDIR\locale\ru\LC_MESSAGES\pidgin-sipe.mo"
Delete "$INSTDIR\locale\sv\LC_MESSAGES\pidgin-sipe.mo"
Delete "$INSTDIR\locale\ta\LC_MESSAGES\pidgin-sipe.mo"
Delete "$INSTDIR\locale\zh_CN\LC_MESSAGES\pidgin-sipe.mo"
Delete "$INSTDIR\locale\zh_TW\LC_MESSAGES\pidgin-sipe.mo"
Delete "$INSTDIR\pixmaps\pidgin\protocols\16\sipe.png"
Delete "$INSTDIR\pixmaps\pidgin\protocols\22\sipe.png"
Delete "$INSTDIR\pixmaps\pidgin\protocols\48\sipe.png"

SectionEnd

