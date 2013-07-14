#
# Fedora 19+: upgrade to mingw32-gcc 4.8.x breaks backward compatibility.
#             Fetch F18 packages of mingw32-gcc and set PIDGIN_MINGW_ROOT
# 	      and LD_LIBRARY_PATH to the local install root.
#
ifneq ($(wildcard $(PIDGIN_MINGW_ROOT)/bin/i686-w64-mingw32-*),)
# Fedora 17+
CC       := $(PIDGIN_MINGW_ROOT)/bin/i686-w64-mingw32-gcc
STRIP    := $(PIDGIN_MINGW_ROOT)/bin/i686-w64-mingw32-strip
WINDRES  := $(PIDGIN_MINGW_ROOT)/bin/i686-w64-mingw32-windres
EXTUTILS := /usr/share/perl5/ExtUtils
else ifneq ($(wildcard $(PIDGIN_MINGW_ROOT)/usr/bin/i686-pc-mingw32-*),)
# Fedora
CC       := $(PIDGIN_MINGW_ROOT)/usr/bin/i686-pc-mingw32-gcc
STRIP    := $(PIDGIN_MINGW_ROOT)/usr/bin/i686-pc-mingw32-strip
WINDRES  := $(PIDGIN_MINGW_ROOT)/usr/bin/i686-pc-mingw32-windres
EXTUTILS := /usr/share/perl5/ExtUtils
else
# Ubuntu
CC       := /usr/bin/i586-mingw32msvc-cc
STRIP    := /usr/bin/i586-mingw32msvc-strip
WINDRES  := /usr/bin/i586-mingw32msvc-windres
EXTUTILS := /usr/share/perl/5.10/ExtUtils
endif

# common
GMSGFMT := msgfmt
MAKENSIS := /usr/bin/makensis
PERL := /usr/bin/perl

INCLUDE_PATHS := -I\$(PIDGIN_TREE_TOP)/../win32-dev/w32api/include
LIB_PATHS := -L\$(PIDGIN_TREE_TOP)/../win32-dev/w32api/lib
