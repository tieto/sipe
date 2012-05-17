ifneq ($(wildcard /bin/i686-w64-mingw32-*),)
# Fedora 17+
CC       := /bin/i686-w64-mingw32-gcc
STRIP    := /bin/i686-w64-mingw32-strip
WINDRES  := /bin/i686-w64-mingw32-windres
EXTUTILS := /usr/share/perl5/ExtUtils
else ifneq ($(wildcard /usr/bin/i686-pc-mingw32-*),)
# Fedora
CC       := /usr/bin/i686-pc-mingw32-gcc
STRIP    := /usr/bin/i686-pc-mingw32-strip
WINDRES  := /usr/bin/i686-pc-mingw32-windres
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
