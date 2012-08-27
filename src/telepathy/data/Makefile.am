MAINTAINERCLEANFILES = \
	Makefile.in

# D-Bus service file
servicedir       = $(datadir)/dbus-1/services
service_in_files = org.freedesktop.Telepathy.ConnectionManager.sipe.service.in
service_DATA     = $(service_in_files:%.service.in=%.service)
profiledir       = $(datadir)/telepathy/profiles
profile_DATA     = sipe.profile
EXTRA_DIST       = $(service_in_files) sipe.profile
CLEANFILES       = $(service_DATA)

# Rule to make the service file with libexecdir expanded
$(service_DATA): $(service_in_files) Makefile
	$(AM_V_GEN)sed -e "s|\@libexecdir\@|$(libexecdir)|" $< >$@

