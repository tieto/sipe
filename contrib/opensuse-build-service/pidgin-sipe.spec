#
# OBS SPEC file to generate a RPM for pidgin-sipe.
#
# It has support for:
#
#     RedHat family (CentOS, Fedora, RHEL, ScientificLinux)
#     SUSE family (openSUSE, SLED, SLES)
#     Mageia
#     Windows (mingw32, mingw64)
#

# Build options
%undefine build_telepathy

# Check for mingw32 cross compilation build
#
# Manually add this repository to your private OBS project:
#
#  <repository name="mingw32">
#    <path repository="openSUSE_13.2" project="windows:mingw:win32"/>
#    <arch>i586</arch>
#  </repository>
#
%if "%{_repository}" == "mingw32"
%define purple_sipe_mingw32 1
%define mingw_prefix        mingw32-
%define mingw_cache         %{_mingw32_cache}
%define mingw_configure     %{_mingw32_configure}
%define mingw_datadir       %{_mingw32_datadir}
%define mingw_debug_package %{_mingw32_debug_package}
%define mingw_ldflags       MINGW32_LDFLAGS
%define mingw_libdir        %{_mingw32_libdir}
%define mingw_make          %{_mingw32_make}
%define mingw_makeinstall   %{_mingw32_makeinstall}
%define __strip             %{_mingw32_strip}
%define __objdump           %{_mingw32_objdump}
%define _use_internal_dependency_generator 0
%define __find_requires     %{_mingw32_findrequires}
%define __find_provides     %{_mingw32_findprovides}
%define __os_install_post   %{_mingw32_debug_install_post} \
                            %{_mingw32_install_post}
%endif

# Check for mingw64 cross compilation build
#
# Manually add this repository to your private OBS project:
#
#  <repository name="mingw64">
#    <path repository="openSUSE_13.2" project="windows:mingw:win64"/>
#    <arch>i586</arch>
#  </repository>
#
%if "%{_repository}" == "mingw64"
%define purple_sipe_mingw64 1
%define mingw_prefix        mingw64-
%define mingw_cache         %{_mingw64_cache}
%define mingw_configure     %{_mingw64_configure}
%define mingw_datadir       %{_mingw64_datadir}
%define mingw_debug_package %{_mingw64_debug_package}
%define mingw_ldflags       MINGW64_LDFLAGS
%define mingw_libdir        %{_mingw64_libdir}
%define mingw_make          %{_mingw64_make}
%define mingw_makeinstall   %{_mingw64_makeinstall}
%define __strip             %{_mingw64_strip}
%define __objdump           %{_mingw64_objdump}
%define _use_internal_dependency_generator 0
%define __find_requires     %{_mingw64_findrequires}
%define __find_provides     %{_mingw64_findprovides}
%define __os_install_post   %{_mingw64_debug_install_post} \
                            %{_mingw64_install_post}
%endif

%define purple_plugin    %{?mingw_prefix:%{mingw_prefix}}libpurple-plugin-sipe
%define telepathy_plugin %{?mingw_prefix:%{mingw_prefix}}telepathy-plugin-sipe
%define nsis_package     %{?mingw_prefix:%{mingw_prefix}}pidgin-sipe-nsis
%define common_files     sipe-common
%define empathy_files    empathy-sipe
%define ktp_files        ktp-accounts-kcm-sipe


%if 0%{?mageia}
%if %{mageia} > 6
%define has_freerdp 1
%define has_gssntlmssp 1
%else
%define has_appstream_legacy 1
%endif
%define has_appstream 1
%define has_gstreamer 1
%endif

%if 0%{?suse_version}
%if 0%{?is_opensuse}
%define has_appstream 1
%define has_appstream_legacy 1
%if 0%{?suse_version} >= 1500
%define has_freerdp 1
%else
%define build_empathy 1
%endif
%endif
%define has_gstreamer 1
%define build_telepathy 1
%endif

%if 0%{?suse_version}
%define pkg_group Productivity/Networking/Instant Messenger
%else
%define pkg_group Applications/Communications
%endif

# workaround for Fedora Rawhide
%if 0%{?fedora_version}
%if 0%{?fedora}
%else
%define fedora %{?fedora_version}
%endif
%endif

%if 0%{?fedora}
%define has_appstream 1
%if %{fedora} <= 29
%define build_empathy 1
%endif
%if %{fedora} <= 26
%define has_appstream_legacy 1
%endif
%if %{fedora} > 25
%define has_freerdp 1
%endif
%define has_gssntlmssp 1
%define has_gstreamer 1
%define build_telepathy 1
%define build_ktp 1
%endif

%if 0%{?centos_version} || 0%{?scientificlinux_version}
%define has_krb5devel 1
%define rhel_base_version %{?centos_version}%{?scientificlinux_version}
%if %{rhel_base_version} >= 800
%define has_gstreamer 1
%endif
%endif

%if 0%{?purple_sipe_mingw32}
Name:           mingw32-pidgin-sipe
%else
%if 0%{?purple_sipe_mingw64}
Name:           mingw64-pidgin-sipe
%else
Name:           pidgin-sipe
%endif
%endif
Summary:        Pidgin protocol plugin to connect to MS Office Communicator
Version:        1.25.0
Release:        1
Source:         pidgin-sipe-%{version}.tar.gz
Group:          %{pkg_group}
License:        GPL-2.0-or-later
URL:            http://sipe.sourceforge.net/

BuildRoot:      %{_tmppath}/%{name}-%{version}-build

%if 0%{?mingw_prefix:1}
#
# Windows cross-compilation build setup
#
BuildArch:      noarch
#!BuildIgnore:   post-build-checks

BuildRequires:  libtool
BuildRequires:  intltool
BuildRequires:  %{mingw_prefix}filesystem >= 23
BuildRequires:  %{mingw_prefix}cross-gcc
BuildRequires:  %{mingw_prefix}cross-binutils
BuildRequires:  %{mingw_prefix}gettext-runtime
BuildRequires:  %{mingw_prefix}cross-pkg-config
BuildRequires:  %{mingw_prefix}glib2-devel >= 2.18.0
BuildRequires:  %{mingw_prefix}libxml2-devel
BuildRequires:  %{mingw_prefix}mozilla-nss-devel
BuildRequires:  %{mingw_prefix}libpurple-devel >= 2.7.0
BuildRequires:  %{mingw_prefix}cross-nsis

# For directory ownership
BuildRequires:  %{mingw_prefix}pidgin

# Make sure telepathy is disabled for Windows builds
%undefine build_telepathy

%else
#
# Standard Linux build setup
#
BuildRequires:  gcc
BuildRequires:  libtool
BuildRequires:  intltool
BuildRequires:  pkgconfig(dbus-1)
BuildRequires:  pkgconfig(glib-2.0) >= 2.18.0
BuildRequires:  pkgconfig(gmodule-2.0) >= 2.18.0
BuildRequires:  pkgconfig(libxml-2.0)
BuildRequires:  pkgconfig(nss)
BuildRequires:  pkgconfig(purple) >= 2.7.0
%if 0%{?mageia}
# It seems linking against -lpurple is severely broken on Mageia...
BuildRequires:  pkgconfig(libgadu)
%if %{mageia} > 7
# -lpurple depends on this but doesn't have a dependency in -devel?
BuildRequires:  pkgconfig(libnm)
%endif
%endif
%if 0%{?has_appstream:1}
%if 0%{?suse_version}
BuildRequires:  AppStream
%else
BuildRequires:  appstream
%endif
%endif
%if 0%{?has_gstreamer:1}
BuildRequires:  pkgconfig(farstream-0.2)
BuildRequires:  pkgconfig(gio-2.0)
BuildRequires:  pkgconfig(gstreamer-1.0)
BuildRequires:  pkgconfig(gstreamer-rtp-1.0)
BuildRequires:  pkgconfig(nice) >= 0.1.0
# Requirements for appshare server
%if 0%{?has_freerdp:1}
BuildRequires:  pkgconfig(freerdp-shadow2)
%endif
%endif
# Requirements for telepathy backend
%if 0%{?build_telepathy:1}
BuildRequires:  gmime-devel
BuildRequires:  pkgconfig(dbus-glib-1)
BuildRequires:  pkgconfig(gio-2.0) >= 2.32.0
BuildRequires:  pkgconfig(glib-2.0) >= 2.32.0
BuildRequires:  pkgconfig(gobject-2.0)
BuildRequires:  pkgconfig(telepathy-glib) >= 0.24.0
%endif

# Configurable components
# Use "--without kerberos" to disable krb5
%if !0%{?_without_kerberos:1}
%if 0%{?has_krb5devel:1}
BuildRequires:  krb5-devel
%else
BuildRequires:  pkgconfig(krb5)
%endif
%if 0%{?has_gssntlmssp:1}
BuildRequires:  gssntlmssp-devel >= 0.5.0
Requires:       gssntlmssp >= 0.5.0
%endif
%endif

# For directory ownership
BuildRequires:  pidgin
Requires:       pidgin
%if 0%{?build_telepathy:1}
%if 0%{?build_empathy:1}
BuildRequires:  empathy
%endif
%endif

# End Windows cross-compilation/Linux build setup
%endif

Requires:       %{purple_plugin} = %{?epoch:%{epoch}:}%{version}-%{release}


%description
A third-party plugin for the Pidgin multi-protocol instant messenger.
It implements the extended version of SIP/SIMPLE used by various products:

    * Skype for Business
    * Microsoft Office 365
    * Microsoft Business Productivity Online Suite (BPOS)
    * Microsoft Lync Server
    * Microsoft Office Communications Server (OCS 2007/2007 R2)
    * Microsoft Live Communications Server (LCS 2003/2005)

With this plugin you should be able to replace your Microsoft Office
Communicator client with Pidgin.

This package provides the icon set for Pidgin.


%package -n %{purple_plugin}
Summary:        Libpurple protocol plugin to connect to MS Office Communicator
Group:          %{pkg_group}
License:        GPL-2.0-or-later
Obsoletes:      purple-sipe
%if 0%{?build_telepathy:1}
Requires:       %{common_files} = %{?epoch:%{epoch}:}%{version}-%{release}
%endif

%description -n %{purple_plugin}
A third-party plugin for the Pidgin multi-protocol instant messenger.
It implements the extended version of SIP/SIMPLE used by various products:

    * Skype for Business
    * Microsoft Office 365
    * Microsoft Business Productivity Online Suite (BPOS)
    * Microsoft Lync Server
    * Microsoft Office Communications Server (OCS 2007/2007 R2)
    * Microsoft Live Communications Server (LCS 2003/2005)

This package provides the protocol plugin for libpurple clients.


%if 0%{?build_telepathy:1}
%if 0%{?build_empathy:1}
%package -n %{empathy_files}
Summary:        Telepathy connection manager to connect to MS Office Communicator
Group:          %{pkg_group}
License:        GPL-2.0-or-later
Requires:       empathy
Requires:       %{telepathy_plugin} = %{?epoch:%{epoch}:}%{version}-%{release}

%description -n %{empathy_files}
A Telepathy connection manager that implements the extended version of
SIP/SIMPLE used by various products:

    * Skype for Business
    * Microsoft Office 365
    * Microsoft Business Productivity Online Suite (BPOS)
    * Microsoft Lync Server
    * Microsoft Office Communications Server (OCS 2007/2007 R2)
    * Microsoft Live Communications Server (LCS 2003/2005)

This package provides the icon set for Empathy.
%endif


%if 0%{?build_ktp:1}
%package -n %{ktp_files}
Summary:        Telepathy connection manager to connect to MS Office Communicator
Group:          %{pkg_group}
License:        GPL-2.0-or-later
Requires:       %{telepathy_plugin} = %{?epoch:%{epoch}:}%{version}-%{release}

%description -n %{ktp_files}
A Telepathy connection manager that implements the extended version of
SIP/SIMPLE used by various products:

    * Skype for Business
    * Microsoft Office 365
    * Microsoft Business Productivity Online Suite (BPOS)
    * Microsoft Lync Server
    * Microsoft Office Communications Server (OCS 2007/2007 R2)
    * Microsoft Live Communications Server (LCS 2003/2005)

This package provides the profile for KTP account manager.
%endif


%package -n %{telepathy_plugin}
Summary:        Telepathy connection manager to connect to MS Office Communicator
Group:          %{pkg_group}
License:        GPL-2.0-or-later
Requires:       %{common_files} = %{?epoch:%{epoch}:}%{version}-%{release}

%description -n %{telepathy_plugin}
A Telepathy connection manager that implements the extended version of
SIP/SIMPLE used by various products:

    * Skype for Business
    * Microsoft Office 365
    * Microsoft Business Productivity Online Suite (BPOS)
    * Microsoft Lync Server
    * Microsoft Office Communications Server (OCS 2007/2007 R2)
    * Microsoft Live Communications Server (LCS 2003/2005)

This package provides the protocol support for Telepathy clients.


%package -n %{common_files}
Summary:        Common files for SIPE protocol plugins
Group:          %{pkg_group}
License:        GPL-2.0-or-later
BuildArch:      noarch

%description -n %{common_files}
This package provides common files for the SIPE protocol plugins:

    * Localisation
%endif


%if 0%{?mingw_prefix:1}
%package -n %{nsis_package}
Summary:        Windows Pidgin protocol plugin to connect to MS Office Communicator
Group:          %{pkg_group}
License:        GPL-2.0-or-later

%description -n %{nsis_package}
A third-party plugin for the Pidgin multi-protocol instant messenger.
It implements the extended version of SIP/SIMPLE used by various products:

    * Skype for Business
    * Microsoft Office 365
    * Microsoft Business Productivity Online Suite (BPOS)
    * Microsoft Lync Server
    * Microsoft Office Communications Server (OCS 2007/2007 R2)
    * Microsoft Live Communications Server (LCS 2003/2005)

This package contains the NSIS installer package of the protocol plugin
for Pidgin on Windows.
%endif


%{mingw_debug_package}


%prep
%setup -q -n pidgin-sipe-%{version}

%build
%if 0%{?mingw_prefix:1}
#
# Windows cross-compilation build
#
%{?env_options}
echo "lt_cv_deplibs_check_method='pass_all'" >>%{mingw_cache}
autoreconf --verbose --install --force
%{mingw_ldflags}="-Wl,--exclude-libs=libintl.a -Wl,--exclude-libs=libiconv.a -lws2_32"
%{mingw_configure} \
    --enable-purple \
%if 0%{?build_telepathy:1}
    --enable-telepathy
%else
    --disable-telepathy
%endif
%{mingw_make} %{?_smp_mflags} || %{mingw_make}

%else
#
# Standard Linux build
#
# Special case handling for Mageia
%if 0%{?mageia}
%configure2_5x \
    --with-krb5 \
    --with-vv \
    --disable-telepathy
%make_build
%make_build check

# All other Linuxes
%else
%configure \
%if !0%{?has_appstream:1}
    --without-appstream \
%endif
%if !0%{?_without_kerberos:1}
    --with-krb5 \
%endif
%if 0%{?has_gstreamer:1}
    --with-vv \
%endif
    --enable-purple \
%if 0%{?build_telepathy:1}
    --enable-telepathy
%else
    --disable-telepathy
%endif
make %{?_smp_mflags}
make %{?_smp_mflags} check
%endif

# End Windows cross-compilation/Linux build setup
%endif


%install
%if 0%{?mingw_prefix:1}
#
# Windows cross-compilation install
#
%{mingw_makeinstall}
rm -f %{buildroot}%{mingw_libdir}/purple-2/*.dll.a

# generate .dbgsym file
rm -f %{buildroot}%{mingw_libdir}/purple-2/libsipe.dll.dbgsym
mv \
    %{buildroot}%{mingw_libdir}/purple-2/libsipe.dll \
    %{buildroot}%{mingw_libdir}/purple-2/libsipe.dll.dbgsym
%{__strip} --strip-unneeded \
    %{buildroot}%{mingw_libdir}/purple-2/libsipe.dll.dbgsym \
    -o %{buildroot}%{mingw_libdir}/purple-2/libsipe.dll \

# generate NSIS installer package
perl contrib/opensuse-build-service/generate_nsi.pl po/LINGUAS \
    <contrib/opensuse-build-service/pidgin-sipe.nsi.template \
    >%{buildroot}/pidgin-sipe.nsi
( \
    set -e; \
    cd %{buildroot}; \
    makensis \
        -DPIDGIN_VERSION=UNKNOWN \
        -DVERSION=%{version} \
        -DMINGW_LIBDIR=%{buildroot}%{mingw_libdir} \
        -DMINGW_DATADIR=%{buildroot}%{mingw_datadir} \
        pidgin-sipe.nsi \
)
rm -f %{buildroot}/pidgin-sipe.nsi

%else
#
# Standard Linux install
#
%make_install

# End Windows cross-compilation/Linux build setup
%endif

find %{buildroot} -type f -name "*.la" -delete -print
# Pidgin doesn't have 24 or 32 pixel icons
rm -f \
   %{buildroot}%{_datadir}/pixmaps/pidgin/protocols/24/sipe.png \
   %{buildroot}%{_datadir}/pixmaps/pidgin/protocols/32/sipe.png
%if 0%{?has_appstream_legacy:1}
mv %{buildroot}/%{_datadir}/metainfo %{buildroot}/%{_datadir}/appdata
%endif
%if 0%{?build_telepathy:1}
%if !0%{?build_empathy:1}
rm -r %{buildroot}%{_datadir}/empathy
%endif
%if !0%{?build_ktp:1}
rm -r %{buildroot}%{_datadir}/telepathy
%endif
%endif
%find_lang pidgin-sipe


%if 0%{?build_telepathy:1}
%files -n %{purple_plugin}
%else
%files -n %{purple_plugin} -f pidgin-sipe.lang
%endif
%defattr(-,root,root,-)
%doc AUTHORS ChangeLog COPYING NEWS README TODO
%if 0%{?mingw_prefix:1}
%{mingw_libdir}/purple-2/libsipe.dll
%{mingw_libdir}/purple-2/libsipe.dll.dbgsym
%else
%{_libdir}/purple-2/libsipe.so
%endif


%if 0%{?build_telepathy:1}
%if 0%{?build_empathy:1}
%files -n %{empathy_files}
%defattr(-,root,root,-)
%{_datadir}/empathy/icons/hicolor/*/apps/im-sipe.png
%{_datadir}/empathy/icons/hicolor/*/apps/im-sipe.svg
%endif


%if 0%{?build_ktp:1}
%files -n %{ktp_files}
%defattr(-,root,root,-)
%doc AUTHORS COPYING
%{_datadir}/telepathy/profiles/sipe.profile
%endif


%files -n %{telepathy_plugin}
%defattr(-,root,root,-)
%doc AUTHORS ChangeLog COPYING NEWS README TODO
%{_datadir}/dbus-1/services/*.sipe.service
%{_libexecdir}/telepathy-sipe


%files -n %{common_files} -f pidgin-sipe.lang
%defattr(-,root,root,-)
%endif


%files
%defattr(-,root,root,-)
%doc AUTHORS COPYING
%if 0%{?mingw_prefix:1}
%if 0%{?has_appstream:1}
%{mingw_datadir}/metainfo/pidgin-sipe.metainfo.xml
%endif
%{mingw_datadir}/pixmaps/pidgin/protocols/*/sipe.png
%{mingw_datadir}/pixmaps/pidgin/protocols/*/sipe.svg
%else
%if 0%{?has_appstream:1}
%if 0%{?has_appstream_legacy:1}
%{_datadir}/appdata/%{name}.metainfo.xml
%else
%{_datadir}/metainfo/%{name}.metainfo.xml
%endif
%endif
%{_datadir}/pixmaps/pidgin/protocols/*/sipe.png
%{_datadir}/pixmaps/pidgin/protocols/*/sipe.svg
%endif


%if 0%{?mingw_prefix:1}
%files -n %{nsis_package}
%defattr(-, root, root)
/pidgin-sipe-%{version}.exe
%endif


%changelog
* Tue Oct 15 2019 J. D. User <jduser@noreply.com> 1.25.0-*git*
- make sure V&V features are really enabled when requested

* Sat Oct 12 2019 J. D. User <jduser@noreply.com> 1.25.0
- update to 1.25.0

* Fri Oct 04 2019 J. D. User <jduser@noreply.com> 1.24.0-*git*
- add BR libnm for Mageia 8+

* Tue Jul 02 2019 J. D. User <jduser@noreply.com> 1.24.0-*git*
- add freerdp & gssntlmssp for Mageia 7+

* Sun Jun 30 2019 J. D. User <jduser@noreply.com> 1.24.0-*git*
- switch to SPDX identifier GPL-2.0-or-later

* Sun Jun 30 2019 J. D. User <jduser@noreply.com> 1.24.0-*git*
- newer distros no longer package empathy

* Sun Jun 30 2019 J. D. User <jduser@noreply.com> 1.24.0-*git*
- raise BR telepathy-glib >= 0.24.0

* Sat Nov 10 2018 J. D. User <jduser@noreply.com> 1.24.0
- update to 1.24.0

* Sat Sep 01 2018 J. D. User <jduser@noreply.com> 1.23.3-*git*
- update support for CentOS & Scientific Linux 7

* Mon Aug 27 2018 J. D. User <jduser@noreply.com> 1.23.3-*git*
- add BR freerdp-shadow2

* Mon Aug 20 2018 J. D. User <jduser@noreply.com> 1.23.3
- update to 1.23.3

* Sat Mar 10 2018 J. D. User <jduser@noreply.com> 1.23.2
- update to 1.23.2

* Sun Feb 25 2018 J. D. User <jduser@noreply.com> 1.23.1
- update to 1.23.1

* Sun Feb 18 2018 J. D. User <jduser@noreply.com> 1.23.0-*git*
- remove obsolete clean section

* Sun Feb 18 2018 J. D. User <jduser@noreply.com> 1.23.0-*git*
- add BR gcc

* Mon Nov 06 2017 J. D. User <jduser@noreply.com> 1.23.0-*git*
- add BR appstream

* Sun Nov 05 2017 J. D. User <jduser@noreply.com> 1.23.0-*git*
- add support for new AppStream metadata file location

* Sat Oct 28 2017 J. D. User <jduser@noreply.com> 1.23.0
- update to 1.23.0
- raise BR glib-2.0 >= 2.18.0
- raise BR purple >= 2.7.0

* Fri Aug 11 2017 J. D. User <jduser@noreply.com> 1.22.1-*git*
- add BR dbus-1
- fix incorrect BR gstreamer-0.10 when gstreamer-1.0 is selected

* Sun Jun 11 2017 J. D. User <jduser@noreply.com> 1.22.1
- update to 1.22.1

* Wed Feb 01 2017 J. D. User <jduser@noreply.com> 1.22.0
- update to 1.22.0

* Sun Dec 18 2016 J. D. User <jduser@noreply.com> 1.21.1-*git*
- add BR gio-2.0

* Wed Jun 15 2016 J. D. User <jduser@noreply.com> 1.21.1-*git*
- add BR farstream-0.2

* Sat May 28 2016 J. D. User <jduser@noreply.com> 1.21.1
- update to 1.21.1

* Sat Apr 23 2016 J. D. User <jduser@noreply.com> 1.21.0
- update to 1.21.0

* Tue Apr 05 2016 J. D. User <jduser@noreply.com> 1.20.1-*git*
- align with Fedora SPEC file

* Fri Jan 01 2016 J. D. User <jduser@noreply.com> 1.20.1-*git*
- add AppStream metadata file

* Sun Nov 08 2015 J. D. User <jduser@noreply.com> 1.20.1-*git*
- add dependency on pkgconfig(gstreamer-1.0) for F22+ & Leap 42.1+

* Sat Oct 24 2015 J. D. User <jduser@noreply.com> 1.20.1
- update to 1.20.1

* Thu Sep 03 2015 J. D. User <jduser@noreply.com> 1.20.0-*git*
- we also support "Skype for Business"

* Sat Aug 29 2015 J. D. User <jduser@noreply.com> 1.20.0
- update to 1.20.0

* Sat Apr 04 2015 J. D. User <jduser@noreply.com> 1.19.1
- update to 1.19.1

* Sat Feb 07 2015 J. D. User <jduser@noreply.com> 1.19.0
- update to 1.19.0

* Tue Jan 06 2015 J. D. User <jduser@noreply.com> 1.18.5-*git*
- add dependency on gssntlmssp(-devel) >= 0.5.0 for F21+

* Mon Jan 05 2015 J. D. User <jduser@noreply.com> 1.18.5-*git*
- remove support for obsolete distributions
    - Fedora < 19
    - Mandriva
    - OpenSUSE < 13.x

* Mon Dec 29 2014 J. D. User <jduser@noreply.com> 1.18.5
- update to 1.18.5

* Thu Dec 18 2014 J. D. User <jduser@noreply.com> 1.18.4-*git*
- improve support for CentOS & Scientific Linux

* Sat Oct 18 2014 J. D. User <jduser@noreply.com> 1.18.4
- update to 1.18.4

* Sat Aug 16 2014 J. D. User <jduser@noreply.com> 1.18.3
- update to 1.18.3

* Sat Jun 07 2014 J. D. User <jduser@noreply.com> 1.18.2
- update to 1.18.2

* Sat Apr 12 2014 J. D. User <jduser@noreply.com> 1.18.1
- update to 1.18.1

* Tue Mar 04 2014 J. D. User <jduser@noreply.com> 1.18.0-*git*
- F20+/openSUSE 12.2+ require libnice gstreamer-0.10 plugin

* Sat Jan 11 2014 J. D. User <jduser@noreply.com> 1.18.0
- update to 1.18.0

* Wed Dec 11 2013 J. D. User <jduser@noreply.com> 1.17.3
- update to 1.17.3

* Sat Nov 30 2013 J. D. User <jduser@noreply.com> 1.17.2
- update to 1.17.2

* Sat Nov 16 2013 J. D. User <jduser@noreply.com> 1.17.1
- update to 1.17.1

* Sat Sep 21 2013 J. D. User <jduser@noreply.com> 1.17.0
- update to 1.17.0

* Sat Jul 13 2013 J. D. User <jduser@noreply.com> 1.16.1
- update to 1.16.1

* Fri Jun 14 2013 J. D. User <jduser@noreply.com> 1.16.0
- update to 1.16.0

* Sun Apr 07 2013 J. D. User <jduser@noreply.com> 1.15.1
- update to 1.15.1

* Fri Mar 29 2013 J. D. User <jduser@noreply.com> 1.15.0-*git*
- update package description texts

* Sat Mar 09 2013 J. D. User <jduser@noreply.com> 1.15.0
- update to 1.15.0

* Wed Dec 26 2012 J. D. User <jduser@noreply.com> 1.14.1
- update to 1.14.1

* Sun Dec 16 2012 J. D. User <jduser@noreply.com> 1.14.0
- update to 1.14.0

* Tue Sep 25 2012 J. D. User <jduser@noreply.com> 1.13.3-*git*
- change BR gstreamer-devel to pkgconfig(gstreamer-0.10)

* Sun Sep 09 2012 J. D. User <jduser@noreply.com> 1.13.3-*git*
- BR telepathy-glib-devel >= 0.18.0

* Wed Sep 05 2012 J. D. User <jduser@noreply.com> 1.13.3-*git*
- BR telepathy-glib-devel >= 0.14.0

* Sun Sep 02 2012 J. D. User <jduser@noreply.com> 1.13.3-*git*
- really disable telepathy for Windows cross-compilation builds

* Thu Aug 30 2012 J. D. User <jduser@noreply.com> 1.13.3-*git*
- updates to enable telepathy build

* Sun Aug 19 2012 J. D. User <jduser@noreply.com> 1.13.3
- update to 1.13.3

* Sun Jun 10 2012 J. D. User <jduser@noreply.com> 1.13.2
- update to 1.13.2

* Mon Apr 09 2012 J. D. User <jduser@noreply.com> 1.13.1
- update to 1.13.1

* Wed Mar 14 2012 J. D. User <jduser@noreply.com> 1.13.0
- update to 1.13.0

* Mon Dec 12 2011 J. D. User <jduser@noreply.com> 1.12.0-*git*
- we do support Microsoft Lync Server 2010 now.

* Tue Dec 06 2011 J. D. User <jduser@noreply.com> 1.12.0-*git*
- update GPL2 license name

* Sat Nov 12 2011 J. D. User <jduser@noreply.com> 1.12.0-*git*
- add BR gmime-devel for Fedora to have at least one verification platform

* Sun Nov 06 2011 J. D. User <jduser@noreply.com> 1.12.0-*git*
- fix Mandriva 2011 unresolvable BR

* Mon Oct 31 2011 J. D. User <jduser@noreply.com> 1.12.0-*git*
- add BR nss-devel

* Sat Oct 01 2011 J. D. User <jduser@noreply.com> 1.12.0-*git*
- add NSIS package for mingw builds

* Sat Oct 01 2011 J. D. User <jduser@noreply.com> 1.12.0-*git*
- add mingw64 build

* Wed Sep 28 2011 J. D. User <jduser@noreply.com> 1.12.0-*git*
- remove BR mingw32-mozilla-nss-devel, not needed for SSPI.

* Mon Sep 19 2011 J. D. User <jduser@noreply.com> 1.12.0-*git*
- update mingw32 build
- update descriptions

* Mon Aug 29 2011 J. D. User <jduser@noreply.com> 1.12.0
- update to 1.12.0

* Wed Jun 22 2011 J. D. User <jduser@noreply.com> 1.11.2-*git*
- add gstreamer-devel to enable Voice & Video features

* Sat Dec 11 2010 J. D. User <jduser@noreply.com> 1.11.2-*git*
- add optional subpackage for telepathy connection manager

* Tue Nov 02 2010 J. D. User <jduser@noreply.com> 1.11.2
- update to 1.11.2

* Sun Oct 24 2010 J. D. User <jduser@noreply.com> 1.11.1
- update to 1.11.1

* Fri Oct 15 2010 J. D. User <jduser@noreply.com> 1.11.0-*git*
- add mingw32 build configuration

* Sun Oct 03 2010 J. D. User <jduser@noreply.com> 1.11.0
- update to 1.11.0

* Thu Sep 02 2010 J. D. User <jduser@noreply.com> pre-1.11.0-*git*
- Mandriva config for OBS has changed

* Tue May 04 2010 J. D. User <jduser@noreply.com> 1.10.0-*git*
- add libnice build information discovered through OBS testing

* Mon Apr 12 2010 J. D. User <jduser@noreply.com> 1.10.0-*git*
- add NSS build information discovered through OBS testing

* Sun Apr 04 2010 pier11 <pier11@operamail.com> 1.10.0
- release

* Fri Apr 02 2010 J. D. User <jduser@noreply.com> pre-1.10.0-*git*
- Mandriva has too old libtool version

* Fri Apr 02 2010 J. D. User <jduser@noreply.com> pre-1.10.0-*git*
- SLE11, openSUSE 11.0/1 don't have pidgin/protocols/scalable directory

* Thu Apr 01 2010 pier11 <pier11@operamail.com> pre-1.10.0-*git*
- OBS tests of pre-1.10.0 git-snapshot 4fa20cd65e5be0e469d4aa55d861f11c5b08b816

* Sun Mar 28 2010 J. D. User <jduser@noreply.com> 1.9.1-*git*
- added --enable/--disable build options

* Sun Mar 28 2010 J. D. User <jduser@noreply.com> 1.9.1-*git*
- removed --with-krb5 configure option as it is autodetected now

* Tue Mar 23 2010 J. D. User <jduser@noreply.com> 1.9.1-*git*
- add SVG icon

* Sat Mar 20 2010 J. D. User <jduser@noreply.com> 1.9.1-*git*
- add BR glib2-devel >= 2.12.0

* Wed Mar 17 2010 J. D. User <jduser@noreply.com> 1.9.1-*git*
- add tests to build

* Tue Mar 16 2010 J. D. User <jduser@noreply.com> 1.9.1
- update to 1.9.1

* Thu Mar 11 2010 J. D. User <jduser@noreply.com> 1.9.0-*git*
- add BR libxml2-devel

* Wed Mar 10 2010 pier11 <pier11@operamail.com> 1.9.0
- release
- dropped SLE 10 due to libpurple min version increase
- updated target distros in comment line

* Mon Mar 08 2010 J. D. User <jduser@noreply.com> 1.9.0-*git*
- increased libpurple build requisite to >= 2.4.0

* Sun Mar 07 2010 pier11 <pier11@operamail.com> pre-1.9.0-*git*
- OBS tests of pre-1.9.0 git-snapshot 61ea0856855483b9e18f23a87afe47437e526f0e

* Sun Mar 07 2010 J. D. User <jduser@noreply.com> 1.8.1-*git*
- sync with RPM SPEC from contrib/rpm

* Mon Feb 08 2010 pier11 <pier11@operamail.com> 1.8.0
- source is an original 1.8.0 with patch: git(upstream) 9c34cc3557daa3d61a002002492c71d0343c8cae
- temp hack - renamed source in spec from .bz2 to .gz as the latter was prepared with the patch. 

* Sun Nov 22 2009 pier11 <pier11@operamail.com> 1.7.1
- reinstated enable-quality-check

* Wed Nov 04 2009 John Beranek <john@redux.org.uk> 1.7.0
- Spec file modifications to allow SLES/D 10 and Mandriva 2009.1 builds

* Tue Nov 03 2009 John Beranek <john@redux.org.uk> 1.7.0
- Spec file modifications for openSUSE build service

* Sun Oct 11 2009 J. D. User <jduser@noreply.com> 1.6.3-*git*
- move non-Pidgin files to new sub-package purple-sipe

* Sun Oct 11 2009 J. D. User <jduser@noreply.com> 1.6.3-*git*
- remove directory for emoticon theme icons

* Sun Oct 11 2009 J. D. User <jduser@noreply.com> 1.6.3-*git*
- libpurple protocol plugins are located under %%{_libdir}/purple-2

* Mon Sep 28 2009 J. D. User <jduser@noreply.com> 1.6.3-*git*
- added directory for emoticon theme icons

* Wed Sep 09 2009 J. D. User <jduser@noreply.com> 1.6.3
- update to 1.6.3

* Fri Aug 28 2009 J. D. User <jduser@noreply.com> 1.6.2-*git*
- reduce libpurple-devel requirement to >= 2.3.1

* Mon Aug 24 2009 J. D. User <jduser@noreply.com> 1.6.2
- update to 1.6.2

* Fri Aug 21 2009 J. D. User <jduser@noreply.com> 1.6.1-*git*
- reduce libpurple-devel requirement to >= 2.4.1

* Mon Aug 17 2009 J. D. User <jduser@noreply.com> 1.6.1-*git*
- com_err.h only required for kerberos

* Tue Aug 11 2009 J. D. User <jduser@noreply.com> 1.6.0-*git*
- require libpurple-devel >= 2.5.0

* Sun Aug 09 2009 J. D. User <jduser@noreply.com> 1.6.0-*git*
- refactor configure parameters
- make kerberos configurable
- don't hard code prefix for git builds

* Sun Aug 09 2009 J. D. User <jduser@noreply.com> 1.6.0-*git*
- removed unnecessary zlib-devel

* Sat Aug 08 2009 J. D. User <jduser@noreply.com> 1.6.0-*git*
- fix prefix for git builds

* Sat Aug 01 2009 J. D. User <jduser@noreply.com> 1.6.0-*git*
- append -Wno-unused-parameter for GCC <4.4 compilation errors

* Thu Jul 30 2009 J. D. User <jduser@noreply.com> 1.6.0-*git*
- remove duplicate GPL2

* Thu Jul 30 2009 J. D. User <jduser@noreply.com> 1.6.0-*git*
- use "--with git" to build from git
- corrected download URL for release archive
- add missing BR gettext-devel

* Wed Jul 29 2009 J. D. User <jduser@noreply.com> 1.6.0-*git*
- use default rpmbuild CFLAGS also for git builds
- merge with SPEC files created by mricon & jberanek

* Tue Jul 28 2009 J. D. User <jduser@noreply.com> 1.6.0-*git*
- initial RPM SPEC example generated
