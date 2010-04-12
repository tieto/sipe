#
# OBS SPEC file to generate a RPM for pidgin-sipe.
# It should work on Fedora 9/10/11/12, openSUSE 11.x, RHEL5/CentOS 5, SLES/D 11 and Mandriva 2009.1/2010.
#

%define purple_plugin libpurple-plugin-sipe

%define purple_develname libpurple-devel

%if 0%{?mandriva_version} >= 200910
%ifarch x86_64
%define purple_develname lib64purple-devel
%endif
%endif

%if 0%{?suse_version}
%define nss_develname mozilla-nss-devel
%else
%define nss_develname nss-devel
%endif

%if 0%{?suse_version} || 0%{?sles_version}
%define pkg_group Productivity/Networking/Instant Messenger
%endif
%if 0%{?fedora_version}
%define pkg_group Applications/Internet
%endif
%if 0%{?mandriva_version}
%define pkg_group Networking/Instant messaging
%else
%define pkg_group Applications/Internet
%endif

Name:           pidgin-sipe
Summary:        Pidgin protocol plugin to connect to MS Office Communicator
Version:        1.10.0
Release:        1
Source:         %{name}-%{version}.tar.gz
Group:          %{pkg_group}
License:        GPLv2+
URL:            http://sipe.sourceforge.net/

BuildRoot:      %{_tmppath}/%{name}-%{version}-build

BuildRequires:  %{purple_develname} >= 2.4.0
BuildRequires:  glib2-devel >= 2.12.0
BuildRequires:  libxml2-devel
#BuildRequires:  %{nss_develname}
BuildRequires:  libtool
BuildRequires:  intltool
BuildRequires:  gettext-devel

# Configurable components
%if !0%{?_without_kerberos:1}
BuildRequires:  krb5-devel
%endif

# For directory ownership
BuildRequires:  pidgin
Requires:       %{purple_plugin} = %{?epoch:%{epoch}:}%{version}-%{release}
Requires:       pidgin
%if 0%{?sles_version} == 10
BuildRequires:  gnome-keyring-devel
%endif

# For OBS's "have choice for" for Fedora 11 (only)
%if 0%{?fedora_version} == 11
BuildRequires:  libproxy-mozjs
BuildRequires:  PolicyKit-gnome
%endif

%description
A third-party plugin for the Pidgin multi-protocol instant messenger.
It implements the extended version of SIP/SIMPLE used by various products:

    * Microsoft Office Communications Server (OCS 2007/2007 R2 and newer)
    * Microsoft Live Communications Server (LCS 2003/2005)
    * Reuters Messaging

With this plugin you should be able to replace your Microsoft Office
Communicator client with Pidgin.

This package provides the icon set for Pidgin.


%package -n %{purple_plugin}
Summary:        Libpurple protocol plugin to connect to MS Office Communicator
Group:          %{pkg_group}
License:        GPLv2+
Obsoletes:      purple-sipe

%description -n %{purple_plugin}
A third-party plugin for the Pidgin multi-protocol instant messenger.
It implements the extended version of SIP/SIMPLE used by various products:

    * Microsoft Office Communications Server (OCS 2007/2007 R2 and newer)
    * Microsoft Live Communications Server (LCS 2003/2005)
    * Reuters Messaging

This package provides the protocol plugin for libpurple clients.


%prep
%setup -q

%build
%if 0%{?sles_version} == 10
export CFLAGS="%optflags -I%{_includedir}/gssapi"
%endif
%if 0%{?mandriva_version}
autoreconf --verbose --install --force
%endif
%configure \
	--enable-purple \
	--disable-telepathy
make %{_smp_mflags}
make %{_smp_mflags} check


%install
%makeinstall
find %{buildroot} -type f -name "*.la" -delete -print
# SLES11 defines suse_version = 1110
%if 0%{?suse_version} && 0%{?suse_version} < 1120
rm -r %{buildroot}/%{_datadir}/pixmaps/pidgin/protocols/scalable
%endif
%find_lang %{name}


%clean
rm -rf %{buildroot}


%files -n %{purple_plugin} -f %{name}.lang
%defattr(-,root,root,-)
%doc AUTHORS ChangeLog COPYING NEWS README TODO
%{_libdir}/purple-2/libsipe.so


%files
%defattr(-,root,root,-)
%doc AUTHORS COPYING
%{_datadir}/pixmaps/pidgin/protocols/*/sipe.png
# SLES11 defines suse_version = 1110
%if !0%{?suse_version} || 0%{?suse_version} >= 1120
%{_datadir}/pixmaps/pidgin/protocols/*/sipe.svg
%endif


%changelog
* Mon Apr 12 2010 J. D. User <jduser@noreply.com> 1.10.0-*git*
- add NSS build information discovered through OBS testing

* Wed Apr 04 2010 pier11 <pier11@operamail.com> 1.10.0
- release

* Fri Apr 02 2010 J. D. User <jduser@noreply.com> pre-1.10.0-*git*
- Mandriva has too old libtool version

* Fri Apr 02 2010 J. D. User <jduser@noreply.com> pre-1.10.0-*git*
- SLE11, openSUSE 11.0/1 don't have pidgin/protocols/scalable directory

* Sun Mar 07 2010 pier11 <pier11@operamail.com> pre-1.10.0-*git*
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

* Sun Feb 08 2010 pier11 <pier11@operamail.com> 1.8.0
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
