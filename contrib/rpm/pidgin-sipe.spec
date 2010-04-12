#
# Example SPEC file to generate a RPM for pidgin-sipe.
# It should work out-of-the-box on Fedora 10/11 and RHEL5.
#
%if 0%{?_with_git:1}
#------------------------------- BUILD FROM GIT -------------------------------
# Add "--with git" to the rpmbuild command line to build from git
#
# Instructions how to access the repository: http://sipe.sourceforge.net/git/
#
# Run "./git-snapshot.sh ." in your local repository.
# Then update the following line from the generated archive name
%define git       20100207git96eee8a
# Increment when you generate several RPMs on the same day...
%define gitcount  0
#------------------------------- BUILD FROM GIT -------------------------------
%endif

%define purple_plugin purple-sipe
%define pkg_group     Applications/Internet

Name:           pidgin-sipe
Summary:        Pidgin protocol plugin to connect to MS Office Communicator
Version:        1.10.0
%if 0%{?_with_git:1}
Release:        %{gitcount}.%{git}%{?dist}
Source:         %{name}-%{git}.tar.bz2
# git package overrides official released package
Epoch:          1
%else
Release:        1%{?dist}
Source:         http://downloads.sourceforge.net/sipe/%{name}-%{version}.tar.bz2
%endif
Group:          %{pkg_group}
License:        GPLv2+
URL:            http://sipe.sourceforge.net/

BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:  libpurple-devel >= 2.4.0
BuildRequires:  glib2-devel >= 2.12.0
BuildRequires:  libxml2-devel
#BuildRequires:  nss-devel
BuildRequires:  libtool
BuildRequires:  intltool
BuildRequires:  gettext-devel

# Configurable components
%if !0%{?_without_kerberos:1}
BuildRequires:  krb5-devel
%endif

Requires:       %{purple_plugin} = %{?epoch:%{epoch}:}%{version}-%{release}


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

%description -n %{purple_plugin}
A third-party plugin for the Pidgin multi-protocol instant messenger.
It implements the extended version of SIP/SIMPLE used by various products:

    * Microsoft Office Communications Server (OCS 2007/2007 R2 and newer)
    * Microsoft Live Communications Server (LCS 2003/2005)
    * Reuters Messaging

This package provides the protocol plugin for libpurple clients.


%prep
%if 0%{?_with_git:1}
%setup -q -n %{name}-%{git}
%else
%setup -q
%endif


%build
%if 0%{?_with_git:1}
./autogen.sh
%endif
%configure \
	--enable-purple \
	--disable-telepathy
make %{_smp_mflags}
make %{_smp_mflags} check


%install
%makeinstall
find %{buildroot} -type f -name "*.la" -delete -print
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
%{_datadir}/pixmaps/pidgin/protocols/*/sipe.svg


%changelog
* Mon Apr 12 2010 J. D. User <jduser@noreply.com> 1.10.0-*git*
- add (commented out) BR nss-devel

* Sun Apr 04 2010 J. D. User <jduser@noreply.com> 1.10.0
- update to 1.10.0

* Sun Mar 28 2010 J. D. User <jduser@noreply.com> 1.9.1-*git*
- changed --with/--without options to --enable/--disable

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

* Wed Mar 10 2010 J. D. User <jduser@noreply.com> 1.9.0
- update to 1.9.0

* Mon Mar 08 2010 J. D. User <jduser@noreply.com> 1.8.1-*git*
- increased libpurple build requisite to >= 2.4.0

* Sun Mar 07 2010 J. D. User <jduser@noreply.com> 1.8.1-*git*
- sync with RPM SPEC from contrib/OBS

* Sat Mar 06 2010 J. D. User <jduser@noreply.com> 1.8.1-*git*
- update package summary & description

* Tue Feb 16 2010 J. D. User <jduser@noreply.com> 1.8.1
- update to 1.8.1

* Sun Feb 07 2010 J. D. User <jduser@noreply.com> 1.8.0
- update to 1.8.0

* Thu Jan 14 2010 J. D. User <jduser@noreply.com> 1.7.1-*git*
- autogen.sh no longer runs configure

* Tue Dec 29 2009 J. D. User <jduser@noreply.com> 1.7.1-*git*
- add configure parameters for purple and telepathy

* Sat Dec 12 2009 J. D. User <jduser@noreply.com> 1.7.1-*git*
- add Epoch: for git packages to avoid update clash with official packages

* Mon Nov 19 2009 J. D. User <jduser@noreply.com> 1.7.1
- update to 1.7.1

* Mon Oct 28 2009 J. D. User <jduser@noreply.com> 1.7.0-*git*
- add missing Group: to purple-sipe

* Mon Oct 19 2009 J. D. User <jduser@noreply.com> 1.7.0
- update to 1.7.0

* Sun Oct 11 2009 J. D. User <jduser@noreply.com> 1.6.3-*git*
- move non-Pidgin files to new sub-package purple-sipe

* Sun Oct 11 2009 J. D. User <jduser@noreply.com> 1.6.3-*git*
- remove directory for emoticon theme icons

* Sun Oct 11 2009 J. D. User <jduser@noreply.com> 1.6.3-*git*
- libpurple protocol plugins are located under %{_libdir}/purple-2

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
