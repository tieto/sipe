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
%define git       20091011git80e8002
# Increment when you generate several RPMs on the same day...
%define gitcount  0
#------------------------------- BUILD FROM GIT -------------------------------
%endif

%define protocol purple-sipe

Name:           pidgin-sipe
Summary:        Pidgin third-party plugin for Microsoft LCS/OCS
Version:        1.7.0
%if 0%{?_with_git:1}
Release:        %{gitcount}.%{git}%{?dist}
Source:         %{name}-%{git}.tar.bz2
%else
Release:        1%{?dist}
Source:         http://downloads.sourceforge.net/sipe/%{name}-%{version}.tar.bz2
%endif
Group:          Applications/Internet
License:        GPLv2+
URL:            http://sipe.sourceforge.net/

BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:  libpurple-devel >= 2.3.1, libtool, intltool, gettext-devel

# Configurable components
%if !0%{?_without_kerberos:1}
%define config_krb5 --with-krb5
BuildRequires:  krb5-devel
%endif

Requires:       %{protocol} = %{version}-%{release}


%description
A third-party plugin for the Pidgin multi-protocol instant messenger. It
implements the extended version of SIP/SIMPLE used by various products:

    * Microsoft Office Communications Server (OCS 2007 and newer)
    * Microsoft Live Communications Server (LCS 2003/2005)
    * Reuters Messaging

This package provides the icon set for Pidgin.


%package -n %{protocol}
Summary:        Libpurple third-party plugin for Microsoft LCS/OCS

%description -n %{protocol}
A third-party plugin for the libpurple multi-protocol instant messaging core.
It implements the extended version of SIP/SIMPLE used by various products:

    * Microsoft Office Communications Server (OCS 2007 and newer)
    * Microsoft Live Communications Server (LCS 2003/2005)
    * Reuters Messaging


%prep
%if 0%{?_with_git:1}
%setup -q -n %{name}-%{git}
%else
%setup -q
%endif


%build
%define config_params %{?config_krb5:%{config_krb5}}
%if 0%{?_with_git:1}
# Copied from "rpmbuild --showrc" configure definition
export CFLAGS="${CFLAGS:-%optflags}"
./autogen.sh --build=%{_build} --host=%{_host} \
	--target=%{_target_platform} \
	--prefix=%{_prefix} \
	--datadir=%{_datadir} \
	--libdir=%{_libdir} \
	%{config_params}
%else
%configure %{config_params}
%endif

make %{_smp_mflags}


%install
%makeinstall
%find_lang %{name}

# NOTE: We intentionally don't ship *.la files
find $RPM_BUILD_ROOT -type f -name '*.la' | xargs rm -f -- || :


%clean
rm -rf $RPM_BUILD_ROOT


%files -n %{protocol} -f %{name}.lang
%defattr(-,root,root,-)
%doc AUTHORS ChangeLog COPYING NEWS README TODO
%{_libdir}/purple-2/libsipe.so


%files
%defattr(-,root,root,-)
%doc AUTHORS COPYING
%{_datadir}/pixmaps/pidgin/protocols/*/sipe.png


%changelog
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
