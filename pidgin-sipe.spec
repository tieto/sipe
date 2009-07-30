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
%define git       20090730git4bc9d64
# Increment when you generate several RPMs on the same day...
%define gitcount  0
#------------------------------- BUILD FROM GIT -------------------------------
%endif

Name:           pidgin-sipe
Summary:        Pidgin plugin for connecting to Microsoft LCS/OCS
Version:        1.6.0
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

BuildRequires:  zlib-devel, libpurple-devel, libtool, intltool, gettext-devel
BuildRequires:  krb5-devel
# Required for com_err.h
BuildRequires:  e2fsprogs-devel


%description
Provides an Open Implementation of SIP/Simple protocol for connecting Pidgin to
Live Communications Server 2003/2005 and Office Communications Server 2007.


%prep
%if 0%{?_with_git:1}
%setup -q -n %{name}-%{git}
%else
%setup -q
%endif


%build
%if 0%{?_with_git:1}
# Copied from "rpmbuild --showrc" configure definition
export CFLAGS="${CFLAGS:-%optflags}"
./autogen.sh --with-krb5
%else
%configure --with-krb5
%endif

make %{_smp_mflags}


%install
%makeinstall
%find_lang %{name}

# NOTE: We intentionally don't ship *.la files
find $RPM_BUILD_ROOT -type f -name '*.la' | xargs rm -f -- || :


%clean
rm -rf $RPM_BUILD_ROOT


%files -f %{name}.lang
%defattr(-,root,root,-)
%doc AUTHORS ChangeLog COPYING LICENSE NEWS README TODO
%{_libdir}/pidgin/libsipe.so
%{_datadir}/pixmaps/pidgin/protocols/*/sipe.png


%changelog
* Thu Jul 30 2009 J. D. User <jduser@noreply.com> 1.6.0-*git*
- use "--with git" to build from git
- corrected download URL for release archive
- add missing BR gettext-devel

* Wed Jul 29 2009 J. D. User <jduser@noreply.com> 1.6.0-*git*
- use default rpmbuild CFLAGS also for git builds
- merge with SPEC files created by mricon & jberanek

* Tue Jul 28 2009 J. D. User <jduser@noreply.com> 1.6.0-*git*
- initial RPM SPEC example generated
