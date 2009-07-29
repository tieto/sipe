#
# Example SPEC file to generate a RPM for pidgin-sipe.
# It should work out-of-the-box on Fedora 10/11 and RHEL5.
#
#------------------------------ BUILD FROM GIT ------------------------------
# Comment out the definition of %{git} to build from release version
#
# Instructions how to access the repository: http://sipe.sourceforge.net/git/
#
# Run "./git-snapshot.sh ." in your local repository.
# Then update the following line from the generated archive name
%define git       20090728gite895a0e
# Increment when you generate several RPMs on the same day...
%define gitcount  0
#------------------------------ BUILD FROM GIT ------------------------------


Name:           pidgin-sipe
Summary:        Pidgin plugin for connecting to Microsoft LCS/OCS
Version:        1.6.0
%if %{?git:1}0
Release:        %{gitcount}.%{git}%{?dist}
Source:         %{name}-%{git}.tar.bz2
%else
Release:        1%{?dist}
Source:         http://download.sourceforge.net/pidgin-sipe/%{name}-%{version}.tar.bz2
%endif
Group:          Applications/Internet
License:        GPLv2+
URL:            http://sipe.sourceforge.net/

BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:  zlib-devel, libpurple-devel, libtool, intltool
BuildRequires:  krb5-devel
# Required for com_err.h
BuildRequires:  e2fsprogs-devel


%description
Provides an Open Implementation of SIP/Simple protocol for connecting Pidgin to
Live Communications Server 2003/2005 and Office Communications Server 2007.


%prep
%if %{?git:1}0
%setup -q -n %{name}-%{git}
%else
%setup -q
%endif


%build
%if %{?git:1}0
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
* Wed Jul 29 2009 J. D. User <jduser@noreply.com> 1.6.0-*git*
- use default rpmbuild CFLAGS also for git builds
- merge with SPEC files created by mricon & jberanek

* Tue Jul 28 2009 J. D. User <jduser@noreply.com> 1.6.0-*git*
- initial RPM SPEC example generated
