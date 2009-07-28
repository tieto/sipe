#
# Example SPEC file to generate a RPM from a git snapshot.
# It should work out-of-the-box on Fedora 10/11 and RHEL5.
#
%if 1
# Run "./git-snapshot.sh ." in your local repository.
# Then update the following line from the generated archive name
%define git       20090728gite895a0e
# Increment when you generate several RPMs on the same day...
%define gitcount  0
%endif

Name:           pidgin-sipe
Summary:        Pidgin plugin for connecting to Microsoft LCS/OCS
Version:        1.6.0
%if %{?git:1}0
Release:        %{gitcount}.%{git}%{?dist}
# FYI: git clone git+ssh://mob@repo.or.cz/srv/git/siplcs.git
Source:         %{name}-%{git}.tar.bz2
%else
Release:        1%{?dist}
Source:         %{name}-%{version}.tar.bz2
%endif
License:        GPL v2 or later
Group:          Productivity/Networking/Instant Messenger
URL:            http://sipe.sourceforge.net/
AutoReqProv:    on
BuildRequires:  pidgin-devel libpurple-devel 
BuildRequires:  intltool gettext-devel
BuildRequires:  zlib-devel krb5-devel
# Required for com_err.h
BuildRequires:  e2fsprogs-devel
BuildRequires:  automake autoconf libtool
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
Requires:       libpurple >= 2.0.0
PreReq:         /usr/bin/gconftool-2 coreutils

%description
Microsoft Live Communication Server (LCS) and Office Communication Server (OCS) plugin for Pidgin.

Allows talking with users of Office Communicator or Pidgin via a LCS or OCS server.

%prep
%if %{?git:1}0
%setup -q -n %{name}-%{git}
%else
%setup -q
%endif

%build
%if %{?git:1}0
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
%defattr(-,root,root)
%doc AUTHORS ChangeLog COPYING HACKING INSTALL LICENSE NEWS README TODO
%{_datadir}/pixmaps/pidgin/protocols/16/sipe.png
%{_datadir}/pixmaps/pidgin/protocols/22/sipe.png
%{_datadir}/pixmaps/pidgin/protocols/48/sipe.png
%{_libdir}/pidgin/libsipe.*

%changelog
* Tue Jul 28 2009 J. D. User <jduser@noreply.com> 1.6.0-*git*
- initial RPM SPEC example generated
