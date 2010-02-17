#
# spec file for package pidgin-sipe (Version 1.8.1)
#
# Copyright (c) 2010 SUSE LINUX Products GmbH, Nuernberg, Germany.
#
# All modifications and additions to the file contributed by third parties
# remain the property of their copyright owners, unless otherwise agreed
# upon. The license for this file, and modifications and additions to the
# file, is the same license as for the pristine package itself (unless the
# license for the pristine package is not an Open Source License, in which
# case the license is the MIT License). An "Open Source License" is a
# license that conforms to the Open Source Definition (Version 1.9)
# published by the Open Source Initiative.

# Please submit bugfixes or comments via http://bugs.opensuse.org/
#



Name:           pidgin-sipe
Version:        1.8.1
Release:        1
License:        GPLv2+
Summary:        Pidgin third-party plugin for Microsoft LCS/OCS
Url:            http://sipe.sourceforge.net/
Group:          Productivity/Networking/Instant Messenger
Source:         %{name}-%{version}.tar.gz
BuildRequires:  gettext-devel
BuildRequires:  intltool
BuildRequires:  krb5-devel
BuildRequires:  libpurple-devel >= 2.3.1
BuildRequires:  libtool
# For directory ownership
BuildRequires:  pidgin
Requires:       libpurple-plugin-sipe = %{version}
Requires:       pidgin
Supplements:    packageand(libpurple-plugin-sipe:pidgin}
BuildRoot:      %{_tmppath}/%{name}-%{version}-build

%description
A third-party plugin for the Pidgin multi-protocol instant messenger. It
implements the extended version of SIP/SIMPLE used by various products:

    * Microsoft Office Communications Server (OCS 2007 and newer)
    * Microsoft Live Communications Server (LCS 2003/2005)
    * Reuters Messaging

This package provides the icon set for Pidgin.

%package -n libpurple-plugin-sipe
License:        GPLv2+
Summary:        Libpurple third-party plugin for Microsoft LCS/OCS
Group:          Productivity/Networking/Instant Messenger
Enhances:       libpurple

%description -n libpurple-plugin-sipe
A third-party plugin for the libpurple multi-protocol instant messaging core.
It implements the extended version of SIP/SIMPLE used by various products:

    * Microsoft Office Communications Server (OCS 2007 and newer)
    * Microsoft Live Communications Server (LCS 2003/2005)
    * Reuters Messaging

%prep
%setup -q

%build
%{?env_options}
%configure --with-krb5
make %{_smp_mflags}

%install
%makeinstall
find %{buildroot} -type f -name "*.la" -delete -print
%find_lang %{name}

%clean
rm -rf %{buildroot}

%files -n libpurple-plugin-sipe -f %{name}.lang
%defattr(-,root,root,-)
%doc AUTHORS ChangeLog COPYING NEWS README TODO
%{_libdir}/purple-2/libsipe.so

%files
%defattr(-,root,root,-)
%doc AUTHORS COPYING
%{_datadir}/pixmaps/pidgin/protocols/*/sipe.png

%changelog
