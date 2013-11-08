Name:		libstrophe
Version:	1
Release:	1%{?dist}_git
Summary:	xmpp library in C

Group:		Application/System
License:	MIT/GPLv3
URL:		http://strophe.im/libstrophe/
Source0:	libstrophe_git.tar.gz

BuildRequires:	expat-devel
Requires:		expat

%description
XMPP library in C

%prep
%setup -n libstrophe
./bootstrap.sh

%build
%configure
make %{?_smp_mflags}

%install
make install DESTDIR=%{buildroot}

%files
%{_libdir}/libstrophe.a
%{_includedir}/strophe.h

%changelog
