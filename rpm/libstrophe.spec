Name:		libstrophe
Version:	1
Release:	1%{?dist}_git
Summary:	xmpp library in C

Group:		Application/System
License:	MIT/GPLv3
URL:		http://strophe.im/libstrophe/
Source0:	libstrophe_git.tar.gz

BuildRequires:	automake
BuildRequires:	libtool
BuildRequires:	openssl-devel
BuildRequires:	expat-devel
Requires:	expat

%description
XMPP library in C

%package        devel
Summary:        Headers and libraries for building apps that use libstrophe
Group:          Development/Libraries
Requires:       %{name} = %{version}-%{release}

%description    devel
This package contains headers and libraries required to build applications that
use the strophe XMPP library.

%prep
%setup -n libstrophe
./bootstrap.sh

%build
%configure
make %{?_smp_mflags}

%install
make install DESTDIR=%{buildroot}

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files
%defattr(-,root,root,-)
%{_libdir}/libstrophe.so*
%doc

%files devel
%defattr(-,root,root,-)
%{_libdir}/libstrophe.a
%{_libdir}/libstrophe.la
%{_libdir}/pkgconfig/libstrophe.pc
%{_includedir}/strophe.h
%doc

%changelog
