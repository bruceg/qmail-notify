Name: @PACKAGE@
Summary: Delayed delivery notification for qmail
Version: @VERSION@
Release: 1
License: GPL
Group: Utilities/System
Source: http://untroubled.org/@PACKAGE@/@PACKAGE@-@VERSION@.tar.gz
BuildRoot: %{_tmppath}/@PACKAGE@-root
BuildRequires: bglibs >= 1.022
URL: http://untroubled.org/@PACKAGE@/
Packager: Bruce Guenter <bruceg@em.ca>

%description
This package contains a program to notify senders about email that has
been held in the qmail queue.

%prep
%setup
echo %{_bindir} >conf-bin
echo gcc "%{optflags}" >conf-cc
echo gcc -s >conf-ld

%build
make

%install
rm -fr %{buildroot}
mkdir -p %{buildroot}%{_bindir}
echo %{buildroot}%{_bindir} >conf-bin
make install install_prefix=%{buildroot}

mkdir -p %{buildroot}/etc/cron.hourly
install -m 755 cron.hourly %{buildroot}/etc/cron.hourly/qmail-notify

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root)
%doc COPYING NEWS README
%config /etc/cron.hourly/*
%{_bindir}/*
