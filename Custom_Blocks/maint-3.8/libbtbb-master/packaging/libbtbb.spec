#
#Copyright 2013 Dominic Spill
#
#This file is part of libbtbb
#
#This program is free software; you can redistribute it and/or modify
#it under the terms of the GNU General Public License as published by
#the Free Software Foundation; either version 2, or (at your option)
#any later version.
#
#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.
#
#You should have received a copy of the GNU General Public License
#along with libbtbb; see the file COPYING.  If not, write to
#the Free Software Foundation, Inc., 51 Franklin Street,
#Boston, MA 02110-1301, USA.
#

Summary: Bluetooth baseband library
Name:    libbtbb
Version: 2013.06
Release: 1
Summary: A Bluetooth basebad decoding library
License: GPLv2
URL:     http://mooedit.sourceforge.net/           
Source:  %{name}-%{version}.tar.gz

BuildRequires:  cmake gcc python

Autoreqprov:    on

%description
A library for decoding and processing Bluetooth baseband packets.
It can be used with any raw bitstream receiver, such as Ubertooth or
gr-bluetooth.

%prep
%setup -q
%build
cmake -DCMAKE_SKIP_RPATH=ON \
      -DCMAKE_INSTALL_PREFIX=%{_prefix} \
	  -DBUILD_ROOT=%{buildroot}

%{__make} %{?jobs:-j%jobs}

%install
%{__make} DESTDIR=%{buildroot} install

%files
%{_prefix}/lib/libbtbb.so
%{_prefix}/lib/libbtbb.so.0
%{_prefix}/lib/libbtbb.so.0.2.0
%{_prefix}/lib/python*
%{_bindir}/btaptap
%{_libdir}/../include/libbtbb/bluetooth_le_packet.h
%{_libdir}/../include/libbtbb/btbb.h
%doc COPYING README.md

%changelog
* Thu Jun 06 2013 Dominic Spill <dominincgs@gmail.com> - 0.2.0
- First binary release
