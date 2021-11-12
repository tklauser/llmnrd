# llmnrd - Link-Local Multicast Resolution Daemon

[![Coverity Status](https://scan.coverity.com/projects/8697/badge.svg)](https://scan.coverity.com/projects/tklauser-llmnrd)

llmnrd is a daemon implementing the Link-Local Multicast Name Resolution (LLMNR)
protocol according to [RFC 4795](https://tools.ietf.org/html/rfc4795). It
currently only supports Linux, as it uses the
[netlink kernel interface](http://man7.org/linux/man-pages/man7/netlink.7.html).

llmnrd will respond to name resolution queries sent by Windows clients in
networks where no DNS server is available. It supports both IPv4 and IPv6.

Installation
============

To build and install llmnrd use the following commands:

```
$ make
$ sudo make install
```

By default, the llmnrd binary will be installed to /usr/local/sbin. To install
the binary to a different installation path, use:

```
$ make
$ sudo make prefix=<path> install
```

Cross-Compilation
=================

To cross-compile llmnrd for a different architecture, set the `CC` make
variable to the corresponding cross-compiler. To e.g. build it using the
arm-linux-gnueabihf toolchain use:

```
$ make CC=arm-linux-gnueabihf-gcc
```

When cross-compiling, you usually don't want to install the generated binary to
your root filesystem, but to the sysroot of a cross-compiled system. Use the
`DESTDIR` variable to change the installation destination path, e.g.

```
$ make DESTDIR=$HOME/sysroot/ prefix=/usr install
```

Usage
=====

To run llmnrd in the default mode (listening on UDP port 5355):

```
$ llmnrd
```

By default, LLMNR name resolution is only possible over IPv4. To additionally
enable LLMNR name resolution over IPv6 use:

```
$ llmnrd -6
```

Use `llmnrd --help` to show additional usage information.

Additionally, the `llmnr-query` utility is shipped together with llmnrd and
can be used to send customized LLMNR queries:

```
$ llmnr-query <hostname>
```

Use `llmnr-query --help` to show additional usage information.

License
=======

llmnrd is free software: you can redistribute it and/or modify it under the
terms of the GNU General Public License as published by the Free Software
Foundation, version 2 of the License.

llmnrd is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE.  See the GNU General Public License for more details.

Please see the [COPYING](https://github.com/tklauser/llmnrd/blob/master/COPYING)
file for the full license text.

Contributors
============

llmnrd is authored and maintained by Tobias Klauser <tklauser@distanz.ch>

The following people contributed patches and ideas, found and reported bugs or
otherwise helped in the development of llmnrd:

* Diego Santa Cruz (@diego-santacruz)
* Elazar Leibovich (@elazarl)
* Martin Hauke
* Michael Evertz (@dvl-mevertz)
* Pali Rohár
* @Schimmelreiter
* @svimik
* @tbetker

Thanks a lot!

References
==========

* [RFC 4795](https://tools.ietf.org/html/rfc4795)
* [Microsoft TechNet article about LLMNR](https://technet.microsoft.com/en-us/library/bb878128.aspx)
* [xllmnrd: An IPv6-only LLMNR responder daemon](http://www.vx68k.org/xllmnrd) ([Repository](https://bitbucket.org/kazssym/xllmnrd/))
