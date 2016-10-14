#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT(wsharktest, 0.1, peloy@chapus.net)
AC_CONFIG_SRCDIR([wshark-test.c])
AC_CONFIG_HEADER([config.h])

AM_INIT_AUTOMAKE

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LIBTOOL

# Checks for libraries.
LIBS="$LIBS -L/usr/lib/wireshark"

AC_CHECK_LIB(wiretap, wtap_dump_can_open)
AC_CHECK_LIB(wireshark, epan_init)
AC_CHECK_LIB(pcap, pcap_open_live)

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([stdlib.h stdarg.h])

#
# Define WS_VAR_IMPORT appropriately for declarations of external
# variables exported from dynamically-linked libraries.
#
AC_DEFINE(WS_VAR_IMPORT, extern, [Define as the string to precede external variable declarations in dynamically-linked libraries])

# Checks for typedefs, structures, and compiler characteristics.


# Checks for library functions.

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
