## Makefile.am -- Process this file with automake to produce Makefile.in

AUTOMAKE_OPTIONS	= no-dependencies

bin_PROGRAMS		= wshark-test

AM_CFLAGS		= -W -Wall
INCLUDES		= `pkg-config --cflags glib-2.0` \
			  -I/usr/include/wireshark

wshark_test_SOURCES	= wshark-test.c print.h print.c cfile.h
