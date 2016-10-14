# Prerequisites
* Download wireshark 1.10.3 : https://www.wireshark.org/download/src/all-versions/
* Untar it : tar -xvjf wireshark-1.10.3.tar.bz2
* Copy epan folder : cp -r wireshark-1.10.3/epan ./

# Building
- ./configure
- vim Makefile { change following in Makefile }
 * my_include = -I/usr/include/glib-2.0 -I/usr/lib/x86_64-linux-gnu/glib-2.0/include/ -I/home/mehul/Downloads/wireshark/wireshark-1.10.3/wsutil -I/home/mehul/Downloads/wireshark/wireshark-1.10.3/
 * DEFAULT_INCLUDES = -I. -I$(srcdir) -I. ${my_include}
 * LIBS = -L/usr/local/lib -lpcap -lwireshark -lwiretap -lglib-2.0 -lwsutil -lpthread

- sudo make all
- sudo ./wshark-test
