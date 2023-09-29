CXX?=g++
CXXFLAGS+=-Wall -ansi -D_FILE_OFFSET_BITS=64 -DFUSE_USE_VERSION=26 -DHAVE_SETXATTR=1 -DELPP_SYSLOG -DELPP_NO_DEFAULT_LOG_FILE -DELPP_THREAD_SAFE -std=c++11 `xml2-config --cflags`
LDFLAGS+=-Wall -ansi -lpcre2-8 -lfuse `xml2-config --libs` -lpthread
srcdir=fuse
easyloggingdir=vendor/github.com/muflihun/easyloggingpp/src
builddir=build

all: $(builddir) openvfsfuse

$(builddir):
	mkdir $(builddir)

openvfsfuse: $(builddir)/openvfsfuse.o $(builddir)/Config.o $(builddir)/Filter.o $(builddir)/easylogging.o
	$(CXX) $(CPPFLAGS) -o openvfsfuse $(builddir)/openvfsfuse.o $(builddir)/Config.o $(builddir)/Filter.o $(builddir)/easylogging.o $(LDFLAGS)

$(builddir)/openvfsfuse.o: $(builddir)/Config.o $(builddir)/Filter.o $(srcdir)/openvfsfuse.cpp
	$(CXX) $(CPPFLAGS) -o $(builddir)/openvfsfuse.o -c $(srcdir)/openvfsfuse.cpp $(CXXFLAGS) -I$(easyloggingdir)

$(builddir)/Config.o: $(builddir)/Filter.o $(srcdir)/Config.cpp $(srcdir)/Config.h
	$(CXX) $(CPPFLAGS) -o $(builddir)/Config.o -c $(srcdir)/Config.cpp $(CXXFLAGS)

$(builddir)/Filter.o: $(srcdir)/Filter.cpp $(srcdir)/Filter.h
	$(CXX) $(CPPFLAGS) -o $(builddir)/Filter.o -c $(srcdir)/Filter.cpp $(CXXFLAGS)

$(builddir)/easylogging.o: $(easyloggingdir)/easylogging++.cc $(easyloggingdir)/easylogging++.h
	$(CXX) $(CPPFLAGS) -o $(builddir)/easylogging.o -c $(easyloggingdir)/easylogging++.cc $(CXXFLAGS)

clean:
	rm -rf $(builddir)/

install:
	mkdir -p $(DESTDIR)/usr/share/man/man1 $(DESTDIR)/usr/bin $(DESTDIR)/etc
	gzip < openvfsfuse.1 > $(DESTDIR)/usr/share/man/man1/openvfsfuse.1.gz
	cp openvfsfuse $(DESTDIR)/usr/bin/
	cp openvfsfuse.xml $(DESTDIR)/etc/


mrproper: clean
	rm -rf openvfsfuse

release:
	tar -c --exclude="CVS" $(srcdir)/ openvfsfuse.xml LICENSE openvfsfuse.1.gz Makefile | bzip2 - > openvfsfuse.tar.bz2
