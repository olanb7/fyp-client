## The following line supports click-mkmindriver and should not be changed.
## Click userlevel driver Makefile ##
SHELL = /bin/sh

top_srcdir := ..
srcdir := .
top_builddir := ..
subdir := userlevel
conf_auxdir := $(top_srcdir)

prefix = /usr/local
bindir = /usr/local/bin
sbindir = /usr/local/sbin
libdir = /usr/local/lib

VPATH = .:$(top_srcdir)/lib:$(top_srcdir)/$(subdir):$(top_srcdir)/elements/standard

CC = gcc -W -Wall
CPP = gcc -E
CXX = g++ -W -Wall 
CXXCPP = g++ -W -Wall  -E
AR_CREATE = ar cru
RANLIB = ranlib
INSTALL = /usr/bin/install -c
mkinstalldirs = $(conf_auxdir)/mkinstalldirs

ifeq ($(V),1)
ccompile = $(COMPILE) $(1)
cxxcompile = $(CXXCOMPILE) $(1)
cxxlink = $(CXXLINK) $(1)
verbose_cmd = $(1)
else
ccompile = @/bin/echo ' ' $(2) $< && $(COMPILE) $(1)
cxxcompile = @/bin/echo ' ' $(2) $< && $(CXXCOMPILE) $(1)
cxxlink = @/bin/echo ' ' $(2) $@ && $(CXXLINK) $(1)
verbose_cmd = @/bin/echo ' ' $(2) && $(1)
endif

.SUFFIXES:
.SUFFIXES: .S .c .cc .o .s .ii

.c.o:
	$(call ccompile,-c $< -o $@,CC)
.s.o:
	$(call ccompile,-c $< -o $@,ASM)
.S.o:
	$(call ccompile,-c $< -o $@,ASM)
.cc.o:
	$(call cxxcompile,-c $< -o $@,CXX)
.cc.s:
	$(call cxxcompile,-S $< -o $@,CXX -S)
.cc.ii:
	$(call cxxcompile,-E $< > $@,CXXCPP)


GENERIC_OBJS = string.o straccum.o nameinfo.o \
	bitvector.o vectorv.o templatei.o bighashmap_arena.o hashallocator.o \
	ipaddress.o ipflowid.o etheraddress.o \
	packet.o \
	error.o timestamp.o glue.o task.o timer.o atomic.o gaprate.o \
	element.o \
	confparse.o variableenv.o lexer.o elemfilter.o routervisitor.o \
	routerthread.o router.o master.o handlercall.o notifier.o \
	integers.o md5.o crc32.o in_cksum.o iptable.o \
	archive.o userutils.o driver.o \
	$(EXTRA_DRIVER_OBJS)

EXTRA_DRIVER_OBJS = 

LIBOBJS = $(GENERIC_OBJS) $(STD_ELEMENT_OBJS) clp.o exportstub.o
STD_ELEMENT_OBJS = addressinfo.o alignmentinfo.o \
	errorelement.o portinfo.o scheduleinfo.o
OBJS = $(ELEMENT_OBJS) $(ELEMENTSCONF).o click.o

CPPFLAGS =  -DCLICK_USERLEVEL
CFLAGS = -g -O2
CXXFLAGS = -g -O2
DEPCFLAGS = -MD -MP

DEFS = -DHAVE_CONFIG_H
INCLUDES = -I$(top_builddir)/include -I$(top_srcdir)/include \
	-I$(srcdir) -I$(top_srcdir) -I/home/olan/openwrt/build_dir/target-mips_uClibc-0.9.30.1/protobuf-2.3.0/src 
LDFLAGS = 
LIBS =  `$(top_builddir)/click-buildtool --otherlibs` $(ELEMENT_LIBS)

CXXCOMPILE = $(CXX) $(DEFS) $(INCLUDES) $(CPPFLAGS) $(CXXFLAGS) $(DEPCFLAGS)
CXXLD = $(CXX)
CXXLINK = $(CXXLD) $(CXXFLAGS) $(LDFLAGS) -o $@
COMPILE = $(CC) $(DEFS) $(INCLUDES) $(CPPFLAGS) $(CFLAGS) $(DEPCFLAGS)
CCLD = $(CC)
LINK = $(CCLD) $(CFLAGS) $(LDFLAGS) -o $@

ifndef MINDRIVER
DRIVER = click
ELEMENTSCONF = elements
INSTALLLIBS = libclick.a
else
DRIVER = $(MINDRIVER)click
ELEMENTSCONF = elements_$(MINDRIVER)
endif
INSTALLPROGS = $(DRIVER)

all: $(INSTALLPROGS) $(INSTALLLIBS)

ifneq ($(MAKECMDGOALS),clean)
-include $(ELEMENTSCONF).mk
endif

$(DRIVER): Makefile libclick.a $(OBJS)
	$(call cxxlink,-rdynamic $(OBJS) libclick.a $(LIBS),LINK)

libclick.a: Makefile $(LIBOBJS)
	$(call verbose_cmd,$(AR_CREATE) libclick.a $(LIBOBJS),AR libclick.a)
	$(call verbose_cmd,$(RANLIB) libclick.a,RANLIB libclick.a)

Makefile: $(srcdir)/Makefile.in $(top_builddir)/config.status
	cd $(top_builddir) \
	  && CONFIG_FILES=$(subdir)/$@ CONFIG_HEADERS= $(SHELL) ./config.status

elemlist:
	@rm -f elements.conf
	@$(MAKE) elements.conf
elements.conf: $(top_builddir)/config.status $(top_builddir)/click-buildtool
	echo "userlevel  analysis app aqm ethernet icmp ip local standard tcpudp test threads wifi" | $(top_builddir)/click-buildtool findelem -r userlevel -p $(top_srcdir) -X $(srcdir)/elements.exclude > elements.conf
$(ELEMENTSCONF).mk: $(ELEMENTSCONF).conf $(top_builddir)/click-buildtool
	$(top_builddir)/click-buildtool elem2make -x "$(STD_ELEMENT_OBJS)" < $(ELEMENTSCONF).conf > $(ELEMENTSCONF).mk
$(ELEMENTSCONF).cc: $(ELEMENTSCONF).conf $(top_builddir)/click-buildtool
	$(top_builddir)/click-buildtool elem2export < $(ELEMENTSCONF).conf > $(ELEMENTSCONF).cc
	@rm -f $(ELEMENTSCONF).d

DEPFILES := $(wildcard *.d)
ifneq ($(DEPFILES),)
include $(DEPFILES)
endif

install: $(INSTALLPROGS) install-lib
	$(mkinstalldirs) $(DESTDIR)$(bindir)
	for i in $(INSTALLPROGS); do $(INSTALL) $$i $(DESTDIR)$(bindir)/$$i; done
install-lib: $(INSTALLLIBS)
	$(mkinstalldirs) $(DESTDIR)$(libdir)
	for i in $(INSTALLLIBS); do $(INSTALL) $$i $(DESTDIR)$(libdir)/$$i; done
install-man:
	:
uninstall:
	for i in $(INSTALLLIBS); do rm -f $(DESTDIR)$(libdir)/$$i; done
	for i in $(INSTALLPROGS); do rm -f $(DESTDIR)$(bindir)/$$i; done

clean:
	rm -f *.d *.o $(INSTALLPROGS) $(ELEMENTSCONF).mk $(ELEMENTSCONF).cc elements.conf libclick.a
clean-lib:
	rm -f $(LIBOBJS) libclick.a
distclean: clean
	-rm -f Makefile

.PHONY: all clean clean-lib distclean elemlist \
	install install-lib uninstall
