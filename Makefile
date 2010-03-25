# Warning: this file must be usable by regular make
# (unlike the Makefiles in subdirectories).

SHELL = /bin/sh


PACKAGE = click
VERSION = 1.7.0rc1

top_srcdir = .
srcdir = .
top_builddir = .
subdir = .
conf_auxdir = $(top_srcdir)

AUTOCONF = autoconf
# ACLOCAL = aclocal -I m4
ACLOCAL = :
PERL = perl
INSTALL = /usr/bin/install -c
INSTALL_IF_CHANGED = $(INSTALL) -C
INSTALL_DATA = /usr/bin/install -c -m 644
INSTALL_DATA_IF_CHANGED = $(INSTALL) -C -m 644
mkinstalldirs = $(conf_auxdir)/mkinstalldirs

EXTRA_PROVIDES =
PROVISIONS = i686 i386 i586 analysis int64 linux linux_2_6 wifi $(EXTRA_PROVIDES)

prefix = /usr/local
exec_prefix = ${prefix}
includedir = /usr/local/include
clickincludedir = $(includedir)/click
netincludedir = $(includedir)/clicknet
toolincludedir = $(includedir)/clicktool
bindir = /usr/local/bin
datarootdir = /usr/local/share
datadir = /usr/local/share
clickdatadir = $(datadir)/click

DRIVERS =  userlevel
OTHER_TARGETS =  tools
ALL_TARGETS = $(DRIVERS) $(OTHER_TARGETS)

all: $(ALL_TARGETS) Makefile

bsdmodule: Makefile click-buildtool stamp-h
	@cd bsdmodule && $(MAKE) all
linuxmodule: Makefile click-buildtool stamp-h
	@cd linuxmodule && $(MAKE) all
ns: Makefile click-buildtool stamp-h
	@cd ns && $(MAKE) all
userlevel: Makefile click-buildtool click-compile stamp-h
	@cd userlevel && $(MAKE) all
exopc: Makefile click-buildtool stamp-h
	@cd exopc && $(MAKE) all
tools: Makefile
	@cd tools && $(MAKE) all

install: Makefile click-buildtool click-compile stamp-h installch
	@for d in $(ALL_TARGETS); do (cd $$d && $(MAKE) install) || exit 1; done
	@$(MAKE) install-local install-doc install-local-include
install-local: elementmap.xml click-buildtool click-compile config.mk \
	etc/pkg-config.mk installch
	$(mkinstalldirs) $(DESTDIR)$(bindir)
	$(INSTALL_IF_CHANGED) click-buildtool $(DESTDIR)$(bindir)/click-buildtool
	$(INSTALL_IF_CHANGED) click-compile $(DESTDIR)$(bindir)/click-compile
	$(INSTALL_IF_CHANGED) $(srcdir)/click-mkelemmap $(DESTDIR)$(bindir)/click-mkelemmap
	$(INSTALL_IF_CHANGED) $(top_srcdir)/test/testie $(DESTDIR)$(bindir)/testie
	$(mkinstalldirs) $(DESTDIR)$(clickdatadir)
	$(INSTALL) $(mkinstalldirs) $(DESTDIR)$(clickdatadir)/mkinstalldirs
	$(INSTALL_DATA) elementmap.xml $(DESTDIR)$(clickdatadir)/elementmap.xml
	$(INSTALL_DATA_IF_CHANGED) config.mk $(DESTDIR)$(clickdatadir)/config.mk
	$(INSTALL_DATA_IF_CHANGED) etc/pkg-config.mk $(DESTDIR)$(clickdatadir)/pkg-config.mk
	$(INSTALL_DATA_IF_CHANGED) $(srcdir)/etc/pkg-Makefile $(DESTDIR)$(clickdatadir)/pkg-Makefile
	$(INSTALL_DATA_IF_CHANGED) $(srcdir)/etc/pkg-userlevel.mk $(DESTDIR)$(clickdatadir)/pkg-userlevel.mk
	$(INSTALL_DATA_IF_CHANGED) $(srcdir)/etc/pkg-linuxmodule.mk $(DESTDIR)$(clickdatadir)/pkg-linuxmodule.mk
	$(INSTALL_DATA_IF_CHANGED) $(srcdir)/etc/pkg-linuxmodule-26.mk $(DESTDIR)$(clickdatadir)/pkg-linuxmodule-26.mk
	(cd $(top_srcdir); pwd) > $(DESTDIR)$(clickdatadir)/srcdir
	/bin/rm -rf $(DESTDIR)$(clickdatadir)/src
	/bin/ln -s "`cd $(top_srcdir); pwd`" $(DESTDIR)$(clickdatadir)/src
install-doc: elementmap.xml
	@cd doc && $(MAKE) install
install-info:
	@cd doc && $(MAKE) install-info
install-man: elementmap.xml
	@-for d in $(ALL_TARGETS) doc; do (cd $$d && $(MAKE) install-man); done
install-local-include: stamp-h installch
	$(mkinstalldirs) $(DESTDIR)$(clickincludedir)
	$(INSTALL_DATA_IF_CHANGED) $(srcdir)/include/click/*.h $(DESTDIR)$(clickincludedir)
	$(INSTALL_DATA_IF_CHANGED) $(srcdir)/include/click/*.hh $(DESTDIR)$(clickincludedir)
	$(INSTALL_DATA_IF_CHANGED) $(srcdir)/include/click/*.cc $(DESTDIR)$(clickincludedir)
	$(INSTALL_DATA_IF_CHANGED) $(top_builddir)/include/click/*.h $(DESTDIR)$(clickincludedir)
	$(mkinstalldirs) $(DESTDIR)$(clickincludedir)/standard
	$(INSTALL_DATA_IF_CHANGED) $(srcdir)/include/click/standard/*.hh $(DESTDIR)$(clickincludedir)/standard
	$(mkinstalldirs) $(DESTDIR)$(netincludedir)
	$(INSTALL_DATA_IF_CHANGED) $(srcdir)/include/clicknet/*.h $(DESTDIR)$(netincludedir)
install-include: install-local-include
	@cd tools && $(MAKE) install-include
install-lib:
	@if echo $(ALL_TARGETS) | grep userlevel >/dev/null 2>&1; then cd userlevel && $(MAKE) install-lib; fi
	@if echo $(ALL_TARGETS) | grep tools >/dev/null 2>&1; then cd tools && $(MAKE) install-lib; fi

uninstall: elementmap.xml
	@for d in $(ALL_TARGETS) doc; do (cd $$d && $(MAKE) uninstall) || exit 1; done
	@$(MAKE) uninstall-local uninstall-local-include
uninstall-local:
	/bin/rm -f $(DESTDIR)$(bindir)/click-buildtool $(DESTDIR)$(bindir)/click-compile $(DESTDIR)$(bindir)/click-mkelemmap $(DESTDIR)$(bindir)/testie $(DESTDIR)$(clickdatadir)/elementmap.xml $(DESTDIR)$(clickdatadir)/srcdir $(DESTDIR)$(clickdatadir)/src $(DESTDIR)$(clickdatadir)/config.mk $(DESTDIR)$(clickdatadir)/mkinstalldirs
	/bin/rm -f $(DESTDIR)$(clickdatadir)/pkg-config.mk $(DESTDIR)$(clickdatadir)/pkg-userlevel.mk $(DESTDIR)$(clickdatadir)/pkg-linuxmodule.mk $(DESTDIR)$(clickdatadir)/pkg-linuxmodule-26.mk $(DESTDIR)$(clickdatadir)/pkg-Makefile
uninstall-local-include:
	cd $(srcdir)/include/click; for i in *.h *.hh *.cc; do /bin/rm -f $(DESTDIR)$(clickincludedir)/$$i; done
	cd $(top_builddir)/include/click; for i in *.h; do /bin/rm -f $(DESTDIR)$(clickincludedir)/$$i; done
	cd $(srcdir)/include/click/standard; for i in *.hh; do /bin/rm -f $(DESTDIR)$(clickincludedir)/standard/$$i; done
	cd $(srcdir)/include/clicknet; for i in *.h; do /bin/rm -f $(DESTDIR)$(netincludedir)/$$i; done
	@-/bin/rmdir $(DESTDIR)$(clickincludedir)/standard
	@-/bin/rmdir $(DESTDIR)$(clickincludedir)
	@-/bin/rmdir $(DESTDIR)$(netincludedir)

elemlist elemlists: click-buildtool
	@for d in $(DRIVERS); do (cd $$d && $(MAKE) elemlist) || exit 1; done

MKELEMMAPFLAGS =
elementmap.xml: click-buildtool $(srcdir)/click-mkelemmap always
	echo $(DRIVERS)  analysis app aqm ethernet icmp ip local standard tcpudp test threads wifi $(EXTRA_PROVIDES) | $(top_builddir)/click-buildtool findelem -r "$(PROVISIONS) $(DRIVERS)" -p $(top_srcdir) | $(PERL) $(top_srcdir)/click-mkelemmap -r "$(PROVISIONS)" -t "$(DRIVERS)" -p $(top_srcdir) -Iinclude -s "`cd $(top_srcdir) && pwd`" $(MKELEMMAPFLAGS) > elementmap.xml
always:
	@:

click-buildtool: $(srcdir)/click-buildtool.in config.status
	cd $(top_builddir) && \
	  CONFIG_FILES=$(subdir)/$@ CONFIG_HEADERS= $(SHELL) ./config.status
	@chmod +x click-buildtool; touch click-buildtool
click-compile: $(srcdir)/click-compile.in config.status
	cd $(top_builddir) && \
	  CONFIG_FILES=$(subdir)/$@ CONFIG_HEADERS= $(SHELL) ./config.status
	@chmod +x click-compile; touch click-compile
config.mk: $(srcdir)/config.mk.in config.status
	cd $(top_builddir) && \
	  CONFIG_FILES=$(subdir)/$@ CONFIG_HEADERS= $(SHELL) ./config.status
installch: $(srcdir)/installch.in config.status
	cd $(top_builddir) && \
	  CONFIG_FILES=$(subdir)/$@ CONFIG_HEADERS= $(SHELL) ./config.status
	@chmod +x installch; touch installch
etc/pkg-config.mk: $(srcdir)/etc/pkg-config.mk.in config.status
	cd $(top_builddir) && \
	  CONFIG_FILES=$(subdir)/$@ CONFIG_HEADERS= $(SHELL) ./config.status

$(srcdir)/configure: $(srcdir)/configure.in $(srcdir)/m4/click.m4
	cd $(srcdir) && $(ACLOCAL) && $(AUTOCONF)
config.status: $(srcdir)/configure
	$(SHELL) $(srcdir)/configure  '--enable-wifi' '--enable-local'
Makefile: config.status $(srcdir)/Makefile.in
	cd $(top_builddir) && \
	  CONFIG_FILES=$@ CONFIG_HEADERS= $(SHELL) ./config.status
config.h: stamp-h
stamp-h: $(srcdir)/config.h.in $(srcdir)/config-bsdmodule.h.in $(srcdir)/config-linuxmodule.h.in $(srcdir)/config-ns.h.in $(srcdir)/config-userlevel.h.in config.status
	cd $(top_builddir) \
	  && CONFIG_FILES= $(SHELL) ./config.status
	echo > stamp-h

check-filenames:
	@a=`find . \( -name \*.cc -or -name \*.c \) -print | sed 's/.*\/\(.*\)\.c*$$/\1.o/' | grep -v 'elements\.o' | sort | uniq -d`; \
	if test -z $$a; then echo OK; else echo "*** warning: duplicate object file names:"; echo "$$a"; fi

clean:
	@-for d in  bsdmodule exopc linuxmodule ns userlevel tools doc; do (cd $$d && $(MAKE) clean); done
	-rm -f elementmap.xml conftest.*
distclean:
	@-for d in  bsdmodule exopc linuxmodule ns userlevel tools doc; do (cd $$d && $(MAKE) distclean); done
	-rm -f Makefile config.status etc/libclick/Makefile
	-rm -f include/click/config.h include/click/config-*.h include/click/pathvars.h
	-rm -f config.cache config.log click-buildtool click-compile config.mk stamp-h
	-rm -f etc/pkg-config.mk
	-rm -f elementmap.xml conftest.* installch


distdir = $(PACKAGE)-$(VERSION)
top_distdir = $(distdir)

dist: distdir
	tar czf $(distdir).tar.gz $(distdir)
	-rm -rf $(distdir)
distdir: $(srcdir)/configure
	-rm -rf doc/click.info* doc/testie.1 $(srcdir)/doc/click.info* $(srcdir)/doc/testie.1
	cd doc && $(MAKE) info testie.1
	cd $(srcdir)/etc/samplepackage && $(AUTOCONF)
	-rm -rf $(distdir)
	mkdir $(distdir)
	chmod 777 $(distdir)
	@echo Copying library, documentation, configuration, and driver files...
	[ "$(srcdir)" = . ] || cp doc/click.info* doc/testie.1 $(srcdir)/doc
	@for file in `cat $(srcdir)/DISTFILES | grep .`; do \
	  if expr "$$file" : '.*:$$' >/dev/null 2>&1; then \
	    d=`echo $$file | sed 's/:$$//;s/^\.\///'`; \
	  elif test -d "$(srcdir)/$$d/$$file"; then \
	    mkdir $(distdir)/$$d/$$file; \
	    chmod 777 $(distdir)/$$d/$$file; \
	  else \
	    for f in `cd $(srcdir)/$$d && echo $$file`; do \
	      test -f "$(distdir)/$$d/$$f" \
	      || ln $(srcdir)/$$d/$$f $(distdir)/$$d/$$f 2> /dev/null \
	      || cp -p $(srcdir)/$$d/$$f $(distdir)/$$d/$$f \
	      || echo "Could not copy $$d/$$f!" 1>&2; \
	  done; fi; \
	done
	@echo Copying element files...
	@d=$(srcdir); \
	for dir in `cd $$d && find elements -type d | grep -v 'exopc\|CVS'`; do \
	  mkdir $(distdir)/$$dir 2>/dev/null; \
	  chmod 777 $(distdir)/$$dir; \
	  for cfile in `cd $$d && find $$dir -maxdepth 1 \( -type f -and \( -name \[^,.]\*.cc -or -name \[^,.]\*.c -or -name \[^,.]\*.hh -or -name \[^,.]\*.h -or -name README \) \) -print`; do \
	    ln $$d/$$cfile $(distdir)/$$cfile; \
	  done; \
	done
	@echo Removing files not meant for distribution...
	@if test -r $(srcdir)/NODIST; then \
	for i in `cat $(srcdir)/NODIST`; do \
	  rm -rf $(distdir)/$$i; \
	done; fi
	@if grep -q 'Id:.*benjie' `find $(srcdir)/etc -maxdepth 1 -type f`; then \
	  echo 'ERROR: Benjie must be punished!'; exit 1; \
	fi
	@if test `grep 'CLICK_VERSION=' $(srcdir)/configure.in` != `grep 'CLICK_VERSION=' $(srcdir)/etc/libclick/lc-configure.in`; then \
	  echo 'ERROR: Bad libclick CLICK_VERSION!'; exit 1; \
	fi


.PHONY: all always elemlist elemlists \
	bsdmodule exopc linuxmodule ns tools userlevel \
	clean distclean dist distdir \
	install install-doc install-lib install-man install-local install-include install-local-include \
	uninstall uninstall-local uninstall-local-include
