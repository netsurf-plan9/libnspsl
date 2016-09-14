CFLAGS := $(CFLAGS) -I$(BUILDDIR)

DIR_SOURCES := nspsl.c

src/nspsl.c:$(BUILDDIR)/psl.inc

$(BUILDDIR)/psl.inc:$(BUILDDIR)/public_suffix_list.dat
	perl src/genpubsuffix.pl $< > $@

$(BUILDDIR)/public_suffix_list.dat:
	wget -O $@ https://publicsuffix.org/list/public_suffix_list.dat

include $(NSBUILD)/Makefile.subdir
