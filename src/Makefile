DIR_SOURCES := nspsl.c

src/nspsl.c:src/psl.inc

src/psl.inc:src/public_suffix_list.dat
	perl src/genpubsuffix.pl $< > $@

src/public_suffix_list.dat:
	wget -O $@ https://publicsuffix.org/list/public_suffix_list.dat

include $(NSBUILD)/Makefile.subdir
