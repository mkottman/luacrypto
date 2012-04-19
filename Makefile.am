ACLOCAL_AMFLAGS = -I m4

SUBDIRS = src \
	  doc

test: all
	$(MAKE) -C tests

clean-local:
	$(MAKE) -C tests clean
	
