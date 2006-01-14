# Change these to reflect your Lua installation locations. The system
# independent Lua files (LUA_PATH), the system dependent Lua files (LUA_CPATH),
# and the Lua include files (LUAINC) are required to compile and install.
LUA_PATH = /usr/share/lua
LUA_CPATH = /usr/local/lua
LUAINC = /usr/include/lua

# The location of the Lua interpreter and Lua compiler are required to make the
# tests and luadocs, and to generate compiled Lua libraries instead of source
# Lua libraries for install.
LUA = /usr/bin/lua
LUAC = /usr/bin/luac

# This provides the necessary flags for linking against your OpenSSL libcrypto
# installation. Change it to suit your system if necessary.
LDFLAGS = -lcrypto
#CFLAGS =

# Set this to lc to install the precompiled Lua libraries (compiled with luac),
# or to lua to install the source Lua libraries.
LUATYPE = lc

# You shouldn't need to change anything below here.
.SUFFIXES:
srcdir := ./src
outdir := ./obj
tstdir := ./tests
INSTALL = install
SHELL = /bin/sh
MODULES = evp hmac
CFLAGS = -I$(LUAINC) -ansi -pedantic -Wall -O2
SOOBJS = $(outdir)/crypto.so $(foreach module,$(MODULES),$(outdir)/$(module).so)
LCOBJS = $(outdir)/crypto.$(LUATYPE) $(foreach module,$(MODULES),$(outdir)/$(module).$(LUATYPE))

.PHONY: all $(outdir)
all: $(outdir) $(SOOBJS) $(LCOBJS)

$(outdir):
	@if [ ! -d $(outdir) ]; then $(INSTALL) -d $(outdir); fi

$(outdir)/%.so:	$(outdir)/%.o
	$(CC) $(LDFLAGS) -shared $< -o $@

$(outdir)/%.o:	$(srcdir)/%.c 
	$(CC) -c $(CFLAGS) $(CPPFLAGS) $< -o $@

$(outdir)/%.lc:	$(srcdir)/%.lua
	$(LUAC) $(LUACFLAGS) -o $@ $<

$(outdir)/%.lua: $(srcdir)/%.lua
	cp $< $@

luadoc: $(srcdir)/crypto.lua $(foreach module,$(MODULES),$(srcdir)/$(module).lua)
	@if [ -x $(LUA) ]; then \
		echo "Building luadoc..."; \
		LUA_PATH="$(LUA_PATH)/?.$(LUATYPE)"; \
		LUA_CPATH="$(LUA_CPATH)/?.so"; \
		export LUA_PATH LUA_CPATH; \
		$(LUA) $(srcdir)/test.lua $(srcdir)/crypto.lua; \
	else \
		echo "Lua interpreter not found; not building luadoc."; \
		echo "Set LUA to your interpreter location and execute"; \
		echo "'make tests' to run the test suite."; \
	fi

.PHONY: clean distclean mostlyclean
clean:
	rm -fr $(outdir)
	rm -f ./core ./core.*

distclean: clean ;

mostlyclean:
	rm -fr $(outdir)/*
	rm -f ./core ./core.*

define INSTALL_TEMPLATE
$(1)_install: $(outdir)/$(1).so $(outdir)/$(1).$(LUATYPE)
	$(INSTALL) -d $(LUA_CPATH)/crypto/$(1)
	$(INSTALL) -D $(outdir)/$(1).so $(LUA_CPATH)/crypto/$(1)/core.so
	$(INSTALL) -D $(outdir)/$(1).$(LUATYPE) $(LUA_PATH)/crypto/$(1).$(LUATYPE)

$(1)_uninstall:
	-rm $(LUA_CPATH)/crypto/$(1)/core.so
	-rm -r $(LUA_CPATH)/crypto/$(1)/
	-rm $(LUA_PATH)/crypto/$(1).$(LUATYPE)
endef

$(foreach module,$(MODULES),$(eval $(call INSTALL_TEMPLATE,$(module))))

.PHONY: install crypto_install uninstall crypto_uninstall

crypto_install:
	$(INSTALL) -d $(LUA_PATH)/crypto/
	$(INSTALL) -d $(LUA_CPATH)/crypto/
	$(INSTALL) -D $(outdir)/crypto.so $(LUA_CPATH)/crypto/core.so
	$(INSTALL) -D $(outdir)/crypto.$(LUATYPE) $(LUA_CPATH)/crypto.$(LUATYPE)

install: crypto_install $(foreach module,$(MODULES),$(module)_install) tests ;

crypto_uninstall:
	-rm $(LUA_CPATH)/crypto/core.so
	-rm -r $(LUA_CPATH)/crypto/
	-rm -r $(LUA_PATH)/crypto/
	-rm $(LUA_PATH)/crypto.$(LUATYPE)

uninstall: $(foreach module,$(MODULES),$(module)_uninstall) crypto_uninstall

.PHONY: tests
tests:
	@echo ""
	@if [ -x $(LUA) ]; then \
		echo "Running tests..."; \
		LUA_PATH="$(LUA_PATH)/?.$(LUATYPE)"; \
		LUA_CPATH="$(LUA_CPATH)/?.so"; \
		export LUA_PATH LUA_CPATH; \
		$(LUA) $(tstdir)/test.lua $(tstdir)/message; \
	else \
		echo "Lua interpreter not found; not running tests."; \
		echo "Set LUA to your interpreter location and execute"; \
		echo "'make tests' to run the test suite."; \
	fi
	@echo ""
