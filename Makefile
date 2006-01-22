# include in user config or use default values instead
-include ./config
LUA_PATH ?= /usr/share/lua
LUA_CPATH ?= /usr/local/lua
LUAINC ?= /usr/include/lua
LUA ?= /usr/bin/lua
LUAC ?= /usr/bin/luac
CRYPTOLIB ?= -lcrypto
LUATYPE ?= lc

# other default stuff that generally won't change
.SUFFIXES:
srcdir := ./src
outdir := ./obj
tstdir := ./tests
INSTALL = install
SHELL = /bin/sh
MODULES = evp hmac
CFLAGS = $(CRYPTOINC) $(LUAINC) -ansi -pedantic -Wall -O2
SOOBJS = $(outdir)/crypto/core.so $(foreach module,$(MODULES),$(outdir)/crypto/$(module)/core.so)
LCOBJS = $(outdir)/crypto.$(LUATYPE) $(foreach module,$(MODULES),$(outdir)/crypto/$(module).$(LUATYPE))
LDFLAGS = $(CRYPTOLIB)

# default target
.PHONY: all $(outdir)
all: $(outdir) $(SOOBJS) $(LCOBJS)

# rule to create build directory
$(outdir):
	@if [ ! -d $(outdir) ]; then $(INSTALL) -d $(outdir); fi
	@if [ ! -d $(outdir)/crypto ]; then $(INSTALL) -d $(outdir); fi
	@$(foreach module,$(MODULES),if [ ! -d $(outdir)/crypto/$(module) ]; then $(INSTALL) -d $(outdir)/crypto/$(module); fi ; )

# rules for building the final so's
$(outdir)/%/core.so: $(outdir)/%.o
	$(CC) $(LDFLAGS) -shared $< -o $@

$(outdir)/crypto/%/core.so: $(outdir)/%.o
	$(CC) $(LDFLAGS) -shared $< -o $@

# rules for building intermediary objects
$(outdir)/%.o: $(srcdir)/%.c $(srcdir)/%.h
	$(CC) -c $(CFLAGS) $(CPPFLAGS) $< -o $@

# rules for building the final lua/lc files
$(outdir)/%.lc: $(srcdir)/%.lua
	$(LUAC) $(LUACFLAGS) -o $@ $<

$(outdir)/crypto/%.lc: $(srcdir)/%.lua
	$(LUAC) $(LUACFLAGS) -o $@ $<

$(outdir)/%.lua: $(srcdir)/%.lua
	cp $< $@

$(outdir)/crypto/%.lua: $(srcdir)/%.lua
	cp $< $@

# cleanup rules
.PHONY: clean distclean mostlyclean
clean:
	rm -fr $(outdir)
	rm -f ./core ./core.*

distclean: clean ;

mostlyclean:
	rm -fr $(outdir)/*
	rm -f ./core ./core.*

# template for generating un/install rules
define INSTALL_TEMPLATE
$(1)_install: $(outdir)/crypto/$(1)/core.so $(outdir)/crypto/$(1).$(LUATYPE)
	$(INSTALL) -d $(LUA_CPATH)/crypto/$(1)
	$(INSTALL) -D $(outdir)/crypto/$(1)/core.so $(LUA_CPATH)/crypto/$(1)/core.so
	$(INSTALL) -D $(outdir)/crypto/$(1).$(LUATYPE) $(LUA_PATH)/crypto/$(1).$(LUATYPE)

$(1)_uninstall:
	-rm $(LUA_CPATH)/crypto/$(1)/core.so
	-rm -r $(LUA_CPATH)/crypto/$(1)/
	-rm $(LUA_PATH)/crypto/$(1).$(LUATYPE)
endef

# install rules
$(foreach module,$(MODULES),$(eval $(call INSTALL_TEMPLATE,$(module))))

.PHONY: install crypto_install uninstall crypto_uninstall

crypto_install:
	$(INSTALL) -d $(LUA_PATH)/crypto/
	$(INSTALL) -d $(LUA_CPATH)/crypto/
	$(INSTALL) -D $(outdir)/crypto/core.so $(LUA_CPATH)/crypto/core.so
	$(INSTALL) -D $(outdir)/crypto.$(LUATYPE) $(LUA_CPATH)/crypto.$(LUATYPE)

install: crypto_install $(foreach module,$(MODULES),$(module)_install) ;

# uninstall rules
crypto_uninstall:
	-rm $(LUA_CPATH)/crypto/core.so
	-rm -r $(LUA_CPATH)/crypto/
	-rm -r $(LUA_PATH)/crypto/
	-rm $(LUA_PATH)/crypto.$(LUATYPE)

uninstall: $(foreach module,$(MODULES),$(module)_uninstall) crypto_uninstall

# rule to run the test suite
.PHONY: tests
tests:
	@echo ""
	@if [ -x $(LUA) ]; then \
		echo "Running tests..."; \
		LUA_PATH="$(outdir)/?.$(LUATYPE)"; \
		LUA_CPATH="$(outdir)/?.so"; \
		export LUA_PATH LUA_CPATH; \
		$(LUA) $(tstdir)/test.lua $(tstdir)/message; \
	else \
		echo "Lua interpreter not found; not running tests."; \
		echo "Set LUA to your interpreter location and execute"; \
		echo "'make tests' to run the test suite."; \
	fi
	@echo ""
