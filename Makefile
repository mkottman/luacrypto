T= crypto
V= 0.2.0
CONFIG= ./config

include $(CONFIG)

OBJS= src/l$T.o
SRCS= src/l$T.h src/l$T.c
TESTS=tests/*.lua

lib: $(LIBNAME)

$(LIBNAME): $(OBJS)
	export MACOSX_DEPLOYMENT_TARGET="10.3"; $(CC) $(CFLAGS) $(LIB_OPTION) -o $(LIBNAME) $(OBJS) $(OPENSSL_LIBS)

install: src/$(LIBNAME)
	mkdir -p $(LUA_LIBDIR)
	cp src/$(LIBNAME) $(LUA_LIBDIR)

clean:
	rm -f src/$(LIBNAME) $(OBJS) $(COMPAT_O)

tests: test
test: $(TESTS) lib
	./tests/run-tests

.PHONY: test tests
