INSTALLDIR ?= /usr/local
BINDIR ?= $(INSTALLDIR)/bin
SYSCONFDIR ?= $(INSTALLDIR)/etc
LIBEXECDIR ?= $(INSTALLDIR)/lib/sso

SODIUM_CPPFLAGS ?= -I/usr/local/include
SODIUM_LDFLAGS ?= -L/usr/local/lib -lsodium
CFLAGS ?= -O2 -fPIC
CPPFLAGS += $(SODIUM_CPPFLAGS)
LDFLAGS += -ldl $(SODIUM_LDFLAGS)
DYLIB_CFLAGS ?= $(CFLAGS) -shared

TARGETS_BIN_SERVER = sso_server
TARGETS_BIN_CLIENT = sso_client
TARGETS_MODULES_SERVER = server/server.o shared/tai.o
TARGETS_MODULES_CLIENT = client/client.o shared/tai.o

TARGETS = server client
TARGETS_SERVER = $(TARGETS_BIN_SERVER) $(TARGETS_MODULES_SERVER)
TARGETS_CLIENT = $(TARGETS_BIN_CLIENT) $(TARGETS_MODULES_CLIENT)

all: $(TARGETS)

clean:
	rm -f $(TARGETS_SERVER) $(TARGETS_CLIENT)
	cd hiredis && make clean

distclean: clean

install: all
	mkdir -p $(BINDIR) $(SYSCONFDIR) $(LIBEXECDIR)
	cp $(TARGETS_BIN) $(BINDIR)
	cp $(TARGETS_MODULES) $(LIBEXECDIR)

server: $(TARGETS_MODULES_SERVER)
	cd hiredis && make
	$(CC) -o sso_server hiredis/libhiredis.a $(TARGETS_MODULES_SERVER) $(LDFLAGS)

client: $(TARGETS_MODULES_CLIENT)
	$(CC) -o sso_client $(TARGETS_MODULES_CLIENT) $(LDFLAGS)

%.o: %.c $(HEADERS)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
