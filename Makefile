# if you want to change/override some variables, do so in a file called
# config.mak, which is gets included automatically if it exists.

prefix ?= /usr/local
exec_prefix ?= $(prefix)
bindir ?= $(exec_prefix)/bin
sysconfdir ?= /etc
systemdunitdir ?= /etc/systemd/system
SERVICE_USER ?= muonsocks

PROG = muonsocks
C_SRCS =  $(sort nk/privs.c main.c)
OBJS = $(C_SRCS:.c=.o) $(CXX_SRCS:.cc=.o)
DEPS = $(C_SRCS:.c=.d) $(CXX_SRCS:.cc=.d)

WARN_CFLAGS = -Wall -pedantic -Wextra -Wformat=2 -Wformat-nonliteral \
	-Wformat-security -Wshadow -Wpointer-arith -Wmissing-prototypes \
	-Wcast-qual -Wsign-conversion -Wstrict-overflow=5
HARDEN_CFLAGS = -fstack-protector-strong -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2
HARDEN_LDFLAGS = -Wl,-z,relro,-z,now

CFLAGS = -MMD -O2 -flto -s -DNDEBUG -std=c17 -I. \
	-D_POSIX_C_SOURCE=200809L -D_XOPEN_SOURCE=700 -D_GNU_SOURCE
CPPFLAGS += $(INC)

#CFLAGS += -fsanitize=undefined
#LDFLAGS += -fsanitize=undefined

-include config.mak

# Keep warnings even if config.mak replaces CFLAGS.
CFLAGS += $(WARN_CFLAGS)

# make SANITIZE=address,undefined — drop hardening that fights sanitizers
SANITIZE ?=
ifneq ($(SANITIZE),)
CFLAGS = -MMD -O1 -g -fno-omit-frame-pointer -std=c17 -I. $(WARN_CFLAGS) \
	-fsanitize=$(SANITIZE) -D_POSIX_C_SOURCE=200809L -D_XOPEN_SOURCE=700 -D_GNU_SOURCE
LDFLAGS = -fsanitize=$(SANITIZE)
else
CFLAGS += $(HARDEN_CFLAGS)
LDFLAGS += $(HARDEN_LDFLAGS)
endif

all: $(PROG)

$(PROG): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -lpthread -o $@ $^

-include $(DEPS)

install: $(PROG)
	DESTDIR="$(DESTDIR)" prefix="$(prefix)" bindir="$(bindir)" \
	sysconfdir="$(sysconfdir)" systemdunitdir="$(systemdunitdir)" \
	SERVICE_USER="$(SERVICE_USER)" PROG="$(PROG)" ./install.sh

uninstall:
	DESTDIR="$(DESTDIR)" prefix="$(prefix)" bindir="$(bindir)" \
	sysconfdir="$(sysconfdir)" systemdunitdir="$(systemdunitdir)" \
	SERVICE_USER="$(SERVICE_USER)" PROG="$(PROG)" ./install.sh --uninstall

update:
	./install.sh --update

test: $(PROG)
	python3 tests/test_security.py ./$(PROG)

clean:
	rm -f $(PROG) $(OBJS) $(DEPS)

.PHONY: all clean install uninstall update test
