CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -std=gnu11
PREFIX  ?= /usr/local
BIN      = nwu

$(BIN): nwu.c
	$(CC) $(CFLAGS) -o $@ $<

install: $(BIN)
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 0755 $(BIN) $(DESTDIR)$(PREFIX)/bin/$(BIN)

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/$(BIN)

clean:
	rm -f $(BIN)

.PHONY: install uninstall clean
