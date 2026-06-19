CXX      ?= c++
CXXFLAGS ?= -O2 -Wall -Wextra -std=gnu++20
PREFIX   ?= /usr/local
DESTDIR  ?=

# Installed icon / desktop-entry basename (icon theme name = nwu).
APP_NAME  = nwu

BIN       = nwu
GUI       = nwu-gui
CORE_SRC  = nwu_core.cpp
CORE_OBJ  = nwu_core.o

# GTK4 for the GUI only; the CLI has no third-party dependencies.
GTK_CFLAGS := $(shell pkg-config --cflags gtk4 2>/dev/null)
GTK_LIBS   := $(shell pkg-config --libs   gtk4 2>/dev/null)

# install locations
BINDIR     = $(PREFIX)/bin
DATADIR    = $(PREFIX)/share
ICONDIR    = $(DATADIR)/icons/hicolor/scalable/apps
DESKTOPDIR = $(DATADIR)/applications

all: $(BIN) $(GUI)

$(CORE_OBJ): $(CORE_SRC) nwu_core.h
	$(CXX) $(CXXFLAGS) -c $(CORE_SRC) -o $@

# command-line front-end
$(BIN): nwu.cpp nwu_core.h $(CORE_OBJ)
	$(CXX) $(CXXFLAGS) -o $@ nwu.cpp $(CORE_OBJ)

# GTK4 GUI front-end
$(GUI): nwu-gui.cpp nwu_core.h $(CORE_OBJ)
	@if [ -z "$(GTK_LIBS)" ]; then \
	  echo "error: gtk4 not found via pkg-config (install libgtk-4-dev / gtk4-devel)"; \
	  exit 1; fi
	$(CXX) $(CXXFLAGS) $(GTK_CFLAGS) -o $@ nwu-gui.cpp $(CORE_OBJ) $(GTK_LIBS)

# build only the CLI (no GTK needed)
cli: $(BIN)

install: all
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 $(BIN) $(DESTDIR)$(BINDIR)/$(BIN)
	install -m 0755 $(GUI) $(DESTDIR)$(BINDIR)/$(GUI)
	install -d $(DESTDIR)$(ICONDIR)
	install -m 0644 icons/$(APP_NAME).svg $(DESTDIR)$(ICONDIR)/$(APP_NAME).svg
	install -d $(DESTDIR)$(DESKTOPDIR)
	install -m 0644 $(APP_NAME).desktop $(DESTDIR)$(DESKTOPDIR)/$(APP_NAME).desktop
	-gtk-update-icon-cache -q -t -f $(DESTDIR)$(DATADIR)/icons/hicolor 2>/dev/null || true
	-update-desktop-database -q $(DESTDIR)$(DESKTOPDIR) 2>/dev/null || true
	@echo "installed: $(BINDIR)/$(BIN), $(BINDIR)/$(GUI), icon + desktop entry"

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(BIN)
	rm -f $(DESTDIR)$(BINDIR)/$(GUI)
	rm -f $(DESTDIR)$(ICONDIR)/$(APP_NAME).svg
	rm -f $(DESTDIR)$(DESKTOPDIR)/$(APP_NAME).desktop
	-gtk-update-icon-cache -q -t -f $(DESTDIR)$(DATADIR)/icons/hicolor 2>/dev/null || true
	-update-desktop-database -q $(DESTDIR)$(DESKTOPDIR) 2>/dev/null || true
	@echo "uninstalled nwu / nwu-gui, icon and desktop entry"

clean:
	rm -f $(BIN) $(GUI) $(CORE_OBJ)

.PHONY: all cli install uninstall clean
