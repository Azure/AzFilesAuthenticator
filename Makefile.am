AUTOMAKE_OPTIONS = subdir-objects
ACLOCAL_AMFLAGS = -I m4

lib_LTLIBRARIES = libazfilesauth.la
libazfilesauth_la_SOURCES = src/azfilesauth.cpp
libazfilesauth_la_LDFLAGS = -shared -fPIC -lcurl -lkrb5
libazfilesauth_la_CPPFLAGS = -Iinclude

# Install configuration file
configdir = /etc/azfilesauth
config_DATA = config/config.yaml

# Python Script Installation
bindir = $(prefix)/bin
bin_SCRIPTS = azfilesauthmanager

# Ensure it is installed without .py
azfilesauthmanager: src/azfilesauthmanager.py
	cp $< $@
	chmod +x $@

EXTRA_DIST = src/azfilesauthmanager.py
CLEANFILES = azfilesauthmanager