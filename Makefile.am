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
bin_SCRIPTS = azfilesauthmanager azfilesrefresh

# Create Python package directory
pymoduledir = $(PYTHON_SITE_PKG)/azfilesauth
pymodule_PYTHON = src/azfilesauthmanager.py 

# Create __init__.py to make the directory a Python package
install-data-hook:
	mkdir -p $(DESTDIR)$(pymoduledir)
	echo "from .azfilesauthmanager import *" > $(DESTDIR)$(pymoduledir)/__init__.py

# Create systemd service file
systemddir = /etc/systemd/system
systemd_DATA = src/azfilesrefresh.service

# Ensure scripts are installed without .py extension
azfilesauthmanager: src/azfilesauthmanager.py
	cp $< $@
	chmod +x $@

azfilesrefresh: src/azfilesrefresh.py
	cp $< $@
	chmod +x $@

EXTRA_DIST = src/azfilesauthmanager.py src/azfilesrefresh.py config/azfilesrefresh.service
CLEANFILES = azfilesauthmanager azfilesrefresh

# ensure only one instance of service is running
