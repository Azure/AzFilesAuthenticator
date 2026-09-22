AUTOMAKE_OPTIONS = subdir-objects
ACLOCAL_AMFLAGS = -I m4

lib_LTLIBRARIES = libazfilesauth.la
libazfilesauth_la_SOURCES = src/azfilesauth.cpp
libazfilesauth_la_LDFLAGS = -shared -fPIC -lcurl -lkrb5
libazfilesauth_la_LIBADD = $(YAML_LIBS)
libazfilesauth_la_CPPFLAGS = -Iinclude

# Install configuration file
configdir = /etc/azfilesauth

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
	mkdir -p $(DESTDIR)$(configdir)
	if test ! -e $(DESTDIR)$(configdir)/config.yaml; then \
		$(INSTALL) -m 0600 config/config.yaml $(DESTDIR)$(configdir)/config.yaml; \
	fi
	$(PYTHON) -m venv $(DESTDIR)/opt/azfilesauth/venv
	sed -i "s|$(DESTDIR)||g" $(DESTDIR)/opt/azfilesauth/venv/pyvenv.cfg
	$(DESTDIR)/opt/azfilesauth/venv/bin/python -m pip install --no-cache-dir --disable-pip-version-check --upgrade pip
	$(DESTDIR)/opt/azfilesauth/venv/bin/python -m pip install --no-cache-dir --disable-pip-version-check "azure-identity>=1.14.0" "azure-core>=1.26.0" "PyYAML>=5.4"
	venv_site_pkg="$$($(DESTDIR)/opt/azfilesauth/venv/bin/python -c 'import sysconfig; print(sysconfig.get_path("purelib"))')"; \
	mkdir -p "$$venv_site_pkg/azfilesauth"; \
	$(INSTALL) -m 0644 src/azfilesauthmanager.py "$$venv_site_pkg/azfilesauth/azfilesauthmanager.py"; \
	echo "from .azfilesauthmanager import *" > "$$venv_site_pkg/azfilesauth/__init__.py"; \
	venv_site_rel="$${venv_site_pkg#$(DESTDIR)}"; \
	find $(DESTDIR)/opt/azfilesauth/venv/bin -mindepth 1 -maxdepth 1 -delete; \
	runtime_python="$(PYTHON)"; \
	printf '#!/bin/sh\nexport PYTHONPATH="%s$${PYTHONPATH:+:$${PYTHONPATH}}"\nexec %s "$$@"\n' "$$venv_site_rel" "$$runtime_python" > $(DESTDIR)/opt/azfilesauth/venv/bin/python; \
	chmod 0755 $(DESTDIR)/opt/azfilesauth/venv/bin/python
	for script in $(DESTDIR)$(bindir)/azfilesauthmanager $(DESTDIR)$(bindir)/azfilesrefresh; do \
		if [ -f "$$script" ]; then sed -i "1c#!/opt/azfilesauth/venv/bin/python" "$$script"; fi; \
	done

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

EXTRA_DIST = src/azfilesauthmanager.py src/azfilesrefresh.py config/azfilesrefresh.service config/config.yaml
CLEANFILES = azfilesauthmanager azfilesrefresh

# ensure only one instance of service is running

# Install public headers
include_HEADERS = include/azfilesauth.h include/azfilesauthversion.h
