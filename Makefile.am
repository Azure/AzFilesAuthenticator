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
	if [ -n "$(DESTDIR)" ]; then sed -i "s|$(DESTDIR)||g" $(DESTDIR)/opt/azfilesauth/venv/pyvenv.cfg; fi
	$(DESTDIR)/opt/azfilesauth/venv/bin/python -m pip install --no-cache-dir --no-compile --disable-pip-version-check --require-hashes -r $(srcdir)/requirements.lock
	venv_site_pkg="$$($(DESTDIR)/opt/azfilesauth/venv/bin/python -c 'import sysconfig; print(sysconfig.get_path("purelib"))')"; \
	mkdir -p "$$venv_site_pkg/azfilesauth"; \
	$(INSTALL) -m 0644 src/azfilesauthmanager.py "$$venv_site_pkg/azfilesauth/azfilesauthmanager.py"; \
	echo "from .azfilesauthmanager import *" > "$$venv_site_pkg/azfilesauth/__init__.py"; \
	py_ver="$$($(DESTDIR)/opt/azfilesauth/venv/bin/python -c 'import sys; print(f"python{sys.version_info.major}.{sys.version_info.minor}")')"; \
	$(DESTDIR)/opt/azfilesauth/venv/bin/python -m pip uninstall -y pip; \
	find $(DESTDIR)/opt/azfilesauth/venv/bin -mindepth 1 -maxdepth 1 -delete; \
	venv_site_rel="$${venv_site_pkg#$(DESTDIR)}"; \
	runtime_python="$(PYTHON)"; \
	printf '#!/bin/sh\nexport PYTHONPATH="%s$${PYTHONPATH:+:$${PYTHONPATH}}"\nif command -v %s >/dev/null 2>&1; then\n    exec %s "$$@"\nelif [ -x "%s" ]; then\n    exec "%s" "$$@"\nelse\n    exec python3 "$$@"\nfi\n' "$$venv_site_rel" "$$py_ver" "$$py_ver" "$$runtime_python" "$$runtime_python" > $(DESTDIR)/opt/azfilesauth/venv/bin/python; \
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

EXTRA_DIST = src/azfilesauthmanager.py src/azfilesrefresh.py config/azfilesrefresh.service config/config.yaml requirements.in requirements.lock
CLEANFILES = azfilesauthmanager azfilesrefresh

# ensure only one instance of service is running

# Install public headers
include_HEADERS = include/azfilesauth.h include/azfilesauthversion.h
