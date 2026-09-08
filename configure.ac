AC_CONFIG_MACRO_DIRS([m4])
AC_INIT([azfilesauth],[1.0.12],[rbudhiraja@microsoft.com])
AM_INIT_AUTOMAKE([foreign])
AC_PROG_CXX
LT_INIT
AC_PREFIX_DEFAULT(/usr)

AC_CHECK_HEADER([yaml.h], [], [AC_MSG_ERROR([libyaml headers not found])])
AC_CHECK_LIB([yaml], [yaml_parser_initialize], [YAML_LIBS="-lyaml"], [AC_MSG_ERROR([libyaml library not found])])
AC_SUBST([YAML_LIBS])

# Detect Python and get the correct site-packages directory.
# Azure Identity requires Python 3.7 or newer; the package contract uses 3.8.
AM_PATH_PYTHON([3.8])
AC_ARG_VAR([PYTHON_SITE_PKG], [Python site-packages directory])
AS_IF([test -z "$PYTHON_SITE_PKG"], [
    PYTHON_SITE_PKG=`$PYTHON -c "import sysconfig; print(sysconfig.get_path('purelib'))"`
])
AC_SUBST([PYTHON_SITE_PKG])

AC_CONFIG_FILES([
                 Makefile
                 src/azfilesrefresh.py
                 include/azfilesauthversion.h
                 ])
AC_OUTPUT
