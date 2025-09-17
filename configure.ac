AC_CONFIG_MACRO_DIRS([m4])
AC_INIT([azfilesauth],[1.0.7],[rbudhiraja@microsoft.com])
AM_INIT_AUTOMAKE([foreign])
AC_PROG_CXX
LT_INIT
AC_PREFIX_DEFAULT(/usr)

# Detect Python and get the correct site-packages directory
AM_PATH_PYTHON([3.6])
PYTHON_SITE_PKG=`$PYTHON -c "import sysconfig; print(sysconfig.get_path('stdlib'))"`
AC_SUBST([PYTHON_SITE_PKG])

AC_CONFIG_FILES([
                 Makefile
                 src/azfilesrefresh.py
                 include/azfilesauthversion.h
                 ])
AC_OUTPUT
