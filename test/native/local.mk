# Native self-test for the credential cache owner check (make check). The
# root variant needs two distinct UIDs; it exits 77 (SKIP) when
# not run as root or when those UIDs are unusable.
check_PROGRAMS = test/native/ccache_selftest test/native/ccache_selftest_root
test_native_ccache_selftest_SOURCES = test/native/ccache_owner_check_selftest.cpp
test_native_ccache_selftest_CPPFLAGS = -I$(top_srcdir)/include -I$(top_builddir)/include
test_native_ccache_selftest_LDADD = -lcurl -lkrb5 $(YAML_LIBS)
test_native_ccache_selftest_LDFLAGS = -Wl,--wrap=open,--wrap=close,--wrap=lstat,--wrap=krb5_cc_get_principal,--wrap=krb5_cc_initialize,--wrap=krb5_cc_store_cred
test_native_ccache_selftest_root_SOURCES = test/native/ccache_owner_check_selftest.cpp
test_native_ccache_selftest_root_CPPFLAGS = $(test_native_ccache_selftest_CPPFLAGS) -DCCACHE_SELFTEST_ROOT
test_native_ccache_selftest_root_LDADD = $(test_native_ccache_selftest_LDADD)
test_native_ccache_selftest_root_LDFLAGS = $(test_native_ccache_selftest_LDFLAGS)
TESTS = $(check_PROGRAMS)
