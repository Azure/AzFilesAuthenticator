// Native self-test for the credential cache owner check in src/azfilesauth.cpp
// (check_ccache_file and its use in set and clear). The library source is
// included to reach its static helpers and the g_ccache_dir test hook.
//
//   ccache_selftest       portable cases, any user (the owner is the caller).
//   ccache_selftest_root  (-DCCACHE_SELFTEST_ROOT) cases that need two distinct
//                         UIDs: a pre-existing cache owned by another user,
//                         other owners and concurrent creation. Exits 77
//                         (automake SKIP) unless AZF_SELFTEST_ROOT=1 is set, it
//                         runs as root, and the synthetic UIDs are usable, so
//                         package builds (which run `make check` as root) never
//                         run it.
//
// Owner and other are bare numeric UIDs (fork + setuid); no accounts are
// created. Each case gets a 1777 directory standing in for /tmp.
static const char* g_config_path = "/nonexistent/azfilesauth-selftest/config.yaml";
#define CONFIG_FILE_PATH g_config_path
#include "../../src/azfilesauth.cpp"

#include <ftw.h>
#include <grp.h>
#include <sys/wait.h>
#include <climits>
#include <cstdlib>
#include <functional>
#include <cstdarg>

static int g_checks = 0;
static int g_failures = 0;

#define CHECK(cond) do { \
        g_checks++; \
        if (!(cond)) { \
            g_failures++; \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        } \
    } while (0)

static const uid_t kOwnerUid = 4000123;
static const uid_t kOtherUid = 4000124;
static const char* kRealm = "FILES.AZURE.STORAGE.MICROSOFT.COM";
static const char* kClient = "AzureFileClient";
static const char* kHost = "acct.file.core.windows.net";

static std::string g_scratch;
static std::string g_dir_storage;

// Link-time interception applies only to references in this executable, not
// libkrb5's internals. A null pointer leaves every operation untouched.
enum class Injection { collide, denied, disappear, close_error };
struct Boundary {
    std::string path;
    Injection injection;
    int absent = 0, present = 0, opens = 0, closes = 0, initializes = 0, stores = 0;
    int created_fd = -1, retained_fd = -1, open_error = 0;
    bool removed = false, nofile = false, closed = false, private_before_init = false;
    bool collided = false, checked_before_open = false, checked_before_remove = false;
    mode_t create_mode = 0;
};
static Boundary* g_boundary = nullptr;

extern "C" {
int __real_open(const char*, int, ...);
int __real_close(int);
int __real_lstat(const char*, struct stat*);
krb5_error_code __real_krb5_cc_get_principal(krb5_context, krb5_ccache, krb5_principal*);
krb5_error_code __real_krb5_cc_initialize(krb5_context, krb5_ccache, krb5_principal);
krb5_error_code __real_krb5_cc_store_cred(krb5_context, krb5_ccache, krb5_creds*);
}

static void effective_uid(uid_t uid) {
    if (seteuid(uid) != 0) {
        std::perror("selftest seteuid");
        std::exit(2);
    }
}

static bool target_cache(krb5_context ctx, krb5_ccache cc) {
    return g_boundary && std::strcmp(krb5_cc_get_type(ctx, cc), "FILE") == 0 &&
           g_boundary->path == krb5_cc_get_name(ctx, cc);
}

extern "C" int __wrap_lstat(const char* path, struct stat* st) {
    int rc = __real_lstat(path, st);
    int error = errno;
    if (g_boundary && g_boundary->path == path) {
        if (rc == 0) g_boundary->present++;
        if (rc < 0 && error == ENOENT) g_boundary->absent++;
    }
    errno = error;
    return rc;
}

extern "C" int __wrap_open(const char* path, int flags, ...) {
    mode_t mode = 0;
    bool has_mode = (flags & O_CREAT) != 0;
#ifdef O_TMPFILE
    has_mode = has_mode || (flags & O_TMPFILE) == O_TMPFILE;
#endif
    if (has_mode) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, mode_t);
        va_end(args);
    }
    Boundary* b = g_boundary;
    if (!b || b->path != path || (flags & (O_CREAT | O_EXCL)) != (O_CREAT | O_EXCL))
        return has_mode ? __real_open(path, flags, mode) : __real_open(path, flags);
    b->opens++;
    b->create_mode = mode;
    b->checked_before_open = b->injection == Injection::disappear ?
        b->checked_before_remove && b->removed && b->nofile : b->absent == 1;
    if (b->injection == Injection::denied) {
        b->open_error = EACCES;
        errno = EACCES;
        return -1;
    }
    if (b->injection == Injection::collide && b->opens == 1) {
        // The root runner retains real/saved UID 0; only effective UID changes.
        // Keep a writable descriptor from the other user's file even after
        // switching back to the owner.
        uid_t owner = geteuid();
        effective_uid(0);
        effective_uid(kOtherUid);
        b->retained_fd = __real_open(path, O_RDWR | O_CREAT | O_EXCL, 0666);
        const char bytes[] = "other-owned-cache";
        if (b->retained_fd >= 0) {
            b->collided = fchmod(b->retained_fd, 0666) == 0 &&
                write(b->retained_fd, bytes, sizeof(bytes) - 1) == sizeof(bytes) - 1;
        }
        effective_uid(0);
        effective_uid(owner);
    }
    int fd = __real_open(path, flags, mode);
    int error = errno;
    b->created_fd = fd;
    if (fd < 0) b->open_error = error;
    errno = error;
    return fd;
}

extern "C" int __wrap_close(int fd) {
    int rc = __real_close(fd);
    int error = errno;
    if (g_boundary && fd == g_boundary->created_fd) {
        g_boundary->closes++;
        g_boundary->closed = rc == 0;
        if (g_boundary->injection == Injection::close_error) {
            errno = EIO;
            return -1;
        }
    }
    errno = error;
    return rc;
}

extern "C" krb5_error_code __wrap_krb5_cc_get_principal(
        krb5_context ctx, krb5_ccache cc, krb5_principal* principal) {
    bool remove = target_cache(ctx, cc) && g_boundary->injection == Injection::disappear &&
                  !g_boundary->removed;
    if (remove) {
        g_boundary->checked_before_remove = g_boundary->present == 1 && g_boundary->absent == 0;
        g_boundary->removed = unlink(g_boundary->path.c_str()) == 0;
    }
    krb5_error_code rc = __real_krb5_cc_get_principal(ctx, cc, principal);
    if (remove) g_boundary->nofile = rc == KRB5_FCC_NOFILE;
    return rc;
}

extern "C" krb5_error_code __wrap_krb5_cc_initialize(
        krb5_context ctx, krb5_ccache cc, krb5_principal principal) {
    if (target_cache(ctx, cc)) {
        Boundary& b = *g_boundary;
        b.initializes++;
        struct stat st;
        b.private_before_init = b.opens == 1 && b.closes == 1 && b.closed &&
            __real_lstat(b.path.c_str(), &st) == 0 && S_ISREG(st.st_mode) &&
            st.st_uid == kOwnerUid && (st.st_mode & 07777) == 0600 &&
            st.st_size == 0;
    }
    return __real_krb5_cc_initialize(ctx, cc, principal);
}

extern "C" krb5_error_code __wrap_krb5_cc_store_cred(
        krb5_context ctx, krb5_ccache cc, krb5_creds* cred) {
    if (target_cache(ctx, cc)) g_boundary->stores++;
    return __real_krb5_cc_store_cred(ctx, cc, cred);
}

// ---- small helpers ----

static std::string read_file(const std::string& path) {
    std::string out;
    int fd = ::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) return out;
    char buf[4096];
    ssize_t n;
    while ((n = ::read(fd, buf, sizeof(buf))) > 0) out.append(buf, n);
    ::close(fd);
    return out;
}

static bool write_file(const std::string& path, const std::string& data, mode_t mode) {
    int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, mode);
    if (fd < 0) return false;
    bool ok = ::write(fd, data.data(), data.size()) == static_cast<ssize_t>(data.size());
    ::close(fd);
    return ok && chmod(path.c_str(), mode) == 0;
}

static int count(const std::string& haystack, const std::string& needle) {
    int n = 0;
    for (size_t pos = haystack.find(needle); pos != std::string::npos; pos = haystack.find(needle, pos + 1)) n++;
    return n;
}

static std::string key32(const std::string& tag) {
    std::string k = "KEY-" + tag;
    k.resize(32, '#');
    return k;
}

// Runs fn and returns its result with stdout and stderr captured. Child
// processes started by fn inherit the redirection.
static int capture(const std::function<int()>& fn, std::string* out, std::string* err) {
    std::string po = g_scratch + "/stdout.capture", pe = g_scratch + "/stderr.capture";
    std::cout.flush();
    std::fflush(nullptr);
    int fo = ::open(po.c_str(), O_RDWR | O_CREAT | O_TRUNC, 0644);
    int fe = ::open(pe.c_str(), O_RDWR | O_CREAT | O_TRUNC, 0644);
    int so = dup(1), se = dup(2);
    dup2(fo, 1);
    dup2(fe, 2);
    int rc = fn();
    std::cout.flush();
    std::fflush(nullptr);
    dup2(so, 1);
    dup2(se, 2);
    ::close(so);
    ::close(se);
    ::close(fo);
    ::close(fe);
    *out = read_file(po);
    *err = read_file(pe);
    unlink(po.c_str());
    unlink(pe.c_str());
    return rc;
}

// Fresh 1777 directory standing in for /tmp; points g_ccache_dir at it.
static std::string new_case(const std::string& name) {
    std::string dir = g_scratch + "/" + name;
    if (mkdir(dir.c_str(), 0700) != 0 || chmod(dir.c_str(), 01777) != 0) {
        std::fprintf(stderr, "cannot create case %s: %s\n", dir.c_str(), strerror(errno));
        std::exit(2);
    }
    g_dir_storage = dir;
    g_ccache_dir = g_dir_storage.c_str();
    return dir;
}

static std::string cache_path(uid_t uid) {
    return std::string(g_ccache_dir) + "/krb5cc_" + std::to_string(uid);
}

// Runs fn in a child process as uid (gid = uid). Returns the child's exit code.
static int run_as(uid_t uid, const std::function<int()>& fn) {
    std::cout.flush();
    std::fflush(nullptr);
    pid_t pid = fork();
    if (pid == 0) {
        gid_t gid = uid;
        if (setgroups(1, &gid) != 0 || setgid(gid) != 0 || setuid(uid) != 0) _exit(100);
        int rc = fn();
        std::cout.flush();
        std::fflush(nullptr);
        _exit(rc);
    }
    int status = 0;
    if (pid < 0 || waitpid(pid, &status, 0) < 0 || !WIFEXITED(status)) return -1;
    return WEXITSTATUS(status);
}

// Runs fn as uid: directly when that is the caller, else in a child. The
// result is an exit code either way (-1 becomes 255).
static int as(uid_t uid, const std::function<int()>& fn) {
    return uid == geteuid() ? (fn() & 0xff) : run_as(uid, fn);
}

// ---- Kerberos fixtures ----

static std::string der(unsigned char tag, const std::string& body) {
    std::string out(1, static_cast<char>(tag));
    size_t n = body.size();
    if (n < 0x80) {
        out += static_cast<char>(n);
    } else if (n < 0x100) {
        out += static_cast<char>(0x81);
        out += static_cast<char>(n);
    } else {
        out += static_cast<char>(0x82);
        out += static_cast<char>(n >> 8);
        out += static_cast<char>(n & 0xff);
    }
    return out + body;
}

static std::string der_small_int(int v) { return der(0x02, std::string(1, static_cast<char>(v))); }
static std::string der_gstring(const std::string& s) { return der(0x1b, s); }

// Minimal DER Ticket for cifs/<host>; the opaque cipher carries a marker.
static std::string make_ticket_der(const std::string& host, const std::string& cipher) {
    std::string sname = der(0x30, der(0xa0, der_small_int(2)) +
                                  der(0xa1, der(0x30, der_gstring("cifs") + der_gstring(host))));
    std::string enc = der(0x30, der(0xa0, der_small_int(18)) + der(0xa2, der(0x04, cipher)));
    return der(0x61, der(0x30, der(0xa0, der_small_int(5)) + der(0xa1, der_gstring(kRealm)) +
                               der(0xa2, sname) + der(0xa3, enc)));
}

// Unencrypted KRB-CRED carrying one cifs/<host> ticket for the public client
// principal, like the service returns. key is the session key.
static std::string make_krb_cred(const std::string& host, const std::string& key) {
    krb5_context ctx;
    krb5_auth_context ac = NULL;
    krb5_creds cr;
    krb5_data* der_out = NULL;
    krb5_replay_data replay;
    std::string out;

    if (krb5_init_context(&ctx)) return out;
    std::memset(&cr, 0, sizeof(cr));
    std::string ticket = make_ticket_der(host, "TICKET-" + key);
    krb5_timestamp now = static_cast<krb5_timestamp>(time(nullptr));
    if (krb5_build_principal(ctx, &cr.client, std::strlen(kRealm), kRealm, kClient, NULL) == 0 &&
        krb5_build_principal(ctx, &cr.server, std::strlen(kRealm), kRealm, "cifs", host.c_str(), NULL) == 0 &&
        krb5_auth_con_init(ctx, &ac) == 0) {
        cr.keyblock.enctype = ENCTYPE_AES256_CTS_HMAC_SHA1_96;
        cr.keyblock.length = key.size();
        cr.keyblock.contents = (krb5_octet*)key.data();
        cr.times.authtime = cr.times.starttime = now;
        cr.times.endtime = now + 3600;
        cr.times.renew_till = now + 7200;
        cr.ticket_flags = 8388608;
        cr.ticket.data = (char*)ticket.data();
        cr.ticket.length = ticket.size();
        krb5_error_code ret = krb5_mk_1cred(ctx, ac, &cr, &der_out, &replay);
        if (ret) {
            std::fprintf(stderr, "krb5_mk_1cred: %s\n", krb5_get_error_message(ctx, ret));
        } else {
            out.assign(der_out->data, der_out->length);
            krb5_free_data(ctx, der_out);
        }
    }
    if (ac) krb5_auth_con_free(ctx, ac);
    krb5_free_principal(ctx, cr.client);
    krb5_free_principal(ctx, cr.server);
    krb5_free_context(ctx);
    return out;
}

// Writes a valid cache for the public client principal directly with krb5,
// as the caller.
static bool write_cache_direct(const std::string& path, const std::string& host, const std::string& key) {
    krb5_context ctx;
    krb5_ccache cc = NULL;
    krb5_principal cl = NULL;
    krb5_creds cr;
    bool ok = false;
    if (krb5_init_context(&ctx)) return false;
    std::memset(&cr, 0, sizeof(cr));
    if (krb5_build_principal(ctx, &cl, std::strlen(kRealm), kRealm, kClient, NULL) == 0 &&
        krb5_cc_resolve(ctx, ("FILE:" + path).c_str(), &cc) == 0 &&
        krb5_cc_initialize(ctx, cc, cl) == 0 &&
        krb5_build_principal(ctx, &cr.server, std::strlen(kRealm), kRealm, "cifs", host.c_str(), NULL) == 0) {
        cr.client = cl;
        cr.keyblock.enctype = ENCTYPE_AES256_CTS_HMAC_SHA1_96;
        cr.keyblock.length = key.size();
        cr.keyblock.contents = (krb5_octet*)key.data();
        cr.times.authtime = cr.times.starttime = 1765082912;
        cr.times.endtime = cr.times.renew_till = 1765169127;
        cr.ticket.data = (char*)"TICKET";
        cr.ticket.length = 6;
        ok = krb5_cc_store_cred(ctx, cc, &cr) == 0;
        krb5_free_principal(ctx, cr.server);
    }
    if (cc) krb5_cc_close(ctx, cc);
    if (cl) krb5_free_principal(ctx, cl);
    krb5_free_context(ctx);
    return ok;
}

// The library entry points, minus the config file and the HTTP fetch.
static int op_set(uid_t uid, const std::string& host, const std::string& key) {
    std::string krbcred = make_krb_cred(host, key);
    if (krbcred.empty()) return 2;
    return smb_insert_credential("https://" + host, krbcred.data(), krbcred.size(), uid);
}

static int op_clear(uid_t uid, const std::string& host) {
    return smb_clear_credential("https://" + host, uid);
}

struct Snap {
    bool exists = false;
    ino_t ino = 0;
    mode_t mode = 0;
    uid_t uid = 0;
    off_t size = 0;
    std::string data;
};

// lstat plus content (regular files) or target (symlinks).
static Snap snap(const std::string& path) {
    Snap s;
    struct stat st;
    if (lstat(path.c_str(), &st) != 0) return s;
    s.exists = true;
    s.ino = st.st_ino;
    s.mode = st.st_mode;
    s.uid = st.st_uid;
    s.size = st.st_size;
    if (S_ISREG(st.st_mode)) {
        s.data = read_file(path);
    } else if (S_ISLNK(st.st_mode)) {
        char buf[PATH_MAX];
        ssize_t n = readlink(path.c_str(), buf, sizeof(buf));
        if (n > 0) s.data.assign(buf, n);
    }
    return s;
}

static bool same(const Snap& a, const Snap& b) {
    return a.exists == b.exists && a.ino == b.ino && a.mode == b.mode && a.uid == b.uid &&
           a.size == b.size && a.data == b.data;
}

static bool trusted(const Snap& s, uid_t uid) {
    return s.exists && S_ISREG(s.mode) && s.uid == uid && (s.mode & 07777) == 0600;
}

static bool chown_as_root(const std::string& path, uid_t uid) {
    return geteuid() != 0 || lchown(path.c_str(), uid, uid) == 0;
}

// ---- cases for any user ----

// set creates a private cache and a second set appends to it; clear works on
// it and cannot be used on an absent cache.
static void normal_flow(uid_t owner) {
    new_case("normal");
    std::string path = cache_path(owner);
    std::string k1 = key32("NORMAL-ONE"), k2 = key32("NORMAL-TWO");
    std::string out, err;

    CHECK(capture([&] { return as(owner, [&] { return op_clear(owner, kHost); }); }, &out, &err) != 0);
    CHECK(!snap(path).exists);

    CHECK(capture([&] { return as(owner, [&] { return op_set(owner, kHost, k1); }); }, &out, &err) == 0);
    Snap first = snap(path);
    CHECK(trusted(first, owner));
    CHECK(count(first.data, k1) >= 1);

    CHECK(capture([&] { return as(owner, [&] { return op_set(owner, "two.file.core.windows.net", k2); }); },
                  &out, &err) == 0);
    Snap second = snap(path);
    CHECK(trusted(second, owner));
    CHECK(second.ino == first.ino);
    CHECK(count(second.data, k1) >= 1 && count(second.data, k2) >= 1);

    CHECK(capture([&] { return as(owner, [&] { return op_clear(owner, kHost); }); }, &out, &err) == 0);
    CHECK(err.find("refusing") == std::string::npos);
}

// An existing cache in an untrusted state makes set and clear fail and is left
// unchanged.
static void refusal_matrix(uid_t owner, uid_t other_uid) {
    std::vector<std::string> states = {"mode-0644", "mode-0400", "mode-0666", "mode-0700",
                                       "symlink", "directory", "fifo"};
    if (geteuid() == 0 && owner != other_uid) {
        states.push_back("root-owned");
        states.push_back("other-owned");
    }
    for (const std::string& s : states) {
        for (const char* opname : {"set", "clear"}) {
            std::string op(opname);
            std::string dir = new_case("refuse-" + s + "-" + op);
            std::string path = cache_path(owner);
            std::string other = dir + "/other";
            std::string marker = key32("REFUSE-" + s + "-" + op);

            if (s == "directory") {
                CHECK(mkdir(path.c_str(), 0700) == 0 && chown_as_root(path, owner));
            } else if (s == "fifo") {
                CHECK(mkfifo(path.c_str(), 0600) == 0 && chown_as_root(path, owner));
            } else {
                std::string file = s == "symlink" ? other : path;
                CHECK(write_cache_direct(file, kHost, key32("existing")));
                uid_t file_owner = s == "root-owned" ? 0 : s == "other-owned" ? other_uid : owner;
                mode_t mode = s == "mode-0644" ? 0644 : s == "mode-0400" ? 0400 :
                              (s == "mode-0666" || s == "other-owned") ? 0666 :
                              s == "mode-0700" ? 0700 : 0600;
                CHECK(chown_as_root(file, file_owner) && chmod(file.c_str(), mode) == 0);
                if (s == "symlink") {
                    CHECK(symlink(other.c_str(), path.c_str()) == 0 && chown_as_root(path, other_uid));
                }
            }
            Snap before = snap(path), before_other = snap(other);

            std::string out, err;
            int rc = capture([&] {
                return as(owner, [&] {
                    if (op == "set") return op_set(owner, kHost, marker);
                    return op_clear(owner, kHost);
                });
            }, &out, &err);

            Snap after = snap(path), after_other = snap(other);
            bool ok = rc != 0 && same(before, after) && same(before_other, after_other) &&
                      count(after.data + after_other.data, marker) == 0 &&
                      err.find("refusing to use credential cache " + path + ":") != std::string::npos;
            if (!ok) {
                std::fprintf(stderr, "refusal state=%s op=%s rc=%d out=[%s] err=[%s]\n",
                             s.c_str(), op.c_str(), rc, out.c_str(), err.c_str());
            }
            CHECK(ok);
        }
    }
}

// Config-driven cache location: the config names the caller's own UID (0 for
// root) and a private cache such as /var/lib/krb5/krb5cc_0 instead of
// /tmp/krb5cc_<uid>. Runs the config reader and the extern_* list and clear
// entry points; set goes through smb_insert_credential (no HTTP fetch).
static void custom_cache_config(uid_t uid, mode_t dir_mode) {
    char mode_name[16];
    std::snprintf(mode_name, sizeof(mode_name), "%04o", static_cast<unsigned>(dir_mode));
    std::string root = new_case(std::string("custom-cache-") + mode_name);
    std::string dir = root;
    for (const char* part : {"var", "lib", "krb5"}) {
        dir += std::string("/") + part;
        CHECK(mkdir(dir.c_str(), 0755) == 0);
    }
    CHECK(chmod(dir.c_str(), dir_mode) == 0);
    std::string path = dir + "/krb5cc_" + std::to_string(uid);
    static std::string cfg;
    cfg = root + "/config.yaml";
    CHECK(write_file(cfg, "USER_UID: " + std::to_string(uid) + "\nKRB5_CC_NAME: " + path + "\n", 0600));

    const char* saved_config = g_config_path;
    g_config_path = cfg.c_str();
    CHECK(read_config_value("USER_UID") == std::to_string(uid));
    CHECK(read_config_value("KRB5_CC_NAME") == path);

    std::string out, err;
    std::string uri = "https://" + std::string(kHost), host2 = "two.file.core.windows.net";
    std::string k1 = key32("CUSTOM-ONE"), k2 = key32("CUSTOM-TWO"), k3 = key32("CUSTOM-THREE"), k4 = key32("CUSTOM-FOUR");
    auto clear = [&] { return extern_smb_clear_credential(const_cast<char*>(uri.c_str())); };

    // set creates the configured cache (owned by uid, 0600), not the default one, and a second set reuses it.
    CHECK(capture([&] { return as(uid, [&] { return op_set(uid, kHost, k1); }); }, &out, &err) == 0);
    Snap first = snap(path);
    CHECK(trusted(first, uid) && count(first.data, k1) >= 1);
    CHECK(!snap(cache_path(uid)).exists);
    CHECK(err.find("refusing") == std::string::npos);
    CHECK(capture([&] { return as(uid, [&] { return op_set(uid, host2, k2); }); }, &out, &err) == 0);
    Snap second = snap(path);
    CHECK(trusted(second, uid) && second.ino == first.ino);
    CHECK(count(second.data, k1) >= 1 && count(second.data, k2) >= 1);

    // list shows both endpoints; clear removes one and restores the effective UID.
    CHECK(capture([&] { return extern_smb_list_credential(false); }, &out, &err) == 0);
    CHECK(geteuid() == uid);
    CHECK(out.find(kHost) != std::string::npos && out.find(host2) != std::string::npos);
    CHECK(capture([&] { return extern_smb_list_credential(true); }, &out, &err) == 0);
    CHECK(geteuid() == uid);
    CHECK(out.find(kHost) != std::string::npos && out.find(host2) != std::string::npos);
    CHECK(capture(clear, &out, &err) == 0);
    CHECK(geteuid() == uid && err.find("refusing") == std::string::npos);
    CHECK(trusted(snap(path), uid) && !snap(cache_path(uid)).exists);
    CHECK(capture([&] { return extern_smb_list_credential(false); }, &out, &err) == 0);
    CHECK(out.find(kHost) == std::string::npos && out.find(host2) != std::string::npos);

    // An existing 0600 cache is used.
    CHECK(unlink(path.c_str()) == 0);
    CHECK(write_cache_direct(path, kHost, key32("PRE-EXISTING")) && chmod(path.c_str(), 0600) == 0);
    Snap pre = snap(path);
    CHECK(trusted(pre, uid));
    CHECK(capture([&] { return as(uid, [&] { return op_set(uid, kHost, k3); }); }, &out, &err) == 0);
    Snap after = snap(path);
    CHECK(trusted(after, uid) && after.ino == pre.ino && count(after.data, k3) >= 1);

    // A 0644 cache is refused for set and clear and left unchanged; it works again at 0600.
    CHECK(chmod(path.c_str(), 0644) == 0);
    Snap loose = snap(path);
    CHECK(capture([&] { return as(uid, [&] { return op_set(uid, kHost, k4); }); }, &out, &err) != 0);
    CHECK(err.find("refusing to use credential cache " + path + ": type=file owner_uid=" +
                   std::to_string(uid) + " (expected " + std::to_string(uid) + ") mode=0644") != std::string::npos);
    CHECK(capture(clear, &out, &err) != 0 && err.find("refusing") != std::string::npos);
    CHECK(geteuid() == uid);
    CHECK(same(loose, snap(path)) && count(read_file(path), k4) == 0);
    CHECK(chmod(path.c_str(), 0600) == 0);
    CHECK(capture([&] { return as(uid, [&] { return op_set(uid, kHost, k4); }); }, &out, &err) == 0);
    CHECK(trusted(snap(path), uid) && count(read_file(path), k4) >= 1);
    CHECK(capture(clear, &out, &err) == 0);

    g_config_path = saved_config;
}

#ifndef CCACHE_SELFTEST_ROOT
// check_ccache_file accepts only a regular file owned by the UID, mode exactly
// 0600; it passes non-FILE cache types through.
static void helper_matrix() {
    std::string dir = new_case("helper");
    uid_t me = geteuid();
    std::string p = dir + "/krb5cc";
    bool exists = true;
    std::string out, err;
    auto check = [&](const std::string& name, uid_t uid) {
        return capture([&] { return check_ccache_file(name, uid, &exists); }, &out, &err);
    };

    CHECK(check(p, me) == 0 && !exists);
    CHECK(check("FILE:" + p, me) == 0 && !exists);
    CHECK(check("FILE:" + dir + "/missing/krb5cc", me) == 0 && !exists);
    CHECK(write_file(p, "cache", 0600));
    exists = false;
    CHECK(check(p, me) == 0 && exists);
    exists = false;
    CHECK(check("FILE:" + p, me) == 0 && exists);
    CHECK(err.empty());
    CHECK(check(p, me + 1) == -1);
    CHECK(err.find("refusing to use credential cache " + p + ": type=file owner_uid=" + std::to_string(me) +
                   " (expected " + std::to_string(me + 1) + ")") != std::string::npos);
    for (mode_t mode : {0644, 0640, 0604, 0400, 0666, 0700, 04600, 01600}) {
        CHECK(chmod(p.c_str(), mode) == 0);
        CHECK(check(p, me) == -1);
        CHECK(check("FILE:" + p, me) == -1);
    }
    CHECK(chmod(p.c_str(), 0644) == 0);
    CHECK(check(p, me) == -1);
    CHECK(err.find("mode=0644 (expected 0600)") != std::string::npos);
    CHECK(err.find("sudo rm -rf " + p) != std::string::npos);
    CHECK(chmod(p.c_str(), 0600) == 0);

    // A one-letter prefix is a FILE path to krb5, so it is checked, not passed through.
    {
        std::string rel = "a:krb5cc-owner-check-selftest";
        exists = true;
        CHECK(check(rel, me) == 0 && !exists);
        exists = false;
        CHECK(check("KEYRING:persistent:" + std::to_string(me), me) == 0 && exists);
    }

    // lstat errors other than ENOENT refuse.
    CHECK(check(p + "/sub", me) == -1);
    CHECK(err.find("cannot check credential cache") != std::string::npos);

    std::string sym = dir + "/symlink";
    CHECK(symlink(p.c_str(), sym.c_str()) == 0);
    CHECK(check(sym, me) == -1);
    CHECK(err.find("type=symlink") != std::string::npos);

    std::string sub = dir + "/dir";
    CHECK(mkdir(sub.c_str(), 0700) == 0);
    CHECK(check(sub, me) == -1);
    CHECK(err.find("type=directory") != std::string::npos);
    std::string fifo = dir + "/fifo";
    CHECK(mkfifo(fifo.c_str(), 0600) == 0 && chmod(fifo.c_str(), 0600) == 0);
    CHECK(check(fifo, me) == -1);
    CHECK(err.find("type=fifo") != std::string::npos);

    for (const char* name : {"KEYRING:persistent:1000", "KCM:1000", "MEMORY:x"}) {
        exists = false;
        CHECK(check(name, me) == 0 && exists);
    }
}
#else
// ---- cases that need root ----

// Deterministic interleavings, confined to one path and one op_set call.
// Unlike run_as, this root-only case retains saved root for the other-user
// transition at the open boundary; production runs with the owner euid.
static void exclusive_create_boundaries() {
    for (Injection injection : {Injection::collide, Injection::denied,
                                Injection::disappear, Injection::close_error}) {
        const char* name = injection == Injection::collide ? "boundary-eexist" :
                           injection == Injection::denied ? "boundary-eacces" :
                           injection == Injection::disappear ? "boundary-disappear" :
                           "boundary-close";
        new_case(name);
        Boundary b;
        b.path = cache_path(kOwnerUid);
        b.injection = injection;
        std::string marker = key32(name);
        if (injection == Injection::disappear) {
            CHECK(run_as(kOwnerUid, [&] {
                return write_cache_direct(b.path, kHost, key32("old")) ? 0 : 1;
            }) == 0);
            CHECK(trusted(snap(b.path), kOwnerUid));
        }
        std::string out, err;
        int rc = capture([&] {
            effective_uid(kOwnerUid);
            g_boundary = &b;
            int result = op_set(kOwnerUid, kHost, marker);
            g_boundary = nullptr;
            effective_uid(0);
            return result;
        }, &out, &err);
        CHECK(b.opens == 1 && b.checked_before_open && b.create_mode == 0600);
        CHECK(injection == Injection::disappear ? b.present >= 1 : b.absent == 1);
        Snap after = snap(b.path);
        if (injection == Injection::disappear) {
            CHECK(b.removed && b.nofile);
            CHECK(rc == 0 && b.initializes == 1 && b.stores == 1);
            CHECK(b.private_before_init);
            CHECK(trusted(after, kOwnerUid) && count(after.data, marker) >= 1);
        } else {
            CHECK(rc != 0 && b.initializes == 0 && b.stores == 0);
            CHECK(count(after.data, marker) == 0);
            if (g_log_fp) std::fflush(g_log_fp);
            std::string log = read_file(g_scratch + "/selftest.log");
            int error = injection == Injection::collide ? EEXIST :
                        injection == Injection::denied ? EACCES : EIO;
            std::string prefix = injection == Injection::close_error ?
                "Failed to close newly created credential cache " : "Failed to create credential cache ";
            CHECK(log.find(prefix + b.path + ": " + strerror(error)) != std::string::npos);
            if (injection == Injection::collide) {
                CHECK(b.collided && b.open_error == EEXIST && b.created_fd == -1);
                CHECK(after.exists && after.uid == kOtherUid && (after.mode & 07777) == 0666);
                CHECK(after.data == "other-owned-cache");
                char buf[128];
                ssize_t n = pread(b.retained_fd, buf, sizeof(buf), 0);
                std::string retained = n >= 0 ? std::string(buf, n) : "";
                CHECK(retained == "other-owned-cache" && count(retained, marker) == 0);
                struct stat st;
                CHECK(fstat(b.retained_fd, &st) == 0 && st.st_ino == after.ino &&
                      st.st_size == static_cast<off_t>(retained.size()));
                CHECK((fcntl(b.retained_fd, F_GETFL) & O_ACCMODE) == O_RDWR);
                CHECK(b.retained_fd >= 0 && ::close(b.retained_fd) == 0);
                CHECK(b.closes == 0);
            } else if (injection == Injection::denied) {
                CHECK(b.open_error == EACCES && !after.exists && b.closes == 0);
            } else {
                CHECK(b.closes == 1 && b.closed);
                CHECK(trusted(after, kOwnerUid) && after.data.empty());
                errno = 0;
                CHECK(fcntl(b.created_fd, F_GETFD) == -1 && errno == EBADF);
            }
        }
    }
}

// Root in a user namespace (e.g. a rootless build container) may be unable to
// use the synthetic UIDs; the caller skips instead of failing.
static bool synthetic_ids_usable(std::string* why) {
    std::string probe = g_scratch + "/id-probe";
    for (uid_t uid : {kOwnerUid, kOtherUid}) {
        bool chowned = write_file(probe, "", 0600) && chown(probe.c_str(), uid, uid) == 0;
        int saved_errno = errno;
        unlink(probe.c_str());
        if (!chowned) {
            *why = "chown to uid " + std::to_string(uid) + ": " + strerror(saved_errno);
            return false;
        }
        if (run_as(uid, [uid] { return geteuid() == uid && getegid() == uid ? 0 : 1; }) != 0) {
            *why = "cannot switch to uid/gid " + std::to_string(uid);
            return false;
        }
    }
    return true;
}

// A group/world-writable cache owned by another user must be refused and must
// not receive the owner's credentials.
static void other_owned_cache() {
    new_case("other-owned");
    std::string path = cache_path(kOwnerUid);
    std::string marker = key32("OTHER-OWNED-KEY");

    CHECK(run_as(kOtherUid, [&] {
        return write_cache_direct(path, "other.example", key32("other")) &&
               chmod(path.c_str(), 0666) == 0 ? 0 : 1;
    }) == 0);
    Snap existing = snap(path);
    CHECK(existing.exists && existing.uid == kOtherUid && (existing.mode & 07777) == 0666);

    // root runs set for the owner (euid = owner, as extern_* does).
    std::string out, err;
    int rc = capture([&] { return run_as(kOwnerUid, [&] { return op_set(kOwnerUid, kHost, marker); }); },
                     &out, &err);
    CHECK(rc != 0);
    CHECK(err.find("refusing to use credential cache " + path + ": type=file owner_uid=" +
                   std::to_string(kOtherUid)) != std::string::npos);

    // The file is byte-identical and contains no credential bytes.
    CHECK(same(existing, snap(path)));
    CHECK(run_as(kOtherUid, [&] { return count(read_file(path), marker) == 0 ? 0 : 1; }) == 0);
    CHECK(count(read_file(path), marker) == 0);
}

// Another user races set: it creates a file (O_CREAT|O_EXCL) or a symlink to
// its own cache while the owner's cache does not exist yet. Either set wins
// and the cache is the owner's private file, or set fails and no file the
// other user owns holds the key.
static void create_race() {
    int won = 0, lost = 0;
    for (int i = 0; i < 200; i++) {
        std::string dir = new_case("race" + std::to_string(i));
        std::string path = cache_path(kOwnerUid);
        std::string bait = dir + "/bait";
        std::string marker = key32("RACE-" + std::to_string(i));
        bool use_symlink = i % 2;
        if (use_symlink) {
            CHECK(run_as(kOtherUid, [&] {
                return write_cache_direct(bait, kHost, key32("bait")) && chmod(bait.c_str(), 0666) == 0 ? 0 : 1;
            }) == 0);
        }

        std::cout.flush();
        std::fflush(nullptr);
        pid_t pid = fork();
        if (pid == 0) {
            gid_t gid = kOtherUid;
            if (setgroups(1, &gid) != 0 || setgid(gid) != 0 || setuid(kOtherUid) != 0) _exit(100);
            usleep((i * 37) % 3000);
            for (int n = 0; n < 100000; n++) {
                if (use_symlink) {
                    if (symlink(bait.c_str(), path.c_str()) == 0) _exit(0);
                } else {
                    int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0666);
                    if (fd >= 0) {
                        fchmod(fd, 0666);
                        ::close(fd);
                        _exit(0);
                    }
                }
                if (errno == EEXIST) _exit(1);
            }
            _exit(2);
        }

        std::string out, err;
        int rc = capture([&] { return run_as(kOwnerUid, [&] { return op_set(kOwnerUid, kHost, marker); }); },
                         &out, &err);
        int status = 0;
        if (pid > 0) waitpid(pid, &status, 0);

        Snap s = snap(path);
        if (rc == 0) {
            won++;
            CHECK(trusted(s, kOwnerUid) && count(s.data, marker) >= 1);
        } else {
            lost++;
        }
        if (!trusted(s, kOwnerUid)) CHECK(count(s.data, marker) == 0);
        CHECK(count(read_file(bait), marker) == 0);
    }
    std::printf("race: set won %d, other user created first %d\n", won, lost);
}
#endif

static int remove_entry(const char* path, const struct stat*, int, struct FTW*) {
    return remove(path);
}

int main(int argc, char**) {
    std::setvbuf(stdout, nullptr, _IOLBF, 0);
    umask(022);
    if (argc != 1) {
        std::fprintf(stderr, "usage: takes no arguments\n");
        return 2;
    }
#ifdef CCACHE_SELFTEST_ROOT
    const char* opt_in = std::getenv("AZF_SELFTEST_ROOT");
    if (!opt_in || std::strcmp(opt_in, "1") != 0) {
        std::printf("SKIP: root-only credential cache cases need AZF_SELFTEST_ROOT=1\n");
        return 77;
    }
    if (geteuid() != 0) {
        std::printf("SKIP: root-only credential cache cases need root\n");
        return 77;
    }
#endif

    char tmpl[] = "/tmp/azf-ccache-st.XXXXXX";
    if (!mkdtemp(tmpl) || chmod(tmpl, 0755) != 0) {
        std::perror("mkdtemp");
        return 2;
    }
    g_scratch = tmpl;

    // Keep the library's log output out of syslog, in the scratch directory.
    g_use_file_log = true;
    g_log_fp = std::fopen((g_scratch + "/selftest.log").c_str(), "a");
    std::printf("scratch %s, euid %u\n", g_scratch.c_str(), geteuid());

#ifdef CCACHE_SELFTEST_ROOT
    std::string why;
    if (!synthetic_ids_usable(&why)) {
        std::printf("SKIP: synthetic test UIDs unusable here (%s)\n", why.c_str());
        if (g_log_fp) std::fclose(g_log_fp);
        nftw(g_scratch.c_str(), remove_entry, 16, FTW_DEPTH | FTW_PHYS);
        return 77;
    }
    other_owned_cache();
    refusal_matrix(kOwnerUid, kOtherUid);
    normal_flow(kOwnerUid);
    custom_cache_config(0, 0755);
    custom_cache_config(0, 0700);
    exclusive_create_boundaries();
    create_race();
#else
    helper_matrix();
    normal_flow(geteuid());
    refusal_matrix(geteuid(), geteuid());
    custom_cache_config(geteuid(), 0755);
    custom_cache_config(geteuid(), 0700);
#endif
    std::printf("%d checks, %d failures\n", g_checks, g_failures);

    if (g_failures) {
        std::printf("scratch kept for inspection: %s (library log: selftest.log)\n", g_scratch.c_str());
        return 1;
    }
    if (g_log_fp) {
        std::fclose(g_log_fp);
        g_log_fp = nullptr;
    }
    nftw(g_scratch.c_str(), remove_entry, 16, FTW_DEPTH | FTW_PHYS);
    return 0;
}
