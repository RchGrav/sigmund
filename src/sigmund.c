#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define ID_HEX_LEN 6
#define STOP_TIMEOUT_MS 5000
#define POLL_SLEEP_MS 25
#define SIGMUND_VERSION "0.1.0"
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif
#define SIGMUND_PATH_MAX PATH_MAX
#ifndef SIGMUND_BOOT_ID_PATH
#define SIGMUND_BOOT_ID_PATH "/proc/sys/kernel/random/boot_id"
#endif

struct record {
    int version;
    char id[16];
    pid_t pid;
    pid_t pgid;
    pid_t sid;
    int64_t start_unix_ns;
    uid_t uid;
    gid_t gid;
    char log_path[SIGMUND_PATH_MAX];
    char boot_id[128];
    uint64_t proc_starttime_ticks;
    uint64_t exe_dev;
    uint64_t exe_ino;
    char cmdline[SIGMUND_PATH_MAX];
    bool has_log;
    bool has_boot;
};

enum run_state { STATE_RUNNING, STATE_DEAD, STATE_STALE, STATE_UNKNOWN };

static volatile sig_atomic_t g_tail_interrupted = 0;
static int write_all(int fd, const void *buf, size_t n);

static void handle_tail_sigint(int signo) {
    (void)signo;
    g_tail_interrupted = 1;
}

static void die_errno(const char *msg) {
    int e = errno;
    fprintf(stderr, "%s: %s\n", msg, strerror(e));
    exit(1);
}

static int checked_snprintf(char *dst, size_t n, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int r = vsnprintf(dst, n, fmt, ap);
    va_end(ap);
    if (r < 0 || (size_t)r >= n) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return 0;
}

static bool has_suffix(const char *s, const char *suffix) {
    size_t sl = strlen(s), sufl = strlen(suffix);
    return sl >= sufl && strcmp(s + (sl - sufl), suffix) == 0;
}

static bool valid_id(const char *id) {
    size_t len = strlen(id);
    if (len < 6 || len > 10) {
        return false;
    }
    for (size_t i = 0; i < len; i++) {
        if (!isdigit((unsigned char)id[i]) && !(id[i] >= 'a' && id[i] <= 'f')) {
            return false;
        }
    }
    return true;
}

static bool is_hidden_id_artifact(const char *name, const char *suffix) {
    size_t nl = strlen(name);
    size_t sl = strlen(suffix);
    if (nl <= 1 + sl || name[0] != '.') {
        return false;
    }
    if (strcmp(name + (nl - sl), suffix) != 0) {
        return false;
    }
    size_t id_len = nl - 1 - sl;
    if (id_len >= 32) {
        return false;
    }
    char id[32];
    memcpy(id, name + 1, id_len);
    id[id_len] = '\0';
    return valid_id(id);
}

static bool valid_record(const struct record *r) {
    return r->pid > 0 && r->pgid > 1 && r->id[0] != '\0';
}

static int mkdir_p0700(const char *dir) {
    char path[SIGMUND_PATH_MAX];
    if (checked_snprintf(path, sizeof(path), "%s", dir) != 0) {
        return -1;
    }

    size_t len = strlen(path);
    if (len == 0) {
        errno = EINVAL;
        return -1;
    }

    for (size_t i = 1; i <= len; i++) {
        if (path[i] != '/' && path[i] != '\0') {
            continue;
        }
        char saved = path[i];
        path[i] = '\0';
        if (path[0] != '\0') {
            struct stat st;
            bool created = false;
            if (stat(path, &st) != 0) {
                if (mkdir(path, 0700) != 0 && errno != EEXIST) {
                    return -1;
                }
                created = true;
            } else if (!S_ISDIR(st.st_mode)) {
                errno = ENOTDIR;
                return -1;
            }
            if (created && chmod(path, 0700) != 0) {
                return -1;
            }
        }
        path[i] = saved;
    }
    return 0;
}

static int read_file_trim(const char *path, char *buf, size_t n) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        return -1;
    }
    ssize_t r = read(fd, buf, n - 1);
    close(fd);
    if (r < 0) {
        return -1;
    }
    buf[r] = '\0';
    while (r > 0 && (buf[r - 1] == '\n' || buf[r - 1] == '\r' || isspace((unsigned char)buf[r - 1]))) {
        buf[r - 1] = '\0';
        r--;
    }
    return 0;
}

static int get_boot_id(char *buf, size_t n) {
    return read_file_trim(SIGMUND_BOOT_ID_PATH, buf, n);
}

static int rand_bytes(uint8_t *buf, size_t n) {
    size_t off = 0;
    bool fallback = false;
    while (off < n && !fallback) {
        ssize_t r = getrandom(buf + off, n - off, 0);
        if (r > 0) {
            off += (size_t)r;
            continue;
        }
        if (r < 0 && errno == EINTR) {
            continue;
        }
        if (r < 0 && (errno == ENOSYS || errno == EINVAL)) {
            fallback = true;
            break;
        }
        return -1;
    }
    if (!fallback) {
        return 0;
    }

    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        return -1;
    }
    while (off < n) {
        ssize_t x = read(fd, buf + off, n - off);
        if (x > 0) {
            off += (size_t)x;
            continue;
        }
        if (x < 0 && errno == EINTR) {
            continue;
        }
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

static int gen_id(const char *dir, char *out, size_t out_n) {
    uint8_t b[ID_HEX_LEN / 2];
    char reserve[SIGMUND_PATH_MAX];
    for (int tries = 0; tries < 100; tries++) {
        if (rand_bytes(b, sizeof(b)) != 0) {
            return -1;
        }
        for (size_t i = 0; i < sizeof(b); i++) {
            snprintf(out + i * 2, out_n - i * 2, "%02x", b[i]);
        }
        if (checked_snprintf(reserve, sizeof(reserve), "%s/.%s.reserve", dir, out) != 0) {
            return -1;
        }
        int fd = open(reserve, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (fd >= 0) {
            close(fd);
            return 0;
        }
        if (errno != EEXIST) {
            return -1;
        }
    }
    errno = EEXIST;
    return -1;
}

static int ensure_storage(char *dir, size_t n) {
    const char *home = getenv("HOME");
    if (!home || !*home) {
        fprintf(stderr, "sigmund: error: HOME is not set\n");
        errno = EINVAL;
        return -1;
    }
    if (checked_snprintf(dir, n, "%s/.local/state/sigmund", home) != 0) {
        return -1;
    }
    if (mkdir_p0700(dir) != 0) {
        return -1;
    }
    if (chmod(dir, 0700) != 0) {
        return -1;
    }
    return 0;
}

static int maybe_cleanup_for_boot(const char *dir) {
    char current_boot[128];
    if (get_boot_id(current_boot, sizeof(current_boot)) != 0) {
        return 0;
    }
    char marker[SIGMUND_PATH_MAX];
    if (checked_snprintf(marker, sizeof(marker), "%s/.boot_id", dir) != 0) {
        return -1;
    }
    char prev_boot[128] = {0};
    bool had_marker = read_file_trim(marker, prev_boot, sizeof(prev_boot)) == 0 && prev_boot[0] != '\0';
    bool should_write_marker = !had_marker;
    if (had_marker && strcmp(prev_boot, current_boot) != 0) {
        should_write_marker = true;
        DIR *d = opendir(dir);
        if (!d) {
            return -1;
        }
        const struct dirent *e;
        while ((e = readdir(d))) {
            const char *name = e->d_name;
            if (!strcmp(name, ".") || !strcmp(name, "..") || !strcmp(name, ".boot_id")) {
                continue;
            }
            bool rm = has_suffix(name, ".json") || has_suffix(name, ".log") ||
                      is_hidden_id_artifact(name, ".reserve") ||
                      is_hidden_id_artifact(name, ".tmp");
            if (rm) {
                char p[SIGMUND_PATH_MAX];
                if (checked_snprintf(p, sizeof(p), "%s/%s", dir, name) == 0) {
                    unlink(p);
                }
            }
        }
        closedir(d);
    }
    if (!should_write_marker) {
        return 0;
    }

    char marker_tmp[SIGMUND_PATH_MAX];
    if (checked_snprintf(marker_tmp, sizeof(marker_tmp), "%s/.boot_id.tmp", dir) != 0) {
        return -1;
    }
    int fd = open(marker_tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        return -1;
    }
    if (write_all(fd, current_boot, strlen(current_boot)) != 0) {
        close(fd);
        return -1;
    }
    if (fchmod(fd, 0600) != 0) {
        close(fd);
        return -1;
    }
    if (fsync(fd) != 0) {
        close(fd);
        return -1;
    }
    close(fd);
    if (rename(marker_tmp, marker) != 0) {
        int re = errno;
        unlink(marker_tmp);
        if (re == ENOENT || re == EEXIST) {
            char chk[128] = {0};
            if (read_file_trim(marker, chk, sizeof(chk)) == 0 && strcmp(chk, current_boot) == 0) {
                return 0;
            }
        }
        errno = re;
        return -1;
    }
    return 0;
}

static int write_all(int fd, const void *buf, size_t n) {
    const char *p = buf;
    while (n > 0) {
        ssize_t w = write(fd, p, n);
        if (w < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        p += w;
        n -= (size_t)w;
    }
    return 0;
}

static void json_escape(FILE *f, const char *s) {
    for (; *s; s++) {
        if (*s == '"' || *s == '\\') {
            fprintf(f, "\\%c", *s);
        } else if (*s == '\n') {
            fputs("\\n", f);
        } else if (*s == '\r') {
            fputs("\\r", f);
        } else if (*s == '\t') {
            fputs("\\t", f);
        } else if (*s == '\b') {
            fputs("\\b", f);
        } else if (*s == '\f') {
            fputs("\\f", f);
        } else if ((unsigned char)*s < 32) {
            fprintf(f, "\\u%04x", (unsigned char)*s);
        } else {
            fputc(*s, f);
        }
    }
}

static int write_json_argv(FILE *f, int argc, char **argv) {
    fputs("[", f);
    for (int i = 0; i < argc; i++) {
        if (i > 0) {
            fputs(", ", f);
        }
        fputc('"', f);
        json_escape(f, argv[i]);
        fputc('"', f);
    }
    fputs("]", f);
    return 0;
}

static int write_record_atomic(const char *dir, const struct record *r, int argc, char **argv, char *out_json_path, size_t out_n) {
    char tmp[SIGMUND_PATH_MAX], fin[SIGMUND_PATH_MAX], reserve[SIGMUND_PATH_MAX];
    int rc = -1;
    int fd = -1;
    FILE *f = NULL;
    if (checked_snprintf(fin, sizeof(fin), "%s/%s.json", dir, r->id) != 0) {
        return -1;
    }
    if (checked_snprintf(tmp, sizeof(tmp), "%s/.%s.tmp", dir, r->id) != 0) {
        return -1;
    }
    if (checked_snprintf(reserve, sizeof(reserve), "%s/.%s.reserve", dir, r->id) != 0) {
        return -1;
    }

    fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
        return -1;
    }
    f = fdopen(fd, "w");
    if (!f) {
        close(fd);
        fd = -1;
        goto out;
    }

    fprintf(f, "{\n");
    fprintf(f, "  \"version\": %d,\n", r->version);
    fprintf(f, "  \"id\": \"");
    json_escape(f, r->id);
    fprintf(f, "\",\n");
    fprintf(f, "  \"pid\": %ld,\n", (long)r->pid);
    fprintf(f, "  \"pgid\": %ld,\n", (long)r->pgid);
    fprintf(f, "  \"sid\": %ld,\n", (long)r->sid);
    fprintf(f, "  \"start_unix_ns\": %" PRId64 ",\n", r->start_unix_ns);
    fprintf(f, "  \"argv\": ");
    write_json_argv(f, argc, argv);
    fprintf(f, ",\n");
    fprintf(f, "  \"cmdline_display\": \"");
    json_escape(f, r->cmdline);
    fprintf(f, "\",\n");
    fprintf(f, "  \"uid\": %u,\n", r->uid);
    fprintf(f, "  \"gid\": %u,\n", r->gid);
    if (r->has_log) {
        fprintf(f, "  \"log_path\": \"");
        json_escape(f, r->log_path);
        fprintf(f, "\",\n");
    }
    if (r->has_boot) {
        fprintf(f, "  \"boot_id\": \"");
        json_escape(f, r->boot_id);
        fprintf(f, "\",\n");
    }
    fprintf(f, "  \"proc_starttime_ticks\": %" PRIu64 ",\n", r->proc_starttime_ticks);
    fprintf(f, "  \"exe_dev\": %" PRIu64 ",\n", r->exe_dev);
    fprintf(f, "  \"exe_ino\": %" PRIu64 "\n", r->exe_ino);
    fprintf(f, "}\n");

    fflush(f);
    if (fsync(fd) != 0) {
        goto out;
    }
    if (fclose(f) != 0) {
        f = NULL;
        goto out;
    }
    f = NULL;
    fd = -1;
    if (rename(tmp, fin) != 0) {
        goto out;
    }
    unlink(reserve);
    int dfd = open(dir, O_RDONLY | O_DIRECTORY);
    if (dfd >= 0) {
        if (fsync(dfd) != 0) {
            fprintf(stderr, "sigmund: warning: failed to fsync storage dir: %s\n", strerror(errno));
        }
        close(dfd);
    }
    if (out_json_path && checked_snprintf(out_json_path, out_n, "%s", fin) != 0) {
        goto out;
    }
    rc = 0;

out:
    if (f) {
        fclose(f);
    } else if (fd >= 0) {
        close(fd);
    }
    if (rc != 0) {
        unlink(tmp);
    }
    return rc;
}

static int append_cmd_escaped(char *dst, size_t n, size_t *off, const char *arg) {
    const char *sq = "'\\''";
    if (*off + 1 >= n) {
        return -1;
    }
    dst[(*off)++] = '\'';
    for (; *arg; arg++) {
        if (*arg == '\'') {
            for (size_t j = 0; sq[j]; j++) {
                if (*off + 1 >= n) {
                    return -1;
                }
                dst[(*off)++] = sq[j];
            }
        } else {
            if (*off + 1 >= n) {
                return -1;
            }
            dst[(*off)++] = *arg;
        }
    }
    if (*off + 1 >= n) {
        return -1;
    }
    dst[(*off)++] = '\'';
    dst[*off] = '\0';
    return 0;
}

static int count_session_escapees(pid_t sid, pid_t expected_pgid) {
    DIR *d = opendir("/proc");
    if (!d) {
        return -1;
    }
    int count = 0;
    const struct dirent *e;
    while ((e = readdir(d))) {
        if (!isdigit((unsigned char)e->d_name[0])) {
            continue;
        }
        char *pid_end = NULL;
        errno = 0;
        long pid_long = strtol(e->d_name, &pid_end, 10);
        if (pid_end == e->d_name || *pid_end != '\0' || errno != 0) {
            continue;
        }
        pid_t pid = (pid_t)pid_long;
        char path[128], buf[4096];
        if (checked_snprintf(path, sizeof(path), "/proc/%ld/stat", (long)pid) != 0) {
            continue;
        }
        int fd = open(path, O_RDONLY);
        if (fd < 0) {
            continue;
        }
        ssize_t nr = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (nr <= 0) {
            continue;
        }
        buf[nr] = '\0';
        char *rp = strrchr(buf, ')');
        if (!rp) {
            continue;
        }
        char *p = rp + 2;
        char *save = NULL;
        int idx = 0;
        pid_t pgid = 0;
        pid_t proc_sid = 0;
        for (char *tok = strtok_r(p, " ", &save); tok; tok = strtok_r(NULL, " ", &save), idx++) {
            if (idx == 2) {
                char *end = NULL;
                errno = 0;
                long pgid_long = strtol(tok, &end, 10);
                if (end == tok || errno != 0) {
                    continue;
                }
                pgid = (pid_t)pgid_long;
            }
            if (idx == 3) {
                char *end = NULL;
                errno = 0;
                long sid_long = strtol(tok, &end, 10);
                if (end == tok || errno != 0) {
                    continue;
                }
                proc_sid = (pid_t)sid_long;
                break;
            }
        }
        if (proc_sid == sid && pgid != expected_pgid) {
            count++;
        }
    }
    closedir(d);
    return count;
}

static void report_session_escapees(const struct record *r) {
    int escaped = count_session_escapees(r->sid, r->pgid);
    if (escaped > 0) {
        fprintf(stderr,
                "sigmund: warning: %d process(es) escaped process-group %ld but remain in session %ld\n",
                escaped, (long)r->pgid, (long)r->sid);
    }
}

static int read_proc_stat_tokens(pid_t pid, char *state_out, uint64_t *starttime_out) {
    char path[128], buf[4096];
    if (checked_snprintf(path, sizeof(path), "/proc/%ld/stat", (long)pid) != 0) {
        return -1;
    }
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        return -1;
    }
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) {
        return -1;
    }
    buf[n] = '\0';
    char *rp = strrchr(buf, ')');
    if (!rp) {
        return -1;
    }
    char *p = rp + 2;
    int idx = 0;
    char *save = NULL;
    bool got_state = false;
    for (char *tok = strtok_r(p, " ", &save); tok; tok = strtok_r(NULL, " ", &save), idx++) {
        if (idx == 0 && state_out) {
            *state_out = tok[0];
            got_state = true;
        }
        /* /proc/<pid>/stat starttime is field 22 (1-indexed overall),
         * which is index 19 after the trailing ')' where idx 0 starts at state. */
        if (idx == 19 && starttime_out) {
            char *end = NULL;
            errno = 0;
            unsigned long long parsed = strtoull(tok, &end, 10);
            if (end == tok || errno != 0) {
                return -1;
            }
            *starttime_out = parsed;
            return 0;
        }
    }
    return (state_out && got_state && !starttime_out) ? 0 : -1;
}

static int read_proc_exe(pid_t pid, uint64_t *dev, uint64_t *ino) {
    char path[128];
    struct stat st;
    if (checked_snprintf(path, sizeof(path), "/proc/%ld/exe", (long)pid) != 0) {
        return -1;
    }
    if (stat(path, &st) != 0) {
        return -1;
    }
    *dev = (uint64_t)st.st_dev;
    *ino = (uint64_t)st.st_ino;
    return 0;
}

static bool leader_present(pid_t pid) {
    char path[128];
    struct stat st;
    if (checked_snprintf(path, sizeof(path), "/proc/%ld", (long)pid) != 0) {
        return false;
    }
    if (stat(path, &st) == 0) {
        char stc = 0;
        if (read_proc_stat_tokens(pid, &stc, NULL) == 0 && stc == 'Z') {
            return false;
        }
        return true;
    }
    if (kill(pid, 0) == 0 || errno == EPERM) {
        return true;
    }
    return false;
}

static int group_exists(pid_t pgid) {
    if (kill(-pgid, 0) == 0 || errno == EPERM) {
        return 1;
    }
    if (errno == ESRCH) {
        return 0;
    }
    return -1;
}

static const char *skip_ws(const char *p) {
    while (*p && isspace((unsigned char)*p)) p++;
    return p;
}

static int skip_json_string(const char **pp) {
    const char *p = *pp;
    if (*p != '"') return -1;
    p++;
    while (*p) {
        if (*p == '"') {
            *pp = p + 1;
            return 0;
        }
        if (*p == '\\') {
            p++;
            if (!*p) return -1;
            if (*p == 'u') {
                for (int i = 0; i < 4; i++) {
                    p++;
                    if (!isxdigit((unsigned char)*p)) return -1;
                }
            }
        }
        p++;
    }
    return -1;
}

/* BMP-only; surrogate pairs are rejected. */
static int parse_json_string(const char *p, char *out, size_t n, const char **endp) {
    if (*p != '"') return -1;
    p++;
    size_t i = 0;
    while (*p) {
        if (*p == '"') {
            if (i >= n) return -1;
            out[i] = '\0';
            if (endp) *endp = p + 1;
            return 0;
        }
        if (*p == '\\') {
            p++;
            if (!*p) return -1;
            char c = *p;
            switch (*p) {
            case 'n': c = '\n'; break;
            case 't': c = '\t'; break;
            case 'r': c = '\r'; break;
            case 'b': c = '\b'; break;
            case 'f': c = '\f'; break;
            case '\\': case '"': case '/': break;
            case 'u': {
                unsigned v = 0;
                for (int j = 0; j < 4; j++) {
                    p++;
                    if (!isxdigit((unsigned char)*p)) return -1;
                    v = (v << 4) + (unsigned)(isdigit((unsigned char)*p) ? *p - '0' : (tolower((unsigned char)*p) - 'a' + 10));
                }
                if (v == 0) return -1;
                if (v >= 0xD800 && v <= 0xDFFF) return -1;
                if (v <= 0x7F) {
                    c = (char)v;
                    if (i + 1 >= n) return -1;
                    out[i++] = c;
                } else if (v <= 0x7FF) {
                    if (i + 2 >= n) return -1;
                    out[i++] = (char)(0xC0 | (v >> 6));
                    out[i++] = (char)(0x80 | (v & 0x3F));
                } else {
                    if (i + 3 >= n) return -1;
                    out[i++] = (char)(0xE0 | (v >> 12));
                    out[i++] = (char)(0x80 | ((v >> 6) & 0x3F));
                    out[i++] = (char)(0x80 | (v & 0x3F));
                }
                p++;
                continue;
            }
            default: return -1;
            }
            if (i + 1 >= n) return -1;
            out[i++] = c;
            p++;
            continue;
        }
        if (i + 1 >= n) return -1;
        out[i++] = *p++;
    }
    return -1;
}

static int skip_json_value(const char **pp);

static int match_json_string(const char *p, const char *lit, const char **endp, bool *matched) {
    if (*p != '"') return -1;
    p++;
    size_t li = 0;
    bool ok = true;
    while (*p) {
        if (*p == '"') {
            if (lit[li] != '\0') {
                ok = false;
            }
            if (endp) *endp = p + 1;
            if (matched) *matched = ok;
            return 0;
        }
        unsigned cp = 0;
        if (*p == '\\') {
            p++;
            if (!*p) return -1;
            switch (*p) {
            case 'n': cp = '\n'; p++; break;
            case 't': cp = '\t'; p++; break;
            case 'r': cp = '\r'; p++; break;
            case 'b': cp = '\b'; p++; break;
            case 'f': cp = '\f'; p++; break;
            case '\\': cp = '\\'; p++; break;
            case '"': cp = '"'; p++; break;
            case '/': cp = '/'; p++; break;
            case 'u': {
                unsigned v = 0;
                for (int j = 0; j < 4; j++) {
                    p++;
                    if (!isxdigit((unsigned char)*p)) return -1;
                    v = (v << 4) + (unsigned)(isdigit((unsigned char)*p) ? *p - '0' : (tolower((unsigned char)*p) - 'a' + 10));
                }
                if (v == 0 || (v >= 0xD800 && v <= 0xDFFF)) return -1;
                cp = v;
                p++;
                break;
            }
            default:
                return -1;
            }
        } else {
            cp = (unsigned char)*p;
            p++;
        }

        if (cp <= 0x7F) {
            if (lit[li] == '\0' || (unsigned char)lit[li] != cp) {
                ok = false;
            }
            if (lit[li] != '\0') {
                li++;
            }
        } else {
            ok = false;
        }
    }
    return -1;
}

static int skip_json_value(const char **pp) {
    const char *p = skip_ws(*pp);
    if (*p == '"') {
        if (skip_json_string(&p) != 0) return -1;
        *pp = p;
        return 0;
    }
    if (*p == '{' || *p == '[') {
        char open = *p, close = (open == '{') ? '}' : ']';
        p++;
        while (*p) {
            p = skip_ws(p);
            if (*p == close) { *pp = p + 1; return 0; }
            if (open == '{') {
                if (skip_json_string(&p) != 0) return -1;
                p = skip_ws(p);
                if (*p != ':') return -1;
                p++;
            }
            if (skip_json_value(&p) != 0) return -1;
            p = skip_ws(p);
            if (*p == ',') p++;
        }
        return -1;
    }
    while (*p && !isspace((unsigned char)*p) && *p != ',' && *p != '}' && *p != ']') p++;
    *pp = p;
    return 0;
}

static int json_find_key(const char *j, const char *k, const char **v) {
    const char *p = skip_ws(j);
    if (*p != '{') return -1;
    p++;
    while (*p) {
        p = skip_ws(p);
        if (*p == '}') return -1;
        bool key_match = false;
        if (match_json_string(p, k, &p, &key_match) != 0) return -1;
        p = skip_ws(p);
        if (*p != ':') return -1;
        p = skip_ws(p + 1);
        if (key_match) {
            *v = p;
            return 0;
        }
        if (skip_json_value(&p) != 0) return -1;
        p = skip_ws(p);
        if (*p == ',') p++;
    }
    return -1;
}

static int json_get_i64(const char *j, const char *k, int64_t *out) {
    const char *v;
    if (json_find_key(j, k, &v) != 0) {
        return -1;
    }
    if (*v == '+') return -1;
    char *end = NULL;
    errno = 0;
    long long x = strtoll(v, &end, 10);
    if (end == v || errno != 0) return -1;
    end = (char *)skip_ws(end);
    if (*end && *end != ',' && *end != '}' && *end != ']') return -1;
    *out = x;
    return 0;
}

static int json_get_u64(const char *j, const char *k, uint64_t *out) {
    const char *v;
    if (json_find_key(j, k, &v) != 0) {
        return -1;
    }
    if (*v == '+' || *v == '-') return -1;
    char *end = NULL;
    errno = 0;
    unsigned long long x = strtoull(v, &end, 10);
    if (end == v || errno != 0) return -1;
    end = (char *)skip_ws(end);
    if (*end && *end != ',' && *end != '}' && *end != ']') return -1;
    *out = x;
    return 0;
}

static int json_get_str(const char *j, const char *k, char *out, size_t n) {
    const char *v;
    if (json_find_key(j, k, &v) != 0) return -1;
    return parse_json_string(skip_ws(v), out, n, NULL);
}

static int json_get_argv_display(const char *j, char *out, size_t n) {
    const char *v;
    if (json_find_key(j, "argv", &v) != 0 || *v != '[') {
        return -1;
    }
    v = skip_ws(v + 1);
    size_t off = 0;
    bool first = true;
    while (*v && *v != ']') {
        char arg[SIGMUND_PATH_MAX];
        if (parse_json_string(v, arg, sizeof(arg), &v) != 0) {
            return -1;
        }
        if (!first) {
            if (off + 1 >= n) return -1;
            out[off++] = ' ';
            out[off] = '\0';
        }
        if (append_cmd_escaped(out, n, &off, arg) != 0) {
            return -1;
        }
        first = false;
        v = skip_ws(v);
        if (*v == ',') {
            v = skip_ws(v + 1);
        } else if (*v != ']') {
            return -1;
        }
    }
    if (*v != ']') return -1;
    return 0;
}

static int load_record(const char *path, struct record *r) {
    memset(r, 0, sizeof(*r));
    FILE *f = fopen(path, "r");
    if (!f) {
        return -1;
    }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *j = malloc((size_t)sz + 1);
    if (!j) {
        fclose(f);
        return -1;
    }
    if (fread(j, 1, (size_t)sz, f) != (size_t)sz) {
        free(j);
        fclose(f);
        return -1;
    }
    j[sz] = '\0';
    fclose(f);

    int64_t tmp = 0;
    if (json_get_i64(j, "version", &tmp) != 0) {
        free(j);
        return -1;
    }
    r->version = (int)tmp;
    if (json_get_str(j, "id", r->id, sizeof(r->id)) != 0) {
        free(j);
        return -1;
    }
    if (json_get_i64(j, "pid", &tmp) != 0) {
        free(j);
        return -1;
    }
    r->pid = (pid_t)tmp;
    if (json_get_i64(j, "pgid", &tmp) != 0) {
        free(j);
        return -1;
    }
    r->pgid = (pid_t)tmp;
    if (json_get_i64(j, "sid", &tmp) != 0) {
        free(j);
        return -1;
    }
    r->sid = (pid_t)tmp;
    if (json_get_i64(j, "start_unix_ns", &r->start_unix_ns) != 0) {
        free(j);
        return -1;
    }
    if (json_get_i64(j, "uid", &tmp) != 0) {
        free(j);
        return -1;
    }
    r->uid = (uid_t)tmp;
    if (json_get_i64(j, "gid", &tmp) != 0) {
        free(j);
        return -1;
    }
    r->gid = (gid_t)tmp;
    if (json_get_str(j, "log_path", r->log_path, sizeof(r->log_path)) == 0) {
        r->has_log = true;
    }
    if (json_get_str(j, "boot_id", r->boot_id, sizeof(r->boot_id)) == 0) {
        r->has_boot = true;
    }
    if (json_get_u64(j, "proc_starttime_ticks", &r->proc_starttime_ticks) != 0 ||
        json_get_u64(j, "exe_dev", &r->exe_dev) != 0 ||
        json_get_u64(j, "exe_ino", &r->exe_ino) != 0) {
        free(j);
        return -1;
    }
    if (json_get_str(j, "cmdline_display", r->cmdline, sizeof(r->cmdline)) != 0) {
        if (json_get_argv_display(j, r->cmdline, sizeof(r->cmdline)) != 0) {
            snprintf(r->cmdline, sizeof(r->cmdline), "?");
        }
    }
    free(j);
    return 0;
}

static enum run_state eval_state(const struct record *r, const char *current_boot) {
    if (r->pgid <= 1) {
        return STATE_UNKNOWN;
    }
    if (r->has_boot && current_boot && strcmp(r->boot_id, current_boot) != 0) {
        return STATE_STALE;
    }
    char state = 0;
    uint64_t now_starttime = 0;
    bool has_stat = read_proc_stat_tokens(r->pid, &state, &now_starttime) == 0;
    bool present = has_stat || leader_present(r->pid);
    if (has_stat && state == 'Z') {
        return STATE_DEAD;
    }
    if (present) {
        if (r->proc_starttime_ticks && has_stat) {
            if (now_starttime != r->proc_starttime_ticks) {
                return STATE_STALE;
            }
        }
        if (r->exe_dev && r->exe_ino) {
            uint64_t d, i;
            if (read_proc_exe(r->pid, &d, &i) == 0 && (d != r->exe_dev || i != r->exe_ino)) {
                return STATE_STALE;
            }
        }
        return STATE_RUNNING;
    }
    int g = group_exists(r->pgid);
    if (g == 1) {
        return STATE_RUNNING;
    }
    if (g == 0) {
        return STATE_DEAD;
    }
    return STATE_UNKNOWN;
}

static int tail_log_until_exit(const struct record *r, bool from_end) {
    int fd = open(r->log_path, O_RDONLY);
    if (fd < 0) {
        die_errno("sigmund: failed to open log for tail");
    }

    char boot[128] = {0};
    if (r->has_boot) {
        get_boot_id(boot, sizeof(boot));
    }
    if (from_end) {
        lseek(fd, 0, SEEK_END);
    }

    struct sigaction sa = {0}, old_sa = {0};
    sa.sa_handler = handle_tail_sigint;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, &old_sa);
    g_tail_interrupted = 0;

    char buf[4096];
    int sleep_polls = 0;
    while (!g_tail_interrupted) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n > 0) {
            if (write_all(STDOUT_FILENO, buf, (size_t)n) != 0) {
                close(fd);
                sigaction(SIGINT, &old_sa, NULL);
                die_errno("sigmund: failed writing tailed output");
            }
            continue;
        }
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            close(fd);
            sigaction(SIGINT, &old_sa, NULL);
            die_errno("sigmund: failed while tailing log");
        }
        struct timespec sl = {.tv_sec = 0, .tv_nsec = 100 * 1000000L};
        nanosleep(&sl, NULL);
        sleep_polls++;
        if (sleep_polls % 10 == 0) {
            enum run_state st = eval_state(r, r->has_boot ? boot : NULL);
            if (st != STATE_RUNNING) {
                break;
            }
        }
    }

    close(fd);
    sigaction(SIGINT, &old_sa, NULL);
    return 0;
}

static int perform_start(const char *dir, bool tail, int argc, char **argv) {

    char id[16], log_path[SIGMUND_PATH_MAX], reserve_path[SIGMUND_PATH_MAX], boot_id[128] = {0};
    bool has_boot = get_boot_id(boot_id, sizeof(boot_id)) == 0;
    if (gen_id(dir, id, sizeof(id)) != 0) {
        die_errno("sigmund: failed to generate id");
    }
    if (checked_snprintf(log_path, sizeof(log_path), "%s/%s.log", dir, id) != 0) {
        die_errno("sigmund: log path too long");
    }
    if (checked_snprintf(reserve_path, sizeof(reserve_path), "%s/.%s.reserve", dir, id) != 0) {
        die_errno("sigmund: reserve path too long");
    }

    int pipefd[2];
#ifdef O_CLOEXEC
    if (pipe2(pipefd, O_CLOEXEC) != 0)
#endif
    {
        if (pipe(pipefd) != 0) {
            die_errno("sigmund: pipe failed");
        }
        fcntl(pipefd[0], F_SETFD, FD_CLOEXEC);
        fcntl(pipefd[1], F_SETFD, FD_CLOEXEC);
    }
    pid_t pid = fork();
    if (pid < 0) {
        die_errno("sigmund: fork failed");
    }
    if (pid == 0) {
        close(pipefd[0]);
        if (setsid() < 0) {
            int e = errno;
            write_all(pipefd[1], &e, sizeof(e));
            _exit(127);
        }
        int nullfd = open("/dev/null", O_RDONLY);
        if (nullfd < 0 || dup2(nullfd, STDIN_FILENO) < 0) {
            int e = errno;
            write_all(pipefd[1], &e, sizeof(e));
            _exit(127);
        }
        if (nullfd > 2) {
            close(nullfd);
        }

        int lfd = open(log_path, O_WRONLY | O_CREAT | O_APPEND, 0600);
        if (lfd < 0 || dup2(lfd, STDOUT_FILENO) < 0 || dup2(lfd, STDERR_FILENO) < 0) {
            int e = errno;
            write_all(pipefd[1], &e, sizeof(e));
            _exit(127);
        }
        if (lfd > 2) {
            close(lfd);
        }
        execvp(argv[0], argv);
        int e = errno;
        write_all(pipefd[1], &e, sizeof(e));
        _exit(127);
    }

    close(pipefd[1]);
    int child_errno = 0;
    ssize_t n = read(pipefd[0], &child_errno, sizeof(child_errno));
    close(pipefd[0]);
    if (n > 0) {
        int st;
        waitpid(pid, &st, 0);
        fprintf(stderr, "sigmund: exec failed: %s\n", strerror(child_errno));
        unlink(reserve_path);
        return 1;
    }

    struct record r = {0};
    r.version = 1;
    if (checked_snprintf(r.id, sizeof(r.id), "%s", id) != 0) {
        die_errno("sigmund: id too long");
    }
    r.pid = pid;
    r.pgid = pid;
    r.sid = pid;
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    r.start_unix_ns = (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
    r.uid = getuid();
    r.gid = getgid();
    r.has_log = true;
    if (checked_snprintf(r.log_path, sizeof(r.log_path), "%s", log_path) != 0) {
        die_errno("sigmund: log path too long");
    }
    r.has_boot = has_boot;
    if (r.has_boot) {
        snprintf(r.boot_id, sizeof(r.boot_id), "%s", boot_id);
    }
    read_proc_stat_tokens(pid, NULL, &r.proc_starttime_ticks);
    read_proc_exe(pid, &r.exe_dev, &r.exe_ino);
    size_t off = 0;
    r.cmdline[0] = '\0';
    for (int i = 0; i < argc; i++) {
        if (i > 0) {
            if (off + 1 >= sizeof(r.cmdline)) {
                break;
            }
            r.cmdline[off++] = ' ';
            r.cmdline[off] = '\0';
        }
        if (append_cmd_escaped(r.cmdline, sizeof(r.cmdline), &off, argv[i]) != 0) {
            break;
        }
    }
    if (write_record_atomic(dir, &r, argc, argv, NULL, 0) != 0) {
        unlink(reserve_path);
        die_errno("sigmund: failed to write record");
    }

    printf("sigmund: id=%s pid=%ld pgid=%ld sid=%ld\n", r.id, (long)r.pid, (long)r.pgid, (long)r.sid);
    printf("sigmund: log: %s\n", r.log_path);
    printf("sigmund: stop: sigmund stop %s\n", r.id);
    fflush(stdout);

    if (tail) {
        return tail_log_until_exit(&r, false);
    }
    return 0;
}

static int load_record_by_id(const char *dir, const char *id, struct record *r, char *path, size_t n) {
    if (!valid_id(id)) {
        return -1;
    }
    if (checked_snprintf(path, n, "%s/%s.json", dir, id) != 0) {
        return -1;
    }
    if (load_record(path, r) != 0) {
        return -1;
    }
    return 0;
}

static int do_signal_action(const char *dir, const char *id, int sig, bool graceful) {
    struct record r;
    char path[SIGMUND_PATH_MAX], boot[128] = {0};
    if (load_record_by_id(dir, id, &r, path, sizeof(path)) != 0) {
        return 5;
    }
    if (r.pgid <= 1) {
        fprintf(stderr, "sigmund: error: invalid pgid %ld in record file\n", (long)r.pgid);
        return 5;
    }
    if (r.has_boot && get_boot_id(boot, sizeof(boot)) == 0 && strcmp(r.boot_id, boot) != 0) {
        return 2;
    }

    enum run_state st = eval_state(&r, r.has_boot ? boot : NULL);
    if (st == STATE_STALE) {
        return 2;
    }
    if (st == STATE_DEAD) {
        return 0;
    }

    if (kill(-r.pgid, sig) != 0) {
        if (errno == EPERM) {
            return 3;
        }
        if (errno == ESRCH) {
            return 0;
        }
        return 4;
    }

    if (graceful) {
        int waited = 0;
        while (waited < STOP_TIMEOUT_MS) {
            int g = group_exists(r.pgid);
            char state = 0;
            if (g == 0 || (read_proc_stat_tokens(r.pgid, &state, NULL) == 0 && state == 'Z')) {
                report_session_escapees(&r);
                return 0;
            }
            struct timespec sl = {.tv_sec = 0, .tv_nsec = POLL_SLEEP_MS * 1000000L};
            nanosleep(&sl, NULL);
            waited += POLL_SLEEP_MS;
        }
        if (kill(-r.pgid, SIGKILL) != 0 && errno != ESRCH) {
            if (errno == EPERM) {
                return 3;
            }
            return 4;
        }
        int g = group_exists(r.pgid);
        if (g == 0) {
            report_session_escapees(&r);
            return 0;
        }
        return 4;
    }
    report_session_escapees(&r);
    return 0;
}

static const char *state_str(enum run_state s) {
    switch (s) {
    case STATE_RUNNING:
        return "running";
    case STATE_DEAD:
        return "dead";
    case STATE_STALE:
        return "stale";
    default:
        return "unknown";
    }
}

static void format_age(int64_t start_ns, char *out, size_t n) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    int64_t now = (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
    int64_t sec = (now - start_ns) / 1000000000LL;
    if (sec < 0) {
        sec = 0;
    }
    int64_t days = sec / 86400;
    int64_t hours = (sec % 86400) / 3600;
    int64_t mins = (sec % 3600) / 60;
    if (days > 0) {
        snprintf(out, n, "%" PRId64 "d%" PRId64 "h", days, hours);
    } else if (hours > 0) {
        snprintf(out, n, "%" PRId64 "h%" PRId64 "m", hours, mins);
    } else if (mins > 0) {
        snprintf(out, n, "%" PRId64 "m", mins);
    } else {
        snprintf(out, n, "%" PRId64 "s", sec);
    }
}

static int cmd_list(const char *dir) {
    DIR *d = opendir(dir);
    if (!d) {
        return 0;
    }
    char boot[128] = {0};
    get_boot_id(boot, sizeof(boot));
    printf("%-7s %-8s %-8s %-6s %-8s %s\n", "ID", "PID", "PGID", "AGE", "STATE", "CMD");
    const struct dirent *e;
    while ((e = readdir(d))) {
        if (!has_suffix(e->d_name, ".json")) {
            continue;
        }
        char path[SIGMUND_PATH_MAX];
        if (checked_snprintf(path, sizeof(path), "%s/%s", dir, e->d_name) != 0) {
            continue;
        }
        struct record r;
        if (load_record(path, &r) != 0) {
            continue;
        }
        if (!valid_record(&r)) {
            fprintf(stderr, "sigmund: warning: skipping corrupt record %s\n", e->d_name);
            continue;
        }
        enum run_state st = eval_state(&r, r.has_boot ? boot : NULL);
        char age[32];
        format_age(r.start_unix_ns, age, sizeof(age));
        char cmd[64];
        if (checked_snprintf(cmd, sizeof(cmd), "%s", r.cmdline[0] ? r.cmdline : "?") != 0) {
            continue;
        }
        if (strlen(cmd) > 48) {
            cmd[48] = '\0';
            strcat(cmd, "...");
        }
        printf("%-7s %-8ld %-8ld %-6s %-8s %s\n", r.id, (long)r.pid, (long)r.pgid, age, state_str(st), cmd);
    }
    closedir(d);
    return 0;
}

static int cmd_prune(const char *dir) {
    DIR *d = opendir(dir);
    if (!d) {
        return 0;
    }
    char boot[128] = {0};
    get_boot_id(boot, sizeof(boot));
    const struct dirent *e;
    while ((e = readdir(d))) {
        if (!has_suffix(e->d_name, ".json")) {
            continue;
        }
        char path[SIGMUND_PATH_MAX];
        if (checked_snprintf(path, sizeof(path), "%s/%s", dir, e->d_name) != 0) {
            continue;
        }
        struct record r;
        if (load_record(path, &r) != 0) {
            unlink(path);
            continue;
        }
        if (!valid_record(&r)) {
            unlink(path);
            continue;
        }
        if (eval_state(&r, r.has_boot ? boot : NULL) == STATE_DEAD) {
            unlink(path);
            if (r.has_log) {
                unlink(r.log_path);
            }
        }
    }
    rewinddir(d);
    while ((e = readdir(d))) {
        if (!has_suffix(e->d_name, ".log")) {
            continue;
        }
        size_t len = strlen(e->d_name);
        if (len <= 4) {
            continue;
        }
        char id[32];
        size_t id_len = len - 4;
        if (id_len >= sizeof(id)) {
            continue;
        }
        memcpy(id, e->d_name, id_len);
        id[id_len] = '\0';
        if (!valid_id(id)) {
            continue;
        }
        char json_path[SIGMUND_PATH_MAX], log_path[SIGMUND_PATH_MAX];
        if (checked_snprintf(json_path, sizeof(json_path), "%s/%s.json", dir, id) != 0) {
            continue;
        }
        if (checked_snprintf(log_path, sizeof(log_path), "%s/%s", dir, e->d_name) != 0) {
            continue;
        }
        if (access(json_path, F_OK) != 0) {
            unlink(log_path);
        }
    }
    closedir(d);
    return 0;
}

static void usage(void) {
    printf("sigmund %s — More than nohup, less than systemd.\n\n"
           "usage:\n"
           "  sigmund <cmd...>              launch command in background\n"
           "  sigmund --tail <cmd...>       launch and follow log output\n"
           "  sigmund tail <id>             follow existing log output\n"
           "  sigmund -l, --list            list tracked processes\n"
           "  sigmund stop <id>...          graceful stop (SIGTERM → SIGKILL)\n"
           "  sigmund kill <id>...          immediate kill (SIGKILL)\n"
           "  sigmund killcmd <id>...       print kill command for scripting\n"
           "  sigmund prune                 remove dead records and logs\n",
           SIGMUND_VERSION);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        usage();
        return 1;
    }

    char dir[SIGMUND_PATH_MAX];
    if (ensure_storage(dir, sizeof(dir)) != 0) {
        die_errno("sigmund: failed to init storage");
    }
    if (maybe_cleanup_for_boot(dir) != 0) {
        die_errno("sigmund: failed to perform boot cleanup");
    }

    int argi = 1;
    if (!strcmp(argv[argi], "--tail")) {
        argi++;
        if (argi >= argc) {
            usage();
            return 5;
        }
        if (!strcmp(argv[argi], "--")) {
            argi++;
            if (argi >= argc) {
                usage();
                return 5;
            }
        }
        return perform_start(dir, true, argc - argi, argv + argi);
    }

    if (!strcmp(argv[argi], "--")) {
        argi++;
        if (argi >= argc) {
            return 5;
        }
        return perform_start(dir, false, argc - argi, argv + argi);
    }

    if (!strcmp(argv[argi], "tail")) {
        if (argi + 1 >= argc) {
            fprintf(stderr, "usage: sigmund tail <id>\n");
            return 5;
        }
        struct record r;
        char path[SIGMUND_PATH_MAX];
        if (load_record_by_id(dir, argv[argi + 1], &r, path, sizeof(path)) != 0) {
            return 5;
        }
        if (!r.has_log) {
            fprintf(stderr, "sigmund: record has no log path: %s\n", argv[argi + 1]);
            return 5;
        }
        return tail_log_until_exit(&r, true);
    }

    if (!strcmp(argv[argi], "-l") || !strcmp(argv[argi], "--list")) {
        return cmd_list(dir);
    }
    if (!strcmp(argv[argi], "prune")) {
        return cmd_prune(dir);
    }
    if (!strcmp(argv[argi], "stop")) {
        if (argi + 1 >= argc) {
            fprintf(stderr, "usage: sigmund stop <id>...\n");
            return 5;
        }
        int worst = 0;
        for (int i = argi + 1; i < argc; i++) {
            int rc = do_signal_action(dir, argv[i], SIGTERM, true);
            if (rc > worst) {
                worst = rc;
            }
        }
        return worst;
    }
    if (!strcmp(argv[argi], "kill")) {
        if (argi + 1 >= argc) {
            fprintf(stderr, "usage: sigmund kill <id>...\n");
            return 5;
        }
        int worst = 0;
        for (int i = argi + 1; i < argc; i++) {
            int rc = do_signal_action(dir, argv[i], SIGKILL, false);
            if (rc > worst) {
                worst = rc;
            }
        }
        return worst;
    }
    if (!strcmp(argv[argi], "killcmd")) {
        if (argi + 1 >= argc) {
            fprintf(stderr, "usage: sigmund killcmd <id>...\n");
            return 5;
        }
        int worst = 0;
        for (int i = argi + 1; i < argc; i++) {
            struct record r;
            char path[SIGMUND_PATH_MAX];
            int rc = 0;
            if (load_record_by_id(dir, argv[i], &r, path, sizeof(path)) != 0) {
                rc = 5;
            } else if (r.pgid <= 1) {
                fprintf(stderr, "sigmund: error: invalid pgid %ld in record file\n", (long)r.pgid);
                rc = 5;
            } else {
                printf("kill -TERM -- -%ld\n", (long)r.pgid);
            }
            if (rc > worst) {
                worst = rc;
            }
        }
        return worst;
    }
    if (!strcmp(argv[argi], "--version")) {
        puts(SIGMUND_VERSION);
        return 0;
    }
    if (!strcmp(argv[argi], "--help") || !strcmp(argv[argi], "-h")) {
        usage();
        return 0;
    }

    return perform_start(dir, false, argc - argi, argv + argi);
}
