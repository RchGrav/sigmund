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
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define ID_HEX_LEN 6
#define STOP_TIMEOUT_MS 5000
#define POLL_SLEEP_MS 25

typedef struct {
    int version;
    char id[16];
    pid_t pid;
    pid_t pgid;
    pid_t sid;
    int64_t start_unix_ns;
    uid_t uid;
    gid_t gid;
    char log_path[1024];
    char boot_id[128];
    uint64_t proc_starttime_ticks;
    uint64_t exe_dev;
    uint64_t exe_ino;
    char cmdline[1024];
    bool has_log;
    bool has_boot;
} record_t;

typedef enum { STATE_RUNNING, STATE_DEAD, STATE_STALE, STATE_UNKNOWN } run_state_t;

static void die(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(1);
}

static int mkdir_p0700(const char *dir) {
    struct stat st;
    if (stat(dir, &st) == 0) {
        if (!S_ISDIR(st.st_mode)) return -1;
        return chmod(dir, 0700);
    }
    return mkdir(dir, 0700);
}

static int read_file_trim(const char *path, char *buf, size_t n) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t r = read(fd, buf, n - 1);
    close(fd);
    if (r < 0) return -1;
    buf[r] = '\0';
    while (r > 0 && (buf[r - 1] == '\n' || buf[r - 1] == '\r' || isspace((unsigned char)buf[r - 1]))) {
        buf[r - 1] = '\0';
        r--;
    }
    return 0;
}

static int get_boot_id(char *buf, size_t n) {
    return read_file_trim("/proc/sys/kernel/random/boot_id", buf, n);
}

static int rand_bytes(uint8_t *buf, size_t n) {
    ssize_t r = getrandom(buf, n, 0);
    if (r == (ssize_t)n) return 0;
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    size_t off = 0;
    while (off < n) {
        ssize_t x = read(fd, buf + off, n - off);
        if (x <= 0) { close(fd); return -1; }
        off += (size_t)x;
    }
    close(fd);
    return 0;
}

static int gen_id(const char *dir, char *out, size_t out_n) {
    uint8_t b[ID_HEX_LEN / 2];
    char path[1200];
    for (int tries = 0; tries < 100; tries++) {
        if (rand_bytes(b, sizeof(b)) != 0) return -1;
        for (size_t i = 0; i < sizeof(b); i++) snprintf(out + i * 2, out_n - i * 2, "%02x", b[i]);
        snprintf(path, sizeof(path), "%s/%s.json", dir, out);
        if (access(path, F_OK) != 0) return 0;
    }
    return -1;
}

static int ensure_storage(char *dir, size_t n, bool *persistent) {
    const char *xdg_runtime = getenv("XDG_RUNTIME_DIR");
    if (xdg_runtime && *xdg_runtime) {
        snprintf(dir, n, "%s/sigmund", xdg_runtime);
        if (mkdir_p0700(dir) == 0) { *persistent = false; return 0; }
    }
    const char *xdg_state = getenv("XDG_STATE_HOME");
    if (xdg_state && *xdg_state) {
        snprintf(dir, n, "%s/sigmund", xdg_state);
    } else {
        const char *home = getenv("HOME");
        if (!home || !*home) return -1;
        snprintf(dir, n, "%s/.local/state/sigmund", home);
        char p1[1024], p2[1024];
        snprintf(p1, sizeof(p1), "%s/.local", home);
        snprintf(p2, sizeof(p2), "%s/.local/state", home);
        mkdir_p0700(p1);
        mkdir_p0700(p2);
    }
    if (mkdir_p0700(dir) != 0) return -1;
    *persistent = true;
    return 0;
}

static int write_all(int fd, const void *buf, size_t n) {
    const char *p = buf;
    while (n > 0) {
        ssize_t w = write(fd, p, n);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        p += w;
        n -= (size_t)w;
    }
    return 0;
}

static void json_escape(FILE *f, const char *s) {
    for (; *s; s++) {
        if (*s == '"' || *s == '\\') fprintf(f, "\\%c", *s);
        else if ((unsigned char)*s < 32) fprintf(f, " ");
        else fputc(*s, f);
    }
}

static int write_record_atomic(const char *dir, const record_t *r, char *out_json_path, size_t out_n) {
    char tmp[1200], fin[1200];
    snprintf(fin, sizeof(fin), "%s/%s.json", dir, r->id);
    snprintf(tmp, sizeof(tmp), "%s/.%s.tmp.%ld", dir, r->id, (long)getpid());

    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return -1;
    FILE *f = fdopen(fd, "w");
    if (!f) { close(fd); return -1; }

    fprintf(f, "{\n");
    fprintf(f, "  \"version\": %d,\n", r->version);
    fprintf(f, "  \"id\": \""); json_escape(f, r->id); fprintf(f, "\",\n");
    fprintf(f, "  \"pid\": %ld,\n", (long)r->pid);
    fprintf(f, "  \"pgid\": %ld,\n", (long)r->pgid);
    fprintf(f, "  \"sid\": %ld,\n", (long)r->sid);
    fprintf(f, "  \"start_unix_ns\": %" PRId64 ",\n", r->start_unix_ns);
    fprintf(f, "  \"argv\": [\""); json_escape(f, r->cmdline); fprintf(f, "\"],\n");
    fprintf(f, "  \"uid\": %u,\n", r->uid);
    fprintf(f, "  \"gid\": %u,\n", r->gid);
    if (r->has_log) { fprintf(f, "  \"log_path\": \""); json_escape(f, r->log_path); fprintf(f, "\",\n"); }
    if (r->has_boot) { fprintf(f, "  \"boot_id\": \""); json_escape(f, r->boot_id); fprintf(f, "\",\n"); }
    fprintf(f, "  \"proc_starttime_ticks\": %" PRIu64 ",\n", r->proc_starttime_ticks);
    fprintf(f, "  \"exe_dev\": %" PRIu64 ",\n", r->exe_dev);
    fprintf(f, "  \"exe_ino\": %" PRIu64 "\n", r->exe_ino);
    fprintf(f, "}\n");

    fflush(f);
    if (fsync(fd) != 0) { fclose(f); unlink(tmp); return -1; }
    fclose(f);
    if (rename(tmp, fin) != 0) { unlink(tmp); return -1; }
    int dfd = open(dir, O_RDONLY | O_DIRECTORY);
    if (dfd >= 0) { fsync(dfd); close(dfd); }
    if (out_json_path) snprintf(out_json_path, out_n, "%s", fin);
    return 0;
}

static int read_proc_stat_tokens(pid_t pid, char *state_out, uint64_t *starttime_out) {
    char path[128], buf[4096];
    snprintf(path, sizeof(path), "/proc/%ld/stat", (long)pid);
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = read(fd, buf, sizeof(buf)-1);
    close(fd);
    if (n <= 0) return -1;
    buf[n] = '\0';
    char *rp = strrchr(buf, ')');
    if (!rp) return -1;
    char *p = rp + 2;
    int idx = 0;
    char *save = NULL;
    bool got_state = false;
    for (char *tok = strtok_r(p, " ", &save); tok; tok = strtok_r(NULL, " ", &save), idx++) {
        if (idx == 0 && state_out) { *state_out = tok[0]; got_state = true; }
        if (idx == 19 && starttime_out) {
            *starttime_out = strtoull(tok, NULL, 10);
            return 0;
        }
    }
    return (state_out && got_state && !starttime_out) ? 0 : -1;
}

static int read_proc_starttime(pid_t pid, uint64_t *out) {
    char path[128], buf[4096];
    snprintf(path, sizeof(path), "/proc/%ld/stat", (long)pid);
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = read(fd, buf, sizeof(buf)-1);
    close(fd);
    if (n <= 0) return -1;
    buf[n] = '\0';
    char *rp = strrchr(buf, ')');
    if (!rp) return -1;
    char *p = rp + 2;
    int idx = 0;
    char *save = NULL;
    for (char *tok = strtok_r(p, " ", &save); tok; tok = strtok_r(NULL, " ", &save), idx++) {
        if (idx == 19) {
            *out = strtoull(tok, NULL, 10);
            return 0;
        }
    }
    return -1;
}

static int read_proc_exe(pid_t pid, uint64_t *dev, uint64_t *ino) {
    char path[128];
    struct stat st;
    snprintf(path, sizeof(path), "/proc/%ld/exe", (long)pid);
    if (stat(path, &st) != 0) return -1;
    *dev = (uint64_t)st.st_dev;
    *ino = (uint64_t)st.st_ino;
    return 0;
}

static bool leader_zombie(pid_t pid) {
    char st = 0;
    return read_proc_stat_tokens(pid, &st, NULL) == 0 && st == 'Z';
}

static bool leader_present(pid_t pid) {
    char path[128];
    struct stat st;
    snprintf(path, sizeof(path), "/proc/%ld", (long)pid);
    if (stat(path, &st) == 0) {
        char stc = 0;
        if (read_proc_stat_tokens(pid, &stc, NULL) == 0 && stc == 'Z') return false;
        return true;
    }
    if (kill(pid, 0) == 0 || errno == EPERM) return true;
    return false;
}

static int group_exists(pid_t pgid) {
    if (kill(-pgid, 0) == 0 || errno == EPERM) return 1;
    if (errno == ESRCH) return 0;
    return -1;
}

static int json_find_key(const char *j, const char *k, const char **v) {
    char pat[64];
    snprintf(pat, sizeof(pat), "\"%s\"", k);
    const char *p = strstr(j, pat);
    if (!p) return -1;
    p = strchr(p, ':');
    if (!p) return -1;
    p++;
    while (*p && isspace((unsigned char)*p)) p++;
    *v = p;
    return 0;
}

static int json_get_i64(const char *j, const char *k, int64_t *out) {
    const char *v;
    if (json_find_key(j, k, &v) != 0) return -1;
    *out = strtoll(v, NULL, 10);
    return 0;
}

static int json_get_u64(const char *j, const char *k, uint64_t *out) {
    const char *v;
    if (json_find_key(j, k, &v) != 0) return -1;
    *out = strtoull(v, NULL, 10);
    return 0;
}

static int json_get_str(const char *j, const char *k, char *out, size_t n) {
    const char *v;
    if (json_find_key(j, k, &v) != 0 || *v != '"') return -1;
    v++;
    size_t i = 0;
    while (*v && *v != '"' && i + 1 < n) {
        if (*v == '\\' && v[1]) v++;
        out[i++] = *v++;
    }
    out[i] = '\0';
    return 0;
}

static int load_record(const char *path, record_t *r) {
    memset(r, 0, sizeof(*r));
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *j = malloc((size_t)sz + 1);
    if (!j) { fclose(f); return -1; }
    if (fread(j, 1, (size_t)sz, f) != (size_t)sz) { free(j); fclose(f); return -1; }
    j[sz] = '\0';
    fclose(f);

    int64_t tmp = 0;
    json_get_i64(j, "version", &tmp); r->version = (int)tmp;
    json_get_str(j, "id", r->id, sizeof(r->id));
    json_get_i64(j, "pid", &tmp); r->pid = (pid_t)tmp;
    json_get_i64(j, "pgid", &tmp); r->pgid = (pid_t)tmp;
    json_get_i64(j, "sid", &tmp); r->sid = (pid_t)tmp;
    json_get_i64(j, "start_unix_ns", &r->start_unix_ns);
    json_get_i64(j, "uid", &tmp); r->uid = (uid_t)tmp;
    json_get_i64(j, "gid", &tmp); r->gid = (gid_t)tmp;
    if (json_get_str(j, "log_path", r->log_path, sizeof(r->log_path)) == 0) r->has_log = true;
    if (json_get_str(j, "boot_id", r->boot_id, sizeof(r->boot_id)) == 0) r->has_boot = true;
    json_get_u64(j, "proc_starttime_ticks", &r->proc_starttime_ticks);
    json_get_u64(j, "exe_dev", &r->exe_dev);
    json_get_u64(j, "exe_ino", &r->exe_ino);
    json_get_str(j, "argv", r->cmdline, sizeof(r->cmdline));
    if (r->cmdline[0] == '\0') {
        const char *v;
        if (json_find_key(j, "argv", &v) == 0 && *v == '[') {
            const char *q = strchr(v, '"');
            if (q) {
                q++;
                size_t i = 0;
                while (*q && *q != '"' && i + 1 < sizeof(r->cmdline)) {
                    if (*q == '\\' && q[1]) q++;
                    r->cmdline[i++] = *q++;
                }
                r->cmdline[i] = '\0';
            }
        }
    }
    free(j);
    return 0;
}

static run_state_t eval_state(const record_t *r, const char *current_boot) {
    if (r->has_boot && current_boot && strcmp(r->boot_id, current_boot) != 0) return STATE_STALE;
    bool present = leader_present(r->pid);
    if (!present && leader_zombie(r->pid)) return STATE_DEAD;
    if (present) {
        if (r->proc_starttime_ticks) {
            uint64_t now;
            if (read_proc_starttime(r->pid, &now) == 0 && now != r->proc_starttime_ticks) return STATE_STALE;
        }
        if (r->exe_dev && r->exe_ino) {
            uint64_t d, i;
            if (read_proc_exe(r->pid, &d, &i) == 0 && (d != r->exe_dev || i != r->exe_ino)) return STATE_STALE;
        }
        return STATE_RUNNING;
    }
    int g = group_exists(r->pgid);
    if (g == 1) return STATE_RUNNING;
    if (g == 0) return STATE_DEAD;
    return STATE_UNKNOWN;
}

static int perform_start(int argc, char **argv) {
    char dir[1024], id[16], log_path[1200], boot_id[128] = {0};
    bool persistent = false;
    if (ensure_storage(dir, sizeof(dir), &persistent) != 0) die("sigmund: failed to prepare storage");
    if (persistent && get_boot_id(boot_id, sizeof(boot_id)) != 0) die("sigmund: failed to read boot_id");
    if (gen_id(dir, id, sizeof(id)) != 0) die("sigmund: failed to generate id");
    snprintf(log_path, sizeof(log_path), "%s/%s.log", dir, id);

    int pipefd[2];
#ifdef O_CLOEXEC
    if (pipe2(pipefd, O_CLOEXEC) != 0)
#endif
    {
        if (pipe(pipefd) != 0) die("sigmund: pipe failed: %s", strerror(errno));
        fcntl(pipefd[0], F_SETFD, FD_CLOEXEC);
        fcntl(pipefd[1], F_SETFD, FD_CLOEXEC);
    }
    bool interactive = isatty(STDOUT_FILENO) && isatty(STDERR_FILENO);

    pid_t pid = fork();
    if (pid < 0) die("sigmund: fork failed: %s", strerror(errno));
    if (pid == 0) {
        close(pipefd[0]);
        if (setsid() < 0) { int e = errno; write_all(pipefd[1], &e, sizeof(e)); _exit(127); }
        int nullfd = open("/dev/null", O_RDONLY);
        if (nullfd < 0 || dup2(nullfd, STDIN_FILENO) < 0) { int e = errno; write_all(pipefd[1], &e, sizeof(e)); _exit(127); }
        if (nullfd > 2) close(nullfd);

        if (!interactive) {
            int lfd = open(log_path, O_WRONLY | O_CREAT | O_APPEND, 0600);
            if (lfd < 0 || dup2(lfd, STDOUT_FILENO) < 0 || dup2(lfd, STDERR_FILENO) < 0) {
                int e = errno; write_all(pipefd[1], &e, sizeof(e)); _exit(127);
            }
            if (lfd > 2) close(lfd);
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
        return 1;
    }

    record_t r = {0};
    r.version = 1;
    snprintf(r.id, sizeof(r.id), "%s", id);
    r.pid = pid;
    r.pgid = pid;
    r.sid = pid;
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    r.start_unix_ns = (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
    r.uid = getuid();
    r.gid = getgid();
    r.has_log = !interactive;
    if (r.has_log) { strncpy(r.log_path, log_path, sizeof(r.log_path)-1); r.log_path[sizeof(r.log_path)-1]=0; }
    r.has_boot = persistent;
    if (r.has_boot) snprintf(r.boot_id, sizeof(r.boot_id), "%s", boot_id);
    read_proc_starttime(pid, &r.proc_starttime_ticks);
    read_proc_exe(pid, &r.exe_dev, &r.exe_ino);
    size_t off = 0;
    for (int i = 0; i < argc; i++) {
        size_t left = sizeof(r.cmdline) - off;
        int w = snprintf(r.cmdline + off, left, "%s%s", i ? " " : "", argv[i]);
        if (w < 0 || (size_t)w >= left) break;
        off += (size_t)w;
    }
    if (write_record_atomic(dir, &r, NULL, 0) != 0) die("sigmund: failed to write record");

    printf("sigmund: id=%s pid=%ld pgid=%ld sid=%ld\n", r.id, (long)r.pid, (long)r.pgid, (long)r.sid);
    if (r.has_log) printf("sigmund: log: %s\n", r.log_path);
    return 0;
}

static int load_record_by_id(const char *dir, const char *id, record_t *r, char *path, size_t n) {
    snprintf(path, n, "%s/%s.json", dir, id);
    if (access(path, F_OK) != 0) return -1;
    return load_record(path, r);
}

static int do_signal_action(const char *dir, const char *id, int sig, bool graceful) {
    record_t r;
    char path[1200], boot[128] = {0};
    if (load_record_by_id(dir, id, &r, path, sizeof(path)) != 0) return 5;
    if (r.has_boot && get_boot_id(boot, sizeof(boot)) == 0 && strcmp(r.boot_id, boot) != 0) return 2;

    run_state_t st = eval_state(&r, r.has_boot ? boot : NULL);
    if (st == STATE_STALE) return 2;
    if (st == STATE_DEAD) return 0;

    if (kill(-r.pgid, sig) != 0) {
        if (errno == EPERM) return 3;
        if (errno == ESRCH) return 0;
        return 4;
    }

    if (graceful) {
        int waited = 0;
        while (waited < STOP_TIMEOUT_MS) {
            int g = group_exists(r.pgid);
            if (g == 0 || leader_zombie(r.pgid)) return 0;
            struct timespec sl = {.tv_sec = 0, .tv_nsec = POLL_SLEEP_MS * 1000000L};
            nanosleep(&sl, NULL);
            waited += POLL_SLEEP_MS;
        }
        if (kill(-r.pgid, SIGKILL) != 0 && errno != ESRCH) {
            if (errno == EPERM) return 3;
            return 4;
        }
        int g = group_exists(r.pgid);
        return g == 0 ? 0 : 4;
    }

    return 0;
}

static const char *state_str(run_state_t s) {
    switch (s) {
        case STATE_RUNNING: return "running";
        case STATE_DEAD: return "dead";
        case STATE_STALE: return "stale";
        default: return "unknown";
    }
}

static void format_age(int64_t start_ns, char *out, size_t n) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    int64_t now = (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
    int64_t sec = (now - start_ns) / 1000000000LL;
    if (sec < 0) sec = 0;
    snprintf(out, n, "%" PRId64 "s", sec);
}

static int cmd_list(const char *dir) {
    DIR *d = opendir(dir);
    if (!d) return 0;
    char boot[128] = {0};
    get_boot_id(boot, sizeof(boot));
    printf("ID      PID      PGID     AGE    STATE    CMD\n");
    struct dirent *e;
    while ((e = readdir(d))) {
        if (!strstr(e->d_name, ".json")) continue;
        char path[1200];
        if (snprintf(path, sizeof(path), "%s/%s", dir, e->d_name) >= (int)sizeof(path)) continue;
        record_t r;
        if (load_record(path, &r) != 0) continue;
        run_state_t st = eval_state(&r, r.has_boot ? boot : NULL);
        char age[32];
        format_age(r.start_unix_ns, age, sizeof(age));
        char cmd[64];
        strncpy(cmd, r.cmdline[0] ? r.cmdline : "?", sizeof(cmd)-1); cmd[sizeof(cmd)-1]=0;
        if (strlen(cmd) > 48) { cmd[48] = '\0'; strcat(cmd, "..."); }
        printf("%-7s %-8ld %-8ld %-6s %-8s %s\n", r.id, (long)r.pid, (long)r.pgid, age, state_str(st), cmd);
    }
    closedir(d);
    return 0;
}

static int cmd_prune(const char *dir) {
    DIR *d = opendir(dir);
    if (!d) return 0;
    char boot[128] = {0};
    get_boot_id(boot, sizeof(boot));
    struct dirent *e;
    while ((e = readdir(d))) {
        if (!strstr(e->d_name, ".json")) continue;
        char path[1200];
        if (snprintf(path, sizeof(path), "%s/%s", dir, e->d_name) >= (int)sizeof(path)) continue;
        record_t r;
        if (load_record(path, &r) != 0) continue;
        if (eval_state(&r, r.has_boot ? boot : NULL) == STATE_DEAD) unlink(path);
    }
    closedir(d);
    return 0;
}

static void usage(void) {
    puts("usage: sigmund <cmd...>\n"
         "       sigmund -l|--list\n"
         "       sigmund stop <id>\n"
         "       sigmund kill <id>\n"
         "       sigmund killcmd <id>\n"
         "       sigmund prune");
}

int main(int argc, char **argv) {
    if (argc < 2) { usage(); return 1; }

    char dir[1024];
    bool persistent = false;
    if (ensure_storage(dir, sizeof(dir), &persistent) != 0) die("sigmund: failed to init storage");

    if (!strcmp(argv[1], "-l") || !strcmp(argv[1], "--list")) return cmd_list(dir);
    if (!strcmp(argv[1], "prune")) return cmd_prune(dir);
    if (!strcmp(argv[1], "stop")) {
        if (argc != 3) return 5;
        return do_signal_action(dir, argv[2], SIGTERM, true);
    }
    if (!strcmp(argv[1], "kill")) {
        if (argc != 3) return 5;
        return do_signal_action(dir, argv[2], SIGKILL, false);
    }
    if (!strcmp(argv[1], "killcmd")) {
        if (argc != 3) return 5;
        record_t r; char path[1200];
        if (load_record_by_id(dir, argv[2], &r, path, sizeof(path)) != 0) return 5;
        printf("kill -TERM -- -%ld\n", (long)r.pgid);
        return 0;
    }
    if (!strcmp(argv[1], "--help") || !strcmp(argv[1], "-h")) { usage(); return 0; }

    return perform_start(argc - 1, argv + 1);
}
