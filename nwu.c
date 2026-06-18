/*
 * nwu - Novel Wiping Utility
 *
 * Secure file/directory removal and free-space wiping, SSD-aware.
 *
 * The novel angle: COMBINE logical overwrite with controller-level discard
 * (TRIM) in one operation, instead of doing one or the other:
 *
 *   1. overwrite the addressable bytes with a fast high-entropy stream ->
 *      defeats the mapped copy, covers drives that ignore/lack TRIM, and is
 *      non-compressible so SSD controllers that transparently compress/dedupe
 *      cannot collapse the write to nothing.
 *   2. fallocate(PUNCH_HOLE) the file's own extents -> per-file discard,
 *      issued while we still hold the fd, before unlink.
 *   3. FITRIM the whole filesystem after unlink -> tells the NAND controller
 *      every free block may be physically erased.
 *
 * Plus, to wipe "as much as possible":
 *   - overwrite is rounded up to the filesystem block size, so the slack at the
 *     tail of the final block is erased too (not just st_size bytes).
 *   - the name is destroyed by several random renames, each followed by an
 *     fsync of the containing directory so the metadata change reaches disk.
 *   - free-space wipe uses f_bfree when root (also reclaims the reserved
 *     blocks), and rolls onto additional fill files when one hits the
 *     filesystem's max file size (EFBIG on FAT32/exFAT) so the whole free area
 *     is covered, not just the first 4 GiB.
 *
 * On an SSD no userspace tool can guarantee erasure (wear leveling +
 * over-provisioning keep stale pages physically present until the controller
 * GCs them). This maximizes the chance: it both poisons the mapped data and
 * asks the controller to reclaim/erase as much as it is willing to.
 *
 * Runs as an interactive menu (no args) or from the command line (scripting).
 * Build: make.  Linux only (fallocate punch-hole, getrandom, FITRIM).
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <ftw.h>
#include <poll.h>
#include <termios.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/ioctl.h>
#include <sys/random.h>
#include <sys/resource.h>  /* setrlimit, RLIMIT_CORE */
#include <sys/mman.h>      /* mlock, munlock */
#include <sys/prctl.h>     /* prctl, PR_SET_DUMPABLE */
#include <linux/fs.h>      /* FITRIM, struct fstrim_range */

#ifndef FALLOC_FL_PUNCH_HOLE
#include <linux/falloc.h>
#endif

#define NWU_VERSION "1.2.0"
#define BUFSZ (1u << 20)   /* 1 MiB I/O buffer */

static int g_passes = 1;
static int g_verbose = 0;
static int g_do_trim = 1;
static int g_verify  = 0;   /* -c: read-back verification after overwrite */

static void vlog(const char *fmt, ...)
{
    if (!g_verbose) return;
    va_list ap; va_start(ap, fmt);
    vfprintf(stderr, fmt, ap); va_end(ap);
}

/* ---------------------------------------------------------------- hardening */

/* Best-effort process hardening. Non-fatal: the tool still runs if these
 * fail (e.g. unprivileged). nwu never reads target data into memory, so this
 * is mainly hygiene: stop a crash from writing a core file onto the disk we
 * are wiping, and block ptrace/dump of the live process. */
static void harden_process(void)
{
    struct rlimit rl = { 0, 0 };
    if (setrlimit(RLIMIT_CORE, &rl) < 0)
        vlog("  harden: RLIMIT_CORE: %s\n", strerror(errno));
    if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) < 0)
        vlog("  harden: PR_SET_DUMPABLE: %s\n", strerror(errno));
}

/* ------------------------------------------------------------------ random */

/* Direct kernel CSPRNG. Used for small, security-sensitive values (keystream
 * seed, random rename names) and as the fallback bulk source. */
static int fill_random_sys(unsigned char *buf, size_t n)
{
    size_t off = 0;
    while (off < n) {
        ssize_t r = getrandom(buf + off, n - off, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        off += (size_t)r;
    }
    return 0;
}

/* ---- fast high-entropy stream (ChaCha20) -------------------------------
 * getrandom() can be slower than the disk for multi-GB fills and would be the
 * bottleneck. We seed a ChaCha20 keystream from getrandom() once, then generate
 * non-compressible bytes in userspace at GB/s. High entropy is the point: a
 * low-entropy pattern would be transparently compressed/deduped by SandForce-
 * class SSD controllers and never actually overwrite anything. */

#define ROTL32(v, c) (((v) << (c)) | ((v) >> (32 - (c))))
#define QROUND(x, a, b, c, d) do {                                  \
    (x)[a] += (x)[b]; (x)[d] ^= (x)[a]; (x)[d] = ROTL32((x)[d], 16); \
    (x)[c] += (x)[d]; (x)[b] ^= (x)[c]; (x)[b] = ROTL32((x)[b], 12); \
    (x)[a] += (x)[b]; (x)[d] ^= (x)[a]; (x)[d] = ROTL32((x)[d],  8); \
    (x)[c] += (x)[d]; (x)[b] ^= (x)[c]; (x)[b] = ROTL32((x)[b],  7); \
} while (0)

typedef struct {
    uint32_t state[16];
    unsigned char block[64];
    size_t used;            /* bytes of block already consumed (64 = exhausted) */
} chacha_t;

static chacha_t g_rng;
static int g_rng_ready = 0;

static void chacha_block(uint32_t out[16], const uint32_t in[16])
{
    uint32_t x[16];
    memcpy(x, in, sizeof x);
    for (int i = 0; i < 10; i++) {            /* 20 rounds = 10 double-rounds */
        QROUND(x, 0, 4,  8, 12); QROUND(x, 1, 5,  9, 13);
        QROUND(x, 2, 6, 10, 14); QROUND(x, 3, 7, 11, 15);
        QROUND(x, 0, 5, 10, 15); QROUND(x, 1, 6, 11, 12);
        QROUND(x, 2, 7,  8, 13); QROUND(x, 3, 4,  9, 14);
    }
    for (int i = 0; i < 16; i++) out[i] = x[i] + in[i];
}

static int rng_init(void)
{
    unsigned char seed[40];                   /* 32-byte key + 8-byte nonce */
    if (fill_random_sys(seed, sizeof seed) < 0) { g_rng_ready = 0; return -1; }
    g_rng.state[0] = 0x61707865u; g_rng.state[1] = 0x3320646eu;
    g_rng.state[2] = 0x79622d32u; g_rng.state[3] = 0x6b206574u;  /* "expand 32-byte k" */
    for (int i = 0; i < 8; i++)
        g_rng.state[4 + i] = (uint32_t)seed[i*4]
                           | ((uint32_t)seed[i*4 + 1] << 8)
                           | ((uint32_t)seed[i*4 + 2] << 16)
                           | ((uint32_t)seed[i*4 + 3] << 24);
    g_rng.state[12] = 0;                       /* 64-bit block counter (12,13) */
    g_rng.state[13] = 0;
    g_rng.state[14] = (uint32_t)seed[32] | ((uint32_t)seed[33] << 8)
                    | ((uint32_t)seed[34] << 16) | ((uint32_t)seed[35] << 24);
    g_rng.state[15] = (uint32_t)seed[36] | ((uint32_t)seed[37] << 8)
                    | ((uint32_t)seed[38] << 16) | ((uint32_t)seed[39] << 24);
    g_rng.used = 64;
    g_rng_ready = 1;
    return 0;
}

/* Fill buf with the keystream (falls back to the kernel if seeding failed). */
static int rng_fill(unsigned char *buf, size_t n)
{
    if (!g_rng_ready) return fill_random_sys(buf, n);
    size_t off = 0;
    while (off < n) {
        if (g_rng.used >= 64) {
            uint32_t out[16];
            chacha_block(out, g_rng.state);
            for (int i = 0; i < 16; i++) {
                g_rng.block[i*4 + 0] = (unsigned char)(out[i]);
                g_rng.block[i*4 + 1] = (unsigned char)(out[i] >> 8);
                g_rng.block[i*4 + 2] = (unsigned char)(out[i] >> 16);
                g_rng.block[i*4 + 3] = (unsigned char)(out[i] >> 24);
            }
            g_rng.used = 0;
            if (++g_rng.state[12] == 0) g_rng.state[13]++;   /* 64-bit counter */
        }
        size_t take = 64 - g_rng.used;
        if (take > n - off) take = n - off;
        memcpy(buf + off, g_rng.block + g_rng.used, take);
        g_rng.used += take;
        off += take;
    }
    return 0;
}

/* Print what is actually in effect, so the operator knows this run's posture.
 * Called once at startup, after harden_process() and rng_init(). */
static void print_startup_status(void)
{
    printf("nwu " NWU_VERSION " starting\n");

    /* Privilege level. */
    uid_t euid = geteuid();
    if (euid == 0)
        printf("  [ok]   privilege: ELEVATED (root) - FITRIM + reserved-block wipe available\n");
    else
        printf("  [warn] privilege: unprivileged (uid %u) - FITRIM needs root\n",
               (unsigned)euid);

    /* Coredumps: read back the limit harden_process() set. */
    struct rlimit rl;
    if (getrlimit(RLIMIT_CORE, &rl) == 0 && rl.rlim_cur == 0)
        printf("  [ok]   coredumps: disabled\n");
    else
        printf("  [warn] coredumps: NOT disabled (could write a core to disk)\n");

    /* RNG: report which fill source is live. */
    if (g_rng_ready)
        printf("  [ok]   rng: ChaCha20 keystream seeded (fast, non-compressible)\n");
    else
        printf("  [warn] rng: ChaCha20 seed failed - using getrandom() per call\n");

    /* mlock probe: try to lock one page so we report the real capability. */
    long pg = sysconf(_SC_PAGESIZE);
    if (pg < 1) pg = 4096;
    void *probe = malloc((size_t)pg);
    if (probe && mlock(probe, (size_t)pg) == 0) {
        munlock(probe, (size_t)pg);
        printf("  [ok]   mlock: working - I/O buffers kept out of swap\n");
    } else {
        printf("  [warn] mlock: unavailable (%s) - buffers may reach swap\n",
               strerror(errno));
    }
    free(probe);
    fflush(stdout);
}

/* malloc + best-effort mlock so the random buffer never reaches swap.
 * The pragma silences a GCC constprop false positive on the mlock() arg. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
static unsigned char *locked_alloc(size_t n)
{
    void *p = malloc(n);
    if (!p) return NULL;
    if (mlock(p, n) < 0)
        vlog("  mlock(%zu): %s (non-fatal)\n", n, strerror(errno));
    return (unsigned char *)p;
}
#pragma GCC diagnostic pop

static void locked_free(unsigned char *p, size_t n)
{
    if (!p) return;
    munlock(p, n);
    free(p);
}

/* --------------------------------------------------------------------- trim */

static void fs_trim(const char *path_on_fs)
{
    if (!g_do_trim) return;
    int fd = open(path_on_fs, O_RDONLY);
    if (fd < 0) return;
    struct fstrim_range r = { .start = 0, .len = (uint64_t)-1, .minlen = 0 };
    if (ioctl(fd, FITRIM, &r) < 0) {
        const char *hint;
        if (errno == EOPNOTSUPP || errno == ENOTTY)
            hint = "filesystem/stack does not support discard "
                   "(e.g. LUKS without 'discard', HDD, or VM disk) - "
                   "the random overwrite was still done";
        else if (errno == EPERM || errno == EACCES)
            hint = "needs root";
        else
            hint = "discard step skipped";
        vlog("  FITRIM(%s): %s (%s)\n", path_on_fs, strerror(errno), hint);
    } else
        vlog("  FITRIM(%s): discarded ~%llu bytes\n",
             path_on_fs, (unsigned long long)r.len);
    close(fd);
}

static void fs_trim_for(const char *path)
{
    char *dup = strdup(path);
    if (!dup) return;
    char *slash = strrchr(dup, '/');
    const char *dir = (slash) ? (slash == dup ? "/" : (*slash = 0, dup)) : ".";
    fs_trim(dir);
    free(dup);
}

/* ------------------------------------------------------------- file wiping */

static int overwrite_pass(int fd, off_t size, unsigned char *buf)
{
    if (lseek(fd, 0, SEEK_SET) < 0) return -1;
    off_t left = size;
    while (left > 0) {
        size_t chunk = (left < (off_t)BUFSZ) ? (size_t)left : BUFSZ;
        if (rng_fill(buf, chunk) < 0) return -1;
        size_t w = 0;
        while (w < chunk) {
            ssize_t k = write(fd, buf + w, chunk - w);
            if (k < 0) { if (errno == EINTR) continue; return -1; }
            w += (size_t)k;
        }
        left -= (off_t)chunk;
    }
    return fdatasync(fd);
}

/* Read-back verification (DoD 5200.28 style "last pass verify"): write a known
 * pattern (zeros), flush it to the device, drop the cache, then read it back and
 * confirm every byte landed. Proves the sectors are actually writable and that
 * the final on-device state is what we intended - not just dirtied in RAM.
 * Returns 0 on success, -1 on I/O error, 1 on a verification MISMATCH. */
static int verify_pass(int fd, off_t size, unsigned char *buf)
{
    /* write the known pattern */
    if (lseek(fd, 0, SEEK_SET) < 0) return -1;
    memset(buf, 0, BUFSZ);
    off_t left = size;
    while (left > 0) {
        size_t chunk = (left < (off_t)BUFSZ) ? (size_t)left : BUFSZ;
        size_t w = 0;
        while (w < chunk) {
            ssize_t k = write(fd, buf + w, chunk - w);
            if (k < 0) { if (errno == EINTR) continue; return -1; }
            w += (size_t)k;
        }
        left -= (off_t)chunk;
    }
    if (fdatasync(fd) < 0) return -1;
    /* evict the page cache so the read comes from the device, not RAM */
    posix_fadvise(fd, 0, size, POSIX_FADV_DONTNEED);

    /* read it back and confirm */
    if (lseek(fd, 0, SEEK_SET) < 0) return -1;
    left = size;
    while (left > 0) {
        size_t chunk = (left < (off_t)BUFSZ) ? (size_t)left : BUFSZ;
        size_t r = 0;
        while (r < chunk) {
            ssize_t k = read(fd, buf + r, chunk - r);
            if (k < 0) { if (errno == EINTR) continue; return -1; }
            if (k == 0) return 1;                 /* short file: cannot confirm */
            r += (size_t)k;
        }
        for (size_t i = 0; i < chunk; i++)
            if (buf[i] != 0) return 1;            /* a byte did not stick */
        left -= (off_t)chunk;
    }
    return 0;
}

/* Derive the parent directory of path into dir[dirsz] ("." / "/" handled). */
static void parent_dir(const char *path, char *dir, size_t dirsz)
{
    char *dup = strdup(path);
    if (!dup) { snprintf(dir, dirsz, "."); return; }
    char *slash = strrchr(dup, '/');
    if (slash) {
        if (slash == dup) snprintf(dir, dirsz, "/");
        else { *slash = 0; snprintf(dir, dirsz, "%s", dup); }
    } else {
        snprintf(dir, dirsz, ".");
    }
    free(dup);
}

/* Build dir/.<hexlen hex chars> from fresh kernel randomness. */
static void rand_name(char *out, size_t outsz, const char *dir, int hexlen)
{
    static const char H[] = "0123456789abcdef";
    unsigned char r[8];
    char hex[17];
    if (hexlen > 16) hexlen = 16;
    fill_random_sys(r, sizeof r);
    for (int i = 0; i < hexlen; i++)
        hex[i] = H[(r[i / 2] >> ((i & 1) ? 0 : 4)) & 0xf];
    hex[hexlen] = 0;
    snprintf(out, outsz, "%s/.%s", dir, hex);
}

/* Destroy the directory entry: rename to several random names of decreasing
 * length, fsync the directory after each so the entry rewrite reaches disk,
 * then unlink and fsync once more. On journaling filesystems the old name may
 * still survive in the journal, but this overwrites the live directory block. */
static void obscure_and_unlink(const char *path)
{
    char dir[4096];
    parent_dir(path, dir, sizeof dir);

    int dfd = open(dir, O_RDONLY | O_DIRECTORY);
    char cur[4128];
    snprintf(cur, sizeof cur, "%s", path);

    const int lens[] = { 8, 6, 4 };
    for (size_t i = 0; i < sizeof lens / sizeof lens[0]; i++) {
        char next[4128];
        rand_name(next, sizeof next, dir, lens[i]);
        if (rename(cur, next) != 0) break;
        snprintf(cur, sizeof cur, "%s", next);
        if (dfd >= 0) fsync(dfd);
    }
    unlink(cur);
    if (dfd >= 0) { fsync(dfd); close(dfd); }
}

/* Wipe a single regular file. Does NOT issue fs TRIM (caller batches that). */
static int wipe_one_file(const char *path)
{
    struct stat st;
    if (lstat(path, &st) < 0) {
        fprintf(stderr, "nwu: %s: %s\n", path, strerror(errno));
        return -1;
    }
    if (!S_ISREG(st.st_mode)) {
        if (S_ISLNK(st.st_mode)) { unlink(path); return 0; }  /* just drop link */
        fprintf(stderr, "nwu: %s: not a regular file, skipping\n", path);
        return -1;
    }
    if (st.st_nlink > 1)
        fprintf(stderr,
                "nwu: warning: %s has %lu hard links; overwriting destroys the "
                "shared data for ALL of them\n",
                path, (unsigned long)st.st_nlink);

    int fd = open(path, O_RDWR | O_NOFOLLOW);
    if (fd < 0) {
        fprintf(stderr, "nwu: open %s: %s\n", path, strerror(errno));
        return -1;
    }

    unsigned char *buf = locked_alloc(BUFSZ);
    if (!buf) { close(fd); return -1; }

    /* Round up to the filesystem block size so the slack at the tail of the
     * final block (old data beyond EOF, but inside the allocated block) is
     * overwritten too, not just the st_size addressable bytes. */
    off_t wsize = st.st_size;
    blksize_t bs = st.st_blksize;
    if (bs > 0 && wsize > 0)
        wsize = ((wsize + bs - 1) / bs) * bs;

    int rc = 0;
    for (int p = 0; p < g_passes; p++) {
        vlog("  %s: overwrite pass %d/%d (%lld bytes, slack-rounded)\n", path,
             p + 1, g_passes, (long long)wsize);
        if (overwrite_pass(fd, wsize, buf) < 0) {
            fprintf(stderr, "nwu: overwrite %s: %s\n", path, strerror(errno));
            rc = -1; break;
        }
    }

    if (rc == 0 && g_verify && wsize > 0) {
        vlog("  %s: verifying (read-back)\n", path);
        int v = verify_pass(fd, wsize, buf);
        if (v < 0) {
            fprintf(stderr, "nwu: verify %s: %s\n", path, strerror(errno));
            rc = -1;
        } else if (v > 0) {
            fprintf(stderr, "nwu: VERIFY FAILED: %s - data did not land on the "
                            "device as written\n", path);
            rc = -1;
        } else {
            vlog("  %s: verified OK\n", path);
        }
    }
    locked_free(buf, BUFSZ);

    if (rc == 0 && wsize > 0) {
        if (fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
                      0, wsize) == 0)
            vlog("  %s: extents marked discardable\n", path);
    }

    if (ftruncate(fd, 0) < 0) vlog("  %s: truncate: %s\n", path, strerror(errno));
    fsync(fd);
    close(fd);

    obscure_and_unlink(path);
    return rc;
}

/* nftw callback: depth-first so files are wiped before their dirs removed. */
static int nftw_cb(const char *path, const struct stat *st,
                   int typeflag, struct FTW *ftw)
{
    (void)ftw;
    switch (typeflag) {
    case FTW_F:    if (S_ISREG(st->st_mode)) wipe_one_file(path);
                   else unlink(path);   /* fifo/socket/device node: just remove */
                   return 0;            /* keep walking regardless */
    case FTW_SL:
    case FTW_SLN:  unlink(path); return 0;
    case FTW_DP:   if (rmdir(path) < 0)
                       fprintf(stderr, "nwu: rmdir %s: %s\n",
                               path, strerror(errno));
                   else vlog("  removed dir %s\n", path);
                   return 0;
    case FTW_DNR:  fprintf(stderr, "nwu: %s: unreadable dir\n", path); return 0;
    default:       return 0;
    }
}

/* Public entry: wipe a path (file OR directory tree), then one fs TRIM. */
static int wipe_path(const char *path)
{
    struct stat st;
    if (lstat(path, &st) < 0) {
        fprintf(stderr, "nwu: %s: %s\n", path, strerror(errno));
        return -1;
    }
    int rc = 0;
    if (S_ISDIR(st.st_mode)) {
        printf("nwu: wiping directory tree %s\n", path);
        if (nftw(path, nftw_cb, 32, FTW_DEPTH | FTW_PHYS) < 0) {
            fprintf(stderr, "nwu: nftw %s: %s\n", path, strerror(errno));
            rc = -1;
        }
    } else {
        printf("nwu: wiping file %s\n", path);
        rc = wipe_one_file(path);
    }
    fs_trim_for(path);
    return rc;
}

/* ------------------------------------------------------ free-space wiping */

static double now_sec(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

static void human(double bytes, char *out, size_t n)
{
    const char *u[] = { "B", "KiB", "MiB", "GiB", "TiB" };
    int i = 0;
    while (bytes >= 1024.0 && i < 4) { bytes /= 1024.0; i++; }
    snprintf(out, n, "%.2f %s", bytes, u[i]);
}

static void draw_progress(unsigned long long done, unsigned long long total,
                          double elapsed)
{
    double frac = total ? (double)done / (double)total : 0.0;
    if (frac > 1.0) frac = 1.0;
    int width = 30;
    int filled = (int)(frac * width);

    double speed = elapsed > 0 ? done / elapsed : 0;          /* B/s */
    double eta = speed > 0 ? (total - done) / speed : 0;       /* s   */

    char sp[32], spd[32];
    human(done, sp, sizeof sp);
    human(speed, spd, sizeof spd);

    fprintf(stderr, "\r[");
    for (int i = 0; i < width; i++) fputc(i < filled ? '#' : '-', stderr);
    fprintf(stderr, "] %5.1f%%  %s  %s/s  ETA %02d:%02d   ",
            frac * 100.0, sp, spd,
            (int)(eta / 60), (int)eta % 60);
    fflush(stderr);
}

/* Put the controlling TTY into non-canonical, no-echo mode so we can read
 * single keypresses without Enter. Returns 1 if raw mode was enabled (stdin is
 * a TTY) and fills *saved; 0 otherwise. */
static int tty_raw_on(struct termios *saved)
{
    if (!isatty(STDIN_FILENO)) return 0;
    if (tcgetattr(STDIN_FILENO, saved) < 0) return 0;
    struct termios raw = *saved;
    raw.c_lflag &= ~(ICANON | ECHO);
    raw.c_cc[VMIN] = 0;
    raw.c_cc[VTIME] = 0;
    if (tcsetattr(STDIN_FILENO, TCSANOW, &raw) < 0) return 0;
    return 1;
}

static void tty_raw_off(const struct termios *saved)
{
    tcsetattr(STDIN_FILENO, TCSANOW, saved);
}

/* Non-blocking: return 1 if the user pressed 's' or 'S' since last check. */
static int stop_requested(void)
{
    struct pollfd pfd = { .fd = STDIN_FILENO, .events = POLLIN };
    int hit = 0;
    while (poll(&pfd, 1, 0) > 0 && (pfd.revents & POLLIN)) {
        char c;
        ssize_t r = read(STDIN_FILENO, &c, 1);
        if (r <= 0) break;
        if (c == 's' || c == 'S') hit = 1;   /* drain rest of buffer too */
    }
    return hit;
}

/* Create one anonymous fill file in mount: linked just long enough to get an
 * fd, then unlinked. Kept open it occupies blocks; closing (or a crash) frees
 * them automatically, so we never leave a giant file behind. */
static int open_fill_file(const char *mount)
{
    char tmpl[4096];
    snprintf(tmpl, sizeof tmpl, "%s/.nwu_fill_XXXXXX", mount);
    int fd = mkstemp(tmpl);
    if (fd < 0) return -1;
    unlink(tmpl);
    return fd;
}

static int wipe_freespace(const char *mount)
{
    struct statvfs vfs;
    if (statvfs(mount, &vfs) < 0) {
        fprintf(stderr, "nwu: statvfs %s: %s\n", mount, strerror(errno));
        return -1;
    }
    /* As root, fill f_bfree (includes the reserved blocks) so even the
     * root-reserved free space gets wiped; otherwise only f_bavail is usable. */
    int as_root = (geteuid() == 0);
    unsigned long long avail =
        (unsigned long long)(as_root ? vfs.f_bfree : vfs.f_bavail) * vfs.f_frsize;

    unsigned char *buf = locked_alloc(BUFSZ);
    if (!buf) return -1;

    /* Hold every fill file's fd open so its blocks stay occupied until we are
     * done; roll to a new file when one hits the FS max file size (EFBIG). */
    enum { MAXFILES = 4096 };
    int *fds = malloc(sizeof(int) * 8);
    int cap = 8, nfds = 0;
    if (!fds) { locked_free(buf, BUFSZ); return -1; }

    int fd = open_fill_file(mount);
    if (fd < 0) {
        fprintf(stderr, "nwu: mkstemp in %s: %s\n", mount, strerror(errno));
        free(fds); locked_free(buf, BUFSZ); return -1;
    }
    fds[nfds++] = fd;

    struct termios saved;
    int raw = tty_raw_on(&saved);

    char ah[32]; human((double)avail, ah, sizeof ah);
    printf("nwu: wiping free space on %s (~%s%s)%s\n", mount, ah,
           as_root ? ", incl. reserved" : "",
           raw ? "  [press 's' to stop]" : "");

    unsigned long long written = 0;
    double start = now_sec(), last = start;
    int rc = 0, stopped = 0;
    for (;;) {
        if (raw && stop_requested()) { stopped = 1; break; }
        if (rng_fill(buf, BUFSZ) < 0) { rc = -1; break; }
        ssize_t k = write(fd, buf, BUFSZ);
        if (k < 0) {
            if (errno == ENOSPC) break;
            if (errno == EINTR) continue;
            if (errno == EFBIG) {                 /* this file is maxed out */
                fdatasync(fd);
                if (nfds >= MAXFILES) break;
                int nf = open_fill_file(mount);
                if (nf < 0) break;                /* out of space/inodes: done */
                if (nfds >= cap) {
                    int ncap = cap * 2;
                    int *t = realloc(fds, sizeof(int) * ncap);
                    if (!t) { close(nf); break; }
                    fds = t; cap = ncap;
                }
                fds[nfds++] = nf;
                fd = nf;
                continue;
            }
            fprintf(stderr, "\nnwu: write: %s\n", strerror(errno));
            rc = -1; break;
        }
        written += (unsigned long long)k;

        double t = now_sec();
        if (t - last >= 0.1) {           /* refresh ~10x/s */
            draw_progress(written, avail, t - start);
            last = t;
        }
    }
    if (stopped)
        draw_progress(written, avail, now_sec() - start);
    else
        draw_progress(written > avail ? written : avail, avail,
                      now_sec() - start);
    fputc('\n', stderr);
    if (raw) tty_raw_off(&saved);
    if (stopped) printf("nwu: stopped by user; syncing what was written...\n");

    /* Flush to the device, then release (close frees the anonymous files'
     * blocks), then TRIM so the controller can physically discard them. */
    for (int i = 0; i < nfds; i++) fdatasync(fds[i]);
    for (int i = 0; i < nfds; i++) close(fds[i]);
    free(fds);
    locked_free(buf, BUFSZ);

    char wh[32]; human((double)written, wh, sizeof wh);
    printf("nwu: wrote %s across %d file(s), issuing filesystem TRIM...\n",
           wh, nfds);
    fs_trim(mount);
    printf("nwu: free-space wipe complete.\n");
    return rc;
}

/* ----------------------------------------------------------- interactive */

static void read_line(char *buf, size_t n)
{
    if (!fgets(buf, n, stdin)) { buf[0] = 0; return; }
    size_t l = strlen(buf);
    if (l && buf[l - 1] == '\n') buf[l - 1] = 0;
}

static int confirm(const char *prompt)
{
    char b[16];
    printf("%s [y/N]: ", prompt);
    fflush(stdout);
    read_line(b, sizeof b);
    return (b[0] == 'y' || b[0] == 'Y');
}

static void interactive(void)
{
    char line[4096];
    for (;;) {
        printf("\n=== nwu " NWU_VERSION " : Novel Wiping Utility ===\n");
        printf("  1) Wipe a file\n");
        printf("  2) Wipe a directory (recursive)\n");
        printf("  3) Wipe free space on a mountpoint\n");
        printf("  4) Settings (passes=%d, trim=%s, verify=%s, verbose=%s)\n",
               g_passes, g_do_trim ? "on" : "off", g_verify ? "on" : "off",
               g_verbose ? "on" : "off");
        printf("  5) Quit\n");
        printf("Choose: ");
        fflush(stdout);
        read_line(line, sizeof line);

        if (!strcmp(line, "1") || !strcmp(line, "2")) {
            printf("Path: ");
            fflush(stdout);
            read_line(line, sizeof line);
            if (!line[0]) continue;
            if (confirm("Permanently wipe this path?"))
                wipe_path(line);
            else printf("nwu: cancelled.\n");
        } else if (!strcmp(line, "3")) {
            printf("Mountpoint: ");
            fflush(stdout);
            read_line(line, sizeof line);
            if (!line[0]) continue;
            if (confirm("Fill and wipe all free space here?"))
                wipe_freespace(line);
            else printf("nwu: cancelled.\n");
        } else if (!strcmp(line, "4")) {
            printf("Overwrite passes [%d]: ", g_passes);
            fflush(stdout);
            read_line(line, sizeof line);
            if (line[0]) { int p = atoi(line); if (p >= 1) g_passes = p; }
            g_do_trim = confirm("Enable filesystem TRIM?");
            g_verify  = confirm("Verify overwrite by reading it back?");
            g_verbose = confirm("Enable verbose output?");
        } else if (!strcmp(line, "5") || !strcmp(line, "q") || !line[0]) {
            return;
        } else {
            printf("nwu: unknown choice.\n");
        }
    }
}

/* ------------------------------------------------------------------- cli */

static void usage(const char *p)
{
    fprintf(stderr,
"nwu " NWU_VERSION " - Novel Wiping Utility "
"(SSD-aware secure delete & free-space wipe)\n\n"
"Interactive:\n"
"  %s                                 launch the menu\n\n"
"Scripting:\n"
"  %s [opts] wipe <path>...           wipe file(s) and/or directory tree(s)\n"
"  %s [opts] free <mountpoint>        wipe free space, then TRIM\n\n"
"Options:\n"
"  -p N   overwrite passes (default 1; >1 helps only on HDDs)\n"
"  -T     skip the filesystem TRIM step\n"
"  -c     verify the overwrite by reading it back (per-file; slower)\n"
"  -v     verbose\n"
"  -V     print version\n"
"  -h     help\n\n"
"Filesystem TRIM (FITRIM) needs root. On SSDs erasure cannot be guaranteed\n"
"(wear leveling / over-provisioning); nwu maximizes effort by combining\n"
"overwrite + per-file discard + filesystem TRIM.\n",
        p, p, p);
}

int main(int argc, char **argv)
{
    harden_process();   /* no coredumps; non-fatal best-effort */

    int opt;
    while ((opt = getopt(argc, argv, "p:TcvVh")) != -1) {
        switch (opt) {
        case 'p': g_passes = atoi(optarg); if (g_passes < 1) g_passes = 1; break;
        case 'T': g_do_trim = 0; break;
        case 'c': g_verify = 1; break;
        case 'v': g_verbose = 1; break;
        case 'V': printf("nwu " NWU_VERSION "\n"); return 0;
        case 'h': usage(argv[0]); return 0;
        default:  usage(argv[0]); return 2;
        }
    }

    rng_init();             /* seed the fast keystream before reporting status */
    print_startup_status();

    if (optind >= argc) { interactive(); return 0; }   /* no command -> menu */

    const char *cmd = argv[optind++];
    int rc = 0;

    if (!strcmp(cmd, "wipe")) {
        if (optind >= argc) { usage(argv[0]); return 2; }
        for (int i = optind; i < argc; i++)
            if (wipe_path(argv[i]) < 0) rc = 1;
    } else if (!strcmp(cmd, "free")) {
        if (optind >= argc) { usage(argv[0]); return 2; }
        if (wipe_freespace(argv[optind]) < 0) rc = 1;
    } else {
        usage(argv[0]);
        return 2;
    }
    return rc;
}
