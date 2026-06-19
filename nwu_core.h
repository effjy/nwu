/*
 * nwu_core - shared wiping engine for the nwu CLI and the nwu-gui front-end.
 *
 * All the actual work (overwrite, punch-hole, FITRIM/BLKDISCARD, secure erase,
 * free-space fill) lives here so the command-line tool and the GTK4 GUI share
 * one implementation. Both link against nwu_core.cpp.
 */
#ifndef NWU_CORE_H
#define NWU_CORE_H

#include <cstddef>

#define NWU_VERSION "1.4.0"

#ifdef __cplusplus
extern "C" {
#endif

/* Run-time options, shared by both front-ends. Defaults match the CLI. */
extern int g_passes;       /* overwrite passes (>=1) */
extern int g_verbose;      /* verbose logging to stderr */
extern int g_do_trim;      /* issue FITRIM / BLKDISCARD */
extern int g_verify;       /* read-back verification after overwrite */
extern int g_assume_yes;   /* skip the typed device-wipe confirmation */
extern int g_secure_erase; /* 0 none, 1 user-data erase, 2 crypto erase */

/* Cooperative stop flag. A front-end sets it (e.g. a GUI "Stop" button) to ask
 * an in-progress free-space or device wipe to finish gracefully: the loop
 * breaks, then still syncs, releases the fill files (freeing their blocks) and
 * issues TRIM - so stopping never leaves a giant fill file behind. Reset to 0
 * at the start of each wipe. */
extern volatile int g_stop;

/* One-time setup: process hardening (no coredumps) + seed the fast RNG. */
void harden_process(void);
int  rng_init(void);
void print_startup_status(void);

/* Public operations. Each returns 0 on success, non-zero on error. */
int wipe_path(const char *path);        /* file OR directory tree */
int wipe_freespace(const char *mount);  /* fill + TRIM free space */
int wipe_device(const char *dev);       /* whole block device (root) */

/* Read one line from stdin (newline stripped). Used for confirmations. */
void read_line(char *buf, size_t n);

#ifdef __cplusplus
}
#endif

#endif /* NWU_CORE_H */
