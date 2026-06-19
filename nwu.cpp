/*
 * nwu - Novel Wiping Utility (command-line front-end)
 *
 * Thin CLI wrapper around the shared wiping engine in nwu_core.cpp. The GTK4
 * GUI (nwu-gui.cpp) links the same engine, so both tools behave identically.
 *
 * Runs as an interactive menu (no args) or from the command line (scripting).
 * Build: make.  Linux only (fallocate punch-hole, getrandom, FITRIM).
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <getopt.h>

#include "nwu_core.h"

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
        printf("  4) Wipe a whole block device (e.g. /dev/sdX)\n");
        printf("  5) Wipe RAM (scrub free memory, then release)\n");
        printf("  6) Settings (passes=%d, trim=%s, verify=%s, verbose=%s)\n",
               g_passes, g_do_trim ? "on" : "off", g_verify ? "on" : "off",
               g_verbose ? "on" : "off");
        printf("  7) Quit\n");
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
            printf("Block device (e.g. /dev/sdb): ");
            fflush(stdout);
            read_line(line, sizeof line);
            if (!line[0]) continue;
            g_secure_erase = 0;
            if (confirm("Also issue the drive's FIRMWARE secure erase afterward?"))
                g_secure_erase = confirm("Use cryptographic erase (else user-data)?")
                                 ? 2 : 1;
            wipe_device(line);          /* asks its own typed confirmation */
            g_secure_erase = 0;
        } else if (!strcmp(line, "5")) {
            wipe_ram(NWU_RAM_SAFETY_MB);
            printf("\nPress Enter to release the scrubbed RAM... ");
            fflush(stdout);
            read_line(line, sizeof line);
            release_ram();
        } else if (!strcmp(line, "6")) {
            printf("Overwrite passes [%d]: ", g_passes);
            fflush(stdout);
            read_line(line, sizeof line);
            if (line[0]) { int p = atoi(line); if (p >= 1) g_passes = p; }
            g_do_trim = confirm("Enable filesystem TRIM / device discard?");
            g_verify  = confirm("Verify overwrite by reading it back?");
            g_verbose = confirm("Enable verbose output?");
        } else if (!strcmp(line, "7") || !strcmp(line, "q") || !line[0]) {
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
"  %s [opts] wipe   <path>...         wipe file(s) and/or directory tree(s)\n"
"  %s [opts] free   <mountpoint>      wipe free space, then TRIM\n"
"  %s [opts] device <blockdev>        wipe a WHOLE device + BLKDISCARD (root)\n"
"  %s        ram                      scrub free RAM, then release on Enter\n\n"
"There is also a GTK4 GUI: run 'nwu-gui' (or launch it from your desktop menu).\n\n"
"Options:\n"
"  -p N   overwrite passes (default 1; >1 helps only on HDDs)\n"
"  -T     skip the TRIM / device-discard step\n"
"  -c     verify the overwrite by reading it back (slower)\n"
"  -y     skip the typed confirmation for 'device' (DANGEROUS)\n"
"  --secure-erase   after a device wipe, issue the drive's firmware secure\n"
"                   erase (native NVMe Format / ATA via hdparm)\n"
"  --crypto-erase   like --secure-erase but request cryptographic erase\n"
"  -v     verbose\n"
"  -V     print version\n"
"  -h     help\n\n"
"Filesystem TRIM (FITRIM) and device wipes need root. On SSDs erasure cannot be\n"
"guaranteed in software (wear leveling / over-provisioning); nwu maximizes effort\n"
"by combining a non-compressible overwrite (O_DIRECT for big targets) with\n"
"discard, and points you at the firmware secure erase for a hard guarantee.\n",
        p, p, p, p, p);
}

int main(int argc, char **argv)
{
    harden_process();   /* no coredumps; non-fatal best-effort */

    static const struct option longopts[] = {
        { "secure-erase", no_argument, 0, 1000 },
        { "crypto-erase", no_argument, 0, 1001 },
        { 0, 0, 0, 0 }
    };
    int opt;
    while ((opt = getopt_long(argc, argv, "p:TcyvVh", longopts, NULL)) != -1) {
        switch (opt) {
        case 'p': g_passes = atoi(optarg); if (g_passes < 1) g_passes = 1; break;
        case 'T': g_do_trim = 0; break;
        case 'c': g_verify = 1; break;
        case 'y': g_assume_yes = 1; break;
        case 'v': g_verbose = 1; break;
        case 1000: g_secure_erase = 1; break;       /* --secure-erase */
        case 1001: g_secure_erase = 2; break;       /* --crypto-erase */
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
    } else if (!strcmp(cmd, "device") || !strcmp(cmd, "dev")) {
        if (optind >= argc) { usage(argv[0]); return 2; }
        for (int i = optind; i < argc; i++)
            if (wipe_device(argv[i]) < 0) rc = 1;
    } else if (!strcmp(cmd, "ram")) {
        wipe_ram(NWU_RAM_SAFETY_MB);
        char line[16];
        printf("\nPress Enter to release the scrubbed RAM... ");
        fflush(stdout);
        read_line(line, sizeof line);
        release_ram();
    } else {
        usage(argv[0]);
        return 2;
    }
    return rc;
}
