/*
 * nwu-gui - GTK4 front-end for the Novel Wiping Utility.
 *
 * Same engine as the command-line tool (nwu_core.cpp), wrapped in a desktop
 * GUI. Each wipe runs on a worker thread; the engine's stdout/stderr are piped
 * back into a log view so the operator sees exactly what the core does
 * (including the progress bar). All destructive actions require an explicit
 * confirmation dialog first.
 *
 * Build: make  (pkg-config gtk4).  Linux only.
 */

#include <gtk/gtk.h>

#include <atomic>
#include <thread>

#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <climits>
#include <fcntl.h>
#include <unistd.h>

#include "nwu_core.h"

/* GApplication ID: must be a valid reverse-DNS name (needs at least one dot),
 * so it stays fully qualified. It also becomes the X11 WM_CLASS / Wayland
 * app_id, which is why nwu.desktop's StartupWMClass keeps this value. */
#define APP_ID "io.github.effjy.nwu"
/* Icon theme name: matches the installed file (nwu.svg) and desktop Icon=nwu. */
#define ICON_NAME "nwu"

/* Home directory of the human who launched the GUI. When we relaunch under
 * pkexec the process becomes root (HOME=/root), but the operator wants to
 * browse their own files - so the unprivileged instance forwards its HOME and
 * the file choosers open there instead of /root. */
static char g_user_home[PATH_MAX] = "";

/* ---- widgets we need to reach from callbacks ---------------------------- */
typedef struct {
    GtkWindow     *win;
    GtkStack      *stack;

    GtkEntry      *path_entry;     /* file / directory */
    GtkEntry      *mount_entry;    /* free space */
    GtkEntry      *device_entry;   /* block device */
    GtkCheckButton *dev_secure;    /* issue firmware secure erase */
    GtkCheckButton *dev_crypto;    /* cryptographic erase */

    GtkSpinButton *passes;
    GtkCheckButton *trim;
    GtkCheckButton *verify;
    GtkCheckButton *verbose;

    GtkTextView   *log;
    GtkWidget     *run_buttons[8]; /* disabled while a job runs */
    int            n_run_buttons;
    GtkWidget     *stop_button;    /* enabled only while a job runs */
} App;

/* ---- a running job ------------------------------------------------------ */
typedef struct {
    App  *app;
    int   kind;            /* 0 wipe path, 1 free, 2 device */
    char *target;          /* heap string, freed when the job ends */
    int   secure_erase;    /* 0/1/2, only for device */
    /* options snapshot */
    int   passes, trim, verify, verbose, assume_yes;
    int   pipe_rd;         /* read end of the engine's stdout/stderr pipe */
    int   saved_out, saved_err;
    std::thread worker;
    std::atomic<bool> done;
} Job;

/* ---- log helpers (main thread only) ------------------------------------- */
static void log_append(App *app, const char *text)
{
    GtkTextBuffer *buf = gtk_text_view_get_buffer(app->log);
    /* The engine's progress bar repaints with '\r' (carriage return = back to
     * column 0, overwrite the line). If we mapped '\r' to '\n' the view would
     * scroll a fresh line every ~100 ms - hundreds of near-identical lines that
     * are painful to watch. Instead we honour terminal semantics: '\r' deletes
     * the current (last) line so the next text overwrites it in place, giving a
     * single progress line that updates live. '\n' still starts a new line.
     * Process in runs so we never split a multibyte UTF-8 sequence. */
    char *copy = g_utf8_validate(text, -1, NULL)
               ? g_strdup(text) : g_utf8_make_valid(text, -1);
    const char *p = copy;
    while (*p) {
        const char *start = p;
        while (*p && *p != '\r' && *p != '\n') p++;
        if (p > start) {
            GtkTextIter end;
            gtk_text_buffer_get_end_iter(buf, &end);
            gtk_text_buffer_insert(buf, &end, start, (int)(p - start));
        }
        if (*p == '\n') {
            GtkTextIter end;
            gtk_text_buffer_get_end_iter(buf, &end);
            gtk_text_buffer_insert(buf, &end, "\n", 1);
            p++;
        } else if (*p == '\r') {
            /* drop everything since the start of the current line */
            GtkTextIter end, ls;
            gtk_text_buffer_get_end_iter(buf, &end);
            ls = end;
            gtk_text_iter_set_line_offset(&ls, 0);
            gtk_text_buffer_delete(buf, &ls, &end);
            p++;
        }
    }
    g_free(copy);
    GtkTextMark *mark = gtk_text_buffer_get_insert(buf);
    gtk_text_view_scroll_mark_onscreen(app->log, mark);
}

static void set_buttons_sensitive(App *app, gboolean s)
{
    for (int i = 0; i < app->n_run_buttons; i++)
        gtk_widget_set_sensitive(app->run_buttons[i], s);
    /* Stop is the inverse: usable only while a job is running. */
    if (app->stop_button) gtk_widget_set_sensitive(app->stop_button, !s);
}

/* Ask the running engine to stop. It breaks out of its fill loop, then still
 * syncs, closes (frees) the fill files and TRIMs - so no giant file is left. */
static void on_stop(GtkButton *, gpointer data)
{
    App *app = (App *)data;
    g_stop = 1;
    gtk_widget_set_sensitive(app->stop_button, FALSE);
    log_append(app, "\nnwu-gui: stop requested - finishing the current block, "
                    "then syncing and releasing the fill file(s)...\n");
}

/* ---- pipe pump: drain engine output into the log view ------------------- */
static gboolean pump_pipe(gpointer data)
{
    Job *job = (Job *)data;
    char buf[4096];
    for (;;) {
        ssize_t r = read(job->pipe_rd, buf, sizeof buf - 1);
        if (r > 0) { buf[r] = 0; log_append(job->app, buf); continue; }
        break;   /* EAGAIN (non-blocking, nothing now) or EOF */
    }

    if (!job->done.load())
        return G_SOURCE_CONTINUE;   /* worker still running, keep draining */

    /* worker finished: drain whatever is left, then tear down */
    ssize_t r;
    while ((r = read(job->pipe_rd, buf, sizeof buf - 1)) > 0) {
        buf[r] = 0; log_append(job->app, buf);
    }
    if (job->worker.joinable()) job->worker.join();

    /* restore the real stdout/stderr the GUI inherited */
    dup2(job->saved_out, STDOUT_FILENO);
    dup2(job->saved_err, STDERR_FILENO);
    close(job->saved_out);
    close(job->saved_err);
    close(job->pipe_rd);

    log_append(job->app, "\n--- done ---\n\n");
    set_buttons_sensitive(job->app, TRUE);
    g_free(job->target);
    delete job;
    return G_SOURCE_REMOVE;
}

/* ---- start a job: redirect fds, snapshot options, spawn worker ---------- */
static void start_job(App *app, int kind, const char *target, int secure_erase)
{
    Job *job = new Job();
    job->app = app;
    job->kind = kind;
    job->target = g_strdup(target);
    job->secure_erase = secure_erase;
    job->passes = gtk_spin_button_get_value_as_int(app->passes);
    job->trim   = gtk_check_button_get_active(app->trim);
    job->verify = gtk_check_button_get_active(app->verify);
    job->verbose= gtk_check_button_get_active(app->verbose);
    job->assume_yes = 1;   /* GUI already confirmed via dialog */
    job->done.store(false);

    int fds[2];
    if (pipe(fds) != 0) {
        log_append(app, "nwu-gui: pipe() failed\n");
        g_free(job->target); delete job; return;
    }
    fcntl(fds[0], F_SETFL, O_NONBLOCK);   /* reader never blocks the UI */

    /* redirect the process stdout/stderr into the pipe for the engine's run */
    job->saved_out = dup(STDOUT_FILENO);
    job->saved_err = dup(STDERR_FILENO);
    dup2(fds[1], STDOUT_FILENO);
    dup2(fds[1], STDERR_FILENO);
    close(fds[1]);
    job->pipe_rd = fds[0];

    g_stop = 0;   /* clear any leftover request from a previous run */
    set_buttons_sensitive(app, FALSE);
    gtk_text_buffer_set_text(gtk_text_view_get_buffer(app->log), "", -1);

    job->worker = std::thread([job]() {
        /* apply this job's options to the shared engine globals */
        g_passes = job->passes < 1 ? 1 : job->passes;
        g_do_trim = job->trim;
        g_verify = job->verify;
        g_verbose = job->verbose;
        g_assume_yes = job->assume_yes;
        g_secure_erase = job->secure_erase;

        switch (job->kind) {
        case 0: wipe_path(job->target); break;
        case 1: wipe_freespace(job->target); break;
        case 2: wipe_device(job->target); break;
        case 3: wipe_ram(NWU_RAM_SAFETY_MB); break;
        }
        fflush(stdout); fflush(stderr);
        job->done.store(true);
    });

    g_timeout_add(80, pump_pipe, job);   /* ~12 Hz UI refresh */
}

/* ---- confirmation dialog, then start ------------------------------------ */
typedef struct { App *app; int kind; char *target; int secure_erase; } Pending;

static void on_confirm_response(GObject *src, GAsyncResult *res, gpointer data)
{
    Pending *p = (Pending *)data;
    int choice = gtk_alert_dialog_choose_finish(GTK_ALERT_DIALOG(src), res, NULL);
    if (choice == 1)   /* index 1 == "Wipe" */
        start_job(p->app, p->kind, p->target, p->secure_erase);
    g_free(p->target);
    g_free(p);
}

static void confirm_then_run(App *app, int kind, const char *target,
                             int secure_erase, const char *what)
{
    GtkAlertDialog *dlg = gtk_alert_dialog_new("Permanently wipe %s?", target);
    char *detail = g_strdup_printf("%s\n\nThis cannot be undone.", what);
    gtk_alert_dialog_set_detail(dlg, detail);
    g_free(detail);
    const char *buttons[] = { "Cancel", "Wipe", NULL };
    gtk_alert_dialog_set_buttons(dlg, buttons);
    gtk_alert_dialog_set_cancel_button(dlg, 0);
    gtk_alert_dialog_set_default_button(dlg, 0);   /* Cancel is the safe default */
    gtk_alert_dialog_set_modal(dlg, TRUE);

    Pending *p = g_new0(Pending, 1);
    p->app = app; p->kind = kind;
    p->target = g_strdup(target); p->secure_erase = secure_erase;
    gtk_alert_dialog_choose(dlg, app->win, NULL, on_confirm_response, p);
    g_object_unref(dlg);
}

/* ---- button handlers ---------------------------------------------------- */
static const char *entry_text(GtkEntry *e)
{
    return gtk_editable_get_text(GTK_EDITABLE(e));
}

static void on_wipe_path(GtkButton *, gpointer data)
{
    App *app = (App *)data;
    const char *t = entry_text(app->path_entry);
    if (!t || !*t) return;
    confirm_then_run(app, 0, t, 0,
                     "The file or directory tree will be overwritten, "
                     "discarded (TRIM), and removed.");
}

static void on_wipe_free(GtkButton *, gpointer data)
{
    App *app = (App *)data;
    const char *t = entry_text(app->mount_entry);
    if (!t || !*t) return;
    confirm_then_run(app, 1, t, 0,
                     "All free space on this mountpoint will be filled, "
                     "synced, released and TRIMmed.");
}

static void on_wipe_device(GtkButton *, gpointer data)
{
    App *app = (App *)data;
    const char *t = entry_text(app->device_entry);
    if (!t || !*t) return;
    int se = 0;
    if (gtk_check_button_get_active(app->dev_secure))
        se = gtk_check_button_get_active(app->dev_crypto) ? 2 : 1;
    confirm_then_run(app, 2, t, se,
                     "THE ENTIRE BLOCK DEVICE will be overwritten and "
                     "discarded. Every partition and filesystem on it is lost.");
}

/* ---- RAM scrub: start fills+pins free memory, release gives it back ----- */
static void on_wipe_ram(GtkButton *, gpointer data)
{
    App *app = (App *)data;
    /* Not destructive to user data (it scrubs free memory), so no confirm. */
    start_job(app, 3, "", 0);
}

static void on_release_ram(GtkButton *, gpointer data)
{
    App *app = (App *)data;
    if (!ram_is_held()) {
        log_append(app, "nwu-gui: no scrubbed RAM is currently held.\n");
        return;
    }
    log_append(app, "nwu-gui: releasing scrubbed RAM...\n");
    release_ram();   /* zero, unpin, free */
    log_append(app, "nwu-gui: RAM released.\n");
}

/* ---- file/folder chooser for the path entry ----------------------------- */
static void on_chosen(GObject *src, GAsyncResult *res, gpointer data)
{
    GtkEntry *entry = (GtkEntry *)data;
    GFile *f = gtk_file_dialog_open_finish(GTK_FILE_DIALOG(src), res, NULL);
    if (f) {
        char *path = g_file_get_path(f);
        if (path) { gtk_editable_set_text(GTK_EDITABLE(entry), path); g_free(path); }
        g_object_unref(f);
    }
}

static void on_chosen_folder(GObject *src, GAsyncResult *res, gpointer data)
{
    GtkEntry *entry = (GtkEntry *)data;
    GFile *f = gtk_file_dialog_select_folder_finish(GTK_FILE_DIALOG(src), res, NULL);
    if (f) {
        char *path = g_file_get_path(f);
        if (path) { gtk_editable_set_text(GTK_EDITABLE(entry), path); g_free(path); }
        g_object_unref(f);
    }
}

/* Open file choosers in the launching user's home, not root's /root. */
static void set_initial_home(GtkFileDialog *d)
{
    if (!*g_user_home) return;
    GFile *f = g_file_new_for_path(g_user_home);
    gtk_file_dialog_set_initial_folder(d, f);
    g_object_unref(f);
}

static void on_browse_file(GtkButton *, gpointer data)
{
    App *app = (App *)data;
    GtkFileDialog *d = gtk_file_dialog_new();
    set_initial_home(d);
    gtk_file_dialog_open(d, app->win, NULL, on_chosen, app->path_entry);
    g_object_unref(d);
}

static void on_browse_folder(GtkButton *, gpointer data)
{
    App *app = (App *)data;
    GtkFileDialog *d = gtk_file_dialog_new();
    set_initial_home(d);
    gtk_file_dialog_select_folder(d, app->win, NULL, on_chosen_folder, app->mount_entry);
    g_object_unref(d);
}

/* ---- run-as-root via pkexec --------------------------------------------- *
 *
 * pkexec wipes the environment, so a naively elevated GUI has no DISPLAY /
 * XAUTHORITY / WAYLAND_DISPLAY / XDG_RUNTIME_DIR and cannot open the display
 * (the "I typed the root password and nothing appeared" bug). pkexec *does*
 * preserve argv, so we forward those values as command-line flags and the
 * elevated instance re-applies them with setenv() before GTK initialises.
 * root can read the user's X cookie and runtime dir, so the window then shows.
 */

/* Re-apply a display environment forwarded by a prior pkexec relaunch. Must run
 * before any GTK/GDK call. Returns TRUE if this is the elevated instance. */
static gboolean apply_forwarded_env(int argc, char **argv)
{
    gboolean as_root = FALSE;
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        const char *v = (i + 1 < argc) ? argv[i + 1] : "";
        if      (!strcmp(a, "--as-root"))     { as_root = TRUE; }
        else if (!strcmp(a, "--display"))     { if (*v) setenv("DISPLAY", v, 1);         i++; }
        else if (!strcmp(a, "--xauthority"))  { if (*v) setenv("XAUTHORITY", v, 1);      i++; }
        else if (!strcmp(a, "--wayland"))     { if (*v) setenv("WAYLAND_DISPLAY", v, 1); i++; }
        else if (!strcmp(a, "--runtime-dir")) { if (*v) setenv("XDG_RUNTIME_DIR", v, 1); i++; }
        else if (!strcmp(a, "--user-home"))   { if (*v) snprintf(g_user_home, sizeof g_user_home, "%s", v); i++; }
    }
    /* When an X display is reachable, force the X11 backend for the root
     * instance: root can always read the forwarded X cookie, whereas some
     * Wayland compositors reject a connection from a different uid. */
    if (as_root && getenv("DISPLAY"))
        setenv("GDK_BACKEND", "x11", 1);
    return as_root;
}

/* pkexec exited: if it (and the root GUI it launched) finished cleanly we quit
 * the unprivileged instance too; otherwise the auth was cancelled/failed, so we
 * bring our own window back. */
static void on_root_child_exit(GPid pid, int status, gpointer data)
{
    App *app = (App *)data;
    g_spawn_close_pid(pid);
    if (g_spawn_check_wait_status(status, NULL)) {
        g_application_quit(G_APPLICATION(gtk_window_get_application(app->win)));
    } else {
        gtk_widget_set_visible(GTK_WIDGET(app->win), TRUE);
        log_append(app, "nwu-gui: root authentication was cancelled or failed.\n");
    }
}

static void on_run_as_root(GtkButton *, gpointer data)
{
    App *app = (App *)data;

    char self[PATH_MAX];
    ssize_t n = readlink("/proc/self/exe", self, sizeof self - 1);
    if (n <= 0) { log_append(app, "nwu-gui: cannot resolve own path.\n"); return; }
    self[n] = 0;

    /* gather the display environment to forward (with sensible fallbacks) */
    const char *disp  = getenv("DISPLAY");        if (!disp)  disp = "";
    const char *wl    = getenv("WAYLAND_DISPLAY"); if (!wl)   wl = "";
    const char *rt    = getenv("XDG_RUNTIME_DIR"); if (!rt)   rt = "";
    const char *xauth = getenv("XAUTHORITY");
    char xfallback[PATH_MAX] = "";
    if (!xauth || !*xauth) {
        const char *home = getenv("HOME");
        if (home) { snprintf(xfallback, sizeof xfallback, "%s/.Xauthority", home); }
        xauth = xfallback;     /* root can read it even when XAUTHORITY is unset */
    }

    const char *home = getenv("HOME");  if (!home) home = "";

    char *child_argv[] = {
        (char *)"pkexec", self, (char *)"--as-root",
        (char *)"--display",     (char *)disp,
        (char *)"--xauthority",  (char *)xauth,
        (char *)"--wayland",     (char *)wl,
        (char *)"--runtime-dir", (char *)rt,
        (char *)"--user-home",   (char *)home,
        NULL
    };

    GError *err = NULL;
    GPid pid = 0;
    if (!g_spawn_async(NULL, child_argv, NULL,
                       (GSpawnFlags)(G_SPAWN_DO_NOT_REAP_CHILD | G_SPAWN_SEARCH_PATH),
                       NULL, NULL, &pid, &err)) {
        char *m = g_strdup_printf("nwu-gui: could not launch pkexec: %s\n",
                                  err ? err->message : "unknown error");
        log_append(app, m);
        g_free(m);
        if (err) g_error_free(err);
        return;
    }
    /* hide our unprivileged window while the elevated copy is up */
    gtk_widget_set_visible(GTK_WIDGET(app->win), FALSE);
    g_child_watch_add(pid, on_root_child_exit, app);
}

/* ---- about dialog ------------------------------------------------------- */
static void on_about(GtkButton *, gpointer data)
{
    App *app = (App *)data;
    GtkWidget *about = gtk_about_dialog_new();
    GtkAboutDialog *a = GTK_ABOUT_DIALOG(about);
    gtk_about_dialog_set_program_name(a, "nwu — Novel Wiping Utility");
    gtk_about_dialog_set_version(a, NWU_VERSION);
    gtk_about_dialog_set_comments(a,
        "Secure, SSD-aware file, free-space and whole-device wiping: a "
        "non-compressible random overwrite combined with controller-level "
        "discard (TRIM/BLKDISCARD) and optional firmware secure erase.");
    gtk_about_dialog_set_license_type(a, GTK_LICENSE_MIT_X11);
    gtk_about_dialog_set_website(a, "https://github.com/effjy/nwu");
    gtk_about_dialog_set_website_label(a, "Project page");
    gtk_about_dialog_set_logo_icon_name(a, ICON_NAME);
    gtk_window_set_transient_for(GTK_WINDOW(about), app->win);
    gtk_window_set_modal(GTK_WINDOW(about), TRUE);
    gtk_window_present(GTK_WINDOW(about));
}

/* ---- small UI builders -------------------------------------------------- */
static GtkWidget *labeled_row(const char *label, GtkWidget *child)
{
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *l = gtk_label_new(label);
    gtk_widget_set_size_request(l, 90, -1);
    gtk_label_set_xalign(GTK_LABEL(l), 0.0);
    gtk_box_append(GTK_BOX(box), l);
    gtk_widget_set_hexpand(child, TRUE);
    gtk_box_append(GTK_BOX(box), child);
    return box;
}

static void track_button(App *app, GtkWidget *b)
{
    if (app->n_run_buttons < (int)(sizeof app->run_buttons / sizeof app->run_buttons[0]))
        app->run_buttons[app->n_run_buttons++] = b;
}

static void activate(GtkApplication *gapp, gpointer)
{
    App *app = g_new0(App, 1);

    GtkWidget *win = gtk_application_window_new(gapp);
    app->win = GTK_WINDOW(win);
    gtk_window_set_title(app->win, "nwu " NWU_VERSION " — Novel Wiping Utility");
    gtk_window_set_default_size(app->win, 720, 560);
    gtk_window_set_icon_name(app->win, ICON_NAME);   /* taskbar icon */

    GtkWidget *root = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_window_set_child(app->win, root);

    /* --- privilege banner: run-as-root button, or "running as root" --- */
    {
        GtkWidget *bar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
        gtk_widget_set_margin_start(bar, 12); gtk_widget_set_margin_end(bar, 12);
        gtk_widget_set_margin_top(bar, 8);
        if (geteuid() == 0) {
            GtkWidget *l = gtk_label_new("● Running as root — FITRIM, free-space "
                                         "reserved blocks and device wipes enabled.");
            gtk_label_set_xalign(GTK_LABEL(l), 0.0);
            gtk_widget_add_css_class(l, "success");
            gtk_widget_set_hexpand(l, TRUE);
            gtk_box_append(GTK_BOX(bar), l);
        } else {
            GtkWidget *l = gtk_label_new("Unprivileged — device wipes and FITRIM "
                                         "need root.");
            gtk_label_set_xalign(GTK_LABEL(l), 0.0);
            gtk_widget_set_hexpand(l, TRUE);
            gtk_box_append(GTK_BOX(bar), l);
            GtkWidget *b = gtk_button_new_with_label("Relaunch as root…");
            gtk_widget_add_css_class(b, "suggested-action");
            g_signal_connect(b, "clicked", G_CALLBACK(on_run_as_root), app);
            gtk_box_append(GTK_BOX(bar), b);
        }
        GtkWidget *about = gtk_button_new_with_label("About");
        g_signal_connect(about, "clicked", G_CALLBACK(on_about), app);
        gtk_box_append(GTK_BOX(bar), about);
        gtk_box_append(GTK_BOX(root), bar);
    }

    /* --- tab switcher + stack --- */
    GtkWidget *stack = gtk_stack_new();
    app->stack = GTK_STACK(stack);
    GtkWidget *switcher = gtk_stack_switcher_new();
    gtk_stack_switcher_set_stack(GTK_STACK_SWITCHER(switcher), GTK_STACK(stack));
    gtk_widget_set_halign(switcher, GTK_ALIGN_CENTER);
    gtk_widget_set_margin_top(switcher, 8);
    gtk_widget_set_margin_bottom(switcher, 8);
    gtk_box_append(GTK_BOX(root), switcher);

    /* page 1: file / directory --------------------------------------- */
    {
        GtkWidget *page = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
        gtk_widget_set_margin_start(page, 16); gtk_widget_set_margin_end(page, 16);
        gtk_widget_set_margin_top(page, 8); gtk_widget_set_margin_bottom(page, 8);

        GtkWidget *e = gtk_entry_new();
        app->path_entry = GTK_ENTRY(e);
        gtk_entry_set_placeholder_text(app->path_entry, "/path/to/file-or-directory");
        gtk_box_append(GTK_BOX(page), labeled_row("Path", e));

        GtkWidget *brow = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
        GtkWidget *bf = gtk_button_new_with_label("Browse file…");
        g_signal_connect(bf, "clicked", G_CALLBACK(on_browse_file), app);
        gtk_box_append(GTK_BOX(brow), bf);
        gtk_box_append(GTK_BOX(page), brow);

        GtkWidget *go = gtk_button_new_with_label("Wipe file / directory");
        gtk_widget_add_css_class(go, "destructive-action");
        g_signal_connect(go, "clicked", G_CALLBACK(on_wipe_path), app);
        track_button(app, go);
        gtk_box_append(GTK_BOX(page), go);

        gtk_stack_add_titled(GTK_STACK(stack), page, "file", "File / Folder");
    }

    /* page 2: free space --------------------------------------------- */
    {
        GtkWidget *page = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
        gtk_widget_set_margin_start(page, 16); gtk_widget_set_margin_end(page, 16);
        gtk_widget_set_margin_top(page, 8); gtk_widget_set_margin_bottom(page, 8);

        GtkWidget *e = gtk_entry_new();
        app->mount_entry = GTK_ENTRY(e);
        gtk_entry_set_placeholder_text(app->mount_entry, "/mountpoint (e.g. /media/usb)");
        gtk_box_append(GTK_BOX(page), labeled_row("Mountpoint", e));

        GtkWidget *bb = gtk_button_new_with_label("Browse folder…");
        g_signal_connect(bb, "clicked", G_CALLBACK(on_browse_folder), app);
        GtkWidget *brow = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
        gtk_box_append(GTK_BOX(brow), bb);
        gtk_box_append(GTK_BOX(page), brow);

        GtkWidget *go = gtk_button_new_with_label("Wipe free space");
        gtk_widget_add_css_class(go, "destructive-action");
        g_signal_connect(go, "clicked", G_CALLBACK(on_wipe_free), app);
        track_button(app, go);
        gtk_box_append(GTK_BOX(page), go);

        gtk_stack_add_titled(GTK_STACK(stack), page, "free", "Free space");
    }

    /* page 3: device ------------------------------------------------- */
    {
        GtkWidget *page = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
        gtk_widget_set_margin_start(page, 16); gtk_widget_set_margin_end(page, 16);
        gtk_widget_set_margin_top(page, 8); gtk_widget_set_margin_bottom(page, 8);

        GtkWidget *warn = gtk_label_new(
            "⚠ Erases an ENTIRE block device. Needs root. Unmount it first.");
        gtk_label_set_xalign(GTK_LABEL(warn), 0.0);
        gtk_widget_add_css_class(warn, "error");
        gtk_box_append(GTK_BOX(page), warn);

        GtkWidget *e = gtk_entry_new();
        app->device_entry = GTK_ENTRY(e);
        gtk_entry_set_placeholder_text(app->device_entry, "/dev/sdX");
        gtk_box_append(GTK_BOX(page), labeled_row("Device", e));

        GtkWidget *cs = gtk_check_button_new_with_label(
            "Also issue the drive's firmware secure erase afterward");
        app->dev_secure = GTK_CHECK_BUTTON(cs);
        gtk_box_append(GTK_BOX(page), cs);
        GtkWidget *cc = gtk_check_button_new_with_label(
            "Use cryptographic erase (else user-data erase)");
        app->dev_crypto = GTK_CHECK_BUTTON(cc);
        gtk_box_append(GTK_BOX(page), cc);

        GtkWidget *go = gtk_button_new_with_label("Wipe whole device");
        gtk_widget_add_css_class(go, "destructive-action");
        g_signal_connect(go, "clicked", G_CALLBACK(on_wipe_device), app);
        track_button(app, go);
        gtk_box_append(GTK_BOX(page), go);

        gtk_stack_add_titled(GTK_STACK(stack), page, "device", "Device");
    }

    /* page 4: RAM ---------------------------------------------------- */
    {
        GtkWidget *page = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
        gtk_widget_set_margin_start(page, 16); gtk_widget_set_margin_end(page, 16);
        gtk_widget_set_margin_top(page, 8); gtk_widget_set_margin_bottom(page, 8);

        GtkWidget *info = gtk_label_new(
            "Overwrites free RAM with entropy to scrub data left in "
            "previously-used memory pages.\nThe memory is pinned (mlock) and "
            "kept allocated until you press Release. A safety\nmargin of free "
            "RAM is always left so the system stays responsive.");
        gtk_label_set_xalign(GTK_LABEL(info), 0.0);
        gtk_label_set_wrap(GTK_LABEL(info), TRUE);
        gtk_box_append(GTK_BOX(page), info);

        GtkWidget *brow = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
        GtkWidget *start = gtk_button_new_with_label("Start RAM wipe");
        gtk_widget_add_css_class(start, "suggested-action");
        g_signal_connect(start, "clicked", G_CALLBACK(on_wipe_ram), app);
        track_button(app, start);   /* disabled while a job runs */
        gtk_box_append(GTK_BOX(brow), start);

        GtkWidget *rel = gtk_button_new_with_label("Release RAM");
        g_signal_connect(rel, "clicked", G_CALLBACK(on_release_ram), app);
        track_button(app, rel);   /* disabled while a job runs: releasing during
                                   * the fill would race the worker's block list */
        gtk_box_append(GTK_BOX(brow), rel);
        gtk_box_append(GTK_BOX(page), brow);

        gtk_stack_add_titled(GTK_STACK(stack), page, "ram", "RAM");
    }

    gtk_box_append(GTK_BOX(root), stack);

    /* --- shared options row --- */
    {
        GtkWidget *opts = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 14);
        gtk_widget_set_margin_start(opts, 16); gtk_widget_set_margin_end(opts, 16);
        gtk_widget_set_margin_top(opts, 6); gtk_widget_set_margin_bottom(opts, 6);

        gtk_box_append(GTK_BOX(opts), gtk_label_new("Passes"));
        GtkWidget *sp = gtk_spin_button_new_with_range(1, 35, 1);
        app->passes = GTK_SPIN_BUTTON(sp);
        gtk_box_append(GTK_BOX(opts), sp);

        GtkWidget *t = gtk_check_button_new_with_label("TRIM/discard");
        app->trim = GTK_CHECK_BUTTON(t);
        gtk_check_button_set_active(app->trim, TRUE);
        gtk_box_append(GTK_BOX(opts), t);

        GtkWidget *v = gtk_check_button_new_with_label("Verify (read-back)");
        app->verify = GTK_CHECK_BUTTON(v);
        gtk_box_append(GTK_BOX(opts), v);

        GtkWidget *vb = gtk_check_button_new_with_label("Verbose");
        app->verbose = GTK_CHECK_BUTTON(vb);
        gtk_check_button_set_active(app->verbose, TRUE);
        gtk_box_append(GTK_BOX(opts), vb);

        /* Stop button: pushed to the right, disabled until a job is running. */
        GtkWidget *stop = gtk_button_new_with_label("Stop");
        gtk_widget_add_css_class(stop, "destructive-action");
        gtk_widget_set_halign(stop, GTK_ALIGN_END);
        gtk_widget_set_hexpand(stop, TRUE);
        gtk_widget_set_sensitive(stop, FALSE);
        app->stop_button = stop;
        g_signal_connect(stop, "clicked", G_CALLBACK(on_stop), app);
        gtk_box_append(GTK_BOX(opts), stop);

        gtk_box_append(GTK_BOX(root), gtk_separator_new(GTK_ORIENTATION_HORIZONTAL));
        gtk_box_append(GTK_BOX(root), opts);
    }

    /* --- log view --- */
    {
        GtkWidget *scroll = gtk_scrolled_window_new();
        gtk_widget_set_vexpand(scroll, TRUE);
        GtkWidget *tv = gtk_text_view_new();
        app->log = GTK_TEXT_VIEW(tv);
        gtk_text_view_set_editable(app->log, FALSE);
        gtk_text_view_set_monospace(app->log, TRUE);
        gtk_text_view_set_cursor_visible(app->log, FALSE);
        gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll), tv);
        gtk_box_append(GTK_BOX(root), scroll);
    }

    if (geteuid() != 0)
        log_append(app, "nwu-gui: not running as root — click \"Relaunch as "
                        "root…\" for FITRIM, device wipes and reserved-block "
                        "free-space.\n\n");

    gtk_window_present(app->win);
}

/* Silence one specific, purely-cosmetic GTK rendering warning ("Trying to
 * snapshot GtkGizmo ... without a current allocation") that some GTK/theme
 * combinations emit during the first frame. It is harmless (a draw-timing
 * glitch on an internal widget, nothing to do with our data), but it looks
 * unprofessional on the console. Every other log message is passed straight
 * through to GLib's default writer, so genuine warnings are never hidden. */
static GLogWriterOutput log_filter(GLogLevelFlags level,
                                   const GLogField *fields, gsize n_fields,
                                   gpointer user_data)
{
    for (gsize i = 0; i < n_fields; i++) {
        if (!strcmp(fields[i].key, "MESSAGE") && fields[i].value &&
            strstr((const char *)fields[i].value, "without a current allocation"))
            return G_LOG_WRITER_HANDLED;   /* drop it */
    }
    return g_log_writer_default(level, fields, n_fields, user_data);
}

int main(int argc, char **argv)
{
    g_log_set_writer_func(log_filter, NULL, NULL);

    /* Re-apply any display env forwarded by a pkexec relaunch BEFORE GTK opens
     * the display — this is what stops the "elevated window never appears" bug. */
    apply_forwarded_env(argc, argv);

    /* Not relaunched (or no home forwarded): fall back to this process's HOME. */
    if (!*g_user_home) {
        const char *home = getenv("HOME");
        if (home) snprintf(g_user_home, sizeof g_user_home, "%s", home);
    }

    harden_process();
    rng_init();

    /* NON_UNIQUE: the elevated (root) instance must not try to hand off to the
     * unprivileged one over the session bus (different uid / no bus). */
    GtkApplication *app = gtk_application_new(APP_ID, G_APPLICATION_NON_UNIQUE);
    g_signal_connect(app, "activate", G_CALLBACK(activate), NULL);
    /* our own --as-root/--display flags are consumed above; don't pass them to
     * GApplication (it would reject the unknown options). */
    char *only[] = { argv[0], NULL };
    int status = g_application_run(G_APPLICATION(app), 1, only);
    g_object_unref(app);
    return status;
}
