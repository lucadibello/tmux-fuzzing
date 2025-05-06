#define _GNU_SOURCE

#include <assert.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>

#include "tmux.h"

#define MAX_FUZZ_LEN 512

struct event_base *libevent;

/* Dummy state to prevent "no current target" */
static void
create_dummy_tmux_state(void)
{
	struct session		*s;
	struct window		*w;
	struct window_pane	*wp;
	struct environ		*env;
	struct options		*opts;
	struct termios		term;
	const struct options_table_entry *oe;

	memset(&term, 0, sizeof term);

	w = window_create(80, 25, 0, 0);
	assert(w != NULL);

	wp = window_add_pane(w, NULL, 0, 0);
	assert(wp != NULL);

	wp->fd = open("/dev/null", O_WRONLY);
	assert(wp->fd >= 0);

	wp->event = bufferevent_new(wp->fd, NULL, NULL, NULL, NULL);
	wp->ictx = input_init(wp, NULL, NULL);

	env = environ_create();
	opts = options_create(NULL);

	/* This is critical: populate opts with default session options */
	for (oe = options_table; oe->name != NULL; oe++) {
		if (oe->scope & OPTIONS_TABLE_SESSION)
			options_default(opts, oe);
	}

	fprintf(stderr, "before session_create\n");
	s = session_create("fuzz", "/tmp", "xterm-256color", env, opts, &term);
	fprintf(stderr, "after session_create\n");

	assert(s != NULL);
	session_select(s, 0);
}

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
	const struct options_table_entry *oe;
    fprintf(stderr, "init start\n");

	libevent = osdep_event_init();

	global_environ   = environ_create();
	global_options   = options_create(NULL);
	global_s_options = options_create(NULL);
	global_w_options = options_create(NULL);

	for (oe = options_table; oe->name != NULL; oe++) {
		if (oe->scope & OPTIONS_TABLE_SERVER)
			options_default(global_options, oe);
		if (oe->scope & OPTIONS_TABLE_SESSION)
			options_default(global_s_options, oe);
		if (oe->scope & OPTIONS_TABLE_WINDOW)
			options_default(global_w_options, oe);
	}

	setenv("TERM", "xterm", 1);
	options_set_number(global_w_options, "monitor-bell", 0);
	options_set_number(global_options,   "set-clipboard", 0);
	socket_path = xstrdup("dummy");

	create_dummy_tmux_state();
    fprintf(stderr, "init complete\n");
	return 0;
}

static int
fuzz_tmux_entry(int argc, char **argv, struct event_base *base)
{
	const struct options_table_entry *oe;
	const char *s, *cwd;
	uint64_t flags = CLIENT_STARTSERVER;
	int feat = 0;

	// Create global options
	if (global_environ == NULL)
		global_environ = environ_create();
	if (global_options == NULL)
		global_options = options_create(NULL);
	if (global_s_options == NULL)
		global_s_options = options_create(NULL);
	if (global_w_options == NULL)
		global_w_options = options_create(NULL);

	for (oe = options_table; oe->name != NULL; oe++) {
		if (oe->scope & OPTIONS_TABLE_SERVER)
			options_default(global_options, oe);
		if (oe->scope & OPTIONS_TABLE_SESSION)
			options_default(global_s_options, oe);
		if (oe->scope & OPTIONS_TABLE_WINDOW)
			options_default(global_w_options, oe);
	}

	// Set some env vars for the client
	setenv("TERM", "xterm", 1);

	// Set default socket path
	if (!socket_path)
		socket_path = xstrdup("dummy");

	// Set session/workspace-specific config
	if ((cwd = find_cwd()) != NULL)
		environ_set(global_environ, "PWD", 0, "%s", cwd);

	options_set_number(global_options, "set-clipboard", 0);
	options_set_number(global_w_options, "monitor-bell", 0);

	// Default shell setup (simplified)
	options_set_string(global_s_options, "default-shell", 0, "%s", _PATH_BSHELL);

	// Actually invoke tmux client logic
	return client_main(base, argc, argv, flags, feat);
}

static void
cleanup_fuzz_iteration(void)
{
    /* Free global options */
    if (global_options != NULL) {
        options_free(global_options);
        global_options = NULL;
    }
    if (global_s_options != NULL) {
        options_free(global_s_options);
        global_s_options = NULL;
    }
    if (global_w_options != NULL) {
        options_free(global_w_options);
        global_w_options = NULL;
    }

    /* Free global environment */
    if (global_environ != NULL) {
        environ_free(global_environ);
        global_environ = NULL;
    }

    /* Free socket path */
    if (socket_path != NULL) {
        free(socket_path);
        socket_path = NULL;
    }
}


int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0 || size > MAX_FUZZ_LEN)
        return 0;

    // Save original fds
    /*int saved_stdout = dup(STDOUT_FILENO);
    int saved_stderr = dup(STDERR_FILENO);

    // Redirect stdout/stderr to /dev/null
    int devnull = open("/dev/null", O_WRONLY);
    if (devnull != -1) {
        dup2(devnull, STDOUT_FILENO);
        dup2(devnull, STDERR_FILENO);
        close(devnull);
    }*/

    // Fuzz target
    char *buf = malloc(size + 1);
    /*if (!buf)
        goto restore;*/
    memcpy(buf, data, size);
    buf[size] = '\0';

    char *argv[] = { buf, NULL };
    
    int status = 0;
    if ((status = LLVMFuzzerRunDriver(1, argv)) != 0) {
        free(buf);
        return status;
    }
    
    //int rc = client_main(libevent, 1, argv, CLIENT_STARTSERVER, 0);

    #define _GNU_SOURCE

    #include <assert.h>
    #include <stddef.h>
    #include <stdlib.h>
    #include <string.h>
    #include <unistd.h>
    #include <fcntl.h>
    #include <sys/wait.h>
    
    #include "tmux.h"
    
    #define MAX_FUZZ_LEN 512
    
    struct event_base *libevent;
    
    /* Dummy state to prevent "no current target" */
    static void
    create_dummy_tmux_state(void)
    {
        struct session		*s;
        struct window		*w;
        struct window_pane	*wp;
        struct environ		*env;
        struct options		*opts;
        struct termios		term;
        const struct options_table_entry *oe;
    
        memset(&term, 0, sizeof term);
    
        w = window_create(80, 25, 0, 0);
        assert(w != NULL);
    
        wp = window_add_pane(w, NULL, 0, 0);
        assert(wp != NULL);
    
        wp->fd = open("/dev/null", O_WRONLY);
        assert(wp->fd >= 0);
    
        wp->event = bufferevent_new(wp->fd, NULL, NULL, NULL, NULL);
        wp->ictx = input_init(wp, NULL, NULL);
    
        env = environ_create();
        opts = options_create(NULL);
    
        /* This is critical: populate opts with default session options */
        for (oe = options_table; oe->name != NULL; oe++) {
            if (oe->scope & OPTIONS_TABLE_SESSION)
                options_default(opts, oe);
        }
    
        fprintf(stderr, "before session_create\n");
        s = session_create("fuzz", "/tmp", "xterm-256color", env, opts, &term);
        fprintf(stderr, "after session_create\n");
    
        assert(s != NULL);
        session_select(s, 0);
    }
    
    int
    LLVMFuzzerInitialize(int *argc, char ***argv)
    {
        const struct options_table_entry *oe;
        fprintf(stderr, "init start\n");
    
        libevent = osdep_event_init();
    
        global_environ   = environ_create();
        global_options   = options_create(NULL);
        global_s_options = options_create(NULL);
        global_w_options = options_create(NULL);
    
        for (oe = options_table; oe->name != NULL; oe++) {
            if (oe->scope & OPTIONS_TABLE_SERVER)
                options_default(global_options, oe);
            if (oe->scope & OPTIONS_TABLE_SESSION)
                options_default(global_s_options, oe);
            if (oe->scope & OPTIONS_TABLE_WINDOW)
                options_default(global_w_options, oe);
        }
    
        setenv("TERM", "xterm", 1);
        options_set_number(global_w_options, "monitor-bell", 0);
        options_set_number(global_options,   "set-clipboard", 0);
        socket_path = xstrdup("dummy");
    
        create_dummy_tmux_state();
        fprintf(stderr, "init complete\n");
        return 0;
    }
    
    static int
    fuzz_tmux_entry(int argc, char **argv, struct event_base *base)
    {
        const struct options_table_entry *oe;
        const char *s, *cwd;
        uint64_t flags = CLIENT_STARTSERVER;
        int feat = 0;
    
        // Create global options
        if (global_environ == NULL)
            global_environ = environ_create();
        if (global_options == NULL)
            global_options = options_create(NULL);
        if (global_s_options == NULL)
            global_s_options = options_create(NULL);
        if (global_w_options == NULL)
            global_w_options = options_create(NULL);
    
        for (oe = options_table; oe->name != NULL; oe++) {
            if (oe->scope & OPTIONS_TABLE_SERVER)
                options_default(global_options, oe);
            if (oe->scope & OPTIONS_TABLE_SESSION)
                options_default(global_s_options, oe);
            if (oe->scope & OPTIONS_TABLE_WINDOW)
                options_default(global_w_options, oe);
        }
    
        // Set some env vars for the client
        setenv("TERM", "xterm", 1);
    
        // Set default socket path
        if (!socket_path)
            socket_path = xstrdup("dummy");
    
        // Set session/workspace-specific config
        if ((cwd = find_cwd()) != NULL)
            environ_set(global_environ, "PWD", 0, "%s", cwd);
    
        options_set_number(global_options, "set-clipboard", 0);
        options_set_number(global_w_options, "monitor-bell", 0);
    
        // Default shell setup (simplified)
        options_set_string(global_s_options, "default-shell", 0, "%s", _PATH_BSHELL);
    
        // Actually invoke tmux client logic
        return client_main(base, argc, argv, flags, feat);
    }
    
    static void
    cleanup_fuzz_iteration(void)
    {
        /* Free global options */
        if (global_options != NULL) {
            options_free(global_options);
            global_options = NULL;
        }
        if (global_s_options != NULL) {
            options_free(global_s_options);
            global_s_options = NULL;
        }
        if (global_w_options != NULL) {
            options_free(global_w_options);
            global_w_options = NULL;
        }
    
        /* Free global environment */
        if (global_environ != NULL) {
            environ_free(global_environ);
            global_environ = NULL;
        }
    
        /* Free socket path */
        if (socket_path != NULL) {
            free(socket_path);
            socket_path = NULL;
        }
    }
    
    
    int
    LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
    {
        if (size == 0 || size > MAX_FUZZ_LEN)
            return 0;
    
        // Save original fds
        /*int saved_stdout = dup(STDOUT_FILENO);
        int saved_stderr = dup(STDERR_FILENO);
    
        // Redirect stdout/stderr to /dev/null
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull != -1) {
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }*/
    
        // Fuzz target
        char *buf = malloc(size + 1);
        /*if (!buf)
            goto restore;*/
        memcpy(buf, data, size);
        buf[size] = '\0';
    
        char *argv[] = { buf, NULL };
        
        int status = 0;
        if ((status = LLVMFuzzerRunDriver(1, argv)) != 0) {
            free(buf);
            return status;
        }
        
        //int rc = client_main(libevent, 1, argv, CLIENT_STARTSERVER, 0);
    
        pid_t pid = fork();
        if (pid == 0) { // Child
            __sanitizer_cov_reset_edgeguards();
            client_main(libevent, 1, argv, CLIENT_STARTSERVER, 0);
            _exit(0);
        } else if (pid > 0) { // Parent
            waitpid(pid, &status, 0);
            __sanitizer_cov_dump();
        }    
        
        //(void)rc;
    
        free(buf);
    
    /*restore:
        // Restore original stdout/stderr
        if (saved_stdout != -1) {
            dup2(saved_stdout, STDOUT_FILENO);
            close(saved_stdout);
        }
        if (saved_stderr != -1) {
            dup2(saved_stderr, STDERR_FILENO);
            close(saved_stderr);
        }*/
    
        return 0;
    }
    


    
    //(void)rc;

    free(buf);

/*restore:
    // Restore original stdout/stderr
    if (saved_stdout != -1) {
        dup2(saved_stdout, STDOUT_FILENO);
        close(saved_stdout);
    }
    if (saved_stderr != -1) {
        dup2(saved_stderr, STDERR_FILENO);
        close(saved_stderr);
    }*/

    return 0;
}
