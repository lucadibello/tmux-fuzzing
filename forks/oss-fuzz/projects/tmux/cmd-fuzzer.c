#include <stddef.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include "tmux.h"

/* Max data length */
#define FUZZER_MAXLEN 1024

struct event_base *libevent;

/* Fuzzer entry point */
int LLVMFuzzerTestOneInput(const u_char *data, size_t size) {
    u_char *sanitized_data;
    size_t sanitized_size = 0;
    size_t i;
    
    /* Limit fuzzing `data` size*/
    if (size > FUZZER_MAXLEN)
        return 0;
    
    /* Allocate buffer for sanitized data. */
    sanitized_data = malloc(size);
    if (sanitized_data == NULL)
        return 0;
    
    /* As non-printable characters must not be used in tmux, they should be
     filtered out to create a valid argument string. */
    for (i = 0; i < size; i++) {
        if (isprint(data[i]))
            sanitized_data[sanitized_size++] = data[i];
    }
    if (sanitized_size == 0) {
        free(sanitized_data);
        return 0;
    }
    
    /* Initialize a tail queue to hold parsed command arguments. */
    TAILQ_HEAD(, args_value) args_head;
    TAILQ_INIT(&args_head);
    
    const u_char *p = sanitized_data;
    const u_char *end;
    u_int c = 0;
    size_t len;
    size_t remaining = sanitized_size;
    
    /* Split sanitized data into null-terminated arguments. */
    while (remaining > 0) {
        end = memchr(p, '\0', remaining);
        if (end != NULL) {
            len = end - p;
            remaining -= len + 1;
        } else {
            len = remaining;
            remaining = 0;
        }
        
        /* Copy the current argument. */
        char *arg_str = malloc(len + 1);
        if (arg_str == NULL)
            break;
        memcpy(arg_str, p, len);
        arg_str[len] = '\0';
        
        /* Check if the argument is valid UTF-8, skip it otherwise to avoid tmux parsing errors */
        if (!utf8_isvalid(arg_str)) {
            free(arg_str);
            p = end != NULL ? end + 1 : p + len;
            continue;
        }
        
        struct args_value *av = malloc(sizeof(*av));
        if (av == NULL) {
            free(arg_str);
            break;
        }
        av->type = ARGS_STRING;
        av->string = arg_str;
        TAILQ_INSERT_TAIL(&args_head, av, entry);
        c++;
        
        p = end != NULL ? end + 1 : p + len;
    }
    
    /* Replace the first argument with a valid tmux command name to ensure meaningful tests. */
    struct args_value *first_av = TAILQ_FIRST(&args_head);
    if (c > 0 && sanitized_size > 1) {
        const char *cmd_names[] = {
            "attach-session -Ad -t %1",   // Test flags with targets
            "bind-key -T root C-f",       // Test key tables
            "new-window -n '${=}'",       // Test format expansions
            "resize-pane -x 10 -y 5",     // Test numeric arguments
            "invalid-command"             // Test error handling
        };
                size_t n = sizeof(cmd_names) / sizeof(cmd_names[0]);
        size_t override_idx = sanitized_data[0] % n;
        
        free(first_av->string);
        first_av->string = xstrdup(cmd_names[override_idx]);
    }
    
    /* Parse the command for validity and structure. */
    char *error = NULL;
    struct cmd *cmd = cmd_parse(first_av, c, "fuzz", 0, &error);
    if (cmd == NULL) {
        free(error);
    }
    
    /* Command lookup by name functionality. */
    {
        char *cause = NULL;
        const struct cmd_entry *entry = cmd_find(first_av->string, &cause);
        if (entry == NULL)
            free(cause);
    }
    
    /* If parsing succeded, continue by parsing other command operations. */
    if (cmd != NULL) {
        char *printed = cmd_print(cmd);
        free(printed);
        
        /* Command copying with dummy arguments. */
        char *dummy_argv[] = { "fuzz", "arg1", "arg2" };
        struct cmd *cmd_copy_result = cmd_copy(cmd, 3, dummy_argv);
        cmd_free(cmd_copy_result);
        
        char *templated = cmd_template_replace("%1", "replacement", 1);
        free(templated);
    }
    
    /* Clean up all allocated argument structures. */
    struct args_value *av;
    while (!TAILQ_EMPTY(&args_head)) {
        av = TAILQ_FIRST(&args_head);
        TAILQ_REMOVE(&args_head, av, entry);
        free(av->string);
        free(av);
    }
    free(sanitized_data);
    
    if (cmd != NULL)
        cmd_free(cmd);
    
    return 0;
}

/* Initialize global state. */
int LLVMFuzzerInitialize(int *argc, char ***argv) {
    const struct options_table_entry *oe;
    
    global_environ = environ_create();
    global_options = options_create(NULL);
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
    
    options_set_number(global_options, "set-clipboard", 2);
    socket_path = xstrdup("dummy");
    
    /* Initialize libevent for asynchronous I/O handling. */
    libevent = osdep_event_init();
    
    return 0;
}
