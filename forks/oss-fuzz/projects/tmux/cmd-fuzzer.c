#include <stddef.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include "tmux.h"

/* Max data length */
#define FUZZER_MAXLEN 1024

/* Min data length */
#define FUZZER_MINLEN 32

struct event_base *libevent;

/* Fuzzer entry point */
int LLVMFuzzerTestOneInput(const u_char *data, size_t size) {
    if (size > FUZZER_MAXLEN)
        return 0;
	/* Parse a full command string */
    char cmd[FUZZER_MAXLEN];
    size_t len = size < FUZZER_MAXLEN ? size : FUZZER_MAXLEN - 1;
    memcpy(cmd, data, len);
    cmd[len] = '\0';

	struct cmd_parse_result *pr = cmd_parse_from_string(cmd, NULL);
    
    if (pr == NULL)
			return 0;
	
		switch (pr->status) {
		case CMD_PARSE_SUCCESS:
			if (pr->cmdlist) {
				char *printed = (pr->cmdlist, 0);
				free(printed);
				cmd_list_free(pr->cmdlist);
			}
			break;
	
		case CMD_PARSE_ERROR:
			free(pr->error);
			break;
		}
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
