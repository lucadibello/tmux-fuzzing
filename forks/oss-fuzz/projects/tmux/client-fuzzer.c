#include <stddef.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <sanitizer/lsan_interface.h>
#include "tmux.h"

/* Max data length */
#define FUZZER_MAXLEN 1024

/* Min data length */
#define FUZZER_MAXARGS 64

struct event_base *libevent;
struct cmd_parse_result *pr;

void free_pr_contents(struct cmd_parse_result *pr){
  if (pr == NULL)
    return;
	
  switch(pr->status) {
    case CMD_PARSE_ERROR:
      if (pr->error) {
        free(pr->error);
      }
      break;
    case CMD_PARSE_SUCCESS:
      if (pr->cmdlist) {
        cmd_list_free(pr->cmdlist);
      }
      break;
  }
}

#include <stdbool.h>

bool is_keyboard_visible(const char *s, size_t len) {
    if (s == NULL) return false;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = s[i];
        if (c < 33 || c > 126)
            return false;
    }
    return true;
}

/* Fuzzer entry point */
int LLVMFuzzerTestOneInput(const u_char *data, size_t size) {
  if (size > FUZZER_MAXLEN || size < 1)
      return 0;
  
	/* Parse a full command string */
  //if (!is_keyboard_visible((const char *)data, size))
  //  return 0;

  static char buf[FUZZER_MAXLEN];
  size_t len = size < FUZZER_MAXLEN - 1 ? size : FUZZER_MAXLEN - 1;
  memcpy(buf, data, len);
  buf[len] = '\0';

  // TO DO: Create argc and argv from the data.
  int    argc = 0;
  char * argv[FUZZER_MAXARGS + 1];  // +1 for a terminating NULL if needed
  char * p = buf;
  while (argc < FUZZER_MAXARGS) {
      /* strsep will return the next token, or NULL when done */
      char *tok = strsep(&p, " \t\r\n");
      if (tok == NULL)
          break;
      if (*tok == '\0')
          continue;         /* skip empty tokens (multiple spaces) */
      argv[argc++] = tok;
  }
  argv[argc] = NULL;             /* optional, in case downstream expects a NULL */

  if (argc == 0)
    return 0;

  /* 
  if (argc == 0) {
    // point argv[0] at an empty string in buf
    buf[0] = '\0';
    argv[argc++] = buf;
  }
  */

  struct args_value	*values = args_from_vector(argc, argv);
  pr = cmd_parse_from_arguments(values, argc, NULL);
  if (pr->status == CMD_PARSE_SUCCESS) {
    cmd_list_free(pr->cmdlist);
  } else
  free(pr->error);
  args_free_values(values, argc);
  free(values);

  // for `args_make_commands_now`
  // get struct cmd from cmd_parse

  // How to redo:
	//pr = cmd_parse_from_string(buf, NULL);

  //free(new_cmd);


  /*if (pr->status == CMD_PARSE_SUCCESS) {
    cmdq_append(NULL, cmdq_get_command(pr->cmdlist, NULL));
  } else {
  }*/

  // Also test the other functions
  // cmd_parse_from_arguments
  // To do that:
  // values = args_from_vector(argc, argv);
	// pr = cmd_parse_from_arguments(values, argc, NULL);


  // cmd_parse_and_insert
  // cmd_parse_and_append
    
  //free_pr_contents(pr);

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

    input_key_build();

    //key_bindings_init();
    
    //socket_path = xstrdup("dummy");
    
    /* Initialize libevent for asynchronous I/O handling. */
    //libevent = osdep_event_init();
    
    return 0;
}