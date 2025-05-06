/*
 * Copyright (c) 2024 OpenAI
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF MIND, USE, DATA OR PROFITS, WHETHER
 * IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

 #include <stddef.h>
 #include <assert.h>
 #include <string.h>
 #include <stdlib.h>
 #include <ctype.h>
 #include "tmux.h"
 
 #define FUZZER_MAXLEN 1024
 
 /* Global event base used by tmux */
 struct event_base *libevent;
 
 int LLVMFuzzerTestOneInput(const u_char *data, size_t size) {
     u_char *sanitized_data;
     size_t sanitized_size = 0;
     size_t i;
     
     /* Limit input size to avoid timeouts */
     if (size > FUZZER_MAXLEN)
         return 0;
     
     /* Allocate worst-case buffer (same size as original input) */
     sanitized_data = malloc(size);
     if (sanitized_data == NULL)
         return 0;
     
     /* Filter the input so that only printable characters are kept.
        This includes characters in the ASCII range 0x20 to 0x7E. */
     for (i = 0; i < size; i++) {
         if (isprint(data[i]))
             sanitized_data[sanitized_size++] = data[i];
     }
     
     /* If nothing printable remains, exit early */
     if (sanitized_size == 0) {
         free(sanitized_data);
         return 0;
     }
     
     /* Process the sanitized input in place of the raw fuzz data.
        Split the input into null-terminated arguments.
        We assume that tokens are separated by '\0'.
        If no '\0' is found, the rest of the data is treated as one token. */
     TAILQ_HEAD(, args_value) args_head;
     TAILQ_INIT(&args_head);
     
     const u_char *p = sanitized_data;
     const u_char *end;
     u_int count = 0;
     size_t len;
     size_t remaining = sanitized_size;
     
     while (remaining > 0) {
         end = memchr(p, '\0', remaining);
         if (end != NULL) {
             len = end - p;
             remaining -= len + 1;
         } else {
             len = remaining;
             remaining = 0;
         }
         
         /* Create a temporary null-terminated string from the token */
         char *arg_str = malloc(len + 1);
         if (arg_str == NULL)
             break;
         memcpy(arg_str, p, len);
         arg_str[len] = '\0';
         
         /* Validate that the string is valid UTF-8.
            If not, drop this token. */
         if (!utf8_isvalid(arg_str)) {
             free(arg_str);
             p = end != NULL ? end + 1 : p + len;
             continue;
         }
         
         /* Create an args_value entry and insert it into the list */
         struct args_value *av = malloc(sizeof(*av));
         if (av == NULL) {
             free(arg_str);
             break;
         }
         av->type = ARGS_STRING;
         av->string = arg_str;
         TAILQ_INSERT_TAIL(&args_head, av, entry);
         count++;
         
         p = end != NULL ? end + 1 : p + len;
     }
     
     /* Call the command parser with the generated arguments */
     char *error = NULL;
     struct cmd *cmd = cmd_parse(TAILQ_FIRST(&args_head), count, "fuzz", 0, &error);
     if (cmd != NULL)
         cmd_free(cmd);
     free(error);
     
     /* Clean up the argument list */
     struct args_value *av;
     while (!TAILQ_EMPTY(&args_head)) {
         av = TAILQ_FIRST(&args_head);
         TAILQ_REMOVE(&args_head, av, entry);
         free(av->string);
         free(av);
     }
     
     free(sanitized_data);
     return 0;
 }
 
 int LLVMFuzzerInitialize(int *argc, char ***argv) {
     const struct options_table_entry *oe;
     
     /* Initialize tmux environment globals */
     global_environ = environ_create();
     global_options = options_create(NULL);
     global_s_options = options_create(NULL);
     global_w_options = options_create(NULL);
     
     /* Set default options */
     for (oe = options_table; oe->name != NULL; oe++) {
         if (oe->scope & OPTIONS_TABLE_SERVER)
             options_default(global_options, oe);
         if (oe->scope & OPTIONS_TABLE_SESSION)
             options_default(global_s_options, oe);
         if (oe->scope & OPTIONS_TABLE_WINDOW)
             options_default(global_w_options, oe);
     }
     
     /* Set critical options */
     options_set_number(global_options, "set-clipboard", 2);
     socket_path = xstrdup("dummy");
     
     /* Initialize libevent */
     libevent = osdep_event_init();
     
     return 0;
 }
 