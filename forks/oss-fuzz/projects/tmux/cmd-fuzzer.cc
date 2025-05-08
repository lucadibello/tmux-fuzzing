#include <stddef.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>


#pragma once

#pragma push_macro("template")

#define template tmux_template

extern "C" {
#  include "tmux.h"
}

#pragma pop_macro("template")
	
#include <fuzzer/FuzzedDataProvider.h>

#define FUZZER_MAXLEN 1024

struct event_base *libevent;

static void FreeArgv(int argc, char **argv)
{
    for (int i = 0; i < argc; ++i) free(argv[i]);
    free(argv);
}

extern "C" int LLVMFuzzerTestOneInput(const u_char *data, size_t size) {
	FuzzedDataProvider provider(data, size);

	/* Parse a full command string */
    if (provider.ConsumeBool()) {
        std::string cmd = provider.ConsumeRemainingBytesAsString();

        struct cmd_parse_input pi{};
        struct cmd_parse_result *pr = cmd_parse_from_string(cmd.c_str(), &pi);

		if (pr == NULL)
			return 0;
	
		switch (pr->status) {
		case CMD_PARSE_SUCCESS:

			if (pr->cmdlist) {
				char *printed = cmd_list_print(pr->cmdlist, 0);
				free(printed);
				cmd_list_free(pr->cmdlist);
			}
			//free(pr); Causes free problems...
			break;
	
		case CMD_PARSE_ERROR:
			free(pr->error);
			break;
		}
		
		// How to call them from cmd-parse.y????
		//cmd_parse_free_commands();
		//cmd_parse_free_lexer();

		return 0;
	}

	/* Exercise low-level args helpers */
	
	const uint8_t argc_u8 = provider.ConsumeIntegralInRange<uint8_t>(0, 20);
	const int user_argc   = static_cast<int>(argc_u8);
	const int real_argc   = (user_argc == 0) ? 1 : user_argc;


    /* build argv */
	std::vector<std::string> arg_vec;
	arg_vec.reserve(real_argc);
	for (int i = 0; i < user_argc; ++i)
	    arg_vec.emplace_back(provider.ConsumeRandomLengthString(32));
	if (user_argc == 0) arg_vec.emplace_back("");


	char **argv = static_cast<char **>(calloc(real_argc, sizeof(char *)));
	for (int i = 0; i < real_argc; ++i) {
			argv[i] = static_cast<char *>(malloc(arg_vec[i].size() + 1));
        memcpy(argv[i], arg_vec[i].c_str(), arg_vec[i].size() + 1);
    }

	struct args_value *vals = args_from_vector(real_argc, argv);
	
	struct args_parse ap = {
		"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
		-1,
		-1,
		nullptr
	};
	
	char *cause = NULL;
	struct args *a = args_parse(&ap, vals, real_argc, &cause);

    if (a) {
        char *printed = args_print(a);
        free(printed);

        int out_argc = 0;
        char **out_argv = nullptr;
        args_to_vector(a, &out_argc, &out_argv);
        cmd_free_argv(out_argc, out_argv);

        args_free(a);
    }

	if (cause != NULL) free(cause);
	args_free_values(vals, real_argc);
	free(vals);
	FreeArgv(real_argc, argv);
	return 0;
}

extern "C" int LLVMFuzzerInitialize(__unused int *argc, __unused char ***argv)
{
	const struct options_table_entry	*oe;

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
	libevent = osdep_event_init();

    key_bindings_init();

    alerts_reset_all();

    //proc_start_server()
    setenv("LC_ALL", "C", 1);

	options_set_number(global_w_options, "monitor-bell", 0);
	options_set_number(global_w_options, "allow-rename", 1);
	options_set_number(global_options, "set-clipboard", 2);
	socket_path = xstrdup("dummy");

	return 0;
}