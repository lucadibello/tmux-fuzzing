// fuzz/fuzz_client.cc
#include <cstdint>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <locale.h>
#include <setjmp.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstdint>
#include <cstddef>
#include <string>
#include <fuzzer/FuzzedDataProvider.h>
#include <iostream>
#include <sanitizer/lsan_interface.h>

#pragma push_macro("template")
#define template tmux_template
extern "C" {
#  include "tmux.h"
#  include <event2/event.h>
}
#pragma pop_macro("template")

static struct event_base *libevent;

void global_init(){
  const struct options_table_entry	*oe;

  if (!global_environ)
    global_environ = environ_create();
  if (!global_options)
    global_options = options_create(NULL);
  if (!global_s_options)
    global_s_options = options_create(NULL);
  if (!global_w_options)
    global_w_options = options_create(NULL);
  if (!libevent)
    libevent = osdep_event_init();
  
  for (oe = options_table; oe->name != NULL; oe++) {
    if (oe->scope & OPTIONS_TABLE_SERVER)
      options_default(global_options, oe);
    if (oe->scope & OPTIONS_TABLE_SESSION)
      options_default(global_s_options, oe);
    if (oe->scope & OPTIONS_TABLE_WINDOW)
      options_default(global_w_options, oe);
  }

  if (!socket_path)
    socket_path = xstrdup("/tmp/tmux-1000/default");

}

int LLVMFuzzerInitialize(__unused int *argc, __unused char ***argv)
{
  socket_path = xstrdup("/tmp/tmux-1000/default");
  options_set_number(global_w_options, "monitor-bell", 0);
  options_set_number(global_w_options, "allow-rename", 1);
  options_set_number(global_options, "set-clipboard", 2);

  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1) {
    return 0;
  }

  global_init();

  // Use FuzzedDataProvider to consume the input data
  FuzzedDataProvider fdp(data, size);

  // Extract a random number of arguments between 1 and 5
  int argc = fdp.ConsumeIntegralInRange<int>(1, 5);

  // Store arguments
  std::vector<std::string> args;
  std::vector<char*> argv;

  args.reserve(argc);

  //argv.push_back("-c");
  
  for (int i = 0; i < argc; ++i) {
    // Each argument is a string of up to 100 bytes
    std::string arg;
    do {
      arg = fdp.ConsumeRandomLengthString(100);
      
      // Remove any null bytes
      arg.erase(std::remove(arg.begin(), arg.end(), '\0'), arg.end());
      
      // Only allow alphanumeric and some special characters
      std::replace_if(arg.begin(), arg.end(),
        [](char c) { return !isalnum(c) && strchr("!@#$%^&*()-_=+[]{}|;:'\",.<>?/", c) == nullptr; }, '_');
      
      // Asvoid empty strings
      if (arg.empty()) arg = "a";
      
    } while (arg.empty()); // Ensure we have valid content

    args.push_back(arg);
    argv.push_back((char*)args.back().c_str());
  }

  argv.push_back(nullptr);

  int flags = CLIENT_NOSTARTSERVER | CLIENT_CONTROL;

  //__lsan_do_recoverable_leak_check();
  client_main(libevent, argc, argv.data(), flags, /*feat=*/0);
  
  return 0;
}