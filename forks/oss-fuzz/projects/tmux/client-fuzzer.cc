// fuzz/fuzz_client.cc
#include <cstdint>
#include <cstddef>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/lsan_interface.h>

#pragma push_macro("template")
#define template tmux_template
extern "C" {
#  include "tmux.h"
#  include <event2/event.h>
}
#pragma pop_macro("template")

// One event_base for the lifetime of the fuzzer
static struct event_base *global_base = nullptr;

// tmux globals are declared in tmux.h as extern; we'll just initialize them

// Helper to initialize tmux globals
static void init_tmux_globals() {
  if (!global_environ) global_environ = environ_create();
  if (!global_options) global_options = options_create(nullptr);
  if (!global_s_options) global_s_options = options_create(nullptr);
  if (!global_w_options) global_w_options = options_create(nullptr);
  for (const struct options_table_entry *oe = options_table;
       oe->name != nullptr; ++oe) {
    if (oe->scope & OPTIONS_TABLE_SERVER)
      options_default(global_options,   oe);
    if (oe->scope & OPTIONS_TABLE_SESSION)
      options_default(global_s_options, oe);
    if (oe->scope & OPTIONS_TABLE_WINDOW)
      options_default(global_w_options, oe);
  }
}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
  // One-time tmux global initialization
  init_tmux_globals();
  event_set_log_callback([](int severity, const char *msg){
    (void)severity; (void)msg;
  });
  global_base = osdep_event_init();
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 2 || size > 1024) return 0;

  // Parse client flags
  uint8_t flagByte = data[0];
  uint64_t flags = 0;
  if (flagByte & 0x01) flags |= CLIENT_STARTSERVER;
  if (flagByte & 0x02) flags |= CLIENT_CONTROLCONTROL;
  if (flagByte & 0x04) flags |= CLIENT_CONTROL_WAITEXIT;
  if (flagByte & 0x08) flags |= CLIENT_NOSTARTSERVER;

  // Build command argument
  const uint8_t *cmdBuf = data + 1;
  size_t cmdSize = size - 1;
  char *arg = (char*)malloc(cmdSize + 1);
  if (!arg) return 0;
  memcpy(arg, cmdBuf, cmdSize);
  arg[cmdSize] = '\0';
  char *argv0[2] = { arg, nullptr };

  // Ensure valid socket_path
  socket_path = xstrdup("fuzz-socket");
  if (!socket_path) { free(arg); return 0; }

  // Run tmux client_main under ASan/LSan
  client_main(global_base, 1, argv0, flags, /*feat=*/0);

  // Clean up harness allocations
  free(arg);
  free((void * ) socket_path);
  socket_path = nullptr;

  // Reinitialize tmux globals if needed
  init_tmux_globals();

  return 0;
}
