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

// We’ll keep one event_base for the entire lifetime of the fuzzer:
static struct event_base *global_base = nullptr;

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
  // Do the one‐time tmux global initialization
  global_environ    = environ_create();
  global_options    = options_create(nullptr);
  global_s_options  = options_create(nullptr);
  global_w_options  = options_create(nullptr);
  for (const struct options_table_entry *oe = options_table;
       oe->name != nullptr; ++oe) {
    if (oe->scope & OPTIONS_TABLE_SERVER)
      options_default(global_options,   oe);
    if (oe->scope & OPTIONS_TABLE_SESSION)
      options_default(global_s_options, oe);
    if (oe->scope & OPTIONS_TABLE_WINDOW)
      options_default(global_w_options, oe);
  }
  // Suppress libevent warnings entirely:
  event_set_log_callback([](int severity, const char *msg){
    (void)severity; (void)msg;
  });

  // Create just one event loop for all fuzz calls
  global_base = osdep_event_init();
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 2 || size > 1024) {
    return 0;
  }

  uint8_t flagByte = data[0];
  uint64_t flags   = 0;
  if (flagByte & 0x01) flags |= CLIENT_STARTSERVER;
  if (flagByte & 0x02) flags |= CLIENT_CONTROLCONTROL;
  if (flagByte & 0x04) flags |= CLIENT_CONTROL_WAITEXIT;
  if (flagByte & 0x08) flags |= CLIENT_NOSTARTSERVER;

  const uint8_t *cmdBuf   = data + 1;
  size_t         cmdSize  = size - 1;
  char *arg = (char*)malloc(cmdSize + 1);
  memcpy(arg, cmdBuf, cmdSize);
  arg[cmdSize] = '\0';



  struct event_base *base = osdep_event_init();

  // Build a NUL-terminated argv
  //char *arg = (char*)malloc(size+1);
  //if (!arg) return 0;
  //memcpy(arg, data, size);
  //arg[size] = '\0';
  char *argv0[2] = { arg, nullptr };

  // Make tmux think we should try connecting to “fuzz-socket”,
  // but our stub above will short-circuit it.
  socket_path = xstrdup("fuzz-socket");

  // Run the client_main() harness
  //__lsan_disable();  // if you still want to allow its one-time leaks
  client_main(global_base, 1, argv0, flags, /*feat=*/0);
  //__lsan_enable();

  // Clean up what *you* allocated here:
  free(arg);
  free((char*)socket_path);

  return 0;
}
