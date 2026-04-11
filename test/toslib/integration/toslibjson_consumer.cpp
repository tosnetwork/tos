#include "toslib/toslib_client_json.h"
#include "toslib/toslib_engine_console.h"

int main() {
  void* client = toslib_client_json_create();
  toslib_client_json_destroy(client);

  ToslibEventLoop* loop = toslib_event_loop_create(1);
  toslib_event_loop_destroy(loop);

  return 0;
}
