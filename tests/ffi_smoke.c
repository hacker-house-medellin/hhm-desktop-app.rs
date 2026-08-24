#include "hhm_desktop.h"

#include <stdio.h>
#include <string.h>

int main(void) {
  if (hhm_desktop_abi_version() != HHM_DESKTOP_ABI_VERSION) {
    fputs("ABI version mismatch\n", stderr);
    return 1;
  }

  HhmDesktopHandle *handle = hhm_desktop_handle_new();
  if (handle == NULL) {
    fputs("handle allocation failed\n", stderr);
    return 2;
  }

  if (hhm_desktop_set_proximity(handle, 2) != HhmDesktopStatus_Ok) {
    hhm_desktop_handle_free(handle);
    return 3;
  }
  if (hhm_desktop_set_auth_state(handle, 99) != HhmDesktopStatus_InvalidValue) {
    hhm_desktop_handle_free(handle);
    return 4;
  }

  char *snapshot = NULL;
  if (hhm_desktop_snapshot_json(handle, &snapshot) != HhmDesktopStatus_Ok ||
      snapshot == NULL) {
    hhm_desktop_handle_free(handle);
    return 5;
  }
  if (strstr(snapshot, "\"may_request_presence_transition\":false") == NULL) {
    hhm_desktop_string_free(snapshot);
    hhm_desktop_handle_free(handle);
    return 6;
  }

  hhm_desktop_string_free(snapshot);
  hhm_desktop_handle_free(handle);
  return 0;
}
