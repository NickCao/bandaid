#include <stdio.h>
#include <systemd/sd-daemon.h>

int main() {
  int num_fds = sd_listen_fds(1);
  for (int off = 0; offset < num_fds; off++) {
    int fd = SD_LISTEN_FDS_START + off;
    printf("%d\n", fd);
  }
}
