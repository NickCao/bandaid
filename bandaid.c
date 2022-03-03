#include <netinet/in.h>
#include <seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <systemd/sd-daemon.h>
#include <unistd.h>

int main(int argc, char **argv, char **envp) {
  if (argc < 2)
    exit(1);

  int num_fds = sd_listen_fds(1);
  for (int off = 0; off < num_fds; off++) {
    int fd = SD_LISTEN_FDS_START + off;
    printf("inspecting fd: %d\n", fd);
  }

  scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
  if (ctx == NULL)
    exit(1);
  if (seccomp_rule_add(ctx, SCMP_ACT_NOTIFY, SCMP_SYS(bind), 0) < 0)
    exit(1);
  if (seccomp_load(ctx) < 0)
    exit(1);

  int pid = fork();
  if (pid == 0) {
    execve(argv[1], argv + 1, envp);
  } else {
    int notifd = seccomp_notify_fd(ctx);
    struct seccomp_notif *req;
    struct seccomp_notif_resp *resp;
    while (waitpid(pid, NULL, WNOHANG) == 0) {
      if (seccomp_notify_alloc(&req, &resp) != 0)
        exit(1);
      if (seccomp_notify_receive(notifd, req) != 0)
        exit(1);
      printf("bind: fd: %lld, sockaddr*: 0x%llx, sockaddr_size: %lld\n",
             req->data.args[0], req->data.args[1], req->data.args[2]);
      resp->id = req->id;
      resp->error = 0;
      resp->val = 0;
      resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
      if (seccomp_notify_respond(notifd, resp) != 0)
        exit(1);
      seccomp_notify_free(req, resp);
    }
  }
}
