#define _GNU_SOURCE
#include <netinet/in.h>
#include <seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <systemd/sd-daemon.h>
#include <unistd.h>

int confine(const char *pathname, char *const argv[], char *const envp[],
            int *pid) {
  scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
  if (ctx == NULL)
    return -1;
  if (seccomp_rule_add(ctx, SCMP_ACT_NOTIFY, SCMP_SYS(socket), 0) < 0)
    return -1;
  if (seccomp_rule_add(ctx, SCMP_ACT_NOTIFY, SCMP_SYS(bind), 0) < 0)
    return -1;
  if (seccomp_load(ctx) < 0)
    return -1;

  *pid = fork();
  if (*pid == 0) {
    execvpe(pathname, argv, envp);
  } else {
    if (*pid == -1)
      return -1;
    return seccomp_notify_fd(ctx);
  }
  return -1;
}

static void sighandler(int sig) { exit(0); }

int main(int argc, char **argv, char **envp) {
  if (argc < 2) {
    fprintf(stderr, "usage: bandaid COMMAND [ARGS...]");
    exit(2);
  }

  struct sigaction sa;
  sa.sa_handler = sighandler;
  sa.sa_flags = 0;
  sigemptyset(&sa.sa_mask);
  if (sigaction(SIGCHLD, &sa, NULL) != 0)
    exit(1);

  int num_fds = sd_listen_fds(1);
  // no fd passed, doing nothing
  if (num_fds == 0) {
    execvpe(argv[1], argv + 1, envp);
  }

  int pid;
  int notifd = confine(argv[1], argv + 1, envp, &pid);
  if (notifd == -1)
    exit(1);

  while (1) {
    struct seccomp_notif *req;
    struct seccomp_notif_resp *resp;

    if (seccomp_notify_alloc(&req, &resp) != 0) {
      kill(pid, SIGTERM);
      exit(1);
    }

    if (seccomp_notify_receive(notifd, req) != 0) {
      kill(pid, SIGTERM);
      exit(1);
    };

    resp->id = req->id;
    resp->val = 0;
    resp->error = 0;
    resp->flags = 0;

    if (req->data.nr == __NR_socket) {
      int type = req->data.args[1];
      struct seccomp_notif_addfd addfd;
      addfd.id = req->id;
      addfd.srcfd = SD_LISTEN_FDS_START; // TODO: find matching fd
      addfd.newfd = 0;
      addfd.flags = 0;
      addfd.newfd_flags = (type & SOCK_CLOEXEC) ? O_CLOEXEC : 0;
      resp->val = ioctl(notifd, SECCOMP_IOCTL_NOTIF_ADDFD, &addfd);
    }

    if (seccomp_notify_respond(notifd, resp) != 0) {
      kill(pid, SIGTERM);
      exit(1);
    }
    seccomp_notify_free(req, resp);
  }
}
