// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

/* Qualification-only exact detach of a pinned BPF link. */

#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static int bpf_call(enum bpf_cmd command, union bpf_attr *attr) {
  return (int)syscall(__NR_bpf, command, attr, sizeof(*attr));
}

int main(int argc, char **argv) {
  union bpf_attr attr = {0};
  int fd;
  if (argc != 2) {
    fprintf(stderr, "usage: b7-link-detach <pinned-link>\n");
    return 13;
  }
  attr.pathname = (uint64_t)(uintptr_t)argv[1];
  fd = bpf_call(BPF_OBJ_GET, &attr);
  if (fd < 0) {
    fprintf(stderr, "BPF_OBJ_GET: %s\n", strerror(errno));
    return 1;
  }
  memset(&attr, 0, sizeof(attr));
  attr.link_detach.link_fd = fd;
  if (bpf_call(BPF_LINK_DETACH, &attr) < 0) {
    fprintf(stderr, "BPF_LINK_DETACH: %s\n", strerror(errno));
    close(fd);
    return 1;
  }
  close(fd);
  return 0;
}
