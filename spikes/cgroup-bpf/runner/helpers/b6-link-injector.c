// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

/* Qualification-only helper: create and pin one cgroup BPF link from an
 * already-loaded production program ID. It neither loads nor changes a BPF
 * program. The caller replaces a detached recorded pin and records the new
 * kernel link identity as an injected, deliberately UNKNOWN state. */

#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static int sys_bpf(enum bpf_cmd command, union bpf_attr *attr,
                   unsigned int size) {
  return (int)syscall(__NR_bpf, command, attr, size);
}

static int program_fd(uint32_t id) {
  union bpf_attr attr = {0};
  attr.prog_id = id;
  return sys_bpf(BPF_PROG_GET_FD_BY_ID, &attr, sizeof(attr));
}

static int link_create(int prog_fd, int target_fd, uint32_t attach_type) {
  union bpf_attr attr = {0};
  attr.link_create.prog_fd = prog_fd;
  attr.link_create.target_fd = target_fd;
  attr.link_create.attach_type = attach_type;
  return sys_bpf(BPF_LINK_CREATE, &attr, sizeof(attr));
}

static int object_pin(int fd, const char *path) {
  union bpf_attr attr = {0};
  attr.pathname = (uint64_t)(uintptr_t)path;
  attr.bpf_fd = fd;
  return sys_bpf(BPF_OBJ_PIN, &attr, sizeof(attr));
}

int main(int argc, char **argv) {
  char *end = NULL;
  unsigned long program_id;
  unsigned long attach_type;
  int target_fd;
  int prog_fd;
  int link_fd;

  if (argc != 5) {
    fprintf(stderr,
            "usage: b6-link-injector <program-id> <attach-type> <cgroup> <pin>\n");
    return 13;
  }
  errno = 0;
  program_id = strtoul(argv[1], &end, 10);
  if (errno != 0 || end == argv[1] || *end != '\0' || program_id > UINT32_MAX) {
    fprintf(stderr, "invalid program id: %s\n", argv[1]);
    return 13;
  }
  errno = 0;
  attach_type = strtoul(argv[2], &end, 10);
  if (errno != 0 || end == argv[2] || *end != '\0' || attach_type > UINT32_MAX) {
    fprintf(stderr, "invalid attach type: %s\n", argv[2]);
    return 13;
  }
  target_fd = open(argv[3], O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (target_fd < 0) {
    perror("open target cgroup");
    return 1;
  }
  prog_fd = program_fd((uint32_t)program_id);
  if (prog_fd < 0) {
    perror("BPF_PROG_GET_FD_BY_ID");
    close(target_fd);
    return 1;
  }
  link_fd = link_create(prog_fd, target_fd, (uint32_t)attach_type);
  if (link_fd < 0) {
    perror("BPF_LINK_CREATE");
    close(prog_fd);
    close(target_fd);
    return 1;
  }
  if (object_pin(link_fd, argv[4]) < 0) {
    perror("BPF_OBJ_PIN");
    close(link_fd);
    close(prog_fd);
    close(target_fd);
    return 1;
  }
  close(link_fd);
  close(prog_fd);
  close(target_fd);
  return 0;
}
