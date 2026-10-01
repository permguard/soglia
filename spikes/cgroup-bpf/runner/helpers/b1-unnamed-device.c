// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

/* Qualification-only loader for an intentionally unnamed cgroup-device
 * program.  The BPF_PROG_LOAD request leaves prog_name all-zero so the test
 * exercises kernels and bpftool versions that omit the optional name. */

#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static int bpf_call(enum bpf_cmd command, union bpf_attr *attr) {
  return (int)syscall(__NR_bpf, command, attr, sizeof(*attr));
}

static int pin_object(int fd, const char *path) {
  union bpf_attr attr = {0};
  attr.pathname = (uint64_t)(uintptr_t)path;
  attr.bpf_fd = fd;
  return bpf_call(BPF_OBJ_PIN, &attr);
}

static int get_pinned(const char *path) {
  union bpf_attr attr = {0};
  attr.pathname = (uint64_t)(uintptr_t)path;
  return bpf_call(BPF_OBJ_GET, &attr);
}

static int create_link(int program_fd, int cgroup_fd) {
  union bpf_attr attr = {0};
  attr.link_create.prog_fd = program_fd;
  attr.link_create.target_fd = cgroup_fd;
  attr.link_create.attach_type = BPF_CGROUP_DEVICE;
  return bpf_call(BPF_LINK_CREATE, &attr);
}

static int load_program(unsigned int variant) {
  static const char license[] = "Apache-2.0";
  char verifier_log[16384] = {0};
  struct bpf_insn variant_one[] = {
      {.code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = BPF_REG_0, .imm = 1},
      {.code = BPF_JMP | BPF_EXIT},
  };
  struct bpf_insn variant_two[] = {
      {.code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = BPF_REG_0, .imm = 0},
      {.code = BPF_ALU64 | BPF_ADD | BPF_K, .dst_reg = BPF_REG_0, .imm = 1},
      {.code = BPF_JMP | BPF_EXIT},
  };
  struct bpf_insn *instructions = variant == 1 ? variant_one : variant_two;
  size_t instruction_count =
      variant == 1 ? sizeof(variant_one) / sizeof(variant_one[0])
                   : sizeof(variant_two) / sizeof(variant_two[0]);
  union bpf_attr attr = {0};
  attr.prog_type = BPF_PROG_TYPE_CGROUP_DEVICE;
  attr.expected_attach_type = BPF_CGROUP_DEVICE;
  attr.insn_cnt = (uint32_t)instruction_count;
  attr.insns = (uint64_t)(uintptr_t)instructions;
  attr.license = (uint64_t)(uintptr_t)license;
  attr.log_buf = (uint64_t)(uintptr_t)verifier_log;
  attr.log_size = sizeof(verifier_log);
  attr.log_level = 1;
  /* Deliberately do not populate attr.prog_name. */
  int fd = bpf_call(BPF_PROG_LOAD, &attr);
  if (fd < 0) {
    fprintf(stderr, "BPF_PROG_LOAD: %s\n%s", strerror(errno), verifier_log);
  }
  return fd;
}

static int attach_and_pin(int program_fd, const char *cgroup,
                          const char *link_pin) {
  int cgroup_fd = open(cgroup, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (cgroup_fd < 0) {
    perror("open cgroup");
    return -1;
  }
  int link_fd = create_link(program_fd, cgroup_fd);
  close(cgroup_fd);
  if (link_fd < 0) {
    perror("BPF_LINK_CREATE");
    return -1;
  }
  if (pin_object(link_fd, link_pin) < 0) {
    perror("pin link");
    close(link_fd);
    return -1;
  }
  close(link_fd);
  return 0;
}

int main(int argc, char **argv) {
  if (argc == 6 && strcmp(argv[1], "load") == 0) {
    char *end = NULL;
    errno = 0;
    unsigned long variant = strtoul(argv[2], &end, 10);
    if (errno != 0 || end == argv[2] || *end != '\0' ||
        (variant != 1 && variant != 2)) {
      fprintf(stderr, "variant must be 1 or 2\n");
      return 13;
    }
    int program_fd = load_program((unsigned int)variant);
    if (program_fd < 0) {
      return 1;
    }
    if (pin_object(program_fd, argv[4]) < 0) {
      perror("pin program");
      close(program_fd);
      return 1;
    }
    if (attach_and_pin(program_fd, argv[3], argv[5]) < 0) {
      unlink(argv[4]);
      close(program_fd);
      return 1;
    }
    close(program_fd);
    return 0;
  }
  if (argc == 5 && strcmp(argv[1], "attach") == 0) {
    int program_fd = get_pinned(argv[3]);
    if (program_fd < 0) {
      perror("BPF_OBJ_GET program");
      return 1;
    }
    int status = attach_and_pin(program_fd, argv[2], argv[4]);
    close(program_fd);
    return status == 0 ? 0 : 1;
  }
  fprintf(stderr,
          "usage: %s load <1|2> <cgroup> <program-pin> <link-pin>\n"
          "       %s attach <cgroup> <program-pin> <link-pin>\n",
          argv[0], argv[0]);
  return 13;
}
