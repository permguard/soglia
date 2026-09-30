// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <linux/limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

static int bpf_call(enum bpf_cmd command, union bpf_attr *attr)
{
    return (int)syscall(__NR_bpf, command, attr, sizeof(*attr));
}

static int object_get(const char *path)
{
    union bpf_attr attr = {0};

    attr.pathname = (uint64_t)(uintptr_t)path;
    return bpf_call(BPF_OBJ_GET, &attr);
}

static int link_info(int fd, struct bpf_link_info *info)
{
    union bpf_attr attr = {0};

    attr.info.bpf_fd = (uint32_t)fd;
    attr.info.info_len = sizeof(*info);
    attr.info.info = (uint64_t)(uintptr_t)info;
    return bpf_call(BPF_OBJ_GET_INFO_BY_FD, &attr);
}

static void print_link_info(const struct bpf_link_info *info)
{
    printf("{\"id\":%u,\"prog_id\":%u,\"type\":%u,"
           "\"cgroup_id\":%llu,\"attach_type\":%u}",
           info->id, info->prog_id, info->type,
           (unsigned long long)info->cgroup.cgroup_id,
           info->cgroup.attach_type);
}

static int run_link_info(const char *pin)
{
    struct bpf_link_info info = {0};
    int fd = object_get(pin);

    if (fd < 0) {
        perror("BPF_OBJ_GET");
        return 1;
    }
    if (link_info(fd, &info) != 0) {
        perror("BPF_OBJ_GET_INFO_BY_FD");
        close(fd);
        return 1;
    }
    print_link_info(&info);
    putchar('\n');
    close(fd);
    return 0;
}

static int run_link_detach(const char *pin)
{
    struct bpf_link_info before = {0};
    struct bpf_link_info after = {0};
    union bpf_attr attr = {0};
    int detach_errno = 0;
    int detach_result;
    int fd = object_get(pin);

    if (fd < 0) {
        perror("BPF_OBJ_GET");
        return 1;
    }
    if (link_info(fd, &before) != 0) {
        perror("BPF_OBJ_GET_INFO_BY_FD before detach");
        close(fd);
        return 1;
    }
    attr.link_detach.link_fd = (uint32_t)fd;
    detach_result = bpf_call(BPF_LINK_DETACH, &attr);
    if (detach_result != 0)
        detach_errno = errno;
    if (link_info(fd, &after) != 0) {
        perror("BPF_OBJ_GET_INFO_BY_FD after detach");
        close(fd);
        return 1;
    }

    printf("{\"before\":");
    print_link_info(&before);
    printf(",\"detach_result\":%d,\"detach_errno\":%d,"
           "\"detach_error\":\"%s\",\"after\":",
           detach_result, detach_errno,
           detach_errno == 0 ? "" : strerror(detach_errno));
    print_link_info(&after);
    printf("}\n");
    close(fd);
    return detach_result == 0 ? 0 : 1;
}

static int open_handle(int mount_fd, struct file_handle *handle, int *error)
{
    int fd = open_by_handle_at(mount_fd, handle, O_PATH | O_DIRECTORY);

    *error = fd < 0 ? errno : 0;
    return fd;
}

static int wait_for_marker(const char *marker)
{
    for (int attempt = 0; attempt < 3000; ++attempt) {
        if (access(marker, F_OK) == 0)
            return 0;
        usleep(10000);
    }
    errno = ETIMEDOUT;
    return -1;
}

static int run_handle_probe(const char *path, const char *marker)
{
    unsigned char storage[sizeof(struct file_handle) + 128] = {0};
    struct file_handle *handle = (struct file_handle *)storage;
    int before_errno = 0;
    int after_errno = 0;
    int mount_id = 0;
    int mount_fd;
    int before_fd;
    int after_fd;

    handle->handle_bytes = 128;
    if (name_to_handle_at(AT_FDCWD, path, handle, &mount_id, 0) != 0) {
        perror("name_to_handle_at");
        return 1;
    }
    mount_fd = open("/sys/fs/cgroup", O_RDONLY | O_DIRECTORY);
    if (mount_fd < 0) {
        perror("open cgroup2 mount");
        return 1;
    }
    before_fd = open_handle(mount_fd, handle, &before_errno);
    if (before_fd >= 0)
        close(before_fd);

    printf("{\"stage\":\"before\",\"mount_id\":%d,"
           "\"handle_type\":%d,\"handle_bytes\":%u,"
           "\"open_result\":%d,\"open_errno\":%d,\"handle_hex\":\"",
           mount_id, handle->handle_type, handle->handle_bytes,
           before_fd < 0 ? -1 : 0, before_errno);
    for (unsigned int index = 0; index < handle->handle_bytes; ++index)
        printf("%02x", handle->f_handle[index]);
    printf("\"}\n");
    fflush(stdout);

    if (wait_for_marker(marker) != 0) {
        perror("wait for removal marker");
        close(mount_fd);
        return 1;
    }
    after_fd = open_handle(mount_fd, handle, &after_errno);
    if (after_fd >= 0)
        close(after_fd);
    printf("{\"stage\":\"after\",\"open_result\":%d,"
           "\"open_errno\":%d,\"open_error\":\"%s\"}\n",
           after_fd < 0 ? -1 : 0, after_errno,
           after_errno == 0 ? "" : strerror(after_errno));
    close(mount_fd);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 3 && strcmp(argv[1], "link-info") == 0)
        return run_link_info(argv[2]);
    if (argc == 3 && strcmp(argv[1], "link-detach") == 0)
        return run_link_detach(argv[2]);
    if (argc == 4 && strcmp(argv[1], "handle-probe") == 0)
        return run_handle_probe(argv[2], argv[3]);

    fprintf(stderr,
            "usage: %s link-info PIN | link-detach PIN | "
            "handle-probe CGROUP MARKER\n",
            argv[0]);
    return 64;
}
