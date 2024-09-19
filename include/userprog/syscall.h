#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
// 재원 추가
// #define USERPROG
#include <stdbool.h>
#include <stdint.h>
#include "process.h"

void syscall_init(void);
typedef int pid_t;

// // 재원 추가
// void halt(void);
// void exit(int status);
// pid_t fork(const char *thread_name);
// int exec(const char *cmd_line);
// int wait(pid_t pid);
// bool create(const char *file, unsigned initial_size);
// bool remove(const char *file);
// int open(const char *file);
// int write(int fd, const void *buffer, unsigned size);

// void syscall_handler(struct intr_frame *f);

#endif /* userprog/syscall.h */
