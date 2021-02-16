#ifndef __PTRACE_H__
#define __PTRACE_H__

#include <stdio.h>      
#include <stdlib.h>      
#include <sys/user.h>
#include <sys/ptrace.h>      
#include <sys/wait.h>      
#include <sys/mman.h>      
#include <dlfcn.h>      
#include <dirent.h>      
#include <unistd.h>      
#include <string.h>
#include <stdint.h>
#include <errno.h>

#define pt_regs  pt_regs
#define std_width uint32_t

int ptrace_readdata(pid_t pid,  uint8_t *src, uint8_t *buf, size_t size);
int ptrace_writedata(pid_t pid, uint8_t *dest, uint8_t *data, size_t size);
int ptrace_call(pid_t pid, void* addr, std_width *params, int num_params, struct pt_regs * regs);
int ptrace_getregs(pid_t pid, struct pt_regs * regs);
int ptrace_setregs(pid_t pid, struct pt_regs * regs);
int ptrace_continue(pid_t pid);
int ptrace_attach(pid_t pid);
int ptrace_detach(pid_t pid);
std_width ptrace_retval(struct pt_regs * regs);
std_width ptrace_pc(struct pt_regs * regs);
int ptrace_call_wrapper(pid_t pid, const char *func_name, void * addr, std_width * params, int num_param, struct pt_regs * regs);

#endif	//__PTRACE_H__ ends
