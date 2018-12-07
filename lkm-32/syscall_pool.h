#include <linux/module.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/syscalls.h>
// #include </usr/include/x86_64-linux-gnu/asm/unistd_64.h>
// #ifndef __NR_llseek
// #endif

void **syscall_table = (void *)0xc16a0140;

asmlinkage long (*orig_sys_open)(const char __user *filename, int flags, int mode);
asmlinkage long (*orig_sys_openat)(int dfd, const char __user *filename, int flags, umode_t mode);
asmlinkage long (*orig_sys_creat)(const char __user *pathname, umode_t mode);
asmlinkage long (*orig_sys_close)(unsigned int fd);
asmlinkage long (*orig_sys_write)(unsigned int fd, const char __user *buf, size_t count);
asmlinkage long (*orig_sys_writev)(unsigned long fd, const struct iovec __user *vec, unsigned long vlen);
asmlinkage long (*orig_sys_pwrite64)(unsigned int fd, const char __user *buf, size_t count, loff_t pos);
asmlinkage long (*orig_sys_pwritev)(unsigned long fd, const struct iovec __user *vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h);
asmlinkage long (*orig_sys_read)(unsigned int fd, char __user *buf, size_t count);
asmlinkage long (*orig_sys_readv)(unsigned long fd, const struct iovec __user *vec, unsigned long vlen);
asmlinkage long (*orig_sys_pread64)(unsigned int fd, char __user *buf, size_t count, loff_t pos);
asmlinkage long (*orig_sys_preadv)(unsigned long fd, const struct iovec __user *vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h);
asmlinkage long (*orig_sys_nanosleep)(struct timespec __user *rqtp, struct timespec __user *rmtp);
asmlinkage off_t (*orig_sys_lseek)(int fd, off_t offset, int whence);

asmlinkage int (*orig_sys_connect)(int sockfd, struct sockaddr *addr, int addrlen);
asmlinkage int (*orig_sys_bind)(int sockfd, struct sockaddr *my_addr, int addrlen);
asmlinkage int (*orig_sys_listen)(int sockfd, int backlog);
asmlinkage int (*orig_sys_accept)(int sockfd, struct sockaddr *addr, int addrlen);
asmlinkage long (*orig_sys_accept4)(int, struct sockaddr __user *, int __user *, int);
asmlinkage long (*orig_sys_select)(int n, fd_set __user *inp, fd_set __user *outp, fd_set __user *exp, struct timeval __user *tvp);
asmlinkage ssize_t (*orig_sys_sendto)(int sockfd, void *buf, size_t len, int flags, const struct sockaddr *dest_addr, int addrlen);
asmlinkage ssize_t (*orig_sys_sendmsg)(int sockfd, const struct msghdr *msg, int flags);
asmlinkage ssize_t (*orig_sys_recvfrom)(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, int *addrlen);
asmlinkage ssize_t (*orig_sys_recvmsg)(int sockfd, struct msghdr *msg, int flags);
asmlinkage ssize_t (*orig_sys_send)(int sockfd, const void *buf, size_t len, int flags);
asmlinkage ssize_t (*orig_sys_recv)(int sockfd, void *buf, size_t len, int flags);
asmlinkage long (*orig_sys_socketcall)(int call, unsigned long __user *args);
asmlinkage long (*orig_sys_fstat)(unsigned int fd, struct __old_kernel_stat __user *statbuf);
asmlinkage long (*orig_sys_stat)(const char __user *filename, struct __old_kernel_stat __user *statbuf);
asmlinkage long (*orig_sys_lstat)(const char __user *filename, struct __old_kernel_stat __user *statbuf);
asmlinkage long (*orig_sys_exit)(int error_code);
asmlinkage long (*orig_sys_exit_group)(int error_code);
asmlinkage long (*orig_sys_dup)(unsigned int fildes);
asmlinkage long (*orig_sys_dup2)(unsigned int oldfd, unsigned int newfd);
asmlinkage long (*orig_sys_dup3)(unsigned int oldfd, unsigned int newfd, int flags);
asmlinkage long (*orig_sys_unlink)(const char __user *pathname);
asmlinkage long (*orig_sys_rename)(const char __user *oldname, const char __user *newname);
asmlinkage long (*orig_sys_fork)(void);
asmlinkage long (*orig_sys_clone)(unsigned long, unsigned long, int __user *, int, int __user *);
asmlinkage long (*orig_sys_mmap_pgoff)(unsigned long addr, unsigned long len, unsigned long prot, unsigned long flags, unsigned long fd, unsigned long pgoff);
asmlinkage long (*orig_sys_old_mmap)(struct mmap_arg_struct __user *arg);

asmlinkage long (*orig_sys_llseek)(unsigned int fd, unsigned long offset_high, unsigned long offset_low, loff_t __user *result, unsigned int whence);
asmlinkage long (*orig_sys_old_select)(struct sel_arg_struct __user *arg);
asmlinkage long (*orig_sys_fstat64)(unsigned long fd, struct stat64 __user *statbuf);
asmlinkage long (*orig_sys_stat64)(const char __user *filename, struct stat64 __user *statbuf);
asmlinkage long (*orig_sys_lstat64)(const char __user *filename, struct stat64 __user *statbuf);
asmlinkage long (*orig_sys_newstat)(const char __user *filename, struct stat __user *statbuf);
asmlinkage long (*orig_sys_newlstat)(const char __user *filename, struct stat __user *statbuf);
asmlinkage long (*orig_sys_newfstat)(unsigned int fd, struct stat __user *statbuf);


asmlinkage long my_sys_open(const char __user *filename, int flags, umode_t mode);
asmlinkage long my_sys_openat(int dfd, const char __user *filename, int flags, umode_t mode);
asmlinkage long my_sys_creat(const char __user *pathname, umode_t mode);   //
asmlinkage long my_sys_close(unsigned int fd);
asmlinkage long my_sys_write(unsigned int fd, const char __user *buf, size_t count);
asmlinkage long my_sys_writev(unsigned long fd, const struct iovec __user *vec, unsigned long vlen);
asmlinkage long my_sys_pwrite64(unsigned int fd, const char __user *buf, size_t count, loff_t pos);
asmlinkage long my_sys_pwritev(unsigned long fd, const struct iovec __user *vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h);
asmlinkage long my_sys_read(unsigned int fd, char __user *buf, size_t count);
asmlinkage long my_sys_readv(unsigned long fd, const struct iovec __user *vec, unsigned long vlen);
asmlinkage long my_sys_pread64(unsigned int fd, char __user *buf, size_t count, loff_t pos);
asmlinkage long my_sys_preadv(unsigned long fd, const struct iovec __user *vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h);
asmlinkage long my_sys_nanosleep(struct timespec __user *rqtp, struct timespec __user *rmtp);
asmlinkage off_t my_sys_lseek(int fd, off_t offset, int whence);
asmlinkage int my_sys_connect(int sockfd, struct sockaddr *addr, int addrlen);
asmlinkage int my_sys_bind(int sockfd, struct sockaddr *my_addr, int addrlen);
asmlinkage int my_sys_listen(int sockfd, int backlog);
asmlinkage int my_sys_accept(int sockfd, struct sockaddr *addr, int addrlen);
asmlinkage long my_sys_accept4(int, struct sockaddr __user *, int __user *, int);
asmlinkage long my_sys_select(int n, fd_set __user *inp, fd_set __user *outp, fd_set __user *exp, struct timeval __user *tvp);
asmlinkage ssize_t my_sys_sendto(int sockfd, void *buf, int len, int flags, struct sockaddr *dest_addr, int addrlen);
asmlinkage ssize_t my_sys_sendmsg(int sockfd, struct msghdr *msg, int flags);
asmlinkage ssize_t my_sys_recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, int *addrlen);
asmlinkage ssize_t my_sys_recvmsg(int sockfd, struct msghdr *msg, int flags);
asmlinkage ssize_t my_sys_send(int sockfd, void *buf, size_t len, int flags);
asmlinkage ssize_t my_sys_recv(int sockfd, void *buf, size_t len, int flags);
asmlinkage long my_sys_socketcall(int call, unsigned long __user *args);
asmlinkage long my_sys_fstat(unsigned int fd, struct __old_kernel_stat __user *statbuf);
asmlinkage long my_sys_stat(const char __user *filename, struct __old_kernel_stat __user *statbuf);
asmlinkage long my_sys_lstat(const char __user *filename, struct __old_kernel_stat __user *statbuf);
asmlinkage long my_sys_exit(int error_code);
asmlinkage long my_sys_exit_group(int error_code);
asmlinkage long my_sys_dup(unsigned int fildes);
asmlinkage long my_sys_dup2(unsigned int oldfd, unsigned int newfd);
asmlinkage long my_sys_dup3(unsigned int oldfd, unsigned int newfd, int flags);
asmlinkage long my_sys_unlink(const char __user *pathname);
asmlinkage long my_sys_rename(const char __user *oldname, const char __user *newname);
asmlinkage long my_sys_fork(void);
asmlinkage long my_sys_clone(unsigned long, unsigned long, int __user *, int, int __user *);
asmlinkage long my_sys_mmap_pgoff(unsigned long addr, unsigned long len, unsigned long prot, unsigned long flags, unsigned long fd, unsigned long pgoff);
asmlinkage long my_sys_old_mmap(struct mmap_arg_struct __user *arg);
asmlinkage long my_sys_llseek(unsigned int fd, unsigned long offset_high, unsigned long offset_low, loff_t __user *result, unsigned int whence);
asmlinkage long my_sys_old_select(struct sel_arg_struct __user *arg);
asmlinkage long my_sys_fstat64(unsigned long fd, struct stat64 __user *statbuf);
asmlinkage long my_sys_stat64(const char __user *filename, struct stat64 __user *statbuf);
asmlinkage long my_sys_lstat64(const char __user *filename, struct stat64 __user *statbuf);
asmlinkage long my_sys_newstat(const char __user *filename, struct stat __user *statbuf);
asmlinkage long my_sys_newlstat(const char __user *filename, struct stat __user *statbuf);
asmlinkage long my_sys_newfstat(unsigned int fd, struct stat __user *statbuf);

//etc etc, we just calculate the number and disturb when they are topped, nothing else at all
//the number of syscalls will be enlarged extradinarily 

void syscall_update(void);
void restore_syscall(void);


