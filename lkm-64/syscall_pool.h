#include <linux/module.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/syscalls.h>
// #include </usr/include/x86_64-linux-gnu/asm/unistd_64.h>
// #ifndef __NR_llseek
// #endif

void **syscall_table;
void **ia32_syscall_table;
long (*orig_32_open)(const char __user *filename, int flags, int mode);
long my_32_open(const char __user *filename, int flags, int mode);

long (*orig_sys_open)(const char __user *filename, int flags, int mode);
long (*orig_sys_openat)(int dirfd, const char *pathname, int flags);
long (*orig_sys_creat)(const char __user *pathname, umode_t mode);
long (*orig_sys_close)(unsigned int fd);
ssize_t (*orig_sys_write)(unsigned int fd, char * buf, size_t count);
long (*orig_sys_writev)(unsigned long fd, const struct iovec __user *vec, unsigned long vlen);
long (*orig_sys_pwrite64)(unsigned int fd, const char __user *buf, size_t count, loff_t pos);
long (*orig_sys_pwritev)(unsigned long fd, const struct iovec __user *vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h);
ssize_t (*orig_sys_read)(int fd, void *buf, size_t count);
long (*orig_sys_readv)(unsigned long fd, const struct iovec __user *vec, unsigned long vlen);
long (*orig_sys_pread64)(unsigned int fd, char __user *buf, size_t count, loff_t pos);
long (*orig_sys_preadv)(unsigned long fd, const struct iovec __user *vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h);
long (*orig_sys_nanosleep)(struct timespec *req, struct timespec *rem);
off_t (*orig_sys_lseek)(int fd, off_t offset, int whence);
// long (*orig_sys_llseek)(unsigned int fd, unsigned long offset_high, unsigned long offset_low, loff_t __user *result, unsigned int whence);
int (*orig_sys_connect)(int sockfd, struct sockaddr *addr, int addrlen);
int (*orig_sys_bind)(int sockfd, struct sockaddr *my_addr, int addrlen);
int (*orig_sys_listen)(int sockfd, int backlog);
int (*orig_sys_accept)(int sockfd, struct sockaddr *addr, int addrlen);
long (*orig_sys_accept4)(int, struct sockaddr __user *, int __user *, int);
long (*orig_sys_select)(int n, fd_set __user *inp, fd_set __user *outp, fd_set __user *exp, struct timeval __user *tvp);
// long (*orig_sys_old_select)(struct sel_arg_struct __user *arg);
// ssize_t (*orig_sys_send)(int sockfd, const void *buf, size_t len, int flags);
ssize_t (*orig_sys_sendto)(int sockfd, void *buf, size_t len, int flags, const struct sockaddr *dest_addr, int addrlen);
ssize_t (*orig_sys_sendmsg)(int sockfd, const struct msghdr *msg, int flags);
// ssize_t (*orig_sys_recv)(int sockfd, void *buf, size_t len, int flags);
ssize_t (*orig_sys_recvfrom)(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, int *addrlen);
ssize_t (*orig_sys_recvmsg)(int sockfd, struct msghdr *msg, int flags);
long (*orig_sys_fstat)(unsigned int fd, struct __old_kernel_stat __user *statbuf);
// long (*orig_sys_fstat64)(unsigned long fd, struct stat64 __user *statbuf);
long (*orig_sys_stat)(const char __user *filename, struct __old_kernel_stat __user *statbuf);
// long (*orig_sys_stat64)(const char __user *filename, struct stat64 __user *statbuf);
long (*orig_sys_lstat)(const char __user *filename, struct __old_kernel_stat __user *statbuf);
// long (*orig_sys_lstat64)(const char __user *filename, struct stat64 __user *statbuf);
// long (*orig_sys_newstat)(const char __user *filename, struct stat __user *statbuf);
// long (*orig_sys_newlstat)(const char __user *filename, struct stat __user *statbuf);
// long (*orig_sys_newfstat)(unsigned int fd, struct stat __user *statbuf);
long (*orig_sys_exit)(int error_code);
long (*orig_sys_exit_group)(int error_code);
long (*orig_sys_dup)(unsigned int fildes);
long (*orig_sys_dup2)(unsigned int oldfd, unsigned int newfd);
long (*orig_sys_dup3)(unsigned int oldfd, unsigned int newfd, int flags);
long (*orig_sys_unlink)(const char __user *pathname);
long (*orig_sys_rename)(const char __user *oldname, const char __user *newname);
long (*orig_sys_fork)(void);
long (*orig_sys_clone)(unsigned long, unsigned long, int __user *, int, int __user *);
long (*orig_sys_mmap_pgoff)(unsigned long addr, unsigned long len, unsigned long prot, unsigned long flags, unsigned long fd, unsigned long pgoff);
long (*orig_sys_old_mmap)(struct mmap_arg_struct __user *arg);


long my_sys_open(const char __user *filename, int flags, int mode);
long my_sys_openat(int dirfd, const char *pathname, int flags);
long my_sys_creat(const char __user *pathname, umode_t mode);   //
long my_sys_close(unsigned int fd);
ssize_t my_sys_write(unsigned int fd, char * buf, size_t count);
long my_sys_writev(unsigned long fd, const struct iovec __user *vec, unsigned long vlen);
long my_sys_pwrite64(unsigned int fd, const char __user *buf, size_t count, loff_t pos);
long my_sys_pwritev(unsigned long fd, const struct iovec __user *vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h);
ssize_t my_sys_read(int fd, void *buf, size_t count);
long my_sys_readv(unsigned long fd, const struct iovec __user *vec, unsigned long vlen);
long my_sys_pread64(unsigned int fd, char __user *buf, size_t count, loff_t pos);
long my_sys_preadv(unsigned long fd, const struct iovec __user *vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h);
long my_sys_nanosleep(struct timespec *req, struct timespec *rem);
off_t my_sys_lseek(int fd, off_t offset, int whence);
// long my_sys_llseek(unsigned int fd, unsigned long offset_high, unsigned long offset_low, loff_t __user *result, unsigned int whence);
int my_sys_connect(int sockfd, struct sockaddr *addr, int addrlen);
int my_sys_bind(int sockfd, struct sockaddr *my_addr, int addrlen);
int my_sys_listen(int sockfd, int backlog);
int my_sys_accept(int sockfd, struct sockaddr *addr, int addrlen);
long my_sys_accept4(int, struct sockaddr __user *, int __user *, int);
long my_sys_select(int n, fd_set __user *inp, fd_set __user *outp, fd_set __user *exp, struct timeval __user *tvp);
// long my_sys_old_select(struct sel_arg_struct __user *arg);
// ssize_t my_sys_send(int sockfd, void *buf, size_t len, int flags);
ssize_t my_sys_sendto(int sockfd, void *buf, int len, int flags, struct sockaddr *dest_addr, int addrlen);
ssize_t my_sys_sendmsg(int sockfd, struct msghdr *msg, int flags);
// ssize_t my_sys_recv(int sockfd, void *buf, size_t len, int flags);
ssize_t my_sys_recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, int *addrlen);
ssize_t my_sys_recvmsg(int sockfd, struct msghdr *msg, int flags);
long my_sys_fstat(unsigned int fd, struct __old_kernel_stat __user *statbuf);
// long my_sys_fstat64(unsigned long fd, struct stat64 __user *statbuf);
long my_sys_stat(const char __user *filename, struct __old_kernel_stat __user *statbuf);
// long my_sys_stat64(const char __user *filename, struct stat64 __user *statbuf);
long my_sys_lstat(const char __user *filename, struct __old_kernel_stat __user *statbuf);
// long my_sys_lstat64(const char __user *filename, struct stat64 __user *statbuf);
// long my_sys_newstat(const char __user *filename, struct stat __user *statbuf);
// long my_sys_newlstat(const char __user *filename, struct stat __user *statbuf);
// long my_sys_newfstat(unsigned int fd, struct stat __user *statbuf);
long my_sys_exit(int error_code);
long my_sys_exit_group(int error_code);
long my_sys_dup(unsigned int fildes);
long my_sys_dup2(unsigned int oldfd, unsigned int newfd);
long my_sys_dup3(unsigned int oldfd, unsigned int newfd, int flags);
long my_sys_unlink(const char __user *pathname);
long my_sys_rename(const char __user *oldname, const char __user *newname);
long my_sys_fork(void);
long my_sys_clone(unsigned long, unsigned long, int __user *, int, int __user *);
long my_sys_mmap_pgoff(unsigned long addr, unsigned long len, unsigned long prot, unsigned long flags, unsigned long fd, unsigned long pgoff);
long my_sys_old_mmap(struct mmap_arg_struct __user *arg);
//etc etc, we just calculate the number and disturb when they are topped, nothing else at all
//the number of syscalls will be enlarged extradinarily 

void syscall_update(void);
void restore_syscall(void);


