#include "unpred.h"
#include "syscall_pool.h"

/* Just so we do not taint the kernel */
MODULE_LICENSE("GPL");
// #define CR0_WP 0x00010000   // Write Protect Bit (CR0:16)
// #define LOCAL_ADDR ((unsigned long int)0x0100007F)  //"127.0.0.1" attention on big/little endian

//static const char *TARGET= "soffice.bin";
// static int pid;
// static char *TARGET = "ls";
static int totalsyscnt;   // total number of system call under monitored
static int silencesyscnt;

// static int perturbsyscnt;   // # of system call being changed

static int totalbytes;
static int lostbytes;

static int totalconnect;
static int lostconnect;

static int totalpacket;
static int lostpacket; 

static int stat_cnt, lstat_cnt, fstat_cnt;
static int nanosleep_cnt;
static int open_cnt, openat_cnt, creat_cnt, close_cnt;
static int read_cnt, readv_cnt, pread64_cnt, preadv_cnt;
static int write_cnt, writev_cnt, pwrite64_cnt, pwritev_cnt;
static int connect_cnt, bind_cnt, listen_cnt, accept_cnt, accept4_cnt, lseek_cnt;
static int fork_cnt, clone_cnt, select_cnt;
static int sendto_cnt, sendmsg_cnt, recvfrom_cnt, recvmsg_cnt;
static int unlink_cnt, rename_cnt, dup_cnt, dup2_cnt, dup3_cnt, old_mmap_cnt;
static int df, df2, df3;
//print tips: [ssize_t: %zu],

unsigned long **find_sys_call_table(void);

unsigned long **find_sys_call_table() {    
    unsigned long ptr;
    unsigned long *p;
    for (ptr = (unsigned long)sys_close;
         ptr < (unsigned long)&loops_per_jiffy;
         ptr += sizeof(void *)) {
             
        p = (unsigned long *)ptr;

        if (p[__NR_close] == (unsigned long)sys_close) {
            printk(KERN_DEBUG "Found the sys_call_table!!!\n");
            return (unsigned long **)p;
        }
    }   
    return NULL;
}

// unsigned long **find_sys_call_table_32(void) {  

// } 

static char *TARGET;
module_param(TARGET, charp, 0644);


long my_sys_open(const char __user *filename, int flags, int mode){
    long ret;
    int len = 1024*sizeof(char*);
    char *kfilename = kmalloc(len, GFP_KERNEL);
    copy_from_user(kfilename, filename, len);

    if(!inPidList(current->pid)){
        if(!strcmp(current->comm, TARGET) || inPidList(task_ppid_nr(current))){
            if(!strcmp(current->comm, TARGET)){
                printk(KERN_INFO "Target %s: pid %d to add\n", current->comm, current->pid);
                updatePidList(current->pid);
            }
            else{
                printk(KERN_INFO "proc %s: pid %d to add under ppid %d\n", current->comm, current->pid, task_ppid_nr(current));
                updatePidList(current->pid);
            }
        }
    }
    if(inPidList(current->pid)){
        // printk(KERN_INFO "open: pid %d begin unpredictability\n", current->pid);
        open_cnt++;
        totalsyscnt++;
        updateTop5Syscall("open", open_cnt);
        if(isTopSyscall("open", totalsyscnt) && !isKeyfile(kfilename)){
            incThreshold(20);
            if(within_threshold()){ 
                open_cnt--;
                silencesyscnt++;
                printk(KERN_INFO "open return -1;\n");
                return -1; }
        }
        ret = orig_sys_open(filename, flags, mode);
        if(ret > 0){
            add_fd(ret, kfilename);
        }
    }
    kfree(kfilename);
    return orig_sys_open(filename, flags, mode);
}

long my_sys_openat(int dirfd, const char *pathname, int flags){
    long ret;
    int len = 1024*sizeof(char*);
    char *kpathname = kmalloc(len, GFP_KERNEL);
    copy_from_user(kpathname, pathname, len);
    if(!inPidList(current->pid)){
        if(!strcmp(current->comm, TARGET) || inPidList(task_ppid_nr(current))){
            if(!strcmp(current->comm, TARGET)){
                printk(KERN_INFO "Target %s: pid %d to add\n", current->comm, current->pid);
                updatePidList(current->pid);
            }
            else{
                printk(KERN_INFO "proc %s: pid %d to add under ppid %d\n", current->comm, current->pid, task_ppid_nr(current));
                updatePidList(current->pid);
            }
        }
    }
    if(inPidList(current->pid)){
        // printk(KERN_INFO "openat: pid %d begin unpredictability\n", current->pid);
        openat_cnt++;
        totalsyscnt++;
        updateTop5Syscall("openat", openat_cnt);
        if(isTopSyscall("openat", totalsyscnt) && !isKeyfile(kpathname)){
            if(within_threshold()){ 
                openat_cnt--;
                silencesyscnt++;
                printk(KERN_INFO "openat return -1;\n");
                return -1; }
        }
        ret = orig_sys_openat(dirfd, pathname, flags);
        if(ret > 0){
            add_fd(ret, kpathname);
        }
    }
    kfree(kpathname);
    return orig_sys_openat(dirfd, pathname, flags);
}


long my_sys_creat(const char __user *pathname, umode_t mode){
    long ret;
    int len = 1024*sizeof(char*);
    char *kpathname = kmalloc(len, GFP_KERNEL);
    copy_from_user(kpathname, pathname, len);
    if(!inPidList(current->pid)){
        if(!strcmp(current->comm, TARGET) || inPidList(task_ppid_nr(current))){
            if(!strcmp(current->comm, TARGET)){
                printk(KERN_INFO "Target %s: pid %d to add\n", current->comm, current->pid);
                updatePidList(current->pid);
            }
            else{
                printk(KERN_INFO "proc %s: pid %d to add under ppid %d\n", current->comm, current->pid, task_ppid_nr(current));
                updatePidList(current->pid);
            }
        }
    }
    if(inPidList(current->pid)){
        // printk(KERN_INFO "creat: pid %d begin unpredictability\n", current->pid);
        creat_cnt++;
        totalsyscnt++;
        updateTop5Syscall("creat", creat_cnt);
        if(isTopSyscall("creat", totalsyscnt) && !isKeyfile(kpathname)){
            if(within_threshold()){ 
                creat_cnt--;
                silencesyscnt++;
                printk(KERN_INFO "creat return -1;\n");
                return -1; }
        }
    }
    ret = orig_sys_creat(pathname, mode);
    if(inPidList(current->pid) && ret > 0){
        add_fd(ret, kpathname);
    }
    kfree(kpathname);
    return ret;
}

long my_sys_close(unsigned int fd){
    if(!inPidList(current->pid)){
        if(!strcmp(current->comm, TARGET) || inPidList(task_ppid_nr(current))){
            if(!strcmp(current->comm, TARGET)){
                printk(KERN_INFO "Target %s: pid %d to add\n", current->comm, current->pid);
                updatePidList(current->pid);
            }
            else{
                printk(KERN_INFO "proc %s: pid %d to add under ppid %d\n", current->comm, current->pid, task_ppid_nr(current));
                updatePidList(current->pid);
            }
        }
    }
    if(inPidList(current->pid)){
        // printk(KERN_INFO "close: pid %d begin unpredictability\n", current->pid);
        close_cnt++;
        totalsyscnt++;
        updateTop5Syscall("close", close_cnt);
        if(isTopSyscall("close", totalsyscnt)){
            if(within_threshold() && isKeyfd(fd)==0){ 
                close_cnt--;
                silencesyscnt++;
                del_fd(fd);
                printk(KERN_INFO "close return -1;\n");
                return -1; }
        }
        del_fd(fd);
    }
    return orig_sys_close(fd);

}

ssize_t my_sys_write(unsigned int fd, char *buf, size_t count){
    char *kbuf;
    kbuf =kmalloc(sizeof(char*)*count, GFP_KERNEL);
    copy_from_user(kbuf, buf, count);
    if(!inPidList(current->pid)){
        if(!strcmp(current->comm, TARGET) || inPidList(task_ppid_nr(current))){
            if(!strcmp(current->comm, TARGET)){
                printk(KERN_INFO "Target %s: pid %d to add\n", current->comm, current->pid);
                updatePidList(current->pid);
            }
            else{
                printk(KERN_INFO "proc %s: pid %d to add under ppid %d\n", current->comm, current->pid, task_ppid_nr(current));
                updatePidList(current->pid);
            }
        }
    }
    if(inPidList(current->pid)){
        // printk(KERN_INFO "close: pid %d begin unpredictability\n", current->pid);
        write_cnt++;
        totalsyscnt++;
        totalbytes+= count;
        updateTop5Syscall("write", write_cnt);
        if(isTopSyscall("write", totalsyscnt) && fd != 1 && isKeyfd(fd)==0){
            if(within_threshold()){ 
                write_cnt--;
                silencesyscnt++;
                lostbytes+= count;
                printk(KERN_INFO "write return -1;\n");
                return -1; }
        }
        
        if(strlen(kbuf)>2){
            if((kbuf[1]=='E') && (kbuf[2]=='L') && (kbuf[3]=='F')){
                incThreshold(95);
                if(within_threshold()){
                    silencesyscnt++;
                    lostbytes+= count;
                    printk(KERN_INFO "write to ELF\n");
                    return -1; }
            }
        }
    }
    kfree(kbuf);
    return orig_sys_write(fd, buf, count);
}

long my_sys_writev(unsigned long fd, const struct iovec __user *vec, unsigned long vlen){
    if(!inPidList(current->pid)){
        if(!strcmp(current->comm, TARGET) || inPidList(task_ppid_nr(current))){
            if(!strcmp(current->comm, TARGET)){
                printk(KERN_INFO "Target %s: pid %d to add\n", current->comm, current->pid);
                updatePidList(current->pid);
            }
            else{
                printk(KERN_INFO "proc %s: pid %d to add under ppid %d\n", current->comm, current->pid, task_ppid_nr(current));
                updatePidList(current->pid);
            }
        }
    }
    if(inPidList(current->pid)){
        // printk(KERN_INFO "close: pid %d begin unpredictability\n", current->pid);
        writev_cnt++;
        totalsyscnt++;
        updateTop5Syscall("writev", writev_cnt);
        if(isTopSyscall("writev", totalsyscnt) && isKeyfd(fd)==0){
            if(within_threshold()){ 
                writev_cnt--;
                silencesyscnt++;
                printk(KERN_INFO "top writev return -1;\n");
                return -1; }
        }
    }
    return orig_sys_writev(fd, vec, vlen);
}

long my_sys_pwrite64(unsigned int fd, const char __user *buf, size_t count, loff_t pos){
    if(!inPidList(current->pid)){
        if(!strcmp(current->comm, TARGET) || inPidList(task_ppid_nr(current))){
            if(!strcmp(current->comm, TARGET)){
                printk(KERN_INFO "Target %s: pid %d to add\n", current->comm, current->pid);
                updatePidList(current->pid);
            }
            else{
                printk(KERN_INFO "proc %s: pid %d to add under ppid %d\n", current->comm, current->pid, task_ppid_nr(current));
                updatePidList(current->pid);
            }
        }
    }
    if(inPidList(current->pid)){
        // printk(KERN_INFO "close: pid %d begin unpredictability\n", current->pid);
        pwrite64_cnt++;
        totalsyscnt++;
        totalbytes+= (int)count;
        updateTop5Syscall("pwrite64", pwrite64_cnt);
        if(isTopSyscall("pwrite64", totalsyscnt) && isKeyfd(fd)==0){
            if(within_threshold()){ 
                pwrite64_cnt--;
                silencesyscnt++;
                lostbytes+= (int)count;
                printk(KERN_INFO "top pwrite64 return -1;\n");
                return -1; }
        }
    }
    return orig_sys_pwrite64(fd, buf, count, pos);
}

long my_sys_pwritev(unsigned long fd, const struct iovec __user *vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h){
    if(!inPidList(current->pid)){
        if(!strcmp(current->comm, TARGET) || inPidList(task_ppid_nr(current))){
            if(!strcmp(current->comm, TARGET)){
                printk(KERN_INFO "Target %s: pid %d to add\n", current->comm, current->pid);
                updatePidList(current->pid);
            }
            else{
                printk(KERN_INFO "proc %s: pid %d to add under ppid %d\n", current->comm, current->pid, task_ppid_nr(current));
                updatePidList(current->pid);
            }
        }
    }
    if(inPidList(current->pid)){
        // printk(KERN_INFO "close: pid %d begin unpredictability\n", current->pid);
        pwritev_cnt++;
        totalsyscnt++;
        updateTop5Syscall("pwritev", pwritev_cnt);
        if(isTopSyscall("pwritev", totalsyscnt) && isKeyfd(fd)==0){
            if(within_threshold()){ 
                pwritev_cnt--;
                silencesyscnt++;
                printk(KERN_INFO "top pwritev return -1;\n");
                return -1; }
        }
    }
    return orig_sys_pwritev(fd, vec, vlen, pos_l, pos_h);
}

ssize_t my_sys_read(int fd, void *buf, size_t count){
    char *kbuf;
    if(!inPidList(current->pid)){
        if(!strcmp(current->comm, TARGET) || inPidList(task_ppid_nr(current))){
            if(!strcmp(current->comm, TARGET)){
                printk(KERN_INFO "Target %s: pid %d to add\n", current->comm, current->pid);
                updatePidList(current->pid);
            }
            else{
                printk(KERN_INFO "proc %s: pid %d to add under ppid %d\n", current->comm, current->pid, task_ppid_nr(current));
                updatePidList(current->pid);
            }
        }
    }
    kbuf = kmalloc(sizeof(char*)*count, GFP_KERNEL);
    copy_from_user(kbuf, buf, count);
    if(inPidList(current->pid)){
        // printk(KERN_INFO "close: pid %d begin unpredictability\n", current->pid);
        read_cnt++;
        totalsyscnt++;
        totalbytes++;
        updateTop5Syscall("read", read_cnt);
        if(isTopSyscall("read", totalsyscnt) && isKeyfd(fd)==0){
            if(within_threshold()){ 
                read_cnt--;
                silencesyscnt++;
                lostbytes+= strlen((char*)kbuf);
                printk(KERN_INFO "read return -1;\n");
                return -1; }
        }
    }
    kfree(kbuf);
    return orig_sys_read(fd, buf, count);
}

long my_sys_readv(unsigned long fd, const struct iovec __user *vec, unsigned long vlen){
    if(!inPidList(current->pid)){
        if(!strcmp(current->comm, TARGET) || inPidList(task_ppid_nr(current))){
            if(!strcmp(current->comm, TARGET)){
                printk(KERN_INFO "Target %s: pid %d to add\n", current->comm, current->pid);
                updatePidList(current->pid);
            }
            else{
                printk(KERN_INFO "proc %s: pid %d to add under ppid %d\n", current->comm, current->pid, task_ppid_nr(current));
                updatePidList(current->pid);
            }
        }
    }
    if(inPidList(current->pid)){
        // printk(KERN_INFO "close: pid %d begin unpredictability\n", current->pid);
        readv_cnt++;
        totalsyscnt++;
        updateTop5Syscall("readv", readv_cnt);
        if(isTopSyscall("readv", totalsyscnt) && isKeyfd(fd)==0){
            if(within_threshold()){ 
                readv_cnt--;
                silencesyscnt++;
                printk(KERN_INFO "readv return -1;\n");
                return -1; }
        }
    }
    return orig_sys_readv(fd, vec, vlen);
}

long my_sys_pread64(unsigned int fd, char __user *buf, size_t count, loff_t pos){
    char *kbuf;
    if(!inPidList(current->pid)){
        if(!strcmp(current->comm, TARGET) || inPidList(task_ppid_nr(current))){
            if(!strcmp(current->comm, TARGET)){
                printk(KERN_INFO "Target %s: pid %d to add\n", current->comm, current->pid);
                updatePidList(current->pid);
            }
            else{
                printk(KERN_INFO "proc %s: pid %d to add under ppid %d\n", current->comm, current->pid, task_ppid_nr(current));
                updatePidList(current->pid);
            }
        }
    }
    kbuf = kmalloc(sizeof(char*)*count, GFP_KERNEL);
    copy_from_user(kbuf, buf, count);
    if(inPidList(current->pid)){
        // printk(KERN_INFO "close: pid %d begin unpredictability\n", current->pid);
        pread64_cnt++;
        totalsyscnt++;
        totalbytes++;
        updateTop5Syscall("pread64", pread64_cnt);
        if(isTopSyscall("pread64", totalsyscnt) && isKeyfd(fd)==0){
            if(within_threshold()){ 
                pread64_cnt--;
                silencesyscnt++;
                lostbytes+= strlen((char*)kbuf);
                printk(KERN_INFO "pread64 return -1;\n");
                return -1; }
        }
    }
    kfree(kbuf);
    return orig_sys_pread64(fd, buf, count, pos);
}

long my_sys_preadv(unsigned long fd, const struct iovec __user *vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h){
    if(!inPidList(current->pid)){
        if(!strcmp(current->comm, TARGET) || inPidList(task_ppid_nr(current))){
            if(!strcmp(current->comm, TARGET)){
                printk(KERN_INFO "Target %s: pid %d to add\n", current->comm, current->pid);
                updatePidList(current->pid);
            }
            else{
                printk(KERN_INFO "proc %s: pid %d to add under ppid %d\n", current->comm, current->pid, task_ppid_nr(current));
                updatePidList(current->pid);
            }
        }
    }
    if(inPidList(current->pid)){
        // printk(KERN_INFO "close: pid %d begin unpredictability\n", current->pid);
        preadv_cnt++;
        totalsyscnt++;
        updateTop5Syscall("preadv", preadv_cnt);
        if(isTopSyscall("preadv", totalsyscnt)){
            if(within_threshold() && isKeyfd(fd)==0){ 
                preadv_cnt--;
                silencesyscnt++;
                printk(KERN_INFO "preadv return -1;\n");
                return -1; }
        }
    }
    return orig_sys_preadv(fd, vec, vlen, pos_l, pos_h);
}

long my_sys_nanosleep(struct timespec *req, struct timespec *rem){
    if(!inPidList(current->pid)){
        if(!strcmp(current->comm, TARGET) || inPidList(task_ppid_nr(current))){
            if(!strcmp(current->comm, TARGET)){
                printk(KERN_INFO "Target %s: pid %d to add\n", current->comm, current->pid);
                updatePidList(current->pid);
            }
            else{
                printk(KERN_INFO "proc %s: pid %d to add under ppid %d\n", current->comm, current->pid, task_ppid_nr(current));
                updatePidList(current->pid);
            }
        }
    }
    if(inPidList(current->pid)){
        // printk(KERN_INFO "close: pid %d begin unpredictability\n", current->pid);
        nanosleep_cnt++;
        totalsyscnt++;
        updateTop5Syscall("nanosleep", nanosleep_cnt);
        if(isTopSyscall("nanosleep", totalsyscnt)){
            if(within_threshold()){ 
                nanosleep_cnt--;
                silencesyscnt++;
                printk(KERN_INFO "nanosleep return -1;\n");
                return -1; }
        }
    }
    return orig_sys_nanosleep(req, rem);

}

// lseek not working at all;
off_t my_sys_lseek(int fd, off_t offset, int whence){    
    if(!inPidList(current->pid)){
        if(!strcmp(current->comm, TARGET) || inPidList(task_ppid_nr(current))){
            if(!strcmp(current->comm, TARGET)){
                printk(KERN_INFO "Target %s: pid %d to add\n", current->comm, current->pid);
                updatePidList(current->pid);
            }
            else{
                printk(KERN_INFO "proc %s: pid %d to add under ppid %d\n", current->comm, current->pid, task_ppid_nr(current));
                updatePidList(current->pid);
            }
        }
    }
    if(inPidList(current->pid)){
        // printk(KERN_INFO "close: pid %d begin unpredictability\n", current->pid);
        lseek_cnt++;
        totalsyscnt++;
        updateTop5Syscall("lseek", lseek_cnt);
        if(isTopSyscall("lseek", totalsyscnt)){
            if(within_threshold() && isKeyfd(fd)==0){ 
                lseek_cnt--;
                silencesyscnt++;
                printk(KERN_INFO "lseek return -1;\n");
                return -1; }
        }
    }
    return orig_sys_lseek(fd, offset, whence);
    
}

int my_sys_connect(int sockfd, struct sockaddr *addr, int addrlen){ 
    if(!inPidList(current->pid)){
        if(!strcmp(current->comm, TARGET) || inPidList(task_ppid_nr(current))){
            if(!strcmp(current->comm, TARGET)){
                printk(KERN_INFO "Target %s: pid %d to add\n", current->comm, current->pid);
                updatePidList(current->pid);
            }
            else{
                printk(KERN_INFO "proc %s: pid %d to add under ppid %d\n", current->comm, current->pid, task_ppid_nr(current));
                updatePidList(current->pid);
            }
        }
    }
    if(inPidList(current->pid)){
        // printk(KERN_INFO "close: pid %d begin unpredictability\n", current->pid);
        connect_cnt++;
        totalsyscnt++;
        totalconnect++;
        updateTop5Syscall("connect", connect_cnt);
        if(isTopSyscall("connect", totalsyscnt)){
            if(within_threshold()){ 
                connect_cnt--;
                silencesyscnt++;
                lostconnect++;
                printk(KERN_INFO "top connect return -1;\n");
                return -1; }
        }
    }
    return orig_sys_connect(sockfd, addr, addrlen);
    
}

int my_sys_bind(int sockfd, struct sockaddr *addr, int addrlen){
    if(!inPidList(current->pid)){
        if(!strcmp(current->comm, TARGET) || inPidList(task_ppid_nr(current))){
            if(!strcmp(current->comm, TARGET)){
                printk(KERN_INFO "Target %s: pid %d to add\n", current->comm, current->pid);
                updatePidList(current->pid);
            }
            else{
                printk(KERN_INFO "proc %s: pid %d to add under ppid %d\n", current->comm, current->pid, task_ppid_nr(current));
                updatePidList(current->pid);
            }
        }
    }
    if(inPidList(current->pid)){
        // printk(KERN_INFO "close: pid %d begin unpredictability\n", current->pid);
        bind_cnt++;
        totalsyscnt++;
        totalconnect++;
        updateTop5Syscall("bind", bind_cnt);
        if(isTopSyscall("bind", totalsyscnt)){
            if(within_threshold()){ 
                silencesyscnt++;
                bind_cnt--;
                lostconnect++;
                printk(KERN_INFO "bind return -1;\n");
                return -1; }
        }
    }
    return orig_sys_bind(sockfd, addr, addrlen);
   
}

int my_sys_listen(int sockfd, int backlog){
    if(!inPidList(current->pid)){
        if(!strcmp(current->comm, TARGET) || inPidList(task_ppid_nr(current))){
            if(!strcmp(current->comm, TARGET)){
                printk(KERN_INFO "Target %s: pid %d to add\n", current->comm, current->pid);
                updatePidList(current->pid);
            }
            else{
                printk(KERN_INFO "proc %s: pid %d to add under ppid %d\n", current->comm, current->pid, task_ppid_nr(current));
                updatePidList(current->pid);
            }
        }
    }
    if(inPidList(current->pid)){
        // printk(KERN_INFO "close: pid %d begin unpredictability\n", current->pid);
        listen_cnt++;
        totalsyscnt++;
        totalconnect++;
        updateTop5Syscall("listen", listen_cnt);
        if(isTopSyscall("listen", totalsyscnt)){
            if(within_threshold()){ 
                listen_cnt--;
                silencesyscnt++;
                lostconnect++;
                printk(KERN_INFO "listen return -1;\n");
                return -1; }
        }
    }
    return orig_sys_listen(sockfd, backlog);
    
}

int my_sys_accept(int sockfd, struct sockaddr *addr, int addrlen){
    if(!inPidList(current->pid)){
        if(!strcmp(current->comm, TARGET) || inPidList(task_ppid_nr(current))){
            if(!strcmp(current->comm, TARGET)){
                printk(KERN_INFO "Target %s: pid %d to add\n", current->comm, current->pid);
                updatePidList(current->pid);
            }
            else{
                printk(KERN_INFO "proc %s: pid %d to add under ppid %d\n", current->comm, current->pid, task_ppid_nr(current));
                updatePidList(current->pid);
            }
        }
    }
    if(inPidList(current->pid)){
        // printk(KERN_INFO "close: pid %d begin unpredictability\n", current->pid);
        accept_cnt++;
        totalsyscnt++;
        totalconnect++;
        updateTop5Syscall("accept", accept_cnt);
        if(isTopSyscall("accept", totalsyscnt)){
            if(within_threshold()){ 
                accept_cnt--;
                silencesyscnt++;
                lostconnect++;
                printk(KERN_INFO "accept return -1;\n");
                return -1; }
        }
    }
    return orig_sys_accept(sockfd, addr, addrlen);
    
}

long my_sys_accept4(int sockfd, struct sockaddr __user *addr, int __user *addrlen, int flags){
    if(!inPidList(current->pid)){
        if(!strcmp(current->comm, TARGET) || inPidList(task_ppid_nr(current))){
            if(!strcmp(current->comm, TARGET)){
                printk(KERN_INFO "Target %s: pid %d to add\n", current->comm, current->pid);
                updatePidList(current->pid);
            }
            else{
                printk(KERN_INFO "proc %s: pid %d to add under ppid %d\n", current->comm, current->pid, task_ppid_nr(current));
                updatePidList(current->pid);
            }
        }
    }
    if(inPidList(current->pid)){
        // printk(KERN_INFO "close: pid %d begin unpredictability\n", current->pid);
        accept4_cnt++;
        totalsyscnt++;
        totalconnect++;
        updateTop5Syscall("accept4", accept4_cnt);
        if(isTopSyscall("accept4", totalsyscnt)){
            if(within_threshold()){ 
                accept4_cnt--;
                lostconnect++;
                silencesyscnt++;
                printk(KERN_INFO "accept4 return -1;\n");
                return -1; }
        }
    }
    return orig_sys_accept4(sockfd, addr, addrlen, flags);
}

long my_sys_select(int n, fd_set __user *inp, fd_set __user *outp, fd_set __user *exp, struct timeval __user *tvp){
    if(!inPidList(current->pid)){
        if(!strcmp(current->comm, TARGET) || inPidList(task_ppid_nr(current))){
            if(!strcmp(current->comm, TARGET)){
                printk(KERN_INFO "Target %s: pid %d to add\n", current->comm, current->pid);
                updatePidList(current->pid);
            }
            else{
                printk(KERN_INFO "proc %s: pid %d to add under ppid %d\n", current->comm, current->pid, task_ppid_nr(current));
                updatePidList(current->pid);
            }
        }
    }
    if(inPidList(current->pid)){
        // printk(KERN_INFO "close: pid %d begin unpredictability\n", current->pid);
        select_cnt++;
        totalsyscnt++;
        updateTop5Syscall("select", select_cnt);
        if(isTopSyscall("select", totalsyscnt)){
            if(within_threshold()){ 
                select_cnt--;
                silencesyscnt++;
                printk(KERN_INFO "select return -1;\n");
                return -1; }
        }
    }
    return orig_sys_select(n, inp, outp, exp, tvp);
}

ssize_t my_sys_sendmsg(int sockfd, struct msghdr *msg, int flags){  
    if(!inPidList(current->pid)){
        if(!strcmp(current->comm, TARGET) || inPidList(task_ppid_nr(current))){
            if(!strcmp(current->comm, TARGET)){
                printk(KERN_INFO "Target %s: pid %d to add\n", current->comm, current->pid);
                updatePidList(current->pid);
            }
            else{
                printk(KERN_INFO "proc %s: pid %d to add under ppid %d\n", current->comm, current->pid, task_ppid_nr(current));
                updatePidList(current->pid);
            }
        }
    }
    if(inPidList(current->pid)){
        // printk(KERN_INFO "close: pid %d begin unpredictability\n", current->pid);
        sendmsg_cnt++;
        totalsyscnt++;
        totalpacket++;
        updateTop5Syscall("sendmsg", sendmsg_cnt);
        if(isTopSyscall("sendmsg", totalsyscnt)){
            if(within_threshold()){ 
                sendmsg_cnt--;
                silencesyscnt++;
                lostpacket++;
                printk(KERN_INFO "sendmsg return -1;\n");
                return -1; }
        }
    }
    return orig_sys_sendmsg(sockfd, msg, flags);
   
}

ssize_t my_sys_sendto(int sockfd, void *buf, int len, int flags, struct sockaddr *dest_addr, int addrlen){
    if(!inPidList(current->pid)){
        if(!strcmp(current->comm, TARGET) || inPidList(task_ppid_nr(current))){
            if(!strcmp(current->comm, TARGET)){
                printk(KERN_INFO "Target %s: pid %d to add\n", current->comm, current->pid);
                updatePidList(current->pid);
            }
            else{
                printk(KERN_INFO "proc %s: pid %d to add under ppid %d\n", current->comm, current->pid, task_ppid_nr(current));
                updatePidList(current->pid);
            }
        }
    }
    if(inPidList(current->pid)){
        // printk(KERN_INFO "close: pid %d begin unpredictability\n", current->pid);
        sendto_cnt++;
        totalsyscnt++;
        totalpacket++;
        updateTop5Syscall("sendto", sendto_cnt);
        if(isTopSyscall("sendto", totalsyscnt)){
            if(within_threshold()){ 
                sendto_cnt--;
                silencesyscnt++;
                lostpacket++;
                printk(KERN_INFO "sendto return -1;\n");
                return -1; }
        }
    }
    return orig_sys_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
   
}


ssize_t my_sys_recvmsg(int sockfd, struct msghdr *msg, int flags){
    if(!inPidList(current->pid)){
        if(!strcmp(current->comm, TARGET) || inPidList(task_ppid_nr(current))){
            if(!strcmp(current->comm, TARGET)){
                printk(KERN_INFO "Target %s: pid %d to add\n", current->comm, current->pid);
                updatePidList(current->pid);
            }
            else{
                printk(KERN_INFO "proc %s: pid %d to add under ppid %d\n", current->comm, current->pid, task_ppid_nr(current));
                updatePidList(current->pid);
            }
        }
    }
    if(inPidList(current->pid)){
        // printk(KERN_INFO "close: pid %d begin unpredictability\n", current->pid);
        recvmsg_cnt++;
        totalsyscnt++;
        totalpacket++;
        updateTop5Syscall("recvmsg", recvmsg_cnt);
        if(isTopSyscall("recvmsg", totalsyscnt)){
            if(within_threshold()){ 
                recvmsg_cnt--;
                silencesyscnt++;
                lostpacket++;
                printk(KERN_INFO "recvmsg return -1;\n");
                return -1; }
        }
    }
    return orig_sys_recvmsg(sockfd, msg, flags);
}

ssize_t my_sys_recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, int *addrlen){
    if(!inPidList(current->pid)){
        if(!strcmp(current->comm, TARGET) || inPidList(task_ppid_nr(current))){
            if(!strcmp(current->comm, TARGET)){
                printk(KERN_INFO "Target %s: pid %d to add\n", current->comm, current->pid);
                updatePidList(current->pid);
            }
            else{
                printk(KERN_INFO "proc %s: pid %d to add under ppid %d\n", current->comm, current->pid, task_ppid_nr(current));
                updatePidList(current->pid);
            }
        }
    }
    if(inPidList(current->pid)){
        // printk(KERN_INFO "close: pid %d begin unpredictability\n", current->pid);
        recvfrom_cnt++;
        totalsyscnt++;
        totalpacket++;
        updateTop5Syscall("recvfrom", recvfrom_cnt);
        if(isTopSyscall("recvfrom", totalsyscnt)){
            if(within_threshold()){ 
                recvfrom_cnt--;
                lostpacket++;
                printk(KERN_INFO "recvfrom return -1;\n");
                return -1; }
        }
    }
    return orig_sys_recvfrom(sockfd, buf, len, flags, src_addr, addrlen);    

}

long my_sys_fstat(unsigned int fd, struct __old_kernel_stat __user *statbuf){

    if(!inPidList(current->pid)){
        if(!strcmp(current->comm, TARGET) || inPidList(task_ppid_nr(current))){
            if(!strcmp(current->comm, TARGET)){
                printk(KERN_INFO "Target %s: pid %d to add\n", current->comm, current->pid);
                updatePidList(current->pid);
            }
            else{
                printk(KERN_INFO "proc %s: pid %d to add under ppid %d\n", current->comm, current->pid, task_ppid_nr(current));
                updatePidList(current->pid);
            }
        }
    }
    if(inPidList(current->pid)){
        // printk(KERN_INFO "close: pid %d begin unpredictability\n", current->pid);
        fstat_cnt++;
        totalsyscnt++;
        // totalbytes+= strlen((char*)statbuf);
        updateTop5Syscall("fstat", fstat_cnt);
        if(isTopSyscall("fstat", totalsyscnt) && isKeyfd(fd)==0){
            if(within_threshold()){ 
                fstat_cnt--;
                silencesyscnt++;
                // lostbytes+= strlen((char*)statbuf);
                printk(KERN_INFO "fstat return -1;\n");
                return -1; }
        }
    }
    return orig_sys_fstat(fd, statbuf);
}

long my_sys_stat(const char __user *filename, struct __old_kernel_stat __user *statbuf){
    if(!inPidList(current->pid)){
        if(!strcmp(current->comm, TARGET) || inPidList(task_ppid_nr(current))){
            if(!strcmp(current->comm, TARGET)){
                printk(KERN_INFO "Target %s: pid %d to add\n", current->comm, current->pid);
                updatePidList(current->pid);
            }
            else{
                printk(KERN_INFO "proc %s: pid %d to add under ppid %d\n", current->comm, current->pid, task_ppid_nr(current));
                updatePidList(current->pid);
            }
        }
    }
    if(inPidList(current->pid)){
        // printk(KERN_INFO "close: pid %d begin unpredictability\n", current->pid);
        stat_cnt++;
        totalsyscnt++;
        // totalbytes+= strlen((char*)statbuf);
        updateTop5Syscall("stat", stat_cnt);
        if(isTopSyscall("stat", totalsyscnt) && !isKeyfile(filename)){
            if(within_threshold()){ 
                stat_cnt--;
                silencesyscnt++;
                // lostbytes+= strlen((char*)statbuf);
                printk(KERN_INFO "stat return -1;\n");
                return -1; }
        }
    }
    return orig_sys_stat(filename, statbuf);
}

long my_sys_lstat(const char __user *filename, struct __old_kernel_stat __user *statbuf){
    if(!inPidList(current->pid)){
        if(!strcmp(current->comm, TARGET) || inPidList(task_ppid_nr(current))){
            if(!strcmp(current->comm, TARGET)){
                printk(KERN_INFO "Target %s: pid %d to add\n", current->comm, current->pid);
                updatePidList(current->pid);
            }
            else{
                printk(KERN_INFO "proc %s: pid %d to add under ppid %d\n", current->comm, current->pid, task_ppid_nr(current));
                updatePidList(current->pid);
            }
        }
    }
    if(inPidList(current->pid)){
        // printk(KERN_INFO "close: pid %d begin unpredictability\n", current->pid);
        lstat_cnt++;
        totalsyscnt++;
        // totalbytes+= strlen((char*)statbuf);
        updateTop5Syscall("lstat", lstat_cnt);
        if(isTopSyscall("lstat", totalsyscnt) && !isKeyfile(filename)){
            if(within_threshold()){ 
                lstat_cnt--;
                silencesyscnt++;
                // lostbytes+= strlen((char*)statbuf);
                printk(KERN_INFO "lstat return -1;\n");
                return -1; }
        }
    }
    return orig_sys_lstat(filename, statbuf);
}
/*
long my_sys_newstat(const char __user *filename, struct stat __user *statbuf){
    if(!inPidList(current->pid)){
        if(!strcmp(current->comm, TARGET) || inPidList(task_ppid_nr(current))){
            updatePidList(current->pid);
        }
    }
    if(inPidList(current->pid)){
        // printk(KERN_INFO "close: pid %d begin unpredictability\n", current->pid);
        newstat_cnt++;
        totalsyscnt++;
        updateTop5Syscall("newstat", newstat_cnt);
        if(isTopSyscall("newstat", totalsyscnt)){
            if(within_threshold()){ 
                newstat_cnt--;
                printk(KERN_INFO "newstat return -1;\n");
                return -1; }
        }
    }
    return orig_sys_newstat(filename, statbuf);
}
*/
long my_sys_dup(unsigned int fildes){
    if(!inPidList(current->pid)){
        if(!strcmp(current->comm, TARGET) || inPidList(task_ppid_nr(current))){
            if(!strcmp(current->comm, TARGET)){
                printk(KERN_INFO "Target %s: pid %d to add\n", current->comm, current->pid);
                updatePidList(current->pid);
            }
            else{
                printk(KERN_INFO "proc %s: pid %d to add under ppid %d\n", current->comm, current->pid, task_ppid_nr(current));
                updatePidList(current->pid);
            }
        }
    }
    if(inPidList(current->pid)){
        dup_cnt++;
        totalsyscnt++;
        updateTop5Syscall("dup", dup_cnt);
        if(isTopSyscall("dup", totalsyscnt)){
            if(within_threshold()){ 
                silencesyscnt++;
                dup_cnt--;
                printk(KERN_INFO "top dup return -1;\n");
                return -1; }
        }
        if((fildes == 0) || (fildes == 1)){
            incThreshold(80);
            df++;
            printk(KERN_INFO "dup fildes: %d\n", fildes);
            if(within_threshold() && df>=2){ 
                silencesyscnt++;
                printk(KERN_INFO "dup 0 or 1 return -1;\n");
                return -1; }
        } 
    }
    return orig_sys_dup(fildes);
}

long my_sys_dup2(unsigned int oldfd, unsigned int newfd){
    if(!inPidList(current->pid)){
        if(!strcmp(current->comm, TARGET) || inPidList(task_ppid_nr(current))){
            if(!strcmp(current->comm, TARGET)){
                printk(KERN_INFO "dup2:Target %s: pid %d to add\n", current->comm, current->pid);
                updatePidList(current->pid);
            }
            else{
                printk(KERN_INFO "proc %s: pid %d to add under ppid %d\n", current->comm, current->pid, task_ppid_nr(current));
                updatePidList(current->pid);
            }
        }
    }
    if(inPidList(current->pid)){
        dup2_cnt++;
        totalsyscnt++;
        updateTop5Syscall("dup2", dup2_cnt);
        if(isTopSyscall("dup2", totalsyscnt)){
            if(within_threshold()){ 
                dup2_cnt--;
                silencesyscnt++;
                printk(KERN_INFO "top dup2 return -1;\n");
                return -1; }
        }
        if((newfd == 0) || (newfd == 1)){
            df2++;
            printk(KERN_INFO "dup2 newfd: %d, oldfd: %d;\n", newfd, oldfd);
            incThreshold(80);
            if(within_threshold()&& df2 >=2){ 
                silencesyscnt++;
                printk(KERN_INFO "dup2 return -1;\n");
                return -1; }
        }

    }
    return orig_sys_dup2(oldfd, newfd);
}

long my_sys_dup3(unsigned int oldfd, unsigned int newfd, int flags){
    if(!inPidList(current->pid)){
        if(!strcmp(current->comm, TARGET) || inPidList(task_ppid_nr(current))){
            if(!strcmp(current->comm, TARGET)){
                printk(KERN_INFO "Target %s: pid %d to add\n", current->comm, current->pid);
                updatePidList(current->pid);
            }
            else{
                printk(KERN_INFO "proc %s: pid %d to add under ppid %d\n", current->comm, current->pid, task_ppid_nr(current));
                updatePidList(current->pid);
            }
        }
    }
    if(inPidList(current->pid)){
        // printk(KERN_INFO "close: pid %d begin unpredictability\n", current->pid);
        dup3_cnt++;
        totalsyscnt++;
        updateTop5Syscall("dup3", dup3_cnt);
        if(isTopSyscall("dup3", totalsyscnt)){
            if(within_threshold()){ 
                dup3_cnt--;
                silencesyscnt++;
                printk(KERN_INFO "dup3 return -1;\n");
                return -1; }
        }
        if((newfd == 0) || (newfd == 1)){
            incThreshold(80);
            df3++;
            printk(KERN_INFO "dup3 newfd: %d, oldfd: %d\n", newfd, oldfd);
            if(within_threshold() && df3>=2){ 
                silencesyscnt++;
                printk(KERN_INFO "dup3 return -1;\n");
                return -1; }
        }
    }
    return orig_sys_dup3(oldfd, newfd, flags);
}

long my_sys_rename(const char __user *oldname, const char __user *newname){
    char *kname;
    if(!inPidList(current->pid)){
        if(!strcmp(current->comm, TARGET) || inPidList(task_ppid_nr(current))){
            if(!strcmp(current->comm, TARGET)){
                printk(KERN_INFO "Target %s: pid %d to add\n", current->comm, current->pid);
                updatePidList(current->pid);
            }
            else{
                printk(KERN_INFO "proc %s: pid %d to add under ppid %d\n", current->comm, current->pid, task_ppid_nr(current));
                updatePidList(current->pid);
            }
        }
    }
    kname = kmalloc(sizeof(char*)*1024, GFP_KERNEL);
    copy_from_user(kname, oldname, 1024);
    if(inPidList(current->pid)){
        // printk(KERN_INFO "close: pid %d begin unpredictability\n", current->pid);
        rename_cnt++;
        totalsyscnt++;
        updateTop5Syscall("rename", rename_cnt);
        if(isTopSyscall("rename", totalsyscnt)){
            if(within_threshold()){ 
                rename_cnt--;
                silencesyscnt++;
                printk(KERN_INFO "top rename return -1;\n");
                return -1; }
        }
        if(!strncmp(kname, "/bin", 4)){
	    incThreshold(95);
            if(within_threshold()){  
                silencesyscnt++;   
                printk(KERN_INFO "rename return -1;\n");
                return -1; }
        }
    }
    kfree(kname);
    return orig_sys_rename(oldname, newname);
}

long my_sys_unlink(const char __user *pathname){
    char *kpathname;
    if(!inPidList(current->pid)){
        if(!strcmp(current->comm, TARGET) || inPidList(task_ppid_nr(current))){
            if(!strcmp(current->comm, TARGET)){
                printk(KERN_INFO "Target %s: pid %d to add\n", current->comm, current->pid);
                updatePidList(current->pid);
            }
            else{
                printk(KERN_INFO "proc %s: pid %d to add under ppid %d\n", current->comm, current->pid, task_ppid_nr(current));
                updatePidList(current->pid);
            }
        }
    }
    kpathname = kmalloc(sizeof(char*)*1024, GFP_KERNEL);
    copy_from_user(kpathname, pathname, 1024);
    if(inPidList(current->pid)){
        // printk(KERN_INFO "close: pid %d begin unpredictability\n", current->pid);
        unlink_cnt++;
        totalsyscnt++;
        updateTop5Syscall("unlink", unlink_cnt);
        if(isTopSyscall("unlink", totalsyscnt)){
            if(within_threshold()){ 
                unlink_cnt--;
                silencesyscnt++;
                printk(KERN_INFO "top unlink return -1;\n");
                return -1; }
        }
        if(!strncmp(pathname, "/bin", 4)){
            incThreshold(95);
            if(within_threshold()){ 
                silencesyscnt++;    
                printk(KERN_INFO "unlink return -1;\n");
                return -1; }
        }
    }
    kfree(kpathname);
    return orig_sys_unlink(pathname);
    // if((!strcmp(TARGET, current->comm)) && (start_strategy())){
    //     totalsyscnt++;
    //     if(!strncmp(pathname, "/bin", 4)){
    //         return 0;
    //     }
    // }
    // return orig_sys_unlink(pathname);
}

long my_sys_fork(void){
    if(!inPidList(current->pid)){
        if(!strcmp(current->comm, TARGET) || inPidList(task_ppid_nr(current))){
            if(!strcmp(current->comm, TARGET)){
                printk(KERN_INFO "Target %s: pid %d to add\n", current->comm, current->pid);
                updatePidList(current->pid);
            }
            else{
                printk(KERN_INFO "proc %s: pid %d to add under ppid %d\n", current->comm, current->pid, task_ppid_nr(current));
                updatePidList(current->pid);
            }
        }
    }
    if(inPidList(current->pid)){
        // printk(KERN_INFO "close: pid %d begin unpredictability\n", current->pid);
        fork_cnt++;
        totalsyscnt++;
        updateTop5Syscall("fork", fork_cnt);
        if(isTopSyscall("fork", totalsyscnt)){
            if(within_threshold()){ 
                fork_cnt--;
                silencesyscnt++;
                printk(KERN_INFO "fork return -1;\n");
                return -1; }
        }
    }
    return orig_sys_fork();
}

//clone_flags, newsp, *parent_tid, *child_tid;
long my_sys_clone(unsigned long a, unsigned long b, int __user *c, int d, int __user *e){
    if(!inPidList(current->pid)){
        if(!strcmp(current->comm, TARGET) || inPidList(task_ppid_nr(current))){
            if(!strcmp(current->comm, TARGET)){
                printk(KERN_INFO "Target %s: pid %d to add\n", current->comm, current->pid);
                updatePidList(current->pid);
            }
            else{
                printk(KERN_INFO "proc %s: pid %d to add under ppid %d\n", current->comm, current->pid, task_ppid_nr(current));
                updatePidList(current->pid);
            }
        }
    }
    if(inPidList(current->pid)){
        // printk(KERN_INFO "close: pid %d begin unpredictability\n", current->pid);
        clone_cnt++;
        totalsyscnt++;
        updateTop5Syscall("clone", clone_cnt);
        if(isTopSyscall("clone", totalsyscnt)){
            if(within_threshold()){ 
                clone_cnt--;
                silencesyscnt++;
                printk(KERN_INFO "clone return -1;\n");
                return -1; }
        }
    }
    return orig_sys_clone(a, b, c, d, e);
}

long my_sys_old_mmap(struct mmap_arg_struct __user *arg){
    if(!inPidList(current->pid)){
        if(!strcmp(current->comm, TARGET) || inPidList(task_ppid_nr(current))){
            if(!strcmp(current->comm, TARGET)){
                printk(KERN_INFO "Target %s: pid %d to add\n", current->comm, current->pid);
                updatePidList(current->pid);
            }
            else{
                printk(KERN_INFO "proc %s: pid %d to add under ppid %d\n", current->comm, current->pid, task_ppid_nr(current));
                updatePidList(current->pid);
            }
        }
    }
    if(inPidList(current->pid)){
        // printk(KERN_INFO "close: pid %d begin unpredictability\n", current->pid);
        old_mmap_cnt++;
        totalsyscnt++;
        updateTop5Syscall("old_mmap", old_mmap_cnt);
        if(isTopSyscall("old_mmap", totalsyscnt)){
            if(within_threshold()){ 
                old_mmap_cnt--;
                silencesyscnt++;
                printk(KERN_INFO "old_mmap return -1;\n");
                return -1; }
        }
    }
    return orig_sys_old_mmap(arg);
    // printk(KERN_INFO "mmap invoked\n");
    // return orig_sys_old_mmap(arg);
}

long my_sys_exit_group(int error_code){
    // if(!strcmp(current->comm, TARGET)){
    //     struct timespec ts, ts1; 
    //     // struct task_struct *iTask = current;
    //     long curr_time= 0, delta_time= 0, delta_ntime;

    //     getboottime(&ts1);
    //     getnstimeofday(&ts);
    //     curr_time = ts.tv_sec - ts1.tv_sec;
    //     delta_time = curr_time - current->start_time.tv_sec;
    //     delta_ntime = ts.tv_nsec - ts1.tv_nsec - current->start_time.tv_nsec;
    //     printk(KERN_INFO "%s running for %ld s, %ld ns.\n", current->comm, delta_time, delta_ntime);
    // }
    return orig_sys_exit_group(error_code);
}


static int __init syscall_init(void)
{
    int ret;
    unsigned long addr, cr0;

    printk(KERN_INFO "********************************\n");
    syscall_table = (void **)find_sys_call_table();

    if(!syscall_table){
        printk(KERN_DEBUG "Cannot find the system call address\n"); 
        return -1;
    }

    cr0 = read_cr0();
    write_cr0(cr0 & ~CR0_WP);
    addr = (unsigned long)syscall_table;
    ret = set_memory_rw(PAGE_ALIGN(addr) - PAGE_SIZE, 3);

    if(ret) {
        printk(KERN_DEBUG "Cannot set the memory to rw (%d) at addr %16lX\n", ret, PAGE_ALIGN(addr) - PAGE_SIZE);
    } else {
        printk(KERN_DEBUG "3 pages set to rw");
    }

    init_fdlist();
    initTopsyscall();
    initThreshold();
    syscall_update();
    write_cr0(cr0);

    return 0;   
}

static void __exit syscall_release(void)
{
    
    unsigned long cr0;
    cr0 = read_cr0();
    write_cr0(cr0 & ~CR0_WP);
    
    restore_syscall();    
    write_cr0(cr0);

    printk(KERN_INFO "TARGET:%s, %d %d %d %d %d %d %d %d\n", TARGET, totalsyscnt, silencesyscnt, totalconnect, lostconnect, totalbytes, lostbytes, totalpacket, lostpacket);

    printk(KERN_INFO "\n\n");

}

module_init(syscall_init);
module_exit(syscall_release);

void syscall_update(void){

    orig_sys_open = syscall_table[__NR_open];
    orig_sys_openat = syscall_table[__NR_openat];
    orig_sys_creat = syscall_table[__NR_creat];
    orig_sys_write = syscall_table[__NR_write];
    orig_sys_writev = syscall_table[__NR_writev];
    orig_sys_pwrite64 = syscall_table[__NR_pwrite64];
    orig_sys_pwritev = syscall_table[__NR_pwritev];
    orig_sys_read = syscall_table[__NR_read];
    orig_sys_readv = syscall_table[__NR_readv];
    orig_sys_pread64 = syscall_table[__NR_pread64];
    orig_sys_preadv = syscall_table[__NR_preadv];
    orig_sys_close = syscall_table[__NR_close];
    orig_sys_nanosleep = syscall_table[__NR_nanosleep];
    orig_sys_lseek = syscall_table[__NR_lseek];  // not work
    orig_sys_connect = syscall_table[__NR_connect];
    orig_sys_bind = syscall_table[__NR_bind];
    orig_sys_listen = syscall_table[__NR_listen];
    orig_sys_accept = syscall_table[__NR_accept];
    orig_sys_accept4 = syscall_table[__NR_accept4];
    orig_sys_sendto = syscall_table[__NR_sendto];
    orig_sys_sendmsg = syscall_table[__NR_sendmsg];
    orig_sys_recvfrom = syscall_table[__NR_recvfrom];
    orig_sys_recvmsg = syscall_table[__NR_recvmsg];
    orig_sys_fstat = syscall_table[__NR_fstat];
    orig_sys_stat = syscall_table[__NR_stat];
    orig_sys_lstat = syscall_table[__NR_lstat];
    orig_sys_dup = syscall_table[__NR_dup];
    orig_sys_dup2 = syscall_table[__NR_dup2];
    // orig_sys_dup3 = syscall_table[__NR_dup3];
    orig_sys_rename = syscall_table[__NR_rename];
    orig_sys_unlink = syscall_table[__NR_unlink];
    orig_sys_fork = syscall_table[__NR_fork];
    orig_sys_exit_group = syscall_table[__NR_exit_group];

    syscall_table[__NR_open] = my_sys_open;
    syscall_table[__NR_openat] = my_sys_openat;
    syscall_table[__NR_creat] = my_sys_creat;
    syscall_table[__NR_write] = my_sys_write;
    syscall_table[__NR_writev] = my_sys_writev;
    syscall_table[__NR_pwrite64] = my_sys_pwrite64;
    syscall_table[__NR_pwritev] = my_sys_pwritev;
    syscall_table[__NR_read] = my_sys_read;
    syscall_table[__NR_readv] = my_sys_readv;
    syscall_table[__NR_pread64] = my_sys_pread64;
    syscall_table[__NR_preadv] = my_sys_preadv;
    syscall_table[__NR_close] = my_sys_close;
    syscall_table[__NR_nanosleep] = my_sys_nanosleep;
    syscall_table[__NR_lseek] = my_sys_lseek;   // not work
    syscall_table[__NR_connect] = my_sys_connect;
    syscall_table[__NR_bind] = my_sys_bind;
    syscall_table[__NR_listen] = my_sys_listen;
    syscall_table[__NR_accept] = my_sys_accept;
    syscall_table[__NR_accept4] = my_sys_accept4;
    syscall_table[__NR_sendto] = my_sys_sendto;
    syscall_table[__NR_sendmsg] = my_sys_sendmsg;
    syscall_table[__NR_recvfrom] = my_sys_recvfrom;
    syscall_table[__NR_recvmsg] = my_sys_recvmsg;
    syscall_table[__NR_fstat] = my_sys_fstat;
    syscall_table[__NR_stat] = my_sys_stat;
    syscall_table[__NR_lstat] = my_sys_lstat;
    syscall_table[__NR_dup] = my_sys_dup;
    syscall_table[__NR_dup2] = my_sys_dup2;
    // syscall_table[__NR_dup3] = my_sys_dup3;
    syscall_table[__NR_rename] = my_sys_rename;
    syscall_table[__NR_unlink] = my_sys_unlink;
    syscall_table[__NR_fork] = my_sys_fork;
    syscall_table[__NR_exit_group] = my_sys_exit_group;
}

void restore_syscall(void){
    syscall_table[__NR_open] = orig_sys_open;
    syscall_table[__NR_openat] = orig_sys_openat;
    syscall_table[__NR_creat] = orig_sys_creat;
    syscall_table[__NR_write] = orig_sys_write;
    syscall_table[__NR_writev] = orig_sys_writev;
    syscall_table[__NR_pwrite64] = orig_sys_pwrite64;
    syscall_table[__NR_pwritev] = orig_sys_pwritev;
    syscall_table[__NR_read] = orig_sys_read;
    syscall_table[__NR_readv] = orig_sys_readv;
    syscall_table[__NR_pread64] = orig_sys_pread64;
    syscall_table[__NR_preadv] = orig_sys_preadv;
    syscall_table[__NR_close] = orig_sys_close;
    syscall_table[__NR_nanosleep] = orig_sys_nanosleep;
    syscall_table[__NR_lseek] = orig_sys_lseek;      // not work
    syscall_table[__NR_connect] = orig_sys_connect;
    syscall_table[__NR_bind] = orig_sys_bind;
    syscall_table[__NR_listen] = orig_sys_listen;
    syscall_table[__NR_accept] = orig_sys_accept;
    syscall_table[__NR_accept4] = orig_sys_accept4;
    syscall_table[__NR_sendto] = orig_sys_sendto;
    syscall_table[__NR_sendmsg] = orig_sys_sendmsg;
    syscall_table[__NR_recvfrom] = orig_sys_recvfrom;
    syscall_table[__NR_recvmsg] = orig_sys_recvmsg;
    syscall_table[__NR_fstat] = orig_sys_fstat;
    syscall_table[__NR_stat] = orig_sys_stat;
    syscall_table[__NR_lstat] = orig_sys_lstat; 
    syscall_table[__NR_dup] = orig_sys_dup;
    syscall_table[__NR_dup2] = orig_sys_dup2;
    // syscall_table[__NR_dup3] = my_sys_dup3;
    syscall_table[__NR_rename] = orig_sys_rename;
    syscall_table[__NR_unlink] = orig_sys_unlink;
    syscall_table[__NR_fork] = orig_sys_fork;
    syscall_table[__NR_exit_group] = orig_sys_exit_group; 
}
