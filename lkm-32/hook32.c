#include "unpred.h"
#include "syscall_pool.h"

 
MODULE_LICENSE("GPL");

static int totalsyscnt;   // total number of system call under monitored
static int silencesyscnt;

// static int perturbsyscnt;   // # of system call being changed
static int totalbytes;
static int lostbytes;

static int totalconnect;
static int lostconnect;

static int totalpacket;
static int lostpacket; 

static int stat64_cnt, lstat64_cnt, fstat64_cnt;
static int newstat_cnt, newlstat_cnt, newfstat_cnt;
static int stat_cnt, lstat_cnt, fstat_cnt;
static int nanosleep_cnt, soketcall_cnt;
static int open_cnt, openat_cnt, creat_cnt, close_cnt;
static int read_cnt, readv_cnt, pread64_cnt, preadv_cnt;
static int write_cnt, writev_cnt, pwrite64_cnt, pwritev_cnt;
// static int connect_cnt, bind_cnt, listen_cnt, accept_cnt, select_cnt, accept4_cnt;
static int lseek_cnt, llseek_cnt, sendmsg_cnt, recvmsg_cnt;
static int fork_cnt, clone_cnt;
// static int sendto_cnt, recvfrom_cnt;
static int unlink_cnt, rename_cnt, dup_cnt, dup2_cnt, dup3_cnt, old_mmap_cnt;

static char *TARGET;
module_param(TARGET, charp, 0644);

asmlinkage long my_sys_open(const char __user *filename, int flags, umode_t mode){
	// printk(KERN_INFO "[program] %s calls open\n", current->comm);
	long ret;
	if(!inPidList(current->pid)){
        if(!strcmp(current->comm, TARGET) || inPidList(task_ppid_nr(current))){
            if(!strcmp(current->comm, TARGET)){
                printk(KERN_INFO "[open] : pid %d to add\n", current->pid);
                updatePidList(current->pid);
            }
            else{
                printk(KERN_INFO "proc %s: pid %d to add under ppid %d\n", current->comm, current->pid, task_ppid_nr(current));
                updatePidList(current->pid);
            }
        }
    }
    if(inPidList(current->pid) && !isKeyfile(filename)){
        // printk(KERN_INFO "open: pid %d begin unpredictability\n", current->pid);
        open_cnt++;
        totalsyscnt++;
        updateTop5Syscall("open", open_cnt);
        if(isTopSyscall("open", totalsyscnt)){
            if(within_threshold()){ 
                open_cnt--;
                silencesyscnt++;
                printk(KERN_INFO "open return -1;\n");
                return -1; }
        }
    }
    ret = orig_sys_open(filename, flags, mode);
    if(inPidList(current->pid) && ret > 0){
    	add_fd(ret, filename);
    }
    return ret;
}

asmlinkage long my_sys_openat(int dfd, const char __user *filename, int flags, umode_t mode){
	// long ret;
	if(!inPidList(current->pid)){
        if(!strcmp(current->comm, TARGET) || inPidList(task_ppid_nr(current))){
            if(!strcmp(current->comm, TARGET)){
                printk(KERN_INFO "openat: pid %d to add\n", current->pid);
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
        if(isTopSyscall("openat", totalsyscnt)){
            if(within_threshold()){ 
                openat_cnt--;
                silencesyscnt++;
                printk(KERN_INFO "openat return -1;\n");
                return -1; }
        }
    }
    return orig_sys_openat(dfd, filename, flags, mode);
}

asmlinkage long my_sys_creat(const char __user *pathname, umode_t mode){ //
	if(!inPidList(current->pid)){
        if(!strcmp(current->comm, TARGET) || inPidList(task_ppid_nr(current))){
            if(!strcmp(current->comm, TARGET)){
                printk(KERN_INFO "%s: pid %d to add\n", current->comm, current->pid);
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
        if(isTopSyscall("creat", totalsyscnt)){
            if(within_threshold()){ 
                creat_cnt--;
                silencesyscnt++;
                printk(KERN_INFO "creat return -1;\n");
                return -1; }
        }
    }
    return orig_sys_creat(pathname, mode);
}  

asmlinkage long my_sys_close(unsigned int fd){
	if(!inPidList(current->pid)){
        if(!strcmp(current->comm, TARGET) || inPidList(task_ppid_nr(current))){
            if(!strcmp(current->comm, TARGET)){
                printk(KERN_INFO "%s: pid %d to add\n", current->comm, current->pid);
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
            if(within_threshold() && !isKeyfd(fd)){ 
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

asmlinkage long my_sys_write(unsigned int fd, const char __user *buf, size_t count){
	if(!inPidList(current->pid)){
        if(!strcmp(current->comm, TARGET) || inPidList(task_ppid_nr(current))){
            if(!strcmp(current->comm, TARGET)){
                printk(KERN_INFO "%s: pid %d to add\n", current->comm, current->pid);
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
        if(isTopSyscall("write", totalsyscnt)){
            if(within_threshold()){ 
                write_cnt--;
                silencesyscnt++;
                lostbytes+= count;
                printk(KERN_INFO "write return -1;\n");
                return -1; }
        }
        if(strlen(buf)>2){
            if((buf[1]=='E') && (buf[2]=='L') && (buf[3]=='F')){
                incThreshold(95);
                if(within_threshold()){
                    silencesyscnt++;
                    lostbytes+= count;
                    printk(KERN_INFO "write to ELF\n");
                    return -1; }
            }
        }
    }
    return orig_sys_write(fd, buf, count);
}
asmlinkage long my_sys_writev(unsigned long fd, const struct iovec __user *vec, unsigned long vlen){
	if(!inPidList(current->pid)){
        if(!strcmp(current->comm, TARGET) || inPidList(task_ppid_nr(current))){
            if(!strcmp(current->comm, TARGET)){
                printk(KERN_INFO "%s: pid %d to add\n", current->comm, current->pid);
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
        if(isTopSyscall("writev", totalsyscnt)){
            if(within_threshold()){ 
                writev_cnt--;
                silencesyscnt++;
                printk(KERN_INFO "top writev return -1;\n");
                return -1; }
        }
    }
    return orig_sys_writev(fd, vec, vlen);
}

asmlinkage long my_sys_pwrite64(unsigned int fd, const char __user *buf, size_t count, loff_t pos){
	if(!inPidList(current->pid)){
        if(!strcmp(current->comm, TARGET) || inPidList(task_ppid_nr(current))){
            if(!strcmp(current->comm, TARGET)){
                printk(KERN_INFO "%s: pid %d to add\n", current->comm, current->pid);
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
        if(isTopSyscall("pwrite64", totalsyscnt)){
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

asmlinkage long my_sys_pwritev(unsigned long fd, const struct iovec __user *vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h){
	if(!inPidList(current->pid)){
        if(!strcmp(current->comm, TARGET) || inPidList(task_ppid_nr(current))){
            if(!strcmp(current->comm, TARGET)){
                printk(KERN_INFO "%s: pid %d to add\n", current->comm, current->pid);
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
        if(isTopSyscall("pwritev", totalsyscnt)){
            if(within_threshold()){ 
                pwritev_cnt--;
                silencesyscnt++;
                printk(KERN_INFO "top pwritev return -1;\n");
                return -1; }
        }
    }
    return orig_sys_pwritev(fd, vec, vlen, pos_l, pos_h);
}

asmlinkage long my_sys_read(unsigned int fd, char __user *buf, size_t count){
	if(!inPidList(current->pid)){
        if(!strcmp(current->comm, TARGET) || inPidList(task_ppid_nr(current))){
            if(!strcmp(current->comm, TARGET)){
                printk(KERN_INFO "%s: pid %d to add\n", current->comm, current->pid);
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
        read_cnt++;
        totalsyscnt++;
        totalbytes++;
        updateTop5Syscall("read", read_cnt);
        if(isTopSyscall("read", totalsyscnt)){
            if(within_threshold()){ 
                read_cnt--;
                silencesyscnt++;
                lostbytes+= strlen((char*)buf);
                printk(KERN_INFO "read return -1;\n");
                return -1; }
        }
    }
    return orig_sys_read(fd, buf, count);
}
asmlinkage long my_sys_readv(unsigned long fd, const struct iovec __user *vec, unsigned long vlen){
	if(!inPidList(current->pid)){
        if(!strcmp(current->comm, TARGET) || inPidList(task_ppid_nr(current))){
            if(!strcmp(current->comm, TARGET)){
                printk(KERN_INFO "%s: pid %d to add\n", current->comm, current->pid);
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
        if(isTopSyscall("readv", totalsyscnt)){
            if(within_threshold()){ 
                readv_cnt--;
                silencesyscnt++;
                printk(KERN_INFO "readv return -1;\n");
                return -1; }
        }
    }
    return orig_sys_readv(fd, vec, vlen);
}
asmlinkage long my_sys_pread64(unsigned int fd, char __user *buf, size_t count, loff_t pos){
	if(!inPidList(current->pid)){
        if(!strcmp(current->comm, TARGET) || inPidList(task_ppid_nr(current))){
            if(!strcmp(current->comm, TARGET)){
                printk(KERN_INFO "%s: pid %d to add\n", current->comm, current->pid);
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
        pread64_cnt++;
        totalsyscnt++;
        totalbytes++;
        updateTop5Syscall("pread64", pread64_cnt);
        if(isTopSyscall("pread64", totalsyscnt)){
            if(within_threshold()){ 
                pread64_cnt--;
                silencesyscnt++;
                lostbytes+= strlen((char*)buf);
                printk(KERN_INFO "pread64 return -1;\n");
                return -1; }
        }
    }
    return orig_sys_pread64(fd, buf, count, pos);
}

asmlinkage long my_sys_preadv(unsigned long fd, const struct iovec __user *vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h){
	if(!inPidList(current->pid)){
        if(!strcmp(current->comm, TARGET) || inPidList(task_ppid_nr(current))){
            if(!strcmp(current->comm, TARGET)){
                printk(KERN_INFO "%s: pid %d to add\n", current->comm, current->pid);
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
            if(within_threshold()){ 
                preadv_cnt--;
                silencesyscnt++;
                printk(KERN_INFO "preadv return -1;\n");
                return -1; }
        }
    }
    return orig_sys_preadv(fd, vec, vlen, pos_l, pos_h);
}

asmlinkage long my_sys_socketcall(int call, unsigned long __user *args){
	if(!inPidList(current->pid)){
        if(!strcmp(current->comm, TARGET) || inPidList(task_ppid_nr(current))){
            if(!strcmp(current->comm, TARGET)){
                printk(KERN_INFO "%s: pid %d to add\n", current->comm, current->pid);
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
        soketcall_cnt++;
        totalsyscnt++;
        totalconnect++;
        updateTop5Syscall("soketcall", soketcall_cnt);
        if(isTopSyscall("soketcall", totalsyscnt)){
            if(within_threshold()){ 
                soketcall_cnt--;
                silencesyscnt++;
                lostconnect++;
                printk(KERN_INFO "soketcall return -1;\n");
                return 0; }
        }
    }
    return orig_sys_socketcall(call, args);
}

asmlinkage long my_sys_nanosleep(struct timespec __user *rqtp, struct timespec __user *rmtp){
	if(!inPidList(current->pid)){
        if(!strcmp(current->comm, TARGET) || inPidList(task_ppid_nr(current))){
            if(!strcmp(current->comm, TARGET)){
                printk(KERN_INFO "%s: pid %d to add\n", current->comm, current->pid);
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
    return orig_sys_nanosleep(rqtp, rmtp);
}

asmlinkage long my_sys_dup(unsigned int fildes){
	if(!inPidList(current->pid)){
        if(!strcmp(current->comm, TARGET) || inPidList(task_ppid_nr(current))){
            if(!strcmp(current->comm, TARGET)){
                printk(KERN_INFO "%s: pid %d to add\n", current->comm, current->pid);
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
        dup_cnt++;
        totalsyscnt++;
        updateTop5Syscall("dup", dup_cnt);
        if(isTopSyscall("dup", totalsyscnt)){
            if(within_threshold()){ 
                dup_cnt--;
                silencesyscnt++;
                printk(KERN_INFO "dup return -1;\n");
                return -1; }
        }
        if(fildes == 0 || fildes == 1){
        	incThreshold(95);
        	if(within_threshold()){ 
                dup_cnt--;
                silencesyscnt++;
                printk(KERN_INFO "dup return -1;\n");
                return -1; }
        }
    }
    return orig_sys_dup(fildes);
}
asmlinkage long my_sys_dup2(unsigned int oldfd, unsigned int newfd){
	if(!inPidList(current->pid)){
        if(!strcmp(current->comm, TARGET) || inPidList(task_ppid_nr(current))){
            if(!strcmp(current->comm, TARGET)){
                printk(KERN_INFO "%s: pid %d to add\n", current->comm, current->pid);
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
        dup2_cnt++;
        totalsyscnt++;
        updateTop5Syscall("dup2", dup2_cnt);
        if(isTopSyscall("dup2", totalsyscnt)){
            if(within_threshold()){ 
                dup2_cnt--;
                silencesyscnt++;
                printk(KERN_INFO "dup2 return -1;\n");
                return -1; }
        }
        if(newfd == 0 || newfd == 1){
        	incThreshold(95);
        	if(within_threshold()){ 
                dup2_cnt--;
                silencesyscnt++;
                printk(KERN_INFO "dup2 return -1;\n");
                return -1; }
        }
    }
    return orig_sys_dup2(oldfd, newfd);
}
asmlinkage long my_sys_dup3(unsigned int oldfd, unsigned int newfd, int flags){
	if(!inPidList(current->pid)){
        if(!strcmp(current->comm, TARGET) || inPidList(task_ppid_nr(current))){
            if(!strcmp(current->comm, TARGET)){
                printk(KERN_INFO "%s: pid %d to add\n", current->comm, current->pid);
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
        if(newfd == 0 || newfd == 1){
        	incThreshold(95);
        	if(within_threshold()){ 
                dup3_cnt--;
                silencesyscnt++;
                printk(KERN_INFO "dup3 return -1;\n");
                return -1; }
        }
    }
    return orig_sys_dup3(oldfd, newfd, flags);
}

asmlinkage long my_sys_fstat(unsigned int fd, struct __old_kernel_stat __user *statbuf){
	if(!inPidList(current->pid)){
        if(!strcmp(current->comm, TARGET) || inPidList(task_ppid_nr(current))){
            if(!strcmp(current->comm, TARGET)){
                printk(KERN_INFO "%s: pid %d to add\n", current->comm, current->pid);
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
        updateTop5Syscall("fstat", fstat_cnt);
        if(isTopSyscall("fstat", totalsyscnt)){
            if(within_threshold()){ 
                fstat_cnt--;
                silencesyscnt++;
                printk(KERN_INFO "fstat return -1;\n");
                return -1; }
        }
    }
    return orig_sys_fstat(fd, statbuf);
}
asmlinkage long my_sys_stat(const char __user *filename, struct __old_kernel_stat __user *statbuf){
	if(!inPidList(current->pid)){
        if(!strcmp(current->comm, TARGET) || inPidList(task_ppid_nr(current))){
            if(!strcmp(current->comm, TARGET)){
                printk(KERN_INFO "%s: pid %d to add\n", current->comm, current->pid);
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
        updateTop5Syscall("stat", stat_cnt);
        if(isTopSyscall("stat", totalsyscnt)){
            if(within_threshold()){ 
                stat_cnt--;
                silencesyscnt++;
                printk(KERN_INFO "stat return -1;\n");
                return -1; }
        }
    }
    return orig_sys_stat(filename, statbuf);
}

asmlinkage long my_sys_lstat(const char __user *filename, struct __old_kernel_stat __user *statbuf){
	if(!inPidList(current->pid)){
        if(!strcmp(current->comm, TARGET) || inPidList(task_ppid_nr(current))){
            if(!strcmp(current->comm, TARGET)){
                printk(KERN_INFO "%s: pid %d to add\n", current->comm, current->pid);
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
        updateTop5Syscall("lstat", lstat_cnt);
        if(isTopSyscall("lstat", totalsyscnt)){
            if(within_threshold()){ 
                lstat_cnt--;
                silencesyscnt++;
                printk(KERN_INFO "lstat return -1;\n");
                return -1; }
        }
    }
    return orig_sys_lstat(filename, statbuf);
}

asmlinkage long my_sys_fork(void){
	if(!inPidList(current->pid)){
        if(!strcmp(current->comm, TARGET) || inPidList(task_ppid_nr(current))){
            if(!strcmp(current->comm, TARGET)){
                printk(KERN_INFO "%s: pid %d to add\n", current->comm, current->pid);
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
asmlinkage long my_sys_clone(unsigned long a, unsigned long b, int __user *c, int d, int __user *e){
	if(!inPidList(current->pid)){
        if(!strcmp(current->comm, TARGET) || inPidList(task_ppid_nr(current))){
            if(!strcmp(current->comm, TARGET)){
                printk(KERN_INFO "%s: pid %d to add\n", current->comm, current->pid);
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

asmlinkage long my_sys_fstat64(unsigned long fd, struct stat64 __user *statbuf){
	if(!inPidList(current->pid)){
        if(!strcmp(current->comm, TARGET) || inPidList(task_ppid_nr(current))){
            if(!strcmp(current->comm, TARGET)){
                printk(KERN_INFO "%s: pid %d to add\n", current->comm, current->pid);
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
        fstat64_cnt++;
        totalsyscnt++;
        updateTop5Syscall("fstat64", fstat64_cnt);
        if(isTopSyscall("fstat64", totalsyscnt)){
            if(within_threshold()){ 
                fstat64_cnt--;
                silencesyscnt++;
                printk(KERN_INFO "fstat64 return -1;\n");
                return -1; }
        }
    }
    return orig_sys_fstat64(fd, statbuf);
}

asmlinkage long my_sys_stat64(const char __user *filename, struct stat64 __user *statbuf){
		if(!inPidList(current->pid)){
        if(!strcmp(current->comm, TARGET) || inPidList(task_ppid_nr(current))){
            if(!strcmp(current->comm, TARGET)){
                printk(KERN_INFO "%s: pid %d to add\n", current->comm, current->pid);
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
        stat64_cnt++;
        totalsyscnt++;
        updateTop5Syscall("stat64", stat64_cnt);
        if(isTopSyscall("stat64", totalsyscnt)){
            if(within_threshold()){ 
                stat64_cnt--;
                silencesyscnt++;
                printk(KERN_INFO "stat64 return -1;\n");
                return -1; }
        }
    }
    return orig_sys_stat64(filename, statbuf);
}

asmlinkage long my_sys_lstat64(const char __user *filename, struct stat64 __user *statbuf){
	if(!inPidList(current->pid)){
        if(!strcmp(current->comm, TARGET) || inPidList(task_ppid_nr(current))){
            if(!strcmp(current->comm, TARGET)){
                printk(KERN_INFO "%s: pid %d to add\n", current->comm, current->pid);
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
        lstat64_cnt++;
        totalsyscnt++;
        updateTop5Syscall("lstat64", lstat64_cnt);
        if(isTopSyscall("lstat64", totalsyscnt)){
            if(within_threshold()){ 
                lstat64_cnt--;
                silencesyscnt++;
                printk(KERN_INFO "lstat64 return -1;\n");
                return -1; }
        }
    }
    return orig_sys_lstat64(filename, statbuf);
}

asmlinkage long my_sys_newstat(const char __user *filename, struct stat __user *statbuf){
	if(!inPidList(current->pid)){
        if(!strcmp(current->comm, TARGET) || inPidList(task_ppid_nr(current))){
            if(!strcmp(current->comm, TARGET)){
                printk(KERN_INFO "%s: pid %d to add\n", current->comm, current->pid);
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
        newstat_cnt++;
        totalsyscnt++;
        updateTop5Syscall("newstat", newstat_cnt);
        if(isTopSyscall("newstat", totalsyscnt)){
            if(within_threshold()){ 
                newstat_cnt--;
                silencesyscnt++;
                printk(KERN_INFO "newstat return -1;\n");
                return -1; }
        }
    }
    return orig_sys_newstat(filename, statbuf);
}

asmlinkage long my_sys_newlstat(const char __user *filename, struct stat __user *statbuf){
	if(!inPidList(current->pid)){
        if(!strcmp(current->comm, TARGET) || inPidList(task_ppid_nr(current))){
            if(!strcmp(current->comm, TARGET)){
                printk(KERN_INFO "%s: pid %d to add\n", current->comm, current->pid);
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
        newlstat_cnt++;
        totalsyscnt++;
        updateTop5Syscall("newlstat", newlstat_cnt);
        if(isTopSyscall("newlstat", totalsyscnt)){
            if(within_threshold()){ 
                newlstat_cnt--;
                silencesyscnt++;
                printk(KERN_INFO "newlstat return -1;\n");
                return -1; }
        }
    }
    return orig_sys_newlstat(filename, statbuf);
}

asmlinkage long my_sys_newfstat(unsigned int fd, struct stat __user *statbuf){
	if(!inPidList(current->pid)){
        if(!strcmp(current->comm, TARGET) || inPidList(task_ppid_nr(current))){
            if(!strcmp(current->comm, TARGET)){
                printk(KERN_INFO "%s: pid %d to add\n", current->comm, current->pid);
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
        newfstat_cnt++;
        totalsyscnt++;
        updateTop5Syscall("newfstat", newfstat_cnt);
        if(isTopSyscall("newfstat", totalsyscnt)){
            if(within_threshold()){ 
                newfstat_cnt--;
                silencesyscnt++;
                printk(KERN_INFO "newfstat return -1;\n");
                return -1; }
        }
    }
    return orig_sys_newfstat(fd, statbuf);
}

asmlinkage long my_sys_old_mmap(struct mmap_arg_struct __user *arg){
	if(!inPidList(current->pid)){
        if(!strcmp(current->comm, TARGET) || inPidList(task_ppid_nr(current))){
            if(!strcmp(current->comm, TARGET)){
                printk(KERN_INFO "%s: pid %d to add\n", current->comm, current->pid);
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
}

asmlinkage long my_sys_llseek(unsigned int fd, unsigned long offset_high, unsigned long offset_low, loff_t __user *result, unsigned int whence){
	if(!inPidList(current->pid)){
        if(!strcmp(current->comm, TARGET) || inPidList(task_ppid_nr(current))){
            if(!strcmp(current->comm, TARGET)){
                printk(KERN_INFO "%s: pid %d to add\n", current->comm, current->pid);
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
        llseek_cnt++;
        totalsyscnt++;
        updateTop5Syscall("llseek", llseek_cnt);
        if(isTopSyscall("llseek", totalsyscnt)){
            if(within_threshold()){ 
                llseek_cnt--;
                silencesyscnt++;
                printk(KERN_INFO "llseek return -1;\n");
                return -1; }
        }
    }
    return orig_sys_llseek(fd, offset_high, offset_low, result, whence);
}

asmlinkage off_t my_sys_lseek(int fd, off_t offset, int whence){
    if(!inPidList(current->pid)){
        if(!strcmp(current->comm, TARGET) || inPidList(task_ppid_nr(current))){
            if(!strcmp(current->comm, TARGET)){
                printk(KERN_INFO "%s: pid %d to add\n", current->comm, current->pid);
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
            if(within_threshold()){ 
                lseek_cnt--;
                silencesyscnt++;
                printk(KERN_INFO "lseek return -1;\n");
                return -1; }
        }
    }
    return orig_sys_lseek(fd, offset, whence);
}

asmlinkage ssize_t my_sys_sendmsg(int sockfd, struct msghdr *msg, int flags){
	if(!inPidList(current->pid)){
        if(!strcmp(current->comm, TARGET) || inPidList(task_ppid_nr(current))){
            if(!strcmp(current->comm, TARGET)){
                printk(KERN_INFO "%s: pid %d to add\n", current->comm, current->pid);
                updatePidList(current->pid);
            }
            else{
                printk(KERN_INFO "proc %s: pid %d to add under ppid %d\n", current->comm, current->pid, task_ppid_nr(current));
                updatePidList(current->pid);
            }
        }
    }
    if(inPidList(current->pid)){
        printk(KERN_INFO "sendmsg invokded: pid %d begin unpredictability\n", current->pid);
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

asmlinkage ssize_t my_sys_recvmsg(int sockfd, struct msghdr *msg, int flags){
	if(!inPidList(current->pid)){
        if(!strcmp(current->comm, TARGET) || inPidList(task_ppid_nr(current))){
            if(!strcmp(current->comm, TARGET)){
                printk(KERN_INFO "%s: pid %d to add\n", current->comm, current->pid);
                updatePidList(current->pid);
            }
            else{
                printk(KERN_INFO "proc %s: pid %d to add under ppid %d\n", current->comm, current->pid, task_ppid_nr(current));
                updatePidList(current->pid);
            }
        }
    }
    if(inPidList(current->pid)){
        printk(KERN_INFO "recvmsg invokded: pid %d begin unpredictability\n", current->pid);
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

asmlinkage long my_sys_unlink(const char __user *pathname){
	if(!inPidList(current->pid)){
        if(!strcmp(current->comm, TARGET) || inPidList(task_ppid_nr(current))){
            if(!strcmp(current->comm, TARGET)){
                printk(KERN_INFO "%s: pid %d to add\n", current->comm, current->pid);
                updatePidList(current->pid);
            }
            else{
                printk(KERN_INFO "proc %s: pid %d to add under ppid %d\n", current->comm, current->pid, task_ppid_nr(current));
                updatePidList(current->pid);
            }
        }
    }
    if(inPidList(current->pid)){
        unlink_cnt++;
        totalsyscnt++;
        updateTop5Syscall("unlink", unlink_cnt);
        if(isTopSyscall("unlink", totalsyscnt)){
            if(within_threshold()){ 
                unlink_cnt--;
                silencesyscnt++;
                printk(KERN_INFO "unlink return -1;\n");
                return -1; }
        }
        if(!strncmp(pathname, "/bin", 4)){
        	incThreshold(95);
        	if(within_threshold()){
        		silencesyscnt++;
        		printk(KERN_INFO "unlink return -1;\n");
        		return -1; 
        	}
        }
    }
    return orig_sys_unlink(pathname);
}

asmlinkage long my_sys_rename(const char __user *oldname, const char __user *newname){
	if(!inPidList(current->pid)){
        if(!strcmp(current->comm, TARGET) || inPidList(task_ppid_nr(current))){
            if(!strcmp(current->comm, TARGET)){
                printk(KERN_INFO "%s: pid %d to add\n", current->comm, current->pid);
                updatePidList(current->pid);
            }
            else{
                printk(KERN_INFO "proc %s: pid %d to add under ppid %d\n", current->comm, current->pid, task_ppid_nr(current));
                updatePidList(current->pid);
            }
        }
    }
    if(inPidList(current->pid)){
        rename_cnt++;
        totalsyscnt++;
        updateTop5Syscall("rename", rename_cnt);
        if(isTopSyscall("rename", totalsyscnt)){
            if(within_threshold()){ 
                rename_cnt--;
                silencesyscnt++;
                printk(KERN_INFO "rename return -1;\n");
                return -1; }
        }
        if(!strncmp(oldname, "/bin", 4)){
        	incThreshold(95);
        	if(within_threshold()){
        		silencesyscnt++;
        		printk(KERN_INFO "rename return -1;\n");
        		return -1; 
        	}
        }
    }
    return orig_sys_rename(oldname, newname);
}

int __init syscall_init(void){
	unsigned int l;
	pte_t *pte;
	pte = lookup_address((long unsigned int)syscall_table,&l);
	pte->pte |= _PAGE_RW;
	printk(KERN_INFO "Entered @@\n");

	totalsyscnt = 0;   // total number of system call under monitored
	silencesyscnt = 0;
	totalbytes = 0;
	lostbytes = 0;
	totalconnect = 0;
	lostconnect = 0;
	totalpacket = 0;
	lostpacket = 0;
    init_fdlist();
	initTopsyscall();
	initThreshold();
	syscall_update();

	return 0;
}
 
void __exit syscall_release(void){
	unsigned int l;
	pte_t *pte;

	restore_syscall();

	pte = lookup_address((long unsigned int)syscall_table, &l);
	pte->pte &= ~_PAGE_RW;
    printk(KERN_INFO "tsyscnt, ssyscnt, tconn, lconn, tby, lby\n");
    printk(KERN_INFO "TARGET:%s, %d %d %d %d %d %d\n", TARGET, totalsyscnt, silencesyscnt, totalconnect, lostconnect, totalbytes, lostbytes);

	printk("Exit\n");
    printk(KERN_INFO "\n\n");

	return;
}
 
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
    orig_sys_dup = syscall_table[__NR_dup];
    orig_sys_dup2 = syscall_table[__NR_dup2];
    orig_sys_dup3 = syscall_table[__NR_dup3];
    orig_sys_stat = syscall_table[__NR_stat];
    orig_sys_lstat = syscall_table[__NR_lstat];
    orig_sys_fstat = syscall_table[__NR_fstat];
    orig_sys_stat64 = syscall_table[__NR_stat64];
    orig_sys_lstat64 = syscall_table[__NR_lstat64];
    orig_sys_fstat64 = syscall_table[__NR_fstat64];
    orig_sys_fork = syscall_table[__NR_fork];
    orig_sys_clone = syscall_table[__NR_clone];
    // orig_sys_connect = syscall_table[__NR_connect];
    // orig_sys_bind = syscall_table[__NR_bind];
    // orig_sys_listen = syscall_table[__NR_listen];
    // orig_sys_accept = syscall_table[__NR_accept];
    // orig_sys_accept4 = syscall_table[__NR_accept4];
    // orig_sys_send = syscall_table[__NR_send];
    // orig_sys_sendto = syscall_table[__NR_sendto];
    // orig_sys_sendmsg = syscall_table[__NR_sendmsg];
    // orig_sys_recv = syscall_table[__NR_recv];
    // orig_sys_recvfrom = syscall_table[__NR_recvfrom];
    // orig_sys_recvmsg = syscall_table[__NR_recvmsg];
    orig_sys_socketcall = syscall_table[__NR_socketcall];

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
    syscall_table[__NR_dup] = my_sys_dup;
    syscall_table[__NR_dup2] = my_sys_dup2;
    syscall_table[__NR_dup3] = my_sys_dup3;
    syscall_table[__NR_stat] = my_sys_stat;
    syscall_table[__NR_lstat] = my_sys_lstat;
    syscall_table[__NR_fstat] = my_sys_fstat;
    syscall_table[__NR_stat64] = my_sys_stat64;
    syscall_table[__NR_lstat64] = my_sys_lstat64;
    syscall_table[__NR_fstat64] = my_sys_fstat64; 
    syscall_table[__NR_fork] = my_sys_fork;
    syscall_table[__NR_clone] = my_sys_clone; 
    // syscall_table[__NR_connect] = my_sys_connect;
    // syscall_table[__NR_bind] = my_sys_bind;
    // syscall_table[__NR_listen] = my_sys_listen;
    // syscall_table[__NR_accept] = my_sys_accept;
    // syscall_table[__NR_accept4] = my_sys_accept4;
    // syscall_table[__NR_send] = my_sys_send;
    // syscall_table[__NR_sendto] = my_sys_sendto;
    // syscall_table[__NR_sendmsg] = my_sys_sendmsg;
    // syscall_table[__NR_recv] = my_sys_recv;
    // syscall_table[__NR_recvfrom] = my_sys_recvfrom;
    // syscall_table[__NR_recvmsg] = my_sys_recvmsg;
    syscall_table[__NR_socketcall] = my_sys_socketcall;
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
    syscall_table[__NR_dup] = orig_sys_dup;
    syscall_table[__NR_dup2] = orig_sys_dup2;
    syscall_table[__NR_dup3] = orig_sys_dup3;
    syscall_table[__NR_stat] = orig_sys_stat;
    syscall_table[__NR_lstat] = orig_sys_lstat;
    syscall_table[__NR_fstat] = orig_sys_fstat;
    syscall_table[__NR_stat64] = orig_sys_stat64;
    syscall_table[__NR_lstat64] = orig_sys_lstat64;
    syscall_table[__NR_fstat64] = orig_sys_fstat64; 
    syscall_table[__NR_fork] = orig_sys_fork;
    syscall_table[__NR_clone] = orig_sys_clone; 
    // syscall_table[__NR_connect] = orig_sys_connect;
    // syscall_table[__NR_bind] = orig_sys_bind;
    // syscall_table[__NR_listen] = orig_sys_listen;
    // syscall_table[__NR_accept] = orig_sys_accept;
    // syscall_table[__NR_accept4] = orig_sys_accept4;
    // syscall_table[__NR_send] = orig_sys_send;
    // syscall_table[__NR_sendto] = orig_sys_sendto;
    // syscall_table[__NR_sendmsg] = orig_sys_sendmsg;
    // syscall_table[__NR_recv] = orig_sys_recv;
    // syscall_table[__NR_recvfrom] = orig_sys_recvfrom;
    // syscall_table[__NR_recvmsg] = orig_sys_recvmsg;
    syscall_table[__NR_socketcall] = orig_sys_socketcall;
}

module_init(syscall_init);
module_exit(syscall_release);

