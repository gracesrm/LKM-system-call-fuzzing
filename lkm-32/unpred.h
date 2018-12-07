#include <linux/module.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/stat.h>
#include <linux/fcntl.h>
#include <asm/uaccess.h>
#include <asm/cacheflush.h>
// #include <uapi/asm-generic/unistd.h>
// #include <../arch/x86/include/generated/uapi/asm/unistd_x32.h>
// #include <../arch/x86/include/asm/unistd.h>
#include <linux/delay.h>    // loops_per_jiffy
#include <linux/syscalls.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/random.h>
#include <linux/hashtable.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/net.h>
#include <linux/inet.h>
#include <net/sock.h>
#include <linux/tcp.h>
// #include <net/socket.c>
#include <linux/in.h>
#include <linux/file.h>
#include <linux/socket.h>
#include <linux/time.h>

// #define LOCAL_ADDR ((unsigned long int)0x0100007F)  //"127.0.0.1" attention on big/little endian
#define CR0_WP 0x00010000   // Write Protect Bit (CR0:16)
#define LAUNCHTIME 0
#define FDSIZE 1024
#define MINTOPCNT 20
#define NUMOFTOPSYS 5
#define NUMOFPID 50
#define MINTOPPER 70
#define THRESHOLD 10
// #define TARGET "ls"
//"soffice.bin"

int reduce_size(size_t count);
int ret_strategy(int number);
bool within_threshold(void);
void init_fdlist(void);
bool start_strategy(void);

void add_fd(long fd, const char *filename);
void del_fd(long fd);
int isKeyfd(long fd);
bool isKeyfile(const char *filename);

//-------------------------------------------------------------
//write.read.lseek.nanosleep.sendto.recvfrom.bind.listen.connct...
//0.....1....2.....3.........4......5........6....7......8.....

//---------------------------------------------
// void rankSyscall(int syscallnum);
// void initTopSysnum(void);
// bool isRanked(int syscallnum);
// bool isMalSyscall(void);
//how to input unsure number of arguments?
void initThreshold(void);
void incThreshold(int);
bool inPidList(pid_t pid);
void updatePidList(pid_t pid);
void initTopsyscall(void);
void updateTop5Syscall(char *syscall, int count);
bool isTopSyscall(char *syscall, int totalsyscnt);