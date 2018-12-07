#include "unpred.h"

int thresh;
int fdlist[FDSIZE];
long top5sysnum[NUMOFTOPSYS];
pid_t pidlist[NUMOFPID];
char* top5syscall[NUMOFTOPSYS];


int reduce_size(size_t count){
	int t, tt;
    count= (count>0? count: 1);
    get_random_bytes(&t, sizeof(t)); //generate random number
    tt = t%count;
    tt = (tt >0 ? tt:(0-tt));
    tt = ((tt==0)? 1:tt);
    return tt;
}

int ret_strategy(int number){
	int t, tt;
	get_random_bytes(&t, sizeof(t));
	tt = t% number;
    tt = (tt >0 ? tt:(0-tt));
    return tt;
}

bool within_threshold(){
    int t;
    get_random_bytes(&t, sizeof(t));
    t = t % 100;
    t = (t >0? t: (0-t));
    printk(KERN_INFO "Threshold is %d\n", thresh);
    return (t < thresh? true: false);
}

void init_fdlist(){
    int i;
    for(i=0; i<FDSIZE; i++)
        fdlist[i]= 0;
}

void updatePidList(pid_t pid){
    int i;
    for(i=0; i<NUMOFPID; i++){
        // if(pidlist[i] == pid){  break; }
        if(pidlist[i] == 0){
            pidlist[i]= pid;
            printk(KERN_INFO "pid %d added\n", pid);
            break;
        }
    }
}

bool inPidList(pid_t pid){
    int i;
    for(i=0; i<NUMOFPID; i++){
        if(pidlist[i] == pid && pid != 0){  return true; }
        if(pidlist[i] == 0){    return false; }
    }
    return false;
}

void initThreshold(void){
    thresh = THRESHOLD;
}

void incThreshold(int th){
    thresh = th;
}

void initTopsyscall(void){
    int i;
    for(i=0; i< NUMOFTOPSYS; i++){
        top5syscall[i]= kmalloc(10, GFP_KERNEL);
    }
}
void updateTop5Syscall(char *syscall, int count){
    int i, j, tmp;
    char *tch = kmalloc(10, GFP_KERNEL);
    if(count >= MINTOPCNT && count > top5sysnum[NUMOFTOPSYS-1]){  // if 
        for(i=0; i< NUMOFTOPSYS; i++){   
            // printk(KERN_INFO "syscall: %s, array %s\n", syscall, top5syscall[i]);
            // printk(KERN_INFO "Compare result %d\n", strcmp(syscall, top5syscall[i]));
            if(top5syscall[i]!= NULL && !strcmp(syscall, top5syscall[i])){    //already in the top 5 list
                // printk(KERN_INFO "already in the top 5 list");
                top5sysnum[i]= count;
                for(j=i-1; j>=0; j--){
                    if(top5sysnum[j]< top5sysnum[i]){
                        tmp= top5sysnum[i];
                        top5sysnum[i]= top5sysnum[j];
                        top5sysnum[j]= tmp;
                        strcpy(tch, top5syscall[i]);
                        strcpy(top5syscall[i], top5syscall[j]);
                        strcpy(top5syscall[j], tch);
                    }
                    i= j;
                }
                return;
            }
        }
        // not in the top 5 list: so inject it
        for(i=0; i< NUMOFTOPSYS; i++){
            if(count > top5sysnum[i]){
                for(j= NUMOFTOPSYS-1; j>i; j--){
                    top5sysnum[j] = top5sysnum[j-1];
                    strcpy(top5syscall[j], top5syscall[j-1]);
                    // printk(KERN_INFO "%s is bigger than %s\n", top5syscall[j-1], top5syscall[j]);
                }
                top5sysnum[i] = count;
                strcpy(top5syscall[i], syscall);
                printk(KERN_INFO " %s injected to top\n", top5syscall[i]);
                break;
            }
        }
    }
}

bool isTopSyscall(char *syscall, int totalsyscall){
//This includes the top system call and a top syscall pattern
    int i, j;
    long fl= 0;
    for(i=0; i< NUMOFTOPSYS; i++){
        if(!strcmp(syscall, top5syscall[i])){
            for(j=0; j< NUMOFTOPSYS; j++){
                fl += 100*top5sysnum[j]/ totalsyscall;
                if(fl >= MINTOPPER){  
                    thresh = (7*fl/10 > 95? 95: 7*fl/10);
                    return true; 
                }
            }
            thresh = THRESHOLD;
            return false;
        }
    }
    thresh = THRESHOLD;
    return false;
}

bool start_strategy(){
	struct timespec ts, ts1; 
    struct task_struct *iTask = current;
    long curr_time, delta_time, delta_ntime;

    getboottime(&ts1);
    getnstimeofday(&ts);
    curr_time = ts.tv_sec - ts1.tv_sec;
    delta_time = curr_time - iTask->start_time.tv_sec;
    delta_ntime = ts.tv_nsec - ts1.tv_nsec + iTask->start_time.tv_nsec;
    if(delta_time>= LAUNCHTIME){
        // printk(KERN_INFO "%s has been running for %ld nanoseconds\n", target, delta_ntime);
        // printk(KERN_INFO "timeOfday: %ld, bootime: %ld, psStartime: %ld\n", ts.tv_nsec, ts1.tv_nsec, current->start_time.tv_nsec);
        return true;
    } 
    else 
    	return false;
}

// ------------------------------------------
void add_fd(long fd, const char *filename){
	char *f= "/home";
	if(filename[0]== '/'){
		if ((strncmp(f, filename, 5)!=0)&&(strncmp("/tmp", filename, 4)!=0)){ //not under /home, key fd 
			fdlist[fd]= 1;
			// printk(KERN_INFO "fd %d inserted with file name %s\n", fd, filename);
		}
        else{
            if(filename[13]=='.'){
                fdlist[fd]= 1;
            }
            else{
                fdlist[fd]= 0;
                // printk(KERN_INFO "Play %s with fd %ld\n", filename, fd);
            }
        }
	}
}


void del_fd(long fd){
	fdlist[fd]= 0;
}

int isKeyfd(long fd){   //
	return fdlist[fd];
}

bool isKeyfile(const char *filename){
    if(filename[0] == '/'){
        if((strncmp("/home", filename, 5)!=0) && (strncmp("/tmp", filename, 4)!=0)){
            return true;
        }
        if(filename[13] == '.'){    return true; }
    }
    return false;
}
//-------------------------------------------------------------
//write.read.lseek.nanosleep.sendto.recvfrom.bind.listen.connct...
//0.....1....2.....3.........4......5........6....7......8.....
/*
void initTopSysnum(void){
    int i;
    for(i= 0; i< SYSSIZE; i++)
        sysarray[i] = 0;
    for(i=0; i<NUMOFTOPSYS; i++)
        //initialize the top 5 frequently called syscall number
        topsysnum[i]= 100; //100: so the sysarray[topsysnum[i]] will be 0
}

void rankSyscall(int syscallnum){
    int i, j, tmp;
    sysarray[syscallnum]++;
    if(isRanked(syscallnum)){
        //sort the topsysnum;
        for(i= 0; i< NUMOFTOPSYS; i++){
            for(j=0; j< NUMOFTOPSYS-i-1; j++){
                if(sysarray[topsysnum[j]] < sysarray[topsysnum[j+1]]){
                    tmp= topsysnum[j+1];
                    topsysnum[j+1] = topsysnum[j];
                    topsysnum[j] = tmp;
                }
            }
        }
        // print current rank array
        // for(i= 0; i< NUMOFTOPSYS; i++){
        //     printk(KERN_INFO "%d, ", topsysnum[i]);
        // }
        return;
    }
    // not ranked: add the new callnum;
    for(i=0; i<NUMOFTOPSYS; i++){
        if(sysarray[syscallnum]> sysarray[topsysnum[i]]){
            for(j= NUMOFTOPSYS-1; j>i; j--){
                topsysnum[j] = topsysnum[j-1];
            }
            topsysnum[i]= syscallnum;
            printk(KERN_INFO "syscall %d added to toparray\n", syscallnum);
            return;
        }
    }
}


bool isRanked(int syscallnum){
    int i;
    for(i= 0; i<NUMOFTOPSYS; i++){
        if(topsysnum[i] == syscallnum){
            //printk(KERN_INFO "[Syscall %d]rank No.%d\n", syscallnum, i);
            return true;
        }
    }
    return false;
}
*/

// bool isMalSyscall(void){
//     return true;
// }
