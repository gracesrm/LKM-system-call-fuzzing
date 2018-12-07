# How to find the system call and its parameters? 

cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_xxx/format


# How to find the system call ``__NR_xxx ``? 

check /usr/include/x86_64-linux-gnu/asm/unistd.h


# How to find device driver/module path ? 

driver: /proc/driver, /proc/dri

module: /proc/modules