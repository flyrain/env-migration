// author: yufei
// to configure code action 
#ifndef CODE_CONFIG_H
#define CODE_CONFIG_H

//#define LINUX_KERNEL
#define WINDOWS_KERNEL

#ifdef LINUX_KERNEL
#define KERNEL_ADDRESS 0xc0000000
#endif

#ifdef WINDOWS_KERNEL
#define KERNEL_ADDRESS 0x80000000
#endif


#endif // CODE_CONFIG_H
