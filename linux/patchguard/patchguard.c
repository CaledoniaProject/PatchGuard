#include <linux/module.h>
#include <linux/ptrace.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/user.h>
#include <linux/security.h>
#include <linux/unistd.h>
#include <linux/notifier.h>
#include <linux/version.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/timer.h>
#include <linux/workqueue.h>
#include <asm/unistd.h>

// TODO: dirty hack for Arch, WTF?
#ifndef NR_syscalls
#define NR_syscalls 274
#endif

static unsigned long *sys_call_table;
static struct timer_list patchguard_timer;

// TODO: incoroprate disas engine
#define OPCODE_MAX_BYTES 10
#define PATCHGUARD_CHK_INTERVAL 5000

#define WPOFF do { write_cr0(read_cr0() & (~0x10000)); } while (0);
#define WPON  do { write_cr0(read_cr0() | 0x10000);    } while (0);

struct _kern_opcode
{
    unsigned long addr;
    unsigned char bytes[OPCODE_MAX_BYTES];
} kern_opcode [NR_syscalls];

////////////////////////////////////

#ifndef CONFIG_64BIT
static unsigned long *get_syscalls_table(void)
{
    unsigned long *start;

    for (start = (unsigned long *)0xc0000000; start < (unsigned long *)0xffffffff; ++ start)
        if (start[__NR_close] == (unsigned long)sys_close) {
            return start;
        }

    return NULL;
}
#else
static unsigned long *get_syscalls_table(void)
{
    unsigned long *start;

    for (start = (unsigned long *)0xffffffff810001c8; 
            start < (unsigned long *)0xffffffff81ab41a2; 
            ++ start)
        if (start[__NR_close] == (unsigned long)sys_close) {
            return start;
        }

    return NULL;
}
#endif

static void check_hook(unsigned long data)
{
//    printk (KERN_INFO "Running checks %d..\n", data);

    int i, j;
    unsigned char *p;

    // TODO: sys_call_table array base address verification
    for (i = 0; i < NR_syscalls; ++i)
    {
        p = (unsigned char*) sys_call_table[i];

        // Verify sys_call_table
        if (sys_call_table[i] != kern_opcode[i].addr)
        {
            printk (KERN_INFO "Security Alert - syscall hook of %d detected. (restored)\n", i);

            WPOFF;
            sys_call_table[i] = kern_opcode[i].addr;
            WPON;

            continue;
        }

        // Inline hook detection
        for (j = 0; j < OPCODE_MAX_BYTES; ++j)
        {
            if (kern_opcode[i].bytes[j] != *p ++)
            {
                printk (KERN_INFO "Security Alert - inline hook of %d detected. (restored)\n", i);

                p = (unsigned char*) sys_call_table[i];
                for (j = 0; j < OPCODE_MAX_BYTES; ++j)
                {
                    *p = kern_opcode[i].bytes[j]; ++p;   
                }

                continue;
            }
        }
    }

    if (mod_timer (&patchguard_timer, jiffies + msecs_to_jiffies(PATCHGUARD_CHK_INTERVAL)))
    {
        printk (KERN_INFO "Error - can't set timer!\n");
    }
}

static int __init startup(void)
{
    unsigned char *p;
    int i = 0, j = 0;

    // Duplicate opcodes
    sys_call_table = get_syscalls_table();
    if (! sys_call_table)
    {
        printk (KERN_INFO "Error - Unable to acquire sys_call_table!\n");
        return -ECANCELED;
    }

    for (i = 0; i < NR_syscalls; ++i)
    {
        kern_opcode[i].addr = sys_call_table[i];
        p = (unsigned char*)sys_call_table[i];

        for (j = 0; j < OPCODE_MAX_BYTES; ++j)
        {
            kern_opcode[i].bytes[j] = *p ++;
        }
    }

    // Setup timer
    setup_timer(&patchguard_timer, check_hook, 0);
    if (mod_timer (&patchguard_timer, jiffies + msecs_to_jiffies(PATCHGUARD_CHK_INTERVAL)))
    {
        printk (KERN_INFO "Error - can't set timer!\n");
        return -ECANCELED;
    }

//    p = (unsigned char*)sys_call_table[3];
//    printk (KERN_INFO "Syscall table at: 0x%lx, bytes: %02x %02x %02x %02x %02x %02x\n", 
//            sys_call_table, 
//            *p, *(p+1), *(p+2), *(p+3), *(p+4), *(p+5));

    printk (KERN_INFO "Patchguard Initialized.\n");
    return 0;
}

static void __exit cleanup(void)
{
    del_timer(&patchguard_timer);
    printk (KERN_INFO "Patchguard removed.\n");
}

module_init(startup);
module_exit(cleanup);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Aaron Lewis");
MODULE_DESCRIPTION("Patchguard Implementation (Linux)");

