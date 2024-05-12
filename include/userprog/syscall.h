#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);

struct fdt_file
{
	struct file *file;
	int dup_count;
};

#endif /* userprog/syscall.h */
