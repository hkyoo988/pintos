#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "filesys/filesys.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "threads/palloc.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "threads/synch.h"
#include "intrinsic.h"
#include "../include/filesys/file.h"

void syscall_entry(void);
void syscall_handler(struct intr_frame *);
void check_address(void *addr);
void exit(int status);
int exec(const char *file);
bool create(const char *file, unsigned iniital_size);
bool remove(const char *file);
tid_t fork(const char *thread_name, struct intr_frame *f);
int wait(tid_t tid);
int open(const char *filename);
void close(int fd);
int read(int fd, void *buffer, unsigned size);
int filesize(int fd);
int write(int fd, void *buffer, unsigned size);
unsigned tell(int fd);
void seek(int fd, unsigned position);
int dup2(int oldfd, int newfd);

struct lock fd_lock;

/* 시스템 호출.
 *
 * 이전에 시스템 호출 서비스는 인터럽트 핸들러에서 처리되었습니다
 * (예: 리눅스에서 int 0x80). 그러나 x86-64에서는 제조업체가 시스템 호출을
 * 요청하기 위한 효율적인 경로를 제공합니다, 바로 `syscall` 명령어입니다.
 *
 * syscall 명령어는 모델별 레지스터(MSR)에서 값을 읽어와서 작동합니다.
 * 자세한 내용은 메뉴얼을 참조하세요. */

#define MSR_STAR 0xc0000081			/* 세그먼트 선택자 msr */
#define MSR_LSTAR 0xc0000082		/* Long mode SYSCALL 목적지 */
#define MSR_SYSCALL_MASK 0xc0000084 /* eflags를 위한 마스크 */

void syscall_init(void)
{
	lock_init(&fd_lock);

	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 |
							((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t)syscall_entry);

	/* 인터럽트 서비스 루틴은 syscall_entry가 유저랜드 스택을 커널
	 * 모드 스택으로 교체하기 전까지 어떤 인터럽트도 처리해서는 안됩니다.
	 * 따라서 FLAG_FL을 마스킹했습니다. */
	write_msr(MSR_SYSCALL_MASK,
			  FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}
/* The main system call interface */
void syscall_handler(struct intr_frame *f)
{
	uint64_t sys_no = f->R.rax;
	if (sys_no >= 0x0 && sys_no <= 0x18)
	{
		switch (sys_no)
		{
			/* Halt the operating system. */
		case SYS_HALT:
			halt();
			break;
			/* Terminate this process. */
		case SYS_EXIT:
			exit(f->R.rdi);
			break;
			/* Clone current process. */
		case SYS_FORK:
			f->R.rax = fork(f->R.rdi, f);
			break;
			/* Switch current process. */
		case SYS_EXEC:
			f->R.rax = exec(f->R.rdi);
			break;
			/* Wait for a child process to die. */
		case SYS_WAIT:
			f->R.rax = wait(f->R.rdi);
			break;
			/* Create a file. */
		case SYS_CREATE:
			f->R.rax = create(f->R.rdi, f->R.rsi);
			break;
			/* Delete a file. */
		case SYS_REMOVE:
			f->R.rax = remove(f->R.rdi);
			break;
			/* Open a file. */
		case SYS_OPEN:
			f->R.rax = open(f->R.rdi);
			break;
			/* Obtain a file's size. */
		case SYS_FILESIZE:
			f->R.rax = filesize(f->R.rdi);
			break;
			/* Read from a file. */
		case SYS_READ:
			f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
			/* Write to a file. */
		case SYS_WRITE:
			f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
			/* Change position in a file. */
		case SYS_SEEK:
			seek(f->R.rdi, f->R.rsi);
			break;
			/* Report current position in a file. */
		case SYS_TELL:
			f->R.rax = tell(f->R.rdi);
			break;
			/* Close a file. */
		case SYS_CLOSE:
			close(f->R.rdi);
			break;
		case SYS_DUP2:
			f->R.rax = dup2(f->R.rdi, f->R.rsi);
			break;
		}
	}
	else
	{
		printf("Whaaaatt?!?@?!@#!!!\n");
	}
	// thread_exit();
}
void check_address(void *addr)
{
	struct thread *t = thread_current();
	if (!is_user_vaddr(addr) || addr == NULL ||
		pml4_get_page(t->pml4, addr) == NULL)
	{
		exit(-1);
	}
}
void halt()
{
	power_off();
}
void exit(int status)
{
	thread_current()->exit_status = status;
	printf("%s: exit(%d)\n", thread_current()->name, thread_current()->exit_status);
	thread_exit();
}
int exec(const char *file)
{
	check_address(file);
	int len = strlen(file) + 1;
	char *file_name = palloc_get_page(PAL_ZERO);

	if (file_name == NULL)
	{
		exit(-1);
	}
	strlcpy(file_name, file, len);
	if (process_exec(file_name) == -1)
	{
		return -1;
	}
	NOT_REACHED();
	return 0;
}
bool create(const char *file, unsigned int iniital_size)
{
	check_address(file);
	return filesys_create(file, iniital_size);
}
bool remove(const char *file)
{
	check_address(file);
	return filesys_remove(file);
}
tid_t fork(const char *thread_name, struct intr_frame *f)
{
	check_address(thread_name);
	return process_fork(thread_name, f);
}
int wait(tid_t tid)
{
	return process_wait(tid);
}
int open(const char *file_name)
{
	check_address(file_name);

	struct thread *curr = thread_current();

	if (curr->nextfd >= FDT_SIZE)
	{
		return -1;
	}

	struct file *_file = filesys_open(file_name);

	// fdt_file 을 위한 메모리 할당
	struct fdt_file *_fdt_file = malloc(FDT_FILE_SIZE);
	if (_file == NULL || _fdt_file == NULL)
	{
		return -1;
	}

	// fdt_file 을 초기화
	set_file(_fdt_file, _file);
	set_dup_count(_fdt_file, 0);

	// fdt_file 을 nextfd 로 저장
	curr->fdt[curr->nextfd] = _fdt_file;

	int current_fd = curr->nextfd;

	for (int i = 0; i < FDT_SIZE; i++)
	{
		if (curr->fdt[i] == NULL)
		{
			curr->nextfd = i;
			return current_fd;
		}
	}

	curr->nextfd = FDT_SIZE;

	return current_fd;
}

void close(int fd)
{
	struct thread *curr = thread_current();

	if (FDT_SIZE <= fd || fd < 0 || curr->fdt[fd] == NULL)
	{
		exit(-1);
	}

	/* stdin 과 stdout이 아닐 때
	   1. dup_count 가 0이면 바로 file 과 fdt_file 의 memory free
	   2. dup_count 가 0 이상이면 dup_count 감소*/
	if (curr->fdt[fd] != 1 && curr->fdt[fd] != 2)
	{
		if (get_dup_count(curr->fdt[fd]) > 0)
		{
			decrease_dup_count(curr->fdt[fd]);
		}
		else
		{
			file_close(get_file(curr->fdt[fd]));
			free(curr->fdt[fd]);
		}
	}

	// fdt[fd] NULL
	curr->fdt[fd] = NULL;

	for (int i = 0; i < FDT_SIZE; i++)
	{
		if (curr->fdt[i] == NULL)
		{
			curr->nextfd = i;
			break;
		}
	}
}

int read(int fd, void *buffer, unsigned size)
{
	check_address(buffer);

	struct thread *curr = thread_current();

	if (curr->fdt[fd] == 1)
	{
		return input_getc();
	}
	else
	{
		if (FDT_SIZE <= fd || fd < 0 || curr->fdt[fd] == NULL || curr->fdt[fd] == 2)
		{
			exit(-1);
		}
		lock_acquire(&fd_lock);
		int cnt = file_read(get_file(curr->fdt[fd]), buffer, size);
		lock_release(&fd_lock);
		return cnt;
	}
}

int filesize(int fd)
{
	struct thread *curr = thread_current();

	if (FDT_SIZE <= fd || fd < 0 || curr->fdt[fd] == NULL || curr->fdt[fd] == 1 || curr->fdt[fd] == 2)
	{
		exit(-1);
	}
	int length = file_length(get_file(curr->fdt[fd]));

	return length;
}

int write(int fd, void *buffer, unsigned size)
{
	check_address(buffer);

	struct thread *curr = thread_current();

	if (curr->fdt[fd] == 2)
	{
		putbuf(buffer, size);
		return size;
	}

	if (FDT_SIZE <= fd || fd < 0 || curr->fdt[fd] == NULL)
	{
		exit(-1);
	}
	lock_acquire(&fd_lock);
	int cnt = file_write(get_file(curr->fdt[fd]), buffer, size);
	lock_release(&fd_lock);
	return cnt;
}

unsigned tell(int fd)
{
	struct thread *curr = thread_current();

	if (FDT_SIZE <= fd || fd < 0 || curr->fdt[fd] == NULL)
	{
		exit(-1);
	}

	return file_tell(get_file(curr->fdt[fd]));
}

void seek(int fd, unsigned position)
{
	struct thread *curr = thread_current();
	if (curr->fdt[fd] && position >= 0 && curr->fdt[fd] != 1 && curr->fdt[fd] != 2)
		file_seek(get_file(curr->fdt[fd]), position);
}

int dup2(int oldfd, int newfd)
{
	struct thread *curr = thread_current();
	// 예외처리
	if (oldfd < 0 || newfd < 0 || !curr->fdt[oldfd] || FDT_SIZE <= oldfd || FDT_SIZE <= newfd)
	{
		return -1;
	}

	// 1. fd 가 가리키는 값이 1일 때
	if (curr->fdt[oldfd] == 1)
	{
		if (curr->fdt[oldfd] == curr->fdt[newfd])
		{
			return newfd;
		}
		if (curr->fdt[newfd] != 2)
		{
			if (curr->fdt[newfd] && get_dup_count(curr->fdt[newfd]))
			{
				decrease_dup_count(curr->fdt[newfd]);
			}
			else // dup_count 가 0 이라면, 살려둘 필요가 없으므로 close
			{
				file_close(get_file(curr->fdt[newfd]));
				free(curr->fdt[newfd]);
			}
		}

		curr->fdt[newfd] = 1;
		return newfd;
	}
	// 2. fd 가 가리키는 값이 2일 때
	else if (curr->fdt[oldfd] == 2)
	{
		if (curr->fdt[oldfd] == curr->fdt[newfd])
		{
			return newfd;
		}
		if (curr->fdt[newfd] != 1)
		{
			if (curr->fdt[newfd] && get_dup_count(curr->fdt[newfd]))
			{
				decrease_dup_count(curr->fdt[newfd]);
			}
			else // dup_count 가 0 이라면, 살려둘 필요가 없으므로 close
			{
				file_close(get_file(curr->fdt[newfd]));
				free(curr->fdt[newfd]);
			}
		}

		curr->fdt[newfd] = 2;
		return newfd;
	}

	// 이미 dup2 가 된 oldfd, newfd 가 parameter 로 들어오면 그대로 newfd 반환
	if (get_file(curr->fdt[oldfd]) == get_file(curr->fdt[newfd]))
	{
		return newfd;
	}

	// newfd 가 들어오려고 하는 자리가, 이미 이전 dup2 를 통해서 하나의 파일을 두 fd 가 가리키고 있는 상태라면
	// newfd 에 이미 존재하는 fd 를 덮어쓰지만, file 을 close 하지 않고 file 의 dup_count 만 감소해줌
	if (curr->fdt[newfd] && curr->fdt[newfd] != 1 && curr->fdt[newfd] != 2 && get_dup_count(curr->fdt[newfd]))
	{
		decrease_dup_count(curr->fdt[newfd]);
	}
	else if (curr->fdt[newfd] != NULL && curr->fdt[newfd] != 1 && curr->fdt[newfd] != 2) // dup_count 가 0 이라면, 살려둘 필요가 없으므로 close
	{
		file_close(get_file(curr->fdt[newfd]));
		free(curr->fdt[newfd]);
	}

	increase_dup_count(curr->fdt[oldfd]);
	curr->fdt[newfd] = curr->fdt[oldfd];

	for (int i = 0; i < FDT_SIZE; i++)
	{
		if (curr->fdt[i] == NULL)
		{
			curr->nextfd = i;
			return newfd;
		}
	}

	curr->nextfd = FDT_SIZE;

	return newfd;
}