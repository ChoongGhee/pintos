#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
// 재원 추가
#include "filesys/filesys.h"
#include "threads/palloc.h"
#include "userprog/process.h"
#include "filesys/file.h"

#include "threads/synch.h"
#include "string.h"

void syscall_entry(void);
void syscall_handler(struct intr_frame *);

struct lock filesys_lock;

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081			/* Segment selector msr */
#define MSR_LSTAR 0xc0000082		/* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

struct syscall_info
{
	int arg_count;
	bool is_pointer[6]; // 최대 6개 인자에 대한 포인터 여부
};

static const struct syscall_info syscall_table[] = {
	[SYS_HALT] = {0, {false}},
	[SYS_EXIT] = {1, {false}},
	[SYS_FORK] = {1, {true}},
	[SYS_EXEC] = {1, {true}},
	[SYS_WAIT] = {1, {false}},
	[SYS_CREATE] = {2, {true, false}},
	[SYS_REMOVE] = {1, {true}},
	[SYS_OPEN] = {1, {true}},
	[SYS_FILESIZE] = {1, {false}},
	[SYS_READ] = {3, {false, true, false}},
	[SYS_WRITE] = {3, {false, true, false}},
	[SYS_SEEK] = {2, {false, false}},
	[SYS_TELL] = {1, {false}},
	[SYS_CLOSE] = {1, {false}}};

void syscall_init(void)
{
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 |
							((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t)syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			  FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);

	lock_init(&filesys_lock);
}
// 재원 추가
void halt(void)
{
	power_off();
}
void exit(int status)
{
	thread_current()->exit_value = status;
	thread_exit();
}
pid_t fork(const char *thread_name, struct intr_frame *f)
{
	struct thread *cur = thread_current();
	return process_fork(thread_name, f);
}
int exec(const char *cmd_line)
{
	// 만약 cml_line이 이름과 인자를 주는 명령어라고 가정한 방식임
	char *tempcopy = palloc_get_page(2);
	strlcpy(tempcopy, cmd_line, PGSIZE);

	if (thread_current()->exec_file != NULL)
		file_close(thread_current()->exec_file);

	return process_exec(tempcopy);
}
int wait(pid_t pid)
{
	return process_wait(pid);
}
bool create(const char *file, unsigned initial_size)
{
	return filesys_create(file, initial_size);
}
bool remove(const char *file)
{
	return filesys_remove(file);
}
int open(const char *file)
{
	struct thread *cur = thread_current();

	if (cur->file_count > LIST_MAX_SIZE)
	{
		return -1;
	}

	struct file *temp = filesys_open(file);
	if (temp == NULL)
	{
		return -1;
	}

	bool find = false;

	int idx = 3;
	for (idx; idx <= LIST_MAX_SIZE; idx++)
	{
		if (cur->file_list[idx] == NULL)
		{
			cur->file_list[idx] = temp;
			if (!strcmp(cur->name, file))
				file_deny_write(temp);

			cur->file_count++;
			find = true;
			break;
		}
	}

	if (find)
	{
		return idx;
	}
	else
	{
		file_close(temp);
		return -1;
	}
}
int filesize(int fd)
{
	struct thread *cur = thread_current();
	if (fd < 2 || fd > LIST_MAX_SIZE || cur->file_list[fd] == NULL)
	{
		return -1;
	}

	return file_length(cur->file_list[fd]);
}
int read(int fd, void *buffer, unsigned size)
{
	struct thread *cur = thread_current();

	if (fd < 2 || fd > LIST_MAX_SIZE || cur->file_list[fd] == NULL)
	{
		return -1;
	}
	int val = file_read(cur->file_list[fd], buffer, size);

	return val;
}
int write(int fd, const void *buffer, unsigned size)
{

	// lock_acquire(&filesys_lock);
	// printf("\ncur name %s, fd_num %d this start\n", thread_current()->name, fd);

	if (fd == STDOUT_FILENO)
	{
		// printf("\ncur name %s, fd_num %d this is STDOUT_FILENO\n", thread_current()->name, fd);
		putbuf((char *)buffer, size);
		// lock_release(&filesys_lock);
		return size;
	}
	else if (fd == STDIN_FILENO)
	{
		// printf("\ncur name %s, fd_num %d this is STDINFILENO\n", thread_current()->name, fd);
		// lock_release(&filesys_lock);
		return -1;
	}
	else
	{
		struct thread *cur = thread_current();
		if (fd < 2 || fd > LIST_MAX_SIZE || cur->file_list[fd] == NULL)
		{
			// printf("\ncur name %s, fd_num %d this is Error\n", thread_current()->name, fd);
			// lock_release(&filesys_lock);
			return -1;
		}
		int temp = file_write(cur->file_list[fd], buffer, size);
		// lock_release(&filesys_lock);

		// printf("\ncur name %s, fd_num %d this is file_write\n", thread_current()->name, fd);
		return temp;
	}
}
void seek(int fd, unsigned position)
{
	struct thread *cur = thread_current();
	if (fd < 2 || fd > LIST_MAX_SIZE || cur->file_list[fd] == NULL)
	{
		return -1;
	}

	file_seek(cur->file_list[fd], position);
}
unsigned tell(int fd)
{
	struct thread *cur = thread_current();
	if (fd < 2 || fd > LIST_MAX_SIZE || cur->file_list[fd] == NULL)
	{
		return -1;
	}

	return file_tell(cur->file_list[fd]);
}
void close(int fd)
{
	if (fd < 2 || fd >= LIST_MAX_SIZE)
		return;
	struct thread *cur = thread_current();

	if (cur->file_list[fd] != NULL)
	{
		file_close(cur->file_list[fd]);
		cur->file_list[fd] = NULL;
		cur->file_count--;
	}
}
// 재원 추가 vm
void *mmap (void *addr, size_t length, int writable, int fd, off_t offset){

}
// 시스템 콜 인자 검증 함수
bool validate_syscall_args(struct intr_frame *f)
{
	int syscall_number = f->R.rax;
	const struct syscall_info *info = &syscall_table[syscall_number];

	// Array of argument pointers
	void *args[] = {(void *)&f->R.rdi, (void *)&f->R.rsi, (void *)&f->R.rdx,
					(void *)&f->R.r10, (void *)&f->R.r8, (void *)&f->R.r9};

	for (int i = 0; i < info->arg_count; i++)
	{
		if (info->is_pointer[i])
		{
			uint64_t user_addr = *(uint64_t *)args[i];

			// 방법 1
			if (is_kernel_vaddr(user_addr) || user_addr == NULL || pml4_get_page(thread_current()->pml4, user_addr) == NULL)
			{
				return false; // Invalid address
			}
			// 방법 2 (편법 냅다 exit(-1) 핸들러에서)
			// if (is_kernel_vaddr(user_addr) || user_addr == NULL)

			// 방법 2 (실제 page_fault시켜서 작업하는 거)
			// Validate the user address by attempting to read from it
			// if (get_user((const uint8_t *)user_addr) == -1)
			// {
			// 	return false; // Invalid address
			// }
		}
	}

	return true; // All arguments are valid
}

/* The main system call interface */
void syscall_handler(struct intr_frame *f)
{
	thread_current()->isuser = true;
	if (!validate_syscall_args(f))
	{
		exit(-1);
	}

	switch (f->R.rax)
	{
	case SYS_HALT:
		halt();
		break;
	case SYS_EXIT:
		exit(f->R.rdi);
		break;
	case SYS_FORK:
		f->R.rax = fork(f->R.rdi, f);
		break;
	case SYS_EXEC:
		if (f->R.rax = exec(f->R.rdi) == -1)
		{
			exit(-1);
		}
		break;
	case SYS_WAIT:
		f->R.rax = wait(f->R.rdi);
		break;
	case SYS_CREATE:
		f->R.rax = create(f->R.rdi, f->R.rsi);
		break;
	case SYS_REMOVE:
		f->R.rax = remove(f->R.rdi);
		break;
	case SYS_OPEN:
		f->R.rax = open(f->R.rdi);
		break;
	case SYS_FILESIZE:
		f->R.rax = filesize(f->R.rdi);
		break;
	case SYS_READ:
		f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
		break;
	case SYS_WRITE:
		f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
		break;
	case SYS_SEEK:
		seek(f->R.rdi, f->R.rsi);
		break;
	case SYS_TELL:
		f->R.rax = tell(f->R.rdi);
		break;
	case SYS_CLOSE:
		close(f->R.rdi);
		break;
	default:
		printf("Unexpected system call!\n");
		exit(-1); // 걍꺼
	}
	// 재원 추가 exit는 exit시스템 콜에서 함
	// thread_exit();
}