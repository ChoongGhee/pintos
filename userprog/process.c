#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "intrinsic.h"

// 재원 추가
#include "user/syscall.h"


#ifdef VM
#include "vm/vm.h"
#endif

static void process_cleanup(void);
static bool load(const char *file_name, struct intr_frame *if_);
static void initd(void *f_name);
static void __do_fork(void *);

/* General process initializer for initd and other process. */
static void
process_init(void)
{
	struct thread *current = thread_current();
}

/* Starts the first userland program, called "initd", loaded from FILE_NAME.
 * The new thread may be scheduled (and may even exit)
 * before process_create_initd() returns. Returns the initd's
 * thread id, or TID_ERROR if the thread cannot be created.
 * Notice that THIS SHOULD BE CALLED ONCE. */
tid_t process_create_initd(const char *file_name)
{
	char *fn_copy;
	tid_t tid;

	/* Make a copy of FILE_NAME.
	 * Otherwise there's a race between the caller and load(). */
	fn_copy = palloc_get_page(0);
	if (fn_copy == NULL)
		return TID_ERROR;
	strlcpy(fn_copy, file_name, PGSIZE);

	// 재원 추가 passing
	char *trash_svg;
	strtok_r(file_name, " ", &trash_svg);

	/* Create a new thread to execute FILE_NAME. */
	tid = thread_create(file_name, PRI_DEFAULT, initd, fn_copy);
	if (tid == TID_ERROR)
		palloc_free_page(fn_copy);
	return tid;
}

/* A thread function that launches first user process. */
static void
initd(void *f_name)
{
#ifdef VM
	supplemental_page_table_init(&thread_current()->spt);
#endif

	process_init();

	if (process_exec(f_name) < 0)
		PANIC("Fail to launch initd\n");
	NOT_REACHED();
}

/* Clones the current process as `name`. Returns the new process's thread id, or
 * TID_ERROR if the thread cannot be created. */
tid_t process_fork(const char *name, struct intr_frame *if_)
{
	/* Clone current thread to new thread.*/
	struct thread *cur = thread_current();
	cur->user_if = if_;
	// cur->user_if = malloc(sizeof(struct intr_frame));
	// memcpy(cur->user_if, if_, sizeof(struct intr_frame));

	int temp = thread_create(name, PRI_DEFAULT, __do_fork, cur);

	// printf("\ntid num : %d\n", temp);
	enum intr_level old_level = intr_disable();
	thread_block();
	intr_set_level(old_level);

	if (cur->isfork == 0)
	{
		// printf("\nfork Error\n");

		return TID_ERROR;
	}
	return temp;
}

#ifndef VM
/* Duplicate the parent's address space by passing this function to the
 * pml4_for_each. This is only for the project 2. */
static bool
duplicate_pte(uint64_t *pte, void *va, void *aux)
{
	struct thread *current = thread_current();
	struct thread *parent = (struct thread *)aux;
	void *parent_page;
	void *newpage;
	bool writable;

	// 재원 추가 fork
	/* 1. TODO: If the parent_page is kernel page, then return immediately. */
	if (is_kernel_vaddr(va))
		return true;

	/* 2. Resolve VA from the parent's page map level 4. */
	parent_page = pml4_get_page(parent->pml4, va);
	if (parent_page == NULL)
		return false;

	/* 3. TODO: Allocate new PAL_USER page for the child and set result to
	 *    TODO: NEWPAGE. */
	newpage = palloc_get_page(PAL_ZERO);
	if (newpage == NULL)
		return false;

	/* 4. TODO: Duplicate parent's page to the new page and
	 *    TODO: check whether parent's page is writable or not (set WRITABLE
	 *    TODO: according to the result). */
	memcpy(newpage, parent_page, PGSIZE);
	/* 5. Add new page to child's page table at address VA with WRITABLE
	 *    permission. */
	writable = is_writable(pte);

	if (!pml4_set_page(current->pml4, va, newpage, writable))
	{
		/* 6. TODO: if fail to insert page, do error handling. */
		palloc_free_page(newpage);
		return false;
	}
	return true;
}
#endif

/* A thread function that copies parent's execution context.
 * Hint) parent->tf does not hold the userland context of the process.
 *       That is, you are required to pass second argument of process_fork to
 *       this function. */
static void
__do_fork(void *aux)
{
	// 자식 프로세스 인터럽트 프레임 작성
	struct intr_frame if_;
	// aux 내 부모 스레드 값 받음.
	struct thread *parent = (struct thread *)aux;
	// 현재는 자식 프로세스 중임.
	struct thread *current = thread_current();
	/* TODO: somehow pass the parent_if. (i.e. process_fork()'s if_) */
	// 재원 추가 fork()
	struct intr_frame *parent_if = parent->user_if;
	bool succ = true;

	// 재원 추가 fork (안정성을 위해)
	/* 1. Read the cpu context to local stack. */
	memcpy(&if_, parent_if, sizeof(struct intr_frame));
	if_.rip = parent_if->rip;

	// printf("\n\nif data %d\n\n", *if_);
	/* 2. Duplicate PT */
	current->pml4 = pml4_create();
	if (current->pml4 == NULL)
		goto error;

	process_activate(current);
#ifdef VM
	supplemental_page_table_init(&current->spt);
	if (!supplemental_page_table_copy(&current->spt, &parent->spt)){
		printf("나 자식임 죽음 ㅋㅋ");
		
		goto error;
	}
#else
	if (!pml4_for_each(parent->pml4, duplicate_pte, parent))
		goto error;
#endif

	// 재원 추가 fd_복사
	for (int i = 3; i < LIST_MAX_SIZE; i++)
	{
		if (parent->file_list[i] != NULL)
		{
			current->file_list[i] = file_duplicate(parent->file_list[i]);
			if (current->file_list[i] == NULL)
			{
				goto error;
			}
		}
	}

	current->file_count = parent->file_count;

	process_init();
	// 재원 추가 fork() 자식은 rax값 반환이 tid가 아님.
	if_.R.rax = 0;

	thread_unblock(parent);
	
	/* Finally, switch to the newly created process. */
	if (succ)
	{	
		// printf("\n\nfork done pa_rsp : %d, child_rsp: %d\n", parent_if->rsp,if_.rsp);
		// printf("\nfork  done pa_rip: %d, child_rip : %d", parent_if->rip, if_.rip);
		parent->isfork = true;
		do_iret(&if_);
	}
error:
	// 재원 추가 fork 메모리 초과라면 해당 자식프로세스 끄기
	// printf("\nfork Error\n");
	parent->isfork = false;
	current->exit_value = -1;
	thread_unblock(parent);
	// preempt();
	thread_exit();
}

/* Switch the current execution context to thㄲe f_name.
 * Returns -1 on fail. */
int process_exec(void *f_name)
{
	char *file_name = f_name;
	bool success;

	/* We cannot use the intr_frame in the thread structure.
	 * This is because when current thread rescheduled,
	 * it stores the execution information to the member. */
	struct intr_frame _if;
	_if.ds = _if.es = _if.ss = SEL_UDSEG;
	_if.cs = SEL_UCSEG;
	_if.eflags = FLAG_IF | FLAG_MBS;

	/* We first kill the current context */
	process_cleanup();

	/* And then load the binary */
	success = load(file_name, &_if);

	palloc_free_page(f_name);
	if (!success)
		return -1;

	// _if 쏴줌. 메뉴판
	do_iret(&_if);
	NOT_REACHED();
}

/* Waits for thread TID to die and returns its exit status.  If
 * it was terminated by the kernel (i.e. killed due to an
 * exception), returns -1.  If TID is invalid or if it was not a
 * child of the calling process, or if process_wait() has already
 * been successfully called for the given TID, returns -1
 * immediately, without waiting.
 *
 * This function will be implemented in problem 2-2.  For now, it
 * does nothing. */
int process_wait(tid_t child_tid)
{

	// 재원 추가
	struct thread *cur = thread_current();

	struct thread *child = NULL;

	struct list_elem *e;
	for (e = list_begin(&cur->child_list); e != list_end(&cur->child_list); e = list_next(e))
	{
		struct thread *t = list_entry(e, struct thread, child_elem);
		if (t->tid == child_tid)
		{
			child = t;
			break;
		}
	}

	if (child == NULL)
	{

		return -1; // 자식을 찾지 못했거나 이미 wait한 자식
	}

	// 자식 프로세스가 아직 종료되지 않은 경우
	if (child->status != THREAD_DYING)
	{
		child->wakeup_parent = true; // 자식이 종료될 때 부모를 깨우도록 설정
		enum intr_level old_level = intr_disable();
		thread_block(); // 부모 프로세스를 블록
		intr_set_level(old_level);
	}

	// 자식 프로세스가 종료된 후, 종료 상태를 반환
	int reval = child->exit_value;

	// 자식 프로세스의 메모리 해제
	list_remove(e);
	palloc_free_page(child);

	return reval;
}

/* Exit the process. This function is called by thread_exit (). */
void process_exit(void)
{
	struct thread *cur = thread_current();

	process_cleanup();

	if (cur->isuser)
	{
		printf("%s: exit(%d)\n", cur->name, cur->exit_value);
	}

#ifdef USERPROG

	if (cur->exec_file != NULL)
	{
		file_close(cur->exec_file);
	}

	// 재원 추가 wait() 뒤진 자식 정리 + 연 끊기
	while (!list_empty(&cur->child_list))
	{
		struct thread *child = list_entry(list_pop_front(&cur->child_list), struct thread, child_elem);
		if (child->status == THREAD_DYING)
		{
			palloc_free_page(child);
		}
		else
		{ // 작동 중이라면 기다림
			// wait(child->tid);
			child->parent = NULL;
		}
	}

	if (cur->parent != NULL && cur->wakeup_parent)
	{
		thread_unblock(cur->parent);
	}

	for (int i = 3; i < LIST_MAX_SIZE; i++)
	{
		if (cur->file_list[i] != NULL)
		{
			file_close(cur->file_list[i]);
		}
	}

#endif
#ifdef VM
	hash_destroy(&cur->spt, spt_page_destroyer);
#endif
}

/* Free the current process's resources. */
static void
process_cleanup(void)
{
	struct thread *curr = thread_current();

#ifdef VM
	supplemental_page_table_kill(&curr->spt);
#endif

	uint64_t *pml4;
	/* Destroy the current process's page directory and switch back
	 * to the kernel-only page directory. */
	pml4 = curr->pml4;
	if (pml4 != NULL)
	{
		/* Correct ordering here is crucial.  We must set
		 * cur->pagedir to NULL before switching page directories,
		 * so that a timer interrupt can't switch back to the
		 * process page directory.  We must activate the base page
		 * directory before destroying the process's page
		 * directory, or our active page directory will be one
		 * that's been freed (and cleared). */
		curr->pml4 = NULL;
		pml4_activate(NULL);
		pml4_destroy(pml4);
	}
}

/* Sets up the CPU for running user code in the nest thread.
 * This function is called on every context switch. */
void process_activate(struct thread *next)
{
	/* Activate thread's page tables. */
	pml4_activate(next->pml4);

	/* Set thread's kernel stack for use in processing interrupts. */
	tss_update(next);
}

/* We load ELF binaries.  The following definitions are taken
 * from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
#define EI_NIDENT 16

#define PT_NULL 0			/* Ignore. */
#define PT_LOAD 1			/* Loadable segment. */
#define PT_DYNAMIC 2		/* Dynamic linking info. */
#define PT_INTERP 3			/* Name of dynamic loader. */
#define PT_NOTE 4			/* Auxiliary info. */
#define PT_SHLIB 5			/* Reserved. */
#define PT_PHDR 6			/* Program header table. */
#define PT_STACK 0x6474e551 /* Stack segment. */

#define PF_X 1 /* Executable. */
#define PF_W 2 /* Writable. */
#define PF_R 4 /* Readable. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
 * This appears at the very beginning of an ELF binary. */
struct ELF64_hdr
{
	unsigned char e_ident[EI_NIDENT];
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint64_t e_entry;
	uint64_t e_phoff;
	uint64_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
};

struct ELF64_PHDR
{
	uint32_t p_type;
	uint32_t p_flags;
	uint64_t p_offset;
	uint64_t p_vaddr;
	uint64_t p_paddr;
	uint64_t p_filesz;
	uint64_t p_memsz;
	uint64_t p_align;
};

/* Abbreviations */
#define ELF ELF64_hdr
#define Phdr ELF64_PHDR

static bool setup_stack(struct intr_frame *if_);
static bool validate_segment(const struct Phdr *, struct file *);
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage,
						 uint32_t read_bytes, uint32_t zero_bytes,
						 bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
 * Stores the executable's entry point into *RIP
 * and its initial stack pointer into *RSP.
 * Returns true if successful, false otherwise. */
static bool
load(const char *file_name, struct intr_frame *if_)
{
	struct thread *t = thread_current();
	struct ELF ehdr;
	struct file *file = NULL;
	off_t file_ofs;
	bool success = false;
	int i;

	// 재원 추가 argument
	char *trash_svg;
	char *temp_filename = palloc_get_page(0);
	strlcpy(temp_filename, file_name, PGSIZE);
	strtok_r(file_name, " ", &trash_svg);

	/* Allocate and activate page directory. */
	t->pml4 = pml4_create();
	if (t->pml4 == NULL)
		goto done;
	process_activate(thread_current());

	/* Open executable file. */
	file = filesys_open(file_name);
	// file = open(file_name);
	if (file == NULL)
	{
		printf("load: %s: open failed\n", file_name);
		goto done;
	}

	/* Read and verify executable header. */
	if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr || memcmp(ehdr.e_ident, "\177ELF\2\1\1", 7) || ehdr.e_type != 2 || ehdr.e_machine != 0x3E // amd64
		|| ehdr.e_version != 1 || ehdr.e_phentsize != sizeof(struct Phdr) || ehdr.e_phnum > 1024)
	{
		printf("load: %s: error loading executable\n", file_name);
		goto done;
	}

	/* Read program headers. */
	file_ofs = ehdr.e_phoff;
	for (i = 0; i < ehdr.e_phnum; i++)
	{
		struct Phdr phdr;

		if (file_ofs < 0 || file_ofs > file_length(file))
			goto done;
		file_seek(file, file_ofs);

		if (file_read(file, &phdr, sizeof phdr) != sizeof phdr)
			goto done;
		file_ofs += sizeof phdr;
		switch (phdr.p_type)
		{
		case PT_NULL:
		case PT_NOTE:
		case PT_PHDR:
		case PT_STACK:
		default:
			/* Ignore this segment. */
			break;
		case PT_DYNAMIC:
		case PT_INTERP:
		case PT_SHLIB:
			goto done;
		case PT_LOAD:
			if (validate_segment(&phdr, file))
			{
				bool writable = (phdr.p_flags & PF_W) != 0;
				uint64_t file_page = phdr.p_offset & ~PGMASK;
				uint64_t mem_page = phdr.p_vaddr & ~PGMASK;
				uint64_t page_offset = phdr.p_vaddr & PGMASK;
				uint32_t read_bytes, zero_bytes;
				if (phdr.p_filesz > 0)
				{
					/* Normal segment.
					 * Read initial part from disk and zero the rest. */
					read_bytes = page_offset + phdr.p_filesz;
					zero_bytes = (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE) - read_bytes);
				}
				else
				{
					/* Entirely zero.
					 * Don't read anything from disk. */
					read_bytes = 0;
					zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
				}
				// 여기 file_page가 0인가? ofs이 그런가?
				// printf("\n\n%d\n\n", file_page);

				if (!load_segment(file, file_page, (void *)mem_page,
								  read_bytes, zero_bytes, writable))
					goto done;
				
				// 재원 추가 code 2
				if ((phdr.p_flags & PF_X) != 0) // 실행 가능한지 아닌지 확인하는 코드
                {
                  t->code_start = mem_page;
                  t->code_end = (mem_page + read_bytes + zero_bytes);
                }
			}
			else
				goto done;
			break;
		}
	}

	/* Set up stack. */
	if (!setup_stack(if_))
		goto done;

	/* Start address. */
	if_->rip = ehdr.e_entry;

	/* TODO: Your code goes here.
	 * TODO: Implement argument passing (see project2/argument_passing.html). */

	// 재원 추가 args
	char *save_ptr, *token;
	int argc = 0;
	// 전산학 전통, 관례상 128개의 인자를 받음. 1kb정도
	uintptr_t argv[128];

	// 파싱 작업 후 바로 작성 rsp에
	for (token = strtok_r(temp_filename, " ", &save_ptr); token != NULL; token = strtok_r(NULL, " ", &save_ptr))
	{
		if_->rsp -= strlen(token) + 1;
		strlcpy(if_->rsp, token, 128);
		argv[argc] = if_->rsp;
		argc++;
	}

	// 중간 패딩 및 경계면
	if_->rsp = if_->rsp & ~7ULL;
	if_->rsp -= 8;

	// 값들의 포인터 작성
	int cnt = argc - 1;
	while (cnt >= 0)
	{
		if_->rsp -= 8;
		*(uintptr_t *)(if_->rsp) = argv[cnt];
		cnt--;
	}

	// 세팅
	// argv 배열 rsi에 넣어줌.
	if_->R.rsi = if_->rsp;
	// main의 리턴되는 주소
	if_->rsp -= 8;
	// argc값 rdi에 세팅
	if_->R.rdi = argc;
	// 메모리 해제
	palloc_free_page(temp_filename);

	success = true;
done:
	/* We arrive here whether the load is successful or not. */
	// 재원 추가
	if (success)
	{
		t->exec_file = file;
		// file_deny_write(file);
		// file_close(t->exec_file);
	}
	else
	{
		t->exec_file = NULL;
		file_close(file);
	}
	return success;
}

/* Checks whether PHDR describes a valid, loadable segment in
 * FILE and returns true if so, false otherwise. */
static bool
validate_segment(const struct Phdr *phdr, struct file *file)
{
	/* p_offset and p_vaddr must have the same page offset. */
	if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
		return false;

	/* p_offset must point within FILE. */
	if (phdr->p_offset > (uint64_t)file_length(file))
		return false;

	/* p_memsz must be at least as big as p_filesz. */
	if (phdr->p_memsz < phdr->p_filesz)
		return false;

	/* The segment must not be empty. */
	if (phdr->p_memsz == 0)
		return false;

	/* The virtual memory region must both start and end within the
	   user address space range. */
	if (!is_user_vaddr((void *)phdr->p_vaddr))
		return false;
	if (!is_user_vaddr((void *)(phdr->p_vaddr + phdr->p_memsz)))
		return false;

	/* The region cannot "wrap around" across the kernel virtual
	   address space. */
	if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
		return false;

	/* Disallow mapping page 0.
	   Not only is it a bad idea to map page 0, but if we allowed
	   it then user code that passed a null pointer to system calls
	   could quite likely panic the kernel by way of null pointer
	   assertions in memcpy(), etc. */
	if (phdr->p_vaddr < PGSIZE)
		return false;

	/* It's okay. */
	return true;
}

#ifndef VM
/* Codes of this block will be ONLY USED DURING project 2.
 * If you want to implement the function for whole project 2, implement it
 * outside of #ifndef macro. */

/* load() helpers. */
static bool install_page(void *upage, void *kpage, bool writable);

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment(struct file *file, off_t ofs, uint8_t *upage,
			 uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
	ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT(pg_ofs(upage) == 0);
	ASSERT(ofs % PGSIZE == 0);

	file_seek(file, ofs);
	while (read_bytes > 0 || zero_bytes > 0)
	{
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* Get a page of memory. */
		uint8_t *kpage = palloc_get_page(PAL_USER);
		if (kpage == NULL)
			return false;

		/* Load this page. */
		if (file_read(file, kpage, page_read_bytes) != (int)page_read_bytes)
		{
			palloc_free_page(kpage);
			return false;
		}
		memset(kpage + page_read_bytes, 0, page_zero_bytes);

		/* Add the page to the process's address space. */
		if (!install_page(upage, kpage, writable))
		{
			printf("fail\n");
			palloc_free_page(kpage);
			return false;
		}

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a minimal stack by mapping a zeroed page at the USER_STACK */
static bool
setup_stack(struct intr_frame *if_)
{
	uint8_t *kpage;
	bool success = false;

	kpage = palloc_get_page(PAL_USER | PAL_ZERO);
	if (kpage != NULL)
	{
		success = install_page(((uint8_t *)USER_STACK) - PGSIZE, kpage, true);
		if (success)
			if_->rsp = USER_STACK;
		else
			palloc_free_page(kpage);
	}
	return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
 * virtual address KPAGE to the page table.
 * If WRITABLE is true, the user process may modify the page;
 * otherwise, it is read-only.
 * UPAGE must not already be mapped.
 * KPAGE should probably be a page obtained from the user pool
 * with palloc_get_page().
 * Returns true on success, false if UPAGE is already mapped or
 * if memory allocation fails. */
static bool
install_page(void *upage, void *kpage, bool writable)
{
	struct thread *t = thread_current();

	/* Verify that there's not already a page at that virtual
	 * address, then map our page there. */
	return (pml4_get_page(t->pml4, upage) == NULL && pml4_set_page(t->pml4, upage, kpage, writable));
}
#else
/* From here, codes will be used after project 3.
 * If you want to implement the function for only project 2, implement it on the
 * upper block. */


// 재원 추가 lazy에 넘겨줄 aux 데이터 구조체
// struct load_aux{
// 	struct file* file;
// 	off_t offset;
// 	size_t read_bytes;
// 	size_t zero_bytes;
// };

// static bool
bool
lazy_load_segment(struct page *page, void *aux)
{	
	struct load_aux* aux_info = (struct load_aux*) aux;
	/* TODO: Load the segment from the file */
	/* TODO: This called when the first page fault occurs on address VA. */
	/* TODO: VA is available when calling this function. */
	// size_t page_read_bytes, page_zero_bytes;
    // off_t offset;

	struct file *file = aux_info->file;
    off_t ofs = aux_info->offset;
    uint32_t read_bytes = aux_info->read_bytes;
    uint32_t zero_bytes = aux_info->zero_bytes;
    
    file_seek (file, ofs);
    
    // size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    // size_t page_zero_bytes = PGSIZE - page_read_bytes;
    
    /* 실제로 파일을 읽어와서 페이지에 매핑된 물리 프레임에 로드한다. */
    uint8_t *kva = page->frame->kva;
    if (kva == NULL)
        return false;
        
    /* 읽기 실패 */
    if (file_read (file, kva, read_bytes) != (int) read_bytes)
        return false;
        
    memset (kva + read_bytes, 0, zero_bytes);
	// 혹시 모르니 파일의 첫위치로 해줌
    // file_seek (file, 0); // 아닌듯

    /* 더이상 aux는 쓰이지 않는다. */
    free(aux);

	return true;

}

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */

static bool
load_segment(struct file *file, off_t ofs, uint8_t *upage,
			 uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
	ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT(pg_ofs(upage) == 0);
	ASSERT(ofs % PGSIZE == 0);

	while (read_bytes > 0 || zero_bytes > 0)
	{
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* TODO: Set up aux to pass information to the lazy_load_segment. */
		// 재원 추가 aux > bytes를 넘겨줘야함.
		struct load_aux *aux = malloc(sizeof(struct load_aux));
		aux->file = file;
		aux->offset = ofs;
		aux->read_bytes = page_read_bytes;
		aux->zero_bytes = page_zero_bytes;
		// aux 넣어줌
		if (!vm_alloc_page_with_initializer(VM_ANON, upage,
											writable, lazy_load_segment, aux))
			return false;

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
		// ofs 페이지 만큼 해줘야함. 왜냐면 해당 위치를 찾게 하기 위해.
		ofs += page_read_bytes;
	}
	return true;
}

/* Create a PAGE of stack at the USER_STACK. Return true on success. */
static bool
setup_stack(struct intr_frame *if_)
{
	bool success = false;
	void *stack_bottom = (void *)(((uint8_t *)USER_STACK) - PGSIZE);
	/* TODO: Map the stack on stack_bottom and claim the page immediately.
	 * TODO: If success, set the rsp accordingly.
	 * TODO: You should mark the page is stack. */
	/* TODO: Your code goes here */

	if (!vm_alloc_page(VM_ANON|VM_MARKER_0, stack_bottom, 1))
			return success;
	
	if (!vm_claim_page(stack_bottom))
        return success;

	if_->rsp = USER_STACK;

	thread_current()->alloc_stack_adrr = stack_bottom;

	success = true;

	return success;
}
#endif /* VM */
