#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <list.h>
#include <stdint.h>
#include "threads/interrupt.h"
#ifdef VM
#include "vm/vm.h"
#endif


/* States in a thread's life cycle. */
#define LIST_MAX_SIZE 10
// 1 : 쓰레드 실행 중, 2: 준비 중, 3: 블락됨(기다리는 중), 4: 뒤짐
enum thread_status
{
	THREAD_RUNNING, /* Running thread. */
	THREAD_READY,	/* Not running but ready to run. */
	THREAD_BLOCKED, /* Waiting for an event to trigger. */
	THREAD_DYING	/* About to be destroyed. */
};

/* Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;
#define TID_ERROR ((tid_t) - 1) /* Error value for tid_t. */

/* Thread priorities. */
// 우선순위 값 0 ~ 63 범위 내 있음. 정도가
#define PRI_MIN 0	   /* Lowest priority. */
#define PRI_DEFAULT 31 /* Default priority. */
#define PRI_MAX 63	   /* Highest priority. */

/* A kernel thread or user process.
 *
 * Each thread structure is stored in its own 4 kB page.  The
 * thread structure itself sits at the very bottom of the page
 * (at offset 0).  The rest of the page is reserved for the
 * thread's kernel stack, which grows downward from the top of
 * the page (at offset 4 kB).  Here's an illustration:
 *
 *      4 kB +---------------------------------+
 *           |          kernel stack           |
 *           |                |                |
 *           |                |                |
 *           |                V                |
 *           |         grows downward          |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           +---------------------------------+
 *           |              magic              |
 *           |            intr_frame           |
 *           |                :                |
 *           |                :                |
 *           |               name              |
 *           |              status             |
 *      0 kB +---------------------------------+
 *
 * The upshot of this is twofold:
 *
 *    1. First, `struct thread' must not be allowed to grow too
 *       big.  If it does, then there will not be enough room for
 *       the kernel stack.  Our base `struct thread' is only a
 *       few bytes in size.  It probably should stay well under 1
 *       kB.
 *
 *    2. Second, kernel stacks must not be allowed to grow too
 *       large.  If a stack overflows, it will corrupt the thread
 *       state.  Thus, kernel functions should not allocate large
 *       structures or arrays as non-static local variables.  Use
 *       dynamic allocation with malloc() or palloc_get_page()
 *       instead.
 *
 * The first symptom of either of these problems will probably be
 * an assertion failure in thread_current(), which checks that
 * the `magic' member of the running thread's `struct thread' is
 * set to THREAD_MAGIC.  Stack overflow will normally change this
 * value, triggering the assertion. */
/* The `elem' member has a dual purpose.  It can be an element in
 * the run queue (thread.c), or it can be an element in a
 * semaphore wait list (synch.c).  It can be used these two ways
 * only because they are mutually exclusive: only a thread in the
 * ready state is on the run queue, whereas only a thread in the
 * blocked state is on a semaphore wait list. */

// 결론은 두 가지입니다 : **1. 첫째, '구조 스레드'가 너무 커지지 않도록 해야 합니다.
// 그렇게 되면 커널 스택을 위한 공간이 충분하지 않게 됩니다.
// 우리의 기본 '구조체 스레드'는 크기가 몇 바이트에 불과합니다.아마도 1KB 미만으로 유지되어야 할 것입니다.* *
// 2. 둘째, 커널 스택이 너무 커지지 않도록 해야 합니다.스택이 오버플로되면 스레드 상태가 손상됩니다.
// 따라서 커널 함수는 큰 구조체나 배열을 정적이 아닌 지역 변수로 할당해서는 안 됩니다.
// 대신 malloc() 또는 palloc_get_page() 와 함께 동적 할당을 사용하세요.
//**이러한 문제의 첫 번째 증상은 실행 중인 스레드의 '구조체 스레드'의 'magic' 멤버가 THREAD_MAGIC으로 설정되어 있는지 확인하는 thread_current() 의 어설션 실패일 수 있습니다.
// 스택 오버플로는 일반적으로 이 값을 변경하여 어설션을 트리거합니다.* /
/* `elem' 멤버는 두 가지 용도로 사용됩니다.
//실행 대기열(thread.c)의 요소일 수도 있고, 세마포어 대기 목록(synch.c)의 요소일 수도 있습니다.
//준비 상태의 스레드만 실행 대기열에 있는 반면, 차단 상태의 스레드만 세마포어 대기 목록에 있기 때문에 이 두 가지 방법으로만 사용할 수 있습니다. */

struct thread
{
	/* Owned by thread.c. */
	tid_t tid;				   /* Thread identifier. */
	enum thread_status status; /* Thread state. */
	char name[16];			   /* Name (for debugging purposes). */
	int priority;			   /* Priority. */
	// 재원 추가 prior-donate
	int original_priority;
	// 재원 추가 alarm
	int sleep_tick;

	// 재원 추가 prior-donate-multiple1
	struct list lock_list;
	struct lock *wating_lock;
	struct list_elem elem; /* List element. */

	// 재원 추가 mlfqs
	int nice;
	int recent_cpu;
	struct list_elem all_elem;

#ifdef USERPROG
	/* Owned by userprog/process.c. */
	uint64_t *pml4; /* Page map level 4 */
	// 재원 추가 syscall
	int exit_value;
	struct file *file_list[LIST_MAX_SIZE];
	int file_count;

	bool isfork;

	struct thread *parent;
	struct list child_list;
	struct list_elem child_elem;

	int child_num;
	bool wakeup_parent;

	struct intr_frame *user_if;

	bool isuser;

	struct file *exec_file;

#endif
#ifdef VM
	/* Table for whole virtual memory owned by thread. */
	struct supplemental_page_table spt;
#endif

	/* Owned by thread.c. */
	struct intr_frame tf; /* Information for switching */
	// 스택 오버플로우 방지를 위한 경계 변수
	// 커널이 밑으로 내려오면서 magic값을 보면 stop하게 됨. 고로 magic값은 무작위 값으로 주어짐.(특별해야 확인 쉽)
	// 스택오버플로우는 이 값이 덮어씌워져서 assertion 이 발생
	// 또한 thread_current함수가 실행될때 magic이 제대로 되어있나 확임함.
	unsigned magic; /* Detects stack overflow. */
};

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
extern bool thread_mlfqs;

void thread_init(void);
void thread_start(void);

void thread_tick(void);
void thread_print_stats(void);

typedef void thread_func(void *aux);
tid_t thread_create(const char *name, int priority, thread_func *, void *);

void thread_block(void);
void thread_unblock(struct thread *);

struct thread *thread_current(void);
tid_t thread_tid(void);
const char *thread_name(void);

void thread_exit(void) NO_RETURN;
void thread_yield(void);

int thread_get_priority(void);
void thread_set_priority(int);

int thread_get_nice(void);
void thread_set_nice(int nice);
int thread_get_recent_cpu(void);
int thread_get_load_avg(void);

void do_iret(struct intr_frame *tf);

// 재원 추가
void thread_sleep(int ticks);
void thread_awake(int current_ticks);
bool sleep_tick_less(const struct list_elem *a, const struct list_elem *b, void *aux UNUSED);
bool thread_less_fun(const struct list_elem *a, const struct list_elem *b, void *aux);
bool thread_greater_fun(const struct list_elem *a, const struct list_elem *b, void *aux);
void preempt(void);

void cal_prior(struct thread *t);
void cal_recent_cpu(struct thread *t);
void cal_load_avg(void);
void cur_cpu_increment(void);
void all_prior_set(void);
void all_cpu_set(void);
#endif /* threads/thread.h */
