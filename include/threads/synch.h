#ifndef THREADS_SYNCH_H
#define THREADS_SYNCH_H

#include <list.h>
#include <stdbool.h>

/* A counting semaphore. */
struct semaphore
{
	unsigned value;		 /* Current value. */
	struct list waiters; /* List of waiting threads. */
};

void sema_init(struct semaphore *, unsigned value);
void sema_down(struct semaphore *);
bool sema_try_down(struct semaphore *);
void sema_up(struct semaphore *);
void sema_self_test(void);

/* Lock. */
struct lock
{
	struct thread *holder;		/* Thread holding lock (for debugging). */
	struct semaphore semaphore; /* Binary semaphore controlling access. */

	// 재원 추가 prior-donate
	int donated_priority;
	// 재원 추가 prior-chain
	// struct list donate_list;

	struct list_elem lock_elem;
};

void lock_init(struct lock *);
void lock_acquire(struct lock *);
bool lock_try_acquire(struct lock *);
void lock_release(struct lock *);
bool lock_held_by_current_thread(const struct lock *);

/* Condition variable. */
struct condition
{
	struct list waiters; /* List of waiting threads. */
};

void cond_init(struct condition *);
void cond_wait(struct condition *, struct lock *);
void cond_signal(struct condition *, struct lock *);
void cond_broadcast(struct condition *, struct lock *);

void donate(struct thread *t, struct lock *lock);
void donate_realese(struct lock *lock);
void set_max_prior(struct lock *lock);
/* Optimization barrier.
 *
 * The compiler will not reorder operations across an
 * optimization barrier.  See "Optimization Barriers" in the
 * reference guide for more information.*/

// 컴파일러는 최적화 배리어를 가로질러 연산의 순서를 바꾸지 않습니다.
#define barrier() asm volatile("" : : : "memory")

#endif /* threads/synch.h */
