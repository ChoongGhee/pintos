/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
// 재원 추가
#include "string.h"
#include "vm/uninit.h"
#include "vm/anon.h"
#include "vm/file.h"
#include "threads/mmu.h"
#include "userprog/syscall.h"
#include "userprog/process.h"

#include "threads/synch.h"

#define MAX_STACK_SIZE (1<<20)
// 재원 추가 먼저 선언
uint64_t page_hash (const struct hash_elem *p_, void *aux UNUSED);
bool page_less (const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED);
bool supplemental_page_table_insert (struct supplemental_page_table *spt, struct page *page);
struct page *supplemental_page_table_find (struct supplemental_page_table *spt, void *va);
bool supplemental_page_table_delete (struct supplemental_page_table *spt, struct page *page);
/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */

extern struct lock spt_lock;

vm_init (void) {
	vm_anon_init ();
	vm_file_init ();
#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
	lock_init(&spt_lock);
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);
void spt_page_destroyer (struct hash_elem *e, void *aux UNUSED);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable, vm_initializer *init, void *aux) {
	
	ASSERT (VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current ()->spt;
	// printf("\nalloc addr: %p thread_name : %s\n", upage, thread_current()->name);

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */
		/* TODO: Insert the page into the spt. */

        struct page *new_page = malloc(sizeof(struct page));
        if (new_page == NULL) {

			printf("\n\npage_alloc_ addr2233: %p\n", upage);
            goto err; 
        }

        memset(new_page, 0, sizeof(struct page));
		// printf("\n\npage_alloc_ addr22 : %p\n", upage);

        uninit_new(new_page, pg_round_down(upage), init, type, aux ,VM_TYPE(type) == VM_FILE ? file_backed_initializer : anon_initializer);

		new_page->writable = writable;

        if (!spt_insert_page(spt, new_page)) {
			// 재원 추가 일단 프레임 테이블이 없어 냅다 free 잘못되면
			// palloc_free_page(new_page->frame->kva);
			// free(new_page->frame);
			printf("\n\n%pdsad\n", upage);
			printf("\n\npage_alloc_ addr2233: %p\n", upage);

            free(new_page);
            goto err;
        }
		
        return true;
    }


err:
	{printf("안녕 나 뒤졌어 ㅋㅋ");
	return false;}
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
	/* TODO: Fill this function. */
	struct page p;
    struct hash_elem *e;

    p.va = pg_round_down(va);

    e = hash_find (&spt->hash_table, &p.hash_elem);

    return e != NULL ? hash_entry(e, struct page, hash_elem) : NULL;

}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt UNUSED,
		struct page *page UNUSED) {
	// lock_acquire(&spt_lock);
	bool succ = false;
	/* TODO: Fill this function. */
	// 재원 추가 vm
	succ = hash_insert (&spt->hash_table, &page->hash_elem) == NULL;
	// lock_release(&spt_lock);
	return succ;
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	//재원 추가 vm
	// lock_acquire(&spt_lock);
	bool succ = false;
	succ = hash_delete (&spt->hash_table, &page->hash_elem) != NULL;
	
	
	if(succ){
		// palloc_free_page(page->frame->kva);
		free(page->frame);
		vm_dealloc_page (page);}
	// lock_release(&spt_lock);
	

	return succ;
	
}
/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt UNUSED) {
	hash_init (&spt->hash_table, page_hash, page_less, NULL);
	// 락해야함?
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst,
                struct supplemental_page_table *src) {
        // dst 해시 테이블 초기화 이전에 함.
        // hash_init(&dst->hash_table, page_hash, page_less, NULL);

        // src 해시 테이블 순회
        struct hash_iterator i;
        hash_first(&i, &src->hash_table);
        

		while(hash_next(&i))
		{  
			// hash_next는 모든 요소를 돌면 bukets->buket의 요소 모두 돌면 (이유는 malloc으로 bukets를 list 포인터 배열로 만들었기 때문)
                struct page *original_page = hash_entry(hash_cur(&i), struct page, hash_elem);

                // 새로운 페이지 구조체 할당
				if(VM_TYPE(original_page->operations->type) == VM_UNINIT){
					// printf("im_uninit!!\n");

					struct load_aux * new_aux = malloc(sizeof(struct load_aux));
					if(new_aux == NULL){
						// printf("fuck\n");
						return false;
					}
					memcpy(new_aux, original_page->uninit.aux, sizeof(struct load_aux));

					// 이거 아닌 것 같은데 file 많이 많듦
					// new_aux->file = file_duplicate(new_aux->file);
					
					vm_alloc_page_with_initializer(page_get_type(original_page), original_page->va, original_page->writable, original_page->uninit.init, new_aux);
						
				}

				else{
					// printf("im_onon!!\n");
               	vm_alloc_page(page_get_type(original_page), original_page->va, original_page->writable);
				
				struct page* new_page = spt_find_page(dst, original_page->va);
				
				if(VM_TYPE(original_page->operations->type) == VM_FILE){
					new_page->file_info = original_page->file_info;
				}
				
				if(!vm_do_claim_page(new_page)){
					//  printf("\n\ndo claim_copy Failed!!\n\n");
					return false;}
				
				memcpy(new_page->frame->kva, original_page->frame->kva, PAGE_SIZE);}

        }
		// printf("\n\nfork done hello");
        return true;
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	hash_clear(&spt->hash_table, spt_page_destroyer);
	
	// hash_destroy(&spt->hash_table, spt_page_destroyer);
}


// 재원 추가 함수 @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
uint64_t page_hash (const struct hash_elem *p_, void *aux UNUSED) {
    const struct page *p = hash_entry (p_, struct page, hash_elem);
    return hash_bytes (&p->va, sizeof p->va);
}

bool page_less (const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED) {
    const struct page *a = hash_entry (a_, struct page, hash_elem);
    const struct page *b = hash_entry (b_, struct page, hash_elem);
    return a->va < b->va;
}
void
spt_page_destroyer (struct hash_elem *e, void *aux UNUSED) {
    struct page *free_page = hash_entry(e, struct page, hash_elem);

	struct file_info *info = free_page->file_info;
    struct thread* cur = thread_current();
	
    if(VM_TYPE(free_page->operations->type) == VM_FILE){
        if(pml4_is_dirty(cur->pml4, free_page->va)){
            file_write_at(info->open_file, free_page->frame->kva, info->read_bytes,info->ofs);
        }
    }

    free(aux);
	
    spt_remove_page(&cur->spt, free_page);
	// pml4_clear_unused_page(&cur->spt, free_page);
    // pml4_clear_page(cur->pml4, free_page->va);


	free(free_page);
}

// @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
	 /* TODO: The policy for eviction is up to you. */
	 if(victim == NULL)
		return NULL;

	
	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim UNUSED = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */

	return NULL;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
	// 재원 추가

	/* TODO: Fill this function. */
	struct frame *frame = malloc(sizeof(struct frame));
	memset(frame, 0, sizeof(struct frame));
	frame->kva = palloc_get_page(PAL_USER|PAL_ZERO);
	frame->page = NULL;


	ASSERT (frame != NULL);
	ASSERT (frame->page == NULL);
	// printf("\nframe kva: %p", frame->kva);
	
	return frame;
}

/* Growing the stack. */
// static void 원래 보이드 였는데 bool이 나을듯
static bool
vm_stack_growth (void *addr UNUSED, uintptr_t rsp UNUSED) {
	
	if (addr < rsp - 8 || addr > rsp + 32)
    	return false;

	struct thread* cur = thread_current();

	uintptr_t pgd_va = pg_round_down(addr);
	uintptr_t cur_alloc_stack = cur->alloc_stack_adrr - PAGE_SIZE;

	// printf("\ncur_alloc : %p, fault addr : %p, user %d\n", cur_alloc_stack, pgd_va, 3);

	for (; cur_alloc_stack >= pgd_va; cur_alloc_stack -= PAGE_SIZE){
		if(!vm_alloc_page(VM_ANON|VM_MARKER_0, cur_alloc_stack, 1))
			return false;
		if(!vm_claim_page(cur_alloc_stack))
			return false;

	}

	cur->alloc_stack_adrr = cur_alloc_stack;

	return true;
	
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr UNUSED,
		bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
	
	struct thread* cur = thread_current();
	struct supplemental_page_table *spt UNUSED = &cur->spt;
	// 주소 범위 검사
	// printf("\n\nfault addr: %p, and im %s \n", addr, thread_current()->name);

    if (addr == NULL || is_kernel_vaddr(addr)){
		// printf("\nim fault in addr null\n");
		
		return false;
	}
        
	
	struct page *page = spt_find_page(spt, addr);

	// printf("\nwrite: %d, and im %d, is_user %d, not_present %d \n", write, page->writable, user, not_present);

	if(page == NULL){
	// printf("\nwrite: %d, and im %d, is_user %d \n", write, page->writable, user);

		if((USER_STACK - MAX_STACK_SIZE <= addr) && (addr <= USER_STACK)){
			
			uintptr_t cur_rsp = user ? f->rsp : cur->syscall_rsp;

			// printf("\n\ncur_rsp : %p, fault addr : %p, user %d\n\n", cur_rsp, addr, user);
			return vm_stack_growth(addr, cur_rsp);
			
		}
		else{
			// printf("\nim fault in page null\n");
			return false;}

	}
	
	// 읽기 쓰기 권한 확인 못쓰면
	if(write && !page->writable)
		{	
			// printf("\n\nJSJD\n\n");
			return false;}


	if(not_present)
	{	
		int a = vm_do_claim_page(page);
		// printf("\nfault %p\n %p     %d\n\n", addr, page, a);

		return a;
	}
	
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* Claim the page that allocate on VA. */
bool
vm_claim_page (void *va UNUSED) {
	/* TODO: Fill this function */

	// printf("\n\nim claim page, addr : %p\n\n", va);
	struct page * page = spt_find_page(&thread_current()->spt, va);
	if(page == NULL)
		return NULL;

	return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame ();

	if(frame == NULL){
		return false;}

	/* Set links */

	frame->page = page;
	page->frame = frame;


	//재원 추가
	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	struct thread * cur = thread_current();
	if(!pml4_set_page(cur->pml4, page->va, frame->kva, page->writable)) // 검증 필요 PTE 권한 설정
		{
			return false;}
	

	return swap_in (page, frame->kva);
}

