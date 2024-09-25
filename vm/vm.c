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

// 재원 추가 먼저 선언
uint64_t page_hash (const struct hash_elem *p_, void *aux UNUSED);
bool page_less (const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED);
bool supplemental_page_table_insert (struct supplemental_page_table *spt, struct page *page);
struct page *supplemental_page_table_find (struct supplemental_page_table *spt, void *va);
bool supplemental_page_table_delete (struct supplemental_page_table *spt, struct page *page);
/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();
#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
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
static void spt_page_destroyer (struct hash_elem *e, void *aux UNUSED);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
		vm_initializer *init, void *aux) {
	

	ASSERT (VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current ()->spt;

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */
		/* TODO: Insert the page into the spt. */

        struct page *new_page = malloc(sizeof(struct page));
        if (new_page == NULL) {
            goto err; 
        }
        // memset(new_page, 0, sizeof(struct page));
		// printf("\n\npage_alloc_ addr : %p\n", upage);

        uninit_new(new_page, pg_round_down(upage), init, type, aux ,type == VM_FILE ? file_backed_initializer : anon_initializer);

		new_page->writable = writable;

        if (!spt_insert_page(spt, new_page)) {
			// 재원 추가 일단 프레임 테이블이 없어 냅다 free 잘못되면
			// palloc_free_page(new_page->frame->kva);
			// free(new_page->frame);
            free(new_page);
            goto err;
        }
		
        return true;
    }

err:
	return false;
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
	bool succ = false;
	/* TODO: Fill this function. */
	// 재원 추가 vm
	succ = hash_insert (&spt->hash_table, &page->hash_elem) == NULL;
	return succ;
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	//재원 추가 vm
	bool succ = false;
	succ = hash_delete (&spt->hash_table, &page->hash_elem) != NULL;
	if(succ){
	vm_dealloc_page (page);}

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
        // dst 해시 테이블 초기화
        hash_init(&dst->hash_table, page_hash, page_less, NULL);

        // src 해시 테이블 순회
        struct hash_iterator i;
        hash_first(&i, &src->hash_table);
        while (hash_next(&i)) {  // hash_next는 모든 요소를 돌면 bukets->buket의 요소 모두 돌면 (이유는 malloc으로 bukets를 list 포인터 배열로 만들었기 때문)
                struct page *original_page = hash_entry(hash_cur(&i), struct page, hash_elem);

                // 새로운 페이지 구조체 할당
                struct page *copy_page = malloc(sizeof(struct page));
                if (copy_page == NULL)
                        return false;

                // 페이지 구조체 복사 (깊은 복사)
                memcpy(copy_page, original_page, sizeof(struct page));

                // 만약 페이지가 실제 메모리 프레임을 가지고 있다면 해당 프레임도 복사해야 함
                // 예시로 frame 복사 로직 추가
                if (original_page->frame != NULL) {
                        copy_page->frame = malloc(PAGE_SIZE);
                        if (copy_page->frame == NULL) {
                                free(copy_page);
                                return false;
                        }
                        memcpy(copy_page->frame, original_page->frame, PAGE_SIZE);  // 실제 메모리 복사
                }

                // hash_elem은 페이지마다 따로 관리되므로 copy_page의 hash_elem을 사용해야 함
                if (hash_insert(&dst->hash_table, &copy_page->hash_elem) != NULL) {
						//중복된 것이 있어서 해제
                        free(copy_page->frame);  
                        free(copy_page);  
                        return false;
                }
        }
        return true;
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	hash_clear(&spt->hash_table, spt_page_destroyer);
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
static void
spt_page_destroyer (struct hash_elem *e, void *aux UNUSED) {
    struct page *page = hash_entry(e, struct page, hash_elem);

	// 프레임 테이블도 정리해야함

    // // 수정된 내용을 저장장치에 기록
    // if (page->dirty)
    //     write_back_to_storage(page);
    free(page);
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
	// memset(frame, 0, sizeof(struct frame));
	frame->kva = palloc_get_page(PAL_USER | PAL_ZERO);
	frame->page = NULL;


	ASSERT (frame != NULL);
	ASSERT (frame->page == NULL);
	// printf("\nframe kva: %p", frame->kva);
	
	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr UNUSED) {
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr UNUSED,
		bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {

	struct supplemental_page_table *spt UNUSED = &thread_current ()->spt;

	 // 페이지 폴트 검증
	// printf("\n\nfault handle_ addr : %p\n", addr);

    if (addr == NULL || is_kernel_vaddr(addr))
        exit(-1);
    
	struct page *page = spt_find_page(spt, addr);
	
	if(page == NULL)
		exit(-1);
	// printf("fault run do claim page\n\n");
	return vm_do_claim_page (page);
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
	
	// printf("\nim do cla page page addr : %p\n", page->va);
	

	return swap_in (page, frame->kva);
}

