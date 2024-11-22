/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */

#include "vm/vm.h"
#include "devices/disk.h"
#include "bitmap.h"

//재원 추가
static struct disk *swap_disk;
static struct bitmap* swap_bitmap;

/* DO NOT MODIFY BELOW LINE */
static bool anon_swap_in (struct page *page, void *kva);
static bool anon_swap_out (struct page *page);
static void anon_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations anon_ops = {
	.swap_in = anon_swap_in,
	.swap_out = anon_swap_out,
	.destroy = anon_destroy,
	.type = VM_ANON,
};

/* Initialize the data for anonymous pages */
void
vm_anon_init (void) {
	/* TODO: Set up the swap_disk. */
	swap_disk = disk_get(1,1);
	// 섹터의 갯수를 반환함. 그래서 그 갯수에 8을 나누면 페이지를 만들 수 있는 갯수
	size_t max_cnt = disk_size(swap_disk)/(8);
	swap_bitmap = bitmap_create(max_cnt);
}

/* Initialize the file mapping */
bool
anon_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	
	page->operations = &anon_ops;
	struct anon_page *anon_page = &page->anon;

	anon_page->swap_cnt = -1;
	//재원 추가
	return true;
}

/* Swap in the page by read contents from the swap disk. */
static bool
anon_swap_in (struct page *page, void *kva) {
	// printf("\nim swap_in_anon\n");
	if(!page->is_swapped){
		return true;
	}
	
	int base = page->swap_slot*8;
	for(int i = 0;i<8;i++){
		disk_read(swap_disk,base +i,page->frame->kva+(i*DISK_SECTOR_SIZE));
	}

	bitmap_reset(swap_bitmap,page->swap_slot);

	page->is_swapped = false;
	page->swap_slot = -1;

	//재원 추가
	return true;

}

/* Swap out the page by writing contents to the swap disk. */
static bool
anon_swap_out (struct page *page) {
	struct anon_page *anon_page = &page->anon;
	
	int swap_slot = bitmap_scan(swap_bitmap,0,1,0);

	if (swap_slot == BITMAP_ERROR) {
        // 스왑 공간이 부족하면 실패
        return false;
    }
	
	int base = swap_slot* 8;
	for(int i = 0;i<8;i++){
		disk_write(swap_disk,base +i,page->frame->kva+(i*DISK_SECTOR_SIZE));
	}

	bitmap_mark(swap_bitmap,swap_slot);

	pml4_set_accessed(thread_current()->pml4, page->va, false);
	pml4_clear_page(thread_current()->pml4, page->va);

	page->is_swapped = true;
	page->swap_slot = swap_slot;

	page->frame = NULL;

	return true;
}

/* Destroy the anonymous page. PAGE will be freed by the caller. */
static void
anon_destroy (struct page *page) {
	struct anon_page *anon_page = &page->anon;
	//재원 추가
	// palloc_free_page(page->frame->kva);
	// free(page->frame);
	return true;
}
