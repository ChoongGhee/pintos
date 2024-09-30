/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"
// 재원 추가
#include "filesys/file.h"
#include "userprog/process.h"
#include "threads/vaddr.h"
#include "threads/mmu.h"

static bool file_backed_swap_in (struct page *page, void *kva);
static bool file_backed_swap_out (struct page *page);
static void file_backed_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
	.swap_in = file_backed_swap_in,
	.swap_out = file_backed_swap_out,
	.destroy = file_backed_destroy,
	.type = VM_FILE,
};

/* The initializer of file vm */
void
vm_file_init (void) {
}

/* Initialize the file backed page */
bool
file_backed_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &file_ops;

	struct file_page *file_page = &page->file;
}

/* Swap in the page by read contents from the file. */
static bool
file_backed_swap_in (struct page *page, void *kva) {
	struct file_page *file_page UNUSED = &page->file;
}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void
file_backed_destroy (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
}
bool
lazy_load_file(struct page *page, void *aux)
{	
	struct load_aux* aux_info = (struct load_aux*) aux;

	struct file *file = aux_info->file;
    off_t ofs = aux_info->offset;
    uint32_t read_bytes = aux_info->read_bytes;
    uint32_t zero_bytes = aux_info->zero_bytes;

    uint8_t *kva = page->frame->kva;
    

    if(read_bytes > 0){
    file_seek (file, ofs);
    /* 읽기 실패 */

    if (file_read (file, kva, read_bytes)!= (int) read_bytes){
        return false;}
    }

    memset (kva + read_bytes, 0, zero_bytes);

    pml4_set_dirty(thread_current()->pml4, page->va, true);
    /* 더이상 aux는 쓰이지 않는다. */
    free(aux);
    // printf("\nㅎㅇ? read %d, zero %d, ofs: %d\n\n", read_bytes, zero_bytes, ofs);

	return true;
}

/* Do the mmap */
void *
do_mmap (void *addr, size_t length, int writable, struct file *file, off_t offset) {
    struct thread* cur = thread_current();
    
    size_t file_size = file_length(file);
    if (file_size == 0)
        return NULL;

    // 실제 읽을 바이트 수 계산
    size_t read_bytes = file_size < length ? file_size : length;
    size_t remaining_length = length;

    void *va = addr;
    off_t file_offset = offset;

    int page_cnt = length / PGSIZE;
    if(length% PGSIZE > 0)
        page_cnt++;
    
    int cnt = 0;
    while (remaining_length > 0) 
    {   
        size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
        size_t page_zero_bytes = PGSIZE - page_read_bytes;

        // aux 구조체 설정
        struct load_aux *aux = malloc(sizeof(struct load_aux));
        if (aux == NULL)
            return NULL;
        
        aux->file = file_reopen(file);
        aux->offset = file_offset;
        aux->read_bytes = page_read_bytes;
        aux->zero_bytes = page_zero_bytes;
        
        // 페이지 할당
        if (!vm_alloc_page_with_initializer(VM_FILE, va,
                                            writable, lazy_load_file, aux))
        {
            free(aux);
            return NULL;
        }

        // unmap 때 참고
        struct page* p = spt_find_page(&cur->spt, va);

        struct file_info * info = malloc(sizeof(struct file_info));
        info->file_size = file_size;
        info->open_file = aux->file;
        info->start_va = addr;
        info->page_cnt = page_cnt;
        info->read_bytes = aux->read_bytes;
        info->zero_bytes = aux->zero_bytes;
        info->ofs = aux->offset;
        p->file_info = info;
        //


        // 다음 페이지로 이동
        if (read_bytes > 0) {
            read_bytes -= page_read_bytes;
            file_offset += page_read_bytes;
        }

        remaining_length -= PGSIZE;
        va += PGSIZE;

        cnt++;
        // printf("\n\n%d\n\n", cnt);
    }
        
    return addr;
}

/* Do the munmap */
void
do_munmap (void *addr) {

    struct thread * cur = thread_current();
    struct page* p = spt_find_page(&cur->spt, addr);

    size_t length = p->file_info->page_cnt*PGSIZE;
    void *va = p->file_info->start_va;

    // printf("\n\n%d\n\n", length);

    while(length > 0){
        
        struct page* temp = spt_find_page(&cur->spt, va);

        if(pml4_is_dirty(cur->pml4, va)){
            file_seek(temp->file_info->open_file, temp->file_info->ofs);
            file_write(temp->file_info->open_file, temp->frame->kva, temp->file_info->read_bytes);
        }

        file_close(temp->file_info->open_file);

        palloc_free_page(temp->frame->kva);

        free(temp->frame);
        free(temp->file_info);

        struct thread* cur = thread_current();
        spt_remove_page(&cur->spt, temp);
        // free(temp);

        pml4_clear_page(cur->pml4, va);

        length -= PGSIZE;
        va += PGSIZE;

    // printf("\n\n%d\n\n", length);

    }
}
