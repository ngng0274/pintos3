#include "vm/page.h"
#include "vm/frame.h"
#include "vm/swap.h"
#include "threads/thread.h"
#include "filesys/file.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "userprog/syscall.h"
#include <string.h>
#include <stdbool.h>

unsigned page_table_hash(const struct hash_elem *e, void *aux UNUSED)
{
  struct sup_entry *spte = hash_entry(e, struct sup_entry, elem);
  return hash_int((int) spte->page);
}

bool compare(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
  struct sup_entry *sa = hash_entry(a, struct sup_entry, elem);
  struct sup_entry *sb = hash_entry(b, struct sup_entry, elem);
  if (sa->page < sb->page)
      return true;
  return false;
}

void page_free(struct hash_elem *e, void *aux UNUSED)
{
	struct sup_entry *spte = hash_entry(e, struct sup_entry, elem);
	if(spte->loaded)
	{
		frame_free(pagedir_get_page(thread_current()->pagedir, spte->page));
		pagedir_clear_page(thread_current()->pagedir, spte->page);
	}
	free(spte);
}


void page_table_init(struct hash *supt)
{
	hash_init(supt, page_table_hash, compare, NULL);
}

void page_table_destroy(struct hash *supt)
{
	hash_destroy(supt, page_free);
}

struct sup_entry* find_spte(void* uaddr)
{
	struct sup_entry spte;
        spte.page = pg_round_down(uaddr);
        struct hash_elem *e = hash_find(&thread_current()->supt, &spte.elem);
        if(e == NULL)
                return NULL;
        
	return hash_entry(e, struct sup_entry, elem);
}

bool load_page(struct sup_entry *spte)
{
	bool success = false;

	spte->pin = true;

	if (spte->loaded)
		return success;

	if(spte->type == SWAP)
		success = load_swap(spte);
	else
		success = load_file(spte);

	spte->loaded = true;
	return success;
}

bool load_file(struct sup_entry *spte)
{
	enum palloc_flags flags = PAL_USER;

	if (spte->read_bytes == 0)
		flags |= PAL_ZERO;

	uint8_t *frame = frame_allocate(PAL_USER, spte);

	if (frame == NULL)
		return false;
	
	if (spte->read_bytes > 0)
	{
		lock_acquire(&file_lock);
		
		if ((int) spte->read_bytes != file_read_at(spte->file, frame, spte->read_bytes, spte->offset))
		{
			lock_release(&file_lock);
			frame_free(frame);
			return false;
		}

		lock_release(&file_lock);
		memset(frame + spte->read_bytes, 0, spte->zero_bytes);
	}

	if (!install_page(spte->page, frame, spte->writable))
	{
		frame_free(frame);
		return false;
	}

	return true;
}

bool load_swap(struct sup_entry *spte)
{
	uint8_t *frame = frame_allocate(PAL_USER, spte);
	if (frame == NULL)
                return false;

	if (!install_page(spte->page, frame, spte->writable))
        {
                frame_free(frame);
                return false;
        }

	swap_in(spte->swap_index, spte->page);
        return true;
}

bool add_file(struct file *file, int32_t offset, uint8_t *upage, uint32_t rbytes, uint32_t zbytes, bool writable)
{
	struct sup_entry *spte = malloc(sizeof(struct sup_entry));
	if(spte == NULL)
		return false;
	spte->destroy = false;
	spte->file = file;
	spte->offset = offset;
	spte->page = upage;
	spte->read_bytes = rbytes;
	spte->zero_bytes = zbytes;
	spte->writable = writable;
	spte->loaded = false;
	spte->type = FILE;
	spte->pin = false;
	
	if(hash_insert(&thread_current()->supt, &spte->elem) == NULL)
		return true;
	else
		return false;
	
}

bool add_mmap(struct file *file, int32_t offset, uint8_t *upage, uint32_t rbytes, uint32_t zbytes)
{
        struct sup_entry *spte = malloc(sizeof(struct sup_entry));
        if(spte == NULL)
                return false;
	spte->destroy = false;
        spte->file = file;
        spte->offset = offset;
        spte->page = upage;
        spte->read_bytes = rbytes;
        spte->zero_bytes = zbytes;
        spte->writable = true;
        spte->loaded = false;
        spte->type = MMAP;
	spte->pin = false;
	
	struct mmap_file *mm = malloc(sizeof(struct mmap_file));
	if(mm == NULL)
	{
		free(spte);
		return false;
	}
	mm->spte = spte;
        mm->mmap_count = thread_current()->mmap_count;
        list_push_back(&thread_current()->mmap_list, &mm->elem);

        if(hash_insert(&thread_current()->supt, &spte->elem) == NULL)
		return true;
	else
	{
		spte->destroy = true;
                return false;
	}
}

bool page_stack_growth (void* uaddr)
{
	if((size_t) (PHYS_BASE - pg_round_down(uaddr)) > STACK_MAX)
		return false;

	struct sup_entry *spte = malloc(sizeof(struct sup_entry));
	if(spte == NULL)
		return false;
	spte->destroy = false;
	spte->page = pg_round_down(uaddr);
	spte->loaded = true;
	spte->writable = true;
	spte->type = SWAP;
	spte->pin = true;

	void* frame = frame_allocate(PAL_USER, spte);
	if(frame == NULL)
	{
		free(spte);
		return false;
	}
	if (!install_page(spte->page, frame, spte->writable))
    	{
      		free(spte);
      		frame_free(frame);
      		return false;
    	}
	
	if(hash_insert(&thread_current()->supt, &spte->elem) == NULL)
                return true;
        else
                return false;
}
