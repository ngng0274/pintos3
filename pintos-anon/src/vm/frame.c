#include "vm/frame.h"
#include "vm/page.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"

void frame_init() {
	list_init(&frame_table);
	lock_init(&frame_lock);
}

void* frame_allocate(enum palloc_flags flags, struct sup_entry *spte) {

	if((flags & PAL_USER) == 0)
		return NULL;
		
	void *frame = palloc_get_page(flags);



	if(frame)
	{
		struct frame_table_entry *fte = malloc(sizeof(struct frame_table_entry));
		fte->frame = frame;
		fte->owner = thread_current();
		fte->spte = spte;
		lock_acquire(&frame_lock);
		list_push_back(&frame_table, &fte->elem);
		lock_release(&frame_lock);
	}
	else{
		while(frame == NULL)
		{
			frame = frame_evict(flags);
			lock_release(&frame_lock);
		}
		struct frame_table_entry *fte = malloc(sizeof(struct frame_table_entry));
		fte->frame = frame;
		fte->owner = thread_current();
		fte->spte = spte;
		lock_acquire(&frame_lock);
		list_push_back(&frame_table, &fte->elem);
		lock_release(&frame_lock);
	}
	return frame;
}

void frame_free(void *frame) {

	lock_acquire(&frame_lock);
	struct list_elem *e;
	for(e = list_begin(&(frame_table)); e != NULL; e=e->next)
	{
		struct frame_table_entry *fte = list_entry(e, struct frame_table_entry, elem);
		if(fte->frame == frame)
		{
			list_remove(e);
			free(fte);
			palloc_free_page(frame);
			break;
		}
	}
	lock_release(&frame_lock);
}

void* frame_evict(enum palloc_flags flags) {
	lock_acquire(&frame_lock);
	size_t size = list_size(&frame_table);
	if (size == 0)       
	{
		lock_release(&frame_lock);
		return NULL;
	}
	struct list_elem *e = list_begin(&frame_table);
	struct frame_table_entry * fte;
	for(size_t i = 0; i <= size + size; i)
	{
		struct frame_table_entry *fte = list_entry(e, struct frame_table_entry, elem);
		if(fte->spte->pin)
			continue;
		else
		{
			struct thread *t = fte->owner;
			if (pagedir_is_accessed(t->pagedir, fte->spte->page))
			{
				pagedir_set_accessed(t->pagedir, fte->spte->page, false);
			}
			else
			{
				if (pagedir_is_dirty(t->pagedir, fte->spte->page) || fte->spte->type == SWAP)
				{
					if (fte->spte->type == MMAP)
					{
						lock_acquire(&file_lock);
						file_write_at(fte->spte->file, fte->frame,
								fte->spte->read_bytes,
								fte->spte->offset);
						lock_release(&file_lock);
					}
					else
					{
						fte->spte->type = SWAP;
						fte->spte->swap_index = swap_out(fte->frame);
					}
				}
				fte->spte->loaded = false;
				list_remove(&fte->elem);
				pagedir_clear_page(t->pagedir, fte->spte->page);
				palloc_free_page(fte->frame);
				free(fte);
				return palloc_get_page(flags);
			}
		}
		e = e->next;
		if (e == list_end(&frame_table))
		{
			e = list_begin(&frame_table);
		}
	}
}

