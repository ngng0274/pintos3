#include "vm/frame.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"

void frame_init() {
	list_init(&frame_table);
	lock_init(&frame_lock);
}

void* frame_allocate(enum palloc_flags flags) {
	if((flags & PAL_USER) == 0)
		return NULL;
	void *frame = palloc_get_page(flags);
	if(frame)
	{
		struct frame_table_entry *fte = malloc(sizeof(struct frame_table_entry));
  		fte->frame = frame;
  		fte->owner = thread_current();
  
  		lock_acquire(&frame_lock);
  		list_push_back(&frame_table, &fte->elem);
  		lock_release(&frame_lock);
	}
	else{
		if(!frame_evict(frame))
			PANIC("can not evict");
	}
	return frame;
}

bool frame_free(void *frame) {
	if(list_empty(&frame_table))
		return false;
	lock_acquire(&frame_lock);
	struct list_elem *e;
	for(e = list_begin(&(frame_table)); e != NULL; e=e->next)
	{
		struct frame_table_entry *fte = list_entry(e, struct frame_table_entry, elem);
		if(fte->frame == frame)
		{
			list_remove(e);
			free(fte);
			break;
		}
	}
	lock_release(&frame_lock);
	palloc_free_page(frame);
}

bool frame_evict(void *frame) {
	return false;
}
