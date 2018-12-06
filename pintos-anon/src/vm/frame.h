#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"

#include <stdbool.h>
#include <stdint.h>
#include <list.h>

struct lock frame_lock;

struct list frame_table;

struct frame_table_entry
{
	void *frame;

	//struct page_table_entry *pte;

	struct list_elem elem;

	struct thread *owner;
};

void frame_init();
void* frame_allocate(enum palloc_flags flags);
bool frame_free(void *frame);
bool frame_evict(void *frame);

#endif
