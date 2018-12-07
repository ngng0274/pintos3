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

	struct sup_entry *spte;

	struct list_elem elem;

	struct thread *owner;

	//bool pin;
};

void frame_init();
void* frame_allocate(enum palloc_flags flags, struct sup_entry *spte);
void frame_free(void *frame);
void* frame_evict(enum palloc_flags flags, struct sup_entry *spte);
void frame_add_table(void *frame);

#endif
