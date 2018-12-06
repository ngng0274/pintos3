#include "vm/page.h"
#include "vm/frame.h"
#include "threads/thread.h"
#include "filesys/file.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include <string.h>

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

bool load_page(void *uaddr)
{
	struct sup_entry* spte = find_spte(uaddr);

	bool success = false;
	switch (spte->type)
	{
		case FILE:
			success = load_file(spte);
			break;
		case SWAP:
			success = load_swap(spte);
			break;
		case MMAP:
			success = load_mmap(spte);
			break;
	}
	return success;
}

bool load_file(struct sup_entry *spte)
{
	void* addr = pagedir_get_page(thread_current()->pagedir, spte->page);
	uint8_t *frame = frame_allocate(PAL_USER);
	if (frame == NULL)
		return false;
	if ((int) spte->read_bytes != file_read_at(spte->file, frame, spte->read_bytes, spte->offset))
	{
		frame_free(frame);
		return false;
	}
	memset(frame + spte->read_bytes, 0, spte->zero_bytes);
	if (!install_page(spte->page, frame, spte->writable))
	{
		frame_free(frame);
		return false;
	}
  	spte->loaded = true;
	return true;
}

bool load_swap(struct sup_entry *spte)
{
	return false;
}

 bool load_mmap(struct sup_entry *spte)
{
	return false;
}

bool add_file(struct file *file, int32_t offset, uint8_t *upage, uint32_t rbytes, uint32_t zbytes, bool writable)
{
	struct sup_entry *spte = malloc(sizeof(struct sup_entry));
	if(spte == NULL)
		return false;
	spte->file = file;
	spte->offset = offset;
	spte->read_bytes = rbytes;
	spte->zero_bytes = zbytes;
	spte->writable = writable;
	spte->loaded = false;
	spte->type = FILE;
	if(hash_insert(&thread_current()->supt, &spte->elem) == NULL)
		return true;
	else
		return false;
}

