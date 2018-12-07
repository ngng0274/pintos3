#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <hash.h>

#define FILE 0
#define SWAP 1
#define MMAP 2
#define HASH_ERROR 3
#define STACK_MAX (1 << 23)

struct sup_entry
{
	uint8_t type;
	void *page;

	bool writable;
	bool loaded;

	struct file *file;
	size_t offset;
	size_t read_bytes;
	size_t zero_bytes;

	size_t swap_index;

	struct hash_elem elem;
};

void page_table_init(struct hash *supt);
void page_table_destroy(struct hash *supt);

bool load_page(struct sup_entry *spte);
bool load_file(struct sup_entry *spte);
bool load_swap(struct sup_entry *spte);
bool load_mmap(struct sup_entry *spte);

bool add_file(struct file *file, int32_t offset, uint8_t *upage, uint32_t rbytes, uint32_t zbytes, bool writable);
bool add_mmap(struct file *file, int32_t offset, uint8_t *upage, uint32_t rbytes, uint32_t zbytes);

unsigned page_table_hash(const struct hash_elem *e, void *aux);
bool compare(const struct hash_elem *a, const struct hash_elem *b, void *aux);
void page_free(struct hash_elem *e, void *aux);

struct sup_entry* find_spte(void *uaddr);

bool page_stack_growth (void *uaddr);

#endif
