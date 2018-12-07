#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "devices/input.h"
#include "userprog/process.h"
#include "vm/frame.h"
#include "vm/page.h"

static void syscall_handler (struct intr_frame *);

void halt (void)
{
	shutdown_power_off();
}

void exit (int stat)
{
	printf("%s: exit(%d)\n",thread_current()->name, stat);
	thread_current()->exit_status = stat;
	while(!list_empty(&(thread_current()->fd)))	
		close(3);
	thread_exit ();
}

pid_t exec (const char *cmd_line)
{
	if(!cmd_line)
		return -1;
	pid_t pid = process_execute(cmd_line);
	return pid;
}

int wait (pid_t pid)
{
	return process_wait(pid);
}

int read (int fd, void* buffer, unsigned size)
{
	if(!is_user_vaddr(buffer))
		exit(-1);

	lock_acquire(&file_lock);
	int i = 0;
	if (fd == 0) {
		char *buffer_c = (char *) buffer;
		for (i = 0; i < size; i++)
			buffer_c[i] = input_getc();
		lock_release(&file_lock);
		return size;
	}
	else if(fd == 1 || fd == 2)
	{
		lock_release(&file_lock);
		return -1;
	}
	else{
		if(list_empty(&(thread_current()->fd))) {
			lock_release(&file_lock);
			return -1;
		}
		struct list_elem* e = list_begin(&(thread_current()->fd));
		struct file_* f = NULL;
		for(int j = 3; j != fd; j++) {
			e = e->next;
		}
		f = list_entry(e, struct file_, elem);

		if (f->file_addr == NULL) {
			lock_release(&file_lock);
			exit(-1);
		}

		lock_release(&file_lock);
		return file_read(f->file_addr, buffer, size);
	}

	lock_release(&file_lock);
	return i;
}

int write (int fd, const void *buffer, unsigned size)
{
	if(!is_user_vaddr(buffer))
		exit(-1);
	lock_acquire(&file_lock);
	if (fd == 1) {
		putbuf(buffer, size);
		lock_release(&file_lock);
		return size;
	}
	else if (fd >= 3) {
		if(list_empty(&(thread_current()->fd))) {
			lock_release(&file_lock);
			exit(-1);
		}
		struct list_elem* e = list_begin(&(thread_current()->fd));
		struct file_* f = NULL;
		for(int i = 3; i != fd; i++) {
			e = e->next;
		}
		f = list_entry(e, struct file_, elem);
		if(f->file_addr->deny_write)
		{
			file_deny_write(f->file_addr);
		}
		if (f->file_addr == NULL) {
			lock_release(&file_lock);
			exit(-1);
		}

		lock_release(&file_lock);
		return file_write(f->file_addr, buffer, size);
	}

	lock_release(&file_lock);
	return -1;
}




bool create (const char *file, unsigned init_size) {
	if (file == NULL)
		exit(-1);
	return filesys_create(file, init_size);
}

bool remove (const char *file) {
	if (file == NULL)
		exit(-1);
	return filesys_remove(file);
}

int open(const char *file) {
	if (file == NULL)
		exit(-1);
	if(!is_user_vaddr(file))
		exit(-1);

	lock_acquire(&file_lock);

	struct file* fp = filesys_open(file);

	if (fp == NULL) {
		lock_release(&file_lock);
		return -1;
	}
	else {
		struct file_* temp = (struct file_*)malloc(sizeof(struct file_));
		if(!temp)
		{
			lock_release(&file_lock);
			return -1;
		}
		struct list_elem* e;
		for(e = list_begin(&(thread_current()->fd)); e != NULL; e=e->next)
		{
			struct file_* f;
			f = list_entry(e, struct file_, elem);
			if(strcmp(thread_current()->name, file) == 0)
				file_deny_write(fp);
		}
		temp->file_addr = fp;
		list_push_back(&(thread_current()->fd), &temp->elem);
		int cnt = (int) list_size(&(thread_current()->fd)) + 2;


		lock_release(&file_lock);
		return cnt;
	}

}

int filesize (int fd) {
	if(list_empty(&(thread_current()->fd)))
		return -1;

	struct list_elem* e = list_begin(&(thread_current()->fd));
	struct file_* f = NULL;
	for(int i = 3; i < fd; i++) {
		e = e->next;
	}
	f = list_entry(e, struct file_, elem);

	if (f->file_addr == NULL)
		exit(-1);

	return file_length(f->file_addr);
}

void seek (int fd, unsigned position) {
	if(list_empty(&(thread_current()->fd)))
		return;

	struct list_elem* e = list_begin(&(thread_current()->fd));
	struct file_* f = NULL;
	for(int i = 3; i < fd; i++) {
		e = e->next;
	}
	f = list_entry(e, struct file_, elem);

	if (f->file_addr == NULL)
		exit(-1);

	file_seek(f->file_addr, position);
}

unsigned tell (int fd) {
	if(list_empty(&(thread_current()->fd)))
		return -1;

	struct list_elem* e = list_begin(&(thread_current()->fd));
	struct file_ *f;
	for(int i = 3; i < fd; i++) {
		e = e->next;
	}
	f = list_entry(e, struct file_, elem);

	if (f->file_addr == NULL)
		exit(-1);

	return file_tell(f->file_addr);
}

void close (int fd) {
	if(list_empty(&(thread_current()->fd)))
		return;

	struct list_elem* e = list_begin(&(thread_current()->fd));
	struct file_* f = NULL;
	for(int i = 3; i < fd; i++) {
		e = e->next;
	}

	f = list_entry(e, struct file_, elem);
	if (f->file_addr != NULL)
	{
		file_close(f->file_addr);
		list_remove(&f->elem);
		free(f);
	}
}

int mmap (int fd, void *addr)
{
	if(list_empty(&(thread_current()->fd)))
		return -1;

	struct list_elem* e = list_begin(&(thread_current()->fd));
	struct file_* f = NULL;
	for(int i = 3; i < fd; i++) {
		e = e->next;
	}

	f = list_entry(e, struct file_, elem);
	if(f->file_addr == NULL || !is_user_vaddr(addr) || addr < ((void*) 0x08048000) || ((uint32_t) addr % PGSIZE) != 0)
		return -1;

	struct file* file = file_reopen(f->file_addr);
	if(file == NULL || file_length(f->file_addr) == 0)
		return -1;

	thread_current()->mmap_count++;
	int32_t ofs = 0;
	uint32_t read_bytes = file_length(file);
	while (read_bytes > 0)
	{
		uint32_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		uint32_t page_zero_bytes = PGSIZE - page_read_bytes;
		if (!add_mmap(file, ofs, addr, page_read_bytes, page_zero_bytes))
		{
			munmap(thread_current()->mmap_count);
			return -1;
		}
		read_bytes -= page_read_bytes;
		ofs += page_read_bytes;
		addr += PGSIZE;
	}
	return thread_current()->mmap_count;
}

void munmap(int mapping)
{
	process_remove_mmap(mapping);
}

	void
syscall_init (void) 
{
	lock_init(&file_lock);
	intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

	static void
syscall_handler (struct intr_frame *f) 
{
	//printf("%d\n", *(uint32_t*) f->esp);

	check_addr((const void*) f->esp,(const void*) f->esp);

	switch (*(uint32_t *)(f->esp)){
		case SYS_HALT:
			halt();
			break;
		case SYS_EXIT:
			check_addr((const void*) f->esp+4,(const void*) f->esp);
			exit(*(uint32_t *)(f->esp + 4));
			break;
		case SYS_EXEC:
			check_addr((const void*) f->esp+4,(const void*) f->esp);
			check_string((const void*) f->esp+4,(const void*) f->esp);
			f->eax = exec((const char *)*(uint32_t *)(f->esp + 4));
			break;
		case SYS_WAIT:
			check_addr((const void*) f->esp+4,(const void*) f->esp);
			f->eax = wait((pid_t)*(uint32_t *)(f->esp + 4));
			break;
		case SYS_CREATE:
			check_addr((const void*) f->esp+16,(const void*) f->esp);
			check_addr((const void*) f->esp+20,(const void*) f->esp);
			check_string((const void*) f->esp+16,(const void*) f->esp);
			f->eax = create((const char *)*(uint32_t *)(f->esp + 16), (unsigned)*(uint32_t *)(f->esp + 20));
			break;
		case SYS_REMOVE:
			check_addr((const void*) f->esp+4,(const void*) f->esp);
			check_string((const void*) f->esp+4,(const void*) f->esp);
			f->eax = remove((const char *)*(uint32_t *)(f->esp + 4));
			break;
		case SYS_OPEN:
			check_addr((const void*) f->esp+4,(const void*) f->esp);
			check_string((const void*) f->esp+4,(const void*) f->esp);
			f->eax = open((const char *)*(uint32_t *)(f->esp + 4));
			break;
		case SYS_FILESIZE:
			check_addr((const void*) f->esp+4,(const void*) f->esp);
			f->eax = filesize((const char *)*(uint32_t *)(f->esp + 4));
			break;
		case SYS_READ:
			check_addr((const void*) f->esp+20,(const void*) f->esp);
			check_addr((const void*) f->esp+24,(const void*) f->esp);
			check_addr((const void*) f->esp+28,(const void*) f->esp);
			check_buffer((void *)*(uint32_t *)(f->esp + 24), (unsigned)*(uint32_t *)(f->esp + 28),(const void*) f->esp, true);
			f->eax = read((int)*(uint32_t *)(f->esp + 20), (void *)*(uint32_t *)(f->esp + 24), (unsigned)*(uint32_t *)(f->esp + 28));
			break;
		case SYS_WRITE:
			check_addr((const void*) f->esp+20,(const void*) f->esp);
			check_addr((const void*) f->esp+24,(const void*) f->esp);
			check_addr((const void*) f->esp+28,(const void*) f->esp);
			check_buffer((void *)*(uint32_t *)(f->esp + 24), (unsigned)*(uint32_t *)(f->esp + 28),(const void*) f->esp, false);
			f->eax = write((int)*(uint32_t *)(f->esp + 20), (void *)*(uint32_t *)(f->esp + 24), (unsigned)*(uint32_t *)(f->esp + 28));
			break;
		case SYS_SEEK:
			check_addr((const void*) f->esp+16,(const void*) f->esp);
			check_addr((const void*) f->esp+20,(const void*) f->esp);
			seek((const char *)*(uint32_t *)(f->esp + 16), (unsigned)*(uint32_t *)(f->esp + 20));
			break;
		case SYS_TELL:
			check_addr((const void*) f->esp+4,(const void*) f->esp);
			f->eax = tell((const char *)*(uint32_t *)(f->esp + 4));
			break;
		case SYS_CLOSE:
			check_addr((const void*) f->esp+4,(const void*) f->esp);
			close((const char *)*(uint32_t *)(f->esp + 4));
			break;
		case SYS_MMAP:
			check_addr((const void*) f->esp+16,(const void*) f->esp);
			check_addr((const void*) f->esp+20,(const void*) f->esp);

			f->eax = mmap((int)*(uint32_t *)(f->esp + 16), (void *)*(uint32_t *)(f->esp + 20));
			break;
		case SYS_MUNMAP:
			check_addr((const void*) f->esp+4,(const void*) f->esp);
			munmap(*(uint32_t *)(f->esp + 4));
			break;
	} 
}

struct sup_entry* check_addr(const void* vaddr, void* esp)
{
	if(!is_user_vaddr(vaddr) || vaddr < ((void*) 0x08048000))
	{
	//	printf("\n1\n");
		exit(-1);
	}
	bool load = false;
	struct sup_entry* spte = find_spte((void*) vaddr);
	if(spte == NULL)
	{
	//	printf("\n2\n");
		exit(-1);
	}

	load_page(spte);

	load = spte->loaded;

	if(!spte->loaded)
	{
	//	printf("\n3\n");
		exit(-1);
	}
	else if (vaddr >= esp - 32)
		page_stack_growth((void *) vaddr);

	if (!load)
		exit(-1);

	return spte;
}

void check_buffer(void* buffer, unsigned size, void* esp, bool to_write)
{
	char* buffer_ = (char*) buffer;
	for(unsigned i = 0; i < size; i++)
	{
		struct sup_entry *spte = check_addr((const void*) buffer_, esp);

		if (spte && to_write)
			if (!spte->writable)
				exit(-1);

		buffer_++;
	}
}

void check_string(const void* str, void* esp)
{
	while(*(char*) str != 0)
	{
		check_addr(str, esp);
		str = (char*) str+1;
	}
}


