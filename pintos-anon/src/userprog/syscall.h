#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/thread.h"
#include "threads/interrupt.h"
#include "filesys/file.h"
#include "filesys/filesys.h"

#include "vm/frame.h"
#include "vm/page.h"

typedef int pid_t;

struct lock file_lock;

struct file_
{
        struct file * file_addr;
        struct list_elem elem;
};

struct file
{
        struct inode *inode;        /* File's inode. */
        off_t pos;                  /* Current position. */
        bool deny_write;            /* Has file_deny_write() been called? */
};

void syscall_init (void);
void halt (void);
void exit (int stat);
pid_t exec (const char *cmd_line);
int wait (pid_t pid);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void* buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);
int mmap (int fd, void *addr);
void munmap (int mapping);
void check_addr(const void* vaddr);
void check_buffer(void* buffer, unsigned size);
void check_string(const void* str);


struct sup_entry* check_valid_ptr (const void *vaddr, void* esp);
void check_valid_buffer (void* buffer, unsigned size, void* esp, bool to_write);
void check_valid_string (const void* str, void* esp);
void check_write_permission (struct sup_entry *spte);

#endif /* userprog/syscall.h */
