#ifndef ALLOC_TRACKER_COMMON_H
#define ALLOC_TRACKER_COMMON_H

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>

extern void* (*real_malloc)(size_t);
extern void* (*real_calloc)(size_t, size_t);
extern void* (*real_realloc)(void*, size_t);
extern void* (*real_free)(void*);
extern void* (*real_mmap)(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
extern int (*real_munmap)(void *addr, size_t length);
extern int (*real_backtrace)(void **buffer, int size);
extern char** (*real_backtrace_symbols)(void *const *buffer, int size);

static void* inner_calloc(size_t nmemb, size_t size) {
    void* ptr = real_malloc(nmemb * size);
    memset(ptr, 0, nmemb * size);
    return ptr;
}

static int hu_void_ptr_compare(const void* _key1, const void* _key2) {
    void* key1 = *(void**)_key1;
    void* key2 = *(void**)_key2;
    return key1 == key2;
}

static unsigned int hu_void_ptr_hash(const void* _key) {
    void* key = *(void**)_key;
    return (unsigned int)key;
}

static int hu_ull_compare(const void* key1, const void* key2) {
    unsigned long long key1_ull = *(unsigned long long*)key1;
    unsigned long long key2_ull = *(unsigned long long*)key2;
    return key1_ull == key2_ull;
}

static unsigned int hu_ull_hash(const void* key) {
    unsigned long long key_ull = *(unsigned long long*)key;
    // if the key value is greater than the maximum 'unsigned int',
    // this will just truncate all bits above the 32-bit threshold
    // which is fine for hashing purposes
    return (unsigned int)key_ull;
}

static unsigned long long hu_void_ptr_array_hash(const void** arr) {
    unsigned long long hash = 5381u;

    while (*arr) {
        void* ptr_val = (void*)(*arr);
        hash = ((hash << 5) + hash) + (unsigned long long)ptr_val;
        arr++;
    }

    return hash;
}

#endif