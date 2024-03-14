#define _GNU_SOURCE
#define C_FEK_HASH_MAP_IMPLEMENT
#include <dlfcn.h>
#include <execinfo.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include "hash_map.h"
#include "bt.h"
#include "common.h"

//#define ENABLE_DEBUG_FILE_LOGS
//#define INTERCEPT_CALLOC

#define REGULAR_ALLOCATIONS_TRACKING_ENABLED
#define MMAP_ALLOCATIONS_TRACKING_ENABLED
#define BACKTRACE_TRACKING_ENABLED
#define DUMP_THREAD_FREQUENCY_MS (5 * 1000)

#ifdef ENABLE_DEBUG_FILE_LOGS
int debug_fh;
#endif

// Tracking of allocations
static long long malloc_calls = 0;
static long long malloc_calls_peak = 0;
static long long mmap_calls = 0;

// Lock attributes
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_t owner;
static int locked = 0;

// Pointers to real funcs
void* (*real_malloc)(size_t) = NULL;
void* (*real_calloc)(size_t, size_t) = NULL;
void* (*real_realloc)(void*, size_t) = NULL;
void* (*real_free)(void*) = NULL;
void* (*real_mmap)(void *addr, size_t length, int prot, int flags, int fd, off_t offset) = NULL;
int (*real_munmap)(void *addr, size_t length) = NULL;

// Dump thread handler
static pthread_t dump_thread;

// Flag indicating whether the module is initialized
int initialized = 0;

static void lock() {
    pthread_mutex_lock(&mutex);
    owner = pthread_self();
    locked = 1;
}

static void unlock() {
    locked = 0;
    pthread_mutex_unlock(&mutex);
}

static int does_thread_currently_holds_lock() {
    return locked && pthread_equal(owner, pthread_self());
}

static void init_symbols(void) {
    real_malloc = dlsym(RTLD_NEXT, "malloc");
    real_calloc = dlsym(RTLD_NEXT, "calloc");
    real_realloc = dlsym(RTLD_NEXT, "realloc");
    real_free = dlsym(RTLD_NEXT, "free");
    real_mmap = dlsym(RTLD_NEXT, "mmap");
    real_munmap = dlsym(RTLD_NEXT, "munmap");
}

static void* dump_thread_executor(void* args) {
    int fh;
    static char dump_thread_buffer[1024 * 1024];

    for (;;) {
        usleep(DUMP_THREAD_FREQUENCY_MS * 1000);

        lock();

#if defined(REGULAR_ALLOCATIONS_TRACKING_ENABLED) || defined(MMAP_ALLOCATIONS_TRACKING_ENABLED)
        // Write main FH
        int len = sprintf(dump_thread_buffer, "[%lld] [%lld] [%lld]\n", malloc_calls, malloc_calls_peak, mmap_calls);
        fh = open("/tmp/alloctracker-debug.txt", O_WRONLY | O_CREAT | O_APPEND, 0666);
        write(fh, dump_thread_buffer, len);
        close(fh);
#endif

#ifdef BACKTRACE_TRACKING_ENABLED
        // Write BT informtion
        bt_dump();
#endif

        unlock();
    }

    return 0;
}

void memmgmt_init(void) {
    if (initialized) {
#ifdef BACKTRACE_TRACKING_ENABLED
        // Must always call the initializer of bt.
        bt_init();
#endif

        return;
    }

    lock();

    if (initialized) {
#ifdef BACKTRACE_TRACKING_ENABLED
        // Must always call the initializer of bt.
        bt_init();
#endif

        unlock();
        return;
    }

    init_symbols();

    assert(!pthread_create(&dump_thread, NULL, dump_thread_executor, 0));
    initialized = 1;
#ifdef ENABLE_DEBUG_FILE_LOGS
    debug_fh = open("/tmp/alloctracker-debug-2.txt", O_WRONLY | O_CREAT | O_APPEND, 0666);
#endif

    unlock();
}

void *malloc(size_t size) {
#ifdef ENABLE_DEBUG_FILE_LOGS
    write(debug_fh, "malloc\n", sizeof("malloc\n") - 1);
#endif

    memmgmt_init();

    // If we already hold the lock, a new allocation was made while we were handling an allocation
    // In this case we ignore the event to avoid infinite loops.
    int was_already_lock_owner = does_thread_currently_holds_lock();
    void* ptr = real_malloc(size);

    if (!was_already_lock_owner) {
        lock();
    }

#ifdef REGULAR_ALLOCATIONS_TRACKING_ENABLED
    ++malloc_calls;
    if (malloc_calls > malloc_calls_peak) {
        malloc_calls_peak = malloc_calls;
    }
#ifdef BACKTRACE_TRACKING_ENABLED
    //if (!was_already_lock_owner) {
    //    bt_pointer_allocd_event(ptr, "malloc", size);
    //}
#endif
#endif

    if (!was_already_lock_owner) {
        unlock();
    }

    return ptr;
}

void *realloc(void* ptr, size_t size) {
#ifdef ENABLE_DEBUG_FILE_LOGS
    write(debug_fh, "realloc\n", sizeof("realloc\n") - 1);
#endif

    memmgmt_init();

    // If we already hold the lock, a new allocation was made while we were handling an allocation
    // In this case we ignore the event to avoid infinite loops.
    int was_already_lock_owner = does_thread_currently_holds_lock();
    void* new_ptr = real_realloc(ptr, size);

    if (!was_already_lock_owner) {
        lock();
    }

#ifdef REGULAR_ALLOCATIONS_TRACKING_ENABLED
    if (!ptr) {
        ++malloc_calls;
        if (malloc_calls > malloc_calls_peak) {
            malloc_calls_peak = malloc_calls;
        }

#ifdef BACKTRACE_TRACKING_ENABLED
        //if (!was_already_lock_owner) {
        //    bt_pointer_allocd_event(new_ptr, "realloc", size);
        //}
#endif
    } else if (size == 0) {
        --malloc_calls;
#ifdef BACKTRACE_TRACKING_ENABLED
        //bt_pointer_freed_event(ptr);
#endif
    } else {
#ifdef BACKTRACE_TRACKING_ENABLED
        //bt_pointer_freed_event(ptr);
        //if (!was_already_lock_owner) {
        //    bt_pointer_allocd_event(new_ptr, "realloc", size);
        //}
#endif
    }
#endif

    if (!was_already_lock_owner) {
        unlock();
    }
    return new_ptr;
}

void free(void* ptr) {
#ifdef ENABLE_DEBUG_FILE_LOGS
    write(debug_fh, "free\n", sizeof("free\n") - 1);
#endif

    memmgmt_init();

    // TODO: Test removing this check, this way we will never leak allocs. (realloc frees as well :()
    int was_already_lock_owner = does_thread_currently_holds_lock();
    real_free(ptr);

    if (!was_already_lock_owner) {
        lock();
    }

    if (ptr) {
#ifdef REGULAR_ALLOCATIONS_TRACKING_ENABLED
        --malloc_calls;
#ifdef BACKTRACE_TRACKING_ENABLED
        //bt_pointer_freed_event(ptr);
#endif
#endif
    }

    if (!was_already_lock_owner) {
        unlock();
    }
}

// In my current setup, calloc calls malloc, therefore, it shouldn't be intercepted.
#ifdef INTERCEPT_CALLOC
void *calloc(size_t nmemb, size_t size) {
    memmgmt_init();

    int was_already_lock_owner = does_thread_currently_holds_lock();
    void* ptr = real_calloc(nmemb, size);

    if (!was_already_lock_owner) {
        lock();
    }

#ifdef REGULAR_ALLOCATIONS_TRACKING_ENABLED
    ++malloc_calls;
    if (malloc_calls > malloc_calls_peak) {
        malloc_calls_peak = malloc_calls;
    }
#ifdef BACKTRACE_TRACKING_ENABLED
    if (!was_already_lock_owner) {
        bt_pointer_allocd_event(ptr, "malloc", nmemb * size);
    }
#endif
#endif
    if (!was_already_lock_owner) {
        unlock();
    }

    return ptr;
}
#endif

void* mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
#ifdef ENABLE_DEBUG_FILE_LOGS
    write(debug_fh, "mmap\n", sizeof("mmap\n") - 1);
#endif

    memmgmt_init();

    // If we already hold the lock, a new allocation was made while we were handling an allocation
    // In this case we ignore the event to avoid infinite loops.
    int was_already_lock_owner = does_thread_currently_holds_lock();
    void* result = real_mmap(addr, length, prot, flags, fd, offset);

    if (!was_already_lock_owner) {
        lock();
    }

#ifdef MMAP_ALLOCATIONS_TRACKING_ENABLED
    ++mmap_calls;
#ifdef BACKTRACE_TRACKING_ENABLED
    if (!was_already_lock_owner) {
        bt_pointer_allocd_event(result, "mmap", length);
    }
#endif
#endif

    if (!was_already_lock_owner) {
        unlock();
    }

    return result;
}

int munmap(void *addr, size_t length) {
#ifdef ENABLE_DEBUG_FILE_LOGS
    write(debug_fh, "munmap\n", sizeof("munmap\n") - 1);
#endif

    memmgmt_init();

    // TODO: Test removing this check, this way we will never leak allocs.
    int was_already_lock_owner = does_thread_currently_holds_lock();
    int result = real_munmap(addr, length);

    if (!was_already_lock_owner) {
        lock();
    }

#ifdef MMAP_ALLOCATIONS_TRACKING_ENABLED
    // This is not entirely correct - multiple munmaps can be called to completely free a single mmap
    // But for now this is good enough
    --mmap_calls;
#ifdef BACKTRACE_TRACKING_ENABLED
    bt_pointer_freed_event(addr);
#endif
#endif

    if (!was_already_lock_owner) {
        unlock();
    }
    return result;
}