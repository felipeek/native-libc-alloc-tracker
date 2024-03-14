#include "bt.h"
#include "hash_map.h"
#include "common.h"
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdint.h>
#include <assert.h>
#include <dlfcn.h>
#include <pthread.h>

#define BACKTRACE_MAX_NUM_PTRS 128

typedef struct {
    unsigned long long backtrace_hash; // hash of the backtrace bound to this pointer
    size_t allocd_size; // how much memory allocated in this pointer
} Pointer_Info;

typedef struct {
    char type[64]; // string indicating type (human-friendly)
    int live_allocs; // indicates how many allocations (not freed yet) currently exist
    void** backtrace_raw; // the backtrace as a raw array of void*
    int backtrace_len; // number of pointers in the backtrace
    size_t total_allocd_size; // summed amount of memory currently allocated
} Backtrace_Info;

// Hash maps
static Hash_Map backtrace_hash_to_info_map; /* <Backtrace hash as ULL -> BacktraceInfo> */
static Hash_Map pointers_to_info_map; /* <Pointer as Void* -> Pointer Info> */

// Lock attributes
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

// Pointers to real funcs
int (*real_backtrace)(void **buffer, int size) = NULL;
char** (*real_backtrace_symbols)(void *const *buffer, int size) = NULL;

// Flag indicating whether real func symbols were already found in shared objects
static int found_symbols = 0;

// Flag indicating whether the module is initialized
static int initialized = 0;

// Here, we capture the symbols of 'backtrace' and 'backtrace_symbols'
// However, we need to have logic to gracefully retry if these symbols are not found
// Presumably this happens because the SO is only added to the process address space later on
// Therefore, the flag 'found_symbols' stores whether symbols were already found
static void bt_init_symbols(void) {
    if (found_symbols) {
        return;
    }

    pthread_mutex_lock(&mutex);

    if (found_symbols) {
        pthread_mutex_unlock(&mutex);
        return;
    }

    real_backtrace = dlsym(RTLD_NEXT, "backtrace");
    real_backtrace_symbols = dlsym(RTLD_NEXT, "backtrace_symbols");
    if (real_backtrace != NULL && real_backtrace_symbols != NULL) {
        write(1, "Found all BT symbols\n", sizeof("Found all BT symbols\n") - 1);
        found_symbols = 1;
    }

    pthread_mutex_unlock(&mutex);
}

void bt_init() {
    if (initialized) {
        bt_init_symbols();
        return;
    }

    pthread_mutex_lock(&mutex);

    if (initialized) {
        bt_init_symbols();
        pthread_mutex_unlock(&mutex);
        return;
    }

    assert(!hash_map_create(&backtrace_hash_to_info_map, 1024 * 1024, sizeof(unsigned long long), sizeof(Backtrace_Info*), hu_ull_compare, hu_ull_hash, inner_calloc, real_free));
    assert(!hash_map_create(&pointers_to_info_map, 1024 * 1024, sizeof(void*), sizeof(Pointer_Info), hu_void_ptr_compare, hu_void_ptr_hash, inner_calloc, real_free));
    initialized = 1;
    pthread_mutex_unlock(&mutex);
}

void bt_pointer_allocd_event(const void* ptr, const char* type, size_t allocd_size) {
    if (!initialized || !found_symbols) {
        return;
    }

    // Collect backtrace
    void* backtrace_result[BACKTRACE_MAX_NUM_PTRS];
    size_t backtrace_len = real_backtrace(backtrace_result, BACKTRACE_MAX_NUM_PTRS - 1);
    backtrace_result[backtrace_len] = 0x0;

    // Calculate hash of backtrace
    unsigned long long hash = hu_void_ptr_array_hash(backtrace_result);

    // Fill pointer to info map
    Pointer_Info pointer_info;
    pointer_info.backtrace_hash = hash;
    pointer_info.allocd_size = allocd_size;
    assert(!hash_map_put(&pointers_to_info_map, &ptr, &pointer_info));

    // Check if backtrace already exists
    Backtrace_Info* backtrace_info;
    if (hash_map_get(&backtrace_hash_to_info_map, &hash, &backtrace_info)) {
        // If it doesn't exist yet, fill it
        void** backtrace_result_allocd = (void**)real_malloc(BACKTRACE_MAX_NUM_PTRS * sizeof(void*));
        memcpy(backtrace_result_allocd, backtrace_result, BACKTRACE_MAX_NUM_PTRS * sizeof(void*));
        backtrace_info = (Backtrace_Info*)real_malloc(sizeof(Backtrace_Info));
        backtrace_info->live_allocs = 0;
        backtrace_info->backtrace_raw = backtrace_result_allocd;
        backtrace_info->backtrace_len = backtrace_len;
        backtrace_info->total_allocd_size = 0;
        strcpy(backtrace_info->type, type);
        assert(!hash_map_put(&backtrace_hash_to_info_map, &hash, &backtrace_info));
    }

    // Increase live allocs
    ++backtrace_info->live_allocs;
    backtrace_info->total_allocd_size += allocd_size;
}

void bt_pointer_freed_event(const void* ptr) {
    if (!initialized || !found_symbols) {
        return;
    }

    // Collect hash from map
    Pointer_Info pointer_info;
    int found = !hash_map_get(&pointers_to_info_map, &ptr, &pointer_info);

    if (!found) {
        // Usually, this should never happen.
        // However, there are situations that this will happen because, in the 'malloc'/'free'/etc wrappers, we ignore the events
        // when the thread that received the event is already the lock owner (check alloctracker.c)
        // This is because, during the handling of the wrappers, we call functions that allocate memory themselves
        // (e.g. 'backtrace' allocates memory)
        // This causes the wrappers to be called again, and we need to ignore the event to avoid infinite loops.
        // When these pointers are freed, we may end up here, but those pointers were never tracked.
        return;
    }

    // Delete it from map
    assert(!hash_map_delete(&pointers_to_info_map, &ptr));

    // Backtrace must exist
    Backtrace_Info* backtrace_info;
    assert(!hash_map_get(&backtrace_hash_to_info_map, &pointer_info.backtrace_hash, &backtrace_info));

    // Decrease live allocs
    --backtrace_info->live_allocs;
    backtrace_info->total_allocd_size -= pointer_info.allocd_size;

    // If no more allocs, we can clean this backtrace from the map
    if (backtrace_info->live_allocs == 0) {
        real_free(backtrace_info->backtrace_raw);
        real_free(backtrace_info);
        assert(!hash_map_delete(&backtrace_hash_to_info_map, &pointer_info.backtrace_hash));
    }
}

void bt_dump() {
    static char buffer[1024 * 1024];

    if (!initialized || !found_symbols) {
        return;
    }

    Backtrace_Info* backtrace_info;

    int fh = open("/tmp/alloctracker-bt.txt", O_WRONLY | O_CREAT | O_TRUNC | O_APPEND, 0666);

    Hash_Map_Iterator it = hash_map_get_iterator(&backtrace_hash_to_info_map);
    while ((it = hash_map_iterator_next(&backtrace_hash_to_info_map, it, NULL, &backtrace_info)) != HASH_MAP_ITERATOR_END) {
        int len = sprintf(buffer, "%d))))%s))))%zu)))): ", backtrace_info->live_allocs, backtrace_info->type, backtrace_info->total_allocd_size);

        write(fh, buffer, len);

        char **stringfied_backtrace;
        stringfied_backtrace = real_backtrace_symbols(backtrace_info->backtrace_raw, backtrace_info->backtrace_len);

        if (!stringfied_backtrace) {
            write(fh, "error - stringified_backtrace is null", sizeof("error - stringified_backtrace is null") - 1);
            write(fh, "\n\n", 2);
            continue;
        }

        for (int i = 0; i < backtrace_info->backtrace_len; i++) {
            write(fh, stringfied_backtrace[i], strlen(stringfied_backtrace[i]));
            write(fh, "; ", 1);
        }

        real_free(stringfied_backtrace);
        write(fh, "\n", 2);
    }

    close(fh);
}