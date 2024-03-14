#ifndef ALLOC_TRACKER_BT_H
#define ALLOC_TRACKER_BT_H

#include <stdio.h>

void bt_init();
void bt_pointer_allocd_event(const void* ptr, const char* type, size_t allocd_size);
void bt_pointer_freed_event(const void* ptr);
void bt_dump();

#endif