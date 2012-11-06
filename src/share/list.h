#ifndef LIST_H
#define LIST_H

#include "types.h"

struct list;

struct list * list_new();

bool list_end(const struct list * node);

void * list_data(const struct list * node);

struct list * list_next(const struct list * node);

struct list * list_push_front(const struct list * head, const void * data);

struct list * list_pop_front(const struct list * head);

void list_remove(struct list * node);

#endif
