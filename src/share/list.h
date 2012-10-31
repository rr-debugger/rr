#ifndef LIST_H
#define LIST_H

#include "types.h"

struct list;

struct list * list_new();

bool list_end(struct list * node);

void * list_data(struct list * node);

struct list * list_next(struct list * node);

struct list * list_push_front(struct list * head, void * data);

struct list * list_pop_front(struct list * head);

void list_remove(struct list * node);

#endif
