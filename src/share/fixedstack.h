/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#ifndef FIXEDSTACK_H_
#define FIXEDSTACK_H_

#include <assert.h>

#define FIXEDSTACK_ALEN(_arr) (sizeof(_arr) / sizeof(_arr[0]))

/**
 *  FIXEDSTACK_DECL(foostack, void*, 5) mystack;
 */
#define FIXEDSTACK_DECL(_name, _type, _nelts)	\
	struct _name {				\
		_type elts[_nelts];		\
		int len;			\
	}

#define FIXEDSTACK_INITIALIZER { .elts = { 0 }, .len = 0 }

/**
 *  FIXEDSTACK_CLEAR(&mstack);
 */
#define FIXEDSTACK_CLEAR(_var)			\
	memset((_var), 0, sizeof(*(_var)))

/**
 *
 */
#define FIXEDSTACK_EMPTY(_var)			\
	(0 == (_var)->len)

/**
 *  void* last_top = FIXEDSTACK_POP(&mystack);
 */
#define FIXEDSTACK_POP(_var)					\
	(assert((_var)->len > 0), (_var)->elts[--(_var)->len])

/**
 *  FIXEDSTACK_PUSH(&mystack, NULL);
 */
#define FIXEDSTACK_PUSH(_var, _elt)				\
	(assert((_var)->len < FIXEDSTACK_ALEN((_var)->elts)),	\
	 (_var)->elts[(_var)->len++] = (_elt))

/**
 *  void** peek = FIXEDSTACK_TOP(&mystack);
 */
#define FIXEDSTACK_TOP(_var)					\
	(assert((_var)->len > 0), &(_var)->elts[(_var)->len])

#endif /* FIXED_STACK_H_ */
