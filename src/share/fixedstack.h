/* -*- Mode: C++; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#ifndef FIXEDSTACK_H_
#define FIXEDSTACK_H_

#include <assert.h>

#define FIXEDSTACK_ALEN(_arr) ssize_t(sizeof(_arr) / sizeof(_arr[0]))

/**
 * Declare a stack named |_name| of fixed size |_nelts|, with elements
 * of type |_type|, in the current scope.  Use as follows
 *
 *  FIXEDSTACK_DECL(foostack, void*, 5) mystack;
 */
#define FIXEDSTACK_DECL(_name, _type, _nelts)	\
	struct _name {				\
		_type elts[_nelts];		\
		ssize_t len;			\
	}

/**
 * Initialize a fixedstack declared by FIXEDSTACK_DECL().  For example
 *
 *  FIXEDSTACK_DECL(foostack, void*, 5) mystack = FIXEDSTACK_INITIALIZER;
 */
#define FIXEDSTACK_INITIALIZER { .elts = { 0 }, .len = 0 }

/**
 * "Remove" all the elements from the stack.  The caller is
 * responsible for freeing any dynamic memory associated with the
 * elements, so be careful when using this.  After this "call",
 * FIXEDSTACK_EMPTY() will be true.  Use as follows
 *
 *  FIXEDSTACK_CLEAR(&mstack);
 */
#define FIXEDSTACK_CLEAR(_var)			\
	memset((_var), 0, sizeof(*(_var)))

/**
 * Number of calls to PUSH() without a corresponding POP().
 */
#define FIXEDSTACK_DEPTH(_var)			\
	((_var)->len)

/**
 * True when there are no elements pushed onto |_var|.  For example
 *
 *  if (!FIXEDSTACK_EMPTY(&mystack)) { ...
 */
#define FIXEDSTACK_EMPTY(_var)			\
	(0 == (_var)->len)

/**
 * Remove FIXEDSTACK_TOP() from |_var| and "return" it by value.  For
 * example
 *
 *  void* last_top = FIXEDSTACK_POP(&mystack);
 */
#define FIXEDSTACK_POP(_var)					\
	(assert((_var)->len > 0), (_var)->elts[--(_var)->len])

/**
 * Make |_elt| the new FIXEDSTACK_TOP() of |_var|.
 *
 *  FIXEDSTACK_PUSH(&mystack, NULL);
 */
#define FIXEDSTACK_PUSH(_var, _elt)				\
	(assert((_var)->len < FIXEDSTACK_ALEN((_var)->elts)),	\
	 (_var)->elts[(_var)->len++] = (_elt))

/**
 * Return a pointer to the most-recently-pushed element.  Mutations to
 * the pointed-at memory are visible to the next "caller" of
 * FIXEDSTACK_TOP().
 * 
 *  void** peek = FIXEDSTACK_TOP(&mystack);
 *  *peek = (void*)-1;
 *  assert(*FIXEDSTACK_TOP(&mystack) == (void*)-1);
 */
#define FIXEDSTACK_TOP(_var)					\
	(assert((_var)->len > 0), &(_var)->elts[(_var)->len - 1])

#endif /* FIXED_STACK_H_ */
