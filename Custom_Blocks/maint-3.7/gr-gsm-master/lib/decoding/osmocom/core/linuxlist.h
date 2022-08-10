/*! \file linuxlist.h
 *
 * Simple doubly linked list implementation.
 *
 * Some of the internal functions ("__xxx") are useful when
 * manipulating whole llists rather than single entries, as
 * sometimes we already know the next/prev entries and we can
 * generate better code by using them directly rather than
 * using the generic single-entry routines.
 */

#pragma once

/*! \defgroup linuxlist Simple doubly linked list implementation
 *  @{
 * \file linuxlist.h */

#include <stddef.h>

#if (defined(_WIN16) || defined(_WIN32) || defined(_WIN64)) && !defined(__WINDOWS__)
#	define __WINDOWS__
#endif

#ifndef inline
#  ifndef __WINDOWS__
#    define inline __inline__
#  else
#    define inline __inline
#  endif
#endif

static inline void prefetch(const void *x) {;}

/*! cast a member of a structure out to the containing structure
 *
 * \param[in] ptr the pointer to the member.
 * \param[in] type the type of the container struct this is embedded in.
 * \param[in] member the name of the member within the struct.
 */
#define container_of(ptr, type, member) ({			\
        const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
        (type *)( (char *)__mptr - offsetof(type, member) );})


/*!
 * These are non-NULL pointers that will result in page faults
 * under normal circumstances, used to verify that nobody uses
 * non-initialized llist entries.
 */
#define LLIST_POISON1  ((void *) 0x00100100)
#define LLIST_POISON2  ((void *) 0x00200200)

/*! (double) linked list header structure */
struct llist_head {
	/*! Pointer to next and previous item */
	struct llist_head *next, *prev;
};

#define LLIST_HEAD_INIT(name) { &(name), &(name) }

/*! define a statically-initialized \ref llist_head
 *  \param[in] name Variable name
 *
 * This is a helper macro that will define a named variable of type
 * \ref llist_head and initialize it */
#define LLIST_HEAD(name) \
	struct llist_head name = LLIST_HEAD_INIT(name)

/*! initialize a \ref llist_head to point back to self */
#define INIT_LLIST_HEAD(ptr) do { \
	(ptr)->next = (ptr); (ptr)->prev = (ptr); \
} while (0)

/*! Insert a new entry between two known consecutive entries. 
 *
 * This is only for internal llist manipulation where we know
 * the prev/next entries already!
 */
static inline void __llist_add(struct llist_head *_new,
			      struct llist_head *prev,
			      struct llist_head *next)
{
	next->prev = _new;
	_new->next = next;
	_new->prev = prev;
	prev->next = _new;
}

/*! add a new entry into a linked list (at head)
 *  \param _new New entry to be added
 *  \param head \ref llist_head to add it after
 *
 * Insert a new entry after the specified head.
 * This is good for implementing stacks.
 */
static inline void llist_add(struct llist_head *_new, struct llist_head *head)
{
	__llist_add(_new, head, head->next);
}

/*! add a new entry into a linked list (at tail)
 *  \param _new  New entry to be added
 *  \param head  Head of linked list to whose tail we shall add \a _new
 *
 * Insert a new entry before the specified head.
 * This is useful for implementing queues.
 */
static inline void llist_add_tail(struct llist_head *_new, struct llist_head *head)
{
	__llist_add(_new, head->prev, head);
}

/*
 * Delete a llist entry by making the prev/next entries
 * point to each other.
 *
 * This is only for internal llist manipulation where we know
 * the prev/next entries already!
 */
static inline void __llist_del(struct llist_head * prev, struct llist_head * next)
{
	next->prev = prev;
	prev->next = next;
}

/*! Delete entry from linked list
 *  \param entry  The element to delete from the llist
 *
 * Note: llist_empty on entry does not return true after this, the entry is
 * in an undefined state.
 */
static inline void llist_del(struct llist_head *entry)
{
	__llist_del(entry->prev, entry->next);
	entry->next = (struct llist_head *)LLIST_POISON1;
	entry->prev = (struct llist_head *)LLIST_POISON2;
}

/*! Delete entry from linked list and reinitialize it
 *  \param entry  The element to delete from the list
 */
static inline void llist_del_init(struct llist_head *entry)
{
	__llist_del(entry->prev, entry->next);
	INIT_LLIST_HEAD(entry); 
}

/*! Delete from one llist and add as another's head
 *  \param llist The entry to move
 *  \param head	The head that will precede our entry
 */
static inline void llist_move(struct llist_head *llist, struct llist_head *head)
{
        __llist_del(llist->prev, llist->next);
        llist_add(llist, head);
}

/*! Delete from one llist and add as another's tail
 *  \param llist The entry to move
 *  \param head The head that will follow our entry
 */
static inline void llist_move_tail(struct llist_head *llist,
				  struct llist_head *head)
{
        __llist_del(llist->prev, llist->next);
        llist_add_tail(llist, head);
}

/*! Test whether a linked list is empty
 *  \param[in] head  The llist to test.
 *  \returns 1 if the list is empty, 0 otherwise
 */
static inline int llist_empty(const struct llist_head *head)
{
	return head->next == head;
}

static inline void __llist_splice(struct llist_head *llist,
				 struct llist_head *head)
{
	struct llist_head *first = llist->next;
	struct llist_head *last = llist->prev;
	struct llist_head *at = head->next;

	first->prev = head;
	head->next = first;

	last->next = at;
	at->prev = last;
}

/*! Join two llists
 *  \param llist The new linked list to add
 *  \param head The place to add \a llist in the other list
 */
static inline void llist_splice(struct llist_head *llist, struct llist_head *head)
{
	if (!llist_empty(llist))
		__llist_splice(llist, head);
}

/*! join two llists and reinitialise the emptied llist.
 * \param llist The new linked list to add.
 * \param head  The place to add it in the first llist.
 *
 * The llist at @llist is reinitialised
 */
static inline void llist_splice_init(struct llist_head *llist,
				    struct llist_head *head)
{
	if (!llist_empty(llist)) {
		__llist_splice(llist, head);
		INIT_LLIST_HEAD(llist);
	}
}

/*! Get the struct containing this list entry
 *  \param ptr The \ref llist_head pointer
 *  \param type The type of the struct this is embedded in
 *  \param @member The name of the \ref llist_head within the struct
 */
#define llist_entry(ptr, type, member) \
	container_of(ptr, type, member)

/*! Get the first element from a list
 *  \param ptr    the list head to take the element from.
 *  \param type   the type of the struct this is embedded in.
 *  \param member the name of the list_head within the struct.
 *
 * Note, that list is expected to be not empty.
 */
#define llist_first_entry(ptr, type, member) \
	llist_entry((ptr)->next, type, member)

/*! Get the last element from a list
 *  \param ptr    the list head to take the element from.
 *  \param type   the type of the struct this is embedded in.
 *  \param member the name of the llist_head within the struct.
 *
 * Note, that list is expected to be not empty.
 */
#define llist_last_entry(ptr, type, member) \
	llist_entry((ptr)->prev, type, member)

/*! Get the first element from a list, or NULL
 *  \param ptr    the list head to take the element from.
 *  \param type   the type of the struct this is embedded in.
 *  \param member the name of the list_head within the struct.
 *
 * Note that if the list is empty, it returns NULL.
 */
#define llist_first_entry_or_null(ptr, type, member) \
	(!llist_empty(ptr) ? llist_first_entry(ptr, type, member) : NULL)

/*! Iterate over a linked list
 *  \param pos 	The \ref llist_head to use as a loop counter
 *  \param head The head of the list over which to iterate
 */
#define llist_for_each(pos, head) \
	for (pos = (head)->next, prefetch(pos->next); pos != (head); \
        	pos = pos->next, prefetch(pos->next))

/*! Iterate over a llist (no prefetch)
 *  \param pos 	The \ref llist_head to use as a loop counter
 *  \param head The head of the list over which to iterate
 *
 * This variant differs from llist_for_each() in that it's the
 * simplest possible llist iteration code, no prefetching is done.
 * Use this for code that knows the llist to be very short (empty
 * or 1 entry) most of the time.
 */
#define __llist_for_each(pos, head) \
	for (pos = (head)->next; pos != (head); pos = pos->next)

/*! Iterate over a llist backwards
 *  \param pos 	The \ref llist_head to use as a loop counter
 *  \param head The head of the list over which to iterate
 */
#define llist_for_each_prev(pos, head) \
	for (pos = (head)->prev, prefetch(pos->prev); pos != (head); \
        	pos = pos->prev, prefetch(pos->prev))

/*! Iterate over a list; safe against removal of llist entry
 *  \param pos 	The \ref llist_head to use as a loop counter
 *  \param n Another \ref llist_head to use as temporary storage
 *  \param head The head of the list over which to iterate
 */
#define llist_for_each_safe(pos, n, head) \
	for (pos = (head)->next, n = pos->next; pos != (head); \
		pos = n, n = pos->next)

/*! Iterate over llist of given type
 *  \param pos The 'type *' to use as a loop counter
 *  \param head The head of the list over which to iterate
 *  \param member The name of the \ref llist_head within struct \a pos
 */
#define llist_for_each_entry(pos, head, member)				\
	for (pos = llist_entry((head)->next, typeof(*pos), member),	\
		     prefetch(pos->member.next);			\
	     &pos->member != (head); 					\
	     pos = llist_entry(pos->member.next, typeof(*pos), member),	\
		     prefetch(pos->member.next))

/*! Iterate backwards over llist of given type.
 *  \param pos The 'type *' to use as a loop counter
 *  \param head The head of the list over which to iterate
 *  \param member The name of the \ref llist_head within struct \a pos
 */
#define llist_for_each_entry_reverse(pos, head, member)			\
	for (pos = llist_entry((head)->prev, typeof(*pos), member),	\
		     prefetch(pos->member.prev);			\
	     &pos->member != (head); 					\
	     pos = llist_entry(pos->member.prev, typeof(*pos), member),	\
		     prefetch(pos->member.prev))

/*! iterate over llist of given type continuing after existing
 * point
 *  \param pos The 'type *' to use as a loop counter
 *  \param head The head of the list over which to iterate
 *  \param member The name of the \ref llist_head within struct \a pos
 */
#define llist_for_each_entry_continue(pos, head, member) 		\
	for (pos = llist_entry(pos->member.next, typeof(*pos), member),	\
		     prefetch(pos->member.next);			\
	     &pos->member != (head);					\
	     pos = llist_entry(pos->member.next, typeof(*pos), member),	\
		     prefetch(pos->member.next))

/*! iterate over llist of given type, safe against removal of
 * non-consecutive(!) llist entries
 *  \param pos The 'type *' to use as a loop counter
 *  \param n Another type * to use as temporary storage
 *  \param head The head of the list over which to iterate
 *  \param member The name of the \ref llist_head within struct \a pos
 */
#define llist_for_each_entry_safe(pos, n, head, member)			\
	for (pos = llist_entry((head)->next, typeof(*pos), member),	\
		n = llist_entry(pos->member.next, typeof(*pos), member);	\
	     &pos->member != (head); 					\
	     pos = n, n = llist_entry(n->member.next, typeof(*n), member))

/**
 * llist_for_each_rcu	-	iterate over an rcu-protected llist
 * @pos:	the &struct llist_head to use as a loop counter.
 * @head:	the head for your llist.
 */
#define llist_for_each_rcu(pos, head) \
	for (pos = (head)->next, prefetch(pos->next); pos != (head); \
        	pos = pos->next, ({ smp_read_barrier_depends(); 0;}), prefetch(pos->next))
        	
#define __llist_for_each_rcu(pos, head) \
	for (pos = (head)->next; pos != (head); \
        	pos = pos->next, ({ smp_read_barrier_depends(); 0;}))
        	
/**
 * llist_for_each_safe_rcu	-	iterate over an rcu-protected llist safe
 *					against removal of llist entry
 * @pos:	the &struct llist_head to use as a loop counter.
 * @n:		another &struct llist_head to use as temporary storage
 * @head:	the head for your llist.
 */
#define llist_for_each_safe_rcu(pos, n, head) \
	for (pos = (head)->next, n = pos->next; pos != (head); \
		pos = n, ({ smp_read_barrier_depends(); 0;}), n = pos->next)

/**
 * llist_for_each_entry_rcu	-	iterate over rcu llist of given type
 * @pos:	the type * to use as a loop counter.
 * @head:	the head for your llist.
 * @member:	the name of the llist_struct within the struct.
 */
#define llist_for_each_entry_rcu(pos, head, member)			\
	for (pos = llist_entry((head)->next, typeof(*pos), member),	\
		     prefetch(pos->member.next);			\
	     &pos->member != (head); 					\
	     pos = llist_entry(pos->member.next, typeof(*pos), member),	\
		     ({ smp_read_barrier_depends(); 0;}),		\
		     prefetch(pos->member.next))


/**
 * llist_for_each_continue_rcu	-	iterate over an rcu-protected llist 
 *			continuing after existing point.
 * @pos:	the &struct llist_head to use as a loop counter.
 * @head:	the head for your llist.
 */
#define llist_for_each_continue_rcu(pos, head) \
	for ((pos) = (pos)->next, prefetch((pos)->next); (pos) != (head); \
        	(pos) = (pos)->next, ({ smp_read_barrier_depends(); 0;}), prefetch((pos)->next))

/*! count nr of llist items by iterating.
 *  \param head The llist head to count items of.
 *  \returns Number of items.
 *
 * This function is not efficient, mostly useful for small lists and non time
 * critical cases like unit tests.
 */
static inline unsigned int llist_count(struct llist_head *head)
{
	struct llist_head *entry;
	unsigned int i = 0;
	llist_for_each(entry, head)
		i++;
	return i;
}

/*!
 *  @}
 */
