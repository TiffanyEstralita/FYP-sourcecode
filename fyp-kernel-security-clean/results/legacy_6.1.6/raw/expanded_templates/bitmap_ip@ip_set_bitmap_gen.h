/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2013 Jozsef Kadlecsik <kadlec@netfilter.org> */

#ifndef __IP_SET_BITMAP_IP_GEN_H
#define __IP_SET_BITMAP_IP_GEN_H

#define bitmap_ip_do_test		IPSET_TOKEN(MTYPE, _do_test)
#define bitmap_ip_gc_test		IPSET_TOKEN(MTYPE, _gc_test)
#define bitmap_ip_is_filled		IPSET_TOKEN(MTYPE, _is_filled)
#define bitmap_ip_do_add		IPSET_TOKEN(MTYPE, _do_add)
#define bitmap_ip_ext_cleanup	IPSET_TOKEN(MTYPE, _ext_cleanup)
#define bitmap_ip_do_del		IPSET_TOKEN(MTYPE, _do_del)
#define bitmap_ip_do_list		IPSET_TOKEN(MTYPE, _do_list)
#define bitmap_ip_do_head		IPSET_TOKEN(MTYPE, _do_head)
#define bitmap_ip_adt_elem		IPSET_TOKEN(MTYPE, _adt_elem)
#define bitmap_ip_add_timeout	IPSET_TOKEN(MTYPE, _add_timeout)
#define bitmap_ip_gc_init		IPSET_TOKEN(MTYPE, _gc_init)
#define bitmap_ip_kadt		IPSET_TOKEN(MTYPE, _kadt)
#define bitmap_ip_uadt		IPSET_TOKEN(MTYPE, _uadt)
#define bitmap_ip_destroy		IPSET_TOKEN(MTYPE, _destroy)
#define bitmap_ip_memsize		IPSET_TOKEN(MTYPE, _memsize)
#define bitmap_ip_flush		IPSET_TOKEN(MTYPE, _flush)
#define bitmap_ip_head		IPSET_TOKEN(MTYPE, _head)
#define bitmap_ip_same_set		IPSET_TOKEN(MTYPE, _same_set)
#define bitmap_ip_elem		IPSET_TOKEN(MTYPE, _elem)
#define bitmap_ip_test		IPSET_TOKEN(MTYPE, _test)
#define bitmap_ip_add		IPSET_TOKEN(MTYPE, _add)
#define bitmap_ip_del		IPSET_TOKEN(MTYPE, _del)
#define bitmap_ip_list		IPSET_TOKEN(MTYPE, _list)
#define bitmap_ip_gc		IPSET_TOKEN(MTYPE, _gc)
#define bitmap_ip			MTYPE

#define get_ext(set, map, id)	((map)->extensions + ((set)->dsize * (id)))

static void
bitmap_ip_gc_init(struct ip_set *set, void (*gc)(struct timer_list *t))
{
	struct bitmap_ip *map = set->data;

	timer_setup(&map->gc, gc, 0);
	mod_timer(&map->gc, jiffies + IPSET_GC_PERIOD(set->timeout) * HZ);
}

static void
bitmap_ip_ext_cleanup(struct ip_set *set)
{
	struct bitmap_ip *map = set->data;
	u32 id;

	for (id = 0; id < map->elements; id++)
		if (test_bit(id, map->members))
			ip_set_ext_destroy(set, get_ext(set, map, id));
}

static void
bitmap_ip_destroy(struct ip_set *set)
{
	struct bitmap_ip *map = set->data;

	if (SET_WITH_TIMEOUT(set))
		del_timer_sync(&map->gc);

	if (set->dsize && set->extensions & IPSET_EXT_DESTROY)
		bitmap_ip_ext_cleanup(set);
	ip_set_free(map->members);
	ip_set_free(map);

	set->data = NULL;
}

static void
bitmap_ip_flush(struct ip_set *set)
{
	struct bitmap_ip *map = set->data;

	if (set->extensions & IPSET_EXT_DESTROY)
		bitmap_ip_ext_cleanup(set);
	bitmap_zero(map->members, map->elements);
	set->elements = 0;
	set->ext_size = 0;
}

/* Calculate the actual memory size of the set data */
static size_t
bitmap_ip_memsize(const struct bitmap_ip *map, size_t dsize)
{
	return sizeof(*map) + map->memsize +
	       map->elements * dsize;
}

static int
bitmap_ip_head(struct ip_set *set, struct sk_buff *skb)
{
	const struct bitmap_ip *map = set->data;
	struct nlattr *nested;
	size_t memsize = bitmap_ip_memsize(map, set->dsize) + set->ext_size;

	nested = nla_nest_start(skb, IPSET_ATTR_DATA);
	if (!nested)
		goto nla_put_failure;
	if (bitmap_ip_do_head(skb, map) ||
	    nla_put_net32(skb, IPSET_ATTR_REFERENCES, htonl(set->ref)) ||
	    nla_put_net32(skb, IPSET_ATTR_MEMSIZE, htonl(memsize)) ||
	    nla_put_net32(skb, IPSET_ATTR_ELEMENTS, htonl(set->elements)))
		goto nla_put_failure;
	if (unlikely(ip_set_put_flags(skb, set)))
		goto nla_put_failure;
	nla_nest_end(skb, nested);

	return 0;
nla_put_failure:
	return -EMSGSIZE;
}

static int
bitmap_ip_test(struct ip_set *set, void *value, const struct ip_set_ext *ext,
	   struct ip_set_ext *mext, u32 flags)
{
	struct bitmap_ip *map = set->data;
	const struct bitmap_ip_adt_elem *e = value;
	void *x = get_ext(set, map, e->id);
	int ret = bitmap_ip_do_test(e, map, set->dsize);

	if (ret <= 0)
		return ret;
	return ip_set_match_extensions(set, ext, mext, flags, x);
}

static int
bitmap_ip_add(struct ip_set *set, void *value, const struct ip_set_ext *ext,
	  struct ip_set_ext *mext, u32 flags)
{
	struct bitmap_ip *map = set->data;
	const struct bitmap_ip_adt_elem *e = value;
	void *x = get_ext(set, map, e->id);
	int ret = bitmap_ip_do_add(e, map, flags, set->dsize);

	if (ret == IPSET_ADD_FAILED) {
		if (SET_WITH_TIMEOUT(set) &&
		    ip_set_timeout_expired(ext_timeout(x, set))) {
			set->elements--;
			ret = 0;
		} else if (!(flags & IPSET_FLAG_EXIST)) {
			set_bit(e->id, map->members);
			return -IPSET_ERR_EXIST;
		}
		/* Element is re-added, cleanup extensions */
		ip_set_ext_destroy(set, x);
	}
	if (ret > 0)
		set->elements--;

	if (SET_WITH_TIMEOUT(set))
#ifdef IP_SET_BITMAP_STORED_TIMEOUT
		bitmap_ip_add_timeout(ext_timeout(x, set), e, ext, set, map, ret);
#else
		ip_set_timeout_set(ext_timeout(x, set), ext->timeout);
#endif

	if (SET_WITH_COUNTER(set))
		ip_set_init_counter(ext_counter(x, set), ext);
	if (SET_WITH_COMMENT(set))
		ip_set_init_comment(set, ext_comment(x, set), ext);
	if (SET_WITH_SKBINFO(set))
		ip_set_init_skbinfo(ext_skbinfo(x, set), ext);

	/* Activate element */
	set_bit(e->id, map->members);
	set->elements++;

	return 0;
}

static int
bitmap_ip_del(struct ip_set *set, void *value, const struct ip_set_ext *ext,
	  struct ip_set_ext *mext, u32 flags)
{
	struct bitmap_ip *map = set->data;
	const struct bitmap_ip_adt_elem *e = value;
	void *x = get_ext(set, map, e->id);

	if (bitmap_ip_do_del(e, map))
		return -IPSET_ERR_EXIST;

	ip_set_ext_destroy(set, x);
	set->elements--;
	if (SET_WITH_TIMEOUT(set) &&
	    ip_set_timeout_expired(ext_timeout(x, set)))
		return -IPSET_ERR_EXIST;

	return 0;
}

#ifndef IP_SET_BITMAP_STORED_TIMEOUT
static bool
bitmap_ip_is_filled(const struct bitmap_ip_elem *x)
{
	return true;
}
#endif

static int
bitmap_ip_list(const struct ip_set *set,
	   struct sk_buff *skb, struct netlink_callback *cb)
{
	struct bitmap_ip *map = set->data;
	struct nlattr *adt, *nested;
	void *x;
	u32 id, first = cb->args[IPSET_CB_ARG0];
	int ret = 0;

	adt = nla_nest_start(skb, IPSET_ATTR_ADT);
	if (!adt)
		return -EMSGSIZE;
	/* Extensions may be replaced */
	rcu_read_lock();
	for (; cb->args[IPSET_CB_ARG0] < map->elements;
	     cb->args[IPSET_CB_ARG0]++) {
		cond_resched_rcu();
		id = cb->args[IPSET_CB_ARG0];
		x = get_ext(set, map, id);
		if (!test_bit(id, map->members) ||
		    (SET_WITH_TIMEOUT(set) &&
#ifdef IP_SET_BITMAP_STORED_TIMEOUT
		     bitmap_ip_is_filled(x) &&
#endif
		     ip_set_timeout_expired(ext_timeout(x, set))))
			continue;
		nested = nla_nest_start(skb, IPSET_ATTR_DATA);
		if (!nested) {
			if (id == first) {
				nla_nest_cancel(skb, adt);
				ret = -EMSGSIZE;
				goto out;
			}

			goto nla_put_failure;
		}
		if (bitmap_ip_do_list(skb, map, id, set->dsize))
			goto nla_put_failure;
		if (ip_set_put_extensions(skb, set, x, bitmap_ip_is_filled(x)))
			goto nla_put_failure;
		nla_nest_end(skb, nested);
	}
	nla_nest_end(skb, adt);

	/* Set listing finished */
	cb->args[IPSET_CB_ARG0] = 0;

	goto out;

nla_put_failure:
	nla_nest_cancel(skb, nested);
	if (unlikely(id == first)) {
		cb->args[IPSET_CB_ARG0] = 0;
		ret = -EMSGSIZE;
	}
	nla_nest_end(skb, adt);
out:
	rcu_read_unlock();
	return ret;
}

static void
bitmap_ip_gc(struct timer_list *t)
{
	struct bitmap_ip *map = from_timer(map, t, gc);
	struct ip_set *set = map->set;
	void *x;
	u32 id;

	/* We run parallel with other readers (test element)
	 * but adding/deleting new entries is locked out
	 */
	spin_lock_bh(&set->lock);
	for (id = 0; id < map->elements; id++)
		if (bitmap_ip_gc_test(id, map, set->dsize)) {
			x = get_ext(set, map, id);
			if (ip_set_timeout_expired(ext_timeout(x, set))) {
				clear_bit(id, map->members);
				ip_set_ext_destroy(set, x);
				set->elements--;
			}
		}
	spin_unlock_bh(&set->lock);

	map->gc.expires = jiffies + IPSET_GC_PERIOD(set->timeout) * HZ;
	add_timer(&map->gc);
}

static const struct ip_set_type_variant bitmap_ip = {
	.kadt	= bitmap_ip_kadt,
	.uadt	= bitmap_ip_uadt,
	.adt	= {
		[IPSET_ADD] = bitmap_ip_add,
		[IPSET_DEL] = bitmap_ip_del,
		[IPSET_TEST] = bitmap_ip_test,
	},
	.destroy = bitmap_ip_destroy,
	.flush	= bitmap_ip_flush,
	.head	= bitmap_ip_head,
	.list	= bitmap_ip_list,
	.same_set = bitmap_ip_same_set,
};

#endif /* __IP_SET_BITMAP_IP_GEN_H */
