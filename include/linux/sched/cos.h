/* SPDX-License-Identifier: GPL-2.0 */
/*
 * BPF extensible scheduler class: Documentation/scheduler/sched-ext.rst
 *
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2022 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2022 David Vernet <dvernet@meta.com>
 */
#ifndef _LINUX_SCHED_COS_H
#define _LINUX_SCHED_COS_H

// #ifdef CONFIG_SCHED_CLASS_COS

#include <linux/llist.h>

/*
 * Dispatch queue (dsq) is a simple FIFO which is used to buffer between the
 * scheduler core and the COS scheduler. See the documentation for more details.
 */
struct cos_dispatch_q {
	// raw_spinlock_t		lock;
	// struct list_head	fifo;	/* processed in dispatching order */
	// struct rb_root_cached	priq;	/* processed in p->scx.dsq_vtime order */
	// u32			nr;
	// u64			id;
	// struct rhash_head	hash_node;
	// struct llist_node	free_node;
	// struct rcu_head		rcu;
};

/*
 * The following is embedded in task_struct and contains all fields necessary
 * for a task to be scheduled by COS.
 */
struct sched_cos_entity {
	u64			slice;
	u64         cpu_id;  // 做好初始化
};

// #else	/* !CONFIG_SCHED_CLASS_COS */

// #endif	/* CONFIG_SCHED_CLASS_COS */
#endif	/* _LINUX_SCHED_COS_H */