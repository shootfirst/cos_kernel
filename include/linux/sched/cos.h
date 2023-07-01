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
// 	struct cos_dispatch_q	*dsq;
// 	struct {
// 		struct list_head	fifo;	/* dispatch order */
// 		struct rb_node		priq;	/* p->scx.dsq_vtime order */
// 	} dsq_node;
// 	struct list_head	watchdog_node;
	// u32			flags;		/* protected by rq lock */
// 	u32			weight;
// 	s32			sticky_cpu;
// 	s32			holding_cpu;
// 	u32			kf_mask;	/* see scx_kf_mask above */
// 	struct task_struct	*kf_tasks[2];	/* see SCX_CALL_OP_TASK() */
// 	atomic64_t		ops_state;
// 	unsigned long		runnable_at;
// #ifdef CONFIG_SCHED_CORE
// 	u64			core_sched_at;	/* see scx_prio_less() */
// #endif

// 	/* BPF scheduler modifiable fields */

// 	/*
// 	 * Runtime budget in nsecs. This is usually set through
// 	 * scx_bpf_dispatch() but can also be modified directly by the BPF
// 	 * scheduler. Automatically decreased by SCX as the task executes. On
// 	 * depletion, a scheduling event is triggered.
// 	 *
// 	 * This value is cleared to zero if the task is preempted by
// 	 * %SCX_KICK_PREEMPT and shouldn't be used to determine how long the
// 	 * task ran. Use p->se.sum_exec_runtime instead.
// 	 */
	u64			slice;

// 	/*
// 	 * Used to order tasks when dispatching to the vtime-ordered priority
// 	 * queue of a dsq. This is usually set through scx_bpf_dispatch_vtime()
// 	 * but can also be modified directly by the BPF scheduler. Modifying it
// 	 * while a task is queued on a dsq may mangle the ordering and is not
// 	 * recommended.
// 	 */
// 	u64			dsq_vtime;

// 	/*
// 	 * If set, reject future sched_setscheduler(2) calls updating the policy
// 	 * to %SCHED_EXT with -%EACCES.
// 	 *
// 	 * If set from ops.prep_enable() and the task's policy is already
// 	 * %SCHED_EXT, which can happen while the BPF scheduler is being loaded
// 	 * or by inhering the parent's policy during fork, the task's policy is
// 	 * rejected and forcefully reverted to %SCHED_NORMAL. The number of such
// 	 * events are reported through /sys/kernel/debug/sched_ext::nr_rejected.
// 	 */
// 	bool			disallow;	/* reject switching into SCX */

// 	/* cold fields */
// 	struct list_head	tasks_node;
// #ifdef CONFIG_EXT_GROUP_SCHED
// 	struct cgroup		*cgrp_moving_from;
// #endif
};

// #else	/* !CONFIG_SCHED_CLASS_COS */

// #endif	/* CONFIG_SCHED_CLASS_COS */
#endif	/* _LINUX_SCHED_COS_H */