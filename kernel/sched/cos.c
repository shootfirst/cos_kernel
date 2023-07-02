/* SPDX-License-Identifier: GPL-2.0 */
/*
 * BPF extensible scheduler class: Documentation/scheduler/sched-ext.rst
 *
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2022 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2022 David Vernet <dvernet@meta.com>
 */

// CONFIG_SCHED_CLASS_COS

void init_cos_rq(struct cos_rq *cos_rq) 
{
	cos_rq->lord = NULL;
}
/*
 * Used by sched_fork() and __setscheduler_prio() to pick the matching
 * sched_class. dl/rt are already handled.
 */
bool task_should_cos(struct task_struct *p)
{
	return p->policy == SCHED_COS;
}

void enqueue_task_cos(struct rq *rq, struct task_struct *p, int flags) {
	// rq->cos.lord = p;
	printk("enqueue_task_cos  %d\n", p->pid);
}

void dequeue_task_cos(struct rq *rq, struct task_struct *p, int flags) {
	// rq->cos.lord = NULL;
	printk("dequeue_task_cos  %d\n", p->pid);
}

void yield_task_cos(struct rq *rq) {
	printk("yield_task_cos\n");
}

bool yield_to_task_cos(struct rq *rq, struct task_struct *p) {
	printk("yield_to_task_cos\n");
	return false;
}

void check_preempt_curr_cos(struct rq *rq, struct task_struct *p, int flags) {
	printk("check_preempt_curr_cos\n");
}

struct task_struct *pick_next_task_cos(struct rq *rq) {
	// printk("hello\n");
	if (rq->cos.lord == NULL) {
		return NULL;
	}
	if (task_is_running(rq->cos.lord)) {
		return rq->cos.lord;
	}
	return NULL;
	
}

void put_prev_task_cos(struct rq *rq, struct task_struct *p) {
	printk("put_prev_task_cos\n");
}

void set_next_task_cos(struct rq *rq, struct task_struct *p, bool first) {
	printk("set_next_task_cos\n");
}

void task_dead_cos(struct task_struct *p) {
	preempt_disable();
	struct rq *rq;
	int cpu;
	
	cpu = smp_processor_id();
	rq = cpu_rq(cpu);
	if (rq->cos.lord == p) {
		rq->cos.lord = NULL;
	}

	sched_preempt_enable_no_resched();
}

int balance_cos(struct rq *rq, struct task_struct *prev, struct rq_flags *rf) {
	// printk("balance_cos\n");
	return 1;
}

int select_task_rq_cos(struct task_struct *p, int task_cpu, int flags) {
	printk("select_task_rq_cos\n");
	return p->cos.cpu_id;
}

void set_cpus_allowed_cos(struct task_struct *p, struct affinity_context *ctx) {
	printk("set_cpus_allowed_cos\n");
}

void rq_online_cos(struct rq *rq) {
	printk("rq_online_cos\n");
}
	
void rq_offline_cos(struct rq *rq) {
	printk("rq_offline_cos\n");
}

struct task_struct * pick_task_cos(struct rq *rq) {
	printk("pick_task_cos\n");
	return NULL;
}

void task_tick_cos(struct rq *rq, struct task_struct *p, int queued) {
	printk("task_tick_cos\n");
}

void switched_to_cos(struct rq *this_rq, struct task_struct *task) {
	printk("switched_to_cos\n");
}

void prio_changed_cos(struct rq *this_rq, struct task_struct *task, int oldprio) {
	printk("prio_changed_cos\n");
}

void update_curr_cos(struct rq *rq) {
	printk("update_curr_cos\n");
}


/*
 * Omitted operations:
 *
 * - check_preempt_curr: NOOP as it isn't useful in the wakeup path because the
 *   task isn't tied to the CPU at that point. Preemption is implemented by
 *   resetting the victim task's slice to 0 and triggering reschedule on the
 *   target CPU.
 *
 * - migrate_task_rq: Unncessary as task to cpu mapping is transient.
 *
 * - task_fork/dead: We need fork/dead notifications for all tasks regardless of
 *   their current sched_class. Call them directly from sched core instead.
 *
 * - task_woken, switched_from: Unnecessary.
 */
DEFINE_SCHED_CLASS(cos) = {
	.enqueue_task		= enqueue_task_cos,
	.dequeue_task		= dequeue_task_cos,
	.yield_task		= yield_task_cos,
	.yield_to_task		= yield_to_task_cos,

	.check_preempt_curr	= check_preempt_curr_cos,

	.pick_next_task		= pick_next_task_cos,

	.put_prev_task		= put_prev_task_cos,
	.set_next_task          = set_next_task_cos,
	.task_dead = task_dead_cos,

#ifdef CONFIG_SMP
	.balance		= balance_cos,
	.select_task_rq		= select_task_rq_cos,
	.set_cpus_allowed	= set_cpus_allowed_cos,

	.rq_online		= rq_online_cos,
	.rq_offline		= rq_offline_cos,
#endif

#ifdef CONFIG_SCHED_CORE
	.pick_task		= pick_task_cos,
#endif

	.task_tick		= task_tick_cos,

	.switched_to		= switched_to_cos,
	.prio_changed		= prio_changed_cos,

	.update_curr		= update_curr_cos,

#ifdef CONFIG_UCLAMP_TASK
	.uclamp_enabled		= 0,
#endif
};



