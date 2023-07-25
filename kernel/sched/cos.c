/* SPDX-License-Identifier: GPL-2.0 */
/*
 * BPF extensible scheduler class: Documentation/scheduler/sched-ext.rst
 *
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2022 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2022 David Vernet <dvernet@meta.com>
 */

// CONFIG_SCHED_CLASS_COS

#include <linux/mm.h>
#include <linux/file.h>
#include <linux/anon_inodes.h>

// #include <asm/ptrace.h>
#include "sched.h"

// =======================================全局变量===========================================
int cos_on = 0;
int lord_cpu = 1;
struct task_struct *lord = NULL;
DEFINE_SPINLOCK(cos_global_lock);

struct cos_message_queue *global_mq;
DEFINE_SPINLOCK(cos_mq_lock);

struct cos_shoot_area *task_shoot_area; /* Only lord cpu will access it */
int lord_on_rq = 0;

// =====================================全局变量结束=========================================

// =====================================core.c=============================================
/**
 * find_process_by_pid - find a process with a matching PID value.
 * used in sys_sched_set/getaffinity() in kernel/sched/core.c, so
 * cloned here.
 */
static struct task_struct *find_process_by_pid(pid_t pid)
{
	return pid ? find_task_by_vpid(pid) : current;
}
// =====================================core.c=============================================


// =====================================系统调用函数=========================================
//=====================================lord=======================================
int cos_move2target_rq(int cpu_id) 
{
	cpumask_var_t new_mask;
	int ret;
	
	if (cpu_id < 0 || cpu_id >= nr_cpu_ids)
		return -EINVAL;

	if (!zalloc_cpumask_var(&new_mask, GFP_KERNEL)) {
		return -ENOMEM;
	}

	cpumask_set_cpu(cpu_id, new_mask);
	ret = cos_set_cpus_allowed(current, new_mask);
	free_cpumask_var(new_mask);

	return ret;
}

/* must under cos_global_lock locked */
void open_cos(struct rq *rq, struct task_struct *p, int cpu_id) 
{
	rq->cos.lord = p; 
	// rq->cos.lord_on_rq = 1;
	lord_on_rq = 1;
	lord_cpu = cpu_id;
	BUG_ON(lord);
	lord = p;
	BUG_ON(cos_on == 1);
	cos_on = 1;
}

int cos_do_set_lord(int cpu_id) 
{
	int retval = 0;
	struct task_struct *p = current;
	struct rq *rq;
	ulong flags;
	
	/*
	 * First move current task struct to target cpu rq.
	 *
	 * We do this in the kernel (compared to calling sched_setaffinity
	 * from the agent) to step around any cpuset cgroup constraints. 
	 * Because cos is not under the management of cgroup, we have the 
	 * exclusive cgroup.
	 * 
	 * Warning! If the kernel already open the cos, and the lord cpu id 
	 * is same as cpu_id, it will block here, because the lord is always
	 * on the cpu.
	 */
	retval = cos_move2target_rq(cpu_id);
	if (retval != 0) 
		goto move_fail;
	

	/*
	 * Next we check if cos is on, if so we get to move_fail.
	 * Why do not we lock before above move ？That is a good question.
	 * Because we can not hold lock in move.
	 */
	if (cos_on) 
		return -EINVAL;

	spin_lock_irqsave(&cos_global_lock, flags);

	/*
	 * Then we set the sched class to cos using sched_setscheduler(same as 
	 * sys_sched_setscheduler).
	 */
	struct sched_param param = {
		.sched_priority = 0,
	};
	retval = sched_setscheduler(p, SCHED_COS, &param);
	if (retval != 0) 
		goto out;


	/*
	 * Now we open the cos scheduler, change cos_on to 1
	 * to show that cos scheduler is under the control of lord.
	 */
	// 设置lord为当前线程
	rq = cpu_rq(cpu_id);
	open_cos(rq, p, cpu_id);

out:
	spin_unlock_irqrestore(&cos_global_lock, flags);

move_fail:
	return retval;
}

//=====================================lord=======================================

//===================================共享内存相关=====================================
static int _cos_mmap_common(struct vm_area_struct *vma, ulong mapsize)
{
	static const struct vm_operations_struct cos_vm_ops = {};

	/*
	 * VM_MAYSHARE indicates that MAP_SHARED was set in 'mmap' flags.
	 *
	 * Checking VM_SHARED seems intuitive here but this bit is cleared
	 * by do_mmap() if the underlying file is readonly (as is the case
	 * for a sw_region file).
	 */
	if (!(vma->vm_flags & VM_MAYSHARE))
		return -EINVAL;

	/*
	 * Mappings are always readable and 'do_mmap()' ensures that
	 * FMODE_WRITE and VM_WRITE are coherent so the only remaining
	 * check is against VM_EXEC.
	 */
	if (vma->vm_flags & VM_EXEC)
		return -EACCES;

	/* The entire region must be mapped */
	if (vma->vm_pgoff)
		return -EINVAL;

	// if (vma->vm_end - vma->vm_start != mapsize) {
	// 	printk("vma->vm_end %llu - vma->vm_start%llu = %llu != size %d\n", vma->vm_end, vma->vm_start, vma->vm_end- vma->vm_start, mapsize);
	// 	return -EINVAL;
	// }
		

	/*
	 * Don't allow mprotect(2) to relax permissions beyond what
	 * would have been allowed by this function.
	 *
	 * Mappings always readable and 'do_mmap()' ensures that
	 * FMODE_WRITE and VM_MAYWRITE are coherent so just clear
	 * VM_MAYEXEC here.
	 */
	// vma->vm_flags &= ~VM_MAYEXEC;
	// vma->vm_flags |= VM_DONTCOPY;

	/*
	 * Initialize 'vma->vm_ops' to avoid vma_is_anonymous() false-positive.
	 */
	vma->vm_ops = &cos_vm_ops;
	return 0;
}


static int cos_region_mmap(struct file *file, struct vm_area_struct *vma,
			     void *addr, ulong mapsize)
{
	int error = 0;
	error = _cos_mmap_common(vma, mapsize);
	
	if (!error)
		error = remap_vmalloc_range(vma, addr, 0);
	return error;
}

static int queue_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct cos_message_queue *mq = file->private_data;

	return cos_region_mmap(file, vma, mq, sizeof(struct cos_message_queue));
}

static int queue_release(struct inode *inode, struct file *file)
{
	return 0;
}

static const struct file_operations queue_fops = {
	.release		= queue_release,
	.mmap			= queue_mmap,
};

//===================================共享内存相关=====================================

//=====================================mq=========================================
int cos_create_queue(void) 
{
	global_mq = vmalloc_user(sizeof(struct cos_message_queue));

	if (!global_mq) {
		return -ESRCH;
	}

	int fd = anon_inode_getfd("[cos_queue]", &queue_fops, global_mq,
			      O_RDWR | O_CLOEXEC);

	if (fd < 0) {
		vfree(global_mq);
		global_mq = NULL; //TODO
	}

	return fd;
}

int cos_do_create_mq(void) 
{
	if (!is_lord(current)) {
		return -EINVAL;
	}

	int fd = cos_create_queue();

	return fd;
}

//=====================================mq=========================================

//============================================init_shoot===================================================

int cos_create_shoot_area(void) 
{
	task_shoot_area = vmalloc_user(sizeof(struct cos_shoot_area));

	if (!task_shoot_area) {
		return -ESRCH;
	}

	int fd = anon_inode_getfd("[shoot_area]", &queue_fops, task_shoot_area,
			      O_RDWR | O_CLOEXEC);

	if (fd < 0) {
		vfree(task_shoot_area);
		task_shoot_area = NULL; 
	}
	// task_shoot_area->area[lord_cpu].pid = lord->pid; // for test TODO

	return fd;
}

int cos_do_init_shoot(void) 
{
	/* Only lord can init shoot */
	if (!is_lord(current)) {
		return -EINVAL;
	}
	
	int fd = cos_create_shoot_area();

	return fd;
}

//============================================init_shoot===================================================

//============================================shoot=======================================================
int cos_do_shoot_task(cpumask_var_t shoot_mask) 
{
	int need_local_shoot;
	struct task_struct *p;
	pid_t pid;
	struct rq *rq;

	cpumask_var_t ipimask; /* for sent ipi */
	if (!alloc_cpumask_var(&ipimask, GFP_KERNEL))
		return -ENOMEM;

	int cpu_id;

	/*
	 * Here we set each cpu id setting by userspace
	 * , check and set the ipimask and next_to_sched.
	 */
	preempt_disable();
	for_each_cpu(cpu_id, shoot_mask) {

		/* 
		 * First we use shared memory shoot_area to get 
		 * the pid and task struct.
		 */
		pid = task_shoot_area->area[cpu_id].pid;

		rcu_read_lock();
		p = find_process_by_pid(pid);

		if (unlikely(!p)) {
			/* 
			 * We continue when the pid getting from user
			 * is not valid. TODO：是否需要通知用户态
		 	 */
			rcu_read_unlock();
			printk("shoot pid %d is not exist\n", pid);
			continue;
		}
		
		get_task_struct(p);
		rcu_read_unlock();
		

		/* Then we get the target cpu rq and set next_to_sched*/
		rq = cpu_rq(cpu_id);
		if (unlikely(!rq)) {
			/* 
			 * We continue when the cpu id setting from user
			 * is not valid.TODO：是否需要通知用户态
		 	 */
			printk("shoot cpu %d is not exist\n", cpu_id);
			continue;
		}

 		rq->cos.next_to_sched = p; // TODO 线程安全  抢占逻辑


		/* Finally we set the ipimask or local shoot is needed */
		if (cpu_id == lord_cpu) {
			need_local_shoot = true;
		} else {
			__cpumask_set_cpu(cpu_id, ipimask);

			// TODO：can we move it to ipi handler ？
			struct rq_flags rf;
			rq_lock_irqsave(rq, &rf);
			!test_tsk_need_resched(rq->curr) &&
					 set_nr_and_not_polling(rq->curr);
			rq_unlock_irqrestore(rq, &rf);
		}
	}

	/* do shoot work */
	cos_remote_shoot(ipimask);

	if (need_local_shoot) {
		lord_on_rq = 0;
		cos_local_shoot();
		lord_on_rq = 1;
	}

	preempt_enable_no_resched();

	free_cpumask_var(ipimask);

	return 0;
}
//============================================shoot=======================================================

//====================================系统调用函数结束=======================================

//==========================================cos辅助函数=========================================
/* must under cos_global_lock locked */
void close_cos(struct rq *rq) 
{
	rq->cos.lord = NULL; 
	// rq->cos.lord_on_rq = 0;
	lord_on_rq = 0;
	lord_cpu = 1;
	lord = NULL;
	BUG_ON(cos_on == 0);
	cos_on = 0;

	if (task_shoot_area) {
		vfree(task_shoot_area);
		task_shoot_area = NULL; 
	}
	
	if (global_mq) {
		vfree(global_mq);
		global_mq = NULL;
	}
}
//==========================================cos辅助函数结束=========================================

//==================================供core.c使用的函数=====================================

void init_cos_rq(struct cos_rq *cos_rq) 
{
	cos_rq->lord = NULL;
	cos_rq->next_to_sched = NULL;
}

bool is_lord(struct task_struct *p)
{
	return p != NULL && lord != NULL && p == lord;
}

//==================================供core.c使用的函数=====================================

//==================================消息队列函数=====================================
int _produce(struct cos_msg *msg) 
{
	ulong flags;
	spin_lock_irqsave(&cos_mq_lock, flags);

	if (global_mq->head - global_mq->tail >= _MQ_SIZE) { /* The queue is full */
		WARN(1, "cos mq is full!\n");
		spin_unlock_irqrestore(&cos_mq_lock, flags);
		return -EINVAL;
	}

	global_mq->data[global_mq->head % _MQ_SIZE] = *msg;
	smp_wmb(); /* msg update must before head update */

	global_mq->head++;
	smp_wmb(); /* publish head update */

	spin_unlock_irqrestore(&cos_mq_lock, flags);

	return 0;
}

int produce_task_message(u_int32_t msg_type, struct task_struct *p) 
{
	if (is_lord(p) || !global_mq) 
		return 0;
	
	struct cos_msg msg;

	switch (msg_type) {
	case MSG_TASK_RUNNABLE: 
		msg.type = MSG_TASK_RUNNABLE;
		break;
	case MSG_TASK_BLOCKED:
		msg.type = MSG_TASK_BLOCKED;
		break;
	case MSG_TASK_NEW:
		msg.type = MSG_TASK_NEW;
		printk("do not support cos msg %d\n", MSG_TASK_NEW);
		break;
	case MSG_TASK_DEAD:
		msg.type = MSG_TASK_DEAD;
		printk("do not support cos msg %d\n", MSG_TASK_DEAD);
		break;
	case MSG_TASK_PREEMPT:
		msg.type = MSG_TASK_PREEMPT;
		printk("do not support cos msg %d\n", MSG_TASK_PREEMPT);
		break;
	case MSG_TASK_NEW_BLOCKED:
		msg.type = MSG_TASK_NEW_BLOCKED;
		printk("do not support cos msg %d\n", MSG_TASK_NEW_BLOCKED);
		break;
	default:
		WARN(1, "unknown cos_msg type %d!\n", msg_type);
		return -EINVAL;
	}

	msg.pid = p->pid;

	return _produce(&msg);

}

int produce_task_runnable_msg(struct task_struct *p) 
{
	return produce_task_message(MSG_TASK_RUNNABLE, p);
}

int produce_task_blocked_msg(struct task_struct *p) 
{
	return produce_task_message(MSG_TASK_BLOCKED, p);
}

int produce_task_new_msg(struct task_struct *p) 
{
	return produce_task_message(MSG_TASK_NEW, p);
}

int produce_task_dead_msg(struct task_struct *p) 
{
	return produce_task_message(MSG_TASK_DEAD, p);
}

int produce_task_peempt_msg(struct task_struct *p) 
{
	return produce_task_message(MSG_TASK_PREEMPT, p);
}

int produce_task_new_blocked_msg(struct task_struct *p) 
{
	return produce_task_message(MSG_TASK_NEW_BLOCKED, p);
}

//==================================消息队列函数结束=====================================

//==================================cos调度类钩子函数=====================================

void enqueue_task_cos(struct rq *rq, struct task_struct *p, int flags) {
	// rq->cos.lord = p;
	printk("enqueue_task_cos  %d  cpu %d\n", p->pid, task_cpu(p));
	if (p == rq->cos.lord) {
		// rq->cos.lord_on_rq = 1;
		lord_on_rq = 1;
		// 666
		// printk("shizheli! %d %d\n", rq->cos.lord_on_rq, p->__state);
	}
	produce_task_runnable_msg(p);
}

void dequeue_task_cos(struct rq *rq, struct task_struct *p, int flags) {
	// rq->cos.lord = NULL;
	printk("dequeue_task_cos  %d  cpu %d\n", p->pid, task_cpu(p));
	if (p == rq->cos.lord) {
		// rq->cos.lord_on_rq = 0;
		lord_on_rq = 0;
	}
	produce_task_blocked_msg(p);
}

struct task_struct *pick_next_task_cos(struct rq *rq) {
	if (rq->cos.next_to_sched != NULL && task_is_running(rq->cos.next_to_sched)) {
		return rq->cos.next_to_sched;
	}
	if (rq->cos.lord != NULL && task_is_running(rq->cos.lord)) {
		return rq->cos.lord;
	}
	return NULL;
}

void task_dead_cos(struct task_struct *p) {
	preempt_disable();
	struct rq *rq;
	int cpu;
	
	cpu = smp_processor_id();
	rq = cpu_rq(cpu);
	if (rq->cos.lord == p) {
		ulong flags;
		spin_lock_irqsave(&cos_global_lock, flags);
		close_cos(rq);
		spin_unlock_irqrestore(&cos_global_lock, flags);
	}

	if (rq->cos.next_to_sched == p) {
		rq->cos.next_to_sched = NULL;
	}

	sched_preempt_enable_no_resched();
}

int select_task_rq_cos(struct task_struct *p, int task_cpu, int flags) 
{
	printk("select_task_rq_cos, lord_cpu %d\n", lord_cpu);
	if (is_lord(p)) {
		return lord_cpu;
	}
	return lord_cpu;
}

void yield_task_cos(struct rq *rq) 
{
	printk("yield_task_cos\n");
}

bool yield_to_task_cos(struct rq *rq, struct task_struct *p) 
{
	printk("yield_to_task_cos\n");
	return false;
}

void check_preempt_curr_cos(struct rq *rq, struct task_struct *p, int flags) 
{
	printk("check_preempt_curr_cos\n");
}

void put_prev_task_cos(struct rq *rq, struct task_struct *p) 
{
	// printk("put_prev_task_cos\n");
}

void set_next_task_cos(struct rq *rq, struct task_struct *p, bool first) 
{
	// printk("set_next_task_cos\n");
}

int balance_cos(struct rq *rq, struct task_struct *prev, struct rq_flags *rf) 
{
	// printk("balance_cos\n");
	return 0;
}

void set_cpus_allowed_cos(struct task_struct *p, struct affinity_context *ctx) 
{
	printk("set_cpus_allowed_cos\n");
}

void rq_online_cos(struct rq *rq) 
{
	printk("rq_online_cos\n");
}
	
void rq_offline_cos(struct rq *rq) 
{
	printk("rq_offline_cos\n");
}

struct task_struct * pick_task_cos(struct rq *rq) 
{
	printk("pick_task_cos\n");
	return NULL;
}

void task_tick_cos(struct rq *rq, struct task_struct *p, int queued) 
{
	// printk("task_tick_cos\n");
}

void switched_to_cos(struct rq *this_rq, struct task_struct *task) 
{
	printk("switched_to_cos\n");
}

void prio_changed_cos(struct rq *this_rq, struct task_struct *task, int oldprio) 
{
	printk("prio_changed_cos\n");
}

void update_curr_cos(struct rq *rq) 
{
	printk("update_curr_cos\n");
}

void cos_prepare_task_switch(struct rq *rq, struct task_struct *prev, struct task_struct *next) 
{
	
	if (!cos_policy(prev->policy)) {
		return;
	}

	if (is_lord(prev)) {
		return;
	}

	if (prev->cos.is_new) {
		if (task_on_rq_queued(prev)) {
			produce_task_new_msg(prev);
		} else {
			produce_task_new_blocked_msg(prev);
		}
		
		prev->cos.is_new = 0;
	}
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

//==================================cos调度类钩子函数结束=====================================

//==================================cos lord调度类钩子函数=====================================

struct task_struct *pick_next_task_cos_lord(struct rq *rq) {
	// lord不为空 lord可以运行 lord此时没有处于shoot负载的状态
	if (smp_processor_id() == lord_cpu) {
		// 666
		// printk("aaaaaaaaaa\n");
	}
	if (rq->cos.lord != NULL && (task_is_running(rq->cos.lord) || rq->cos.lord->__state, TASK_WAKING) && lord_on_rq != 0) {
		// 666
		// printk("dzhdzhdzh\n");
		return rq->cos.lord;
	}
	return NULL;
}

int balance_cos_lord(struct rq *rq, struct task_struct *prev, struct rq_flags *rf) {
	return 0;
}


DEFINE_SCHED_CLASS(cos_lord) = {
	.pick_next_task		= pick_next_task_cos_lord,
#ifdef CONFIG_SMP
	.balance		= balance_cos_lord,
#endif
};

//==================================cos lord调度类钩子函数结束=====================================



