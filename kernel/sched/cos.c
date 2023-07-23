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
DEFINE_SPINLOCK(cos_global_lock);
struct task_struct *lord = NULL;

struct cos_shoot_area *task_shoot_area; /* Only lord cpu will access it */

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
	rq->cos.lord_on_rq = 1;
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
int cos_create_queue(struct cos_rq *cos_rq) 
{
	cos_rq->mq = vmalloc_user(sizeof(struct cos_message_queue));

	if (!cos_rq->mq) {
		return -ESRCH;
	}

	int fd = anon_inode_getfd("[cos_queue]", &queue_fops, cos_rq->mq,
			      O_RDWR | O_CLOEXEC);

	if (fd < 0) {
		vfree(cos_rq->mq);
		cos_rq->mq = NULL; //TODO
	}
	// cos_rq->mq->tail = 1;
	// cos_rq->mq->data[0].pid = 666;

	return fd;
}

int cos_do_create_mq(void) 
{
	int retval = 0;
	struct rq *rq;
	int cpu;
	preempt_disable();

	// 获取当前运行cpu
	cpu = smp_processor_id();
	rq = cpu_rq(cpu);

	int fd = cos_create_queue(&rq->cos);

	sched_preempt_enable_no_resched();

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
	task_shoot_area->area[lord_cpu].pid = lord->pid; // for test TODO

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
int cos_shoot_task(struct task_struct *p, struct rq *rq) 
{
	// 将p设为next_to_sched
	// rq->cos.next_to_sched = p;

	// 调用schedule()！！！
	cos_agent_schedule_new(p, rq);

	// 返回，宝贝！！！
	return 0;
}


int cos_do_shoot_task(pid_t pid) 
{
	printk("shoot task start! %d\n", pid);
	int retval = 0;
	struct task_struct *p;
	struct rq *rq;
	int cpu;
	preempt_disable();

	// 获取当前运行cpu
	cpu = smp_processor_id();
	rq = cpu_rq(cpu);

	// 获取目标线程
	rcu_read_lock();
	p = find_process_by_pid(pid);
	if (likely(p)) {
		get_task_struct(p);
	} else {
		sched_preempt_enable_no_resched();
		rcu_read_unlock();
		return -ESRCH;
	}
	rcu_read_unlock();

	retval = cos_shoot_task(p, rq);
	sched_preempt_enable_no_resched();
	return retval;
}
//============================================shoot=======================================================

//====================================系统调用函数结束=======================================

//==========================================cos辅助函数=========================================
/* must under cos_global_lock locked */
void close_cos(struct rq *rq) 
{
	rq->cos.lord = NULL; 
	rq->cos.lord_on_rq = 0;
	lord_cpu = 1;
	lord = NULL;
	BUG_ON(cos_on == 0);
	cos_on = 0;

	vfree(task_shoot_area);
	task_shoot_area = NULL; 
}
//==========================================cos辅助函数结束=========================================

//==================================供core.c使用的函数=====================================

void init_cos_rq(struct cos_rq *cos_rq) 
{
	cos_rq->lord = NULL;
	cos_rq->next_to_sched = NULL;
	cos_rq->mq = NULL;
	cos_rq->lord_on_rq = 0;

	// spin_lock_init(&cos_global_lock);
}

bool is_lord(struct task_struct *p)
{
	return p != NULL && p == lord;
}

//==================================供core.c使用的函数=====================================

//==================================消息队列函数=====================================

void product_enqueue_msg(struct rq *rq, struct task_struct *p) {
	if (p == rq->cos.lord || rq->cos.mq == NULL) {
		return;
	}
	printk("sss\n");
	rq->cos.mq->data[rq->cos.mq->tail].pid = p->pid;
	rq->cos.mq->data[rq->cos.mq->tail].type = 1;
	rq->cos.mq->tail++; // TODO
}

void product_dequeue_msg(struct rq *rq, struct task_struct *p) {
	if (p == rq->cos.lord || rq->cos.mq == NULL) {
		return;
	}
	rq->cos.mq->data[rq->cos.mq->tail].pid = p->pid;
	rq->cos.mq->data[rq->cos.mq->tail].type = 2;
	rq->cos.mq->tail++; // TODO
}

//==================================消息队列函数结束=====================================

//==================================cos调度类钩子函数=====================================

void enqueue_task_cos(struct rq *rq, struct task_struct *p, int flags) {
	// rq->cos.lord = p;
	printk("enqueue_task_cos  %d  cpu %d\n", p->pid, task_cpu(p));
	if (p == rq->cos.lord) {
		rq->cos.lord_on_rq = 1;
		// 666
		// printk("shizheli! %d %d\n", rq->cos.lord_on_rq, p->__state);
	}
	product_enqueue_msg(rq, p);
}

void dequeue_task_cos(struct rq *rq, struct task_struct *p, int flags) {
	// rq->cos.lord = NULL;
	printk("dequeue_task_cos  %d  cpu %d\n", p->pid, task_cpu(p));
	if (rq->cos.next_to_sched == p) 
		rq->cos.next_to_sched = NULL;
	if (p == rq->cos.lord) {
		rq->cos.lord_on_rq = 0;
	}
	product_dequeue_msg(rq, p);
}

struct task_struct *pick_next_task_cos(struct rq *rq) {
	if (rq->cos.next_to_sched != NULL) {
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
		if (rq->cos.mq) {
			vfree(rq->cos.mq);
			rq->cos.mq = NULL;
		}
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
	if (rq->cos.lord != NULL && (task_is_running(rq->cos.lord) || rq->cos.lord->__state, TASK_WAKING) && rq->cos.lord_on_rq != 0) {
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



