// CONFIG_SCHED_CLASS_COS

#include <linux/mm.h>
#include <linux/file.h>
#include <linux/anon_inodes.h>

#include <linux/hrtimer.h>

#include "sched.h"

// =======================================全局变量===========================================
int cos_on = 0;
int lord_cpu = 1;
struct task_struct *lord = NULL;
DEFINE_SPINLOCK(cos_global_lock);

struct cos_message_queue *global_mq;
u_int16_t global_seq = 0;
DEFINE_SPINLOCK(cos_mq_lock);

struct cos_shoot_area *task_shoot_area; /* Only lord cpu will access it */

int lord_on_rq = 0;

struct rhashtable coscg_hash;
int next_coscg_id = 0;
spinlock_t coscg_lock; // protect above 2

static struct hrtimer coscg_timer;
ktime_t kt;






// =====================================工具=============================================
/**
 * find_process_by_pid - find a process with a matching PID value.
 * used in sys_sched_set/getaffinity() in kernel/sched/core.c, so
 * cloned here.
 */
static struct task_struct *find_process_by_pid(pid_t pid)
{
	return pid ? find_task_by_vpid(pid) : current;
}





// =======================================cos全局==========================================
void coscg_pay_salary(void)
{
	struct rhashtable_iter iter;
	struct cos_cgroup *coscg;

	rhashtable_walk_enter(&coscg_hash, &iter);
	do {
		rhashtable_walk_start(&iter);

		coscg = rhashtable_walk_next(&iter);
		while (!IS_ERR_OR_NULL(coscg)) {
			
			ulong flags;
			spin_lock_irqsave(&coscg->lock, flags);
			coscg->salary = coscg->rate * _COS_CGROUP_INTERVAL_NS / _COS_CGROUP_MAX_RATE;
			spin_unlock_irqrestore(&coscg->lock, flags);

			coscg = rhashtable_walk_next(&iter);
		}

		rhashtable_walk_stop(&iter);
	} while (coscg == ERR_PTR(-EAGAIN));
	rhashtable_walk_exit(&iter);
}

static enum hrtimer_restart htimer_handler(struct hrtimer *timer)
{
	printk("pay\n");
    hrtimer_forward(timer, timer->base->get_time(), kt);
	coscg_pay_salary();
    return HRTIMER_RESTART;
}
 
static int coscg_timer_init(void)
{
    kt = ktime_set(0, _COS_CGROUP_INTERVAL_NS);
    hrtimer_init(&coscg_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
    hrtimer_start(&coscg_timer, kt, HRTIMER_MODE_REL);
    coscg_timer.function = htimer_handler;
    return 0;
}
 
static void coscg_timer_exit(void)
{
    hrtimer_cancel(&coscg_timer);
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

	BUG_ON(rhashtable_init(&coscg_hash, &coscg_hash_params));
	spin_lock_init(&coscg_lock);
	coscg_timer_init();
}

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






//=====================================mq=========================================
int _produce(struct cos_msg *msg) 
{
	ulong flags;
	spin_lock_irqsave(&cos_mq_lock, flags);

	if (global_mq->head - global_mq->tail >= _MQ_SIZE) { /* The queue is full */
		WARN(1, "cos mq is full!\n");
		spin_unlock_irqrestore(&cos_mq_lock, flags);
		return -EINVAL;
	}
	
	msg->seq = global_seq;
	global_seq++;
	smp_mb();
	if (global_seq >= _MAX_SEQ_NUM) {
		WARN(1, "mq seq is full!\n");
		spin_unlock_irqrestore(&cos_mq_lock, flags);
		return -EINVAL;
	}

	global_mq->data[global_mq->head % _MQ_SIZE] = *msg;
	smp_wmb(); /* msg update must before head update */

	global_mq->head++;
	smp_wmb(); /* publish head update */

	printk("kernel produce msg: type: %d, pid %d\n", msg->type, msg->pid);
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
		break;
	case MSG_TASK_DEAD:
		msg.type = MSG_TASK_DEAD;
		break;
	case MSG_TASK_PREEMPT:
		msg.type = MSG_TASK_PREEMPT;
		break;
	case MSG_TASK_NEW_BLOCKED:
		msg.type = MSG_TASK_NEW_BLOCKED;
		break;
	case MSG_TASK_COS_PREEMPT:
		msg.type = MSG_TASK_COS_PREEMPT;
		break;
	default:
		WARN(1, "unknown cos_msg type %d!\n", msg_type);
		return -EINVAL;
	}

	msg.pid = p->pid;
	// printk("kernel produce msg: type: %d, pid %d\n", msg_type, p->pid);
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

int produce_task_preempt_msg(struct task_struct *p) 
{
	return produce_task_message(MSG_TASK_PREEMPT, p);
}

int produce_task_new_blocked_msg(struct task_struct *p) 
{
	return produce_task_message(MSG_TASK_NEW_BLOCKED, p);
}

int produce_task_cos_preempt_msg(struct task_struct *p) 
{
	return produce_task_message(MSG_TASK_COS_PREEMPT, p);
}


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






//============================================shoot area===================================================

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






//============================================shoot=======================================================
int cos_do_shoot_task(cpumask_var_t shoot_mask) 
{
	ulong flags;
	spin_lock_irqsave(&cos_mq_lock, flags);
	if (global_seq - 1 != task_shoot_area->seq)  {
		spin_unlock_irqrestore(&cos_mq_lock, flags);
		return -EINVAL;
	}
	spin_unlock_irqrestore(&cos_mq_lock, flags);

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

		
		if (p->cos.coscg && p->cos.coscg->salary <= 0) {
			task_shoot_area->area[cpu_id].info = _SA_CGRUNOUT;
			continue;
		}

		if (unlikely(p->cos.is_dying)) {
			task_shoot_area->area[cpu_id].info = _SA_ERROR;
			// printk("task %d is dying, can not be shot!\n", p->pid, cpu_id);
			continue;
		}
		
		if (unlikely(!task_is_running(p))) {
			task_shoot_area->area[cpu_id].info = _SA_ERROR;
			printk("no sync in the shoot loop! %d to cpu %d\n", p->pid, cpu_id);
			continue;
		}

		/* Then we get the target cpu rq and set next_to_sched*/
		rq = cpu_rq(cpu_id);
		if (unlikely(!rq)) {
			task_shoot_area->area[cpu_id].info = _SA_ERROR;
			printk("shoot cpu %d is not exist\n", cpu_id);
			continue;
		}

		spin_lock_irqsave(&rq->cos.lock, flags);
		if (rq->cos.next_to_sched && rq->cos.next_to_sched != p) {
			if (unlikely(rq->cos.next_to_sched->cos.is_dying)) {
				task_shoot_area->area[cpu_id].info = _SA_ERROR;
				spin_unlock_irqrestore(&rq->cos.lock, flags);
				printk("task %d is dying, can not be shot!\n", p->pid, cpu_id);
				continue;
			}
		}
 		rq->cos.next_to_sched = p; 
		rq->cos.is_shoot_first = 1;
		spin_unlock_irqrestore(&rq->cos.lock, flags);

		printk("shoot thread %d to cpu %d\n", p->pid, cpu_id);


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






//============================================cgroup==================================================

void update_before_oncpu(struct rq *rq, struct task_struct *p)
{
	if (!cos_policy(p->policy))
		return;
	p->se.exec_start = rq_clock_task(rq);
}

void update_after_offcpu(struct rq *rq, struct task_struct *p)
{
	u64 delta, now;

	if (!cos_policy(p->policy))
		return;

	VM_BUG_ON(!p->se.exec_start);

	now = rq_clock_task(rq);
	delta = now - p->se.exec_start;
	if ((s64)delta > 0 && p->cos.coscg) {
		ulong lock_flags;
		spin_lock_irqsave(&p->cos.coscg->lock, lock_flags);
		p->cos.coscg->salary -= delta;
		spin_unlock_irqrestore(&p->cos.coscg->lock, lock_flags);
	}
}

int coscg_should_offcpu(struct rq *rq, struct task_struct *p)
{
	u64 delta, now;

	if (!cos_policy(p->policy))
		return 0;

	VM_BUG_ON(!p->se.exec_start);

	now = rq_clock_task(rq);
	delta = now - p->se.exec_start;
	if ((s64)delta > 0 && p->cos.coscg) 
		return p->cos.coscg->salary - delta <= 0;
	
	return 0;
}



int cos_do_coscg_create(void)
{
	if (!cos_on)
		return -EINVAL;

	ulong lock_flags;
	spin_lock_irqsave(&coscg_lock, lock_flags);

	struct cos_cgroup *create = kmalloc(sizeof(*create), GFP_KERNEL);
	create->coscg_id = next_coscg_id;
	create->rate = 0;
	create->salary = 0;
	spin_lock_init(&create->lock);
	INIT_LIST_HEAD(&create->task_list);
	rhashtable_insert_fast(&coscg_hash, &create->hash_node, coscg_hash_params);
	next_coscg_id++;

	spin_unlock_irqrestore(&coscg_lock, lock_flags);

	return create->coscg_id;
}



int cos_do_coscg_delete(int coscg_id)
{
	if (!cos_on)
		return -EINVAL;

	struct task_struct *p;
	struct list_head *ele;

	ulong lock_flags;
	spin_lock_irqsave(&coscg_lock, lock_flags);

	struct cos_cgroup *remove = rhashtable_lookup_fast(&coscg_hash, &coscg_id, coscg_hash_params);
	if (!remove) {
		spin_unlock_irqrestore(&coscg_lock, lock_flags);
		return -EINVAL;
	}
	rhashtable_remove_fast(&coscg_hash, &remove->hash_node, coscg_hash_params);

	spin_unlock_irqrestore(&coscg_lock, lock_flags);


	list_for_each(ele, &remove->task_list) {
		p = list_entry(ele, struct task_struct, tasks);
		p->cos.coscg = NULL;
	}
	
	kfree(remove);
	return 0;
}



int cos_do_coscg_rate(int coscg_id, int rate)
{
	if (!cos_on)
		return -EINVAL;

	ulong lock_flags;
	spin_lock_irqsave(&coscg_lock, lock_flags);

	struct cos_cgroup *coscg = rhashtable_lookup_fast(&coscg_hash, &coscg_id, coscg_hash_params);
	if (!coscg) {
		spin_unlock_irqrestore(&coscg_lock, lock_flags);
		return -EINVAL;
	}
	coscg->rate = rate;
	
	spin_unlock_irqrestore(&coscg_lock, lock_flags);

	return 0;
}



int cos_do_coscg_ctl(int coscg_id, pid_t pid, int mode)
{
	if (!cos_on)
		return -EINVAL;
		
	struct task_struct *p;

	ulong lock_flags;
	spin_lock_irqsave(&coscg_lock, lock_flags);

	struct cos_cgroup *coscg = rhashtable_lookup_fast(&coscg_hash, &coscg_id, coscg_hash_params);
	if (!coscg) {
		spin_unlock_irqrestore(&coscg_lock, lock_flags);
		return -EINVAL;
	}

	spin_unlock_irqrestore(&coscg_lock, lock_flags);
	
	rcu_read_lock();
	p = find_process_by_pid(pid);
	if (unlikely(!p)) {
		rcu_read_unlock();
		return -EINVAL;
	}
	get_task_struct(p);
	rcu_read_unlock();


	spin_lock_irqsave(&coscg->lock, lock_flags);

	if (mode == _COS_CGROUP_TASK_ADD && !p->cos.coscg) {
		list_add_tail(&p->tasks, &coscg->task_list);
		p->cos.coscg = coscg;
	} else if (mode == _COS_CGROUP_TASK_DELETE && p->cos.coscg) {
		list_del(&p->tasks);
		p->cos.coscg = NULL;
	} else {
		spin_unlock_irqrestore(&coscg->lock, lock_flags);
		return -EINVAL;
	}

	spin_unlock_irqrestore(&coscg->lock, lock_flags);

	return 0;
}






//==================================core.c使用的函数=====================================

void init_cos_rq(struct cos_rq *cos_rq) 
{
	cos_rq->lord = NULL;
	spin_lock_init(&cos_rq->lock);
	cos_rq->next_to_sched = NULL;
	cos_rq->is_shoot_first = 0;
}

bool is_lord(struct task_struct *p)
{
	return p != NULL && lord != NULL && p == lord;
}

bool is_dying(struct task_struct *p)
{
	return p != NULL && p->cos.is_dying;
}

void cos_prepare_task_switch(struct rq *rq, struct task_struct *prev, struct task_struct *next) 
{
	
	if (!cos_policy(prev->policy)) 
		return;

	if (is_lord(prev))
		return;

	if (cos_policy(prev->policy)) 
		update_after_offcpu(rq, next);
	
	if (cos_policy(next->policy))
		update_before_oncpu(rq, prev);
		

	if (prev->cos.is_new) {
		if (task_on_rq_queued(prev)) {
			produce_task_new_msg(prev);
		} else {
			produce_task_new_blocked_msg(prev);
		}
		
		prev->cos.is_new = 0;
		return;
	}

	if (prev->cos.is_blocked) {
		return;
	}

	if (unlikely(prev == next)) {
		return;
	}

	ulong flags;
	spin_lock_irqsave(&rq->cos.lock, flags);
	if (prev == rq->cos.next_to_sched)
		rq->cos.next_to_sched = NULL;
	spin_unlock_irqrestore(&rq->cos.lock, flags);

	printk("preempt by %d sched_class %d\n", next->pid, next->policy);

	if (prev->cos.coscg && prev->cos.coscg->salary < 0) 
		return;

	if (cos_policy(next->policy)) 
		produce_task_cos_preempt_msg(prev);
	else 
		produce_task_preempt_msg(prev);
		
}






//==================================cos调度类=====================================

void enqueue_task_cos(struct rq *rq, struct task_struct *p, int flags) 
{
	if (p == rq->cos.lord) 
		lord_on_rq = 1;
	// p->cos.is_blocked = 0;
	// produce_task_runnable_msg(p);
}

void dequeue_task_cos(struct rq *rq, struct task_struct *p, int flags) 
{
	if (p == rq->cos.lord) 
		lord_on_rq = 0;

	ulong lock_flags;
	spin_lock_irqsave(&rq->cos.lock, lock_flags);
	if (p == rq->cos.next_to_sched && (flags & DEQUEUE_SLEEP)) {
		rq->cos.next_to_sched = NULL;
		p->cos.is_blocked = 1;
		produce_task_blocked_msg(p);
		// printk("set blocked %d, flag %x\n", p->pid, flags);
		// dump_stack();
	}
	spin_unlock_irqrestore(&rq->cos.lock, lock_flags);
	
}

struct task_struct *pick_next_task_cos(struct rq *rq) 
{

	ulong flags;
	spin_lock_irqsave(&rq->cos.lock, flags);
	if (rq->cos.next_to_sched != NULL && task_is_running(rq->cos.next_to_sched)) {

		if (rq->cos.next_to_sched->cos.coscg && rq->cos.next_to_sched->cos.coscg->salary <= 0) {
			spin_unlock_irqrestore(&rq->cos.lock, flags);
			return NULL;
		}

		spin_unlock_irqrestore(&rq->cos.lock, flags);
		return rq->cos.next_to_sched;
	}
	spin_unlock_irqrestore(&rq->cos.lock, flags);

	if (rq->cos.lord != NULL && task_is_running(rq->cos.lord)) {
		return rq->cos.lord;
	}
	return NULL;
}

void task_dead_cos(struct task_struct *p) 
{
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

	if (p->cos.coscg) {
		ulong lock_flags;
		spin_lock_irqsave(&p->cos.coscg->lock, lock_flags);
		list_del(&p->tasks);
		spin_unlock_irqrestore(&p->cos.coscg->lock, lock_flags);
		p->cos.coscg = NULL;
	}

	ulong flags;
	spin_lock_irqsave(&rq->cos.lock, flags);
	if (rq->cos.next_to_sched == p) {
		// printk("set dead %d\n", p->pid);
		rq->cos.next_to_sched = NULL;
	}
	spin_unlock_irqrestore(&rq->cos.lock, flags);

	if (p->__state == TASK_DEAD) 
		produce_task_dead_msg(p);

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

void task_woken_cos(struct rq *this_rq, struct task_struct *task)
{
	task->cos.is_blocked = 0;
	produce_task_runnable_msg(task);
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
	if (coscg_should_offcpu(rq, p)) {
		set_tsk_need_resched(p);
		set_preempt_need_resched();
		return;
	}
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
	.task_woken     = task_woken_cos,
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






//==================================cos lord调度类=====================================

struct task_struct *pick_next_task_cos_lord(struct rq *rq) {
	ulong flags;
	spin_lock_irqsave(&rq->cos.lock, flags);
	if (rq->cos.next_to_sched != NULL && task_is_running(rq->cos.next_to_sched) && rq->cos.is_shoot_first) {
		rq->cos.is_shoot_first = 0;
		spin_unlock_irqrestore(&rq->cos.lock, flags);
		return rq->cos.next_to_sched;
	}
	spin_unlock_irqrestore(&rq->cos.lock, flags);

	// lord不为空 lord可以运行 lord此时没有处于shoot负载的状态
	if (rq->cos.lord != NULL && task_is_running(rq->cos.lord) && lord_on_rq) {
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