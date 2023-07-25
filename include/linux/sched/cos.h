#ifndef _LINUX_SCHED_COS_H
#define _LINUX_SCHED_COS_H

/*
 * The following is embedded in task_struct and contains all fields necessary
 * for a task to be scheduled by COS.
 */
struct sched_cos_entity {
	uint is_new;
	uint is_blocked;
};

#endif	/* _LINUX_SCHED_COS_H */