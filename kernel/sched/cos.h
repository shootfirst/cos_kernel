#include <linux/rhashtable.h>
#include <linux/list.h>

//================================mq=====================================
#define _MAX_SEQ_NUM ((1 << 16) - 1)

/* cos message type */
#define _MSG_TASK_FIRST	1
enum {
	MSG_TASK_RUNNABLE  = _MSG_TASK_FIRST,
	MSG_TASK_BLOCKED,
	MSG_TASK_NEW,
	MSG_TASK_DEAD,
	MSG_TASK_PREEMPT,
	MSG_TASK_NEW_BLOCKED,
	MSG_TASK_COS_PREEMPT,
};

#define _MQ_SIZE 511

struct cos_msg {
	u_int32_t pid;
	u_int16_t type;
	u_int16_t seq;
};

struct cos_message_queue {
	u_int32_t head;
	u_int32_t tail;
	struct cos_msg data[_MQ_SIZE];
};
//================================mq=====================================


//================================shoot area=====================================
#define _SHOOT_AREA_SIZE 511
#define _SA_RIGHT 0
#define _SA_ERROR 1
#define _SA_CGRUNOUT 2
struct cos_shoot_arg {
	u_int32_t pid;
	u_int32_t info;
};

struct cos_shoot_area {
	u_int64_t seq;
	struct cos_shoot_arg area[_SHOOT_AREA_SIZE];
};
//================================shoot area=====================================

//================================coscg=============================================
#define _COS_CGROUP_TASK_ADD     1
#define _COS_CGROUP_TASK_DELETE  2

#define _COS_CGROUP_MAX_RATE 100
#define _COS_CGROUP_INTERVAL_NS 1000000

struct cos_cgroup {
	u_int64_t coscg_id;
	struct rhash_head hash_node;

	int rate;
	
	int64_t salary; // set by timer and its task
	struct list_head task_list; // set by lord and task dead
	spinlock_t lock; // protect salary task_list and rate
};

static const struct rhashtable_params coscg_hash_params = {
	.key_len		= 8,
	.key_offset		= offsetof(struct cos_cgroup, coscg_id),
	.head_offset		= offsetof(struct cos_cgroup, hash_node),
};
//================================coscg=============================================



extern const struct sched_class cos_sched_class;
extern const struct sched_class cos_lord_sched_class;

// 外部使用
bool is_lord(struct task_struct *p);
bool is_dying(struct task_struct *p);
void cos_prepare_task_switch(struct rq *rq, struct task_struct *prev, struct task_struct *next);
int produce_task_dead_msg(struct task_struct *p);

// cos系统调用处理函数
int cos_do_set_lord(int cpu_id);
int cos_do_create_mq(void);
int cos_do_init_shoot(void);
int cos_do_shoot_task(cpumask_var_t shoot_mask);

int cos_do_coscg_create(void);
int cos_do_coscg_ctl(int coscg_id, pid_t pid, int mode);
int cos_do_coscg_rate(int coscg_id, int rate);
int cos_do_coscg_delete(int coscg_id);


