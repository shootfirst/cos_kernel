//================================mq=====================================
/* cos message type */
#define _MSG_TASK_FIRST	1
enum {
	MSG_TASK_RUNNABLE  = _MSG_TASK_FIRST,
	MSG_TASK_BLOCKED,
	MSG_TASK_NEW,
	MSG_TASK_DEAD,
	MSG_TASK_PREEMPT,
};

#define _MQ_SIZE 511

struct cos_msg {
	u_int32_t pid;
	u_int32_t type;
};

struct cos_message_queue {
	u_int32_t head;
	u_int32_t tail;
	struct cos_msg data[_MQ_SIZE];
};
//================================mq=====================================


//================================init_shoot=====================================
struct cos_shoot_arg {
	u_int32_t pid;
	u_int32_t info;
};

struct cos_shoot_area {
	struct cos_shoot_arg area[512];
};
//================================init_shoot=====================================



extern const struct sched_class cos_sched_class;
extern const struct sched_class cos_lord_sched_class;

// 外部使用
bool is_lord(struct task_struct *p);

// cos系统调用处理函数
int cos_do_set_lord(int cpu_id);
int cos_do_create_mq(void);
int cos_do_init_shoot(void);
int cos_do_shoot_task(cpumask_var_t shoot_mask);



