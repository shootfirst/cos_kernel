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


//================================init_shoot=====================================
#define _SHOOT_AREA_SIZE 511
#define _SA_RIGHT 0
#define _SA_ERROR 1
struct cos_shoot_arg {
	u_int32_t pid;
	u_int32_t info;
};

struct cos_shoot_area {
	u_int64_t seq;
	struct cos_shoot_arg area[_SHOOT_AREA_SIZE];
};
//================================init_shoot=====================================



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



