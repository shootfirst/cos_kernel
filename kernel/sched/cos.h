struct msg {
	u_int32_t pid;
	u_int32_t type;
};

struct cos_message_queue {
	u_int32_t head;
	u_int32_t tail;
	struct msg data[511];
};



extern const struct sched_class cos_sched_class;
extern const struct sched_class cos_lord_sched_class;

// 外部使用
bool is_lord(struct task_struct *p);

// cos系统调用处理函数
int cos_do_set_lord(int cpu_id);
int cos_do_create_mq(void);
int cos_do_shoot_task(pid_t pid);



