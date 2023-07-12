
static const struct rhashtable_params task_hash_params = {
	.key_len		= 8,
	.key_offset		= offsetof(struct task_struct, pid),
	.head_offset		= offsetof(struct task_struct, hash_node),
};

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

int cos_do_set_lord_cpu(int cpu_id);
bool task_should_cos(struct task_struct *p);
void set_lord_cpu(int cpu);
int cos_create_queue(struct cos_rq *cos_rq);
int cos_shoot_task(struct task_struct *p, struct rq *rq);




