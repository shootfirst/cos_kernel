
static const struct rhashtable_params task_hash_params = {
	.key_len		= 8,
	.key_offset		= offsetof(struct task_struct, pid),
	.head_offset		= offsetof(struct task_struct, hash_node),
};

extern const struct sched_class cos_sched_class;

bool task_should_cos(struct task_struct *p);




