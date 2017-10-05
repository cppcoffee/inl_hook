/*
 * inline hook usage example.
 */

#define KMSG_COMPONENT "HELLO"
#define pr_fmt(fmt) KMSG_COMPONENT ": " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/kallsyms.h>
#include <linux/stop_machine.h>
#include <linux/stacktrace.h>
#include <asm/stacktrace.h>
#include <net/tcp.h>

#include "inl_hook.h"


struct instr_range {
	unsigned long start;
	unsigned long end;
};


#define MAX_STACK_TRACE_DEPTH   64
static unsigned long stack_entries[MAX_STACK_TRACE_DEPTH];
struct stack_trace trace = {
	.max_entries	= ARRAY_SIZE(stack_entries),
	.entries	= &stack_entries[0],
};


/* variable */
static int (*true_tcp_v4_do_rcv)(struct sock *sk, struct sk_buff *skb);


/* hook function */
static int my_tcp_v4_do_rcv(struct sock *sk, struct sk_buff *skb)
{
	pr_info("sk=%p\n", sk);
	return true_tcp_v4_do_rcv(sk, skb);
}


static int init_find_ksymbol(void)
{
	true_tcp_v4_do_rcv = (void *) kallsyms_lookup_name("tcp_v4_do_rcv");
	if (true_tcp_v4_do_rcv == NULL) {
		pr_err("not find tcp_v4_do_rcv.\n");
		return -1;
	}

	return 0;
}


/* Called from stop_machine */
static int
hello_safe_unhook_all(void *data)
{
	struct task_struct *g, *t;
	int i;
	int ret = 0;
	unsigned long address;
	struct instr_range irs[2] = {
		{
			.start = ((struct instr_range *)data)->start,
			.end = ((struct instr_range *)data)->end,
		},
		{
			.start = (unsigned long)hello_safe_unhook_all,
			.end = (unsigned long)&&lable_unhook_end,
		}
	};

	/* Check the stacks of all tasks. */
	do_each_thread(g, t) {
		trace.nr_entries = 0;
		save_stack_trace_tsk(t, &trace);

		if (trace.nr_entries >= trace.max_entries) {
			ret = -EBUSY;
			pr_err("more than %u trace entries!\n",
					trace.max_entries);
			goto out;
		}

		for (i = 0; i < trace.nr_entries; i++) {
			if (trace.entries[i] == ULONG_MAX)
				break;

			address = trace.entries[i];

			// without cleanup function.
			if ((address >= irs[0].start && address < irs[0].end)
				|| (address >= irs[1].start && address < irs[1].end)) {
				break;
			}

			ret = inl_within_trampoline(address);
			if (ret)
				goto out;

			if (within_module_core(address, THIS_MODULE)) {
				pr_info("within: %lx\n", trace.entries[i]);
				ret = -EBUSY;
				goto out;
			}
		}
	} while_each_thread(g, t);

	// hook cleanup.
	inl_unhook(my_tcp_v4_do_rcv);

out:
	return ret;

lable_unhook_end:
	;
}


static int __init hello_init(void)
{
	int ret;

	ret = init_find_ksymbol();
	if (ret < 0) {
		pr_err("find ksymbol fail.\n");
		goto exit;
	}

	ret = inl_sethook((void **)&true_tcp_v4_do_rcv, my_tcp_v4_do_rcv);
	if (ret < 0) {
		pr_err("inl_sethook tcp_v4_do_rcv fail.\n");
		goto exit;
	}

	pr_info("hello loaded.\n");

	return 0;

exit:
	return ret;
}


static void __exit hello_cleanup(void)
{
	int ret;
	struct instr_range ir;

try_again_unhook:
	ir.start = (unsigned long)hello_cleanup;
	ir.end = (unsigned long)&&lable_cleanup_end;

	ret = stop_machine(hello_safe_unhook_all, &ir, NULL);
	if (ret) {
		yield();
		pr_info("module busy, retry again unhook.\n");
		goto try_again_unhook;
	}

	pr_info("hello unloaded.\n");

lable_cleanup_end:
	;
}


module_init(hello_init);
module_exit(hello_cleanup);
MODULE_LICENSE("GPL");

