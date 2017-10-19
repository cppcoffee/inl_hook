/*
 * inl_hook util.
 */
#define KMSG_COMPONENT "KINL_HOOK"
#define pr_fmt(fmt) KMSG_COMPONENT ": " fmt

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kallsyms.h>
#include <linux/swap.h>
#include <linux/stop_machine.h>
#include <linux/stacktrace.h>
#include <asm/stacktrace.h>

#include "util.h"
#include "inl_hook.h"


struct instr_range {
	unsigned long start;
	unsigned long end;
};


struct hook_cbdata {
	struct hook_ops *ops;
	int count;
	struct instr_range ir;
};


#define MAX_HOOK_CODE_BYTES     32
#define MAX_STACK_TRACE_DEPTH   64
static unsigned long stack_entries[MAX_STACK_TRACE_DEPTH];
struct stack_trace trace = {
	.max_entries	= ARRAY_SIZE(stack_entries),
	.entries	= &stack_entries[0],
};


static bool inline
within_address(unsigned long address, struct instr_range *ir)
{
	return address >= ir->start && address < ir->end;
}


bool find_ksymbol(struct symbol_ops *ops, int n)
{
	int i;
	void **addr;
	const char *name;

	for (i = 0; i < n; i++) {
		addr = ops[i].addr;
		name = ops[i].symbol;

		*addr = (void *) kallsyms_lookup_name(name);
		if (*addr == NULL) {
			pr_err("not find %s.\n", name);
			return false;
		}
	}

	return true;
}


static int
inl_sethook_safe_verify(struct hook_ops *ops, int count)
{
	struct instr_range ir;
	struct task_struct *g, *t;
	int i, j;
	void *orig;
	int ret = 0;

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

			for (j = 0; j < count; j++) {
				orig = *(ops[j].orig);

				ir.start = (unsigned long)orig;
				ir.end = (unsigned long)orig + MAX_HOOK_CODE_BYTES;

				if (within_address(trace.entries[i], &ir)) {
					ret = -EBUSY;
					goto out;
				}
			}
		}

	} while_each_thread(g, t);

out:
	return ret;
}


/* Called from stop_machine */
static int
inl_sethook_callback(void *data)
{
	int i;
	int ret;
	struct hook_cbdata *cbdata = (struct hook_cbdata *)data;

	ret = inl_sethook_safe_verify(cbdata->ops, cbdata->count);
	if (ret != 0) {
		return ret;
	}

	for (i = 0; i < cbdata->count; i++) {
		if (inl_sethook((void **)cbdata->ops[i].orig, cbdata->ops[i].hook) < 0) {
			pr_err("sethook_ops hook %s fail.\n", cbdata->ops[i].name);
			return -EFAULT;
		}
	}

	return 0;
}


bool inl_sethook_ops(struct hook_ops *ops, int n)
{
	int ret;
	struct hook_cbdata cbdata = {
		.ops = ops,
		.count = n,
	};

try_again_sethook:

	ret = stop_machine(inl_sethook_callback, &cbdata, NULL);

	if (ret == -EBUSY) {
		yield();
		pr_info("kernel busy, retry again inl_sethook_ops.\n");
		goto try_again_sethook;
	}

	return ret == 0;
}


static int
inl_unhook_safe_verify(struct instr_range *ir)
{
	unsigned long address;
	struct task_struct *g, *t;
	int i;
	int ret = 0;
	struct instr_range self_ir = {
		.start = (unsigned long)inl_unhook_safe_verify,
		.end = (unsigned long)&&label_unhook_verify_end,
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
			// within cleanup method.
			if (within_address(address, ir)
				|| within_address(address, &self_ir)) {
				break;
			}

			if (inl_within_trampoline(address)
				|| within_module_core(address, THIS_MODULE)) {
				ret = -EBUSY;
				goto out;
			}
		}

	} while_each_thread(g, t);

out:
	if (ret) {
		pr_err("PID: %d Comm: %.20s\n", t->pid, t->comm);
		for (i = 0; i < trace.nr_entries; i++) {
			if (trace.entries[i] == ULONG_MAX)
				break;
			pr_err("  [<%pK>] %pB\n",
			       (void *)trace.entries[i],
			       (void *)trace.entries[i]);
		}
	}

	return ret;

label_unhook_verify_end: ;
}


/* Called from stop_machine */
static int
inl_unhook_callback(void *data)
{
	int i;
	int ret;
	struct hook_cbdata *cbdata = (struct hook_cbdata *)data;

	ret = inl_unhook_safe_verify(&cbdata->ir);
	if (ret != 0) {
		return ret;
	}

	for (i = 0; i < cbdata->count; i++) {
		inl_unhook(cbdata->ops[i].hook);
	}

	return 0;
}


void inl_unhook_ops(struct hook_ops *ops, int n)
{
	int ret;
	struct hook_cbdata cbdata = {
		.ops = ops,
		.count = n,
		.ir.start = (unsigned long)inl_unhook_ops,
		.ir.end = (unsigned long)&&label_unhook_end,
	};

try_again_unhook:

	ret = stop_machine(inl_unhook_callback, &cbdata, NULL);

	if (ret) {
		yield();
		pr_info("module busy, retry again inl_unhook_ops.\n");
		goto try_again_unhook;
	}

label_unhook_end: ;
}


