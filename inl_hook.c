/*
 * kernel function inline hook.
 */
#define KMSG_COMPONENT "KINL_HOOK"
#define pr_fmt(fmt) KMSG_COMPONENT ": " fmt

#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/memory.h>
#include <linux/vmalloc.h>

#include "udis86.h"
#include "inl_hook.h"


#define JMP_CODE_BYTES			5
#define HOOK_MAX_CODE_BYTES		32 
#define MAX_DISASSEMBLE_BYTES	1024

struct hook_item {
	void *orig_func;
	void *hook_func;
	int stolen;
	u8 *orig_inst[HOOK_MAX_CODE_BYTES];

	// can execute page.
	u8 *trampoline;
	struct list_head list;
};

LIST_HEAD(hook_list);


inline unsigned long disable_wp(void)
{
	unsigned long cr0;

	preempt_disable();
	barrier();

	cr0 = read_cr0();
	write_cr0(cr0 & ~X86_CR0_WP);
	return cr0;
}


inline void restore_wp(unsigned long cr0)
{
	write_cr0(cr0);

	barrier();
	preempt_enable();
}


static u8 *skip_jumps(u8 *pcode)
{
	u8 *orig_code = pcode;

#if defined(CONFIG_X86_32) || defined(CONFIG_X86_64)
#if defined(CONFIG_X86_32)
	//mov edi,edi: hot patch point
	if (pcode[0] == 0x8b && pcode[1] == 0xff) {
		pcode += 2;
	}

	// push rbp; mov rsp, rbp;
	// 55 48 89 e5
	if (pcode[0] == 0x55 && pcode[1] == 0x48 && pcode[2] == 0x89 && pcode[3] == 0xe5) {
		pcode += 4;
	}
#endif

	if (pcode[0] == 0xff && pcode[1] == 0x25) {
#if defined(CONFIG_X86_32)
		// on x86 we have an absolute pointer...
		u8 *target = *(u8 **)&pcode[2];
		// ... that shows us an absolute pointer.
		return skip_jumps(*(u8 **)target);
#elif defined(CONFIG_X86_64)
		// on x64 we have a 32-bit offset...
		s32 offset = *(s32 *)&pcode[2];
		// ... that shows us an absolute pointer
		return skip_jumps(*(u8 **)(pcode + 6 + offset));
	} else if (pcode[0] == 0x48 && pcode[1] == 0xff && pcode[2] == 0x25) {
		// or we can have the same with a REX prefix
		s32 offset = *(s32 *)&pcode[3];
		// ... that shows us an absolute pointer
		return skip_jumps(*(u8 **)(pcode + 7 + offset));
#endif
	} else if (pcode[0] == 0xe9) {
		// here the behavior is identical, we have...
		// ...a 32-bit offset to the destination.
		return skip_jumps(pcode + 5 + *(s32 *)&pcode[1]);
	} else if (pcode[0] == 0xeb) {
		// and finally an 8-bit offset to the destination
		return skip_jumps(pcode + 2 + *(u8 *)&pcode[1]);
	}
#else
#error unsupported platform
#endif

	return orig_code;
}


static u8 *emit_jump(u8 *pcode, u8 *jumpto)
{
#if defined(CONFIG_X86_32) || defined(CONFIG_X86_64)
	u8 *jumpfrom = pcode + 5;
	size_t diff = jumpfrom > jumpto ? jumpfrom - jumpto : jumpto - jumpfrom;

	pr_debug("emit_jumps from %p to %p, diff is %ld", jumpfrom, jumpto, diff);

	if (diff <= 0x7fff0000) {
		pcode[0] = 0xe9;
		pcode += 1;
		*((u32 *)pcode) = (u32)(jumpto - jumpfrom);
		pcode += sizeof(u32);
	} else {
		pcode[0] = 0xff;
		pcode[1] = 0x25;
		pcode += 2;
#if defined(CONFIG_X86_32)
		// on x86 we write an absolute address (just behind the instruction)
		*((u32 *)pcode) = (u32)(pcode + sizeof(u32));
#elif defined(CONFIG_X86_64)
		// on x64 we write the relative address of the same location
		*((u32 *)pcode) = (u32)0;
#endif
		pcode += sizeof(u32);
		*((u64 *)pcode) = (u64)jumpto;
		pcode += sizeof(u64);
	}
#else
#error unsupported platform
#endif

	return pcode;
}


static u32 disassemble_skip(u8 *target, u32 min_len)
{
	ud_t u;
	u32 ret = 0;

	ud_init(&u);
	ud_set_input_buffer(&u, target, MAX_DISASSEMBLE_BYTES);
	ud_set_mode(&u, 64);
	ud_set_syntax(&u, UD_SYN_INTEL);

	while (ret < min_len && ud_disassemble(&u)) {
		ret += ud_insn_len(&u);
	}

	return ret;
}


static struct hook_item *trampoline_alloc(void *target, u32 stolen)
{
	struct hook_item *item;
	u32 bytes = stolen + HOOK_MAX_CODE_BYTES;

	item = vzalloc(sizeof(struct hook_item));
	if (!item) {
		return NULL;
	}

	item->trampoline = __vmalloc(bytes, GFP_KERNEL, PAGE_KERNEL_EXEC);

	if (item->trampoline == NULL) {
		vfree(item);
		return NULL;
	}

	memset(item->trampoline, 0, bytes);

	return item;
}


static struct hook_item *trampoline_find(u8 *hook)
{
	struct hook_item *item;

	list_for_each_entry(item, &hook_list, list) {
		if (hook == item->hook_func) {
			return item;
		}
	}

	return NULL;
}


static u8 *post_hook(struct hook_item *item, void *target,
		void *hook, u32 stolen)
{
	unsigned long o_cr0;

	item->orig_func = target;
	item->hook_func = hook;
	item->stolen = stolen;

	memmove(item->orig_inst, target, stolen);
	memmove(item->trampoline, target, stolen);

	emit_jump(item->trampoline + stolen, target + stolen);

	o_cr0 = disable_wp();
	emit_jump(target, hook);
	restore_wp(o_cr0);

	list_add(&item->list, &hook_list);

	return item->trampoline;
}


static void hook_restore(struct hook_item *item)
{
	unsigned long o_cr0;

	o_cr0 = disable_wp();
	memmove(item->orig_func, item->orig_inst, item->stolen);
	restore_wp(o_cr0);

	list_del(&item->list);

	vfree(item->trampoline);
	vfree(item);
}


int inl_sethook(void **orig, void *hook)
{
	u32 instr_len;
	struct hook_item *item;
	void *target = *orig;

	target = skip_jumps(target);
	hook = skip_jumps(hook);

	pr_debug("Started on the job: %p / %p\n", target, hook);

	instr_len = disassemble_skip(target, JMP_CODE_BYTES);
	if (instr_len < JMP_CODE_BYTES) {
		pr_err("disassemble_skip invalid instruction length: %u\n",
				instr_len);
		return -1;
	}

	pr_debug("disassembly signals %d bytes.\n", instr_len);

	item = trampoline_alloc(target, instr_len);
	if (item == NULL) {
		pr_err("alloc trampoline fail, no memory.\n");
		return -ENOMEM;
	}

	*orig = post_hook(item, target, hook, instr_len);

	return 0;
}


int inl_unhook(void *hook)
{
	struct hook_item *item;

	item = trampoline_find(hook);
	if (item == NULL) {
		pr_info("no find hook function: %p\n", hook);
		return -1;
	}

	hook_restore(item);

	return 0;
}

