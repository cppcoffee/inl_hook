#ifndef _UTIL_H_
#define _UTIL_H_


#define DECLARE_SYMBOL(addr, str)	\
	{ (void **)addr, str }

struct symbol_ops {
	void **addr;
	char *symbol;
};


#define DECLARE_HOOK(orig, hook)	\
	{ (void *)orig, (void *)hook, #hook }

struct hook_ops {
	void **orig;
	void *hook;
	char *name;
};


typedef bool initfn(void);
typedef void cleanupfn(void);


bool find_ksymbol(struct symbol_ops *ops, int n);
bool inl_sethook_ops(struct hook_ops *ops, int n);
void inl_unhook_ops(struct hook_ops *ops, int n);


#endif

