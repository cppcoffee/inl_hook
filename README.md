### about inl_hook

**inl_hook** is a linux kernel function inline hooking library. it is very easy to use.

### example

in the hello_core.c

```c
static void (*tcp_set_state_fn)(struct sock *sk, int state);

static void my_tcp_set_state(struct sock *sk, int state);

static struct hook_ops hello_hooks[] = {
	DECLARE_HOOK(&tcp_set_state_fn, my_tcp_set_state),
};


static void
my_tcp_set_state(struct sock *sk, int state)
{
	// copy your origin code here, then write patch code.
	// You can refer to hello_core.c
}

// hooking
ret = inl_sethook_ops(hello_hooks, ARRAY_SIZE(hello_hooks));
if (ret < 0) {
	pr_err("inl_sethook_ops hello_hooks fail.\n");
	goto exit;
}

// unhook
inl_unhook_ops(hello_hooks, ARRAY_SIZE(hello_hooks));
```

### thank

udis86: https://github.com/vmt/udis86

mhook: https://github.com/martona/mhook

