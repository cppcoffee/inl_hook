### abort inl_hook
**inl_hook** is a linux kernel function hooking library. It simple easy to use.

### example
```c
static int my_tcp_v4_do_rcv(struct sock *sk, struct sk_buff *skb)
{
	pr_info("sk=%p\n", sk);
	return true_tcp_v4_do_rcv(sk, skb);
}

// hooking
ret = inl_sethook((void **)&true_tcp_v4_do_rcv, my_tcp_v4_do_rcv);
if (ret < 0) {
	pr_err("inl_sethook tcp_v4_do_rcv fail.\n");
	goto exit;
}

// unhook
inl_unhook(my_tcp_v4_do_rcv);
```

### thank
udis86: https://github.com/vmt/udis86
mhook: https://github.com/martona/mhook

