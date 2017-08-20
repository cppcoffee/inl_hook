/*
 * inline hook usage example.
 */

#define KMSG_COMPONENT "HELLO"
#define pr_fmt(fmt) KMSG_COMPONENT ": " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <net/tcp.h>
#include <linux/kallsyms.h>

#include "inl_hook.h"


typedef int (*_TCP_V4_DO_RCV)(struct sock *sk, struct sk_buff *skb);

_TCP_V4_DO_RCV true_tcp_v4_do_rcv;


static int my_tcp_v4_do_rcv(struct sock *sk, struct sk_buff *skb)
{
	pr_info("sk=%p\n", sk);
	return true_tcp_v4_do_rcv(sk, skb);
}


static int init_find_ksymbol(void)
{
	true_tcp_v4_do_rcv = (_TCP_V4_DO_RCV) kallsyms_lookup_name("tcp_v4_do_rcv");
	if (true_tcp_v4_do_rcv == NULL) {
		pr_err("not find tcp_v4_do_rcv.\n");
		return -1;
	}

	return 0;
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
	inl_unhook(my_tcp_v4_do_rcv);
	pr_info("hello unloaded.\n");
}


module_init(hello_init);
module_exit(hello_cleanup);
MODULE_LICENSE("GPL");

