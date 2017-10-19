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

#include "util.h"


/* variable */
static void (*tcp_set_state_fn)(struct sock *sk, int state);

/* hook function */
static void my_tcp_set_state(struct sock *sk, int state);


static struct symbol_ops hello_ops[] = {
	DECLARE_SYMBOL(&tcp_set_state_fn, "tcp_set_state"),
};


static struct hook_ops hello_hooks[] = {
	DECLARE_HOOK(&tcp_set_state_fn, my_tcp_set_state),
};


/* hook function */
static void
my_tcp_set_state(struct sock *sk, int state)
{
	/////////////////////////////////////////////////////////
	// add patch code.
	static const char *my_state_name[]={
		"Unused","Established","Syn Sent","Syn Recv",
		"Fin Wait 1","Fin Wait 2","Time Wait", "Close",
		"Close Wait","Last ACK","Listen","Closing"
	};
	struct inet_sock *inet = inet_sk(sk);
	/////////////////////////////////////////////////////////

	int oldstate = sk->sk_state;

	switch (state) {
	case TCP_ESTABLISHED:
		if (oldstate != TCP_ESTABLISHED)
			TCP_INC_STATS(sock_net(sk), TCP_MIB_CURRESTAB);
		break;

	case TCP_CLOSE:
		if (oldstate == TCP_CLOSE_WAIT || oldstate == TCP_ESTABLISHED)
			TCP_INC_STATS(sock_net(sk), TCP_MIB_ESTABRESETS);

		sk->sk_prot->unhash(sk);
		if (inet_csk(sk)->icsk_bind_hash &&
		    !(sk->sk_userlocks & SOCK_BINDPORT_LOCK))
			inet_put_port(sk);
		/* fall through */
	default:
		if (oldstate == TCP_ESTABLISHED)
			TCP_DEC_STATS(sock_net(sk), TCP_MIB_CURRESTAB);
	}

	/* Change state AFTER socket is unhashed to avoid closed
	 * socket sitting in hash tables.
	 */
	sk->sk_state = state;

	/////////////////////////////////////////////////////////
	// add patch code.
	pr_info("TCP %pI4:%d -> %pI4:%d, State %s -> %s\n",
			&inet->inet_saddr, ntohs(inet->inet_sport),
			&inet->inet_daddr, ntohs(inet->inet_dport),
			my_state_name[oldstate], my_state_name[state]);
	/////////////////////////////////////////////////////////

#ifdef STATE_TRACE
	SOCK_DEBUG(sk, "TCP sk=%p, State %s -> %s\n", sk, statename[oldstate], statename[state]);
#endif
}


static int __init hello_init(void)
{
	if (!find_ksymbol(hello_ops, ARRAY_SIZE(hello_ops))) {
		pr_err("hello symbol table not find.\n");
		return -1;
	}

	if (!inl_sethook_ops(hello_hooks, ARRAY_SIZE(hello_hooks))) {
		pr_err("hijack hello functions fail.\n");
		return -1;
	}

	pr_info("hello loaded.\n");
	return 0;
}


static void __exit hello_cleanup(void)
{
	inl_unhook_ops(hello_hooks, ARRAY_SIZE(hello_hooks));
	pr_info("hello unloaded.\n");
}


module_init(hello_init);
module_exit(hello_cleanup);
MODULE_LICENSE("GPL");

