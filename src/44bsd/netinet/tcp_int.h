#ifndef _TCP_INT_H_
#define _TCP_INT_H_


/* Linux headers */
#include <stdint.h>
#include <sys/types.h>


/* BSD system header */
#include <netinet/queue.h>


/* mbuf and socket headers */
#include <netinet/tcp_mbuf.h>
#include <netinet/tcp_socket.h>


/* BSD TCP headers */ 
#include <netinet/tcp_seq.h>
#include <netinet/tcp.h>

#include <netinet/tcp_timer.h>
#include <netinet/cc/cc.h>
#include <netinet/tcp_var.h>


#ifdef _SYS_INET_H_
#include <netinet/tcpip.h>
#endif
#include <netinet/tcp_debug.h>


extern struct cc_algo newreno_cc_algo;
extern struct cc_algo cubic_cc_algo;

extern void tcp_handle_timers(struct tcpcb *tp);


#endif /* !_TCP_INT_H_ */
