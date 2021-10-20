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


#include <netinet/tcp_debug.h>


#ifdef __cplusplus
extern "C" {
#endif

/* provided functions */
int tcp_int_output(struct tcpcb *tp);
void tcp_int_input(struct tcpcb *tp, struct mbuf *m, struct tcphdr *th, int toff, int tlen, uint8_t iptos);
void tcp_handle_timers(struct tcpcb *tp);
void tcp_timer_activate(struct tcpcb *, uint32_t, u_int);
struct tcpcb* tcp_inittcpcb(struct tcpcb *tp, struct tcp_function_block *fb, struct cc_algo *cc_algo, struct tcp_tune *tune, struct tcpstat *stat);
void tcp_discardcb(struct tcpcb *tp);

/* required functions */
uint32_t tcp_ts_getticks(void);
int tcp_build_pkt(struct tcpcb *tp, uint32_t off, uint32_t len, uint16_t hdrlen, uint16_t optlen, struct mbuf **mp, struct tcphdr **thp);
int tcp_ip_output(struct tcpcb *tp, struct mbuf *m);
int tcp_reass(struct tcpcb *tp, struct tcphdr *th, tcp_seq *seq_start, int *tlenp, struct mbuf *m);
bool tcp_check_no_delay(struct tcpcb *, int);
bool tcp_isipv6(struct tcpcb *);
struct socket* tcp_getsocket(struct tcpcb *);

#ifdef __cplusplus
} /* extern "C" */
#endif

extern struct cc_algo newreno_cc_algo;
extern struct cc_algo cubic_cc_algo;


#endif /* !_TCP_INT_H_ */
