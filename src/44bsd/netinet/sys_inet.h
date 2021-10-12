#ifndef _SYS_INET_H_
#define _SYS_INET_H_


#include <stdint.h>                         // uint32_t
#include <stddef.h>                         // NULL
#include <stdbool.h>                        // bool
#include <limits.h>                         // INT_MAX,UINT_MAX
#include <math.h>                           // pow@cc_cubic.c

#include <linux/errno.h>                    // EMSGSIZE
#include <sys/types.h>                      // u_int,u_long,...

#include <malloc.h>                         // malloc(),free()
#include <assert.h>                         // assert()


// --<sys>---------------------------------------------------------------


// <sys/cdefs.h>
#define __packed            __attribute__((__packed__))
#define __aligned(x)        __attribute__((__aligned__(x)))
#define __unused            __attribute__((unused))
#define __predict_true(exp) __builtin_expect(!!(exp), 1)


#include <netinet/queue.h>


// <net/vnet.h>
#define CURVNET_SET(arg)
#define CURVNET_RESTORE()


// <sys/systm.h>
#define KASSERT(exp,msg)    do {} while(0)
#define bcopy(from, to, len) __builtin_memmove((to), (from), (len))
#define memmove(dest, src, n) __builtin_memmove((dest), (src), (n))


// <sys/param.h>
#define roundup2(x, y) (((x)+((y)-1))&(~((y)-1))) /* if y is powers of two */
#define howmany(x, y) (((x)+((y)-1))/(y))
#define roundup(x, y)   ((((x)+((y)-1))/(y))*(y))  /* to any y */


// <sys/libkern.h>
static __inline int imax(int a, int b) { return (a > b ? a : b); }
static __inline int imin(int a, int b) { return (a < b ? a : b); }
static __inline long lmax(long a, long b) { return (a > b ? a : b); }
static __inline long lmin(long a, long b) { return (a < b ? a : b); }
static __inline u_int max(u_int a, u_int b) { return (a > b ? a : b); }
static __inline u_int min(u_int a, u_int b) { return (a < b ? a : b); }
static __inline u_long ulmin(u_long a, u_long b) { return (a < b ? a : b); }
static __inline u_long ulmax(u_long a, u_long b) { return (a > b ? a : b); }


// <sys/epoch.h>
#define NET_EPOCH_ASSERT()
#define NET_EPOCH_ENTER(et)
#define NET_EPOCH_EXIT(et)


// --<inet>--------------------------------------------------------------


// <netinet/in_kdtrace.h>
#define TCP_PROBE2(probe, arg0, arg1)
#define TCP_PROBE3(probe, arg0, arg1, arg2)
#define TCP_PROBE5(probe, arg0, arg1, arg2, arg3, arg4)
#define TCP_PROBE6(probe, arg0, arg1, arg2, arg3, arg4, arg5)


// <netinet/tcp_log_buf.h>
#define TCP_LOG_EVENT(tp, th, rxbuf, txbuf, eventid, errornum, len, stackinfo, th_hostorder)


// <netinet/in.h>, <machine/endian.h>
#ifdef _LITTLE_ENDIAN
#define ntohl(x)    __builtin_bswap32(x)
#define htonl(x)    __builtin_bswap32(x)
#define ntohs(x)    __builtin_bswap16(x)
#define htons(x)    __builtin_bswap16(x)
#else
#define ntohl(x)    (x)
#define htonl(x)    (x)
#define ntohs(x)    (x)
#define htons(x)    (x)
#endif
typedef uint32_t  in_addr_t;
struct in_addr {
        in_addr_t s_addr;
};
#define IPPROTO_TCP             6               /* tcp */


// <netinet6/in6.h>
struct in6_addr {
        union {
                uint8_t         __u6_addr8[16];
                uint16_t        __u6_addr16[8];
                uint32_t        __u6_addr32[4];
        } __u6_addr;                    /* 128-bit IP6 address */
};


// <netinet/in_pcb.h>
#define INP_WLOCK(inp)
#define INP_WUNLOCK(inp)
#define INP_LOCK_ASSERT(inp)
#define INP_WLOCK_ASSERT(inp)
#define INP_INFO_LOCK_ASSERT(ipi)


#include <netinet/ip.h>
#include <netinet/ip6.h>


// <netinet/sockbuf.h>
#define SOCKBUF_LOCK(_sb)
#define SOCKBUF_LOCK_ASSERT(_sb)
#define SOCKBUF_UNLOCK(_sb)
#define SOCKBUF_UNLOCK_ASSERT(_sb)


#endif /* !_SYS_INET_H_ */
