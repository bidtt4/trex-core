#ifndef _TCP_MBUF_H_
#define _TCP_MBUF_H_


struct mbuf;

#ifdef __cplusplus
extern "C" {
#endif

#define mtod(m, t)      ((t)m_data(m))
void *m_data(struct mbuf *);

void m_adj(struct mbuf *, int);

void m_freem(struct mbuf *);

#ifdef __cplusplus
}
#endif


#endif  /* !_TCP_MBUF_H_ */
