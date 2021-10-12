#ifndef _TCP_MBUF_H_
#define _TCP_MBUF_H_


struct mbuf;

#define mtod(m, t)      ((t)m_data(m))
void *m_data(struct mbuf *);

void m_adj(struct mbuf *, int);

void m_freem(struct mbuf *);


#endif  /* !_TCP_MBUF_H_ */
