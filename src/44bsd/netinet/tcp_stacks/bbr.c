/*-
 * Copyright (c) 2016-2020 Netflix, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */
/**
 * Author: Randall Stewart <rrs@netflix.com>
 * This work is based on the ACM Queue paper
 * BBR - Congestion Based Congestion Control
 * and also numerous discussions with Neal, Yuchung and Van.
 */

#if 1   // BBR_INT

#include "sys_inet.h"
#define	TCPOUTFLAGS
#include "tcp_var.h"

#include "tcp_seq.h"
#include "tcp_mbuf.h"


// sys/counter.h
typedef uint64_t *counter_u64_t;
#define counter_u64_add(c, i)   *c += i


// tcp_hpts.h, temporary
struct hpts_diag {};
struct inpcb;
void __tcp_set_inp_to_drop(struct inpcb *inp, uint16_t reason, int32_t line) {}
#define tcp_set_inp_to_drop(a, b) __tcp_set_inp_to_drop(NULL, b, __LINE__)
static __inline uint32_t tcp_tv_to_mssectick(const struct timeval *sv) {
    return ((uint32_t) ((sv->tv_sec * 1000) + (sv->tv_usec/1000)));
}
static __inline uint32_t tcp_tv_to_usectick(const struct timeval *sv) {
    return ((uint32_t) ((sv->tv_sec * 1000000) + sv->tv_usec));
}
static __inline uint32_t tcp_get_usecs(struct timeval *tv) {
    return (tcp_tv_to_usectick(tv));
}


// sys/queue.h
#define __containerof(ptr, type, member) \
    ((type *) ((uint8_t *)(ptr) - offsetof(type, member)))
#define QUEUE_TYPEOF(type)  struct type
#define TAILQ_LAST_FAST(head, type, field)                      \
    (TAILQ_EMPTY(head) ? NULL : __containerof((head)->tqh_last, QUEUE_TYPEOF(type), field.tqe_next))
#define TAILQ_FOREACH_REVERSE_FROM(var, head, headname, field)          \
        for ((var) = ((var) ? (var) : TAILQ_LAST((head), headname));    \
            (var);                                                      \
            (var) = TAILQ_PREV((var), headname, field))
#define TAILQ_FOREACH_FROM(var, head, field)                            \
        for ((var) = ((var) ? (var) : TAILQ_FIRST((head)));             \
            (var);                                                      \
            (var) = TAILQ_NEXT((var), field))


// temporary
#define arc4random_uniform(x)   (0)
#define V_tcp_map_entries_limit 0   /* unlimited */
#define V_tcp_map_split_limit   0   /* unlimited */

#define KMOD_TCPSTAT_INC    TCPSTAT_INC
#define KMOD_TCPSTAT_ADD    TCPSTAT_ADD

#define ticks   tcp_getticks(tp)

#define tcp_maxpersistidle  TCPTV_KEEP_IDLE

#define tcp_log_end_status(tp,status)

#define __predict_false(x)  __builtin_expect(x, 1)

#define kern_prefetch(x,y)


// for badport_bandlim rstreason, from netinet/icmp_var.h
#define BANDLIM_UNLIMITED -1
#define BANDLIM_RST_CLOSEDPORT 3 /* No connection, and no listeners */
#define BANDLIM_RST_OPENPORT 4   /* No connection, listener */


/* tcp_sack.c */
extern void tcp_clean_sackreport(struct tcpcb *tp);
extern void tcp_update_sack_list(struct tcpcb *tp, tcp_seq rcv_laststart, tcp_seq rcv_lastend);
extern void tcp_update_dsack_list(struct tcpcb *, tcp_seq, tcp_seq);
extern void tcp_clean_dsack_blocks(struct tcpcb *tp);

/* tcp_timer.c */
extern void tcp_timer_twstart(struct tcpcb *);

/* tcp_subr.c */
extern void tcp_state_change(struct tcpcb *, int);
extern struct tcpcb * tcp_drop(struct tcpcb *, int);
extern struct tcpcb * tcp_close(struct tcpcb *);
extern void tcp_respond(struct tcpcb *, void *, struct tcphdr *, struct mbuf *, tcp_seq, tcp_seq, int);
extern void tcp_switch_back_to_default(struct tcpcb *tp); // BBR

/* tcp_input.c */
extern void cc_conn_init(struct tcpcb *tp);
extern void tcp_dooptions(struct tcpcb *, struct tcpopt *, u_char *, int, int);
extern int tcp_addoptions(struct tcpcb *, struct tcpopt *, u_char *);
extern void tcp_mss(struct tcpcb *, int);
extern int tcp_mssopt(struct tcpcb *);


#define _KERNEL
#define CACHE_LINE_SIZE 128

#include "tim_filter.h"

#endif  // BBR_INT

#include "sack_filter.h"
#include "tcp_bbr.h"
#include "rack_bbr_common.h"

#define	TCPT_RANGESET_NOSLOP(tv, value, tvmin, tvmax) do { \
	(tv) = (value); \
	if ((u_long)(tv) < (u_long)(tvmin)) \
		(tv) = (tvmin); \
	if ((u_long)(tv) > (u_long)(tvmax)) \
		(tv) = (tvmax); \
} while(0)

/*
 * initial window
 */
static uint32_t bbr_def_init_win = 10;
static int32_t bbr_persist_min = 250000;	/* 250ms */
static int32_t bbr_persist_max = 1000000;	/* 1 Second */
static int32_t bbr_cwnd_may_shrink = 0;
static int32_t bbr_cwndtarget_rtt_touse = BBR_RTT_PROP;
static int32_t bbr_num_pktepo_for_del_limit = BBR_NUM_RTTS_FOR_DEL_LIMIT;
//static int32_t bbr_hardware_pacing_limit = 8000;
static int32_t bbr_quanta = 3;	/* How much extra quanta do we get? */
static int32_t bbr_no_retran = 0;

static int32_t bbr_error_base_paceout = 10000; /* usec to pace */
static int32_t bbr_max_net_error_cnt = 10;
/* Should the following be dynamic too -- loss wise */
static int32_t bbr_rtt_gain_thresh = 0;
/* Measurement controls */
static int32_t bbr_use_google_algo = 1;
static int32_t bbr_ts_limiting = 1;
static int32_t bbr_ts_can_raise = 0;
static int32_t bbr_do_red = 600;
static int32_t bbr_red_scale = 20000;
static int32_t bbr_red_mul = 1;
static int32_t bbr_red_div = 2;
static int32_t bbr_red_growth_restrict = 1;
static int32_t  bbr_target_is_bbunit = 0;
static int32_t bbr_drop_limit = 0;
/*
 * How much gain do we need to see to
 * stay in startup?
 */
static int32_t bbr_marks_rxt_sack_passed = 0;
static int32_t bbr_start_exit = 25;
static int32_t bbr_low_start_exit = 25;	/* When we are in reduced gain */
static int32_t bbr_startup_loss_thresh = 2000;	/* 20.00% loss */
static int32_t bbr_hptsi_max_mul = 1;	/* These two mul/div assure a min pacing */
static int32_t bbr_hptsi_max_div = 2;	/* time, 0 means turned off. We need this
					 * if we go back ever to where the pacer
					 * has priority over timers.
					 */
static int32_t bbr_policer_call_from_rack_to = 0;
static int32_t bbr_policer_detection_enabled = 1;
static int32_t bbr_min_measurements_req = 1;	/* We need at least 2
						 * measurements before we are
						 * "good" note that 2 == 1.
						 * This is because we use a >
						 * comparison. This means if
						 * min_measure was 0, it takes
						 * num-measures > min(0) and
						 * you get 1 measurement and
						 * you are good. Set to 1, you
						 * have to have two
						 * measurements (this is done
						 * to prevent it from being ok
						 * to have no measurements). */
static int32_t bbr_no_pacing_until = 4;

static int32_t bbr_min_usec_delta = 20000;	/* 20,000 usecs */
static int32_t bbr_min_peer_delta = 20;		/* 20 units */
static int32_t bbr_delta_percent = 150;		/* 15.0 % */

static int32_t bbr_target_cwnd_mult_limit = 8;
/*
 * bbr_cwnd_min_val is the number of
 * segments we hold to in the RTT probe
 * state typically 4.
 */
static int32_t bbr_cwnd_min_val = BBR_PROBERTT_NUM_MSS;

static int32_t bbr_cwnd_min_val_hs = BBR_HIGHSPEED_NUM_MSS;

static int32_t bbr_gain_to_target = 1;
static int32_t bbr_gain_gets_extra_too = 1;
/*
 * bbr_high_gain is the 2/ln(2) value we need
 * to double the sending rate in startup. This
 * is used for both cwnd and hptsi gain's.
 */
static int32_t bbr_high_gain = BBR_UNIT * 2885 / 1000 + 1;
static int32_t bbr_startup_lower = BBR_UNIT * 1500 / 1000 + 1;
static int32_t bbr_use_lower_gain_in_startup = 1;

/* thresholds for reduction on drain in sub-states/drain */
static int32_t bbr_drain_rtt = BBR_SRTT;
static int32_t bbr_drain_floor = 88;
static int32_t google_allow_early_out = 1;
static int32_t google_consider_lost = 1;
static int32_t bbr_drain_drop_mul = 4;
static int32_t bbr_drain_drop_div = 5;
static int32_t bbr_rand_ot = 50;
static int32_t bbr_can_force_probertt = 0;
static int32_t bbr_can_adjust_probertt = 1;
static int32_t bbr_probertt_sets_rtt = 0;
static int32_t bbr_can_use_ts_for_rtt = 1;
static int32_t bbr_is_ratio = 0;
static int32_t bbr_sub_drain_app_limit = 1;
static int32_t bbr_prtt_slam_cwnd = 1;
static int32_t bbr_sub_drain_slam_cwnd = 1;
static int32_t bbr_slam_cwnd_in_main_drain = 1;
static int32_t bbr_filter_len_sec = 6;	/* How long does the rttProp filter
					 * hold */
static uint32_t bbr_rtt_probe_limit = (USECS_IN_SECOND * 4);
/*
 * bbr_drain_gain is the reverse of the high_gain
 * designed to drain back out the standing queue
 * that is formed in startup by causing a larger
 * hptsi gain and thus drainging the packets
 * in flight.
 */
static int32_t bbr_drain_gain = BBR_UNIT * 1000 / 2885;
static int32_t bbr_rttprobe_gain = 192;

/*
 * The cwnd_gain is the default cwnd gain applied when
 * calculating a target cwnd. Note that the cwnd is
 * a secondary factor in the way BBR works (see the
 * paper and think about it, it will take some time).
 * Basically the hptsi_gain spreads the packets out
 * so you never get more than BDP to the peer even
 * if the cwnd is high. In our implemenation that
 * means in non-recovery/retransmission scenarios
 * cwnd will never be reached by the flight-size.
 */
static int32_t bbr_cwnd_gain = BBR_UNIT * 2;
static int32_t bbr_tlp_type_to_use = BBR_SRTT;
static int32_t bbr_delack_time = 100000;	/* 100ms in useconds */
//static int32_t bbr_sack_not_required = 0;	/* set to one to allow non-sack to use bbr */
static int32_t bbr_initial_bw_bps = 62500;	/* 500kbps in bytes ps */
static int32_t bbr_ignore_data_after_close = 1;
static int16_t bbr_hptsi_gain[] = {
	(BBR_UNIT *5 / 4),
	(BBR_UNIT * 3 / 4),
	BBR_UNIT,
	BBR_UNIT,
	BBR_UNIT,
	BBR_UNIT,
	BBR_UNIT,
	BBR_UNIT
};
int32_t bbr_use_rack_resend_cheat = 1;
int32_t bbr_sends_full_iwnd = 1;

#define BBR_HPTSI_GAIN_MAX 8
/*
 * The BBR module incorporates a number of
 * TCP ideas that have been put out into the IETF
 * over the last few years:
 * - Yuchung Cheng's RACK TCP (for which its named) that
 *    will stop us using the number of dup acks and instead
 *    use time as the gage of when we retransmit.
 * - Reorder Detection of RFC4737 and the Tail-Loss probe draft
 *    of Dukkipati et.al.
 * - Van Jacobson's et.al BBR.
 *
 * RACK depends on SACK, so if an endpoint arrives that
 * cannot do SACK the state machine below will shuttle the
 * connection back to using the "default" TCP stack that is
 * in FreeBSD.
 *
 * To implement BBR and RACK the original TCP stack was first decomposed
 * into a functional state machine with individual states
 * for each of the possible TCP connection states. The do_segment
 * functions role in life is to mandate the connection supports SACK
 * initially and then assure that the RACK state matches the conenction
 * state before calling the states do_segment function. Data processing
 * of inbound segments also now happens in the hpts_do_segment in general
 * with only one exception. This is so we can keep the connection on
 * a single CPU.
 *
 * Each state is simplified due to the fact that the original do_segment
 * has been decomposed and we *know* what state we are in (no
 * switches on the state) and all tests for SACK are gone. This
 * greatly simplifies what each state does.
 *
 * TCP output is also over-written with a new version since it
 * must maintain the new rack scoreboard and has had hptsi
 * integrated as a requirment. Still todo is to eliminate the
 * use of the callout_() system and use the hpts for all
 * timers as well.
 */
static uint32_t bbr_rtt_probe_time = 200000;	/* 200ms in micro seconds */
static uint32_t bbr_rtt_probe_cwndtarg = 4;	/* How many mss's outstanding */
static const int32_t bbr_min_req_free = 2;	/* The min we must have on the
						 * free list */
static int32_t bbr_tlp_thresh = 1;
static int32_t bbr_reorder_thresh = 2;
static int32_t bbr_reorder_fade = 60000000;	/* 0 - never fade, def
						 * 60,000,000 - 60 seconds */
static int32_t bbr_pkt_delay = 1000;
static int32_t bbr_min_to = 1000;	/* Number of usec's minimum timeout */
static int32_t bbr_incr_timers = 1;

static int32_t bbr_tlp_min = 10000;	/* 10ms in usecs */
static int32_t bbr_delayed_ack_time = 200000;	/* 200ms in usecs */
static int32_t bbr_exit_startup_at_loss = 1;

/*
 * bbr_lt_bw_ratio is 1/8th
 * bbr_lt_bw_diff is  < 4 Kbit/sec
 */
static uint64_t bbr_lt_bw_diff = 4000 / 8;	/* In bytes per second */
static uint64_t bbr_lt_bw_ratio = 8;	/* For 1/8th */
static uint32_t bbr_lt_bw_max_rtts = 48;	/* How many rtt's do we use
						 * the lt_bw for */
static uint32_t bbr_lt_intvl_min_rtts = 4;	/* Min num of RTT's to measure
						 * lt_bw */
static int32_t bbr_lt_intvl_fp = 0;		/* False positive epoch diff */
static int32_t bbr_lt_loss_thresh = 196;	/* Lost vs delivered % */
static int32_t bbr_lt_fd_thresh = 100;		/* false detection % */

//static int32_t bbr_verbose_logging = 0;
/*
 * Currently regular tcp has a rto_min of 30ms
 * the backoff goes 12 times so that ends up
 * being a total of 122.850 seconds before a
 * connection is killed.
 */
static int32_t bbr_rto_min_ms = 30;	/* 30ms same as main freebsd */
static int32_t bbr_rto_max_sec = 4;	/* 4 seconds */

/****************************************************/
/* DEFAULT TSO SIZING  (cpu performance impacting)  */
/****************************************************/
/* What amount is our formula using to get TSO size */
static int32_t bbr_hptsi_per_second = 1000;

/*
 * For hptsi under bbr_cross_over connections what is delay
 * target 7ms (in usec) combined with a seg_max of 2
 * gets us close to identical google behavior in
 * TSO size selection (possibly more 1MSS sends).
 */
static int32_t bbr_hptsi_segments_delay_tar = 7000;

/* Does pacing delay include overhead's in its time calculations? */
static int32_t bbr_include_enet_oh = 0;
static int32_t bbr_include_ip_oh = 1;
static int32_t bbr_include_tcp_oh = 1;
static int32_t bbr_google_discount = 10;

/* Do we use (nf mode) pkt-epoch to drive us or rttProp? */
static int32_t bbr_state_is_pkt_epoch = 0;
static int32_t bbr_state_drain_2_tar = 1;
/* What is the max the 0 - bbr_cross_over MBPS TSO target
 * can reach using our delay target. Note that this
 * value becomes the floor for the cross over
 * algorithm.
 */
static int32_t bbr_hptsi_segments_max = 2;
static int32_t bbr_hptsi_segments_floor = 1;
static int32_t bbr_hptsi_utter_max = 0;

/* What is the min the 0 - bbr_cross-over MBPS  TSO target can be */
static int32_t bbr_hptsi_bytes_min = 1460;
static int32_t bbr_all_get_min = 0;

/* Cross over point from algo-a to algo-b */
static uint32_t bbr_cross_over = TWENTY_THREE_MBPS;

/* Do we deal with our restart state? */
static int32_t bbr_uses_idle_restart = 0;
static int32_t bbr_idle_restart_threshold = 100000;	/* 100ms in useconds */

/* Do we allow hardware pacing? */
static int32_t bbr_allow_hdwr_pacing = 0;
#if 0
static int32_t bbr_hdwr_pace_adjust = 2;	/* multipler when we calc the tso size */
static int32_t bbr_hdwr_pace_floor = 1;
#endif
static int32_t bbr_hdwr_pacing_delay_cnt = 10;

/****************************************************/
static int32_t bbr_resends_use_tso = 0;
static int32_t bbr_tlp_max_resend = 2;
static int32_t bbr_sack_block_limit = 128;

#define  BBR_MAX_STAT 19
counter_u64_t bbr_state_time[BBR_MAX_STAT];
counter_u64_t bbr_state_lost[BBR_MAX_STAT];
counter_u64_t bbr_state_resend[BBR_MAX_STAT];
counter_u64_t bbr_stat_arry[BBR_STAT_SIZE];
counter_u64_t bbr_opts_arry[BBR_OPTS_SIZE];
counter_u64_t bbr_out_size[TCP_MSS_ACCT_SIZE];
counter_u64_t bbr_flows_whdwr_pacing;
counter_u64_t bbr_flows_nohdwr_pacing;

counter_u64_t bbr_nohdwr_pacing_enobuf;
counter_u64_t bbr_hdwr_pacing_enobuf;

static inline uint64_t bbr_get_bw(struct tcp_bbr *bbr);

/*
 * Static defintions we need for forward declarations.
 */
static uint32_t
bbr_get_pacing_length(struct tcp_bbr *bbr, uint16_t gain,
    uint32_t useconds_time, uint64_t bw);
static uint32_t
bbr_get_a_state_target(struct tcp_bbr *bbr, uint32_t gain);
static void
     bbr_set_state(struct tcpcb *tp, struct tcp_bbr *bbr, uint32_t win);
static void
bbr_set_probebw_gains(struct tcp_bbr *bbr,  uint32_t cts, uint32_t losses);
static void
bbr_substate_change(struct tcp_bbr *bbr, uint32_t cts, int line,
		    int dolog);
static uint32_t
bbr_get_target_cwnd(struct tcp_bbr *bbr, uint64_t bw, uint32_t gain);
static void
bbr_state_change(struct tcp_bbr *bbr, uint32_t cts, int32_t epoch,
		 int32_t pkt_epoch, uint32_t losses);
static uint32_t
bbr_calc_thresh_rack(struct tcp_bbr *bbr, uint32_t srtt, uint32_t cts, struct bbr_sendmap *rsm);
static uint32_t bbr_initial_cwnd(struct tcp_bbr *bbr, struct tcpcb *tp);
static uint32_t
bbr_calc_thresh_tlp(struct tcpcb *tp, struct tcp_bbr *bbr,
    struct bbr_sendmap *rsm, uint32_t srtt,
    uint32_t cts);
static void
bbr_exit_persist(struct tcpcb *tp, struct tcp_bbr *bbr, uint32_t cts,
    int32_t line);
static void
     bbr_set_state_target(struct tcp_bbr *bbr, int line);
static void
     bbr_enter_probe_rtt(struct tcp_bbr *bbr, uint32_t cts, int32_t line);

static void
     tcp_bbr_tso_size_check(struct tcp_bbr *bbr, uint32_t cts);

static void
     bbr_setup_red_bw(struct tcp_bbr *bbr, uint32_t cts);

static struct bbr_sendmap *
	    bbr_find_lowest_rsm(struct tcp_bbr *bbr);
static __inline uint32_t
bbr_get_rtt(struct tcp_bbr *bbr, int32_t rtt_type);

static void
bbr_enter_persist(struct tcpcb *tp, struct tcp_bbr *bbr,
    uint32_t cts, int32_t line);
static void
     bbr_stop_all_timers(struct tcpcb *tp);
static void
     bbr_exit_probe_rtt(struct tcpcb *tp, struct tcp_bbr *bbr, uint32_t cts);
static void
     bbr_check_probe_rtt_limits(struct tcp_bbr *bbr, uint32_t cts);
static void
     bbr_timer_cancel(struct tcp_bbr *bbr, int32_t line, uint32_t cts);


static inline uint8_t
bbr_state_val(struct tcp_bbr *bbr)
{
	return(bbr->rc_bbr_substate);
}

static inline uint32_t
get_min_cwnd(struct tcp_bbr *bbr)
{
	int mss;

	mss = min((bbr->rc_tp->t_maxseg - bbr->rc_last_options), bbr->r_ctl.rc_pace_max_segs);
	if (bbr_get_rtt(bbr, BBR_RTT_PROP) < BBR_HIGH_SPEED)
		return (bbr_cwnd_min_val_hs * mss);
	else
		return (bbr_cwnd_min_val * mss);
}

static uint32_t
bbr_get_persists_timer_val(struct tcpcb *tp, struct tcp_bbr *bbr)
{
	uint64_t srtt, var;
	uint64_t ret_val;

	bbr->r_ctl.rc_hpts_flags |= PACE_TMR_PERSIT;
	if (tp->t_srtt == 0) {
		srtt = (uint64_t)BBR_INITIAL_RTO;
		var = 0;
	} else {
		srtt = ((uint64_t)TICKS_2_USEC(tp->t_srtt) >> TCP_RTT_SHIFT);
		var = ((uint64_t)TICKS_2_USEC(tp->t_rttvar) >> TCP_RTT_SHIFT);
	}
	TCPT_RANGESET_NOSLOP(ret_val, ((srtt + var) * tcp_backoff[tp->t_rxtshift]),
	    bbr_persist_min, bbr_persist_max);
	return ((uint32_t)ret_val);
}

static uint32_t
bbr_timer_start(struct tcpcb *tp, struct tcp_bbr *bbr, uint32_t cts)
{
	/*
	 * Start the FR timer, we do this based on getting the first one in
	 * the rc_tmap. Note that if its NULL we must stop the timer. in all
	 * events we need to stop the running timer (if its running) before
	 * starting the new one.
	 */
	uint32_t thresh, exp, to, srtt, time_since_sent, tstmp_touse;
	int32_t idx;
	int32_t is_tlp_timer = 0;
	struct bbr_sendmap *rsm;

	if (bbr->rc_all_timers_stopped) {
		/* All timers have been stopped none are to run */
		return (0);
	}
	if (bbr->rc_in_persist) {
		/* We can't start any timer in persists */
		return (bbr_get_persists_timer_val(tp, bbr));
	}
	rsm = TAILQ_FIRST(&bbr->r_ctl.rc_tmap);
	if ((rsm == NULL) ||
	    ((tp->t_flags & TF_SACK_PERMIT) == 0) ||
	    (tp->t_state < TCPS_ESTABLISHED)) {
		/* Nothing on the send map */
activate_rxt:
		if (SEQ_LT(tp->snd_una, tp->snd_max) || sbavail(&(tcp_getsocket(tp)->so_snd))) {
			uint64_t tov;

			time_since_sent = 0;
			rsm = TAILQ_FIRST(&bbr->r_ctl.rc_tmap);
			if (rsm) {
				idx = rsm->r_rtr_cnt - 1;
				if (TSTMP_GEQ(rsm->r_tim_lastsent[idx], bbr->r_ctl.rc_tlp_rxt_last_time))
					tstmp_touse = rsm->r_tim_lastsent[idx];
				else
					tstmp_touse = bbr->r_ctl.rc_tlp_rxt_last_time;
				if (TSTMP_GT(tstmp_touse, cts))
				    time_since_sent = cts - tstmp_touse;
			}
			bbr->r_ctl.rc_hpts_flags |= PACE_TMR_RXT;
			if (tp->t_srtt == 0)
				tov = BBR_INITIAL_RTO;
			else
				tov = ((uint64_t)(TICKS_2_USEC(tp->t_srtt) +
				    ((uint64_t)TICKS_2_USEC(tp->t_rttvar) * (uint64_t)4)) >> TCP_RTT_SHIFT);
			if (tp->t_rxtshift)
				tov *= tcp_backoff[tp->t_rxtshift];
			if (tov > time_since_sent)
				tov -= time_since_sent;
			else
				tov = bbr->r_ctl.rc_min_to;
			TCPT_RANGESET_NOSLOP(to, tov,
			    (bbr->r_ctl.rc_min_rto_ms * MS_IN_USEC),
			    (bbr->rc_max_rto_sec * USECS_IN_SECOND));
			return (to);
		}
		return (0);
	}
	if (rsm->r_flags & BBR_ACKED) {
		rsm = bbr_find_lowest_rsm(bbr);
		if (rsm == NULL) {
			/* No lowest? */
			goto activate_rxt;
		}
	}
	/* Convert from ms to usecs */
	if (rsm->r_flags & BBR_SACK_PASSED) {
		if ((tp->t_flags & TF_SENTFIN) &&
		    ((tp->snd_max - tp->snd_una) == 1) &&
		    (rsm->r_flags & BBR_HAS_FIN)) {
			/*
			 * We don't start a bbr rack timer if all we have is
			 * a FIN outstanding.
			 */
			goto activate_rxt;
		}
		srtt = bbr_get_rtt(bbr, BBR_RTT_RACK);
		thresh = bbr_calc_thresh_rack(bbr, srtt, cts, rsm);
		idx = rsm->r_rtr_cnt - 1;
		exp = rsm->r_tim_lastsent[idx] + thresh;
		if (SEQ_GEQ(exp, cts)) {
			to = exp - cts;
			if (to < bbr->r_ctl.rc_min_to) {
				to = bbr->r_ctl.rc_min_to;
			}
		} else {
			to = bbr->r_ctl.rc_min_to;
		}
	} else {
		/* Ok we need to do a TLP not RACK */
		if (bbr->rc_tlp_in_progress != 0) {
			/*
			 * The previous send was a TLP.
			 */
			goto activate_rxt;
		}
		rsm = TAILQ_LAST_FAST(&bbr->r_ctl.rc_tmap, bbr_sendmap, r_tnext);
		if (rsm == NULL) {
			/* We found no rsm to TLP with. */
			goto activate_rxt;
		}
		if (rsm->r_flags & BBR_HAS_FIN) {
			/* If its a FIN we don't do TLP */
			rsm = NULL;
			goto activate_rxt;
		}
		time_since_sent = 0;
		idx = rsm->r_rtr_cnt - 1;
		if (TSTMP_GEQ(rsm->r_tim_lastsent[idx], bbr->r_ctl.rc_tlp_rxt_last_time))
			tstmp_touse = rsm->r_tim_lastsent[idx];
		else
			tstmp_touse = bbr->r_ctl.rc_tlp_rxt_last_time;
		if (TSTMP_GT(tstmp_touse, cts))
		    time_since_sent = cts - tstmp_touse;
		is_tlp_timer = 1;
		srtt = bbr_get_rtt(bbr, bbr_tlp_type_to_use);
		thresh = bbr_calc_thresh_tlp(tp, bbr, rsm, srtt, cts);
		if (thresh > time_since_sent)
			to = thresh - time_since_sent;
		else
			to = bbr->r_ctl.rc_min_to;
		if (to > (((uint32_t)bbr->rc_max_rto_sec) * USECS_IN_SECOND)) {
			/*
			 * If the TLP time works out to larger than the max
			 * RTO lets not do TLP.. just RTO.
			 */
			goto activate_rxt;
		}
		if ((bbr->rc_tlp_rtx_out == 1) &&
		    (rsm->r_start == bbr->r_ctl.rc_last_tlp_seq)) {
			/*
			 * Second retransmit of the same TLP
			 * lets not.
			 */
			bbr->rc_tlp_rtx_out = 0;
			goto activate_rxt;
		}
		if (rsm->r_start != bbr->r_ctl.rc_last_tlp_seq) {
			/*
			 * The tail is no longer the last one I did a probe
			 * on
			 */
			bbr->r_ctl.rc_tlp_seg_send_cnt = 0;
			bbr->r_ctl.rc_last_tlp_seq = rsm->r_start;
		}
	}
	if (is_tlp_timer == 0) {
		BBR_STAT_INC(bbr_to_arm_rack);
		bbr->r_ctl.rc_hpts_flags |= PACE_TMR_RACK;
	} else {
		if (bbr->r_ctl.rc_tlp_seg_send_cnt > bbr_tlp_max_resend) {
			/*
			 * We have exceeded how many times we can retran the
			 * current TLP timer, switch to the RTO timer.
			 */
			goto activate_rxt;
		} else {
			BBR_STAT_INC(bbr_to_arm_tlp);
			bbr->r_ctl.rc_hpts_flags |= PACE_TMR_TLP;
		}
	}
	return (to);
}

static inline int32_t
bbr_minseg(struct tcp_bbr *bbr)
{
	return (bbr->r_ctl.rc_pace_min_segs - bbr->rc_last_options);
}

static void
bbr_start_hpts_timer(struct tcp_bbr *bbr, struct tcpcb *tp, uint32_t cts, int32_t frm, int32_t slot, uint32_t tot_len)
{
#if 0
	struct inpcb *inp;
	struct hpts_diag diag;
#endif
	uint32_t delayed_ack = 0;
	uint32_t left = 0;
	uint32_t hpts_timeout;
	uint8_t stopped;
	int32_t delay_calc = 0;

#if 0   // BBR_INT: INPCB
	inp = tp->t_inpcb;
	if (inp->inp_in_hpts) {
		/* A previous call is already set up */
		return;
	}
#endif
	if ((tp->t_state == TCPS_CLOSED) ||
	    (tp->t_state == TCPS_LISTEN)) {
		return;
	}
	stopped = bbr->rc_tmr_stopped;
	if (stopped && TSTMP_GT(bbr->r_ctl.rc_timer_exp, cts)) {
		left = bbr->r_ctl.rc_timer_exp - cts;
	}
	bbr->r_ctl.rc_hpts_flags = 0;
	bbr->r_ctl.rc_timer_exp = 0;
	if (bbr->r_ctl.rc_last_delay_val &&
	    (slot == 0)) {
		/*
		 * If a previous pacer delay was in place we
		 * are not coming from the output side (where
		 * we calculate a delay, more likely a timer).
		 */
		slot = bbr->r_ctl.rc_last_delay_val;
		if (TSTMP_GT(cts, bbr->rc_pacer_started)) {
			/* Compensate for time passed  */
			delay_calc = cts - bbr->rc_pacer_started;
			if (delay_calc <= slot)
				slot -= delay_calc;
		}
	}
	/* Do we have early to make up for by pushing out the pacing time? */
	if (bbr->r_agg_early_set) {
		slot += bbr->r_ctl.rc_agg_early;
		bbr->r_ctl.rc_agg_early = 0;
		bbr->r_agg_early_set = 0;
	}
	/* Are we running a total debt that needs to be compensated for? */
	if (bbr->r_ctl.rc_hptsi_agg_delay) {
		if (slot > bbr->r_ctl.rc_hptsi_agg_delay) {
			/* We nuke the delay */
			slot -= bbr->r_ctl.rc_hptsi_agg_delay;
			bbr->r_ctl.rc_hptsi_agg_delay = 0;
		} else {
			/* We nuke some of the delay, put in a minimal 100usecs  */
			bbr->r_ctl.rc_hptsi_agg_delay -= slot;
			bbr->r_ctl.rc_last_delay_val = slot = 100;
		}
	}
	bbr->r_ctl.rc_last_delay_val = slot;
	hpts_timeout = bbr_timer_start(tp, bbr, cts);
	if (tp->t_flags & TF_DELACK) {
		if (bbr->rc_in_persist == 0) {
			delayed_ack = bbr_delack_time;
		} else {
			/*
			 * We are in persists and have
			 * gotten a new data element.
			 */
			if (hpts_timeout > bbr_delack_time) {
				/*
				 * Lets make the persists timer (which acks)
				 * be the smaller of hpts_timeout and bbr_delack_time.
				 */
				hpts_timeout = bbr_delack_time;
			}
		}
	}
	if (delayed_ack &&
	    ((hpts_timeout == 0) ||
	     (delayed_ack < hpts_timeout))) {
		/* We need a Delayed ack timer */
		bbr->r_ctl.rc_hpts_flags = PACE_TMR_DELACK;
		hpts_timeout = delayed_ack;
	}
	if (slot) {
		/* Mark that we have a pacing timer up */
		BBR_STAT_INC(bbr_paced_segments);
		bbr->r_ctl.rc_hpts_flags |= PACE_PKT_OUTPUT;
	}
	/*
	 * If no timers are going to run and we will fall off thfe hptsi
	 * wheel, we resort to a keep-alive timer if its configured.
	 */
	if ((hpts_timeout == 0) &&
	    (slot == 0)) {
		if ((V_tcp_always_keepalive || tcp_getsocket(tp)->so_options & SO_KEEPALIVE) &&
		    (tp->t_state <= TCPS_CLOSING)) {
			/*
			 * Ok we have no timer (persists, rack, tlp, rxt  or
			 * del-ack), we don't have segments being paced. So
			 * all that is left is the keepalive timer.
			 */
			if (TCPS_HAVEESTABLISHED(tp->t_state)) {
				hpts_timeout = TICKS_2_USEC(TP_KEEPIDLE(tp));
			} else {
				hpts_timeout = TICKS_2_USEC(TP_KEEPINIT(tp));
			}
			bbr->r_ctl.rc_hpts_flags |= PACE_TMR_KEEP;
		}
	}
	if (left && (stopped & (PACE_TMR_KEEP | PACE_TMR_DELACK)) ==
	    (bbr->r_ctl.rc_hpts_flags & PACE_TMR_MASK)) {
		/*
		 * RACK, TLP, persists and RXT timers all are restartable
		 * based on actions input .. i.e we received a packet (ack
		 * or sack) and that changes things (rw, or snd_una etc).
		 * Thus we can restart them with a new value. For
		 * keep-alive, delayed_ack we keep track of what was left
		 * and restart the timer with a smaller value.
		 */
		if (left < hpts_timeout)
			hpts_timeout = left;
	}
	if (bbr->r_ctl.rc_incr_tmrs && slot &&
	    (bbr->r_ctl.rc_hpts_flags & (PACE_TMR_TLP|PACE_TMR_RXT))) {
		/*
		 * If configured to do so, and the timer is either
		 * the TLP or RXT timer, we need to increase the timeout
		 * by the pacing time. Consider the bottleneck at my
		 * machine as an example, we are sending something
		 * to start a TLP on. The last packet won't be emitted
		 * fully until the pacing time (the bottleneck will hold
		 * the data in place). Once the packet is emitted that
		 * is when we want to start waiting for the TLP. This
		 * is most evident with hardware pacing (where the nic
		 * is holding the packet(s) before emitting). But it
		 * can also show up in the network so we do it for all
		 * cases. Technically we would take off one packet from
		 * this extra delay but this is easier and being more
		 * conservative is probably better.
		 */
		hpts_timeout += slot;
	}
	if (hpts_timeout) {
		/*
		 * Hack alert for now we can't time-out over 2147 seconds (a
		 * bit more than 35min)
		 */
		if (hpts_timeout > 0x7ffffffe)
			hpts_timeout = 0x7ffffffe;
		bbr->r_ctl.rc_timer_exp = cts + hpts_timeout;
	} else
		bbr->r_ctl.rc_timer_exp = 0;
	if ((slot) &&
	    (bbr->rc_use_google ||
	     bbr->output_error_seen ||
	     (slot <= hpts_timeout))  ) {
		/*
		 * Tell LRO that it can queue packets while
		 * we pace.
		 */
#if 0
		bbr->rc_inp->inp_flags2 |= INP_MBUF_QUEUE_READY;
		if ((bbr->r_ctl.rc_hpts_flags & PACE_TMR_RACK) &&
		    (bbr->rc_cwnd_limited == 0)) {
			/*
			 * If we are not cwnd limited and we
			 * are running a rack timer we put on
			 * the do not disturbe even for sack.
			 */
			inp->inp_flags2 |= INP_DONT_SACK_QUEUE;
		} else
			inp->inp_flags2 &= ~INP_DONT_SACK_QUEUE;
#endif
		bbr->rc_pacer_started = cts;

#if 0
		(void)tcp_hpts_insert_diag(tp->t_inpcb, HPTS_USEC_TO_SLOTS(slot),
					   __LINE__, &diag);
#endif
		bbr->rc_timer_first = 0;
		bbr->bbr_timer_src = frm;
	} else if (hpts_timeout) {
#if 0
		(void)tcp_hpts_insert_diag(tp->t_inpcb, HPTS_USEC_TO_SLOTS(hpts_timeout),
					   __LINE__, &diag);
#endif
		/*
		 * We add the flag here as well if the slot is set,
		 * since hpts will call in to clear the queue first before
		 * calling the output routine (which does our timers).
		 * We don't want to set the flag if its just a timer
		 * else the arrival of data might (that causes us
		 * to send more) might get delayed. Imagine being
		 * on a keep-alive timer and a request comes in for
		 * more data.
		 */
		if (slot)
			bbr->rc_pacer_started = cts;
#if 0
		if ((bbr->r_ctl.rc_hpts_flags & PACE_TMR_RACK) &&
		    (bbr->rc_cwnd_limited == 0)) {
			/*
			 * For a rack timer, don't wake us even
			 * if a sack arrives as long as we are
			 * not cwnd limited.
			 */
			bbr->rc_inp->inp_flags2 |= INP_MBUF_QUEUE_READY;
			inp->inp_flags2 |= INP_DONT_SACK_QUEUE;
		} else {
			/* All other timers wake us up */
			bbr->rc_inp->inp_flags2 &= ~INP_MBUF_QUEUE_READY;
			inp->inp_flags2 &= ~INP_DONT_SACK_QUEUE;
		}
#endif
		bbr->bbr_timer_src = frm;
		bbr->rc_timer_first = 1;
	}
	bbr->rc_tmr_stopped = 0;
}

static void
bbr_timer_audit(struct tcpcb *tp, struct tcp_bbr *bbr, uint32_t cts, struct sockbuf *sb)
{
	/*
	 * We received an ack, and then did not call send or were bounced
	 * out due to the hpts was running. Now a timer is up as well, is it
	 * the right timer?
	 */
#if 0
	struct inpcb *inp;
#endif
	struct bbr_sendmap *rsm;
	uint32_t hpts_timeout;
	int tmr_up;

	tmr_up = bbr->r_ctl.rc_hpts_flags & PACE_TMR_MASK;
	if (bbr->rc_in_persist && (tmr_up == PACE_TMR_PERSIT))
		return;
	rsm = TAILQ_FIRST(&bbr->r_ctl.rc_tmap);
	if (((rsm == NULL) || (tp->t_state < TCPS_ESTABLISHED)) &&
	    (tmr_up == PACE_TMR_RXT)) {
		/* Should be an RXT */
		return;
	}
#if 0
	inp = bbr->rc_inp;
#endif
	if (rsm == NULL) {
		/* Nothing outstanding? */
		if (tp->t_flags & TF_DELACK) {
			if (tmr_up == PACE_TMR_DELACK)
				/*
				 * We are supposed to have delayed ack up
				 * and we do
				 */
				return;
		} else if (sbavail(&tcp_getsocket(tp)->so_snd) &&
		    (tmr_up == PACE_TMR_RXT)) {
			/*
			 * if we hit enobufs then we would expect the
			 * possiblity of nothing outstanding and the RXT up
			 * (and the hptsi timer).
			 */
			return;
		} else if (((V_tcp_always_keepalive ||
			    tcp_getsocket(tp)->so_options & SO_KEEPALIVE) &&
			    (tp->t_state <= TCPS_CLOSING)) &&
			    (tmr_up == PACE_TMR_KEEP) &&
		    (tp->snd_max == tp->snd_una)) {
			/* We should have keep alive up and we do */
			return;
		}
	}
	if (rsm && (rsm->r_flags & BBR_SACK_PASSED)) {
		if ((tp->t_flags & TF_SENTFIN) &&
		    ((tp->snd_max - tp->snd_una) == 1) &&
		    (rsm->r_flags & BBR_HAS_FIN)) {
			/* needs to be a RXT */
			if (tmr_up == PACE_TMR_RXT)
				return;
			else
				goto wrong_timer;
		} else if (tmr_up == PACE_TMR_RACK)
			return;
		else
			goto wrong_timer;
	} else if (rsm && (tmr_up == PACE_TMR_RACK)) {
		/* Rack timer has priority if we have data out */
		return;
	} else if (SEQ_GT(tp->snd_max, tp->snd_una) &&
		    ((tmr_up == PACE_TMR_TLP) ||
	    (tmr_up == PACE_TMR_RXT))) {
		/*
		 * Either a TLP or RXT is fine if no sack-passed is in place
		 * and data is outstanding.
		 */
		return;
	} else if (tmr_up == PACE_TMR_DELACK) {
		/*
		 * If the delayed ack was going to go off before the
		 * rtx/tlp/rack timer were going to expire, then that would
		 * be the timer in control. Note we don't check the time
		 * here trusting the code is correct.
		 */
		return;
	}
	if (SEQ_GT(tp->snd_max, tp->snd_una) &&
	    ((tmr_up == PACE_TMR_RXT) ||
	     (tmr_up == PACE_TMR_TLP) ||
	     (tmr_up == PACE_TMR_RACK))) {
		/*
		 * We have outstanding data and
		 * we *do* have a RACK, TLP or RXT
		 * timer running. We won't restart
		 * anything here since thats probably ok we
		 * will get called with some timer here shortly.
		 */
		return;
	}
	/*
	 * Ok the timer originally started is not what we want now. We will
	 * force the hpts to be stopped if any, and restart with the slot
	 * set to what was in the saved slot.
	 */
wrong_timer:
	if ((bbr->r_ctl.rc_hpts_flags & PACE_PKT_OUTPUT) == 0) {
#if 0
		if (inp->inp_in_hpts)
			tcp_hpts_remove(inp, HPTS_REMOVE_OUTPUT);
#endif
		bbr_timer_cancel(bbr, __LINE__, cts);
		bbr_start_hpts_timer(bbr, tp, cts, 1, bbr->r_ctl.rc_last_delay_val,
		    0);
	} else {
		/*
		 * Output is hptsi so we just need to switch the type of
		 * timer. We don't bother with keep-alive, since when we
		 * jump through the output, it will start the keep-alive if
		 * nothing is sent.
		 *
		 * We only need a delayed-ack added and or the hpts_timeout.
		 */
		hpts_timeout = bbr_timer_start(tp, bbr, cts);
		if (tp->t_flags & TF_DELACK) {
			if (hpts_timeout == 0) {
				hpts_timeout = bbr_delack_time;
				bbr->r_ctl.rc_hpts_flags = PACE_TMR_DELACK;
			}
			else if (hpts_timeout > bbr_delack_time) {
				hpts_timeout = bbr_delack_time;
				bbr->r_ctl.rc_hpts_flags = PACE_TMR_DELACK;
			}
		}
		if (hpts_timeout) {
			if (hpts_timeout > 0x7ffffffe)
				hpts_timeout = 0x7ffffffe;
			bbr->r_ctl.rc_timer_exp = cts + hpts_timeout;
		}
	}
}

int32_t bbr_clear_lost = 0;

/*
 * Considers the two time values now (cts) and earlier.
 * If cts is smaller than earlier, we could have
 * had a sequence wrap (our counter wraps every
 * 70 min or so) or it could be just clock skew
 * getting us two differnt time values. Clock skew
 * will show up within 10ms or so. So in such
 * a case (where cts is behind earlier time by
 * less than 10ms) we return 0. Otherwise we
 * return the true difference between them.
 */
static inline uint32_t
bbr_calc_time(uint32_t cts, uint32_t earlier_time) {
	/*
	 * Given two timestamps, the current time stamp cts, and some other
	 * time-stamp taken in theory earlier return the difference. The
	 * trick is here sometimes locking will get the other timestamp
	 * after the cts. If this occurs we need to return 0.
	 */
	if (TSTMP_GEQ(cts, earlier_time))
		return (cts - earlier_time);
	/*
	 * cts is behind earlier_time if its less than 10ms consider it 0.
	 * If its more than 10ms difference then we had a time wrap. Else
	 * its just the normal locking foo. I wonder if we should not go to
	 * 64bit TS and get rid of this issue.
	 */
	if (TSTMP_GEQ((cts + 10000), earlier_time))
		return (0);
	/*
	 * Ok the time must have wrapped. So we need to answer a large
	 * amount of time, which the normal subtraction should do.
	 */
	return (cts - earlier_time);
}


#if 0   // BBR_INT
static void
bbr_init_sysctls(void)
{
	struct sysctl_oid *bbr_probertt;
	struct sysctl_oid *bbr_hptsi;
	struct sysctl_oid *bbr_measure;
	struct sysctl_oid *bbr_cwnd;
	struct sysctl_oid *bbr_timeout;
	struct sysctl_oid *bbr_states;
	struct sysctl_oid *bbr_startup;
	struct sysctl_oid *bbr_policer;

	/* Probe rtt controls */
	bbr_probertt = SYSCTL_ADD_NODE(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_sysctl_root),
	    OID_AUTO,
	    "probertt",
	    CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
	    "");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_probertt),
	    OID_AUTO, "gain", CTLFLAG_RW,
	    &bbr_rttprobe_gain, 192,
	    "What is the filter gain drop in probe_rtt (0=disable)?");
	SYSCTL_ADD_U32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_probertt),
	    OID_AUTO, "cwnd", CTLFLAG_RW,
	    &bbr_rtt_probe_cwndtarg, 4,
	    "How many mss's are outstanding during probe-rtt");
	SYSCTL_ADD_U32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_probertt),
	    OID_AUTO, "int", CTLFLAG_RW,
	    &bbr_rtt_probe_limit, 4000000,
	    "If RTT has not shrank in this many micro-seconds enter probe-rtt");
	SYSCTL_ADD_U32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_probertt),
	    OID_AUTO, "mintime", CTLFLAG_RW,
	    &bbr_rtt_probe_time, 200000,
	    "How many microseconds in probe-rtt");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_probertt),
	    OID_AUTO, "filter_len_sec", CTLFLAG_RW,
	    &bbr_filter_len_sec, 6,
	    "How long in seconds does the rttProp filter run?");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_probertt),
	    OID_AUTO, "drain_rtt", CTLFLAG_RW,
	    &bbr_drain_rtt, BBR_SRTT,
	    "What is the drain rtt to use in probeRTT (rtt_prop=0, rtt_rack=1, rtt_pkt=2, rtt_srtt=3?");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_probertt),
	    OID_AUTO, "can_force", CTLFLAG_RW,
	    &bbr_can_force_probertt, 0,
	    "If we keep setting new low rtt's but delay going in probe-rtt can we force in??");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_probertt),
	    OID_AUTO, "enter_sets_force", CTLFLAG_RW,
	    &bbr_probertt_sets_rtt, 0,
	    "In NF mode, do we imitate google_mode and set the rttProp on entry to probe-rtt?");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_probertt),
	    OID_AUTO, "can_adjust", CTLFLAG_RW,
	    &bbr_can_adjust_probertt, 1,
	    "Can we dynamically adjust the probe-rtt limits and times?");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_probertt),
	    OID_AUTO, "is_ratio", CTLFLAG_RW,
	    &bbr_is_ratio, 0,
	    "is the limit to filter a ratio?");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_probertt),
	    OID_AUTO, "use_cwnd", CTLFLAG_RW,
	    &bbr_prtt_slam_cwnd, 0,
	    "Should we set/recover cwnd?");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_probertt),
	    OID_AUTO, "can_use_ts", CTLFLAG_RW,
	    &bbr_can_use_ts_for_rtt, 1,
	    "Can we use the ms timestamp if available for retransmistted rtt calculations?");

	/* Pacing controls */
	bbr_hptsi = SYSCTL_ADD_NODE(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_sysctl_root),
	    OID_AUTO,
	    "pacing",
	    CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
	    "");
	SYSCTL_ADD_U32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_hptsi),
	    OID_AUTO, "hw_pacing", CTLFLAG_RW,
	    &bbr_allow_hdwr_pacing, 1,
	    "Do we allow hardware pacing?");
	SYSCTL_ADD_U32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_hptsi),
	    OID_AUTO, "hw_pacing_limit", CTLFLAG_RW,
	    &bbr_hardware_pacing_limit, 4000,
	    "Do we have a limited number of connections for pacing chelsio (0=no limit)?");
	SYSCTL_ADD_U32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_hptsi),
	    OID_AUTO, "hw_pacing_adj", CTLFLAG_RW,
	    &bbr_hdwr_pace_adjust, 2,
	    "Multiplier to calculated tso size?");
	SYSCTL_ADD_U32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_hptsi),
	    OID_AUTO, "hw_pacing_floor", CTLFLAG_RW,
	    &bbr_hdwr_pace_floor, 1,
	    "Do we invoke the hardware pacing floor?");
	SYSCTL_ADD_U32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_hptsi),
	    OID_AUTO, "hw_pacing_delay_cnt", CTLFLAG_RW,
	    &bbr_hdwr_pacing_delay_cnt, 10,
	    "How many packets must be sent after hdwr pacing is enabled");
	SYSCTL_ADD_U32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_hptsi),
	    OID_AUTO, "bw_cross", CTLFLAG_RW,
	    &bbr_cross_over, 3000000,
	    "What is the point where we cross over to linux like TSO size set");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_hptsi),
	    OID_AUTO, "seg_deltarg", CTLFLAG_RW,
	    &bbr_hptsi_segments_delay_tar, 7000,
	    "What is the worse case delay target for hptsi < 48Mbp connections");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_hptsi),
	    OID_AUTO, "enet_oh", CTLFLAG_RW,
	    &bbr_include_enet_oh, 0,
	    "Do we include the ethernet overhead in calculating pacing delay?");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_hptsi),
	    OID_AUTO, "ip_oh", CTLFLAG_RW,
	    &bbr_include_ip_oh, 1,
	    "Do we include the IP overhead in calculating pacing delay?");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_hptsi),
	    OID_AUTO, "tcp_oh", CTLFLAG_RW,
	    &bbr_include_tcp_oh, 0,
	    "Do we include the TCP overhead in calculating pacing delay?");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_hptsi),
	    OID_AUTO, "google_discount", CTLFLAG_RW,
	    &bbr_google_discount, 10,
	    "What is the default google discount percentage wise for pacing (11 = 1.1%%)?");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_hptsi),
	    OID_AUTO, "all_get_min", CTLFLAG_RW,
	    &bbr_all_get_min, 0,
	    "If you are less than a MSS do you just get the min?");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_hptsi),
	    OID_AUTO, "tso_min", CTLFLAG_RW,
	    &bbr_hptsi_bytes_min, 1460,
	    "For 0 -> 24Mbps what is floor number of segments for TSO");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_hptsi),
	    OID_AUTO, "seg_tso_max", CTLFLAG_RW,
	    &bbr_hptsi_segments_max, 6,
	    "For 0 -> 24Mbps what is top number of segments for TSO");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_hptsi),
	    OID_AUTO, "seg_floor", CTLFLAG_RW,
	    &bbr_hptsi_segments_floor, 1,
	    "Minimum TSO size we will fall too in segments");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_hptsi),
	    OID_AUTO, "utter_max", CTLFLAG_RW,
	    &bbr_hptsi_utter_max, 0,
	    "The absolute maximum that any pacing (outside of hardware) can be");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_hptsi),
	    OID_AUTO, "seg_divisor", CTLFLAG_RW,
	    &bbr_hptsi_per_second, 100,
	    "What is the divisor in our hptsi TSO calculation 512Mbps < X > 24Mbps ");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_hptsi),
	    OID_AUTO, "srtt_mul", CTLFLAG_RW,
	    &bbr_hptsi_max_mul, 1,
	    "The multiplier for pace len max");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_hptsi),
	    OID_AUTO, "srtt_div", CTLFLAG_RW,
	    &bbr_hptsi_max_div, 2,
	    "The divisor for pace len max");

	/* Measurement controls */
	bbr_measure = SYSCTL_ADD_NODE(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_sysctl_root),
	    OID_AUTO,
	    "measure",
	    CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
	    "Measurement controls");
	SYSCTL_ADD_U32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_measure),
	    OID_AUTO, "min_i_bw", CTLFLAG_RW,
	    &bbr_initial_bw_bps, 62500,
	    "Minimum initial b/w in bytes per second");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_measure),
	    OID_AUTO, "no_sack_needed", CTLFLAG_RW,
	    &bbr_sack_not_required, 0,
	    "Do we allow bbr to run on connections not supporting SACK?");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_measure),
	    OID_AUTO, "use_google", CTLFLAG_RW,
	    &bbr_use_google_algo, 0,
	    "Use has close to google V1.0 has possible?");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_measure),
	    OID_AUTO, "ts_limiting", CTLFLAG_RW,
	    &bbr_ts_limiting, 1,
	    "Do we attempt to use the peers timestamp to limit b/w caculations?");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_measure),
	    OID_AUTO, "ts_can_raise", CTLFLAG_RW,
	    &bbr_ts_can_raise, 0,
	    "Can we raise the b/w via timestamp b/w calculation?");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_measure),
	    OID_AUTO, "ts_delta", CTLFLAG_RW,
	    &bbr_min_usec_delta, 20000,
	    "How long in usec between ts of our sends in ts validation code?");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_measure),
	    OID_AUTO, "ts_peer_delta", CTLFLAG_RW,
	    &bbr_min_peer_delta, 20,
	    "What min numerical value should be between the peer deltas?");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_measure),
	    OID_AUTO, "ts_delta_percent", CTLFLAG_RW,
	    &bbr_delta_percent, 150,
	    "What percentage (150 = 15.0) do we allow variance for?");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_measure),
	    OID_AUTO, "min_measure_good_bw", CTLFLAG_RW,
	    &bbr_min_measurements_req, 1,
	    "What is the minimum measurement count we need before we switch to our b/w estimate");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_measure),
	    OID_AUTO, "min_measure_before_pace", CTLFLAG_RW,
	    &bbr_no_pacing_until, 4,
	    "How many pkt-epoch's (0 is off) do we need before pacing is on?");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_measure),
	    OID_AUTO, "quanta", CTLFLAG_RW,
	    &bbr_quanta, 2,
	    "Extra quanta to add when calculating the target (ID section 4.2.3.2).");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_measure),
	    OID_AUTO, "noretran", CTLFLAG_RW,
	    &bbr_no_retran, 0,
	    "Should google mode not use retransmission measurements for the b/w estimation?");

	/* State controls */
	bbr_states = SYSCTL_ADD_NODE(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_sysctl_root),
	    OID_AUTO,
	    "states",
	    CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
	    "State controls");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_states),
	    OID_AUTO, "idle_restart", CTLFLAG_RW,
	    &bbr_uses_idle_restart, 0,
	    "Do we use a new special idle_restart state to ramp back up quickly?");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_states),
	    OID_AUTO, "idle_restart_threshold", CTLFLAG_RW,
	    &bbr_idle_restart_threshold, 100000,
	    "How long must we be idle before we restart??");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_states),
	    OID_AUTO, "use_pkt_epoch", CTLFLAG_RW,
	    &bbr_state_is_pkt_epoch, 0,
	    "Do we use a pkt-epoch for substate if 0 rttProp?");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_states),
	    OID_AUTO, "startup_rtt_gain", CTLFLAG_RW,
	    &bbr_rtt_gain_thresh, 0,
	    "What increase in RTT triggers us to stop ignoring no-loss and possibly exit startup?");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_states),
	    OID_AUTO, "drain_floor", CTLFLAG_RW,
	    &bbr_drain_floor, 88,
	    "What is the lowest we can drain (pg) too?");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_states),
	    OID_AUTO, "drain_2_target", CTLFLAG_RW,
	    &bbr_state_drain_2_tar, 1,
	    "Do we drain to target in drain substate?");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_states),
	    OID_AUTO, "gain_2_target", CTLFLAG_RW,
	    &bbr_gain_to_target, 1,
	    "Does probe bw gain to target??");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_states),
	    OID_AUTO, "gain_extra_time", CTLFLAG_RW,
	    &bbr_gain_gets_extra_too, 1,
	    "Does probe bw gain get the extra time too?");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_states),
	    OID_AUTO, "ld_div", CTLFLAG_RW,
	    &bbr_drain_drop_div, 5,
	    "Long drain drop divider?");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_states),
	    OID_AUTO, "ld_mul", CTLFLAG_RW,
	    &bbr_drain_drop_mul, 4,
	    "Long drain drop multiplier?");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_states),
	    OID_AUTO, "rand_ot_disc", CTLFLAG_RW,
	    &bbr_rand_ot, 50,
	    "Random discount of the ot?");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_states),
	    OID_AUTO, "dr_filter_life", CTLFLAG_RW,
	    &bbr_num_pktepo_for_del_limit, BBR_NUM_RTTS_FOR_DEL_LIMIT,
	    "How many packet-epochs does the b/w delivery rate last?");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_states),
	    OID_AUTO, "subdrain_applimited", CTLFLAG_RW,
	    &bbr_sub_drain_app_limit, 0,
	    "Does our sub-state drain invoke app limited if its long?");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_states),
	    OID_AUTO, "use_cwnd_subdrain", CTLFLAG_RW,
	    &bbr_sub_drain_slam_cwnd, 0,
	    "Should we set/recover cwnd for sub-state drain?");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_states),
	    OID_AUTO, "use_cwnd_maindrain", CTLFLAG_RW,
	    &bbr_slam_cwnd_in_main_drain, 0,
	    "Should we set/recover cwnd for main-state drain?");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_states),
	    OID_AUTO, "google_gets_earlyout", CTLFLAG_RW,
	    &google_allow_early_out, 1,
	    "Should we allow google probe-bw/drain to exit early at flight target?");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_states),
	    OID_AUTO, "google_exit_loss", CTLFLAG_RW,
	    &google_consider_lost, 1,
	    "Should we have losses exit gain of probebw in google mode??");

	/* Startup controls */
	bbr_startup = SYSCTL_ADD_NODE(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_sysctl_root),
	    OID_AUTO,
	    "startup",
	    CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
	    "Startup controls");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_startup),
	    OID_AUTO, "cheat_iwnd", CTLFLAG_RW,
	    &bbr_sends_full_iwnd, 1,
	    "Do we not pace but burst out initial windows has our TSO size?");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_startup),
	    OID_AUTO, "loss_threshold", CTLFLAG_RW,
	    &bbr_startup_loss_thresh, 2000,
	    "In startup what is the loss threshold in a pe that will exit us from startup?");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_startup),
	    OID_AUTO, "use_lowerpg", CTLFLAG_RW,
	    &bbr_use_lower_gain_in_startup, 1,
	    "Should we use a lower hptsi gain if we see loss in startup?");
	SYSCTL_ADD_U32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_startup),
	    OID_AUTO, "gain", CTLFLAG_RW,
	    &bbr_start_exit, 25,
	    "What gain percent do we need to see to stay in startup??");
	SYSCTL_ADD_U32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_startup),
	    OID_AUTO, "low_gain", CTLFLAG_RW,
	    &bbr_low_start_exit, 15,
	    "What gain percent do we need to see to stay in the lower gain startup??");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_startup),
	    OID_AUTO, "loss_exit", CTLFLAG_RW,
	    &bbr_exit_startup_at_loss, 1,
	    "Should we exit startup at loss in an epoch if we are not gaining?");

	/* CWND controls */
	bbr_cwnd = SYSCTL_ADD_NODE(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_sysctl_root),
	    OID_AUTO,
	    "cwnd",
	    CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
	    "Cwnd controls");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_cwnd),
	    OID_AUTO, "tar_rtt", CTLFLAG_RW,
	    &bbr_cwndtarget_rtt_touse, 0,
	    "Target cwnd rtt measurement to use (0=rtt_prop, 1=rtt_rack, 2=pkt_rtt, 3=srtt)?");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_cwnd),
	    OID_AUTO, "may_shrink", CTLFLAG_RW,
	    &bbr_cwnd_may_shrink, 0,
	    "Can the cwnd shrink if it would grow to more than the target?");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_cwnd),
	    OID_AUTO, "max_target_limit", CTLFLAG_RW,
	    &bbr_target_cwnd_mult_limit, 8,
	    "Do we limit the cwnd to some multiple of the cwnd target if cwnd can't shrink 0=no?");
	SYSCTL_ADD_U32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_cwnd),
	    OID_AUTO, "highspeed_min", CTLFLAG_RW,
	    &bbr_cwnd_min_val_hs, BBR_HIGHSPEED_NUM_MSS,
	    "What is the high-speed min cwnd (rttProp under 1ms)");
	SYSCTL_ADD_U32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_cwnd),
	    OID_AUTO, "lowspeed_min", CTLFLAG_RW,
	    &bbr_cwnd_min_val, BBR_PROBERTT_NUM_MSS,
	    "What is the min cwnd (rttProp > 1ms)");
	SYSCTL_ADD_U32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_cwnd),
	    OID_AUTO, "initwin", CTLFLAG_RW,
	    &bbr_def_init_win, 10,
	    "What is the BBR initial window, if 0 use tcp version");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_cwnd),
	    OID_AUTO, "do_loss_red", CTLFLAG_RW,
	    &bbr_do_red, 600,
	    "Do we reduce the b/w at exit from recovery based on ratio of prop/srtt (800=80.0, 0=off)?");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_cwnd),
	    OID_AUTO, "red_scale", CTLFLAG_RW,
	    &bbr_red_scale, 20000,
	    "What RTT do we scale with?");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_cwnd),
	    OID_AUTO, "red_growslow", CTLFLAG_RW,
	    &bbr_red_growth_restrict, 1,
	    "Do we restrict cwnd growth for whats in flight?");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_cwnd),
	    OID_AUTO, "red_div", CTLFLAG_RW,
	    &bbr_red_div, 2,
	    "If we reduce whats the divisor?");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_cwnd),
	    OID_AUTO, "red_mul", CTLFLAG_RW,
	    &bbr_red_mul, 1,
	    "If we reduce whats the mulitiplier?");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_cwnd),
	    OID_AUTO, "target_is_unit", CTLFLAG_RW,
	    &bbr_target_is_bbunit, 0,
	    "Is the state target the pacing_gain or BBR_UNIT?");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_cwnd),
	    OID_AUTO, "drop_limit", CTLFLAG_RW,
	    &bbr_drop_limit, 0,
	    "Number of segments limit for drop (0=use min_cwnd w/flight)?");

	/* Timeout controls */
	bbr_timeout = SYSCTL_ADD_NODE(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_sysctl_root),
	    OID_AUTO,
	    "timeout",
	    CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
	    "Time out controls");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_timeout),
	    OID_AUTO, "delack", CTLFLAG_RW,
	    &bbr_delack_time, 100000,
	    "BBR's delayed ack time");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_timeout),
	    OID_AUTO, "tlp_uses", CTLFLAG_RW,
	    &bbr_tlp_type_to_use, 3,
	    "RTT that TLP uses in its calculations, 0=rttProp, 1=Rack_rtt, 2=pkt_rtt and 3=srtt");
	SYSCTL_ADD_U32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_timeout),
	    OID_AUTO, "persmin", CTLFLAG_RW,
	    &bbr_persist_min, 250000,
	    "What is the minimum time in microseconds between persists");
	SYSCTL_ADD_U32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_timeout),
	    OID_AUTO, "persmax", CTLFLAG_RW,
	    &bbr_persist_max, 1000000,
	    "What is the largest delay in microseconds between persists");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_timeout),
	    OID_AUTO, "tlp_minto", CTLFLAG_RW,
	    &bbr_tlp_min, 10000,
	    "TLP Min timeout in usecs");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_timeout),
	    OID_AUTO, "tlp_dack_time", CTLFLAG_RW,
	    &bbr_delayed_ack_time, 200000,
	    "TLP delayed ack compensation value");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_sysctl_root),
	    OID_AUTO, "minrto", CTLFLAG_RW,
	    &bbr_rto_min_ms, 30,
	    "Minimum RTO in ms");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_timeout),
	    OID_AUTO, "maxrto", CTLFLAG_RW,
	    &bbr_rto_max_sec, 4,
	    "Maximum RTO in seconds -- should be at least as large as min_rto");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_timeout),
	    OID_AUTO, "tlp_retry", CTLFLAG_RW,
	    &bbr_tlp_max_resend, 2,
	    "How many times does TLP retry a single segment or multiple with no ACK");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_timeout),
	    OID_AUTO, "minto", CTLFLAG_RW,
	    &bbr_min_to, 1000,
	    "Minimum rack timeout in useconds");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_timeout),
	    OID_AUTO, "pktdelay", CTLFLAG_RW,
	    &bbr_pkt_delay, 1000,
	    "Extra RACK time (in useconds) besides reordering thresh");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_timeout),
	    OID_AUTO, "incr_tmrs", CTLFLAG_RW,
	    &bbr_incr_timers, 1,
	    "Increase the RXT/TLP timer by the pacing time used?");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_timeout),
	    OID_AUTO, "rxtmark_sackpassed", CTLFLAG_RW,
	    &bbr_marks_rxt_sack_passed, 0,
	    "Mark sack passed on all those not ack'd when a RXT hits?");

	/* Policer controls */
	bbr_policer = SYSCTL_ADD_NODE(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_sysctl_root),
	    OID_AUTO,
	    "policer",
	    CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
	    "Policer controls");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_policer),
	    OID_AUTO, "detect_enable", CTLFLAG_RW,
	    &bbr_policer_detection_enabled, 1,
	    "Is policer detection enabled??");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_policer),
	    OID_AUTO, "min_pes", CTLFLAG_RW,
	    &bbr_lt_intvl_min_rtts, 4,
	    "Minimum number of PE's?");
	SYSCTL_ADD_U64(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_policer),
	    OID_AUTO, "bwdiff", CTLFLAG_RW,
	    &bbr_lt_bw_diff, (4000/8),
	    "Minimal bw diff?");
	SYSCTL_ADD_U64(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_policer),
	    OID_AUTO, "bwratio", CTLFLAG_RW,
	    &bbr_lt_bw_ratio, 8,
	    "Minimal bw diff?");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_policer),
	    OID_AUTO, "from_rack_rxt", CTLFLAG_RW,
	    &bbr_policer_call_from_rack_to, 0,
	    "Do we call the policer detection code from a rack-timeout?");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_policer),
	    OID_AUTO, "false_postive", CTLFLAG_RW,
	    &bbr_lt_intvl_fp, 0,
	    "What packet epoch do we do false-postive detection at (0=no)?");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_policer),
	    OID_AUTO, "loss_thresh", CTLFLAG_RW,
	    &bbr_lt_loss_thresh, 196,
	    "Loss threshold 196 = 19.6%?");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_policer),
	    OID_AUTO, "false_postive_thresh", CTLFLAG_RW,
	    &bbr_lt_fd_thresh, 100,
	    "What percentage is the false detection threshold (150=15.0)?");

	/* All the rest */
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_sysctl_root),
	    OID_AUTO, "cheat_rxt", CTLFLAG_RW,
	    &bbr_use_rack_resend_cheat, 0,
	    "Do we burst 1ms between sends on retransmissions (like rack)?");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_sysctl_root),
	    OID_AUTO, "error_paceout", CTLFLAG_RW,
	    &bbr_error_base_paceout, 10000,
	    "When we hit an error what is the min to pace out in usec's?");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_sysctl_root),
	    OID_AUTO, "kill_paceout", CTLFLAG_RW,
	    &bbr_max_net_error_cnt, 10,
	    "When we hit this many errors in a row, kill the session?");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_sysctl_root),
	    OID_AUTO, "data_after_close", CTLFLAG_RW,
	    &bbr_ignore_data_after_close, 1,
	    "Do we hold off sending a RST until all pending data is ack'd");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_sysctl_root),
	    OID_AUTO, "resend_use_tso", CTLFLAG_RW,
	    &bbr_resends_use_tso, 0,
	    "Can resends use TSO?");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_sysctl_root),
	    OID_AUTO, "sblklimit", CTLFLAG_RW,
	    &bbr_sack_block_limit, 128,
	    "When do we start ignoring small sack blocks");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_sysctl_root),
	    OID_AUTO, "bb_verbose", CTLFLAG_RW,
	    &bbr_verbose_logging, 0,
	    "Should BBR black box logging be verbose");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_sysctl_root),
	    OID_AUTO, "reorder_thresh", CTLFLAG_RW,
	    &bbr_reorder_thresh, 2,
	    "What factor for rack will be added when seeing reordering (shift right)");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_sysctl_root),
	    OID_AUTO, "reorder_fade", CTLFLAG_RW,
	    &bbr_reorder_fade, 0,
	    "Does reorder detection fade, if so how many ms (0 means never)");
	SYSCTL_ADD_S32(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_sysctl_root),
	    OID_AUTO, "rtt_tlp_thresh", CTLFLAG_RW,
	    &bbr_tlp_thresh, 1,
	    "what divisor for TLP rtt/retran will be added (1=rtt, 2=1/2 rtt etc)");
	/* Stats and counters */
	/* The pacing counters for hdwr/software can't be in the array */
	bbr_nohdwr_pacing_enobuf = counter_u64_alloc(M_WAITOK);
	bbr_hdwr_pacing_enobuf = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_sysctl_root),
	    OID_AUTO, "enob_hdwr_pacing", CTLFLAG_RD,
	    &bbr_hdwr_pacing_enobuf,
	    "Total number of enobufs for hardware paced flows");
	SYSCTL_ADD_COUNTER_U64(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_sysctl_root),
	    OID_AUTO, "enob_no_hdwr_pacing", CTLFLAG_RD,
	    &bbr_nohdwr_pacing_enobuf,
	    "Total number of enobufs for non-hardware paced flows");

	bbr_flows_whdwr_pacing = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_sysctl_root),
	    OID_AUTO, "hdwr_pacing", CTLFLAG_RD,
	    &bbr_flows_whdwr_pacing,
	    "Total number of hardware paced flows");
	bbr_flows_nohdwr_pacing = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_sysctl_root),
	    OID_AUTO, "software_pacing", CTLFLAG_RD,
	    &bbr_flows_nohdwr_pacing,
	    "Total number of software paced flows");
	COUNTER_ARRAY_ALLOC(bbr_stat_arry, BBR_STAT_SIZE, M_WAITOK);
	SYSCTL_ADD_COUNTER_U64_ARRAY(&bbr_sysctl_ctx, SYSCTL_CHILDREN(bbr_sysctl_root),
	    OID_AUTO, "stats", CTLFLAG_RD,
	    bbr_stat_arry, BBR_STAT_SIZE, "BBR Stats");
	COUNTER_ARRAY_ALLOC(bbr_opts_arry, BBR_OPTS_SIZE, M_WAITOK);
	SYSCTL_ADD_COUNTER_U64_ARRAY(&bbr_sysctl_ctx, SYSCTL_CHILDREN(bbr_sysctl_root),
	    OID_AUTO, "opts", CTLFLAG_RD,
	    bbr_opts_arry, BBR_OPTS_SIZE, "BBR Option Stats");
	COUNTER_ARRAY_ALLOC(bbr_state_lost, BBR_MAX_STAT, M_WAITOK);
	SYSCTL_ADD_COUNTER_U64_ARRAY(&bbr_sysctl_ctx, SYSCTL_CHILDREN(bbr_sysctl_root),
	    OID_AUTO, "lost", CTLFLAG_RD,
	    bbr_state_lost, BBR_MAX_STAT, "Stats of when losses occur");
	COUNTER_ARRAY_ALLOC(bbr_state_resend, BBR_MAX_STAT, M_WAITOK);
	SYSCTL_ADD_COUNTER_U64_ARRAY(&bbr_sysctl_ctx, SYSCTL_CHILDREN(bbr_sysctl_root),
	    OID_AUTO, "stateresend", CTLFLAG_RD,
	    bbr_state_resend, BBR_MAX_STAT, "Stats of what states resend");
	COUNTER_ARRAY_ALLOC(bbr_state_time, BBR_MAX_STAT, M_WAITOK);
	SYSCTL_ADD_COUNTER_U64_ARRAY(&bbr_sysctl_ctx, SYSCTL_CHILDREN(bbr_sysctl_root),
	    OID_AUTO, "statetime", CTLFLAG_RD,
	    bbr_state_time, BBR_MAX_STAT, "Stats of time spent in the states");
	COUNTER_ARRAY_ALLOC(bbr_out_size, TCP_MSS_ACCT_SIZE, M_WAITOK);
	SYSCTL_ADD_COUNTER_U64_ARRAY(&bbr_sysctl_ctx, SYSCTL_CHILDREN(bbr_sysctl_root),
	    OID_AUTO, "outsize", CTLFLAG_RD,
	    bbr_out_size, TCP_MSS_ACCT_SIZE, "Size of output calls");
	SYSCTL_ADD_PROC(&bbr_sysctl_ctx,
	    SYSCTL_CHILDREN(bbr_sysctl_root),
	    OID_AUTO, "clrlost", CTLTYPE_UINT | CTLFLAG_RW | CTLFLAG_MPSAFE,
	    &bbr_clear_lost, 0, sysctl_bbr_clear_lost, "IU", "Clear lost counters");
}
#endif  // BBR_INT

/*
 * Returns the bw from the our filter.
 */
static inline uint64_t
bbr_get_full_bw(struct tcp_bbr *bbr)
{
	uint64_t bw;

	bw = get_filter_value(&bbr->r_ctl.rc_delrate);

	return (bw);
}

static inline void
bbr_set_pktepoch(struct tcp_bbr *bbr, uint32_t cts, int32_t line)
{
	uint64_t calclr;
	uint32_t lost, del;

	if (bbr->r_ctl.rc_lost > bbr->r_ctl.rc_lost_at_pktepoch)
		lost = bbr->r_ctl.rc_lost - bbr->r_ctl.rc_lost_at_pktepoch;
	else
		lost = 0;
	del = bbr->r_ctl.rc_delivered - bbr->r_ctl.rc_pkt_epoch_del;
	if (lost == 0)  {
		calclr = 0;
	} else if (del) {
		calclr = lost;
		calclr *= (uint64_t)1000;
		calclr /= (uint64_t)del;
	} else {
		/* Nothing delivered? 100.0% loss */
		calclr = 1000;
	}
	bbr->r_ctl.rc_pkt_epoch_loss_rate =  (uint32_t)calclr;
	if (IN_RECOVERY(bbr->rc_tp->t_flags))
		bbr->r_ctl.recovery_lr += (uint32_t)calclr;
	bbr->r_ctl.rc_pkt_epoch++;
	if (bbr->rc_no_pacing &&
	    (bbr->r_ctl.rc_pkt_epoch >= bbr->no_pacing_until)) {
		bbr->rc_no_pacing = 0;
		tcp_bbr_tso_size_check(bbr, cts);
	}
	bbr->r_ctl.rc_pkt_epoch_rtt = bbr_calc_time(cts, bbr->r_ctl.rc_pkt_epoch_time);
	bbr->r_ctl.rc_pkt_epoch_time = cts;
	/* What was our loss rate */
	bbr->r_ctl.rc_pkt_epoch_del = bbr->r_ctl.rc_delivered;
	bbr->r_ctl.rc_lost_at_pktepoch = bbr->r_ctl.rc_lost;
}

static inline void
bbr_set_epoch(struct tcp_bbr *bbr, uint32_t cts, int32_t line)
{
	/* Tick the RTT clock */
	bbr->r_ctl.rc_rtt_epoch++;
	bbr->r_ctl.rc_rcv_epoch_start = cts;
}

static inline void
bbr_isit_a_pkt_epoch(struct tcp_bbr *bbr, uint32_t cts, struct bbr_sendmap *rsm, int32_t line, int32_t cum_acked)
{
	if (SEQ_GEQ(rsm->r_delivered, bbr->r_ctl.rc_pkt_epoch_del)) {
		bbr->rc_is_pkt_epoch_now = 1;
	}
}

/*
 * Returns the bw from either the b/w filter
 * or from the lt_bw (if the connection is being
 * policed).
 */
static inline uint64_t
__bbr_get_bw(struct tcp_bbr *bbr)
{
	uint64_t bw, min_bw;
	uint64_t rtt;
	int gm_measure_cnt = 1;

	/*
	 * For startup we make, like google, a
	 * minimum b/w. This is generated from the
	 * IW and the rttProp. We do fall back to srtt
	 * if for some reason (initial handshake) we don't
	 * have a rttProp. We, in the worst case, fall back
	 * to the configured min_bw (rc_initial_hptsi_bw).
	 */
	if (bbr->rc_bbr_state == BBR_STATE_STARTUP) {
		/* Attempt first to use rttProp */
		rtt = (uint64_t)get_filter_value_small(&bbr->r_ctl.rc_rttprop);
		if (rtt && (rtt < 0xffffffff)) {
measure:
			min_bw = (uint64_t)(bbr_initial_cwnd(bbr, bbr->rc_tp)) *
				((uint64_t)1000000);
			min_bw /= rtt;
			if (min_bw < bbr->r_ctl.rc_initial_hptsi_bw) {
				min_bw = bbr->r_ctl.rc_initial_hptsi_bw;
			}

		} else if (bbr->rc_tp->t_srtt != 0) {
			/* No rttProp, use srtt? */
			rtt = bbr_get_rtt(bbr, BBR_SRTT);
			goto measure;
		} else {
			min_bw = bbr->r_ctl.rc_initial_hptsi_bw;
		}
	} else
		min_bw = 0;

	if ((bbr->rc_past_init_win == 0) &&
	    (bbr->r_ctl.rc_delivered > bbr_initial_cwnd(bbr, bbr->rc_tp)))
		bbr->rc_past_init_win = 1;
	if ((bbr->rc_use_google)  && (bbr->r_ctl.r_measurement_count >= 1))
		gm_measure_cnt = 0;
	if (gm_measure_cnt &&
	    ((bbr->r_ctl.r_measurement_count < bbr_min_measurements_req) ||
	     (bbr->rc_past_init_win == 0))) {
		/* For google we use our guess rate until we get 1 measurement */

use_initial_window:
		rtt = (uint64_t)get_filter_value_small(&bbr->r_ctl.rc_rttprop);
		if (rtt && (rtt < 0xffffffff)) {
			/*
			 * We have an RTT measurement. Use that in
			 * combination with our initial window to calculate
			 * a b/w.
			 */
			bw = (uint64_t)(bbr_initial_cwnd(bbr, bbr->rc_tp)) *
				((uint64_t)1000000);
			bw /= rtt;
			if (bw < bbr->r_ctl.rc_initial_hptsi_bw) {
				bw = bbr->r_ctl.rc_initial_hptsi_bw;
			}
		} else {
			/* Drop back to the 40 and punt to a default */
			bw = bbr->r_ctl.rc_initial_hptsi_bw;
		}
		if (bw < 1)
			/* Probably should panic */
			bw = 1;
		if (bw > min_bw)
			return (bw);
		else
			return (min_bw);
	}
	if (bbr->rc_lt_use_bw)
		bw = bbr->r_ctl.rc_lt_bw;
	else if (bbr->r_recovery_bw && (bbr->rc_use_google == 0))
		bw = bbr->r_ctl.red_bw;
	else
		bw = get_filter_value(&bbr->r_ctl.rc_delrate);
	if (bbr->rc_tp->t_peakrate_thr && (bbr->rc_use_google == 0)) {
		/*
		 * Enforce user set rate limit, keep in mind that
		 * t_peakrate_thr is in B/s already
		 */
		bw = min((uint64_t)bbr->rc_tp->t_peakrate_thr, bw);
	}
	if (bw == 0) {
		/* We should not be at 0, go to the initial window then  */
		goto use_initial_window;
	}
	if (bw < 1)
		/* Probably should panic */
		bw = 1;
	if (bw < min_bw)
		bw = min_bw;
	return (bw);
}

static inline uint64_t
bbr_get_bw(struct tcp_bbr *bbr)
{
	uint64_t bw;

	bw = __bbr_get_bw(bbr);
	return (bw);
}

static inline void
bbr_reset_lt_bw_interval(struct tcp_bbr *bbr, uint32_t cts)
{
	bbr->r_ctl.rc_lt_epoch = bbr->r_ctl.rc_pkt_epoch;
	bbr->r_ctl.rc_lt_time = bbr->r_ctl.rc_del_time;
	bbr->r_ctl.rc_lt_del = bbr->r_ctl.rc_delivered;
	bbr->r_ctl.rc_lt_lost = bbr->r_ctl.rc_lost;
}

static inline void
bbr_reset_lt_bw_sampling(struct tcp_bbr *bbr, uint32_t cts)
{
	bbr->rc_lt_is_sampling = 0;
	bbr->rc_lt_use_bw = 0;
	bbr->r_ctl.rc_lt_bw = 0;
	bbr_reset_lt_bw_interval(bbr, cts);
}

static inline void
bbr_lt_bw_samp_done(struct tcp_bbr *bbr, uint64_t bw, uint32_t cts, uint32_t timin)
{
	uint64_t diff;

	/* Do we have a previous sample? */
	if (bbr->r_ctl.rc_lt_bw) {
		/* Get the diff in bytes per second */
		if (bbr->r_ctl.rc_lt_bw > bw)
			diff = bbr->r_ctl.rc_lt_bw - bw;
		else
			diff = bw - bbr->r_ctl.rc_lt_bw;
		if ((diff <= bbr_lt_bw_diff) ||
		    (diff <= (bbr->r_ctl.rc_lt_bw / bbr_lt_bw_ratio))) {
			/* Consider us policed */
			bbr->r_ctl.rc_lt_bw = (bw + bbr->r_ctl.rc_lt_bw) / 2;	/* average of two */
			bbr->rc_lt_use_bw = 1;
			bbr->r_ctl.rc_bbr_hptsi_gain = BBR_UNIT;
			/*
			 * Use pkt based epoch for measuring length of
			 * policer up
			 */
			bbr->r_ctl.rc_lt_epoch_use = bbr->r_ctl.rc_pkt_epoch;
			return;
		}
	}
	bbr->r_ctl.rc_lt_bw = bw;
	bbr_reset_lt_bw_interval(bbr, cts);
}

static void
bbr_randomize_extra_state_time(struct tcp_bbr *bbr)
{
	uint32_t ran, deduct;

	ran = arc4random_uniform(bbr_rand_ot);
	if (ran) {
		deduct = bbr->r_ctl.rc_level_state_extra / ran;
		bbr->r_ctl.rc_level_state_extra -= deduct;
	}
}
/*
 * Return randomly the starting state
 * to use in probebw.
 */
static uint8_t
bbr_pick_probebw_substate(struct tcp_bbr *bbr, uint32_t cts)
{
	uint32_t ran;
	uint8_t ret_val;

	/* Initialize the offset to 0 */
	bbr->r_ctl.rc_exta_time_gd = 0;
	bbr->rc_hit_state_1 = 0;
	bbr->r_ctl.rc_level_state_extra = 0;
	ran = arc4random_uniform((BBR_SUBSTATE_COUNT-1));
	/*
	 * The math works funny here :) the return value is used to set the
	 * substate and then the state change is called which increments by
	 * one. So if we return 1 (DRAIN) we will increment to 2 (LEVEL1) when
	 * we fully enter the state. Note that the (8 - 1 - ran) assures that
	 * we return 1 - 7, so we dont return 0 and end up starting in
	 * state 1 (DRAIN).
	 */
	ret_val = BBR_SUBSTATE_COUNT - 1 - ran;
	/* Set an epoch */
	if ((cts - bbr->r_ctl.rc_rcv_epoch_start) >= bbr_get_rtt(bbr, BBR_RTT_PROP))
		bbr_set_epoch(bbr, cts, __LINE__);

	bbr->r_ctl.bbr_lost_at_state = bbr->r_ctl.rc_lost;
	return (ret_val);
}

static void
bbr_lt_bw_sampling(struct tcp_bbr *bbr, uint32_t cts, int32_t loss_detected)
{
	uint32_t diff, d_time;
	uint64_t del_time, bw, lost, delivered;

	if (bbr->r_use_policer == 0)
		return;
	if (bbr->rc_lt_use_bw) {
		/* We are using lt bw do we stop yet? */
		diff = bbr->r_ctl.rc_pkt_epoch - bbr->r_ctl.rc_lt_epoch_use;
		if (diff > bbr_lt_bw_max_rtts) {
			/* Reset it all */
reset_all:
			bbr_reset_lt_bw_sampling(bbr, cts);
			if (bbr->rc_filled_pipe) {
				bbr_set_epoch(bbr, cts, __LINE__);
				bbr->rc_bbr_substate = bbr_pick_probebw_substate(bbr, cts);
				bbr_substate_change(bbr, cts, __LINE__, 0);
				bbr->rc_bbr_state = BBR_STATE_PROBE_BW;
			} else {
				/*
				 * This should not happen really
				 * unless we remove the startup/drain
				 * restrictions above.
				 */
				bbr->rc_bbr_state = BBR_STATE_STARTUP;
				bbr_set_epoch(bbr, cts, __LINE__);
				bbr->r_ctl.rc_bbr_state_time = cts;
				bbr->r_ctl.rc_lost_at_startup = bbr->r_ctl.rc_lost;
				bbr->r_ctl.rc_bbr_hptsi_gain = bbr->r_ctl.rc_startup_pg;
				bbr->r_ctl.rc_bbr_cwnd_gain = bbr->r_ctl.rc_startup_pg;
				bbr_set_state_target(bbr, __LINE__);
			}
			return;
		}
		if (bbr_lt_intvl_fp == 0) {
			/* Not doing false-postive detection */
			return;
		}
		/* False positive detection */
		if (diff == bbr_lt_intvl_fp) {
			/* At bbr_lt_intvl_fp we record the lost */
			bbr->r_ctl.rc_lt_del = bbr->r_ctl.rc_delivered;
			bbr->r_ctl.rc_lt_lost = bbr->r_ctl.rc_lost;
		} else if (diff > (bbr_lt_intvl_min_rtts + bbr_lt_intvl_fp)) {
			/* Now is our loss rate still high? */
			lost = bbr->r_ctl.rc_lost - bbr->r_ctl.rc_lt_lost;
			delivered = bbr->r_ctl.rc_delivered - bbr->r_ctl.rc_lt_del;
			if ((delivered == 0) ||
			    (((lost * 1000)/delivered) < bbr_lt_fd_thresh)) {
				/* No still below our threshold */
			} else {
				/* Yikes its still high, it must be a false positive */
				goto reset_all;
			}
		}
		return;
	}
	/*
	 * Wait for the first loss before sampling, to let the policer
	 * exhaust its tokens and estimate the steady-state rate allowed by
	 * the policer. Starting samples earlier includes bursts that
	 * over-estimate the bw.
	 */
	if (bbr->rc_lt_is_sampling == 0) {
		/* reason 1 is to begin doing the sampling  */
		if (loss_detected == 0)
			return;
		bbr_reset_lt_bw_interval(bbr, cts);
		bbr->rc_lt_is_sampling = 1;
		return;
	}
	/* Now how long were we delivering long term last> */
	if (TSTMP_GEQ(bbr->r_ctl.rc_del_time, bbr->r_ctl.rc_lt_time))
		d_time = bbr->r_ctl.rc_del_time - bbr->r_ctl.rc_lt_time;
	else
		d_time = 0;

	/* To avoid underestimates, reset sampling if we run out of data. */
	if (bbr->r_ctl.r_app_limited_until) {
		/* Can not measure in app-limited state */
		bbr_reset_lt_bw_sampling(bbr, cts);
		/* reason 2 is to reset sampling due to app limits  */
		return;
	}
	diff = bbr->r_ctl.rc_pkt_epoch - bbr->r_ctl.rc_lt_epoch;
	if (diff < bbr_lt_intvl_min_rtts) {
		/*
		 * need more samples (we don't
		 * start on a round like linux so
		 * we need 1 more).
		 */
		/* 6 is not_enough time or no-loss */
		return;
	}
	if (diff > (4 * bbr_lt_intvl_min_rtts)) {
		/*
		 * For now if we wait too long, reset all sampling. We need
		 * to do some research here, its possible that we should
		 * base this on how much loss as occurred.. something like
		 * if its under 10% (or some thresh) reset all otherwise
		 * don't.  Thats for phase II I guess.
		 */
		bbr_reset_lt_bw_sampling(bbr, cts);
 		/* reason 3 is to reset sampling due too long of sampling */
		return;
	}
	/*
	 * End sampling interval when a packet is lost, so we estimate the
	 * policer tokens were exhausted. Stopping the sampling before the
	 * tokens are exhausted under-estimates the policed rate.
	 */
	if (loss_detected == 0) {
		/* 6 is not_enough time or no-loss */
		return;
	}
	/* Calculate packets lost and delivered in sampling interval. */
	lost = bbr->r_ctl.rc_lost - bbr->r_ctl.rc_lt_lost;
	delivered = bbr->r_ctl.rc_delivered - bbr->r_ctl.rc_lt_del;
	if ((delivered == 0) ||
	    (((lost * 1000)/delivered) < bbr_lt_loss_thresh)) {
		return;
	}
	if (d_time < 1000) {
		/* Not enough time. wait */
		/* 6 is not_enough time or no-loss */
		return;
	}
	if (d_time >= (0xffffffff / USECS_IN_MSEC)) {
		/* Too long */
		bbr_reset_lt_bw_sampling(bbr, cts);
 		/* reason 3 is to reset sampling due too long of sampling */
		return;
	}
	del_time = d_time;
	bw = delivered;
	bw *= (uint64_t)USECS_IN_SECOND;
	bw /= del_time;
	bbr_lt_bw_samp_done(bbr, bw, cts, d_time);
}

/*
 * Allocate a sendmap from our zone.
 */
static struct bbr_sendmap *
bbr_alloc(struct tcp_bbr *bbr)
{
	struct bbr_sendmap *rsm;

	BBR_STAT_INC(bbr_to_alloc);
	rsm = malloc(sizeof(struct bbr_sendmap));
	if (rsm) {
		bbr->r_ctl.rc_num_maps_alloced++;
		return (rsm);
	}
	if (bbr->r_ctl.rc_free_cnt) {
		BBR_STAT_INC(bbr_to_alloc_emerg);
		rsm = TAILQ_FIRST(&bbr->r_ctl.rc_free);
		TAILQ_REMOVE(&bbr->r_ctl.rc_free, rsm, r_next);
		bbr->r_ctl.rc_free_cnt--;
		return (rsm);
	}
	BBR_STAT_INC(bbr_to_alloc_failed);
	return (NULL);
}

static struct bbr_sendmap *
bbr_alloc_full_limit(struct tcp_bbr *bbr)
{
	if ((V_tcp_map_entries_limit > 0) &&
	    (bbr->r_ctl.rc_num_maps_alloced >= V_tcp_map_entries_limit)) {
		BBR_STAT_INC(bbr_alloc_limited);
		if (!bbr->alloc_limit_reported) {
			bbr->alloc_limit_reported = 1;
			BBR_STAT_INC(bbr_alloc_limited_conns);
		}
		return (NULL);
	}
	return (bbr_alloc(bbr));
}

/* wrapper to allocate a sendmap entry, subject to a specific limit */
static struct bbr_sendmap *
bbr_alloc_limit(struct tcp_bbr *bbr, uint8_t limit_type)
{
	struct bbr_sendmap *rsm;

	if (limit_type) {
		/* currently there is only one limit type */
		if (V_tcp_map_split_limit > 0 &&
		    bbr->r_ctl.rc_num_split_allocs >= V_tcp_map_split_limit) {
			BBR_STAT_INC(bbr_split_limited);
			if (!bbr->alloc_limit_reported) {
				bbr->alloc_limit_reported = 1;
				BBR_STAT_INC(bbr_alloc_limited_conns);
			}
			return (NULL);
		}
	}

	/* allocate and mark in the limit type, if set */
	rsm = bbr_alloc(bbr);
	if (rsm != NULL && limit_type) {
		rsm->r_limit_type = limit_type;
		bbr->r_ctl.rc_num_split_allocs++;
	}
	return (rsm);
}

static void
bbr_free(struct tcp_bbr *bbr, struct bbr_sendmap *rsm)
{
	if (rsm->r_limit_type) {
		/* currently there is only one limit type */
		bbr->r_ctl.rc_num_split_allocs--;
	}
	if (rsm->r_is_smallmap)
		bbr->r_ctl.rc_num_small_maps_alloced--;
	if (bbr->r_ctl.rc_tlp_send == rsm)
		bbr->r_ctl.rc_tlp_send = NULL;
	if (bbr->r_ctl.rc_resend == rsm) {
		bbr->r_ctl.rc_resend = NULL;
	}
	if (bbr->r_ctl.rc_next == rsm)
		bbr->r_ctl.rc_next = NULL;
	if (bbr->r_ctl.rc_sacklast == rsm)
		bbr->r_ctl.rc_sacklast = NULL;
	if (bbr->r_ctl.rc_free_cnt < bbr_min_req_free) {
		memset(rsm, 0, sizeof(struct bbr_sendmap));
		TAILQ_INSERT_TAIL(&bbr->r_ctl.rc_free, rsm, r_next);
		rsm->r_limit_type = 0;
		bbr->r_ctl.rc_free_cnt++;
		return;
	}
	bbr->r_ctl.rc_num_maps_alloced--;
	free(rsm);
}

/*
 * Returns the BDP.
 */
static uint64_t
bbr_get_bw_delay_prod(uint64_t rtt, uint64_t bw) {
	/*
	 * Calculate the bytes in flight needed given the bw (in bytes per
	 * second) and the specifyed rtt in useconds. We need to put out the
	 * returned value per RTT to match that rate. Gain will normaly
	 * raise it up from there.
	 *
	 * This should not overflow as long as the bandwidth is below 1
	 * TByte per second (bw < 10**12 = 2**40) and the rtt is smaller
	 * than 1000 seconds (rtt < 10**3 * 10**6 = 10**9 = 2**30).
	 */
	uint64_t usec_per_sec;

	usec_per_sec = USECS_IN_SECOND;
	return ((rtt * bw) / usec_per_sec);
}

/*
 * Return the initial cwnd.
 */
static uint32_t
bbr_initial_cwnd(struct tcp_bbr *bbr, struct tcpcb *tp)
{
	uint32_t i_cwnd;

	if (bbr->rc_init_win) {
		i_cwnd = bbr->rc_init_win * tp->t_maxseg;
	} else if (V_tcp_initcwnd_segments)
		i_cwnd = min((V_tcp_initcwnd_segments * tp->t_maxseg),
		    max(2 * tp->t_maxseg, 14600));
	else if (V_tcp_do_rfc3390)
		i_cwnd = min(4 * tp->t_maxseg,
		    max(2 * tp->t_maxseg, 4380));
	else {
		/* Per RFC5681 Section 3.1 */
		if (tp->t_maxseg > 2190)
			i_cwnd = 2 * tp->t_maxseg;
		else if (tp->t_maxseg > 1095)
			i_cwnd = 3 * tp->t_maxseg;
		else
			i_cwnd = 4 * tp->t_maxseg;
	}
	return (i_cwnd);
}

/*
 * Given a specified gain, return the target
 * cwnd based on that gain.
 */
static uint32_t
bbr_get_raw_target_cwnd(struct tcp_bbr *bbr, uint32_t gain, uint64_t bw)
{
	uint64_t bdp, rtt;
	uint32_t cwnd;

	if ((get_filter_value_small(&bbr->r_ctl.rc_rttprop) == 0xffffffff) ||
	    (bbr_get_full_bw(bbr) == 0)) {
		/* No measurements yet */
		return (bbr_initial_cwnd(bbr, bbr->rc_tp));
	}
	/*
	 * Get bytes per RTT needed (rttProp is normally in
	 * bbr_cwndtarget_rtt_touse)
	 */
	rtt = bbr_get_rtt(bbr, bbr_cwndtarget_rtt_touse);
	/* Get the bdp from the two values */
	bdp = bbr_get_bw_delay_prod(rtt, bw);
	/* Now apply the gain */
	cwnd = (uint32_t)(((bdp * ((uint64_t)gain)) + (uint64_t)(BBR_UNIT - 1)) / ((uint64_t)BBR_UNIT));

	return (cwnd);
}

static uint32_t
bbr_get_target_cwnd(struct tcp_bbr *bbr, uint64_t bw, uint32_t gain)
{
	uint32_t cwnd, mss;

	mss = min((bbr->rc_tp->t_maxseg - bbr->rc_last_options), bbr->r_ctl.rc_pace_max_segs);
	/* Get the base cwnd with gain rounded to a mss */
	cwnd = roundup(bbr_get_raw_target_cwnd(bbr, bw, gain), mss);
	/*
	 * Add in N (2 default since we do not have a
	 * fq layer to trap packets in) quanta's per the I-D
	 * section 4.2.3.2 quanta adjust.
	 */
	cwnd += (bbr_quanta * bbr->r_ctl.rc_pace_max_segs);
	if (bbr->rc_use_google) {
		if((bbr->rc_bbr_state == BBR_STATE_PROBE_BW) &&
		   (bbr_state_val(bbr) == BBR_SUB_GAIN)) {
			/*
			 * The linux implementation adds
			 * an extra 2 x mss in gain cycle which
			 * is documented no-where except in the code.
			 * so we add more for Neal undocumented feature
			 */
			cwnd += 2 * mss;
		}
 		if ((cwnd / mss) & 0x1) {
			/* Round up for odd num mss */
			cwnd += mss;
		}
	}
	/* Are we below the min cwnd? */
	if (cwnd < get_min_cwnd(bbr))
		return (get_min_cwnd(bbr));
	return (cwnd);
}

static uint16_t
bbr_gain_adjust(struct tcp_bbr *bbr, uint16_t gain)
{
	if (gain < 1)
		gain = 1;
	return (gain);
}

static uint32_t
bbr_get_header_oh(struct tcp_bbr *bbr)
{
	int seg_oh;

	seg_oh = 0;
	if (bbr->r_ctl.rc_inc_tcp_oh) {
		/* Do we include TCP overhead? */
		seg_oh = (bbr->rc_last_options + sizeof(struct tcphdr));
	}
	if (bbr->r_ctl.rc_inc_ip_oh) {
		/* Do we include IP overhead? */
#ifdef INET6
		if (bbr->r_is_v6) {
			seg_oh += sizeof(struct ip6_hdr);
		} else
#endif
		{

#ifdef INET
			seg_oh += sizeof(struct ip);
#endif
		}
	}
#if 0
	if (bbr->r_ctl.rc_inc_enet_oh) {
		/* Do we include the ethernet overhead?  */
		seg_oh += sizeof(struct ether_header);
	}
#endif
	return(seg_oh);
}

static uint32_t
bbr_get_pacing_length(struct tcp_bbr *bbr, uint16_t gain, uint32_t useconds_time, uint64_t bw)
{
	uint64_t divor, res, tim;

	if (useconds_time == 0)
		return (0);
	gain = bbr_gain_adjust(bbr, gain);
	divor = (uint64_t)USECS_IN_SECOND * (uint64_t)BBR_UNIT;
	tim = useconds_time;
	res = (tim * bw * gain) / divor;
	if (res == 0)
		res = 1;
	return ((uint32_t)res);
}

/*
 * Given a gain and a length return the delay in useconds that
 * should be used to evenly space out packets
 * on the connection (based on the gain factor).
 */
static uint32_t
bbr_get_pacing_delay(struct tcp_bbr *bbr, uint16_t gain, int32_t len, uint32_t cts, int nolog)
{
	uint64_t bw, lentim, res;
	uint32_t usecs, srtt;
	uint32_t seg_oh, num_segs, maxseg;

	if (len == 0)
		return (0);

	maxseg = bbr->rc_tp->t_maxseg - bbr->rc_last_options;
	num_segs = (len + maxseg - 1) / maxseg;
	if (bbr->rc_use_google == 0) {
		seg_oh = bbr_get_header_oh(bbr);
		len += (num_segs * seg_oh);
	}
	gain = bbr_gain_adjust(bbr, gain);
	bw = bbr_get_bw(bbr);
	if (bbr->rc_use_google) {
		uint64_t cbw;

		/*
		 * Reduce the b/w by the google discount
		 * factor 10 = 1%.
		 */
		cbw = bw *  (uint64_t)(1000 - bbr->r_ctl.bbr_google_discount);
		cbw /= (uint64_t)1000;
		/* We don't apply a discount if it results in 0 */
		if (cbw > 0)
			bw = cbw;
	}
	lentim = ((uint64_t)len *
		  (uint64_t)USECS_IN_SECOND *
		  (uint64_t)BBR_UNIT);
	res = lentim / ((uint64_t)gain * bw);
	if (res == 0)
		res = 1;
	usecs = (uint32_t)res;
	srtt = bbr_get_rtt(bbr, BBR_SRTT);
	if (bbr_hptsi_max_mul && bbr_hptsi_max_div &&
	    (bbr->rc_use_google == 0) &&
	    (usecs > ((srtt * bbr_hptsi_max_mul) / bbr_hptsi_max_div))) {
		/*
		 * We cannot let the delay be more than 1/2 the srtt time.
		 * Otherwise we cannot pace out or send properly.
		 */
		usecs = (srtt * bbr_hptsi_max_mul) / bbr_hptsi_max_div;
		BBR_STAT_INC(bbr_hpts_min_time);
	}
	return (usecs);
}

static void
bbr_ack_received(struct tcpcb *tp, struct tcp_bbr *bbr, struct tcphdr *th, uint32_t bytes_this_ack,
		 uint32_t sack_changed, uint32_t prev_acked, int32_t line, uint32_t losses)
{
	uint64_t bw;
	uint32_t cwnd, target_cwnd, maxseg;

	if ((bbr->rc_bbr_state == BBR_STATE_PROBE_RTT) &&
	    ((bbr->r_ctl.bbr_rttprobe_gain_val == 0) || bbr->rc_use_google)) {
		/* We don't change anything in probe-rtt */
		return;
	}
	maxseg = tp->t_maxseg - bbr->rc_last_options;
	bytes_this_ack += sack_changed;
	if (bytes_this_ack > prev_acked) {
		bytes_this_ack -= prev_acked;
		/*
		 * A byte ack'd gives us a full mss
		 * to be like linux i.e. they count packets.
		 */
		if ((bytes_this_ack < maxseg) && bbr->rc_use_google)
			bytes_this_ack = maxseg;
	} else {
		/* Unlikely */
		bytes_this_ack = 0;
	}
	cwnd = tp->snd_cwnd;
	bw = get_filter_value(&bbr->r_ctl.rc_delrate);
	if (bw)
		target_cwnd = bbr_get_target_cwnd(bbr,
						  bw,
						  (uint32_t)bbr->r_ctl.rc_bbr_cwnd_gain);
	else
		target_cwnd = bbr_initial_cwnd(bbr, bbr->rc_tp);
	if (IN_RECOVERY(tp->t_flags) &&
	    (bbr->bbr_prev_in_rec == 0)) {
		/*
		 * We are entering recovery and
		 * thus packet conservation.
		 */
		bbr->pkt_conservation = 1;
		bbr->r_ctl.rc_recovery_start = bbr->r_ctl.rc_rcvtime;
		cwnd = ctf_flight_size(tp,
				       (bbr->r_ctl.rc_sacked + bbr->r_ctl.rc_lost_bytes)) +
			bytes_this_ack;
	}
	if (IN_RECOVERY(tp->t_flags)) {
		uint32_t flight;

		bbr->bbr_prev_in_rec = 1;
		if (cwnd > losses) {
			cwnd -= losses;
			if (cwnd < maxseg)
				cwnd = maxseg;
		} else
			cwnd = maxseg;
		flight = ctf_flight_size(tp,
					 (bbr->r_ctl.rc_sacked + bbr->r_ctl.rc_lost_bytes));
		if (bbr->pkt_conservation) {
			uint32_t time_in;

			if (TSTMP_GEQ(bbr->r_ctl.rc_rcvtime, bbr->r_ctl.rc_recovery_start))
				time_in = bbr->r_ctl.rc_rcvtime - bbr->r_ctl.rc_recovery_start;
			else
				time_in = 0;

			if (time_in >= bbr_get_rtt(bbr, BBR_RTT_PROP)) {
				/* Clear packet conservation after an rttProp */
				bbr->pkt_conservation = 0;
			} else {
				if ((flight + bytes_this_ack) > cwnd)
					cwnd = flight + bytes_this_ack;
				if (cwnd < get_min_cwnd(bbr))
					cwnd = get_min_cwnd(bbr);
				tp->snd_cwnd = cwnd;
				return;
			}
		}
	} else
		bbr->bbr_prev_in_rec = 0;
	if ((bbr->rc_use_google == 0) && bbr->r_ctl.restrict_growth) {
		bbr->r_ctl.restrict_growth--;
		if (bytes_this_ack > maxseg)
			bytes_this_ack = maxseg;
	}
	if (bbr->rc_filled_pipe) {
		/*
		 * Here we have exited startup and filled the pipe. We will
		 * thus allow the cwnd to shrink to the target. We hit here
		 * mostly.
		 */
		uint32_t s_cwnd;

		s_cwnd = min((cwnd + bytes_this_ack), target_cwnd);
		if (s_cwnd > cwnd)
			cwnd = s_cwnd;
		else if (bbr_cwnd_may_shrink || bbr->rc_use_google || bbr->rc_no_pacing)
			cwnd = s_cwnd;
	} else {
		/*
		 * Here we are still in startup, we increase cwnd by what
		 * has been acked.
		 */
		if ((cwnd < target_cwnd) ||
		    (bbr->rc_past_init_win == 0)) {
			cwnd += bytes_this_ack;
		} else {
			/*
			 * Method 4 means we are at target so no gain in
			 * startup and past the initial window.
			 */
		}
	}
	tp->snd_cwnd = max(cwnd, get_min_cwnd(bbr));
}

static void
tcp_bbr_partialack(struct tcpcb *tp)
{
	struct tcp_bbr *bbr;

	bbr = (struct tcp_bbr *)tp->t_fb_ptr;
	if (ctf_flight_size(tp,
		(bbr->r_ctl.rc_sacked  + bbr->r_ctl.rc_lost_bytes)) <=
	    tp->snd_cwnd) {
		bbr->r_wanted_output = 1;
	}
}

static void
bbr_post_recovery(struct tcpcb *tp)
{
	struct tcp_bbr *bbr;
	uint32_t  flight;

	bbr = (struct tcp_bbr *)tp->t_fb_ptr;
	/*
	 * Here we just exit recovery.
	 */
	EXIT_RECOVERY(tp->t_flags);
	/* Lock in our b/w reduction for the specified number of pkt-epochs */
	bbr->r_recovery_bw = 0;
	tp->snd_recover = tp->snd_una;
	tcp_bbr_tso_size_check(bbr, bbr->r_ctl.rc_rcvtime);
	bbr->pkt_conservation = 0;
	if (bbr->rc_use_google == 0) {
		/*
		 * For non-google mode lets
		 * go ahead and make sure we clear
		 * the recovery state so if we
		 * bounce back in to recovery we
		 * will do PC.
		 */
		bbr->bbr_prev_in_rec = 0;
	}
	if (bbr->rc_bbr_state != BBR_STATE_PROBE_RTT) {
		tp->snd_cwnd = max(tp->snd_cwnd, bbr->r_ctl.rc_cwnd_on_ent);
	} else {
		/* For probe-rtt case lets fix up its saved_cwnd */
		if (bbr->r_ctl.rc_saved_cwnd < bbr->r_ctl.rc_cwnd_on_ent) {
			bbr->r_ctl.rc_saved_cwnd = bbr->r_ctl.rc_cwnd_on_ent;
		}
	}
	flight = ctf_flight_size(tp,
		     (bbr->r_ctl.rc_sacked + bbr->r_ctl.rc_lost_bytes));
	if ((bbr->rc_use_google == 0) &&
	    bbr_do_red) {
		uint64_t val, lr2use;
		uint32_t maxseg, newcwnd, acks_inflight, ratio, cwnd;
		uint32_t *cwnd_p;

		if (bbr_get_rtt(bbr, BBR_SRTT)) {
			val = ((uint64_t)bbr_get_rtt(bbr, BBR_RTT_PROP) * (uint64_t)1000);
			val /= bbr_get_rtt(bbr, BBR_SRTT);
			ratio = (uint32_t)val;
		} else
			ratio = 1000;

		if ((ratio < bbr_do_red) || (bbr_do_red == 0))
			goto done;
		if (((bbr->rc_bbr_state == BBR_STATE_PROBE_RTT) &&
		     bbr_prtt_slam_cwnd) ||
		    (bbr_sub_drain_slam_cwnd &&
		     (bbr->rc_bbr_state == BBR_STATE_PROBE_BW) &&
		     bbr->rc_hit_state_1 &&
		     (bbr_state_val(bbr) == BBR_SUB_DRAIN)) ||
		    ((bbr->rc_bbr_state == BBR_STATE_DRAIN) &&
		     bbr_slam_cwnd_in_main_drain)) {
			/*
			 * Here we must poke at the saved cwnd
			 * as well as the cwnd.
			 */
			cwnd = bbr->r_ctl.rc_saved_cwnd;
			cwnd_p = &bbr->r_ctl.rc_saved_cwnd;
		} else {
 			cwnd = tp->snd_cwnd;
			cwnd_p = &tp->snd_cwnd;
		}
		maxseg = tp->t_maxseg - bbr->rc_last_options;
		/* Add the overall lr with the recovery lr */
		if (bbr->r_ctl.rc_lost == 0)
			lr2use = 0;
		else if (bbr->r_ctl.rc_delivered == 0)
			lr2use = 1000;
		else {
			lr2use = bbr->r_ctl.rc_lost * 1000;
			lr2use /= bbr->r_ctl.rc_delivered;
		}
		lr2use += bbr->r_ctl.recovery_lr;
		acks_inflight = (flight / (maxseg * 2));
		if (bbr_red_scale) {
			lr2use *= bbr_get_rtt(bbr, BBR_SRTT);
			lr2use /= bbr_red_scale;
			if ((bbr_red_growth_restrict) &&
			    ((bbr_get_rtt(bbr, BBR_SRTT)/bbr_red_scale) > 1))
			    bbr->r_ctl.restrict_growth += acks_inflight;
		}
		if (lr2use) {
			val = (uint64_t)cwnd * lr2use;
			val /= 1000;
			if (cwnd > val)
				newcwnd = roundup((cwnd - val), maxseg);
			else
				newcwnd = maxseg;
		} else {
			val = (uint64_t)cwnd * (uint64_t)bbr_red_mul;
			val /= (uint64_t)bbr_red_div;
			newcwnd = roundup((uint32_t)val, maxseg);
		}
		/* with standard delayed acks how many acks can I expect? */
		if (bbr_drop_limit == 0) {
			/*
			 * Anticpate how much we will
			 * raise the cwnd based on the acks.
			 */
			if ((newcwnd + (acks_inflight * maxseg)) < get_min_cwnd(bbr)) {
				/* We do enforce the min (with the acks) */
				newcwnd = (get_min_cwnd(bbr) - acks_inflight);
			}
		} else {
			/*
			 * A strict drop limit of N is is inplace
			 */
			if (newcwnd < (bbr_drop_limit * maxseg)) {
				newcwnd = bbr_drop_limit * maxseg;
			}
		}
		/* For the next N acks do we restrict the growth */
		*cwnd_p = newcwnd;
		if (tp->snd_cwnd > newcwnd)
			tp->snd_cwnd = newcwnd;
		bbr->r_ctl.rc_red_cwnd_pe = bbr->r_ctl.rc_pkt_epoch;
	}
done:
	bbr->r_ctl.recovery_lr = 0;
	if (flight <= tp->snd_cwnd) {
		bbr->r_wanted_output = 1;
	}
	tcp_bbr_tso_size_check(bbr, bbr->r_ctl.rc_rcvtime);
}

static void
bbr_setup_red_bw(struct tcp_bbr *bbr, uint32_t cts)
{
	bbr->r_ctl.red_bw = get_filter_value(&bbr->r_ctl.rc_delrate);
	/* Limit the drop in b/w to 1/2 our current filter. */
	if (bbr->r_ctl.red_bw > bbr->r_ctl.rc_bbr_cur_del_rate)
		bbr->r_ctl.red_bw = bbr->r_ctl.rc_bbr_cur_del_rate;
	if (bbr->r_ctl.red_bw < (get_filter_value(&bbr->r_ctl.rc_delrate) / 2))
		bbr->r_ctl.red_bw = get_filter_value(&bbr->r_ctl.rc_delrate) / 2;
	tcp_bbr_tso_size_check(bbr, cts);
}

static void
bbr_cong_signal(struct tcpcb *tp, struct tcphdr *th, uint32_t type, struct bbr_sendmap *rsm)
{
	struct tcp_bbr *bbr;

	bbr = (struct tcp_bbr *)tp->t_fb_ptr;
	switch (type) {
	case CC_NDUPACK:
		if (!IN_RECOVERY(tp->t_flags)) {
			tp->snd_recover = tp->snd_max;
			/* Start a new epoch */
			bbr_set_pktepoch(bbr, bbr->r_ctl.rc_rcvtime, __LINE__);
			if (bbr->rc_lt_is_sampling || bbr->rc_lt_use_bw) {
				/*
				 * Move forward the lt epoch
				 * so it won't count the truncated
				 * epoch.
				 */
				bbr->r_ctl.rc_lt_epoch++;
			}
			if (bbr->rc_bbr_state == BBR_STATE_STARTUP) {
				/*
				 * Just like the policer detection code
				 * if we are in startup we must push
				 * forward the last startup epoch
				 * to hide the truncated PE.
				 */
				bbr->r_ctl.rc_bbr_last_startup_epoch++;
			}
			bbr->r_ctl.rc_cwnd_on_ent = tp->snd_cwnd;
			ENTER_RECOVERY(tp->t_flags);
			bbr->rc_tlp_rtx_out = 0;
			bbr->r_ctl.recovery_lr = bbr->r_ctl.rc_pkt_epoch_loss_rate;
			tcp_bbr_tso_size_check(bbr, bbr->r_ctl.rc_rcvtime);
#if 0
			if (bbr->rc_inp->inp_in_hpts &&
			    ((bbr->r_ctl.rc_hpts_flags & PACE_TMR_RACK) == 0)) {
				/*
				 * When we enter recovery, we need to restart
				 * any timers. This may mean we gain an agg
				 * early, which will be made up for at the last
				 * rxt out.
				 */
				bbr->rc_timer_first = 1;
				bbr_timer_cancel(bbr, __LINE__, bbr->r_ctl.rc_rcvtime);
			}
#endif
			/*
			 * Calculate a new cwnd based on to the current
			 * delivery rate with no gain. We get the bdp
			 * without gaining it up like we normally would and
			 * we use the last cur_del_rate.
			 */
			if ((bbr->rc_use_google == 0) &&
			    (bbr->r_ctl.bbr_rttprobe_gain_val ||
			     (bbr->rc_bbr_state != BBR_STATE_PROBE_RTT))) {
				tp->snd_cwnd = ctf_flight_size(tp,
					           (bbr->r_ctl.rc_sacked + bbr->r_ctl.rc_lost_bytes)) +
					(tp->t_maxseg - bbr->rc_last_options);
				if (tp->snd_cwnd < get_min_cwnd(bbr)) {
					/* We always gate to min cwnd */
					tp->snd_cwnd = get_min_cwnd(bbr);
				}
			}
		}
		break;
	case CC_RTO_ERR:
		KMOD_TCPSTAT_INC(tcps_sndrexmitbad);
		/* RTO was unnecessary, so reset everything. */
		bbr_reset_lt_bw_sampling(bbr, bbr->r_ctl.rc_rcvtime);
		if (bbr->rc_bbr_state != BBR_STATE_PROBE_RTT) {
			tp->snd_cwnd = tp->snd_cwnd_prev;
			tp->snd_ssthresh = tp->snd_ssthresh_prev;
			tp->snd_recover = tp->snd_recover_prev;
			tp->snd_cwnd = max(tp->snd_cwnd, bbr->r_ctl.rc_cwnd_on_ent);
		}
		tp->t_badrxtwin = 0;
		break;
	}
}

/*
 * Indicate whether this ack should be delayed.  We can delay the ack if
 * following conditions are met:
 *	- There is no delayed ack timer in progress.
 *	- Our last ack wasn't a 0-sized window. We never want to delay
 *	  the ack that opens up a 0-sized window.
 *	- LRO wasn't used for this segment. We make sure by checking that the
 *	  segment size is not larger than the MSS.
 *	- Delayed acks are enabled or this is a half-synchronized T/TCP
 *	  connection.
 *	- The data being acked is less than a full segment (a stretch ack
 *        of more than a segment we should ack.
 *      - nsegs is 1 (if its more than that we received more than 1 ack).
 */
#define DELAY_ACK(tp, bbr, nsegs)				\
	(((tp->t_flags & TF_RXWIN0SENT) == 0) &&		\
	 ((tp->t_flags & TF_DELACK) == 0) && 		 	\
	 ((bbr->bbr_segs_rcvd + nsegs) < tp->t_delayed_ack) &&	\
	 (tp->t_delayed_ack || (tp->t_flags & TF_NEEDSYN)))

/*
 * Return the lowest RSM in the map of
 * packets still in flight that is not acked.
 * This should normally find on the first one
 * since we remove packets from the send
 * map after they are marked ACKED.
 */
static struct bbr_sendmap *
bbr_find_lowest_rsm(struct tcp_bbr *bbr)
{
	struct bbr_sendmap *rsm;

	/*
	 * Walk the time-order transmitted list looking for an rsm that is
	 * not acked. This will be the one that was sent the longest time
	 * ago that is still outstanding.
	 */
	TAILQ_FOREACH(rsm, &bbr->r_ctl.rc_tmap, r_tnext) {
		if (rsm->r_flags & BBR_ACKED) {
			continue;
		}
		goto finish;
	}
finish:
	return (rsm);
}

static struct bbr_sendmap *
bbr_find_high_nonack(struct tcp_bbr *bbr, struct bbr_sendmap *rsm)
{
	struct bbr_sendmap *prsm;

	/*
	 * Walk the sequence order list backward until we hit and arrive at
	 * the highest seq not acked. In theory when this is called it
	 * should be the last segment (which it was not).
	 */
	prsm = rsm;
	TAILQ_FOREACH_REVERSE_FROM(prsm, &bbr->r_ctl.rc_map, bbr_head, r_next) {
		if (prsm->r_flags & (BBR_ACKED | BBR_HAS_FIN)) {
			continue;
		}
		return (prsm);
	}
	return (NULL);
}

/*
 * Returns to the caller the number of microseconds that
 * the packet can be outstanding before we think we
 * should have had an ack returned.
 */
static uint32_t
bbr_calc_thresh_rack(struct tcp_bbr *bbr, uint32_t srtt, uint32_t cts, struct bbr_sendmap *rsm)
{
	/*
	 * lro is the flag we use to determine if we have seen reordering.
	 * If it gets set we have seen reordering. The reorder logic either
	 * works in one of two ways:
	 *
	 * If reorder-fade is configured, then we track the last time we saw
	 * re-ordering occur. If we reach the point where enough time as
	 * passed we no longer consider reordering has occuring.
	 *
	 * Or if reorder-face is 0, then once we see reordering we consider
	 * the connection to alway be subject to reordering and just set lro
	 * to 1.
	 *
	 * In the end if lro is non-zero we add the extra time for
	 * reordering in.
	 */
	int32_t lro;
	uint32_t thresh, t_rxtcur;

	if (srtt == 0)
		srtt = 1;
	if (bbr->r_ctl.rc_reorder_ts) {
		if (bbr->r_ctl.rc_reorder_fade) {
			if (SEQ_GEQ(cts, bbr->r_ctl.rc_reorder_ts)) {
				lro = cts - bbr->r_ctl.rc_reorder_ts;
				if (lro == 0) {
					/*
					 * No time as passed since the last
					 * reorder, mark it as reordering.
					 */
					lro = 1;
				}
			} else {
				/* Negative time? */
				lro = 0;
			}
			if (lro > bbr->r_ctl.rc_reorder_fade) {
				/* Turn off reordering seen too */
				bbr->r_ctl.rc_reorder_ts = 0;
				lro = 0;
			}
		} else {
			/* Reodering does not fade */
			lro = 1;
		}
	} else {
		lro = 0;
	}
	thresh = srtt + bbr->r_ctl.rc_pkt_delay;
	if (lro) {
		/* It must be set, if not you get 1/4 rtt */
		if (bbr->r_ctl.rc_reorder_shift)
			thresh += (srtt >> bbr->r_ctl.rc_reorder_shift);
		else
			thresh += (srtt >> 2);
	} else {
		thresh += 1000;
	}
	/* We don't let the rack timeout be above a RTO */
	if ((bbr->rc_tp)->t_srtt == 0)
		t_rxtcur = BBR_INITIAL_RTO;
	else
		t_rxtcur = TICKS_2_USEC(bbr->rc_tp->t_rxtcur);
	if (thresh > t_rxtcur) {
		thresh = t_rxtcur;
	}
	/* And we don't want it above the RTO max either */
	if (thresh > (((uint32_t)bbr->rc_max_rto_sec) * USECS_IN_SECOND)) {
		thresh = (((uint32_t)bbr->rc_max_rto_sec) * USECS_IN_SECOND);
	}
	return (thresh);
}

/*
 * Return to the caller the amount of time in mico-seconds
 * that should be used for the TLP timer from the last
 * send time of this packet.
 */
static uint32_t
bbr_calc_thresh_tlp(struct tcpcb *tp, struct tcp_bbr *bbr,
    struct bbr_sendmap *rsm, uint32_t srtt,
    uint32_t cts)
{
	uint32_t thresh, len, maxseg, t_rxtcur;
	struct bbr_sendmap *prsm;

	if (srtt == 0)
		srtt = 1;
	if (bbr->rc_tlp_threshold)
		thresh = srtt + (srtt / bbr->rc_tlp_threshold);
	else
		thresh = (srtt * 2);
	maxseg = tp->t_maxseg - bbr->rc_last_options;
	/* Get the previous sent packet, if any  */
	len = rsm->r_end - rsm->r_start;

	/* 2.1 behavior */
	prsm = TAILQ_PREV(rsm, bbr_head, r_tnext);
	if (prsm && (len <= maxseg)) {
		/*
		 * Two packets outstanding, thresh should be (2*srtt) +
		 * possible inter-packet delay (if any).
		 */
		uint32_t inter_gap = 0;
		int idx, nidx;

		idx = rsm->r_rtr_cnt - 1;
		nidx = prsm->r_rtr_cnt - 1;
		if (TSTMP_GEQ(rsm->r_tim_lastsent[nidx], prsm->r_tim_lastsent[idx])) {
			/* Yes it was sent later (or at the same time) */
			inter_gap = rsm->r_tim_lastsent[idx] - prsm->r_tim_lastsent[nidx];
		}
		thresh += inter_gap;
	} else if (len <= maxseg) {
		/*
		 * Possibly compensate for delayed-ack.
		 */
		uint32_t alt_thresh;

		alt_thresh = srtt + (srtt / 2) + bbr_delayed_ack_time;
		if (alt_thresh > thresh)
			thresh = alt_thresh;
	}
	/* Not above the current  RTO */
	if (tp->t_srtt == 0)
		t_rxtcur = BBR_INITIAL_RTO;
	else
		t_rxtcur = TICKS_2_USEC(tp->t_rxtcur);

	/* Not above an RTO */
	if (thresh > t_rxtcur) {
		thresh = t_rxtcur;
	}
	/* Not above a RTO max */
	if (thresh > (((uint32_t)bbr->rc_max_rto_sec) * USECS_IN_SECOND)) {
		thresh = (((uint32_t)bbr->rc_max_rto_sec) * USECS_IN_SECOND);
	}
	/* And now apply the user TLP min */
	if (thresh < bbr_tlp_min) {
		thresh = bbr_tlp_min;
	}
	return (thresh);
}

/*
 * Return one of three RTTs to use (in microseconds).
 */
static __inline uint32_t
bbr_get_rtt(struct tcp_bbr *bbr, int32_t rtt_type)
{
	uint32_t f_rtt;
	uint32_t srtt;

	f_rtt = get_filter_value_small(&bbr->r_ctl.rc_rttprop);
	if (get_filter_value_small(&bbr->r_ctl.rc_rttprop) == 0xffffffff) {
		/* We have no rtt at all */
		if (bbr->rc_tp->t_srtt == 0)
			f_rtt = BBR_INITIAL_RTO;
		else
			f_rtt = (TICKS_2_USEC(bbr->rc_tp->t_srtt) >> TCP_RTT_SHIFT);
		/*
		 * Since we don't know how good the rtt is apply a
		 * delayed-ack min
		 */
		if (f_rtt < bbr_delayed_ack_time) {
			f_rtt = bbr_delayed_ack_time;
		}
	}
	/* Take the filter version or last measured pkt-rtt */
	if (rtt_type == BBR_RTT_PROP) {
		srtt = f_rtt;
	} else if (rtt_type == BBR_RTT_PKTRTT) {
		if (bbr->r_ctl.rc_pkt_epoch_rtt) {
			srtt = bbr->r_ctl.rc_pkt_epoch_rtt;
		} else {
			/* No pkt rtt yet */
			srtt = f_rtt;
		}
	} else if (rtt_type == BBR_RTT_RACK) {
		srtt = bbr->r_ctl.rc_last_rtt;
		/* We need to add in any internal delay for our timer */
		if (bbr->rc_ack_was_delayed)
			srtt += bbr->r_ctl.rc_ack_hdwr_delay;
	} else if (rtt_type == BBR_SRTT) {
		srtt = (TICKS_2_USEC(bbr->rc_tp->t_srtt) >> TCP_RTT_SHIFT);
	} else {
		/* TSNH */
		srtt = f_rtt;
	}
	return (srtt);
}

static int
bbr_is_lost(struct tcp_bbr *bbr, struct bbr_sendmap *rsm, uint32_t cts)
{
	uint32_t thresh;

	thresh = bbr_calc_thresh_rack(bbr, bbr_get_rtt(bbr, BBR_RTT_RACK),
				      cts, rsm);
	if ((cts - rsm->r_tim_lastsent[(rsm->r_rtr_cnt - 1)]) >= thresh) {
		/* It is lost (past time) */
		return (1);
	}
	return (0);
}

/*
 * Return a sendmap if we need to retransmit something.
 */
static struct bbr_sendmap *
bbr_check_recovery_mode(struct tcpcb *tp, struct tcp_bbr *bbr, uint32_t cts)
{
	/*
	 * Check to see that we don't need to fall into recovery. We will
	 * need to do so if our oldest transmit is past the time we should
	 * have had an ack.
	 */

	struct bbr_sendmap *rsm;
	int32_t idx;

	if (TAILQ_EMPTY(&bbr->r_ctl.rc_map)) {
		/* Nothing outstanding that we know of */
		return (NULL);
	}
	rsm = TAILQ_FIRST(&bbr->r_ctl.rc_tmap);
	if (rsm == NULL) {
		/* Nothing in the transmit map */
		return (NULL);
	}
	if (tp->t_flags & TF_SENTFIN) {
		/* Fin restricted, don't find anything once a fin is sent */
		return (NULL);
	}
	if (rsm->r_flags & BBR_ACKED) {
		/*
		 * Ok the first one is acked (this really should not happen
		 * since we remove the from the tmap once they are acked)
		 */
		rsm = bbr_find_lowest_rsm(bbr);
		if (rsm == NULL)
			return (NULL);
	}
	idx = rsm->r_rtr_cnt - 1;
	if (SEQ_LEQ(cts, rsm->r_tim_lastsent[idx])) {
		/* Send timestamp is the same or less? can't be ready */
		return (NULL);
	}
	/* Get our RTT time */
	if (bbr_is_lost(bbr, rsm, cts) &&
	    ((rsm->r_dupack >= DUP_ACK_THRESHOLD) ||
	     (rsm->r_flags & BBR_SACK_PASSED))) {
		if ((rsm->r_flags & BBR_MARKED_LOST) == 0) {
			rsm->r_flags |= BBR_MARKED_LOST;
			bbr->r_ctl.rc_lost += rsm->r_end - rsm->r_start;
			bbr->r_ctl.rc_lost_bytes += rsm->r_end - rsm->r_start;
		}
		bbr_cong_signal(tp, NULL, CC_NDUPACK, rsm);
		return (rsm);
	}
	return (NULL);
}

/*
 * RACK Timer, here we simply do logging and house keeping.
 * the normal bbr_output_wtime() function will call the
 * appropriate thing to check if we need to do a RACK retransmit.
 * We return 1, saying don't proceed with bbr_output_wtime only
 * when all timers have been stopped (destroyed PCB?).
 */
static int
bbr_timeout_rack(struct tcpcb *tp, struct tcp_bbr *bbr, uint32_t cts)
{
	/*
	 * This timer simply provides an internal trigger to send out data.
	 * The check_recovery_mode call will see if there are needed
	 * retransmissions, if so we will enter fast-recovery. The output
	 * call may or may not do the same thing depending on sysctl
	 * settings.
	 */
	uint32_t lost;

	if (bbr->rc_all_timers_stopped) {
		return (1);
	}
	if (TSTMP_LT(cts, bbr->r_ctl.rc_timer_exp)) {
		/* Its not time yet */
		return (0);
	}
	BBR_STAT_INC(bbr_to_tot);
	lost = bbr->r_ctl.rc_lost;
	if (bbr->r_state && (bbr->r_state != tp->t_state))
		bbr_set_state(tp, bbr, 0);
	if (bbr->r_ctl.rc_resend == NULL) {
		/* Lets do the check here */
		bbr->r_ctl.rc_resend = bbr_check_recovery_mode(tp, bbr, cts);
	}
	if (bbr_policer_call_from_rack_to)
		bbr_lt_bw_sampling(bbr, cts, (bbr->r_ctl.rc_lost > lost));
	bbr->r_ctl.rc_hpts_flags &= ~PACE_TMR_RACK;
	return (0);
}

static __inline void
bbr_clone_rsm(struct tcp_bbr *bbr, struct bbr_sendmap *nrsm, struct bbr_sendmap *rsm, uint32_t start)
{
	int idx;

	nrsm->r_start = start;
	nrsm->r_end = rsm->r_end;
	nrsm->r_rtr_cnt = rsm->r_rtr_cnt;
	nrsm-> r_rtt_not_allowed = rsm->r_rtt_not_allowed;
	nrsm->r_flags = rsm->r_flags;
	/* We don't transfer forward the SYN flag */
	nrsm->r_flags &= ~BBR_HAS_SYN;
	/* We move forward the FIN flag, not that this should happen */
	rsm->r_flags &= ~BBR_HAS_FIN;
	nrsm->r_dupack = rsm->r_dupack;
	nrsm->r_rtr_bytes = 0;
	nrsm->r_is_gain = rsm->r_is_gain;
	nrsm->r_is_drain = rsm->r_is_drain;
	nrsm->r_delivered = rsm->r_delivered;
	nrsm->r_ts_valid = rsm->r_ts_valid;
	nrsm->r_del_ack_ts = rsm->r_del_ack_ts;
	nrsm->r_del_time = rsm->r_del_time;
	nrsm->r_app_limited = rsm->r_app_limited;
	nrsm->r_first_sent_time = rsm->r_first_sent_time;
	nrsm->r_flight_at_send = rsm->r_flight_at_send;
	/* We split a piece the lower section looses any just_ret flag. */
	nrsm->r_bbr_state = rsm->r_bbr_state;
	for (idx = 0; idx < nrsm->r_rtr_cnt; idx++) {
		nrsm->r_tim_lastsent[idx] = rsm->r_tim_lastsent[idx];
	}
	rsm->r_end = nrsm->r_start;
	idx = min((bbr->rc_tp->t_maxseg - bbr->rc_last_options), bbr->r_ctl.rc_pace_max_segs);
	idx /= 8;
	/* Check if we got too small */
	if ((rsm->r_is_smallmap == 0) &&
	    ((rsm->r_end - rsm->r_start) <= idx)) {
		bbr->r_ctl.rc_num_small_maps_alloced++;
		rsm->r_is_smallmap = 1;
	}
	/* Check the new one as well */
	if ((nrsm->r_end - nrsm->r_start) <= idx) {
		bbr->r_ctl.rc_num_small_maps_alloced++;
		nrsm->r_is_smallmap = 1;
	}
}

static int
bbr_sack_mergable(struct bbr_sendmap *at,
		  uint32_t start, uint32_t end)
{
	/*
	 * Given a sack block defined by
	 * start and end, and a current postion
	 * at. Return 1 if either side of at
	 * would show that the block is mergable
	 * to that side. A block to be mergable
	 * must have overlap with the start/end
	 * and be in the SACK'd state.
	 */
	struct bbr_sendmap *l_rsm;
	struct bbr_sendmap *r_rsm;

	/* first get the either side blocks */
	l_rsm = TAILQ_PREV(at, bbr_head, r_next);
	r_rsm = TAILQ_NEXT(at, r_next);
	if (l_rsm && (l_rsm->r_flags & BBR_ACKED)) {
		/* Potentially mergeable */
		if ((l_rsm->r_end == start) ||
		    (SEQ_LT(start, l_rsm->r_end) &&
		     SEQ_GT(end, l_rsm->r_end))) {
			    /*
			     * map blk   |------|
			     * sack blk         |------|
			     * <or>
			     * map blk   |------|
			     * sack blk      |------|
			     */
			    return (1);
		    }
	}
	if (r_rsm && (r_rsm->r_flags & BBR_ACKED)) {
		/* Potentially mergeable */
		if ((r_rsm->r_start == end) ||
		    (SEQ_LT(start, r_rsm->r_start) &&
		     SEQ_GT(end, r_rsm->r_start))) {
			/*
			 * map blk          |---------|
			 * sack blk    |----|
			 * <or>
			 * map blk          |---------|
			 * sack blk    |-------|
			 */
			return (1);
		}
	}
	return (0);
}

static struct bbr_sendmap *
bbr_merge_rsm(struct tcp_bbr *bbr,
	      struct bbr_sendmap *l_rsm,
	      struct bbr_sendmap *r_rsm)
{
	/*
	 * We are merging two ack'd RSM's,
	 * the l_rsm is on the left (lower seq
	 * values) and the r_rsm is on the right
	 * (higher seq value). The simplest way
	 * to merge these is to move the right
	 * one into the left. I don't think there
	 * is any reason we need to try to find
	 * the oldest (or last oldest retransmitted).
	 */
	l_rsm->r_end = r_rsm->r_end;
	if (l_rsm->r_dupack < r_rsm->r_dupack)
		l_rsm->r_dupack = r_rsm->r_dupack;
	if (r_rsm->r_rtr_bytes)
		l_rsm->r_rtr_bytes += r_rsm->r_rtr_bytes;
	if (r_rsm->r_in_tmap) {
		/* This really should not happen */
		TAILQ_REMOVE(&bbr->r_ctl.rc_tmap, r_rsm, r_tnext);
	}
	if (r_rsm->r_app_limited)
		l_rsm->r_app_limited = r_rsm->r_app_limited;
	/* Now the flags */
	if (r_rsm->r_flags & BBR_HAS_FIN)
		l_rsm->r_flags |= BBR_HAS_FIN;
	if (r_rsm->r_flags & BBR_TLP)
		l_rsm->r_flags |= BBR_TLP;
	if (r_rsm->r_flags & BBR_RWND_COLLAPSED)
		l_rsm->r_flags |= BBR_RWND_COLLAPSED;
	if (r_rsm->r_flags & BBR_MARKED_LOST) {
		/* This really should not happen */
		bbr->r_ctl.rc_lost_bytes -= r_rsm->r_end - r_rsm->r_start;
	}
	TAILQ_REMOVE(&bbr->r_ctl.rc_map, r_rsm, r_next);
	if ((r_rsm->r_limit_type == 0) && (l_rsm->r_limit_type != 0)) {
		/* Transfer the split limit to the map we free */
		r_rsm->r_limit_type = l_rsm->r_limit_type;
		l_rsm->r_limit_type = 0;
	}
	bbr_free(bbr, r_rsm);
	return(l_rsm);
}

/*
 * TLP Timer, here we simply setup what segment we want to
 * have the TLP expire on, the normal bbr_output_wtime() will then
 * send it out.
 *
 * We return 1, saying don't proceed with bbr_output_wtime only
 * when all timers have been stopped (destroyed PCB?).
 */
static int
bbr_timeout_tlp(struct tcpcb *tp, struct tcp_bbr *bbr, uint32_t cts)
{
	/*
	 * Tail Loss Probe.
	 */
	struct bbr_sendmap *rsm = NULL;
	struct socket *so;
	uint32_t amm;
	uint32_t out, avail;
	uint32_t maxseg;
	int collapsed_win = 0;

	if (bbr->rc_all_timers_stopped) {
		return (1);
	}
	if (TSTMP_LT(cts, bbr->r_ctl.rc_timer_exp)) {
		/* Its not time yet */
		return (0);
	}
	if (ctf_progress_timeout_check(tp, true)) {
		tcp_set_inp_to_drop(bbr->rc_inp, ETIMEDOUT);
		return (1);
	}
	/* Did we somehow get into persists? */
	if (bbr->rc_in_persist) {
		return (0);
	}
	if (bbr->r_state && (bbr->r_state != tp->t_state))
		bbr_set_state(tp, bbr, 0);
	BBR_STAT_INC(bbr_tlp_tot);
	maxseg = tp->t_maxseg - bbr->rc_last_options;
	/*
	 * A TLP timer has expired. We have been idle for 2 rtts. So we now
	 * need to figure out how to force a full MSS segment out.
	 */
	so = tcp_getsocket(tp);
	avail = sbavail(&so->so_snd);
	out = ctf_outstanding(tp);
	if (out > tp->snd_wnd) {
		/* special case, we need a retransmission */
		collapsed_win = 1;
		goto need_retran;
	}
	if (avail > out) {
		/* New data is available */
		amm = avail - out;
		if (amm > maxseg) {
			amm = maxseg;
		} else if ((amm < maxseg) && ((tp->t_flags & TF_NODELAY) == 0)) {
			/* not enough to fill a MTU and no-delay is off */
			goto need_retran;
		}
		/* Set the send-new override */
		if ((out + amm) <= tp->snd_wnd) {
			bbr->rc_tlp_new_data = 1;
		} else {
			goto need_retran;
		}
		bbr->r_ctl.rc_tlp_seg_send_cnt = 0;
		bbr->r_ctl.rc_last_tlp_seq = tp->snd_max;
		bbr->r_ctl.rc_tlp_send = NULL;
		/* cap any slots */
		BBR_STAT_INC(bbr_tlp_newdata);
		goto send;
	}
need_retran:
	/*
	 * Ok we need to arrange the last un-acked segment to be re-sent, or
	 * optionally the first un-acked segment.
	 */
	if (collapsed_win == 0) {
		rsm = TAILQ_LAST_FAST(&bbr->r_ctl.rc_map, bbr_sendmap, r_next);
		if (rsm && (BBR_ACKED | BBR_HAS_FIN)) {
			rsm = bbr_find_high_nonack(bbr, rsm);
		}
		if (rsm == NULL) {
			goto restore;
		}
	} else {
		/*
		 * We must find the last segment
		 * that was acceptable by the client.
		 */
		TAILQ_FOREACH_REVERSE(rsm, &bbr->r_ctl.rc_map, bbr_head, r_next) {
			if ((rsm->r_flags & BBR_RWND_COLLAPSED) == 0) {
				/* Found one */
				break;
			}
		}
		if (rsm == NULL) {
			/* None? if so send the first */
			rsm = TAILQ_FIRST(&bbr->r_ctl.rc_map);
			if (rsm == NULL)
				goto restore;
		}
	}
	if ((rsm->r_end - rsm->r_start) > maxseg) {
		/*
		 * We need to split this the last segment in two.
		 */
		struct bbr_sendmap *nrsm;

		nrsm = bbr_alloc_full_limit(bbr);
		if (nrsm == NULL) {
			/*
			 * We can't get memory to split, we can either just
			 * not split it. Or retransmit the whole piece, lets
			 * do the large send (BTLP :-) ).
			 */
			goto go_for_it;
		}
		bbr_clone_rsm(bbr, nrsm, rsm, (rsm->r_end - maxseg));
		TAILQ_INSERT_AFTER(&bbr->r_ctl.rc_map, rsm, nrsm, r_next);
		if (rsm->r_in_tmap) {
			TAILQ_INSERT_AFTER(&bbr->r_ctl.rc_tmap, rsm, nrsm, r_tnext);
			nrsm->r_in_tmap = 1;
		}
		rsm->r_flags &= (~BBR_HAS_FIN);
		rsm = nrsm;
	}
go_for_it:
	bbr->r_ctl.rc_tlp_send = rsm;
	bbr->rc_tlp_rtx_out = 1;
	if (rsm->r_start == bbr->r_ctl.rc_last_tlp_seq) {
		bbr->r_ctl.rc_tlp_seg_send_cnt++;
		tp->t_rxtshift++;
	} else {
		bbr->r_ctl.rc_last_tlp_seq = rsm->r_start;
		bbr->r_ctl.rc_tlp_seg_send_cnt = 1;
	}
send:
	if (bbr->r_ctl.rc_tlp_seg_send_cnt > bbr_tlp_max_resend) {
		/*
		 * Can't [re]/transmit a segment we have retranmitted the
		 * max times. We need the retransmit timer to take over.
		 */
restore:
		bbr->rc_tlp_new_data = 0;
		bbr->r_ctl.rc_tlp_send = NULL;
		if (rsm)
			rsm->r_flags &= ~BBR_TLP;
		BBR_STAT_INC(bbr_tlp_retran_fail);
		return (0);
	} else if (rsm) {
		rsm->r_flags |= BBR_TLP;
	}
	if (rsm && (rsm->r_start == bbr->r_ctl.rc_last_tlp_seq) &&
	    (bbr->r_ctl.rc_tlp_seg_send_cnt > bbr_tlp_max_resend)) {
		/*
		 * We have retransmitted to many times for TLP. Switch to
		 * the regular RTO timer
		 */
		goto restore;
	}
	bbr->r_ctl.rc_hpts_flags &= ~PACE_TMR_TLP;
	return (0);
}

/*
 * Delayed ack Timer, here we simply need to setup the
 * ACK_NOW flag and remove the DELACK flag. From there
 * the output routine will send the ack out.
 *
 * We only return 1, saying don't proceed, if all timers
 * are stopped (destroyed PCB?).
 */
static int
bbr_timeout_delack(struct tcpcb *tp, struct tcp_bbr *bbr, uint32_t cts)
{
	if (bbr->rc_all_timers_stopped) {
		return (1);
	}
	tp->t_flags &= ~TF_DELACK;
	tp->t_flags |= TF_ACKNOW;
	KMOD_TCPSTAT_INC(tcps_delack);
	bbr->r_ctl.rc_hpts_flags &= ~PACE_TMR_DELACK;
	return (0);
}

/*
 * Here we send a KEEP-ALIVE like probe to the
 * peer, we do not send data.
 *
 * We only return 1, saying don't proceed, if all timers
 * are stopped (destroyed PCB?).
 */
static int
bbr_timeout_persist(struct tcpcb *tp, struct tcp_bbr *bbr, uint32_t cts)
{
#if 0
	struct tcptemp *t_template;
#endif
	int32_t retval = 1;

	if (bbr->rc_all_timers_stopped) {
		return (1);
	}
	if (bbr->rc_in_persist == 0)
		return (0);
	KASSERT(tp->t_inpcb != NULL,
	    ("%s: tp %p tp->t_inpcb == NULL", __func__, tp));
	/*
	 * Persistence timer into zero window. Force a byte to be output, if
	 * possible.
	 */
	bbr->r_ctl.rc_hpts_flags &= ~PACE_TMR_PERSIT;
	KMOD_TCPSTAT_INC(tcps_persisttimeo);
	/*
	 * Have we exceeded the user specified progress time?
	 */
	if (ctf_progress_timeout_check(tp, true)) {
		tcp_set_inp_to_drop(bbr->rc_inp, ETIMEDOUT);
		goto out;
	}
	/*
	 * Hack: if the peer is dead/unreachable, we do not time out if the
	 * window is closed.  After a full backoff, drop the connection if
	 * the idle time (no responses to probes) reaches the maximum
	 * backoff that we would use if retransmitting.
	 */
	if (tp->t_rxtshift == TCP_MAXRXTSHIFT &&
	    (ticks - tp->t_rcvtime >= tcp_maxpersistidle ||
	    ticks - tp->t_rcvtime >= TCP_REXMTVAL(tp) * tcp_totbackoff)) {
		KMOD_TCPSTAT_INC(tcps_persistdrop);
		tcp_log_end_status(tp, TCP_EI_STATUS_PERSIST_MAX);
		tcp_set_inp_to_drop(bbr->rc_inp, ETIMEDOUT);
		goto out;
	}
	if ((sbavail(&tcp_getsocket(tp)->so_snd) == 0) &&
	    tp->snd_una == tp->snd_max) {
		bbr_exit_persist(tp, bbr, cts, __LINE__);
		retval = 0;
		goto out;
	}
	/*
	 * If the user has closed the socket then drop a persisting
	 * connection after a much reduced timeout.
	 */
	if (tp->t_state > TCPS_CLOSE_WAIT &&
	    (ticks - tp->t_rcvtime) >= TCPTV_PERSMAX) {
		KMOD_TCPSTAT_INC(tcps_persistdrop);
		tcp_log_end_status(tp, TCP_EI_STATUS_PERSIST_MAX);
		tcp_set_inp_to_drop(bbr->rc_inp, ETIMEDOUT);
		goto out;
	}
#if 0
	t_template = tcpip_maketemplate(bbr->rc_inp);
	if (t_template) {
		tcp_respond(tp, t_template->tt_ipgen,
			    &t_template->tt_t, (struct mbuf *)NULL,
			    tp->rcv_nxt, tp->snd_una - 1, 0);
		/* This sends an ack */
		if (tp->t_flags & TF_DELACK)
			tp->t_flags &= ~TF_DELACK;
		free(t_template, M_TEMP);
	}
#else
        tcp_respond(tp, NULL, (struct tcphdr *)NULL, (struct mbuf *)NULL,
                tp->rcv_nxt, tp->snd_una - 1, 0);
#endif
	if (tp->t_rxtshift < TCP_MAXRXTSHIFT)
		tp->t_rxtshift++;
	bbr_start_hpts_timer(bbr, tp, cts, 3, 0, 0);
out:
	return (retval);
}

/*
 * If a keepalive goes off, we had no other timers
 * happening. We always return 1 here since this
 * routine either drops the connection or sends
 * out a segment with respond.
 */
static int
bbr_timeout_keepalive(struct tcpcb *tp, struct tcp_bbr *bbr, uint32_t cts)
{
#if 0
	struct tcptemp *t_template;
	struct inpcb *inp;
#endif

	if (bbr->rc_all_timers_stopped) {
		return (1);
	}
	bbr->r_ctl.rc_hpts_flags &= ~PACE_TMR_KEEP;
#if 0
	inp = tp->t_inpcb;
#endif
	/*
	 * Keep-alive timer went off; send something or drop connection if
	 * idle for too long.
	 */
	KMOD_TCPSTAT_INC(tcps_keeptimeo);
	if (tp->t_state < TCPS_ESTABLISHED)
		goto dropit;
	if ((V_tcp_always_keepalive || tcp_getsocket(tp)->so_options & SO_KEEPALIVE) &&
	    tp->t_state <= TCPS_CLOSING) {
		if (ticks - tp->t_rcvtime >= TP_KEEPIDLE(tp) + TP_MAXIDLE(tp))
			goto dropit;
		/*
		 * Send a packet designed to force a response if the peer is
		 * up and reachable: either an ACK if the connection is
		 * still alive, or an RST if the peer has closed the
		 * connection due to timeout or reboot. Using sequence
		 * number tp->snd_una-1 causes the transmitted zero-length
		 * segment to lie outside the receive window; by the
		 * protocol spec, this requires the correspondent TCP to
		 * respond.
		 */
		KMOD_TCPSTAT_INC(tcps_keepprobe);
#if 0
		t_template = tcpip_maketemplate(inp);
		if (t_template) {
			tcp_respond(tp, t_template->tt_ipgen,
			    &t_template->tt_t, (struct mbuf *)NULL,
			    tp->rcv_nxt, tp->snd_una - 1, 0);
			free(t_template, M_TEMP);
		}
#else
                tcp_respond(tp, NULL, (struct tcphdr *)NULL, (struct mbuf *)NULL,
                        tp->rcv_nxt, tp->snd_una - 1, TH_ACK/*trex-core compatible*/);
#endif
	}
	bbr_start_hpts_timer(bbr, tp, cts, 4, 0, 0);
	return (1);
dropit:
	KMOD_TCPSTAT_INC(tcps_keepdrops);
	tcp_log_end_status(tp, TCP_EI_STATUS_KEEP_MAX);
	tcp_set_inp_to_drop(bbr->rc_inp, ETIMEDOUT);
	return (1);
}

/*
 * Retransmit helper function, clear up all the ack
 * flags and take care of important book keeping.
 */
static void
bbr_remxt_tmr(struct tcpcb *tp)
{
	/*
	 * The retransmit timer went off, all sack'd blocks must be
	 * un-acked.
	 */
	struct bbr_sendmap *rsm, *trsm = NULL;
	struct tcp_bbr *bbr;
	uint32_t cts, lost;

	bbr = (struct tcp_bbr *)tp->t_fb_ptr;
	cts = tcp_get_usecs(&bbr->rc_tv);
	lost = bbr->r_ctl.rc_lost;
	if (bbr->r_state && (bbr->r_state != tp->t_state))
		bbr_set_state(tp, bbr, 0);

	TAILQ_FOREACH(rsm, &bbr->r_ctl.rc_map, r_next) {
		if (rsm->r_flags & BBR_ACKED) {
			rsm->r_dupack = 0;
			if (rsm->r_in_tmap == 0) {
				/* We must re-add it back to the tlist */
				if (trsm == NULL) {
					TAILQ_INSERT_HEAD(&bbr->r_ctl.rc_tmap, rsm, r_tnext);
				} else {
					TAILQ_INSERT_AFTER(&bbr->r_ctl.rc_tmap, trsm, rsm, r_tnext);
				}
				rsm->r_in_tmap = 1;
			}
			rsm->r_flags |= BBR_RXT_CLEARED;
			rsm->r_flags &= ~(BBR_ACKED | BBR_SACK_PASSED | BBR_WAS_SACKPASS);
		} else {
			if ((tp->t_state < TCPS_ESTABLISHED) &&
			    (rsm->r_start == tp->snd_una)) {
				/*
				 * Special case for TCP FO. Where
				 * we sent more data beyond the snd_max.
				 * We don't mark that as lost and stop here.
				 */
				break;
			}
			if ((rsm->r_flags & BBR_MARKED_LOST) == 0) {
				bbr->r_ctl.rc_lost += rsm->r_end - rsm->r_start;
				bbr->r_ctl.rc_lost_bytes += rsm->r_end - rsm->r_start;
			}
			if (bbr_marks_rxt_sack_passed) {
				/*
				 * With this option, we will rack out
				 * in 1ms increments the rest of the packets.
				 */
				rsm->r_flags |= BBR_SACK_PASSED | BBR_MARKED_LOST;
				rsm->r_flags &= ~BBR_WAS_SACKPASS;
			} else {
				/*
				 * With this option we only mark them lost
				 * and remove all sack'd markings. We will run
				 * another RXT or a TLP. This will cause
				 * us to eventually send more based on what
				 * ack's come in.
				 */
				rsm->r_flags |= BBR_MARKED_LOST;
				rsm->r_flags &= ~BBR_WAS_SACKPASS;
				rsm->r_flags &= ~BBR_SACK_PASSED;
			}
		}
		trsm = rsm;
	}
	bbr->r_ctl.rc_resend = TAILQ_FIRST(&bbr->r_ctl.rc_map);
	/* Clear the count (we just un-acked them) */
	bbr->rc_tlp_new_data = 0;
	bbr->r_ctl.rc_tlp_seg_send_cnt = 0;
	/* zap the behindness on a rxt */
	bbr->r_ctl.rc_hptsi_agg_delay = 0;
	bbr->r_agg_early_set = 0;
	bbr->r_ctl.rc_agg_early = 0;
	bbr->rc_tlp_rtx_out = 0;
	bbr->r_ctl.rc_sacked = 0;
	bbr->r_ctl.rc_sacklast = NULL;
	bbr->r_timer_override = 1;
	bbr_lt_bw_sampling(bbr, cts, (bbr->r_ctl.rc_lost > lost));
}

/*
 * Re-transmit timeout! If we drop the PCB we will return 1, otherwise
 * we will setup to retransmit the lowest seq number outstanding.
 */
static int
bbr_timeout_rxt(struct tcpcb *tp, struct tcp_bbr *bbr, uint32_t cts)
{
	int32_t rexmt;
	int32_t retval = 0;
#if 0
	bool isipv6;
#endif

	bbr->r_ctl.rc_hpts_flags &= ~PACE_TMR_RXT;
	if (bbr->rc_all_timers_stopped) {
		return (1);
	}
	if (TCPS_HAVEESTABLISHED(tp->t_state) &&
	    (tp->snd_una == tp->snd_max)) {
		/* Nothing outstanding .. nothing to do */
		return (0);
	}
	/*
	 * Retransmission timer went off.  Message has not been acked within
	 * retransmit interval.  Back off to a longer retransmit interval
	 * and retransmit one segment.
	 */
	if (ctf_progress_timeout_check(tp, true)) {
		retval = 1;
		tcp_set_inp_to_drop(bbr->rc_inp, ETIMEDOUT);
		goto out;
	}
	bbr_remxt_tmr(tp);
	if ((bbr->r_ctl.rc_resend == NULL) ||
	    ((bbr->r_ctl.rc_resend->r_flags & BBR_RWND_COLLAPSED) == 0)) {
		/*
		 * If the rwnd collapsed on
		 * the one we are retransmitting
		 * it does not count against the
		 * rxt count.
		 */
		tp->t_rxtshift++;
	}
	if (tp->t_rxtshift > TCP_MAXRXTSHIFT) {
		tp->t_rxtshift = TCP_MAXRXTSHIFT;
		KMOD_TCPSTAT_INC(tcps_timeoutdrop);
		retval = 1;
		tcp_log_end_status(tp, TCP_EI_STATUS_RETRAN);
		tcp_set_inp_to_drop(bbr->rc_inp,
		    (tp->t_softerror ? (uint16_t) tp->t_softerror : ETIMEDOUT));
		goto out;
	}
	if (tp->t_state == TCPS_SYN_SENT) {
		/*
		 * If the SYN was retransmitted, indicate CWND to be limited
		 * to 1 segment in cc_conn_init().
		 */
		tp->snd_cwnd = 1;
	} else if (tp->t_rxtshift == 1) {
		/*
		 * first retransmit; record ssthresh and cwnd so they can be
		 * recovered if this turns out to be a "bad" retransmit. A
		 * retransmit is considered "bad" if an ACK for this segment
		 * is received within RTT/2 interval; the assumption here is
		 * that the ACK was already in flight.  See "On Estimating
		 * End-to-End Network Path Properties" by Allman and Paxson
		 * for more details.
		 */
		tp->snd_cwnd = tp->t_maxseg - bbr->rc_last_options;
		if (!IN_RECOVERY(tp->t_flags)) {
			tp->snd_cwnd_prev = tp->snd_cwnd;
			tp->snd_ssthresh_prev = tp->snd_ssthresh;
			tp->snd_recover_prev = tp->snd_recover;
			tp->t_badrxtwin = ticks + (tp->t_srtt >> (TCP_RTT_SHIFT + 1));
			tp->t_flags |= TF_PREVVALID;
		} else {
			tp->t_flags &= ~TF_PREVVALID;
		}
		tp->snd_cwnd = tp->t_maxseg - bbr->rc_last_options;
	} else {
		tp->snd_cwnd = tp->t_maxseg - bbr->rc_last_options;
		tp->t_flags &= ~TF_PREVVALID;
	}
	KMOD_TCPSTAT_INC(tcps_rexmttimeo);
	if ((tp->t_state == TCPS_SYN_SENT) ||
	    (tp->t_state == TCPS_SYN_RECEIVED))
		rexmt = USEC_2_TICKS(BBR_INITIAL_RTO) * tcp_backoff[tp->t_rxtshift];
	else
		rexmt = TCP_REXMTVAL(tp) * tcp_backoff[tp->t_rxtshift];
	TCPT_RANGESET(tp->t_rxtcur, rexmt,
	    MSEC_2_TICKS(bbr->r_ctl.rc_min_rto_ms),
	    MSEC_2_TICKS(((uint32_t)bbr->rc_max_rto_sec) * 1000));
	/*
	 * If we backed off this far, our srtt estimate is probably bogus.
	 * Clobber it so we'll take the next rtt measurement as our srtt;
	 * move the current srtt into rttvar to keep the current retransmit
	 * times until then.
	 */
	if (tp->t_rxtshift > TCP_MAXRXTSHIFT / 4) {
		tp->t_rttvar += (tp->t_srtt >> TCP_RTT_SHIFT);
		tp->t_srtt = 0;
	}
	sack_filter_clear(&bbr->r_ctl.bbr_sf, tp->snd_una);
	tp->snd_recover = tp->snd_max;
	tp->t_flags |= TF_ACKNOW;
	tp->t_rtttime = 0;
out:
	return (retval);
}

#if 0
static int
#else
int
#endif
bbr_process_timers(struct tcpcb *tp, struct tcp_bbr *bbr, uint32_t cts, uint8_t hpts_calling)
{
	int32_t ret = 0;
	int32_t timers = (bbr->r_ctl.rc_hpts_flags & PACE_TMR_MASK);

	if (timers == 0) {
		return (0);
	}
	if (tp->t_state == TCPS_LISTEN) {
		/* no timers on listen sockets */
		if (bbr->r_ctl.rc_hpts_flags & PACE_PKT_OUTPUT)
			return (0);
		return (1);
	}
	if (TSTMP_LT(cts, bbr->r_ctl.rc_timer_exp)) {
#if 0
		uint32_t left;
#endif

		if (bbr->r_ctl.rc_hpts_flags & PACE_PKT_OUTPUT) {
			ret = -1;
			return (0);
		}
		if (hpts_calling == 0) {
			ret = -2;
			return (0);
		}
		/*
		 * Ok our timer went off early and we are not paced false
		 * alarm, go back to sleep.
		 */
#if 0
		left = bbr->r_ctl.rc_timer_exp - cts;
#endif
		ret = -3;
#if 0
		tcp_hpts_insert(tp->t_inpcb, HPTS_USEC_TO_SLOTS(left));
#endif
		return (1);
	}
	bbr->rc_tmr_stopped = 0;
	bbr->r_ctl.rc_hpts_flags &= ~PACE_TMR_MASK;
	if (timers & PACE_TMR_DELACK) {
		ret = bbr_timeout_delack(tp, bbr, cts);
	} else if (timers & PACE_TMR_PERSIT) {
		ret = bbr_timeout_persist(tp, bbr, cts);
	} else if (timers & PACE_TMR_RACK) {
		bbr->r_ctl.rc_tlp_rxt_last_time = cts;
		ret = bbr_timeout_rack(tp, bbr, cts);
	} else if (timers & PACE_TMR_TLP) {
		bbr->r_ctl.rc_tlp_rxt_last_time = cts;
		ret = bbr_timeout_tlp(tp, bbr, cts);
	} else if (timers & PACE_TMR_RXT) {
		bbr->r_ctl.rc_tlp_rxt_last_time = cts;
		ret = bbr_timeout_rxt(tp, bbr, cts);
	} else if (timers & PACE_TMR_KEEP) {
		ret = bbr_timeout_keepalive(tp, bbr, cts);
	}
	return (ret);
}

static void
bbr_timer_cancel(struct tcp_bbr *bbr, int32_t line, uint32_t cts)
{
	if (bbr->r_ctl.rc_hpts_flags & PACE_TMR_MASK) {
#if 0
		if (bbr->rc_inp->inp_in_hpts &&
		    (bbr->rc_timer_first == 1)) {
			/*
			 * If we are canceling timer's when we have the
			 * timer ahead of the output being paced. We also
			 * must remove ourselves from the hpts.
			 */
			tcp_hpts_remove(bbr->rc_inp, HPTS_REMOVE_OUTPUT);
			if (bbr->r_ctl.rc_last_delay_val) {
				/* Update the last hptsi delay too */
				uint32_t time_since_send;

				if (TSTMP_GT(cts, bbr->rc_pacer_started))
					time_since_send = cts - bbr->rc_pacer_started;
				else
					time_since_send = 0;
				if (bbr->r_ctl.rc_last_delay_val > time_since_send) {
					/* Cut down our slot time */
					bbr->r_ctl.rc_last_delay_val -= time_since_send;
				} else {
					bbr->r_ctl.rc_last_delay_val = 0;
				}
				bbr->rc_pacer_started = cts;
			}
		}
#endif
		bbr->rc_timer_first = 0;
		bbr->rc_tmr_stopped = bbr->r_ctl.rc_hpts_flags & PACE_TMR_MASK;
		bbr->r_ctl.rc_hpts_flags &= ~(PACE_TMR_MASK);
	}
}

static uint32_t
bbr_get_earliest_send_outstanding(struct tcp_bbr *bbr, struct bbr_sendmap *u_rsm, uint32_t cts)
{
	struct bbr_sendmap *rsm;

	rsm = TAILQ_FIRST(&bbr->r_ctl.rc_tmap);
	if ((rsm == NULL) || (u_rsm == rsm))
		return (cts);
	return(rsm->r_tim_lastsent[(rsm->r_rtr_cnt-1)]);
}

static void
bbr_update_rsm(struct tcpcb *tp, struct tcp_bbr *bbr,
     struct bbr_sendmap *rsm, uint32_t cts, uint32_t pacing_time)
{
	int32_t idx;

	rsm->r_rtr_cnt++;
	rsm->r_dupack = 0;
	if (rsm->r_rtr_cnt > BBR_NUM_OF_RETRANS) {
		rsm->r_rtr_cnt = BBR_NUM_OF_RETRANS;
		rsm->r_flags |= BBR_OVERMAX;
	}
	if (rsm->r_flags & BBR_RWND_COLLAPSED) {
		/* Take off the collapsed flag at rxt */
		rsm->r_flags &= ~BBR_RWND_COLLAPSED;
	}
	if (rsm->r_flags & BBR_MARKED_LOST) {
		/* We have retransmitted, its no longer lost */
		rsm->r_flags &= ~BBR_MARKED_LOST;
		bbr->r_ctl.rc_lost_bytes -= rsm->r_end - rsm->r_start;
	}
	if (rsm->r_flags & BBR_RXT_CLEARED) {
		/*
		 * We hit a RXT timer on it and
		 * we cleared the "acked" flag.
		 * We now have it going back into
		 * flight, we can remove the cleared
		 * flag and possibly do accounting on
		 * this piece.
		 */
		rsm->r_flags &= ~BBR_RXT_CLEARED;
	}
	if ((rsm->r_rtr_cnt > 1) && ((rsm->r_flags & BBR_TLP) == 0)) {
		bbr->r_ctl.rc_holes_rxt += (rsm->r_end - rsm->r_start);
		rsm->r_rtr_bytes += (rsm->r_end - rsm->r_start);
	}
	idx = rsm->r_rtr_cnt - 1;
	rsm->r_tim_lastsent[idx] = cts;
	rsm->r_pacing_delay = pacing_time;
	rsm->r_delivered = bbr->r_ctl.rc_delivered;
	rsm->r_ts_valid = bbr->rc_ts_valid;
	if (bbr->rc_ts_valid)
		rsm->r_del_ack_ts = bbr->r_ctl.last_inbound_ts;
	if (bbr->r_ctl.r_app_limited_until)
		rsm->r_app_limited = 1;
	else
		rsm->r_app_limited = 0;
	if (bbr->rc_bbr_state == BBR_STATE_PROBE_BW)
		rsm->r_bbr_state = bbr_state_val(bbr);
	else
		rsm->r_bbr_state = 8;
	if (rsm->r_flags & BBR_ACKED) {
		/* Problably MTU discovery messing with us */
		rsm->r_flags &= ~BBR_ACKED;
		bbr->r_ctl.rc_sacked -= (rsm->r_end - rsm->r_start);
		if (bbr->r_ctl.rc_sacked == 0)
			bbr->r_ctl.rc_sacklast = NULL;
	}
	if (rsm->r_in_tmap) {
		TAILQ_REMOVE(&bbr->r_ctl.rc_tmap, rsm, r_tnext);
	}
	TAILQ_INSERT_TAIL(&bbr->r_ctl.rc_tmap, rsm, r_tnext);
	rsm->r_in_tmap = 1;
	if (rsm->r_flags & BBR_SACK_PASSED) {
		/* We have retransmitted due to the SACK pass */
		rsm->r_flags &= ~BBR_SACK_PASSED;
		rsm->r_flags |= BBR_WAS_SACKPASS;
	}
	rsm->r_first_sent_time = bbr_get_earliest_send_outstanding(bbr, rsm, cts);
	rsm->r_flight_at_send = ctf_flight_size(bbr->rc_tp,
						(bbr->r_ctl.rc_sacked + bbr->r_ctl.rc_lost_bytes));
	bbr->r_ctl.rc_next = TAILQ_NEXT(rsm, r_next);
	if (bbr->r_ctl.rc_bbr_hptsi_gain > BBR_UNIT) {
		rsm->r_is_gain = 1;
		rsm->r_is_drain = 0;
	} else if (bbr->r_ctl.rc_bbr_hptsi_gain < BBR_UNIT) {
		rsm->r_is_drain = 1;
		rsm->r_is_gain = 0;
	} else {
		rsm->r_is_drain = 0;
		rsm->r_is_gain = 0;
	}
	rsm->r_del_time = bbr->r_ctl.rc_del_time; /* TEMP GOOGLE CODE */
}

/*
 * Returns 0, or the sequence where we stopped
 * updating. We also update the lenp to be the amount
 * of data left.
 */

static uint32_t
bbr_update_entry(struct tcpcb *tp, struct tcp_bbr *bbr,
    struct bbr_sendmap *rsm, uint32_t cts, int32_t *lenp, uint32_t pacing_time)
{
	/*
	 * We (re-)transmitted starting at rsm->r_start for some length
	 * (possibly less than r_end.
	 */
	struct bbr_sendmap *nrsm;
	uint32_t c_end;
	int32_t len;

	len = *lenp;
	c_end = rsm->r_start + len;
	if (SEQ_GEQ(c_end, rsm->r_end)) {
		/*
		 * We retransmitted the whole piece or more than the whole
		 * slopping into the next rsm.
		 */
		bbr_update_rsm(tp, bbr, rsm, cts, pacing_time);
		if (c_end == rsm->r_end) {
			*lenp = 0;
			return (0);
		} else {
			int32_t act_len;

			/* Hangs over the end return whats left */
			act_len = rsm->r_end - rsm->r_start;
			*lenp = (len - act_len);
			return (rsm->r_end);
		}
		/* We don't get out of this block. */
	}
	/*
	 * Here we retransmitted less than the whole thing which means we
	 * have to split this into what was transmitted and what was not.
	 */
	nrsm = bbr_alloc_full_limit(bbr);
	if (nrsm == NULL) {
		*lenp = 0;
		return (0);
	}
	/*
	 * So here we are going to take the original rsm and make it what we
	 * retransmitted. nrsm will be the tail portion we did not
	 * retransmit. For example say the chunk was 1, 11 (10 bytes). And
	 * we retransmitted 5 bytes i.e. 1, 5. The original piece shrinks to
	 * 1, 6 and the new piece will be 6, 11.
	 */
	bbr_clone_rsm(bbr, nrsm, rsm, c_end);
	TAILQ_INSERT_AFTER(&bbr->r_ctl.rc_map, rsm, nrsm, r_next);
	nrsm->r_dupack = 0;
	if (rsm->r_in_tmap) {
		TAILQ_INSERT_AFTER(&bbr->r_ctl.rc_tmap, rsm, nrsm, r_tnext);
		nrsm->r_in_tmap = 1;
	}
	rsm->r_flags &= (~BBR_HAS_FIN);
	bbr_update_rsm(tp, bbr, rsm, cts, pacing_time);
	*lenp = 0;
	return (0);
}

#if 0
static uint64_t
bbr_get_hardware_rate(struct tcp_bbr *bbr)
{
	uint64_t bw;

	bw = bbr_get_bw(bbr);
	bw *= (uint64_t)bbr_hptsi_gain[BBR_SUB_GAIN];
	bw /= (uint64_t)BBR_UNIT;
	return(bw);
}

static void
bbr_setup_less_of_rate(struct tcp_bbr *bbr, uint32_t cts,
		       uint64_t act_rate, uint64_t rate_wanted)
{
	/*
	 * We could not get a full gains worth
	 * of rate.
	 */
	if (get_filter_value(&bbr->r_ctl.rc_delrate) >= act_rate) {
		/* we can't even get the real rate */
		uint64_t red;

		bbr->skip_gain = 1;
		bbr->gain_is_limited = 0;
		red = get_filter_value(&bbr->r_ctl.rc_delrate) - act_rate;
		if (red)
			filter_reduce_by(&bbr->r_ctl.rc_delrate, red, cts);
	} else {
		/* We can use a lower gain */
		bbr->skip_gain = 0;
		bbr->gain_is_limited = 1;
	}
}
#endif

static void
bbr_update_hardware_pacing_rate(struct tcp_bbr *bbr, uint32_t cts)
{
#if 0
	const struct tcp_hwrate_limit_table *nrte;
	int error, rate = -1;

	if (bbr->r_ctl.crte == NULL)
		return;
#if 0   // BBR_INT: ROUTE
	if ((bbr->rc_inp->inp_route.ro_nh == NULL) ||
	    (bbr->rc_inp->inp_route.ro_nh->nh_ifp == NULL)) {
		/* Lost our routes? */
		/* Clear the way for a re-attempt */
		bbr->bbr_attempt_hdwr_pace = 0;
lost_rate:
		bbr->gain_is_limited = 0;
		bbr->skip_gain = 0;
		bbr->bbr_hdrw_pacing = 0;
		counter_u64_add(bbr_flows_whdwr_pacing, -1);
		counter_u64_add(bbr_flows_nohdwr_pacing, 1);
		tcp_bbr_tso_size_check(bbr, cts);
		return;
	}
#endif
	rate = bbr_get_hardware_rate(bbr);
	nrte = tcp_chg_pacing_rate(bbr->r_ctl.crte,
				   bbr->rc_tp,
				   bbr->rc_inp->inp_route.ro_nh->nh_ifp,
				   rate,
				   (RS_PACING_GEQ|RS_PACING_SUB_OK),
				   &error, NULL);
	if (nrte == NULL) {
		goto lost_rate;
	}
	if (nrte != bbr->r_ctl.crte) {
		bbr->r_ctl.crte = nrte;
		if (error == 0)  {
			BBR_STAT_INC(bbr_hdwr_rl_mod_ok);
			if (bbr->r_ctl.crte->rate < rate) {
				/* We have a problem */
				bbr_setup_less_of_rate(bbr, cts,
						       bbr->r_ctl.crte->rate, rate);
			} else {
				/* We are good */
				bbr->gain_is_limited = 0;
				bbr->skip_gain = 0;
			}
		} else {
			/* A failure should release the tag */
			BBR_STAT_INC(bbr_hdwr_rl_mod_fail);
			bbr->gain_is_limited = 0;
			bbr->skip_gain = 0;
			bbr->bbr_hdrw_pacing = 0;
		}
	}
#endif
}

static void
bbr_adjust_for_hw_pacing(struct tcp_bbr *bbr, uint32_t cts)
{
#if 0
	/*
	 * If we have hardware pacing support
	 * we need to factor that in for our
	 * TSO size.
	 */
	const struct tcp_hwrate_limit_table *rlp;
	uint32_t cur_delay, seg_sz, maxseg, new_tso, delta, hdwr_delay;

	if ((bbr->bbr_hdrw_pacing == 0) ||
	    (IN_RECOVERY(bbr->rc_tp->t_flags)) ||
	    (bbr->r_ctl.crte == NULL))
		return;
	if (bbr->hw_pacing_set == 0) {
		/* Not yet by the hdwr pacing count delay */
		return;
	}
	if (bbr_hdwr_pace_adjust == 0) {
		/* No adjustment */
		return;
	}
	rlp = bbr->r_ctl.crte;
	if (bbr->rc_tp->t_maxseg > bbr->rc_last_options)
		maxseg = bbr->rc_tp->t_maxseg - bbr->rc_last_options;
	else
		maxseg = BBR_MIN_SEG - bbr->rc_last_options;
	/*
	 * So lets first get the
	 * time we will take between
	 * TSO sized sends currently without
	 * hardware help.
	 */
	cur_delay = bbr_get_pacing_delay(bbr, BBR_UNIT,
		        bbr->r_ctl.rc_pace_max_segs, cts, 1);
	hdwr_delay = bbr->r_ctl.rc_pace_max_segs / maxseg;
	hdwr_delay *= rlp->time_between;
	if (cur_delay > hdwr_delay)
		delta = cur_delay - hdwr_delay;
	else
		delta = 0;
	if (delta &&
	    (delta < (max(rlp->time_between,
			  bbr->r_ctl.bbr_hptsi_segments_delay_tar)))) {
		/*
		 * Now lets divide by the pacing
		 * time between each segment the
		 * hardware sends rounding up and
		 * derive a bytes from that. We multiply
		 * that by bbr_hdwr_pace_adjust to get
		 * more bang for our buck.
		 *
		 * The goal is to have the software pacer
		 * waiting no more than an additional
		 * pacing delay if we can (without the
		 * compensation i.e. x bbr_hdwr_pace_adjust).
		 */
		seg_sz = max(((cur_delay + rlp->time_between)/rlp->time_between),
			     (bbr->r_ctl.rc_pace_max_segs/maxseg));
		seg_sz *= bbr_hdwr_pace_adjust;
		if (bbr_hdwr_pace_floor &&
		    (seg_sz < bbr->r_ctl.crte->ptbl->rs_min_seg)) {
			/* Currently hardware paces
			 * out rs_min_seg segments at a time.
			 * We need to make sure we always send at least
			 * a full burst of bbr_hdwr_pace_floor down.
			 */
			seg_sz = bbr->r_ctl.crte->ptbl->rs_min_seg;
		}
		seg_sz *= maxseg;
	} else if (delta == 0) {
		/*
		 * The highest pacing rate is
		 * above our b/w gained. This means
		 * we probably are going quite fast at
		 * the hardware highest rate. Lets just multiply
		 * the calculated TSO size by the
		 * multiplier factor (its probably
		 * 4 segments in the default config for
		 * mlx).
		 */
		seg_sz = bbr->r_ctl.rc_pace_max_segs * bbr_hdwr_pace_adjust;
		if (bbr_hdwr_pace_floor &&
		    (seg_sz < bbr->r_ctl.crte->ptbl->rs_min_seg)) {
			/* Currently hardware paces
			 * out rs_min_seg segments at a time.
			 * We need to make sure we always send at least
			 * a full burst of bbr_hdwr_pace_floor down.
			 */
			seg_sz = bbr->r_ctl.crte->ptbl->rs_min_seg;
		}
	} else {
		/*
		 * The pacing time difference is so
		 * big that the hardware will
		 * pace out more rapidly then we
		 * really want and then we
		 * will have a long delay. Lets just keep
		 * the same TSO size so its as if
		 * we were not using hdwr pacing (we
		 * just gain a bit of spacing from the
		 * hardware if seg_sz > 1).
		 */
		seg_sz = bbr->r_ctl.rc_pace_max_segs;
	}
	if (seg_sz > bbr->r_ctl.rc_pace_max_segs)
		new_tso = seg_sz;
	else
		new_tso = bbr->r_ctl.rc_pace_max_segs;
	if (new_tso >= (PACE_MAX_IP_BYTES-maxseg))
		new_tso = PACE_MAX_IP_BYTES - maxseg;

	if (new_tso != bbr->r_ctl.rc_pace_max_segs) {
		bbr->r_ctl.rc_pace_max_segs = new_tso;
	}
#endif
}

static void
tcp_bbr_tso_size_check(struct tcp_bbr *bbr, uint32_t cts)
{
	uint64_t bw;
	uint32_t old_tso = 0, new_tso;
	uint32_t maxseg, bytes;
	/*
	 * Google/linux uses the following algorithm to determine
	 * the TSO size based on the b/w of the link (from Neal Cardwell email 9/27/18):
	 *
	 *  bytes = bw_in_bytes_per_second / 1000
	 *  bytes = min(bytes, 64k)
	 *  tso_segs = bytes / MSS
	 *  if (bw < 1.2Mbs)
	 *      min_tso_segs = 1
	 *  else
	 *	min_tso_segs = 2
	 * tso_segs = max(tso_segs, min_tso_segs)
	 *
	 * * Note apply a device specific limit (we apply this in the
	 *   tcp_m_copym).
	 * Note that before the initial measurement is made google bursts out
	 * a full iwnd just like new-reno/cubic.
	 *
	 * We do not use this algorithm. Instead we
	 * use a two phased approach:
	 *
	 *  if ( bw <= per-tcb-cross-over)
	 *     goal_tso =  calculate how much with this bw we
	 *                 can send in goal-time seconds.
	 *     if (goal_tso > mss)
	 *         seg = goal_tso / mss
	 *         tso = seg * mss
	 *     else
	 *         tso = mss
	 *     if (tso > per-tcb-max)
	 *         tso = per-tcb-max
	 *  else if ( bw > 512Mbps)
	 *     tso = max-tso (64k/mss)
	 *  else
	 *     goal_tso = bw / per-tcb-divsor
	 *     seg = (goal_tso + mss-1)/mss
	 *     tso = seg * mss
	 *
	 * if (tso < per-tcb-floor)
	 *    tso = per-tcb-floor
	 * if (tso > per-tcb-utter_max)
	 *    tso = per-tcb-utter_max
	 *
	 * Note the default per-tcb-divisor is 1000 (same as google).
	 * the goal cross over is 30Mbps however. To recreate googles
	 * algorithm you need to set:
	 *
	 * cross-over = 23,168,000 bps
	 * goal-time = 18000
	 * per-tcb-max = 2
	 * per-tcb-divisor = 1000
	 * per-tcb-floor = 1
	 *
	 * This will get you "google bbr" behavior with respect to tso size.
	 *
	 * Note we do set anything TSO size until we are past the initial
	 * window. Before that we gnerally use either a single MSS
	 * or we use the full IW size (so we burst a IW at a time)
	 */

	if (bbr->rc_tp->t_maxseg > bbr->rc_last_options) {
		maxseg = bbr->rc_tp->t_maxseg - bbr->rc_last_options;
	} else {
		maxseg = BBR_MIN_SEG - bbr->rc_last_options;
	}
	old_tso = bbr->r_ctl.rc_pace_max_segs;
	if (bbr->rc_past_init_win == 0) {
		/*
		 * Not enough data has been acknowledged to make a
		 * judgement. Set up the initial TSO based on if we
		 * are sending a full IW at once or not.
		 */
		if (bbr->rc_use_google)
			bbr->r_ctl.rc_pace_max_segs = ((bbr->rc_tp->t_maxseg - bbr->rc_last_options) * 2);
		else if (bbr->bbr_init_win_cheat)
			bbr->r_ctl.rc_pace_max_segs = bbr_initial_cwnd(bbr, bbr->rc_tp);
		else
			bbr->r_ctl.rc_pace_max_segs = bbr->rc_tp->t_maxseg - bbr->rc_last_options;
		if (bbr->r_ctl.rc_pace_min_segs != bbr->rc_tp->t_maxseg)
			bbr->r_ctl.rc_pace_min_segs = bbr->rc_tp->t_maxseg;
		if (bbr->r_ctl.rc_pace_max_segs == 0) {
			bbr->r_ctl.rc_pace_max_segs = maxseg;
		}
		bbr_adjust_for_hw_pacing(bbr, cts);
		return;
	}
	/**
	 * Now lets set the TSO goal based on our delivery rate in
	 * bytes per second. Note we only do this if
	 * we have acked at least the initial cwnd worth of data.
	 */
	bw = bbr_get_bw(bbr);
	if (IN_RECOVERY(bbr->rc_tp->t_flags) &&
	     (bbr->rc_use_google == 0)) {
		/* We clamp to one MSS in recovery */
		new_tso = maxseg;
	} else if (bbr->rc_use_google) {
		int min_tso_segs;

		/* Google considers the gain too */
		if (bbr->r_ctl.rc_bbr_hptsi_gain != BBR_UNIT) {
			bw *= bbr->r_ctl.rc_bbr_hptsi_gain;
			bw /= BBR_UNIT;
		}
		bytes = bw / 1024;
		if (bytes > (64 * 1024))
			bytes = 64 * 1024;
		new_tso = bytes / maxseg;
		if (bw < ONE_POINT_TWO_MEG)
			min_tso_segs = 1;
		else
			min_tso_segs = 2;
		if (new_tso < min_tso_segs)
			new_tso = min_tso_segs;
		new_tso *= maxseg;
	} else if (bbr->rc_no_pacing) {
		new_tso = (PACE_MAX_IP_BYTES / maxseg) * maxseg;
	} else if (bw <= bbr->r_ctl.bbr_cross_over) {
		/*
		 * Calculate the worse case b/w TSO if we are inserting no
		 * more than a delay_target number of TSO's.
		 */
		uint32_t tso_len, min_tso;

		tso_len = bbr_get_pacing_length(bbr, BBR_UNIT, bbr->r_ctl.bbr_hptsi_segments_delay_tar, bw);
		if (tso_len > maxseg) {
			new_tso = tso_len / maxseg;
			if (new_tso > bbr->r_ctl.bbr_hptsi_segments_max)
				new_tso = bbr->r_ctl.bbr_hptsi_segments_max;
			new_tso *= maxseg;
		} else {
			/*
			 * less than a full sized frame yikes.. long rtt or
			 * low bw?
			 */
			min_tso = bbr_minseg(bbr);
			if ((tso_len > min_tso) && (bbr_all_get_min == 0))
				new_tso = rounddown(tso_len, min_tso);
			else
				new_tso = min_tso;
		}
	} else if (bw > FIVETWELVE_MBPS) {
		/*
		 * This guy is so fast b/w wise that we can TSO as large as
		 * possible of segments that the NIC will allow.
		 */
		new_tso = rounddown(PACE_MAX_IP_BYTES, maxseg);
	} else {
		/*
		 * This formula is based on attempting to send a segment or
		 * more every bbr_hptsi_per_second. The default is 1000
		 * which means you are targeting what you can send every 1ms
		 * based on the peers bw.
		 *
		 * If the number drops to say 500, then you are looking more
		 * at 2ms and you will raise how much we send in a single
		 * TSO thus saving CPU (less bbr_output_wtime() calls). The
		 * trade off of course is you will send more at once and
		 * thus tend to clump up the sends into larger "bursts"
		 * building a queue.
		 */
		bw /= bbr->r_ctl.bbr_hptsi_per_second;
		new_tso = roundup(bw, (uint64_t)maxseg);
		/*
		 * Gate the floor to match what our lower than 48Mbps
		 * algorithm does. The ceiling (bbr_hptsi_segments_max) thus
		 * becomes the floor for this calculation.
		 */
		if (new_tso < (bbr->r_ctl.bbr_hptsi_segments_max * maxseg))
			new_tso = (bbr->r_ctl.bbr_hptsi_segments_max * maxseg);
	}
	if (bbr->r_ctl.bbr_hptsi_segments_floor && (new_tso < (maxseg * bbr->r_ctl.bbr_hptsi_segments_floor)))
		new_tso = maxseg * bbr->r_ctl.bbr_hptsi_segments_floor;
	if (new_tso > PACE_MAX_IP_BYTES)
		new_tso = rounddown(PACE_MAX_IP_BYTES, maxseg);
	/* Enforce an utter maximum. */
	if (bbr->r_ctl.bbr_utter_max && (new_tso > (bbr->r_ctl.bbr_utter_max * maxseg))) {
		new_tso = bbr->r_ctl.bbr_utter_max * maxseg;
	}
	if (old_tso != new_tso) {
		/* Only log changes */
		bbr->r_ctl.rc_pace_max_segs = new_tso;
	}
	/* We have hardware pacing! */
	bbr_adjust_for_hw_pacing(bbr, cts);
}

static void
bbr_log_output(struct tcp_bbr *bbr, struct tcpcb *tp, struct tcpopt *to, int32_t len,
    uint32_t seq_out, uint8_t th_flags, int32_t err, uint32_t cts,
    struct mbuf *mb, int32_t * abandon, struct bbr_sendmap *hintrsm, uint32_t delay_calc,
    struct sockbuf *sb)
{

	struct bbr_sendmap *rsm, *nrsm;
	register uint32_t snd_max, snd_una;
	uint32_t pacing_time;
	/*
	 * Add to the RACK log of packets in flight or retransmitted. If
	 * there is a TS option we will use the TS echoed, if not we will
	 * grab a TS.
	 *
	 * Retransmissions will increment the count and move the ts to its
	 * proper place. Note that if options do not include TS's then we
	 * won't be able to effectively use the ACK for an RTT on a retran.
	 *
	 * Notes about r_start and r_end. Lets consider a send starting at
	 * sequence 1 for 10 bytes. In such an example the r_start would be
	 * 1 (starting sequence) but the r_end would be r_start+len i.e. 11.
	 * This means that r_end is actually the first sequence for the next
	 * slot (11).
	 *
	 */
	if (err) {
		/*
		 * We don't log errors -- we could but snd_max does not
		 * advance in this case either.
		 */
		return;
	}
	if (th_flags & TH_RST) {
		/*
		 * We don't log resets and we return immediately from
		 * sending
		 */
		*abandon = 1;
		return;
	}
	snd_una = tp->snd_una;
	if (th_flags & (TH_SYN | TH_FIN) && (hintrsm == NULL)) {
		/*
		 * The call to bbr_log_output is made before bumping
		 * snd_max. This means we can record one extra byte on a SYN
		 * or FIN if seq_out is adding more on and a FIN is present
		 * (and we are not resending).
		 */
		if ((th_flags & TH_SYN) && (tp->iss == seq_out))
			len++;
		if (th_flags & TH_FIN)
			len++;
	}
	if (SEQ_LEQ((seq_out + len), snd_una)) {
		/* Are sending an old segment to induce an ack (keep-alive)? */
		return;
	}
	if (SEQ_LT(seq_out, snd_una)) {
		/* huh? should we panic? */
		uint32_t end;

		end = seq_out + len;
		seq_out = snd_una;
		len = end - seq_out;
	}
	snd_max = tp->snd_max;
	if (len == 0) {
		/* We don't log zero window probes */
		return;
	}
	pacing_time = bbr_get_pacing_delay(bbr, bbr->r_ctl.rc_bbr_hptsi_gain, len, cts, 1);
	/* First question is it a retransmission? */
	if (seq_out == snd_max) {
again:
		rsm = bbr_alloc(bbr);
		if (rsm == NULL) {
			return;
		}
		rsm->r_flags = 0;
		if (th_flags & TH_SYN)
			rsm->r_flags |= BBR_HAS_SYN;
		if (th_flags & TH_FIN)
			rsm->r_flags |= BBR_HAS_FIN;
		rsm->r_tim_lastsent[0] = cts;
		rsm->r_rtr_cnt = 1;
		rsm->r_rtr_bytes = 0;
		rsm->r_start = seq_out;
		rsm->r_end = rsm->r_start + len;
		rsm->r_dupack = 0;
		rsm->r_delivered = bbr->r_ctl.rc_delivered;
		rsm->r_pacing_delay = pacing_time;
		rsm->r_ts_valid = bbr->rc_ts_valid;
		if (bbr->rc_ts_valid)
			rsm->r_del_ack_ts = bbr->r_ctl.last_inbound_ts;
		rsm->r_del_time = bbr->r_ctl.rc_del_time;
		if (bbr->r_ctl.r_app_limited_until)
			rsm->r_app_limited = 1;
		else
			rsm->r_app_limited = 0;
		rsm->r_first_sent_time = bbr_get_earliest_send_outstanding(bbr, rsm, cts);
		rsm->r_flight_at_send = ctf_flight_size(bbr->rc_tp,
						(bbr->r_ctl.rc_sacked + bbr->r_ctl.rc_lost_bytes));
		/*
		 * Here we must also add in this rsm since snd_max
		 * is updated after we return from a new send.
		 */
		rsm->r_flight_at_send += len;
		TAILQ_INSERT_TAIL(&bbr->r_ctl.rc_map, rsm, r_next);
		TAILQ_INSERT_TAIL(&bbr->r_ctl.rc_tmap, rsm, r_tnext);
		rsm->r_in_tmap = 1;
		if (bbr->rc_bbr_state == BBR_STATE_PROBE_BW)
			rsm->r_bbr_state = bbr_state_val(bbr);
		else
			rsm->r_bbr_state = 8;
		if (bbr->r_ctl.rc_bbr_hptsi_gain > BBR_UNIT) {
			rsm->r_is_gain = 1;
			rsm->r_is_drain = 0;
		} else if (bbr->r_ctl.rc_bbr_hptsi_gain < BBR_UNIT) {
			rsm->r_is_drain = 1;
			rsm->r_is_gain = 0;
		} else {
			rsm->r_is_drain = 0;
			rsm->r_is_gain = 0;
		}
		return;
	}
	/*
	 * If we reach here its a retransmission and we need to find it.
	 */
more:
	if (hintrsm && (hintrsm->r_start == seq_out)) {
		rsm = hintrsm;
		hintrsm = NULL;
	} else if (bbr->r_ctl.rc_next) {
		/* We have a hint from a previous run */
		rsm = bbr->r_ctl.rc_next;
	} else {
		/* No hints sorry */
		rsm = NULL;
	}
	if ((rsm) && (rsm->r_start == seq_out)) {
		/*
		 * We used rc_next or hintrsm  to retransmit, hopefully the
		 * likely case.
		 */
		seq_out = bbr_update_entry(tp, bbr, rsm, cts, &len, pacing_time);
		if (len == 0) {
			return;
		} else {
			goto more;
		}
	}
	/* Ok it was not the last pointer go through it the hard way. */
	TAILQ_FOREACH(rsm, &bbr->r_ctl.rc_map, r_next) {
		if (rsm->r_start == seq_out) {
			seq_out = bbr_update_entry(tp, bbr, rsm, cts, &len, pacing_time);
			bbr->r_ctl.rc_next = TAILQ_NEXT(rsm, r_next);
			if (len == 0) {
				return;
			} else {
				continue;
			}
		}
		if (SEQ_GEQ(seq_out, rsm->r_start) && SEQ_LT(seq_out, rsm->r_end)) {
			/* Transmitted within this piece */
			/*
			 * Ok we must split off the front and then let the
			 * update do the rest
			 */
			nrsm = bbr_alloc_full_limit(bbr);
			if (nrsm == NULL) {
				bbr_update_rsm(tp, bbr, rsm, cts, pacing_time);
				return;
			}
			/*
			 * copy rsm to nrsm and then trim the front of rsm
			 * to not include this part.
			 */
			bbr_clone_rsm(bbr, nrsm, rsm, seq_out);
			TAILQ_INSERT_AFTER(&bbr->r_ctl.rc_map, rsm, nrsm, r_next);
			if (rsm->r_in_tmap) {
				TAILQ_INSERT_AFTER(&bbr->r_ctl.rc_tmap, rsm, nrsm, r_tnext);
				nrsm->r_in_tmap = 1;
			}
			rsm->r_flags &= (~BBR_HAS_FIN);
			seq_out = bbr_update_entry(tp, bbr, nrsm, cts, &len, pacing_time);
			if (len == 0) {
				return;
			}
		}
	}
	/*
	 * Hmm not found in map did they retransmit both old and on into the
	 * new?
	 */
	if (seq_out == tp->snd_max) {
		goto again;
	}
}

static void
bbr_collapse_rtt(struct tcpcb *tp, struct tcp_bbr *bbr, int32_t rtt)
{
	/*
	 * Collapse timeout back the cum-ack moved.
	 */
	tp->t_rxtshift = 0;
	tp->t_softerror = 0;
}

static void
tcp_bbr_xmit_timer(struct tcp_bbr *bbr, uint32_t rtt_usecs, uint32_t rsm_send_time, uint32_t r_start, uint32_t tsin)
{
	bbr->rtt_valid = 1;
	bbr->r_ctl.cur_rtt = rtt_usecs;
	bbr->r_ctl.ts_in = tsin;
	if (rsm_send_time)
		bbr->r_ctl.cur_rtt_send_time = rsm_send_time;
}

static void
bbr_make_timestamp_determination(struct tcp_bbr *bbr)
{
	/**
	 * We have in our bbr control:
	 * 1) The timestamp we started observing cum-acks (bbr->r_ctl.bbr_ts_check_tstmp).
	 * 2) Our timestamp indicating when we sent that packet (bbr->r_ctl.rsm->bbr_ts_check_our_cts).
	 * 3) The current timestamp that just came in (bbr->r_ctl.last_inbound_ts)
	 * 4) The time that the packet that generated that ack was sent (bbr->r_ctl.cur_rtt_send_time)
	 *
	 * Now we can calculate the time between the sends by doing:
	 *
	 * delta = bbr->r_ctl.cur_rtt_send_time - bbr->r_ctl.bbr_ts_check_our_cts
	 *
	 * And the peer's time between receiving them by doing:
	 *
	 * peer_delta = bbr->r_ctl.last_inbound_ts - bbr->r_ctl.bbr_ts_check_tstmp
	 *
	 * We want to figure out if the timestamp values are in msec, 10msec or usec.
	 * We also may find that we can't use the timestamps if say we see
	 * that the peer_delta indicates that though we may have taken 10ms to
	 * pace out the data, it only saw 1ms between the two packets. This would
	 * indicate that somewhere on the path is a batching entity that is giving
	 * out time-slices of the actual b/w. This would mean we could not use
	 * reliably the peers timestamps.
	 *
	 * We expect delta > peer_delta initially. Until we figure out the
	 * timestamp difference which we will store in bbr->r_ctl.bbr_peer_tsratio.
	 * If we place 1000 there then its a ms vs our usec. If we place 10000 there
	 * then its 10ms vs our usec. If the peer is running a usec clock we would
	 * put a 1 there. If the value is faster then ours, we will disable the
	 * use of timestamps (though we could revist this later if we find it to be not
	 * just an isolated one or two flows)).
	 *
	 * To detect the batching middle boxes we will come up with our compensation and
	 * if with it in place, we find the peer is drastically off (by some margin) in
	 * the smaller direction, then we will assume the worst case and disable use of timestamps.
	 *
	 */
	uint64_t delta, peer_delta, delta_up;

	delta = bbr->r_ctl.cur_rtt_send_time - bbr->r_ctl.bbr_ts_check_our_cts;
	if (delta < bbr_min_usec_delta) {
		/*
		 * Have not seen a min amount of time
		 * between our send times so we can
		 * make a determination of the timestamp
		 * yet.
		 */
		return;
	}
	peer_delta = bbr->r_ctl.last_inbound_ts - bbr->r_ctl.bbr_ts_check_tstmp;
	if (peer_delta < bbr_min_peer_delta) {
		/*
		 * We may have enough in the form of
		 * our delta but the peers number
		 * has not changed that much. It could
		 * be its clock ratio is such that
		 * we need more data (10ms tick) or
		 * there may be other compression scenarios
		 * going on. In any event we need the
		 * spread to be larger.
		 */
		return;
	}
	/* Ok lets first see which way our delta is going */
	if (peer_delta > delta) {
		/* Very unlikely, the peer without
		 * compensation shows that it saw
		 * the two sends arrive further apart
		 * then we saw then in micro-seconds.
		 */
		if (peer_delta < (delta + ((delta * (uint64_t)1000)/ (uint64_t)bbr_delta_percent))) {
			/* well it looks like the peer is a micro-second clock. */
			bbr->rc_ts_clock_set = 1;
			bbr->r_ctl.bbr_peer_tsratio = 1;
		} else {
			bbr->rc_ts_cant_be_used = 1;
			bbr->rc_ts_clock_set = 1;
		}
		return;
	}
	/* Ok we know that the peer_delta is smaller than our send distance */
	bbr->rc_ts_clock_set = 1;
	/* First question is it within the percentage that they are using usec time? */
	delta_up = (peer_delta * 1000) / (uint64_t)bbr_delta_percent;
	if ((peer_delta + delta_up) >= delta) {
		/* Its a usec clock */
		bbr->r_ctl.bbr_peer_tsratio = 1;
		return;
	}
	/* Ok if not usec, what about 10usec (though unlikely)? */
	delta_up = (peer_delta * 1000 * 10) / (uint64_t)bbr_delta_percent;
	if (((peer_delta * 10) + delta_up) >= delta) {
		bbr->r_ctl.bbr_peer_tsratio = 10;
		return;
	}
	/* And what about 100usec (though again unlikely)? */
	delta_up = (peer_delta * 1000 * 100) / (uint64_t)bbr_delta_percent;
	if (((peer_delta * 100) + delta_up) >= delta) {
		bbr->r_ctl.bbr_peer_tsratio = 100;
		return;
	}
	/* And how about 1 msec (the most likely one)? */
	delta_up = (peer_delta * 1000 * 1000) / (uint64_t)bbr_delta_percent;
	if (((peer_delta * 1000) + delta_up) >= delta) {
		bbr->r_ctl.bbr_peer_tsratio = 1000;
		return;
	}
	/* Ok if not msec could it be 10 msec? */
	delta_up = (peer_delta * 1000 * 10000) / (uint64_t)bbr_delta_percent;
	if (((peer_delta * 10000) + delta_up) >= delta) {
		bbr->r_ctl.bbr_peer_tsratio = 10000;
		return;
	}
	/* If we fall down here the clock tick so slowly we can't use it */
	bbr->rc_ts_cant_be_used = 1;
	bbr->r_ctl.bbr_peer_tsratio = 0;
}

/*
 * Collect new round-trip time estimate
 * and update averages and current timeout.
 */
static void
tcp_bbr_xmit_timer_commit(struct tcp_bbr *bbr, struct tcpcb *tp, uint32_t cts)
{
	int32_t delta;
	uint32_t rtt;
	int32_t rtt_ticks;

	if (bbr->rtt_valid == 0)
		/* No valid sample */
		return;

	rtt = bbr->r_ctl.cur_rtt;
	if (bbr->rc_prtt_set_ts) {
		/*
		 * We are to force feed the rttProp filter due
		 * to an entry into PROBE_RTT. This assures
		 * that the times are sync'd between when we
		 * go into PROBE_RTT and the filter expiration.
		 *
		 * Google does not use a true filter, so they do
		 * this implicitly since they only keep one value
		 * and when they enter probe-rtt they update the
		 * value to the newest rtt.
		 */
		uint32_t rtt_prop;

		bbr->rc_prtt_set_ts = 0;
		rtt_prop = get_filter_value_small(&bbr->r_ctl.rc_rttprop);
		if (rtt > rtt_prop)
			filter_increase_by_small(&bbr->r_ctl.rc_rttprop, (rtt - rtt_prop), cts);
		else
			apply_filter_min_small(&bbr->r_ctl.rc_rttprop, rtt, cts);
	}
	if (bbr->rc_ack_was_delayed)
		rtt += bbr->r_ctl.rc_ack_hdwr_delay;

	if (rtt < bbr->r_ctl.rc_lowest_rtt)
		bbr->r_ctl.rc_lowest_rtt = rtt;
	if (bbr->r_init_rtt) {
		/*
		 * The initial rtt is not-trusted, nuke it and lets get
		 * our first valid measurement in.
		 */
		bbr->r_init_rtt = 0;
		tp->t_srtt = 0;
	}
	if ((bbr->rc_ts_clock_set == 0) && bbr->rc_ts_valid) {
		/*
		 * So we have not yet figured out
		 * what the peers TSTMP value is
		 * in (most likely ms). We need a
		 * series of cum-ack's to determine
		 * this reliably.
		 */
		if (bbr->rc_ack_is_cumack) {
			if (bbr->rc_ts_data_set) {
				/* Lets attempt to determine the timestamp granularity. */
				bbr_make_timestamp_determination(bbr);
			} else {
				bbr->rc_ts_data_set = 1;
				bbr->r_ctl.bbr_ts_check_tstmp = bbr->r_ctl.last_inbound_ts;
				bbr->r_ctl.bbr_ts_check_our_cts = bbr->r_ctl.cur_rtt_send_time;
			}
		} else {
			/*
			 * We have to have consecutive acks
			 * reset any "filled" state to none.
			 */
			bbr->rc_ts_data_set = 0;
		}
	}
	/* Round it up */
	rtt_ticks = USEC_2_TICKS((rtt + (USECS_IN_MSEC - 1)));
	if (rtt_ticks == 0)
		rtt_ticks = 1;
	if (tp->t_srtt != 0) {
		/*
		 * srtt is stored as fixed point with 5 bits after the
		 * binary point (i.e., scaled by 8).  The following magic is
		 * equivalent to the smoothing algorithm in rfc793 with an
		 * alpha of .875 (srtt = rtt/8 + srtt*7/8 in fixed point).
		 * Adjust rtt to origin 0.
		 */

		delta = ((rtt_ticks - 1) << TCP_DELTA_SHIFT)
		    - (tp->t_srtt >> (TCP_RTT_SHIFT - TCP_DELTA_SHIFT));

		tp->t_srtt += delta;
		if (tp->t_srtt <= 0)
			tp->t_srtt = 1;

		/*
		 * We accumulate a smoothed rtt variance (actually, a
		 * smoothed mean difference), then set the retransmit timer
		 * to smoothed rtt + 4 times the smoothed variance. rttvar
		 * is stored as fixed point with 4 bits after the binary
		 * point (scaled by 16).  The following is equivalent to
		 * rfc793 smoothing with an alpha of .75 (rttvar =
		 * rttvar*3/4 + |delta| / 4).  This replaces rfc793's
		 * wired-in beta.
		 */
		if (delta < 0)
			delta = -delta;
		delta -= tp->t_rttvar >> (TCP_RTTVAR_SHIFT - TCP_DELTA_SHIFT);
		tp->t_rttvar += delta;
		if (tp->t_rttvar <= 0)
			tp->t_rttvar = 1;
		if (tp->t_rttbest > tp->t_srtt + tp->t_rttvar)
			tp->t_rttbest = tp->t_srtt + tp->t_rttvar;
	} else {
		/*
		 * No rtt measurement yet - use the unsmoothed rtt. Set the
		 * variance to half the rtt (so our first retransmit happens
		 * at 3*rtt).
		 */
		tp->t_srtt = rtt_ticks << TCP_RTT_SHIFT;
		tp->t_rttvar = rtt_ticks << (TCP_RTTVAR_SHIFT - 1);
		tp->t_rttbest = tp->t_srtt + tp->t_rttvar;
	}
	KMOD_TCPSTAT_INC(tcps_rttupdated);
	tp->t_rttupdated++;
	/*
	 * the retransmit should happen at rtt + 4 * rttvar. Because of the
	 * way we do the smoothing, srtt and rttvar will each average +1/2
	 * tick of bias.  When we compute the retransmit timer, we want 1/2
	 * tick of rounding and 1 extra tick because of +-1/2 tick
	 * uncertainty in the firing of the timer.  The bias will give us
	 * exactly the 1.5 tick we need.  But, because the bias is
	 * statistical, we have to test that we don't drop below the minimum
	 * feasible timer (which is 2 ticks).
	 */
	TCPT_RANGESET(tp->t_rxtcur, TCP_REXMTVAL(tp),
	    max(MSEC_2_TICKS(bbr->r_ctl.rc_min_rto_ms), rtt_ticks + 2),
	    MSEC_2_TICKS(((uint32_t)bbr->rc_max_rto_sec) * 1000));

	/*
	 * We received an ack for a packet that wasn't retransmitted; it is
	 * probably safe to discard any error indications we've received
	 * recently.  This isn't quite right, but close enough for now (a
	 * route might have failed after we sent a segment, and the return
	 * path might not be symmetrical).
	 */
	tp->t_softerror = 0;
	rtt = (TICKS_2_USEC(bbr->rc_tp->t_srtt) >> TCP_RTT_SHIFT);
	if (bbr->r_ctl.bbr_smallest_srtt_this_state > rtt)
		bbr->r_ctl.bbr_smallest_srtt_this_state = rtt;
}

static void
bbr_set_reduced_rtt(struct tcp_bbr *bbr, uint32_t cts, uint32_t line)
{
	bbr->r_ctl.rc_rtt_shrinks = cts;
	if (bbr_can_force_probertt &&
	    (TSTMP_GT(cts, bbr->r_ctl.last_in_probertt)) &&
	    ((cts - bbr->r_ctl.last_in_probertt) > bbr->r_ctl.rc_probertt_int)) {
		/*
		 * We should enter probe-rtt its been too long
		 * since we have been there.
		 */
		bbr_enter_probe_rtt(bbr, cts, __LINE__);
	} else
		bbr_check_probe_rtt_limits(bbr, cts);
}

static void
tcp_bbr_commit_bw(struct tcp_bbr *bbr, uint32_t cts)
{
	uint64_t orig_bw;

	if (bbr->r_ctl.rc_bbr_cur_del_rate == 0) {
		/* We never apply a zero measurement */
		return;
	}
	if (bbr->r_ctl.r_measurement_count < 0xffffffff)
		bbr->r_ctl.r_measurement_count++;
	orig_bw = get_filter_value(&bbr->r_ctl.rc_delrate);
	apply_filter_max(&bbr->r_ctl.rc_delrate, bbr->r_ctl.rc_bbr_cur_del_rate, bbr->r_ctl.rc_pkt_epoch);
	if (orig_bw &&
	    (orig_bw != get_filter_value(&bbr->r_ctl.rc_delrate))) {
		if (bbr->bbr_hdrw_pacing) {
			/*
			 * Apply a new rate to the hardware
			 * possibly.
			 */
			bbr_update_hardware_pacing_rate(bbr, cts);
		}
		bbr_set_state_target(bbr, __LINE__);
		tcp_bbr_tso_size_check(bbr, cts);
		if (bbr->r_recovery_bw)  {
			bbr_setup_red_bw(bbr, cts);
		}
	} else if ((orig_bw == 0) && get_filter_value(&bbr->r_ctl.rc_delrate))
		tcp_bbr_tso_size_check(bbr, cts);
}

static void
bbr_nf_measurement(struct tcp_bbr *bbr, struct bbr_sendmap *rsm, uint32_t rtt, uint32_t cts)
{
	if (bbr->rc_in_persist == 0) {
		/* We log only when not in persist */
		/* Translate to a Bytes Per Second */
		uint64_t tim, bw, ts_diff, ts_bw;
#if 0
		uint32_t upper, lower, delivered;
#else
		uint32_t delivered;
#endif

		if (TSTMP_GT(bbr->r_ctl.rc_del_time, rsm->r_del_time))
			tim = (uint64_t)(bbr->r_ctl.rc_del_time - rsm->r_del_time);
		else
			tim = 1;
		/*
		 * Now that we have processed the tim (skipping the sample
		 * or possibly updating the time, go ahead and
		 * calculate the cdr.
		 */
		delivered = (bbr->r_ctl.rc_delivered - rsm->r_delivered);
		bw = (uint64_t)delivered;
		bw *= (uint64_t)USECS_IN_SECOND;
		bw /= tim;
		if (bw == 0) {
			/* We must have a calculatable amount */
			return;
		}
#if 0
		upper = (bw >> 32) & 0x00000000ffffffff;
		lower = bw & 0x00000000ffffffff;
#endif
		/*
		 * If we are using this b/w shove it in now so we
		 * can see in the trace viewer if it gets over-ridden.
		 */
		if (rsm->r_ts_valid &&
		    bbr->rc_ts_valid &&
		    bbr->rc_ts_clock_set &&
		    (bbr->rc_ts_cant_be_used == 0) &&
		    bbr->rc_use_ts_limit) {
			ts_diff = max((bbr->r_ctl.last_inbound_ts - rsm->r_del_ack_ts), 1);
			ts_diff *= bbr->r_ctl.bbr_peer_tsratio;
			if ((delivered == 0) ||
			    (rtt < 1000)) {
				/* Can't use the ts */
			} else {
				ts_bw = (uint64_t)delivered;
				ts_bw *= (uint64_t)USECS_IN_SECOND;
				ts_bw /= ts_diff;
				if ((bbr->ts_can_raise) &&
				    (ts_bw > bw)) {
					bw = ts_bw;
				} else if (ts_bw && (ts_bw < bw)) {
					bw = ts_bw;
				}
			}
		}
		if (rsm->r_first_sent_time &&
		    TSTMP_GT(rsm->r_tim_lastsent[(rsm->r_rtr_cnt -1)],rsm->r_first_sent_time)) {
			uint64_t sbw, sti;
			/*
			 * We use what was in flight at the time of our
			 * send  and the size of this send to figure
			 * out what we have been sending at (amount).
			 * For the time we take from the time of
			 * the send of the first send outstanding
			 * until this send plus this sends pacing
			 * time. This gives us a good calculation
			 * as to the rate we have been sending at.
			 */

			sbw = (uint64_t)(rsm->r_flight_at_send);
			sbw *= (uint64_t)USECS_IN_SECOND;
			sti = rsm->r_tim_lastsent[(rsm->r_rtr_cnt -1)] - rsm->r_first_sent_time;
			sti += rsm->r_pacing_delay;
			sbw /= sti;
			if (sbw < bw) {
				bw = sbw;
			}
		}
		/* Use the google algorithm for b/w measurements */
		bbr->r_ctl.rc_bbr_cur_del_rate = bw;
		if ((rsm->r_app_limited == 0) ||
		    (bw > get_filter_value(&bbr->r_ctl.rc_delrate))) {
			tcp_bbr_commit_bw(bbr, cts);
		}
	}
}

static void
bbr_google_measurement(struct tcp_bbr *bbr, struct bbr_sendmap *rsm, uint32_t rtt, uint32_t cts)
{
	if (bbr->rc_in_persist == 0) {
		/* We log only when not in persist */
		/* Translate to a Bytes Per Second */
		uint64_t tim, bw;
#if 0
		uint32_t upper, lower, delivered;
#else
		uint32_t delivered;
#endif
		int no_apply = 0;

		if (TSTMP_GT(bbr->r_ctl.rc_del_time, rsm->r_del_time))
			tim = (uint64_t)(bbr->r_ctl.rc_del_time - rsm->r_del_time);
		else
			tim = 1;
		/*
		 * Now that we have processed the tim (skipping the sample
		 * or possibly updating the time, go ahead and
		 * calculate the cdr.
		 */
		delivered = (bbr->r_ctl.rc_delivered - rsm->r_delivered);
		bw = (uint64_t)delivered;
		bw *= (uint64_t)USECS_IN_SECOND;
		bw /= tim;
		if (tim < bbr->r_ctl.rc_lowest_rtt) {
			no_apply = 1;
		}
#if 0
		upper = (bw >> 32) & 0x00000000ffffffff;
		lower = bw & 0x00000000ffffffff;
#endif
		/*
		 * If we are using this b/w shove it in now so we
		 * can see in the trace viewer if it gets over-ridden.
		 */
		bbr->r_ctl.rc_bbr_cur_del_rate = bw;
		/* Gate by the sending rate */
		if (rsm->r_first_sent_time &&
		    TSTMP_GT(rsm->r_tim_lastsent[(rsm->r_rtr_cnt -1)],rsm->r_first_sent_time)) {
			uint64_t sbw, sti;
			/*
			 * We use what was in flight at the time of our
			 * send  and the size of this send to figure
			 * out what we have been sending at (amount).
			 * For the time we take from the time of
			 * the send of the first send outstanding
			 * until this send plus this sends pacing
			 * time. This gives us a good calculation
			 * as to the rate we have been sending at.
			 */

			sbw = (uint64_t)(rsm->r_flight_at_send);
			sbw *= (uint64_t)USECS_IN_SECOND;
			sti = rsm->r_tim_lastsent[(rsm->r_rtr_cnt -1)] - rsm->r_first_sent_time;
			sti += rsm->r_pacing_delay;
			sbw /= sti;
			if (sbw < bw) {
				bw = sbw;
			}
			if ((sti > tim) &&
			    (sti < bbr->r_ctl.rc_lowest_rtt)) {
				no_apply = 1;
			} else
				no_apply = 0;
		}
		bbr->r_ctl.rc_bbr_cur_del_rate = bw;
		if ((no_apply == 0) &&
		    ((rsm->r_app_limited == 0) ||
		     (bw > get_filter_value(&bbr->r_ctl.rc_delrate)))) {
			tcp_bbr_commit_bw(bbr, cts);
		}
	}
}

static void
bbr_update_bbr_info(struct tcp_bbr *bbr, struct bbr_sendmap *rsm, uint32_t rtt, uint32_t cts, uint32_t tsin,
    uint32_t uts, int32_t match, uint32_t rsm_send_time, int32_t ack_type, struct tcpopt *to)
{
	uint64_t old_rttprop;

	/* Update our delivery time and amount */
	bbr->r_ctl.rc_delivered += (rsm->r_end - rsm->r_start);
	bbr->r_ctl.rc_del_time = cts;
	if (rtt == 0) {
		/*
		 * 0 means its a retransmit, for now we don't use these for
		 * the rest of BBR.
		 */
		return;
	}
	if ((bbr->rc_use_google == 0) &&
	    (match != BBR_RTT_BY_EXACTMATCH) &&
	    (match != BBR_RTT_BY_TIMESTAMP)){
		/*
		 * We get a lot of rtt updates, lets not pay attention to
		 * any that are not an exact match. That way we don't have
		 * to worry about timestamps and the whole nonsense of
		 * unsure if its a retransmission etc (if we ever had the
		 * timestamp fixed to always have the last thing sent this
		 * would not be a issue).
		 */
		return;
	}
	if ((bbr_no_retran && bbr->rc_use_google) &&
	    (match != BBR_RTT_BY_EXACTMATCH) &&
	    (match != BBR_RTT_BY_TIMESTAMP)){
		/*
		 * We only do measurements in google mode
		 * with bbr_no_retran on for sure things.
		 */
		return;
	}
	/* Only update srtt if we know by exact match */
	tcp_bbr_xmit_timer(bbr, rtt, rsm_send_time, rsm->r_start, tsin);
	if (ack_type == BBR_CUM_ACKED)
		bbr->rc_ack_is_cumack = 1;
	else
		bbr->rc_ack_is_cumack = 0;
	old_rttprop = bbr_get_rtt(bbr, BBR_RTT_PROP);
	/*
	 * Note the following code differs to the original
	 * BBR spec. It calls for <= not <. However after a
	 * long discussion in email with Neal, he acknowledged
	 * that it should be < than so that we will have flows
	 * going into probe-rtt (we were seeing cases where that
	 * did not happen and caused ugly things to occur). We
	 * have added this agreed upon fix to our code base.
	 */
	if (rtt < old_rttprop) {
		/* Update when we last saw a rtt drop */
		bbr_set_reduced_rtt(bbr, cts, __LINE__);
	}
	apply_filter_min_small(&bbr->r_ctl.rc_rttprop, rtt, cts);
	if (old_rttprop != bbr_get_rtt(bbr, BBR_RTT_PROP)) {
		/*
		 * The RTT-prop moved, reset the target (may be a
		 * nop for some states).
		 */
		bbr_set_state_target(bbr, __LINE__);
		if (bbr->rc_bbr_state == BBR_STATE_PROBE_RTT)
			;
		else if (old_rttprop < bbr_get_rtt(bbr, BBR_RTT_PROP))
			/* It went up */
			bbr_check_probe_rtt_limits(bbr, cts);
	}
	if ((bbr->rc_use_google == 0) &&
	    (match == BBR_RTT_BY_TIMESTAMP)) {
		/*
		 * We don't do b/w update with
		 * these since they are not really
		 * reliable.
		 */
		return;
	}
	if (bbr->r_ctl.r_app_limited_until &&
	    (bbr->r_ctl.rc_delivered >= bbr->r_ctl.r_app_limited_until)) {
		/* We are no longer app-limited */
		bbr->r_ctl.r_app_limited_until = 0;
	}
	if (bbr->rc_use_google) {
		bbr_google_measurement(bbr, rsm, rtt, cts);
	} else {
		bbr_nf_measurement(bbr, rsm, rtt, cts);
	}
}

/*
 * Convert a timestamp that the main stack
 * uses (milliseconds) into one that bbr uses
 * (microseconds). Return that converted timestamp.
 */
static uint32_t
bbr_ts_convert(uint32_t cts) {
	uint32_t sec, msec;

	sec = cts / MS_IN_USEC;
	msec = cts - (MS_IN_USEC * sec);
	return ((sec * USECS_IN_SECOND) + (msec * MS_IN_USEC));
}

/*
 * Return 0 if we did not update the RTT time, return
 * 1 if we did.
 */
static int
bbr_update_rtt(struct tcpcb *tp, struct tcp_bbr *bbr,
    struct bbr_sendmap *rsm, struct tcpopt *to, uint32_t cts, int32_t ack_type, uint32_t th_ack)
{
	int32_t i;
	uint32_t t, uts = 0;

	if ((rsm->r_flags & BBR_ACKED) ||
	    (rsm->r_flags & BBR_WAS_RENEGED) ||
	    (rsm->r_flags & BBR_RXT_CLEARED)) {
		/* Already done */
		return (0);
	}
	if (rsm->r_rtt_not_allowed) {
		/* Not allowed */
		return (0);
	}
	if (rsm->r_rtr_cnt == 1) {
		/*
		 * Only one transmit. Hopefully the normal case.
		 */
		if (TSTMP_GT(cts, rsm->r_tim_lastsent[0]))
			t = cts - rsm->r_tim_lastsent[0];
		else
			t = 1;
		if ((int)t <= 0)
			t = 1;
		bbr->r_ctl.rc_last_rtt = t;
		bbr_update_bbr_info(bbr, rsm, t, cts, to->to_tsecr, 0,
				    BBR_RTT_BY_EXACTMATCH, rsm->r_tim_lastsent[0], ack_type, to);
		return (1);
	}
	/* Convert to usecs */
	if ((bbr_can_use_ts_for_rtt == 1) &&
	    (bbr->rc_use_google == 1) &&
	    (ack_type == BBR_CUM_ACKED) &&
	    (to->to_flags & TOF_TS) &&
	    (to->to_tsecr != 0)) {
		t = tcp_tv_to_mssectick(&bbr->rc_tv) - to->to_tsecr;
		if (t < 1)
			t = 1;
		t *= MS_IN_USEC;
		bbr_update_bbr_info(bbr, rsm, t, cts, to->to_tsecr, 0,
				    BBR_RTT_BY_TIMESTAMP,
				    rsm->r_tim_lastsent[(rsm->r_rtr_cnt-1)],
				    ack_type, to);
		return (1);
	}
	uts = bbr_ts_convert(to->to_tsecr);
	if ((to->to_flags & TOF_TS) &&
	    (to->to_tsecr != 0) &&
	    (ack_type == BBR_CUM_ACKED) &&
	    ((rsm->r_flags & BBR_OVERMAX) == 0)) {
		/*
		 * Now which timestamp does it match? In this block the ACK
		 * may be coming from a previous transmission.
		 */
		uint32_t fudge;

		fudge = BBR_TIMER_FUDGE;
		for (i = 0; i < rsm->r_rtr_cnt; i++) {
			if ((SEQ_GEQ(uts, (rsm->r_tim_lastsent[i] - fudge))) &&
			    (SEQ_LEQ(uts, (rsm->r_tim_lastsent[i] + fudge)))) {
				if (TSTMP_GT(cts, rsm->r_tim_lastsent[i]))
					t = cts - rsm->r_tim_lastsent[i];
				else
					t = 1;
				if ((int)t <= 0)
					t = 1;
				bbr->r_ctl.rc_last_rtt = t;
				bbr_update_bbr_info(bbr, rsm, t, cts, to->to_tsecr, uts, BBR_RTT_BY_TSMATCHING,
						    rsm->r_tim_lastsent[i], ack_type, to);
				if ((i + 1) < rsm->r_rtr_cnt) {
					/* Likely */
					return (0);
				} else if (rsm->r_flags & BBR_TLP) {
					bbr->rc_tlp_rtx_out = 0;
				}
				return (1);
			}
		}
		/* Fall through if we can't find a matching timestamp */
	}
	/*
	 * Ok its a SACK block that we retransmitted. or a windows
	 * machine without timestamps. We can tell nothing from the
	 * time-stamp since its not there or the time the peer last
	 * recieved a segment that moved forward its cum-ack point.
	 *
	 * Lets look at the last retransmit and see what we can tell
	 * (with BBR for space we only keep 2 note we have to keep
	 * at least 2 so the map can not be condensed more).
	 */
	i = rsm->r_rtr_cnt - 1;
	if (TSTMP_GT(cts, rsm->r_tim_lastsent[i]))
		t = cts - rsm->r_tim_lastsent[i];
	else
		goto not_sure;
	if (t < bbr->r_ctl.rc_lowest_rtt) {
		/*
		 * We retransmitted and the ack came back in less
		 * than the smallest rtt we have observed in the
		 * windowed rtt. We most likey did an improper
		 * retransmit as outlined in 4.2 Step 3 point 2 in
		 * the rack-draft.
		 *
		 * Use the prior transmission to update all the
		 * information as long as there is only one prior
		 * transmission.
		 */
		if ((rsm->r_flags & BBR_OVERMAX) == 0) {
			i = rsm->r_rtr_cnt - 2;
			if (TSTMP_GT(cts, rsm->r_tim_lastsent[i]))
				t = cts - rsm->r_tim_lastsent[i];
			else
				t = 1;
			bbr_update_bbr_info(bbr, rsm, t, cts, to->to_tsecr, uts, BBR_RTT_BY_EARLIER_RET,
					    rsm->r_tim_lastsent[i], ack_type, to);
			return (0);
		} else {
			/*
			 * Too many prior transmissions, just
			 * updated BBR delivered
			 */
not_sure:
			bbr_update_bbr_info(bbr, rsm, 0, cts, to->to_tsecr, uts,
					    BBR_RTT_BY_SOME_RETRAN, 0, ack_type, to);
		}
	} else {
		/*
		 * We retransmitted it and the retransmit did the
		 * job.
		 */
		if (rsm->r_flags & BBR_TLP)
			bbr->rc_tlp_rtx_out = 0;
		if ((rsm->r_flags & BBR_OVERMAX) == 0)
			bbr_update_bbr_info(bbr, rsm, t, cts, to->to_tsecr, uts,
					    BBR_RTT_BY_THIS_RETRAN, 0, ack_type, to);
		else
			bbr_update_bbr_info(bbr, rsm, 0, cts, to->to_tsecr, uts,
					    BBR_RTT_BY_SOME_RETRAN, 0, ack_type, to);
		return (1);
	}
	return (0);
}

/*
 * Mark the SACK_PASSED flag on all entries prior to rsm send wise.
 */
static void
bbr_log_sack_passed(struct tcpcb *tp,
    struct tcp_bbr *bbr, struct bbr_sendmap *rsm)
{
	struct bbr_sendmap *nrsm;

	nrsm = rsm;
	TAILQ_FOREACH_REVERSE_FROM(nrsm, &bbr->r_ctl.rc_tmap,
	    bbr_head, r_tnext) {
		if (nrsm == rsm) {
			/* Skip orginal segment he is acked */
			continue;
		}
		if (nrsm->r_flags & BBR_ACKED) {
			/* Skip ack'd segments */
			continue;
		}
		if (nrsm->r_flags & BBR_SACK_PASSED) {
			/*
			 * We found one that is already marked
			 * passed, we have been here before and
			 * so all others below this are marked.
			 */
			break;
		}
		BBR_STAT_INC(bbr_sack_passed);
		nrsm->r_flags |= BBR_SACK_PASSED;
		if (((nrsm->r_flags & BBR_MARKED_LOST) == 0) &&
		    bbr_is_lost(bbr, nrsm, bbr->r_ctl.rc_rcvtime)) {
			bbr->r_ctl.rc_lost += nrsm->r_end - nrsm->r_start;
			bbr->r_ctl.rc_lost_bytes += nrsm->r_end - nrsm->r_start;
			nrsm->r_flags |= BBR_MARKED_LOST;
		}
		nrsm->r_flags &= ~BBR_WAS_SACKPASS;
	}
}

/*
 * Returns the number of bytes that were
 * newly ack'd by sack blocks.
 */
static uint32_t
bbr_proc_sack_blk(struct tcpcb *tp, struct tcp_bbr *bbr, struct sackblk *sack,
    struct tcpopt *to, struct bbr_sendmap **prsm, uint32_t cts)
{
	int32_t times = 0;
	uint32_t start, end, changed = 0;
	struct bbr_sendmap *rsm, *nrsm;
	int32_t used_ref = 1;
	uint8_t went_back = 0, went_fwd = 0;

	start = sack->start;
	end = sack->end;
	rsm = *prsm;
	if (rsm == NULL)
		used_ref = 0;

	/* Do we locate the block behind where we last were? */
	if (rsm && SEQ_LT(start, rsm->r_start)) {
		went_back = 1;
		TAILQ_FOREACH_REVERSE_FROM(rsm, &bbr->r_ctl.rc_map, bbr_head, r_next) {
			if (SEQ_GEQ(start, rsm->r_start) &&
			    SEQ_LT(start, rsm->r_end)) {
				goto do_rest_ofb;
			}
		}
	}
start_at_beginning:
	went_fwd = 1;
	/*
	 * Ok lets locate the block where this guy is fwd from rsm (if its
	 * set)
	 */
	TAILQ_FOREACH_FROM(rsm, &bbr->r_ctl.rc_map, r_next) {
		if (SEQ_GEQ(start, rsm->r_start) &&
		    SEQ_LT(start, rsm->r_end)) {
			break;
		}
	}
do_rest_ofb:
	if (rsm == NULL) {
		/*
		 * This happens when we get duplicate sack blocks with the
		 * same end. For example SACK 4: 100 SACK 3: 100 The sort
		 * will not change there location so we would just start at
		 * the end of the first one and get lost.
		 */
		if (tp->t_flags & TF_SENTFIN) {
			/*
			 * Check to see if we have not logged the FIN that
			 * went out.
			 */
			nrsm = TAILQ_LAST_FAST(&bbr->r_ctl.rc_map, bbr_sendmap, r_next);
			if (nrsm && (nrsm->r_end + 1) == tp->snd_max) {
				/*
				 * Ok we did not get the FIN logged.
				 */
				nrsm->r_end++;
				rsm = nrsm;
				goto do_rest_ofb;
			}
		}
		if (times == 1) {
			goto out;
		}
		times++;
		BBR_STAT_INC(bbr_sack_proc_restart);
		rsm = NULL;
		goto start_at_beginning;
	}
	/* Ok we have an ACK for some piece of rsm */
	if (rsm->r_start != start) {
		/*
		 * Need to split this in two pieces the before and after.
		 */
		if (bbr_sack_mergable(rsm, start, end))
			nrsm = bbr_alloc_full_limit(bbr);
		else
			nrsm = bbr_alloc_limit(bbr, BBR_LIMIT_TYPE_SPLIT);
		if (nrsm == NULL) {
			/* We could not allocate ignore the sack */
			struct sackblk blk;

			blk.start = start;
			blk.end = end;
			sack_filter_reject(&bbr->r_ctl.bbr_sf, &blk);
			goto out;
		}
		bbr_clone_rsm(bbr, nrsm, rsm, start);
		TAILQ_INSERT_AFTER(&bbr->r_ctl.rc_map, rsm, nrsm, r_next);
		if (rsm->r_in_tmap) {
			TAILQ_INSERT_AFTER(&bbr->r_ctl.rc_tmap, rsm, nrsm, r_tnext);
			nrsm->r_in_tmap = 1;
		}
		rsm->r_flags &= (~BBR_HAS_FIN);
		rsm = nrsm;
	}
	if (SEQ_GEQ(end, rsm->r_end)) {
		/*
		 * The end of this block is either beyond this guy or right
		 * at this guy.
		 */
		if ((rsm->r_flags & BBR_ACKED) == 0) {
			bbr_update_rtt(tp, bbr, rsm, to, cts, BBR_SACKED, 0);
			changed += (rsm->r_end - rsm->r_start);
			bbr->r_ctl.rc_sacked += (rsm->r_end - rsm->r_start);
			bbr_log_sack_passed(tp, bbr, rsm);
			if (rsm->r_flags & BBR_MARKED_LOST) {
				bbr->r_ctl.rc_lost_bytes -= rsm->r_end - rsm->r_start;
			}
			/* Is Reordering occuring? */
			if (rsm->r_flags & BBR_SACK_PASSED) {
				BBR_STAT_INC(bbr_reorder_seen);
				bbr->r_ctl.rc_reorder_ts = cts;
				if (rsm->r_flags & BBR_MARKED_LOST) {
					bbr->r_ctl.rc_lost -= rsm->r_end - rsm->r_start;
					if (SEQ_GT(bbr->r_ctl.rc_lt_lost, bbr->r_ctl.rc_lost))
						/* LT sampling also needs adjustment */
						bbr->r_ctl.rc_lt_lost = bbr->r_ctl.rc_lost;
				}
			}
			rsm->r_flags |= BBR_ACKED;
			rsm->r_flags &= ~(BBR_TLP|BBR_WAS_RENEGED|BBR_RXT_CLEARED|BBR_MARKED_LOST);
			if (rsm->r_in_tmap) {
				TAILQ_REMOVE(&bbr->r_ctl.rc_tmap, rsm, r_tnext);
				rsm->r_in_tmap = 0;
			}
		}
		bbr_isit_a_pkt_epoch(bbr, cts, rsm, __LINE__, BBR_SACKED);
		if (end == rsm->r_end) {
			/* This block only - done */
			goto out;
		}
		/* There is more not coverend by this rsm move on */
		start = rsm->r_end;
		nrsm = TAILQ_NEXT(rsm, r_next);
		rsm = nrsm;
		times = 0;
		goto do_rest_ofb;
	}
	if (rsm->r_flags & BBR_ACKED) {
		/* Been here done that */
		goto out;
	}
	/* Ok we need to split off this one at the tail */
	if (bbr_sack_mergable(rsm, start, end))
		nrsm = bbr_alloc_full_limit(bbr);
	else
		nrsm = bbr_alloc_limit(bbr, BBR_LIMIT_TYPE_SPLIT);
	if (nrsm == NULL) {
		/* failed XXXrrs what can we do but loose the sack info? */
		struct sackblk blk;

		blk.start = start;
		blk.end = end;
		sack_filter_reject(&bbr->r_ctl.bbr_sf, &blk);
		goto out;
	}
	/* Clone it */
	bbr_clone_rsm(bbr, nrsm, rsm, end);
	/* The sack block does not cover this guy fully */
	rsm->r_flags &= (~BBR_HAS_FIN);
	TAILQ_INSERT_AFTER(&bbr->r_ctl.rc_map, rsm, nrsm, r_next);
	if (rsm->r_in_tmap) {
		TAILQ_INSERT_AFTER(&bbr->r_ctl.rc_tmap, rsm, nrsm, r_tnext);
		nrsm->r_in_tmap = 1;
	}
	nrsm->r_dupack = 0;
	bbr_update_rtt(tp, bbr, rsm, to, cts, BBR_SACKED, 0);
	bbr_isit_a_pkt_epoch(bbr, cts, rsm, __LINE__, BBR_SACKED);
	changed += (rsm->r_end - rsm->r_start);
	bbr->r_ctl.rc_sacked += (rsm->r_end - rsm->r_start);
	bbr_log_sack_passed(tp, bbr, rsm);
	/* Is Reordering occuring? */
	if (rsm->r_flags & BBR_MARKED_LOST) {
		bbr->r_ctl.rc_lost_bytes -= rsm->r_end - rsm->r_start;
	}
	if (rsm->r_flags & BBR_SACK_PASSED) {
		BBR_STAT_INC(bbr_reorder_seen);
		bbr->r_ctl.rc_reorder_ts = cts;
		if (rsm->r_flags & BBR_MARKED_LOST) {
			bbr->r_ctl.rc_lost -= rsm->r_end - rsm->r_start;
			if (SEQ_GT(bbr->r_ctl.rc_lt_lost, bbr->r_ctl.rc_lost))
				/* LT sampling also needs adjustment */
				bbr->r_ctl.rc_lt_lost = bbr->r_ctl.rc_lost;
		}
	}
	rsm->r_flags &= ~(BBR_TLP|BBR_WAS_RENEGED|BBR_RXT_CLEARED|BBR_MARKED_LOST);
	rsm->r_flags |= BBR_ACKED;
	if (rsm->r_in_tmap) {
		TAILQ_REMOVE(&bbr->r_ctl.rc_tmap, rsm, r_tnext);
		rsm->r_in_tmap = 0;
	}
out:
	if (rsm && (rsm->r_flags & BBR_ACKED)) {
		/*
		 * Now can we merge this newly acked
		 * block with either the previous or
		 * next block?
		 */
		nrsm = TAILQ_NEXT(rsm, r_next);
		if (nrsm &&
		    (nrsm->r_flags & BBR_ACKED)) {
			/* yep this and next can be merged */
			rsm = bbr_merge_rsm(bbr, rsm, nrsm);
		}
		/* Now what about the previous? */
		nrsm = TAILQ_PREV(rsm, bbr_head, r_next);
		if (nrsm &&
		    (nrsm->r_flags & BBR_ACKED)) {
			/* yep the previous and this can be merged */
			rsm = bbr_merge_rsm(bbr, nrsm, rsm);
		}
	}
	if (used_ref == 0) {
		BBR_STAT_INC(bbr_sack_proc_all);
	} else {
		BBR_STAT_INC(bbr_sack_proc_short);
	}
	if (went_fwd && went_back) {
		BBR_STAT_INC(bbr_sack_search_both);
	} else if (went_fwd) {
		BBR_STAT_INC(bbr_sack_search_fwd);
	} else if (went_back) {
		BBR_STAT_INC(bbr_sack_search_back);
	}
	/* Save off where the next seq is */
	if (rsm)
		bbr->r_ctl.rc_sacklast = TAILQ_NEXT(rsm, r_next);
	else
		bbr->r_ctl.rc_sacklast = NULL;
	*prsm = rsm;
	return (changed);
}

static void inline
bbr_peer_reneges(struct tcp_bbr *bbr, struct bbr_sendmap *rsm, tcp_seq th_ack)
{
	struct bbr_sendmap *tmap;

	BBR_STAT_INC(bbr_reneges_seen);
	tmap = NULL;
	while (rsm && (rsm->r_flags & BBR_ACKED)) {
		/* Its no longer sacked, mark it so */
		bbr->r_ctl.rc_sacked -= (rsm->r_end - rsm->r_start);
		if (rsm->r_flags & BBR_MARKED_LOST) {
			bbr->r_ctl.rc_lost -= rsm->r_end - rsm->r_start;
			bbr->r_ctl.rc_lost_bytes -= rsm->r_end - rsm->r_start;
			if (SEQ_GT(bbr->r_ctl.rc_lt_lost, bbr->r_ctl.rc_lost))
				/* LT sampling also needs adjustment */
				bbr->r_ctl.rc_lt_lost = bbr->r_ctl.rc_lost;
		}
		rsm->r_flags &= ~(BBR_ACKED | BBR_SACK_PASSED | BBR_WAS_SACKPASS | BBR_MARKED_LOST);
		rsm->r_flags |= BBR_WAS_RENEGED;
		rsm->r_flags |= BBR_RXT_CLEARED;
		/* Rebuild it into our tmap */
		if (tmap == NULL) {
			TAILQ_INSERT_HEAD(&bbr->r_ctl.rc_tmap, rsm, r_tnext);
			tmap = rsm;
		} else {
			TAILQ_INSERT_AFTER(&bbr->r_ctl.rc_tmap, tmap, rsm, r_tnext);
			tmap = rsm;
		}
		tmap->r_in_tmap = 1;
		/*
		 * XXXrrs Delivered? Should we do anything here?
		 *
		 * Of course we don't on a rxt timeout so maybe its ok that
		 * we don't?
		 *
		 * For now lets not.
		 */
		rsm = TAILQ_NEXT(rsm, r_next);
	}
	/*
	 * Now lets possibly clear the sack filter so we start recognizing
	 * sacks that cover this area.
	 */
	sack_filter_clear(&bbr->r_ctl.bbr_sf, th_ack);
}

static void
bbr_log_syn(struct tcpcb *tp, struct tcpopt *to)
{
	struct tcp_bbr *bbr;
	struct bbr_sendmap *rsm;
	uint32_t cts;

	bbr = (struct tcp_bbr *)tp->t_fb_ptr;
	cts = bbr->r_ctl.rc_rcvtime;
	rsm = TAILQ_FIRST(&bbr->r_ctl.rc_map);
	if (rsm && (rsm->r_flags & BBR_HAS_SYN)) {
		if ((rsm->r_end - rsm->r_start) <= 1) {
			/* Log out the SYN completely */
			bbr->r_ctl.rc_holes_rxt -= rsm->r_rtr_bytes;
			rsm->r_rtr_bytes = 0;
			TAILQ_REMOVE(&bbr->r_ctl.rc_map, rsm, r_next);
			if (rsm->r_in_tmap) {
				TAILQ_REMOVE(&bbr->r_ctl.rc_tmap, rsm, r_tnext);
				rsm->r_in_tmap = 0;
			}
			if (bbr->r_ctl.rc_next == rsm) {
				/* scoot along the marker */
				bbr->r_ctl.rc_next = TAILQ_FIRST(&bbr->r_ctl.rc_map);
			}
			if (to != NULL)
				bbr_update_rtt(tp, bbr, rsm, to, cts, BBR_CUM_ACKED, 0);
			bbr_free(bbr, rsm);
		} else {
			/* There is more (Fast open)? strip out SYN. */
			rsm->r_flags &= ~BBR_HAS_SYN;
			rsm->r_start++;
		}
	}
}

/*
 * Returns the number of bytes that were
 * acknowledged by SACK blocks.
 */

static uint32_t
bbr_log_ack(struct tcpcb *tp, struct tcpopt *to, struct tcphdr *th,
    uint32_t *prev_acked)
{
	uint32_t changed, last_seq, entered_recovery = 0;
	struct tcp_bbr *bbr;
	struct bbr_sendmap *rsm;
	struct sackblk sack, sack_blocks[TCP_MAX_SACK + 1];
	register uint32_t th_ack;
	int32_t i, j, k, new_sb, num_sack_blks = 0;
	uint32_t cts, acked, ack_point, sack_changed = 0;
	uint32_t p_maxseg, maxseg, p_acked = 0;

	if (th->th_flags & TH_RST) {
		/* We don't log resets */
		return (0);
	}
	bbr = (struct tcp_bbr *)tp->t_fb_ptr;
	cts = bbr->r_ctl.rc_rcvtime;

	rsm = TAILQ_FIRST(&bbr->r_ctl.rc_map);
	changed = 0;
	maxseg = tp->t_maxseg - bbr->rc_last_options;
	p_maxseg = min(bbr->r_ctl.rc_pace_max_segs, maxseg);
	th_ack = th->th_ack;
	if (SEQ_GT(th_ack, tp->snd_una)) {
		acked = th_ack - tp->snd_una;
		bbr->rc_tp->t_acktime = ticks;
	} else
		acked = 0;
	if (SEQ_LEQ(th_ack, tp->snd_una)) {
		/* Only sent here for sack processing */
		goto proc_sack;
	}
	if (rsm && SEQ_GT(th_ack, rsm->r_start)) {
		changed = th_ack - rsm->r_start;
	} else if ((rsm == NULL) && ((th_ack - 1) == tp->iss)) {
		/*
		 * For the SYN incoming case we will not have called
		 * tcp_output for the sending of the SYN, so there will be
		 * no map. All other cases should probably be a panic.
		 */
		if ((to->to_flags & TOF_TS) && (to->to_tsecr != 0)) {
			/*
			 * We have a timestamp that can be used to generate
			 * an initial RTT.
			 */
			uint32_t ts, now, rtt;

			ts = bbr_ts_convert(to->to_tsecr);
			now = bbr_ts_convert(tcp_tv_to_mssectick(&bbr->rc_tv));
			rtt = now - ts;
			if (rtt < 1)
				rtt = 1;
			apply_filter_min_small(&bbr->r_ctl.rc_rttprop, rtt, cts);
			changed = 1;
			bbr->r_wanted_output = 1;
			goto out;
		}
		goto proc_sack;
	} else if (rsm == NULL) {
		goto out;
	}
	if (changed) {
		/*
		 * The ACK point is advancing to th_ack, we must drop off
		 * the packets in the rack log and calculate any eligble
		 * RTT's.
		 */
		bbr->r_wanted_output = 1;
more:
		if (rsm == NULL) {
			if (tp->t_flags & TF_SENTFIN) {
				/* if we send a FIN we will not hav a map */
				goto proc_sack;
			}
			goto proc_sack;
		}
	}
	if (SEQ_LT(th_ack, rsm->r_start)) {
		/* Huh map is missing this */
		goto proc_sack;
	} else if (th_ack == rsm->r_start) {
		/* None here to ack */
		goto proc_sack;
	}
	/*
	 * Clear the dup ack counter, it will
	 * either be freed or if there is some
	 * remaining we need to start it at zero.
	 */
	rsm->r_dupack = 0;
	/* Now do we consume the whole thing? */
	if (SEQ_GEQ(th_ack, rsm->r_end)) {
		/* Its all consumed. */
		uint32_t left;

		if (rsm->r_flags & BBR_ACKED) {
			/*
			 * It was acked on the scoreboard -- remove it from
			 * total
			 */
			p_acked += (rsm->r_end - rsm->r_start);
			bbr->r_ctl.rc_sacked -= (rsm->r_end - rsm->r_start);
			if (bbr->r_ctl.rc_sacked == 0)
				bbr->r_ctl.rc_sacklast = NULL;
		} else {
			bbr_update_rtt(tp, bbr, rsm, to, cts, BBR_CUM_ACKED, th_ack);
			if (rsm->r_flags & BBR_MARKED_LOST) {
				bbr->r_ctl.rc_lost_bytes -= rsm->r_end - rsm->r_start;
			}
			if (rsm->r_flags & BBR_SACK_PASSED) {
				/*
				 * There are acked segments ACKED on the
				 * scoreboard further up. We are seeing
				 * reordering.
				 */
				BBR_STAT_INC(bbr_reorder_seen);
				bbr->r_ctl.rc_reorder_ts = cts;
				if (rsm->r_flags & BBR_MARKED_LOST) {
					bbr->r_ctl.rc_lost -= rsm->r_end - rsm->r_start;
					if (SEQ_GT(bbr->r_ctl.rc_lt_lost, bbr->r_ctl.rc_lost))
						/* LT sampling also needs adjustment */
						bbr->r_ctl.rc_lt_lost = bbr->r_ctl.rc_lost;
				}
			}
			rsm->r_flags &= ~BBR_MARKED_LOST;
		}
		bbr->r_ctl.rc_holes_rxt -= rsm->r_rtr_bytes;
		rsm->r_rtr_bytes = 0;
		TAILQ_REMOVE(&bbr->r_ctl.rc_map, rsm, r_next);
		if (rsm->r_in_tmap) {
			TAILQ_REMOVE(&bbr->r_ctl.rc_tmap, rsm, r_tnext);
			rsm->r_in_tmap = 0;
		}
		if (bbr->r_ctl.rc_next == rsm) {
			/* scoot along the marker */
			bbr->r_ctl.rc_next = TAILQ_FIRST(&bbr->r_ctl.rc_map);
		}
		bbr_isit_a_pkt_epoch(bbr, cts, rsm, __LINE__, BBR_CUM_ACKED);
		/* Adjust the packet counts */
		left = th_ack - rsm->r_end;
		/* Free back to zone */
		bbr_free(bbr, rsm);
		if (left) {
			rsm = TAILQ_FIRST(&bbr->r_ctl.rc_map);
			goto more;
		}
		goto proc_sack;
	}
	if (rsm->r_flags & BBR_ACKED) {
		/*
		 * It was acked on the scoreboard -- remove it from total
		 * for the part being cum-acked.
		 */
		p_acked += (rsm->r_end - rsm->r_start);
		bbr->r_ctl.rc_sacked -= (th_ack - rsm->r_start);
		if (bbr->r_ctl.rc_sacked == 0)
			bbr->r_ctl.rc_sacklast = NULL;
	} else {
		/*
		 * It was acked up to th_ack point for the first time
		 */
		struct bbr_sendmap lrsm;

		memcpy(&lrsm, rsm, sizeof(struct bbr_sendmap));
		lrsm.r_end = th_ack;
		bbr_update_rtt(tp, bbr, &lrsm, to, cts, BBR_CUM_ACKED, th_ack);
	}
	if ((rsm->r_flags & BBR_MARKED_LOST) &&
	    ((rsm->r_flags & BBR_ACKED) == 0)) {
		/*
		 * It was marked lost and partly ack'd now
		 * for the first time. We lower the rc_lost_bytes
		 * and still leave it MARKED.
		 */
		bbr->r_ctl.rc_lost_bytes -= th_ack - rsm->r_start;
	}
	bbr_isit_a_pkt_epoch(bbr, cts, rsm, __LINE__, BBR_CUM_ACKED);
	bbr->r_ctl.rc_holes_rxt -= rsm->r_rtr_bytes;
	rsm->r_rtr_bytes = 0;
	/* adjust packet count */
	rsm->r_start = th_ack;
proc_sack:
	/* Check for reneging */
	rsm = TAILQ_FIRST(&bbr->r_ctl.rc_map);
	if (rsm && (rsm->r_flags & BBR_ACKED) && (th_ack == rsm->r_start)) {
		/*
		 * The peer has moved snd_una up to the edge of this send,
		 * i.e. one that it had previously acked. The only way that
		 * can be true if the peer threw away data (space issues)
		 * that it had previously sacked (else it would have given
		 * us snd_una up to (rsm->r_end). We need to undo the acked
		 * markings here.
		 *
		 * Note we have to look to make sure th_ack is our
		 * rsm->r_start in case we get an old ack where th_ack is
		 * behind snd_una.
		 */
		bbr_peer_reneges(bbr, rsm, th->th_ack);
	}
	if ((to->to_flags & TOF_SACK) == 0) {
		/* We are done nothing left to log */
		goto out;
	}
	rsm = TAILQ_LAST_FAST(&bbr->r_ctl.rc_map, bbr_sendmap, r_next);
	if (rsm) {
		last_seq = rsm->r_end;
	} else {
		last_seq = tp->snd_max;
	}
	/* Sack block processing */
	if (SEQ_GT(th_ack, tp->snd_una))
		ack_point = th_ack;
	else
		ack_point = tp->snd_una;
	for (i = 0; i < to->to_nsacks; i++) {
		bcopy((to->to_sacks + i * TCPOLEN_SACK),
		    &sack, sizeof(sack));
		sack.start = ntohl(sack.start);
		sack.end = ntohl(sack.end);
		if (SEQ_GT(sack.end, sack.start) &&
		    SEQ_GT(sack.start, ack_point) &&
		    SEQ_LT(sack.start, tp->snd_max) &&
		    SEQ_GT(sack.end, ack_point) &&
		    SEQ_LEQ(sack.end, tp->snd_max)) {
			if ((bbr->r_ctl.rc_num_small_maps_alloced > bbr_sack_block_limit) &&
			    (SEQ_LT(sack.end, last_seq)) &&
			    ((sack.end - sack.start) < (p_maxseg / 8))) {
				/*
				 * Not the last piece and its smaller than
				 * 1/8th of a p_maxseg. We ignore this.
				 */
				BBR_STAT_INC(bbr_runt_sacks);
				continue;
			}
			sack_blocks[num_sack_blks] = sack;
			num_sack_blks++;
#if 0
                        /* TREX_FBSD: remove warning: array-bounds */
                        if (num_sack_blks > sizeof(sack_blocks)/sizeof(sack_blocks[0])) {
                            break;
                        }
#endif
		}
	}
	if (num_sack_blks == 0)
		goto out;
	/*
	 * Sort the SACK blocks so we can update the rack scoreboard with
	 * just one pass.
	 */
	new_sb = sack_filter_blks(&bbr->r_ctl.bbr_sf, sack_blocks,
				  num_sack_blks, th->th_ack);
#if 0
	ctf_log_sack_filter(bbr->rc_tp, new_sb, sack_blocks);
#endif
	BBR_STAT_ADD(bbr_sack_blocks, num_sack_blks);
	BBR_STAT_ADD(bbr_sack_blocks_skip, (num_sack_blks - new_sb));
	num_sack_blks = new_sb;
	if (num_sack_blks < 2) {
		goto do_sack_work;
	}
        /* TREX_FBSD: remove warning: array-bounds */
        num_sack_blks = min(num_sack_blks, sizeof(sack_blocks)/sizeof(sack_blocks[0]));
	/* Sort the sacks */
	for (i = 0; i < num_sack_blks; i++) {
		for (j = i + 1; j < num_sack_blks; j++) {
			if (SEQ_GT(sack_blocks[i].end, sack_blocks[j].end)) {
				sack = sack_blocks[i];
				sack_blocks[i] = sack_blocks[j];
				sack_blocks[j] = sack;
			}
		}
	}
	/*
	 * Now are any of the sack block ends the same (yes some
	 * implememtations send these)?
	 */
again:
	if (num_sack_blks > 1) {
		for (i = 0; i < num_sack_blks; i++) {
			for (j = i + 1; j < num_sack_blks; j++) {
				if (sack_blocks[i].end == sack_blocks[j].end) {
					/*
					 * Ok these two have the same end we
					 * want the smallest end and then
					 * throw away the larger and start
					 * again.
					 */
					if (SEQ_LT(sack_blocks[j].start, sack_blocks[i].start)) {
						/*
						 * The second block covers
						 * more area use that
						 */
						sack_blocks[i].start = sack_blocks[j].start;
					}
					/*
					 * Now collapse out the dup-sack and
					 * lower the count
					 */
					for (k = (j + 1); k < num_sack_blks; k++) {
						sack_blocks[j].start = sack_blocks[k].start;
						sack_blocks[j].end = sack_blocks[k].end;
						j++;
					}
					num_sack_blks--;
					goto again;
				}
			}
		}
	}
do_sack_work:
	rsm = bbr->r_ctl.rc_sacklast;
	for (i = 0; i < num_sack_blks; i++) {
		acked = bbr_proc_sack_blk(tp, bbr, &sack_blocks[i], to, &rsm, cts);
		if (acked) {
			bbr->r_wanted_output = 1;
			changed += acked;
			sack_changed += acked;
		}
	}
out:
	*prev_acked = p_acked;
	if ((sack_changed) && (!IN_RECOVERY(tp->t_flags))) {
		/*
		 * Ok we have a high probability that we need to go in to
		 * recovery since we have data sack'd
		 */
		struct bbr_sendmap *rsm;

		rsm = bbr_check_recovery_mode(tp, bbr, cts);
		if (rsm) {
			/* Enter recovery */
			entered_recovery = 1;
			bbr->r_wanted_output = 1;
			/*
			 * When we enter recovery we need to assure we send
			 * one packet.
			 */
			if (bbr->r_ctl.rc_resend == NULL) {
				bbr->r_ctl.rc_resend = rsm;
			}
		}
	}
	if (IN_RECOVERY(tp->t_flags) && (entered_recovery == 0)) {
		/*
		 * See if we need to rack-retransmit anything if so set it
		 * up as the thing to resend assuming something else is not
		 * already in that position.
		 */
		if (bbr->r_ctl.rc_resend == NULL) {
			bbr->r_ctl.rc_resend = bbr_check_recovery_mode(tp, bbr, cts);
		}
	}
	/*
	 * We return the amount that changed via sack, this is used by the
	 * ack-received code to augment what was changed between th_ack <->
	 * snd_una.
	 */
	return (sack_changed);
}

static void
bbr_strike_dupack(struct tcp_bbr *bbr)
{
	struct bbr_sendmap *rsm;

	rsm = TAILQ_FIRST(&bbr->r_ctl.rc_tmap);
	if (rsm && (rsm->r_dupack < 0xff)) {
		rsm->r_dupack++;
		if (rsm->r_dupack >= DUP_ACK_THRESHOLD)
			bbr->r_wanted_output = 1;
	}
}

static inline uint16_t
tcp_nsegs(int tlen, struct tcpcb *tp, struct tcphdr *th)
{
    int optlen = ((int)th->th_off << 2) - sizeof(struct tcphdr);
    int segsz = tp->t_maxseg - optlen;
    /* tcp segment size per packet should be tcp_mss - optlen. */
    return (tlen + segsz - 1)/segsz;
}

/*
 * Return value of 1, we do not need to call bbr_process_data().
 * return value of 0, bbr_process_data can be called.
 * For ret_val if its 0 the TCB is locked and valid, if its non-zero
 * its unlocked and probably unsafe to touch the TCB.
 */
static int
bbr_process_ack(struct mbuf *m, struct tcphdr *th, struct socket *so,
    struct tcpcb *tp, struct tcpopt *to,
    uint32_t tiwin, int32_t tlen,
    int32_t * ofia, int32_t thflags, int32_t * ret_val)
{
	int32_t ourfinisacked = 0;
	int32_t acked_amount;
	uint16_t nsegs;
	int32_t acked;
	uint32_t lost, sack_changed = 0;
	struct tcp_bbr *bbr;
	uint32_t prev_acked = 0;

	bbr = (struct tcp_bbr *)tp->t_fb_ptr;
	lost = bbr->r_ctl.rc_lost;
        nsegs = tlen ? tcp_nsegs(tlen, tp, th): 1;
	if (SEQ_GT(th->th_ack, tp->snd_max)) {
		ctf_do_dropafterack(m, tp, th, thflags, tlen, ret_val);
		bbr->r_wanted_output = 1;
		return (1);
	}
	if (SEQ_GEQ(th->th_ack, tp->snd_una) || to->to_nsacks) {
		/* Process the ack */
		if (bbr->rc_in_persist)
			tp->t_rxtshift = 0;
		if ((th->th_ack == tp->snd_una) && (tiwin == tp->snd_wnd))
		        bbr_strike_dupack(bbr);
		sack_changed = bbr_log_ack(tp, to, th, &prev_acked);
	}
	bbr_lt_bw_sampling(bbr, bbr->r_ctl.rc_rcvtime, (bbr->r_ctl.rc_lost > lost));
	if (__predict_false(SEQ_LEQ(th->th_ack, tp->snd_una))) {
		/*
		 * Old ack, behind the last one rcv'd or a duplicate ack
		 * with SACK info.
		 */
		if (th->th_ack == tp->snd_una) {
			bbr_ack_received(tp, bbr, th, 0, sack_changed, prev_acked, __LINE__, 0);
			if (bbr->r_state == TCPS_SYN_SENT) {
				/*
				 * Special case on where we sent SYN. When
				 * the SYN-ACK is processed in syn_sent
				 * state it bumps the snd_una. This causes
				 * us to hit here even though we did ack 1
				 * byte.
				 *
				 * Go through the nothing left case so we
				 * send data.
				 */
				goto nothing_left;
			}
		}
		return (0);
	}
	/*
	 * If we reach this point, ACK is not a duplicate, i.e., it ACKs
	 * something we sent.
	 */
	if (tp->t_flags & TF_NEEDSYN) {
		/*
		 * T/TCP: Connection was half-synchronized, and our SYN has
		 * been ACK'd (so connection is now fully synchronized).  Go
		 * to non-starred state, increment snd_una for ACK of SYN,
		 * and check if we can do window scaling.
		 */
		tp->t_flags &= ~TF_NEEDSYN;
		tp->snd_una++;
		/* Do window scaling? */
		if ((tp->t_flags & (TF_RCVD_SCALE | TF_REQ_SCALE)) ==
		    (TF_RCVD_SCALE | TF_REQ_SCALE)) {
			tp->rcv_scale = tp->request_r_scale;
			/* Send window already scaled. */
		}
	}

	acked = BYTES_THIS_ACK(tp, th);
	KMOD_TCPSTAT_ADD(tcps_rcvackpack, (int)nsegs);
	KMOD_TCPSTAT_ADD(tcps_rcvackbyte, acked);

	/*
	 * If we just performed our first retransmit, and the ACK arrives
	 * within our recovery window, then it was a mistake to do the
	 * retransmit in the first place.  Recover our original cwnd and
	 * ssthresh, and proceed to transmit where we left off.
	 */
	if (tp->t_flags & TF_PREVVALID) {
		tp->t_flags &= ~TF_PREVVALID;
		if (tp->t_rxtshift == 1 &&
		    (int)(ticks - tp->t_badrxtwin) < 0)
			bbr_cong_signal(tp, th, CC_RTO_ERR, NULL);
	}
	acked_amount = min(acked, (int)sbavail(&so->so_snd));
	tp->snd_wnd -= acked_amount;
	sbdrop(&so->so_snd, acked_amount, so);
	/* NB: sowwakeup_locked() does an implicit unlock. */
	sowwakeup(so);
	if (SEQ_GT(th->th_ack, tp->snd_una)) {
		bbr_collapse_rtt(tp, bbr, TCP_REXMTVAL(tp));
	}
	tp->snd_una = th->th_ack;
	bbr_ack_received(tp, bbr, th, acked, sack_changed, prev_acked, __LINE__, (bbr->r_ctl.rc_lost - lost));
	if (IN_RECOVERY(tp->t_flags)) {
		if (SEQ_LT(th->th_ack, tp->snd_recover) &&
		    (SEQ_LT(th->th_ack, tp->snd_max))) {
			tcp_bbr_partialack(tp);
		} else {
			bbr_post_recovery(tp);
		}
	}
	if (SEQ_GT(tp->snd_una, tp->snd_recover)) {
		tp->snd_recover = tp->snd_una;
	}
	if (SEQ_LT(tp->snd_nxt, tp->snd_max)) {
		tp->snd_nxt = tp->snd_max;
	}
	if (tp->snd_una == tp->snd_max) {
		/* Nothing left outstanding */
nothing_left:
		if (sbavail(&tcp_getsocket(tp)->so_snd) == 0)
			bbr->rc_tp->t_acktime = 0;
		if ((sbused(&so->so_snd) == 0) &&
		    (tp->t_flags & TF_SENTFIN)) {
			ourfinisacked = 1;
		}
		bbr_timer_cancel(bbr, __LINE__, bbr->r_ctl.rc_rcvtime);
		if (bbr->rc_in_persist == 0) {
			bbr->r_ctl.rc_went_idle_time = bbr->r_ctl.rc_rcvtime;
		}
		sack_filter_clear(&bbr->r_ctl.bbr_sf, tp->snd_una);
		/*
		 * We invalidate the last ack here since we
		 * don't want to transfer forward the time
		 * for our sum's calculations.
		 */
		if ((tp->t_state >= TCPS_FIN_WAIT_1) &&
		    (sbavail(&so->so_snd) == 0) &&
		    (tp->t_flags2 & TF2_DROP_AF_DATA)) {
			/*
			 * The socket was gone and the peer sent data, time
			 * to reset him.
			 */
			*ret_val = 1;
			tcp_log_end_status(tp, TCP_EI_STATUS_DATA_A_CLOSE);
			/* tcp_close will kill the inp pre-log the Reset */
			tcp_log_end_status(tp, TCP_EI_STATUS_SERVER_RST);
			tp = tcp_close(tp);
			ctf_do_dropwithreset(m, tp, th, BANDLIM_UNLIMITED, tlen);
			BBR_STAT_INC(bbr_dropped_af_data);
			return (1);
		}
		/* Set need output so persist might get set */
		bbr->r_wanted_output = 1;
	}
	if (ofia)
		*ofia = ourfinisacked;
	return (0);
}

static void
bbr_enter_persist(struct tcpcb *tp, struct tcp_bbr *bbr, uint32_t cts, int32_t line)
{
	if (bbr->rc_in_persist == 0) {
		bbr_timer_cancel(bbr, __LINE__, cts);
		bbr->r_ctl.rc_last_delay_val = 0;
		tp->t_rxtshift = 0;
		bbr->rc_in_persist = 1;
		bbr->r_ctl.rc_went_idle_time = cts;
		/* We should be capped when rw went to 0 but just in case */
		/* Time freezes for the state, so do the accounting now */
		if (SEQ_GT(cts, bbr->r_ctl.rc_bbr_state_time)) {
			uint32_t time_in;

			time_in = cts - bbr->r_ctl.rc_bbr_state_time;
			if (bbr->rc_bbr_state == BBR_STATE_PROBE_BW) {
				int32_t idx;

				idx = bbr_state_val(bbr);
				counter_u64_add(bbr_state_time[(idx + 5)], time_in);
			} else {
				counter_u64_add(bbr_state_time[bbr->rc_bbr_state], time_in);
			}
		}
		bbr->r_ctl.rc_bbr_state_time = cts;
	}
}

static void
bbr_restart_after_idle(struct tcp_bbr *bbr, uint32_t cts, uint32_t idle_time)
{
	/*
	 * Note that if idle time does not exceed our
	 * threshold, we do nothing continuing the state
	 * transitions we were last walking through.
	 */
	if (idle_time >= bbr_idle_restart_threshold) {
		if (bbr->rc_use_idle_restart) {
			bbr->rc_bbr_state = BBR_STATE_IDLE_EXIT;
			/*
			 * Set our target using BBR_UNIT, so
			 * we increase at a dramatic rate but
			 * we stop when we get the pipe
			 * full again for our current b/w estimate.
			 */
			bbr->r_ctl.rc_bbr_hptsi_gain = BBR_UNIT;
			bbr->r_ctl.rc_bbr_cwnd_gain = BBR_UNIT;
			bbr_set_state_target(bbr, __LINE__);
			/* Now setup our gains to ramp up */
			bbr->r_ctl.rc_bbr_hptsi_gain = bbr->r_ctl.rc_startup_pg;
			bbr->r_ctl.rc_bbr_cwnd_gain = bbr->r_ctl.rc_startup_pg;
		} else if (bbr->rc_bbr_state == BBR_STATE_PROBE_BW) {
			bbr_substate_change(bbr, cts, __LINE__, 1);
		}
	}
}

static void
bbr_exit_persist(struct tcpcb *tp, struct tcp_bbr *bbr, uint32_t cts, int32_t line)
{
	uint32_t idle_time;

	if (bbr->rc_in_persist == 0)
		return;
	idle_time = bbr_calc_time(cts, bbr->r_ctl.rc_went_idle_time);
	bbr->rc_in_persist = 0;
	bbr->rc_hit_state_1 = 0;
	bbr->r_ctl.rc_del_time = cts;
	/*
	 * We invalidate the last ack here since we
	 * don't want to transfer forward the time
	 * for our sum's calculations.
	 */
#if 0
	if (bbr->rc_inp->inp_in_hpts) {
		tcp_hpts_remove(bbr->rc_inp, HPTS_REMOVE_OUTPUT);
		bbr->rc_timer_first = 0;
		bbr->r_ctl.rc_hpts_flags = 0;
		bbr->r_ctl.rc_last_delay_val = 0;
		bbr->r_ctl.rc_hptsi_agg_delay = 0;
		bbr->r_agg_early_set = 0;
		bbr->r_ctl.rc_agg_early = 0;
	}
#endif
	if (idle_time >= bbr_rtt_probe_time) {
		/*
		 * This qualifies as a RTT_PROBE session since we drop the
		 * data outstanding to nothing and waited more than
		 * bbr_rtt_probe_time.
		 */
		bbr->r_ctl.last_in_probertt = bbr->r_ctl.rc_rtt_shrinks = cts;
	}
	tp->t_rxtshift = 0;
	/*
	 * If in probeBW and we have persisted more than an RTT lets do
	 * special handling.
	 */
	/* Force a time based epoch */
	bbr_set_epoch(bbr, cts, __LINE__);
	/*
	 * Setup the lost so we don't count anything against the guy
	 * we have been stuck with during persists.
	 */
	bbr->r_ctl.bbr_lost_at_state = bbr->r_ctl.rc_lost;
	/* Time un-freezes for the state */
	bbr->r_ctl.rc_bbr_state_time = cts;
	if ((bbr->rc_bbr_state == BBR_STATE_PROBE_BW) ||
	    (bbr->rc_bbr_state == BBR_STATE_PROBE_RTT)) {
		/*
		 * If we are going back to probe-bw
		 * or probe_rtt, we may need to possibly
		 * do a fast restart.
		 */
		bbr_restart_after_idle(bbr, cts, idle_time);
	}
}

static void
bbr_collapsed_window(struct tcp_bbr *bbr)
{
	/*
	 * Now we must walk the
	 * send map and divide the
	 * ones left stranded. These
	 * guys can't cause us to abort
	 * the connection and are really
	 * "unsent". However if a buggy
	 * client actually did keep some
	 * of the data i.e. collapsed the win
	 * and refused to ack and then opened
	 * the win and acked that data. We would
	 * get into an ack war, the simplier
	 * method then of just pretending we
	 * did not send those segments something
	 * won't work.
	 */
	struct bbr_sendmap *rsm, *nrsm;
	tcp_seq max_seq;
	uint32_t maxseg;
	int can_split = 0;
	int fnd = 0;

	maxseg = bbr->rc_tp->t_maxseg - bbr->rc_last_options;
	max_seq = bbr->rc_tp->snd_una + bbr->rc_tp->snd_wnd;
	TAILQ_FOREACH(rsm, &bbr->r_ctl.rc_map, r_next) {
		/* Find the first seq past or at maxseq */
		if (rsm->r_flags & BBR_RWND_COLLAPSED)
			rsm->r_flags &= ~BBR_RWND_COLLAPSED;
		if (SEQ_GEQ(max_seq, rsm->r_start) &&
		    SEQ_GEQ(rsm->r_end, max_seq)) {
			fnd = 1;
			break;
		}
	}
	bbr->rc_has_collapsed = 0;
	if (!fnd) {
		/* Nothing to do strange */
		return;
	}
	/*
	 * Now can we split?
	 *
	 * We don't want to split if splitting
	 * would generate too many small segments
	 * less we let an attacker fragment our
	 * send_map and leave us out of memory.
	 */
	if ((max_seq != rsm->r_start) &&
	    (max_seq != rsm->r_end)){
		/* can we split? */
		int res1, res2;

		res1 = max_seq - rsm->r_start;
		res2 = rsm->r_end - max_seq;
		if ((res1 >= (maxseg/8)) &&
		    (res2 >= (maxseg/8))) {
			/* No small pieces here */
			can_split = 1;
		} else if (bbr->r_ctl.rc_num_small_maps_alloced < bbr_sack_block_limit) {
			/* We are under the limit */
			can_split = 1;
		}
	}
	/* Ok do we need to split this rsm? */
	if (max_seq == rsm->r_start) {
		/* It's this guy no split required */
		nrsm = rsm;
	} else if (max_seq == rsm->r_end) {
		/* It's the next one no split required. */
		nrsm = TAILQ_NEXT(rsm, r_next);
		if (nrsm == NULL) {
			/* Huh? */
			return;
		}
	} else if (can_split && SEQ_LT(max_seq, rsm->r_end)) {
		/* yep we need to split it */
		nrsm = bbr_alloc_limit(bbr, BBR_LIMIT_TYPE_SPLIT);
		if (nrsm == NULL) {
			/* failed XXXrrs what can we do mark the whole? */
			nrsm = rsm;
			goto no_split;
		}
		/* Clone it */
		bbr_clone_rsm(bbr, nrsm, rsm, max_seq);
		TAILQ_INSERT_AFTER(&bbr->r_ctl.rc_map, rsm, nrsm, r_next);
		if (rsm->r_in_tmap) {
			TAILQ_INSERT_AFTER(&bbr->r_ctl.rc_tmap, rsm, nrsm, r_tnext);
			nrsm->r_in_tmap = 1;
		}
	} else {
		/*
		 * Split not allowed just start here just
		 * use this guy.
		 */
		nrsm = rsm;
	}
no_split:
	BBR_STAT_INC(bbr_collapsed_win);
	/* reuse fnd as a count */
	fnd = 0;
	TAILQ_FOREACH_FROM(nrsm, &bbr->r_ctl.rc_map, r_next) {
		nrsm->r_flags |= BBR_RWND_COLLAPSED;
		fnd++;
		bbr->rc_has_collapsed = 1;
	}
}

static void
bbr_un_collapse_window(struct tcp_bbr *bbr)
{
	struct bbr_sendmap *rsm;
	int cleared = 0;

	TAILQ_FOREACH_REVERSE(rsm, &bbr->r_ctl.rc_map, bbr_head, r_next) {
		if (rsm->r_flags & BBR_RWND_COLLAPSED) {
			/* Clear the flag */
			rsm->r_flags &= ~BBR_RWND_COLLAPSED;
			cleared++;
		} else
			break;
	}
	bbr->rc_has_collapsed = 0;
}

/*
 * Return value of 1, the TCB is unlocked and most
 * likely gone, return value of 0, the TCB is still
 * locked.
 */
static int
bbr_process_data(struct mbuf *m, struct tcphdr *th, struct socket *so,
    struct tcpcb *tp, int32_t drop_hdrlen, int32_t tlen,
    uint32_t tiwin, int32_t thflags, int32_t nxt_pkt)
{
	/*
	 * Update window information. Don't look at window if no ACK: TAC's
	 * send garbage on first SYN.
	 */
	uint16_t nsegs;
	struct tcp_bbr *bbr;

	bbr = (struct tcp_bbr *)tp->t_fb_ptr;
	nsegs = tlen ? tcp_nsegs(tlen, tp, th): 1;
	if ((thflags & TH_ACK) &&
	    (SEQ_LT(tp->snd_wl1, th->th_seq) ||
	    (tp->snd_wl1 == th->th_seq && (SEQ_LT(tp->snd_wl2, th->th_ack) ||
	    (tp->snd_wl2 == th->th_ack && tiwin > tp->snd_wnd))))) {
		/* keep track of pure window updates */
		if (tlen == 0 &&
		    tp->snd_wl2 == th->th_ack && tiwin > tp->snd_wnd)
			KMOD_TCPSTAT_INC(tcps_rcvwinupd);
		tp->snd_wnd = tiwin;
		tp->snd_wl1 = th->th_seq;
		tp->snd_wl2 = th->th_ack;
		if (tp->snd_wnd > tp->max_sndwnd)
			tp->max_sndwnd = tp->snd_wnd;
		bbr->r_wanted_output = 1;
	} else if (thflags & TH_ACK) {
		if ((tp->snd_wl2 == th->th_ack) && (tiwin < tp->snd_wnd)) {
			tp->snd_wnd = tiwin;
			tp->snd_wl1 = th->th_seq;
			tp->snd_wl2 = th->th_ack;
		}
	}
	if (tp->snd_wnd < ctf_outstanding(tp))
		/* The peer collapsed its window on us */
		bbr_collapsed_window(bbr);
 	else if (bbr->rc_has_collapsed)
		bbr_un_collapse_window(bbr);
	/* Was persist timer active and now we have window space? */
	if ((bbr->rc_in_persist != 0) &&
	    (tp->snd_wnd >= min((bbr->r_ctl.rc_high_rwnd/2),
				bbr_minseg(bbr)))) {
		/*
		 * Make the rate persist at end of persist mode if idle long
		 * enough
		 */
		bbr_exit_persist(tp, bbr, bbr->r_ctl.rc_rcvtime, __LINE__);

		/* Make sure we output to start the timer */
		bbr->r_wanted_output = 1;
	}
	/* Do we need to enter persist? */
	if ((bbr->rc_in_persist == 0) &&
	    (tp->snd_wnd < min((bbr->r_ctl.rc_high_rwnd/2), bbr_minseg(bbr))) &&
	    TCPS_HAVEESTABLISHED(tp->t_state) &&
	    (tp->snd_max == tp->snd_una) &&
	    sbavail(&tcp_getsocket(tp)->so_snd) &&
	    (sbavail(&tcp_getsocket(tp)->so_snd) > tp->snd_wnd)) {
		/* No send window.. we must enter persist */
		bbr_enter_persist(tp, bbr, bbr->r_ctl.rc_rcvtime, __LINE__);
	}
	if (tp->t_flags2 & TF2_DROP_AF_DATA) {
		m_freem(m);
		return (0);
	}
	/*
	 * We don't support urgent data but
	 * drag along the up just to make sure
	 * if there is a stack switch no one
	 * is surprised.
	 */
	tp->rcv_up = tp->rcv_nxt;

	/*
	 * Process the segment text, merging it into the TCP sequencing
	 * queue, and arranging for acknowledgment of receipt if necessary.
	 * This process logically involves adjusting tp->rcv_wnd as data is
	 * presented to the user (this happens in tcp_usrreq.c, case
	 * PRU_RCVD).  If a FIN has already been received on this connection
	 * then we just ignore the text.
	 */
	if ((tlen || (thflags & TH_FIN)) &&
	    TCPS_HAVERCVDFIN(tp->t_state) == 0) {
		tcp_seq save_start = th->th_seq;
		tcp_seq save_rnxt  = tp->rcv_nxt;
		int     save_tlen  = tlen;

		m = m_adj_fix(m, drop_hdrlen, tlen);	/* delayed header drop */
		/*
		 * Insert segment which includes th into TCP reassembly
		 * queue with control block tp.  Set thflags to whether
		 * reassembly now includes a segment with FIN.  This handles
		 * the common case inline (segment is the next to be
		 * received on an established connection, and the queue is
		 * empty), avoiding linkage into and removal from the queue
		 * and repetition of various conversions. Set DELACK for
		 * segments received in order, but ack immediately when
		 * segments are out of order (so fast retransmit can work).
		 */
		if (th->th_seq == tp->rcv_nxt &&
		    SEGQ_EMPTY(tp) &&
		    (TCPS_HAVEESTABLISHED(tp->t_state))) {
			if (DELAY_ACK(tp, bbr, nsegs)) {
				bbr->bbr_segs_rcvd += max(1, nsegs);
				tp->t_flags |= TF_DELACK;
				bbr_timer_cancel(bbr, __LINE__, bbr->r_ctl.rc_rcvtime);
			} else {
				bbr->r_wanted_output = 1;
				tp->t_flags |= TF_ACKNOW;
			}
			tp->rcv_nxt += tlen;
			if (tlen &&
			    ((tp->t_flags2 & TF2_FBYTES_COMPLETE) == 0) &&
			    (tp->t_fbyte_in == 0)) {
				tp->t_fbyte_in = ticks;
				if (tp->t_fbyte_in == 0)
					tp->t_fbyte_in = 1;
				if (tp->t_fbyte_out && tp->t_fbyte_in)
					tp->t_flags2 |= TF2_FBYTES_COMPLETE;
			}
			thflags = th->th_flags & TH_FIN;
			KMOD_TCPSTAT_ADD(tcps_rcvpack, (int)nsegs);
			KMOD_TCPSTAT_ADD(tcps_rcvbyte, tlen);
			if (so->so_rcv.sb_state & SBS_CANTRCVMORE)
				m_freem(m);
			else
				sbappendstream_locked(&so->so_rcv, m, 0, so);
			/* NB: sorwakeup_locked() does an implicit unlock. */
			sorwakeup(so);

		} else {
			/*
			 * XXX: Due to the header drop above "th" is
			 * theoretically invalid by now.  Fortunately
			 * m_adj() doesn't actually frees any mbufs when
			 * trimming from the head.
			 */
			tcp_seq temp = save_start;

			thflags = tcp_reass(tp, th, &temp, &tlen, m);
			tp->t_flags |= TF_ACKNOW;
			if (tp->t_flags & TF_WAKESOR) {
				tp->t_flags &= ~TF_WAKESOR;
				/* NB: sorwakeup_locked() does an implicit unlock. */
				sorwakeup(so);
			}
		}
		if ((tp->t_flags & TF_SACK_PERMIT) &&
		    (save_tlen > 0) &&
		    TCPS_HAVEESTABLISHED(tp->t_state)) {
			if ((tlen == 0) && (SEQ_LT(save_start, save_rnxt))) {
				/*
				 * DSACK actually handled in the fastpath
				 * above.
				 */
				tcp_update_sack_list(tp, save_start,
				    save_start + save_tlen);
			} else if ((tlen > 0) && SEQ_GT(tp->rcv_nxt, save_rnxt)) {
				if ((tp->rcv_numsacks >= 1) &&
				    (tp->sackblks[0].end == save_start)) {
					/*
					 * Partial overlap, recorded at todrop
					 * above.
					 */
					tcp_update_sack_list(tp,
					    tp->sackblks[0].start,
					    tp->sackblks[0].end);
				} else {
					tcp_update_dsack_list(tp, save_start,
					    save_start + save_tlen);
				}
			} else if (tlen >= save_tlen) {
				/* Update of sackblks. */
				tcp_update_dsack_list(tp, save_start,
				    save_start + save_tlen);
			} else if (tlen > 0) {
				tcp_update_dsack_list(tp, save_start,
				    save_start + tlen);
			}
		}
	} else {
		m_freem(m);
		thflags &= ~TH_FIN;
	}

	/*
	 * If FIN is received ACK the FIN and let the user know that the
	 * connection is closing.
	 */
	if (thflags & TH_FIN) {
		if (TCPS_HAVERCVDFIN(tp->t_state) == 0) {
			/* The socket upcall is handled by socantrcvmore. */
			socantrcvmore(so);
			/*
			 * If connection is half-synchronized (ie NEEDSYN
			 * flag on) then delay ACK, so it may be piggybacked
			 * when SYN is sent. Otherwise, since we received a
			 * FIN then no more input can be expected, send ACK
			 * now.
			 */
			if (tp->t_flags & TF_NEEDSYN) {
				tp->t_flags |= TF_DELACK;
				bbr_timer_cancel(bbr,
				    __LINE__, bbr->r_ctl.rc_rcvtime);
			} else {
				tp->t_flags |= TF_ACKNOW;
			}
			tp->rcv_nxt++;
		}
		switch (tp->t_state) {
			/*
			 * In SYN_RECEIVED and ESTABLISHED STATES enter the
			 * CLOSE_WAIT state.
			 */
		case TCPS_SYN_RECEIVED:
			tp->t_starttime = ticks;
			/* FALLTHROUGH */
		case TCPS_ESTABLISHED:
			tcp_state_change(tp, TCPS_CLOSE_WAIT);
			break;

			/*
			 * If still in FIN_WAIT_1 STATE FIN has not been
			 * acked so enter the CLOSING state.
			 */
		case TCPS_FIN_WAIT_1:
			tcp_state_change(tp, TCPS_CLOSING);
			break;

			/*
			 * In FIN_WAIT_2 state enter the TIME_WAIT state,
			 * starting the time-wait timer, turning off the
			 * other standard timers.
			 */
		case TCPS_FIN_WAIT_2:
			bbr->rc_timer_first = 1;
			bbr_timer_cancel(bbr,
			    __LINE__, bbr->r_ctl.rc_rcvtime);
                        tcp_state_change(tp, TCPS_TIME_WAIT);
			tcp_timer_twstart(tp);
                        soisdisconnected(so);
			return (1);
		}
	}
	/*
	 * Return any desired output.
	 */
	if ((tp->t_flags & TF_ACKNOW) ||
	    (sbavail(&so->so_snd) > ctf_outstanding(tp))) {
		bbr->r_wanted_output = 1;
	}
	return (0);
}

/*
 * Here nothing is really faster, its just that we
 * have broken out the fast-data path also just like
 * the fast-ack. Return 1 if we processed the packet
 * return 0 if you need to take the "slow-path".
 */
static int
bbr_do_fastnewdata(struct mbuf *m, struct tcphdr *th, struct socket *so,
    struct tcpcb *tp, struct tcpopt *to, int32_t drop_hdrlen, int32_t tlen,
    uint32_t tiwin, int32_t nxt_pkt)
{
	uint16_t nsegs;
	struct tcp_bbr *bbr;
#ifdef TCPDEBUG
	/*
	 * The size of tcp_saveipgen must be the size of the max ip header,
	 * now IPv6.
	 */
	u_char tcp_saveipgen[IP6_HDR_LEN];
	struct tcphdr tcp_savetcp;
	short ostate = 0;

#endif
	/* On the hpts and we would have called output */
	bbr = (struct tcp_bbr *)tp->t_fb_ptr;

	/*
	 * If last ACK falls within this segment's sequence numbers, record
	 * the timestamp. NOTE that the test is modified according to the
	 * latest proposal of the tcplw@cray.com list (Braden 1993/04/26).
	 */
	if (bbr->r_ctl.rc_resend != NULL) {
		return (0);
	}
	if (tiwin && tiwin != tp->snd_wnd) {
		return (0);
	}
	if (__predict_false((tp->t_flags & (TF_NEEDSYN | TF_NEEDFIN)))) {
		return (0);
	}
	if (__predict_false((to->to_flags & TOF_TS) &&
	    (TSTMP_LT(to->to_tsval, tp->ts_recent)))) {
		return (0);
	}
	if (__predict_false((th->th_ack != tp->snd_una))) {
		return (0);
	}
	if (__predict_false(tlen > sbspace(&so->so_rcv))) {
		return (0);
	}
	if ((to->to_flags & TOF_TS) != 0 &&
	    SEQ_LEQ(th->th_seq, tp->last_ack_sent)) {
		tp->ts_recent_age = tcp_tv_to_mssectick(&bbr->rc_tv);
		tp->ts_recent = to->to_tsval;
	}
	/*
	 * This is a pure, in-sequence data packet with nothing on the
	 * reassembly queue and we have enough buffer space to take it.
	 */
	nsegs = tlen ? tcp_nsegs(tlen, tp, th): 1;

	/* Clean receiver SACK report if present */
	if (tp->rcv_numsacks)
		tcp_clean_sackreport(tp);
	KMOD_TCPSTAT_INC(tcps_preddat);
	tp->rcv_nxt += tlen;
	if (tlen &&
	    ((tp->t_flags2 & TF2_FBYTES_COMPLETE) == 0) &&
	    (tp->t_fbyte_in == 0)) {
		tp->t_fbyte_in = ticks;
		if (tp->t_fbyte_in == 0)
			tp->t_fbyte_in = 1;
		if (tp->t_fbyte_out && tp->t_fbyte_in)
			tp->t_flags2 |= TF2_FBYTES_COMPLETE;
	}
	/*
	 * Pull snd_wl1 up to prevent seq wrap relative to th_seq.
	 */
	tp->snd_wl1 = th->th_seq;
	/*
	 * Pull rcv_up up to prevent seq wrap relative to rcv_nxt.
	 */
	tp->rcv_up = tp->rcv_nxt;
	KMOD_TCPSTAT_ADD(tcps_rcvpack, (int)nsegs);
	KMOD_TCPSTAT_ADD(tcps_rcvbyte, tlen);
#ifdef TCPDEBUG
	if (so->so_options & SO_DEBUG)
		tcp_trace(TA_INPUT, ostate, tp,
		    (void *)tcp_saveipgen, &tcp_savetcp, 0);
#endif
	/* Add data to socket buffer. */
	if (so->so_rcv.sb_state & SBS_CANTRCVMORE) {
		m_freem(m);
	} else {
		m = m_adj_fix(m, drop_hdrlen, tlen);	/* delayed header drop */

		sbappendstream_locked(&so->so_rcv, m, 0, so);
		ctf_calc_rwin(so, tp);
	}
	/* NB: sorwakeup_locked() does an implicit unlock. */
	sorwakeup(so);
	if (DELAY_ACK(tp, bbr, nsegs)) {
		bbr->bbr_segs_rcvd += max(1, nsegs);
		tp->t_flags |= TF_DELACK;
		bbr_timer_cancel(bbr, __LINE__, bbr->r_ctl.rc_rcvtime);
	} else {
		bbr->r_wanted_output = 1;
		tp->t_flags |= TF_ACKNOW;
	}
	return (1);
}

/*
 * This subfunction is used to try to highly optimize the
 * fast path. We again allow window updates that are
 * in sequence to remain in the fast-path. We also add
 * in the __predict's to attempt to help the compiler.
 * Note that if we return a 0, then we can *not* process
 * it and the caller should push the packet into the
 * slow-path. If we return 1, then all is well and
 * the packet is fully processed.
 */
static int
bbr_fastack(struct mbuf *m, struct tcphdr *th, struct socket *so,
    struct tcpcb *tp, struct tcpopt *to, int32_t drop_hdrlen, int32_t tlen,
    uint32_t tiwin, int32_t nxt_pkt, uint8_t iptos)
{
	int32_t acked;
	uint16_t nsegs;
	uint32_t sack_changed;
#ifdef TCPDEBUG
	/*
	 * The size of tcp_saveipgen must be the size of the max ip header,
	 * now IPv6.
	 */
	u_char tcp_saveipgen[IP6_HDR_LEN];
	struct tcphdr tcp_savetcp;
	short ostate = 0;

#endif
	uint32_t prev_acked = 0;
	struct tcp_bbr *bbr;

	if (__predict_false(SEQ_LEQ(th->th_ack, tp->snd_una))) {
		/* Old ack, behind (or duplicate to) the last one rcv'd */
		return (0);
	}
	if (__predict_false(SEQ_GT(th->th_ack, tp->snd_max))) {
		/* Above what we have sent? */
		return (0);
	}
	if (__predict_false(tiwin == 0)) {
		/* zero window */
		return (0);
	}
	if (__predict_false(tp->t_flags & (TF_NEEDSYN | TF_NEEDFIN))) {
		/* We need a SYN or a FIN, unlikely.. */
		return (0);
	}
	if ((to->to_flags & TOF_TS) && __predict_false(TSTMP_LT(to->to_tsval, tp->ts_recent))) {
		/* Timestamp is behind .. old ack with seq wrap? */
		return (0);
	}
	if (__predict_false(IN_RECOVERY(tp->t_flags))) {
		/* Still recovering */
		return (0);
	}
	bbr = (struct tcp_bbr *)tp->t_fb_ptr;
	if (__predict_false(bbr->r_ctl.rc_resend != NULL)) {
		/* We are retransmitting */
		return (0);
	}
	if (__predict_false(bbr->rc_in_persist != 0)) {
		/* In persist mode */
		return (0);
	}
	if (bbr->r_ctl.rc_sacked) {
		/* We have sack holes on our scoreboard */
		return (0);
	}
	/* Ok if we reach here, we can process a fast-ack */
	nsegs = tlen ? tcp_nsegs(tlen, tp, th): 1;
	sack_changed = bbr_log_ack(tp, to, th, &prev_acked);
	/*
	 * We never detect loss in fast ack [we can't
	 * have a sack and can't be in recovery so
	 * we always pass 0 (nothing detected)].
	 */
	bbr_lt_bw_sampling(bbr, bbr->r_ctl.rc_rcvtime, 0);
	/* Did the window get updated? */
	if (tiwin != tp->snd_wnd) {
		tp->snd_wnd = tiwin;
		tp->snd_wl1 = th->th_seq;
		if (tp->snd_wnd > tp->max_sndwnd)
			tp->max_sndwnd = tp->snd_wnd;
	}
	/* Do we need to exit persists? */
	if ((bbr->rc_in_persist != 0) &&
	    (tp->snd_wnd >= min((bbr->r_ctl.rc_high_rwnd/2),
			       bbr_minseg(bbr)))) {
		bbr_exit_persist(tp, bbr, bbr->r_ctl.rc_rcvtime, __LINE__);
		bbr->r_wanted_output = 1;
	}
	/* Do we need to enter persists? */
	if ((bbr->rc_in_persist == 0) &&
	    (tp->snd_wnd < min((bbr->r_ctl.rc_high_rwnd/2), bbr_minseg(bbr))) &&
	    TCPS_HAVEESTABLISHED(tp->t_state) &&
	    (tp->snd_max == tp->snd_una) &&
	    sbavail(&tcp_getsocket(tp)->so_snd) &&
	    (sbavail(&tcp_getsocket(tp)->so_snd) > tp->snd_wnd)) {
		/* No send window.. we must enter persist */
		bbr_enter_persist(tp, bbr, bbr->r_ctl.rc_rcvtime, __LINE__);
	}
	/*
	 * If last ACK falls within this segment's sequence numbers, record
	 * the timestamp. NOTE that the test is modified according to the
	 * latest proposal of the tcplw@cray.com list (Braden 1993/04/26).
	 */
	if ((to->to_flags & TOF_TS) != 0 &&
	    SEQ_LEQ(th->th_seq, tp->last_ack_sent)) {
		tp->ts_recent_age = bbr->r_ctl.rc_rcvtime;
		tp->ts_recent = to->to_tsval;
	}
	/*
	 * This is a pure ack for outstanding data.
	 */
	KMOD_TCPSTAT_INC(tcps_predack);

	/*
	 * "bad retransmit" recovery.
	 */
	if (tp->t_flags & TF_PREVVALID) {
		tp->t_flags &= ~TF_PREVVALID;
		if (tp->t_rxtshift == 1 &&
		    (int)(ticks - tp->t_badrxtwin) < 0)
			bbr_cong_signal(tp, th, CC_RTO_ERR, NULL);
	}
	/*
	 * Recalculate the transmit timer / rtt.
	 *
	 * Some boxes send broken timestamp replies during the SYN+ACK
	 * phase, ignore timestamps of 0 or we could calculate a huge RTT
	 * and blow up the retransmit timer.
	 */
	acked = BYTES_THIS_ACK(tp, th);

	KMOD_TCPSTAT_ADD(tcps_rcvackpack, (int)nsegs);
	KMOD_TCPSTAT_ADD(tcps_rcvackbyte, acked);
	sbdrop(&so->so_snd, acked, so);

	if (SEQ_GT(th->th_ack, tp->snd_una))
		bbr_collapse_rtt(tp, bbr, TCP_REXMTVAL(tp));
	tp->snd_una = th->th_ack;
	if (tp->snd_wnd < ctf_outstanding(tp))
		/* The peer collapsed its window on us */
		bbr_collapsed_window(bbr);
	else if (bbr->rc_has_collapsed)
		bbr_un_collapse_window(bbr);

	if (SEQ_GT(tp->snd_una, tp->snd_recover)) {
		tp->snd_recover = tp->snd_una;
	}
	bbr_ack_received(tp, bbr, th, acked, sack_changed, prev_acked, __LINE__, 0);
	/*
	 * Pull snd_wl2 up to prevent seq wrap relative to th_ack.
	 */
	tp->snd_wl2 = th->th_ack;
	m_freem(m);
	/*
	 * If all outstanding data are acked, stop retransmit timer,
	 * otherwise restart timer using current (possibly backed-off)
	 * value. If process is waiting for space, wakeup/selwakeup/signal.
	 * If data are ready to send, let tcp_output decide between more
	 * output or persist.
	 */
#ifdef TCPDEBUG
	if (so->so_options & SO_DEBUG)
		tcp_trace(TA_INPUT, ostate, tp,
		    (void *)tcp_saveipgen,
		    &tcp_savetcp, 0);
#endif
	/* Wake up the socket if we have room to write more */
	sowwakeup(so);
	if (tp->snd_una == tp->snd_max) {
		/* Nothing left outstanding */
		if (sbavail(&tcp_getsocket(tp)->so_snd) == 0)
			bbr->rc_tp->t_acktime = 0;
		bbr_timer_cancel(bbr, __LINE__, bbr->r_ctl.rc_rcvtime);
		if (bbr->rc_in_persist == 0) {
			bbr->r_ctl.rc_went_idle_time = bbr->r_ctl.rc_rcvtime;
		}
		sack_filter_clear(&bbr->r_ctl.bbr_sf, tp->snd_una);
		/*
		 * We invalidate the last ack here since we
		 * don't want to transfer forward the time
		 * for our sum's calculations.
		 */
		bbr->r_wanted_output = 1;
	}
	if (sbavail(&so->so_snd)) {
		bbr->r_wanted_output = 1;
	}
	return (1);
}

/*
 * Return value of 1, the TCB is unlocked and most
 * likely gone, return value of 0, the TCB is still
 * locked.
 */
static int
bbr_do_syn_sent(struct mbuf *m, struct tcphdr *th, struct socket *so,
    struct tcpcb *tp, struct tcpopt *to, int32_t drop_hdrlen, int32_t tlen,
    uint32_t tiwin, int32_t thflags, int32_t nxt_pkt, uint8_t iptos)
{
	int32_t todrop;
	int32_t ourfinisacked = 0;
	struct tcp_bbr *bbr;
	int32_t ret_val = 0;

	bbr = (struct tcp_bbr *)tp->t_fb_ptr;
	ctf_calc_rwin(so, tp);
	/*
	 * If the state is SYN_SENT: if seg contains an ACK, but not for our
	 * SYN, drop the input. if seg contains a RST, then drop the
	 * connection. if seg does not contain SYN, then drop it. Otherwise
	 * this is an acceptable SYN segment initialize tp->rcv_nxt and
	 * tp->irs if seg contains ack then advance tp->snd_una. BRR does
	 * not support ECN so we will not say we are capable. if SYN has
	 * been acked change to ESTABLISHED else SYN_RCVD state arrange for
	 * segment to be acked (eventually) continue processing rest of
	 * data/controls, beginning with URG
	 */
	if ((thflags & TH_ACK) &&
	    (SEQ_LEQ(th->th_ack, tp->iss) ||
	    SEQ_GT(th->th_ack, tp->snd_max))) {
		tcp_log_end_status(tp, TCP_EI_STATUS_RST_IN_FRONT);
		ctf_do_dropwithreset(m, tp, th, BANDLIM_RST_OPENPORT, tlen);
		return (1);
	}
	if ((thflags & (TH_ACK | TH_RST)) == (TH_ACK | TH_RST)) {
		tp = tcp_drop(tp, ECONNREFUSED);
		ctf_do_drop(m, tp);
		return (1);
	}
	if (thflags & TH_RST) {
		ctf_do_drop(m, tp);
		return (1);
	}
	if (!(thflags & TH_SYN)) {
		ctf_do_drop(m, tp);
		return (1);
	}
	tp->irs = th->th_seq;
	tcp_rcvseqinit(tp);
	if (thflags & TH_ACK) {
		int tfo_partial = 0;

		KMOD_TCPSTAT_INC(tcps_connects);
		soisconnected(so);
		/* Do window scaling on this connection? */
		if ((tp->t_flags & (TF_RCVD_SCALE | TF_REQ_SCALE)) ==
		    (TF_RCVD_SCALE | TF_REQ_SCALE)) {
			tp->rcv_scale = tp->request_r_scale;
		}
		tp->rcv_adv += min(tp->rcv_wnd,
		    TCP_MAXWIN << tp->rcv_scale);
		/*
		 * If there's data, delay ACK; if there's also a FIN ACKNOW
		 * will be turned on later.
		 */
		if (DELAY_ACK(tp, bbr, 1) && tlen != 0 && !tfo_partial) {
			bbr->bbr_segs_rcvd += 1;
			tp->t_flags |= TF_DELACK;
			bbr_timer_cancel(bbr, __LINE__, bbr->r_ctl.rc_rcvtime);
		} else {
			bbr->r_wanted_output = 1;
			tp->t_flags |= TF_ACKNOW;
		}
		if (SEQ_GT(th->th_ack, tp->iss)) {
			/*
			 * The SYN is acked
			 * handle it specially.
			 */
			bbr_log_syn(tp, to);
		}
		if (SEQ_GT(th->th_ack, tp->snd_una)) {
			/*
			 * We advance snd_una for the
			 * fast open case. If th_ack is
			 * acknowledging data beyond
			 * snd_una we can't just call
			 * ack-processing since the
			 * data stream in our send-map
			 * will start at snd_una + 1 (one
			 * beyond the SYN). If its just
			 * equal we don't need to do that
			 * and there is no send_map.
			 */
			tp->snd_una++;
		}
		/*
		 * Received <SYN,ACK> in SYN_SENT[*] state. Transitions:
		 * SYN_SENT  --> ESTABLISHED SYN_SENT* --> FIN_WAIT_1
		 */
		tp->t_starttime = ticks;
		if (tp->t_flags & TF_NEEDFIN) {
			tcp_state_change(tp, TCPS_FIN_WAIT_1);
			tp->t_flags &= ~TF_NEEDFIN;
			thflags &= ~TH_SYN;
		} else {
			tcp_state_change(tp, TCPS_ESTABLISHED);
			cc_conn_init(tp);
		}
	} else {
		/*
		 * Received initial SYN in SYN-SENT[*] state => simultaneous
		 * open.  If segment contains CC option and there is a
		 * cached CC, apply TAO test. If it succeeds, connection is *
		 * half-synchronized. Otherwise, do 3-way handshake:
		 * SYN-SENT -> SYN-RECEIVED SYN-SENT* -> SYN-RECEIVED* If
		 * there was no CC option, clear cached CC value.
		 */
		tp->t_flags |= (TF_ACKNOW | TF_NEEDSYN);
		tcp_state_change(tp, TCPS_SYN_RECEIVED);
	}
	/*
	 * Advance th->th_seq to correspond to first data byte. If data,
	 * trim to stay within window, dropping FIN if necessary.
	 */
	th->th_seq++;
	if (tlen > tp->rcv_wnd) {
		todrop = tlen - tp->rcv_wnd;
		m_trim(m, todrop);
		tlen = tp->rcv_wnd;
		thflags &= ~TH_FIN;
		KMOD_TCPSTAT_INC(tcps_rcvpackafterwin);
		KMOD_TCPSTAT_ADD(tcps_rcvbyteafterwin, todrop);
	}
	tp->snd_wl1 = th->th_seq - 1;
	tp->rcv_up = th->th_seq;
	/*
	 * Client side of transaction: already sent SYN and data. If the
	 * remote host used T/TCP to validate the SYN, our data will be
	 * ACK'd; if so, enter normal data segment processing in the middle
	 * of step 5, ack processing. Otherwise, goto step 6.
	 */
	if (thflags & TH_ACK) {
		if ((to->to_flags & TOF_TS) != 0) {
			uint32_t t, rtt;

			t = tcp_tv_to_mssectick(&bbr->rc_tv);
			if (TSTMP_GEQ(t, to->to_tsecr)) {
				rtt = t - to->to_tsecr;
				if (rtt == 0) {
					rtt = 1;
				}
				rtt *= MS_IN_USEC;
				tcp_bbr_xmit_timer(bbr, rtt, 0, 0, 0);
				apply_filter_min_small(&bbr->r_ctl.rc_rttprop,
						       rtt, bbr->r_ctl.rc_rcvtime);
			}
		}
		if (bbr_process_ack(m, th, so, tp, to, tiwin, tlen, &ourfinisacked, thflags, &ret_val))
			return (ret_val);
		/* We may have changed to FIN_WAIT_1 above */
		if (tp->t_state == TCPS_FIN_WAIT_1) {
			/*
			 * In FIN_WAIT_1 STATE in addition to the processing
			 * for the ESTABLISHED state if our FIN is now
			 * acknowledged then enter FIN_WAIT_2.
			 */
			if (ourfinisacked) {
				/*
				 * If we can't receive any more data, then
				 * closing user can proceed. Starting the
				 * timer is contrary to the specification,
				 * but if we don't get a FIN we'll hang
				 * forever.
				 *
				 * XXXjl: we should release the tp also, and
				 * use a compressed state.
				 */
				if (so->so_rcv.sb_state & SBS_CANTRCVMORE) {
					soisdisconnected(so);
					tcp_timer_activate(tp, TT_2MSL, TCPTV_2MSL);
				}
				tcp_state_change(tp, TCPS_FIN_WAIT_2);
			}
		}
	}
	return (bbr_process_data(m, th, so, tp, drop_hdrlen, tlen,
	    tiwin, thflags, nxt_pkt));
}

/*
 * Return value of 1, the TCB is unlocked and most
 * likely gone, return value of 0, the TCB is still
 * locked.
 */
static int
bbr_do_syn_recv(struct mbuf *m, struct tcphdr *th, struct socket *so,
		struct tcpcb *tp, struct tcpopt *to, int32_t drop_hdrlen, int32_t tlen,
		uint32_t tiwin, int32_t thflags, int32_t nxt_pkt, uint8_t iptos)
{
	int32_t ourfinisacked = 0;
	int32_t ret_val;
	struct tcp_bbr *bbr;

	bbr = (struct tcp_bbr *)tp->t_fb_ptr;
	ctf_calc_rwin(so, tp);
	if ((thflags & TH_ACK) &&
	    (SEQ_LEQ(th->th_ack, tp->snd_una) ||
	     SEQ_GT(th->th_ack, tp->snd_max))) {
		tcp_log_end_status(tp, TCP_EI_STATUS_RST_IN_FRONT);
		ctf_do_dropwithreset(m, tp, th, BANDLIM_RST_OPENPORT, tlen);
		return (1);
	}
	if ((thflags & TH_RST) ||
	    (tp->t_fin_is_rst && (thflags & TH_FIN)))
		return (ctf_process_rst(m, th, so, tp));
	/*
	 * RFC 1323 PAWS: If we have a timestamp reply on this segment and
	 * it's less than ts_recent, drop it.
	 */
	if ((to->to_flags & TOF_TS) != 0 && tp->ts_recent &&
	    TSTMP_LT(to->to_tsval, tp->ts_recent)) {
		if (ctf_ts_check(m, th, tp, tlen, thflags, &ret_val))
			return (ret_val);
	}
	/*
	 * In the SYN-RECEIVED state, validate that the packet belongs to
	 * this connection before trimming the data to fit the receive
	 * window.  Check the sequence number versus IRS since we know the
	 * sequence numbers haven't wrapped.  This is a partial fix for the
	 * "LAND" DoS attack.
	 */
	if (SEQ_LT(th->th_seq, tp->irs)) {
		tcp_log_end_status(tp, TCP_EI_STATUS_RST_IN_FRONT);
		ctf_do_dropwithreset(m, tp, th, BANDLIM_RST_OPENPORT, tlen);
		return (1);
	}
	if (ctf_drop_checks(to, m, th, tp, &tlen, &thflags, &drop_hdrlen, &ret_val)) {
		return (ret_val);
	}
	/*
	 * If last ACK falls within this segment's sequence numbers, record
	 * its timestamp. NOTE: 1) That the test incorporates suggestions
	 * from the latest proposal of the tcplw@cray.com list (Braden
	 * 1993/04/26). 2) That updating only on newer timestamps interferes
	 * with our earlier PAWS tests, so this check should be solely
	 * predicated on the sequence space of this segment. 3) That we
	 * modify the segment boundary check to be Last.ACK.Sent <= SEG.SEQ
	 * + SEG.Len  instead of RFC1323's Last.ACK.Sent < SEG.SEQ +
	 * SEG.Len, This modified check allows us to overcome RFC1323's
	 * limitations as described in Stevens TCP/IP Illustrated Vol. 2
	 * p.869. In such cases, we can still calculate the RTT correctly
	 * when RCV.NXT == Last.ACK.Sent.
	 */
	if ((to->to_flags & TOF_TS) != 0 &&
	    SEQ_LEQ(th->th_seq, tp->last_ack_sent) &&
	    SEQ_LEQ(tp->last_ack_sent, th->th_seq + tlen +
		    ((thflags & (TH_SYN | TH_FIN)) != 0))) {
		tp->ts_recent_age = tcp_tv_to_mssectick(&bbr->rc_tv);
		tp->ts_recent = to->to_tsval;
	}
	tp->snd_wnd = tiwin;
	/*
	 * If the ACK bit is off:  if in SYN-RECEIVED state or SENDSYN flag
	 * is on (half-synchronized state), then queue data for later
	 * processing; else drop segment and return.
	 */
	if ((thflags & TH_ACK) == 0) {
		return (bbr_process_data(m, th, so, tp, drop_hdrlen, tlen,
					 tiwin, thflags, nxt_pkt));
	}
	KMOD_TCPSTAT_INC(tcps_connects);
	soisconnected(so);
	/* Do window scaling? */
	if ((tp->t_flags & (TF_RCVD_SCALE | TF_REQ_SCALE)) ==
	    (TF_RCVD_SCALE | TF_REQ_SCALE)) {
		tp->rcv_scale = tp->request_r_scale;
	}
	/*
	 * ok for the first time in lets see if we can use the ts to figure
	 * out what the initial RTT was.
	 */
	if ((to->to_flags & TOF_TS) != 0) {
		uint32_t t, rtt;

		t = tcp_tv_to_mssectick(&bbr->rc_tv);
		if (TSTMP_GEQ(t, to->to_tsecr)) {
			rtt = t - to->to_tsecr;
			if (rtt == 0) {
				rtt = 1;
			}
			rtt *= MS_IN_USEC;
			tcp_bbr_xmit_timer(bbr, rtt, 0, 0, 0);
			apply_filter_min_small(&bbr->r_ctl.rc_rttprop, rtt, bbr->r_ctl.rc_rcvtime);
		}
	}
	/* Drop off any SYN in the send map (probably not there)  */
	if (thflags & TH_ACK)
		bbr_log_syn(tp, to);
	/*
	 * Make transitions: SYN-RECEIVED  -> ESTABLISHED SYN-RECEIVED* ->
	 * FIN-WAIT-1
	 */
	tp->t_starttime = ticks;
	if (tp->t_flags & TF_NEEDFIN) {
		tcp_state_change(tp, TCPS_FIN_WAIT_1);
		tp->t_flags &= ~TF_NEEDFIN;
	} else {
		tcp_state_change(tp, TCPS_ESTABLISHED);
		cc_conn_init(tp);
	}
	/*
	 * Account for the ACK of our SYN prior to
	 * regular ACK processing below, except for
	 * simultaneous SYN, which is handled later.
	 */
	if (SEQ_GT(th->th_ack, tp->snd_una) && !(tp->t_flags & TF_NEEDSYN))
		tp->snd_una++;
	/*
	 * If segment contains data or ACK, will call tcp_reass() later; if
	 * not, do so now to pass queued data to user.
	 */
	if (tlen == 0 && (thflags & TH_FIN) == 0) {
		(void)tcp_reass(tp, (struct tcphdr *)0, NULL, 0,
			(struct mbuf *)0);
		if (tp->t_flags & TF_WAKESOR) {
			tp->t_flags &= ~TF_WAKESOR;
			/* NB: sorwakeup_locked() does an implicit unlock. */
			sorwakeup(so);
		}
	}
	tp->snd_wl1 = th->th_seq - 1;
	if (bbr_process_ack(m, th, so, tp, to, tiwin, tlen, &ourfinisacked, thflags, &ret_val)) {
		return (ret_val);
	}
	if (tp->t_state == TCPS_FIN_WAIT_1) {
		/* We could have went to FIN_WAIT_1 (or EST) above */
		/*
		 * In FIN_WAIT_1 STATE in addition to the processing for the
		 * ESTABLISHED state if our FIN is now acknowledged then
		 * enter FIN_WAIT_2.
		 */
		if (ourfinisacked) {
			/*
			 * If we can't receive any more data, then closing
			 * user can proceed. Starting the timer is contrary
			 * to the specification, but if we don't get a FIN
			 * we'll hang forever.
			 *
			 * XXXjl: we should release the tp also, and use a
			 * compressed state.
			 */
			if (so->so_rcv.sb_state & SBS_CANTRCVMORE) {
				soisdisconnected(so);
				tcp_timer_activate(tp, TT_2MSL, TCPTV_2MSL);
			}
			tcp_state_change(tp, TCPS_FIN_WAIT_2);
		}
	}
	return (bbr_process_data(m, th, so, tp, drop_hdrlen, tlen,
				 tiwin, thflags, nxt_pkt));
}

/*
 * Return value of 1, the TCB is unlocked and most
 * likely gone, return value of 0, the TCB is still
 * locked.
 */
static int
bbr_do_established(struct mbuf *m, struct tcphdr *th, struct socket *so,
    struct tcpcb *tp, struct tcpopt *to, int32_t drop_hdrlen, int32_t tlen,
    uint32_t tiwin, int32_t thflags, int32_t nxt_pkt, uint8_t iptos)
{
	struct tcp_bbr *bbr;
	int32_t ret_val;

	/*
	 * Header prediction: check for the two common cases of a
	 * uni-directional data xfer.  If the packet has no control flags,
	 * is in-sequence, the window didn't change and we're not
	 * retransmitting, it's a candidate.  If the length is zero and the
	 * ack moved forward, we're the sender side of the xfer.  Just free
	 * the data acked & wake any higher level process that was blocked
	 * waiting for space.  If the length is non-zero and the ack didn't
	 * move, we're the receiver side.  If we're getting packets in-order
	 * (the reassembly queue is empty), add the data toc The socket
	 * buffer and note that we need a delayed ack. Make sure that the
	 * hidden state-flags are also off. Since we check for
	 * TCPS_ESTABLISHED first, it can only be TH_NEEDSYN.
	 */
	bbr = (struct tcp_bbr *)tp->t_fb_ptr;
	if (bbr->r_ctl.rc_delivered < (4 * tp->t_maxseg)) {
		/*
		 * If we have delived under 4 segments increase the initial
		 * window if raised by the peer. We use this to determine
		 * dynamic and static rwnd's at the end of a connection.
		 */
		bbr->r_ctl.rc_init_rwnd = max(tiwin, tp->snd_wnd);
	}
	if (__predict_true(((to->to_flags & TOF_SACK) == 0)) &&
	    __predict_true((thflags & (TH_SYN | TH_FIN | TH_RST | TH_URG | TH_ACK)) == TH_ACK) &&
	    __predict_true(SEGQ_EMPTY(tp)) &&
	    __predict_true(th->th_seq == tp->rcv_nxt)) {
		if (tlen == 0) {
			if (bbr_fastack(m, th, so, tp, to, drop_hdrlen, tlen,
			    tiwin, nxt_pkt, iptos)) {
				return (0);
			}
		} else {
			if (bbr_do_fastnewdata(m, th, so, tp, to, drop_hdrlen, tlen,
			    tiwin, nxt_pkt)) {
				return (0);
			}
		}
	}
	ctf_calc_rwin(so, tp);

	if ((thflags & TH_RST) ||
	    (tp->t_fin_is_rst && (thflags & TH_FIN)))
		return (ctf_process_rst(m, th, so, tp));
	/*
	 * RFC5961 Section 4.2 Send challenge ACK for any SYN in
	 * synchronized state.
	 */
	if (thflags & TH_SYN) {
		ctf_challenge_ack(m, th, tp, &ret_val);
		return (ret_val);
	}
	/*
	 * RFC 1323 PAWS: If we have a timestamp reply on this segment and
	 * it's less than ts_recent, drop it.
	 */
	if ((to->to_flags & TOF_TS) != 0 && tp->ts_recent &&
	    TSTMP_LT(to->to_tsval, tp->ts_recent)) {
		if (ctf_ts_check(m, th, tp, tlen, thflags, &ret_val))
			return (ret_val);
	}
	if (ctf_drop_checks(to, m, th, tp, &tlen, &thflags, &drop_hdrlen, &ret_val)) {
		return (ret_val);
	}
	/*
	 * If last ACK falls within this segment's sequence numbers, record
	 * its timestamp. NOTE: 1) That the test incorporates suggestions
	 * from the latest proposal of the tcplw@cray.com list (Braden
	 * 1993/04/26). 2) That updating only on newer timestamps interferes
	 * with our earlier PAWS tests, so this check should be solely
	 * predicated on the sequence space of this segment. 3) That we
	 * modify the segment boundary check to be Last.ACK.Sent <= SEG.SEQ
	 * + SEG.Len  instead of RFC1323's Last.ACK.Sent < SEG.SEQ +
	 * SEG.Len, This modified check allows us to overcome RFC1323's
	 * limitations as described in Stevens TCP/IP Illustrated Vol. 2
	 * p.869. In such cases, we can still calculate the RTT correctly
	 * when RCV.NXT == Last.ACK.Sent.
	 */
	if ((to->to_flags & TOF_TS) != 0 &&
	    SEQ_LEQ(th->th_seq, tp->last_ack_sent) &&
	    SEQ_LEQ(tp->last_ack_sent, th->th_seq + tlen +
	    ((thflags & (TH_SYN | TH_FIN)) != 0))) {
		tp->ts_recent_age = tcp_tv_to_mssectick(&bbr->rc_tv);
		tp->ts_recent = to->to_tsval;
	}
	/*
	 * If the ACK bit is off:  if in SYN-RECEIVED state or SENDSYN flag
	 * is on (half-synchronized state), then queue data for later
	 * processing; else drop segment and return.
	 */
	if ((thflags & TH_ACK) == 0) {
		if (tp->t_flags & TF_NEEDSYN) {
			return (bbr_process_data(m, th, so, tp, drop_hdrlen, tlen,
			    tiwin, thflags, nxt_pkt));
		} else if (tp->t_flags & TF_ACKNOW) {
			ctf_do_dropafterack(m, tp, th, thflags, tlen, &ret_val);
			bbr->r_wanted_output = 1;
			return (ret_val);
		} else {
			ctf_do_drop(m, NULL);
			return (0);
		}
	}
	/*
	 * Ack processing.
	 */
	if (bbr_process_ack(m, th, so, tp, to, tiwin, tlen, NULL, thflags, &ret_val)) {
		return (ret_val);
	}
	if (sbavail(&so->so_snd)) {
		if (ctf_progress_timeout_check(tp, true)) {
			ctf_do_dropwithreset_conn(m, tp, th, BANDLIM_RST_OPENPORT, tlen);
			return (1);
		}
	}
	/* State changes only happen in bbr_process_data() */
	return (bbr_process_data(m, th, so, tp, drop_hdrlen, tlen,
	    tiwin, thflags, nxt_pkt));
}

/*
 * Return value of 1, the TCB is unlocked and most
 * likely gone, return value of 0, the TCB is still
 * locked.
 */
static int
bbr_do_close_wait(struct mbuf *m, struct tcphdr *th, struct socket *so,
    struct tcpcb *tp, struct tcpopt *to, int32_t drop_hdrlen, int32_t tlen,
    uint32_t tiwin, int32_t thflags, int32_t nxt_pkt, uint8_t iptos)
{
	struct tcp_bbr *bbr;
	int32_t ret_val;

	bbr = (struct tcp_bbr *)tp->t_fb_ptr;
	ctf_calc_rwin(so, tp);
	if ((thflags & TH_RST) ||
	    (tp->t_fin_is_rst && (thflags & TH_FIN)))
		return (ctf_process_rst(m, th, so, tp));
	/*
	 * RFC5961 Section 4.2 Send challenge ACK for any SYN in
	 * synchronized state.
	 */
	if (thflags & TH_SYN) {
		ctf_challenge_ack(m, th, tp, &ret_val);
		return (ret_val);
	}
	/*
	 * RFC 1323 PAWS: If we have a timestamp reply on this segment and
	 * it's less than ts_recent, drop it.
	 */
	if ((to->to_flags & TOF_TS) != 0 && tp->ts_recent &&
	    TSTMP_LT(to->to_tsval, tp->ts_recent)) {
		if (ctf_ts_check(m, th, tp, tlen, thflags, &ret_val))
			return (ret_val);
	}
	if (ctf_drop_checks(to, m, th, tp, &tlen, &thflags, &drop_hdrlen, &ret_val)) {
		return (ret_val);
	}
	/*
	 * If last ACK falls within this segment's sequence numbers, record
	 * its timestamp. NOTE: 1) That the test incorporates suggestions
	 * from the latest proposal of the tcplw@cray.com list (Braden
	 * 1993/04/26). 2) That updating only on newer timestamps interferes
	 * with our earlier PAWS tests, so this check should be solely
	 * predicated on the sequence space of this segment. 3) That we
	 * modify the segment boundary check to be Last.ACK.Sent <= SEG.SEQ
	 * + SEG.Len  instead of RFC1323's Last.ACK.Sent < SEG.SEQ +
	 * SEG.Len, This modified check allows us to overcome RFC1323's
	 * limitations as described in Stevens TCP/IP Illustrated Vol. 2
	 * p.869. In such cases, we can still calculate the RTT correctly
	 * when RCV.NXT == Last.ACK.Sent.
	 */
	if ((to->to_flags & TOF_TS) != 0 &&
	    SEQ_LEQ(th->th_seq, tp->last_ack_sent) &&
	    SEQ_LEQ(tp->last_ack_sent, th->th_seq + tlen +
	    ((thflags & (TH_SYN | TH_FIN)) != 0))) {
		tp->ts_recent_age = tcp_tv_to_mssectick(&bbr->rc_tv);
		tp->ts_recent = to->to_tsval;
	}
	/*
	 * If the ACK bit is off:  if in SYN-RECEIVED state or SENDSYN flag
	 * is on (half-synchronized state), then queue data for later
	 * processing; else drop segment and return.
	 */
	if ((thflags & TH_ACK) == 0) {
		if (tp->t_flags & TF_NEEDSYN) {
			return (bbr_process_data(m, th, so, tp, drop_hdrlen, tlen,
			    tiwin, thflags, nxt_pkt));
		} else if (tp->t_flags & TF_ACKNOW) {
			ctf_do_dropafterack(m, tp, th, thflags, tlen, &ret_val);
			bbr->r_wanted_output = 1;
			return (ret_val);
		} else {
			ctf_do_drop(m, NULL);
			return (0);
		}
	}
	/*
	 * Ack processing.
	 */
	if (bbr_process_ack(m, th, so, tp, to, tiwin, tlen, NULL, thflags, &ret_val)) {
		return (ret_val);
	}
	if (sbavail(&so->so_snd)) {
		if (ctf_progress_timeout_check(tp, true)) {
			ctf_do_dropwithreset_conn(m, tp, th, BANDLIM_RST_OPENPORT, tlen);
			return (1);
		}
	}
	return (bbr_process_data(m, th, so, tp, drop_hdrlen, tlen,
	    tiwin, thflags, nxt_pkt));
}

static int
bbr_check_data_after_close(struct mbuf *m, struct tcp_bbr *bbr,
    struct tcpcb *tp, int32_t * tlen, struct tcphdr *th, struct socket *so)
{

	if (bbr->rc_allow_data_af_clo == 0) {
close_now:
		tcp_log_end_status(tp, TCP_EI_STATUS_DATA_A_CLOSE);
		/* tcp_close will kill the inp pre-log the Reset */
		tcp_log_end_status(tp, TCP_EI_STATUS_SERVER_RST);
		tp = tcp_close(tp);
		KMOD_TCPSTAT_INC(tcps_rcvafterclose);
		ctf_do_dropwithreset(m, tp, th, BANDLIM_UNLIMITED, (*tlen));
		return (1);
	}
	if (sbavail(&so->so_snd) == 0)
		goto close_now;
	/* Ok we allow data that is ignored and a followup reset */
	tp->rcv_nxt = th->th_seq + *tlen;
	tp->t_flags2 |= TF2_DROP_AF_DATA;
	bbr->r_wanted_output = 1;
	*tlen = 0;
	return (0);
}

/*
 * Return value of 1, the TCB is unlocked and most
 * likely gone, return value of 0, the TCB is still
 * locked.
 */
static int
bbr_do_fin_wait_1(struct mbuf *m, struct tcphdr *th, struct socket *so,
    struct tcpcb *tp, struct tcpopt *to, int32_t drop_hdrlen, int32_t tlen,
    uint32_t tiwin, int32_t thflags, int32_t nxt_pkt, uint8_t iptos)
{
	int32_t ourfinisacked = 0;
	int32_t ret_val;
	struct tcp_bbr *bbr;

	bbr = (struct tcp_bbr *)tp->t_fb_ptr;
	ctf_calc_rwin(so, tp);
	if ((thflags & TH_RST) ||
	    (tp->t_fin_is_rst && (thflags & TH_FIN)))
		return (ctf_process_rst(m, th, so, tp));
	/*
	 * RFC5961 Section 4.2 Send challenge ACK for any SYN in
	 * synchronized state.
	 */
	if (thflags & TH_SYN) {
		ctf_challenge_ack(m, th, tp, &ret_val);
		return (ret_val);
	}
	/*
	 * RFC 1323 PAWS: If we have a timestamp reply on this segment and
	 * it's less than ts_recent, drop it.
	 */
	if ((to->to_flags & TOF_TS) != 0 && tp->ts_recent &&
	    TSTMP_LT(to->to_tsval, tp->ts_recent)) {
		if (ctf_ts_check(m, th, tp, tlen, thflags, &ret_val))
			return (ret_val);
	}
	if (ctf_drop_checks(to, m, th, tp, &tlen, &thflags, &drop_hdrlen, &ret_val)) {
		return (ret_val);
	}
	/*
	 * If new data are received on a connection after the user processes
	 * are gone, then RST the other end.
	 */
	if ((so->so_state & SS_NOFDREF) && tlen) {
		/*
		 * We call a new function now so we might continue and setup
		 * to reset at all data being ack'd.
		 */
		if (bbr_check_data_after_close(m, bbr, tp, &tlen, th, so))
			return (1);
	}
	/*
	 * If last ACK falls within this segment's sequence numbers, record
	 * its timestamp. NOTE: 1) That the test incorporates suggestions
	 * from the latest proposal of the tcplw@cray.com list (Braden
	 * 1993/04/26). 2) That updating only on newer timestamps interferes
	 * with our earlier PAWS tests, so this check should be solely
	 * predicated on the sequence space of this segment. 3) That we
	 * modify the segment boundary check to be Last.ACK.Sent <= SEG.SEQ
	 * + SEG.Len  instead of RFC1323's Last.ACK.Sent < SEG.SEQ +
	 * SEG.Len, This modified check allows us to overcome RFC1323's
	 * limitations as described in Stevens TCP/IP Illustrated Vol. 2
	 * p.869. In such cases, we can still calculate the RTT correctly
	 * when RCV.NXT == Last.ACK.Sent.
	 */
	if ((to->to_flags & TOF_TS) != 0 &&
	    SEQ_LEQ(th->th_seq, tp->last_ack_sent) &&
	    SEQ_LEQ(tp->last_ack_sent, th->th_seq + tlen +
	    ((thflags & (TH_SYN | TH_FIN)) != 0))) {
		tp->ts_recent_age = tcp_tv_to_mssectick(&bbr->rc_tv);
		tp->ts_recent = to->to_tsval;
	}
	/*
	 * If the ACK bit is off:  if in SYN-RECEIVED state or SENDSYN flag
	 * is on (half-synchronized state), then queue data for later
	 * processing; else drop segment and return.
	 */
	if ((thflags & TH_ACK) == 0) {
		if (tp->t_flags & TF_NEEDSYN) {
			return (bbr_process_data(m, th, so, tp, drop_hdrlen, tlen,
			    tiwin, thflags, nxt_pkt));
		} else if (tp->t_flags & TF_ACKNOW) {
			ctf_do_dropafterack(m, tp, th, thflags, tlen, &ret_val);
			bbr->r_wanted_output = 1;
			return (ret_val);
		} else {
			ctf_do_drop(m, NULL);
			return (0);
		}
	}
	/*
	 * Ack processing.
	 */
	if (bbr_process_ack(m, th, so, tp, to, tiwin, tlen, &ourfinisacked, thflags, &ret_val)) {
		return (ret_val);
	}
	if (ourfinisacked) {
		/*
		 * If we can't receive any more data, then closing user can
		 * proceed. Starting the timer is contrary to the
		 * specification, but if we don't get a FIN we'll hang
		 * forever.
		 *
		 * XXXjl: we should release the tp also, and use a
		 * compressed state.
		 */
		if (so->so_rcv.sb_state & SBS_CANTRCVMORE) {
			soisdisconnected(so);
			tcp_timer_activate(tp, TT_2MSL, TCPTV_2MSL);
		}
		tcp_state_change(tp, TCPS_FIN_WAIT_2);
	}
	if (sbavail(&so->so_snd)) {
		if (ctf_progress_timeout_check(tp, true)) {
			ctf_do_dropwithreset_conn(m, tp, th, BANDLIM_RST_OPENPORT, tlen);
			return (1);
		}
	}
	return (bbr_process_data(m, th, so, tp, drop_hdrlen, tlen,
	    tiwin, thflags, nxt_pkt));
}

/*
 * Return value of 1, the TCB is unlocked and most
 * likely gone, return value of 0, the TCB is still
 * locked.
 */
static int
bbr_do_closing(struct mbuf *m, struct tcphdr *th, struct socket *so,
    struct tcpcb *tp, struct tcpopt *to, int32_t drop_hdrlen, int32_t tlen,
    uint32_t tiwin, int32_t thflags, int32_t nxt_pkt, uint8_t iptos)
{
	int32_t ourfinisacked = 0;
	int32_t ret_val;
	struct tcp_bbr *bbr;

	bbr = (struct tcp_bbr *)tp->t_fb_ptr;
	ctf_calc_rwin(so, tp);
	if ((thflags & TH_RST) ||
	    (tp->t_fin_is_rst && (thflags & TH_FIN)))
		return (ctf_process_rst(m, th, so, tp));
	/*
	 * RFC5961 Section 4.2 Send challenge ACK for any SYN in
	 * synchronized state.
	 */
	if (thflags & TH_SYN) {
		ctf_challenge_ack(m, th, tp, &ret_val);
		return (ret_val);
	}
	/*
	 * RFC 1323 PAWS: If we have a timestamp reply on this segment and
	 * it's less than ts_recent, drop it.
	 */
	if ((to->to_flags & TOF_TS) != 0 && tp->ts_recent &&
	    TSTMP_LT(to->to_tsval, tp->ts_recent)) {
		if (ctf_ts_check(m, th, tp, tlen, thflags, &ret_val))
			return (ret_val);
	}
	if (ctf_drop_checks(to, m, th, tp, &tlen, &thflags, &drop_hdrlen, &ret_val)) {
		return (ret_val);
	}
	/*
	 * If new data are received on a connection after the user processes
	 * are gone, then RST the other end.
	 */
	if ((so->so_state & SS_NOFDREF) && tlen) {
		/*
		 * We call a new function now so we might continue and setup
		 * to reset at all data being ack'd.
		 */
		if (bbr_check_data_after_close(m, bbr, tp, &tlen, th, so))
			return (1);
	}
	/*
	 * If last ACK falls within this segment's sequence numbers, record
	 * its timestamp. NOTE: 1) That the test incorporates suggestions
	 * from the latest proposal of the tcplw@cray.com list (Braden
	 * 1993/04/26). 2) That updating only on newer timestamps interferes
	 * with our earlier PAWS tests, so this check should be solely
	 * predicated on the sequence space of this segment. 3) That we
	 * modify the segment boundary check to be Last.ACK.Sent <= SEG.SEQ
	 * + SEG.Len  instead of RFC1323's Last.ACK.Sent < SEG.SEQ +
	 * SEG.Len, This modified check allows us to overcome RFC1323's
	 * limitations as described in Stevens TCP/IP Illustrated Vol. 2
	 * p.869. In such cases, we can still calculate the RTT correctly
	 * when RCV.NXT == Last.ACK.Sent.
	 */
	if ((to->to_flags & TOF_TS) != 0 &&
	    SEQ_LEQ(th->th_seq, tp->last_ack_sent) &&
	    SEQ_LEQ(tp->last_ack_sent, th->th_seq + tlen +
	    ((thflags & (TH_SYN | TH_FIN)) != 0))) {
		tp->ts_recent_age = tcp_tv_to_mssectick(&bbr->rc_tv);
		tp->ts_recent = to->to_tsval;
	}
	/*
	 * If the ACK bit is off:  if in SYN-RECEIVED state or SENDSYN flag
	 * is on (half-synchronized state), then queue data for later
	 * processing; else drop segment and return.
	 */
	if ((thflags & TH_ACK) == 0) {
		if (tp->t_flags & TF_NEEDSYN) {
			return (bbr_process_data(m, th, so, tp, drop_hdrlen, tlen,
			    tiwin, thflags, nxt_pkt));
		} else if (tp->t_flags & TF_ACKNOW) {
			ctf_do_dropafterack(m, tp, th, thflags, tlen, &ret_val);
			bbr->r_wanted_output = 1;
			return (ret_val);
		} else {
			ctf_do_drop(m, NULL);
			return (0);
		}
	}
	/*
	 * Ack processing.
	 */
	if (bbr_process_ack(m, th, so, tp, to, tiwin, tlen, &ourfinisacked, thflags, &ret_val)) {
		return (ret_val);
	}
	if (ourfinisacked) {
                tcp_state_change(tp, TCPS_TIME_WAIT);
                soisdisconnected(so);
		tcp_timer_twstart(tp);
		m_freem(m);
		return (1);
	}
	if (sbavail(&so->so_snd)) {
		if (ctf_progress_timeout_check(tp, true)) {
			ctf_do_dropwithreset_conn(m, tp, th, BANDLIM_RST_OPENPORT, tlen);
			return (1);
		}
	}
	return (bbr_process_data(m, th, so, tp, drop_hdrlen, tlen,
	    tiwin, thflags, nxt_pkt));
}

/*
 * Return value of 1, the TCB is unlocked and most
 * likely gone, return value of 0, the TCB is still
 * locked.
 */
static int
bbr_do_lastack(struct mbuf *m, struct tcphdr *th, struct socket *so,
    struct tcpcb *tp, struct tcpopt *to, int32_t drop_hdrlen, int32_t tlen,
    uint32_t tiwin, int32_t thflags, int32_t nxt_pkt, uint8_t iptos)
{
	int32_t ourfinisacked = 0;
	int32_t ret_val;
	struct tcp_bbr *bbr;

	bbr = (struct tcp_bbr *)tp->t_fb_ptr;
	ctf_calc_rwin(so, tp);
	if ((thflags & TH_RST) ||
	    (tp->t_fin_is_rst && (thflags & TH_FIN)))
		return (ctf_process_rst(m, th, so, tp));
	/*
	 * RFC5961 Section 4.2 Send challenge ACK for any SYN in
	 * synchronized state.
	 */
	if (thflags & TH_SYN) {
		ctf_challenge_ack(m, th, tp, &ret_val);
		return (ret_val);
	}
	/*
	 * RFC 1323 PAWS: If we have a timestamp reply on this segment and
	 * it's less than ts_recent, drop it.
	 */
	if ((to->to_flags & TOF_TS) != 0 && tp->ts_recent &&
	    TSTMP_LT(to->to_tsval, tp->ts_recent)) {
		if (ctf_ts_check(m, th, tp, tlen, thflags, &ret_val))
			return (ret_val);
	}
	if (ctf_drop_checks(to, m, th, tp, &tlen, &thflags, &drop_hdrlen, &ret_val)) {
		return (ret_val);
	}
	/*
	 * If new data are received on a connection after the user processes
	 * are gone, then RST the other end.
	 */
	if ((so->so_state & SS_NOFDREF) && tlen) {
		/*
		 * We call a new function now so we might continue and setup
		 * to reset at all data being ack'd.
		 */
		if (bbr_check_data_after_close(m, bbr, tp, &tlen, th, so))
			return (1);
	}
	/*
	 * If last ACK falls within this segment's sequence numbers, record
	 * its timestamp. NOTE: 1) That the test incorporates suggestions
	 * from the latest proposal of the tcplw@cray.com list (Braden
	 * 1993/04/26). 2) That updating only on newer timestamps interferes
	 * with our earlier PAWS tests, so this check should be solely
	 * predicated on the sequence space of this segment. 3) That we
	 * modify the segment boundary check to be Last.ACK.Sent <= SEG.SEQ
	 * + SEG.Len  instead of RFC1323's Last.ACK.Sent < SEG.SEQ +
	 * SEG.Len, This modified check allows us to overcome RFC1323's
	 * limitations as described in Stevens TCP/IP Illustrated Vol. 2
	 * p.869. In such cases, we can still calculate the RTT correctly
	 * when RCV.NXT == Last.ACK.Sent.
	 */
	if ((to->to_flags & TOF_TS) != 0 &&
	    SEQ_LEQ(th->th_seq, tp->last_ack_sent) &&
	    SEQ_LEQ(tp->last_ack_sent, th->th_seq + tlen +
	    ((thflags & (TH_SYN | TH_FIN)) != 0))) {
		tp->ts_recent_age = tcp_tv_to_mssectick(&bbr->rc_tv);
		tp->ts_recent = to->to_tsval;
	}
	/*
	 * If the ACK bit is off:  if in SYN-RECEIVED state or SENDSYN flag
	 * is on (half-synchronized state), then queue data for later
	 * processing; else drop segment and return.
	 */
	if ((thflags & TH_ACK) == 0) {
		if (tp->t_flags & TF_NEEDSYN) {
			return (bbr_process_data(m, th, so, tp, drop_hdrlen, tlen,
			    tiwin, thflags, nxt_pkt));
		} else if (tp->t_flags & TF_ACKNOW) {
			ctf_do_dropafterack(m, tp, th, thflags, tlen, &ret_val);
			bbr->r_wanted_output = 1;
			return (ret_val);
		} else {
			ctf_do_drop(m, NULL);
			return (0);
		}
	}
	/*
	 * case TCPS_LAST_ACK: Ack processing.
	 */
	if (bbr_process_ack(m, th, so, tp, to, tiwin, tlen, &ourfinisacked, thflags, &ret_val)) {
		return (ret_val);
	}
	if (ourfinisacked) {
		tp = tcp_close(tp);
		ctf_do_drop(m, tp);
		return (1);
	}
	if (sbavail(&so->so_snd)) {
		if (ctf_progress_timeout_check(tp, true)) {
			ctf_do_dropwithreset_conn(m, tp, th, BANDLIM_RST_OPENPORT, tlen);
			return (1);
		}
	}
	return (bbr_process_data(m, th, so, tp, drop_hdrlen, tlen,
	    tiwin, thflags, nxt_pkt));
}

/*
 * Return value of 1, the TCB is unlocked and most
 * likely gone, return value of 0, the TCB is still
 * locked.
 */
static int
bbr_do_fin_wait_2(struct mbuf *m, struct tcphdr *th, struct socket *so,
    struct tcpcb *tp, struct tcpopt *to, int32_t drop_hdrlen, int32_t tlen,
    uint32_t tiwin, int32_t thflags, int32_t nxt_pkt, uint8_t iptos)
{
	int32_t ourfinisacked = 0;
	int32_t ret_val;
	struct tcp_bbr *bbr;

	bbr = (struct tcp_bbr *)tp->t_fb_ptr;
	ctf_calc_rwin(so, tp);
	/* Reset receive buffer auto scaling when not in bulk receive mode. */
	if ((thflags & TH_RST) ||
	    (tp->t_fin_is_rst && (thflags & TH_FIN)))
		return (ctf_process_rst(m, th, so, tp));

	/*
	 * RFC5961 Section 4.2 Send challenge ACK for any SYN in
	 * synchronized state.
	 */
	if (thflags & TH_SYN) {
		ctf_challenge_ack(m, th, tp, &ret_val);
		return (ret_val);
	}
	/*
	 * RFC 1323 PAWS: If we have a timestamp reply on this segment and
	 * it's less than ts_recent, drop it.
	 */
	if ((to->to_flags & TOF_TS) != 0 && tp->ts_recent &&
	    TSTMP_LT(to->to_tsval, tp->ts_recent)) {
		if (ctf_ts_check(m, th, tp, tlen, thflags, &ret_val))
			return (ret_val);
	}
	if (ctf_drop_checks(to, m, th, tp, &tlen, &thflags, &drop_hdrlen, &ret_val)) {
		return (ret_val);
	}
	/*
	 * If new data are received on a connection after the user processes
	 * are gone, then we may RST the other end depending on the outcome
	 * of bbr_check_data_after_close.
	 */
	if ((so->so_state & SS_NOFDREF) &&
	    tlen) {
		/*
		 * We call a new function now so we might continue and setup
		 * to reset at all data being ack'd.
		 */
		if (bbr_check_data_after_close(m, bbr, tp, &tlen, th, so))
			return (1);
	}
	/*
	 * If last ACK falls within this segment's sequence numbers, record
	 * its timestamp. NOTE: 1) That the test incorporates suggestions
	 * from the latest proposal of the tcplw@cray.com list (Braden
	 * 1993/04/26). 2) That updating only on newer timestamps interferes
	 * with our earlier PAWS tests, so this check should be solely
	 * predicated on the sequence space of this segment. 3) That we
	 * modify the segment boundary check to be Last.ACK.Sent <= SEG.SEQ
	 * + SEG.Len  instead of RFC1323's Last.ACK.Sent < SEG.SEQ +
	 * SEG.Len, This modified check allows us to overcome RFC1323's
	 * limitations as described in Stevens TCP/IP Illustrated Vol. 2
	 * p.869. In such cases, we can still calculate the RTT correctly
	 * when RCV.NXT == Last.ACK.Sent.
	 */
	if ((to->to_flags & TOF_TS) != 0 &&
	    SEQ_LEQ(th->th_seq, tp->last_ack_sent) &&
	    SEQ_LEQ(tp->last_ack_sent, th->th_seq + tlen +
	    ((thflags & (TH_SYN | TH_FIN)) != 0))) {
		tp->ts_recent_age = tcp_tv_to_mssectick(&bbr->rc_tv);
		tp->ts_recent = to->to_tsval;
	}
	/*
	 * If the ACK bit is off:  if in SYN-RECEIVED state or SENDSYN flag
	 * is on (half-synchronized state), then queue data for later
	 * processing; else drop segment and return.
	 */
	if ((thflags & TH_ACK) == 0) {
		if (tp->t_flags & TF_NEEDSYN) {
			return (bbr_process_data(m, th, so, tp, drop_hdrlen, tlen,
			    tiwin, thflags, nxt_pkt));
		} else if (tp->t_flags & TF_ACKNOW) {
			ctf_do_dropafterack(m, tp, th, thflags, tlen, &ret_val);
			bbr->r_wanted_output = 1;
			return (ret_val);
		} else {
			ctf_do_drop(m, NULL);
			return (0);
		}
	}
	/*
	 * Ack processing.
	 */
	if (bbr_process_ack(m, th, so, tp, to, tiwin, tlen, &ourfinisacked, thflags, &ret_val)) {
		return (ret_val);
	}
	if (sbavail(&so->so_snd)) {
		if (ctf_progress_timeout_check(tp, true)) {
			ctf_do_dropwithreset_conn(m, tp, th, BANDLIM_RST_OPENPORT, tlen);
			return (1);
		}
	}
	return (bbr_process_data(m, th, so, tp, drop_hdrlen, tlen,
	    tiwin, thflags, nxt_pkt));
}

static void
bbr_stop_all_timers(struct tcpcb *tp)
{
	struct tcp_bbr *bbr;

	/*
	 * Assure no timers are running.
	 */
	if (tcp_timer_active(tp, TT_PERSIST)) {
		/* We enter in persists, set the flag appropriately */
		bbr = (struct tcp_bbr *)tp->t_fb_ptr;
		bbr->rc_in_persist = 1;
	}
#define tcp_timer_suspend(tp,type)  tcp_timer_activate(tp, type, 0)
	tcp_timer_suspend(tp, TT_PERSIST);
	tcp_timer_suspend(tp, TT_REXMT);
	tcp_timer_suspend(tp, TT_KEEP);
	tcp_timer_suspend(tp, TT_DELACK);
}

#if 0
static void
bbr_google_mode_on(struct tcp_bbr *bbr)
{
	bbr->rc_use_google = 1;
	bbr->rc_no_pacing = 0;
	bbr->r_ctl.bbr_google_discount = bbr_google_discount;
	bbr->r_use_policer = bbr_policer_detection_enabled;
	bbr->r_ctl.rc_probertt_int = (USECS_IN_SECOND * 10);
	bbr->bbr_use_rack_cheat = 0;
	bbr->r_ctl.rc_incr_tmrs = 0;
	bbr->r_ctl.rc_inc_tcp_oh = 0;
	bbr->r_ctl.rc_inc_ip_oh = 0;
	bbr->r_ctl.rc_inc_enet_oh = 0;
	reset_time(&bbr->r_ctl.rc_delrate,
		   BBR_NUM_RTTS_FOR_GOOG_DEL_LIMIT);
	reset_time_small(&bbr->r_ctl.rc_rttprop,
			 (11 * USECS_IN_SECOND));
	tcp_bbr_tso_size_check(bbr, tcp_get_usecs(&bbr->rc_tv));
}

static void
bbr_google_mode_off(struct tcp_bbr *bbr)
{
	bbr->rc_use_google = 0;
	bbr->r_ctl.bbr_google_discount = 0;
	bbr->no_pacing_until = bbr_no_pacing_until;
	bbr->r_use_policer = 0;
	if (bbr->no_pacing_until)
		bbr->rc_no_pacing = 1;
	else
		bbr->rc_no_pacing = 0;
	if (bbr_use_rack_resend_cheat)
		bbr->bbr_use_rack_cheat = 1;
	else
		bbr->bbr_use_rack_cheat = 0;
	if (bbr_incr_timers)
		bbr->r_ctl.rc_incr_tmrs = 1;
	else
		bbr->r_ctl.rc_incr_tmrs = 0;
	if (bbr_include_tcp_oh)
		bbr->r_ctl.rc_inc_tcp_oh = 1;
	else
		bbr->r_ctl.rc_inc_tcp_oh = 0;
	if (bbr_include_ip_oh)
		bbr->r_ctl.rc_inc_ip_oh = 1;
	else
		bbr->r_ctl.rc_inc_ip_oh = 0;
	if (bbr_include_enet_oh)
		bbr->r_ctl.rc_inc_enet_oh = 1;
	else
		bbr->r_ctl.rc_inc_enet_oh = 0;
	bbr->r_ctl.rc_probertt_int = bbr_rtt_probe_limit;
	reset_time(&bbr->r_ctl.rc_delrate,
		   bbr_num_pktepo_for_del_limit);
	reset_time_small(&bbr->r_ctl.rc_rttprop,
			 (bbr_filter_len_sec * USECS_IN_SECOND));
	tcp_bbr_tso_size_check(bbr, tcp_get_usecs(&bbr->rc_tv));
}
#endif
/*
 * Return 0 on success, non-zero on failure
 * which indicates the error (usually no memory).
 */
static int
bbr_init(struct tcpcb *tp)
{
	struct tcp_bbr *bbr = NULL;
#if 0
	struct inpcb *inp;
#endif
	uint32_t cts;

	tp->t_fb_ptr = malloc(sizeof(struct tcp_bbr));
	if (tp->t_fb_ptr == NULL) {
		/*
		 * We need to allocate memory but cant. The INP and INP_INFO
		 * locks and they are recusive (happens during setup. So a
		 * scheme to drop the locks fails :(
		 *
		 */
		return (ENOMEM);
	}
	bbr = (struct tcp_bbr *)tp->t_fb_ptr;
	bbr->rtt_valid = 0;
#if 0
	inp = tp->t_inpcb;
	inp->inp_flags2 |= INP_CANNOT_DO_ECN;
	inp->inp_flags2 |= INP_SUPPORTS_MBUFQ;
#endif
	TAILQ_INIT(&bbr->r_ctl.rc_map);
	TAILQ_INIT(&bbr->r_ctl.rc_free);
	TAILQ_INIT(&bbr->r_ctl.rc_tmap);
	bbr->rc_tp = tp;
#if 0
	if (tp->t_inpcb) {
		bbr->rc_inp = tp->t_inpcb;
	}
#endif
	cts = tcp_get_usecs(&bbr->rc_tv);
	tp->t_acktime = 0;
	bbr->rc_allow_data_af_clo = bbr_ignore_data_after_close;
	bbr->r_ctl.rc_reorder_fade = bbr_reorder_fade;
	bbr->rc_tlp_threshold = bbr_tlp_thresh;
	bbr->r_ctl.rc_reorder_shift = bbr_reorder_thresh;
	bbr->r_ctl.rc_pkt_delay = bbr_pkt_delay;
	bbr->r_ctl.rc_min_to = bbr_min_to;
	bbr->rc_bbr_state = BBR_STATE_STARTUP;
	bbr->r_ctl.bbr_lost_at_state = 0;
	bbr->r_ctl.rc_lost_at_startup = 0;
	bbr->rc_all_timers_stopped = 0;
	bbr->r_ctl.rc_bbr_lastbtlbw = 0;
	bbr->r_ctl.rc_pkt_epoch_del = 0;
	bbr->r_ctl.rc_pkt_epoch = 0;
	bbr->r_ctl.rc_lowest_rtt = 0xffffffff;
	bbr->r_ctl.rc_bbr_hptsi_gain = bbr_high_gain;
	bbr->r_ctl.rc_bbr_cwnd_gain = bbr_high_gain;
	bbr->r_ctl.rc_went_idle_time = cts;
	bbr->rc_pacer_started = cts;
	bbr->r_ctl.rc_pkt_epoch_time = cts;
	bbr->r_ctl.rc_rcvtime = cts;
	bbr->r_ctl.rc_bbr_state_time = cts;
	bbr->r_ctl.rc_del_time = cts;
	bbr->r_ctl.rc_tlp_rxt_last_time = cts;
	bbr->r_ctl.last_in_probertt = cts;
	bbr->skip_gain = 0;
	bbr->gain_is_limited = 0;
	bbr->no_pacing_until = bbr_no_pacing_until;
	if (bbr->no_pacing_until)
		bbr->rc_no_pacing = 1;
	if (bbr_use_google_algo) {
		bbr->rc_no_pacing = 0;
		bbr->rc_use_google = 1;
		bbr->r_ctl.bbr_google_discount = bbr_google_discount;
		bbr->r_use_policer = bbr_policer_detection_enabled;
	} else {
		bbr->rc_use_google = 0;
		bbr->r_ctl.bbr_google_discount = 0;
		bbr->r_use_policer = 0;
	}
	if (bbr_ts_limiting)
		bbr->rc_use_ts_limit = 1;
	else
		bbr->rc_use_ts_limit = 0;
	if (bbr_ts_can_raise)
		bbr->ts_can_raise = 1;
	else
		bbr->ts_can_raise = 0;
	if (V_tcp_delack_enabled == 1)
		tp->t_delayed_ack = 2;
	else if (V_tcp_delack_enabled == 0)
		tp->t_delayed_ack = 0;
	else if (V_tcp_delack_enabled < 100)
		tp->t_delayed_ack = V_tcp_delack_enabled;
	else
		tp->t_delayed_ack = 2;
	if (bbr->rc_use_google == 0)
		bbr->r_ctl.rc_probertt_int = bbr_rtt_probe_limit;
	else
		bbr->r_ctl.rc_probertt_int = (USECS_IN_SECOND * 10);
	bbr->r_ctl.rc_min_rto_ms = bbr_rto_min_ms;
	bbr->rc_max_rto_sec = bbr_rto_max_sec;
	bbr->rc_init_win = bbr_def_init_win;
	if (tp->t_flags & TF_REQ_TSTMP)
		bbr->rc_last_options = TCP_TS_OVERHEAD;
	bbr->r_ctl.rc_pace_max_segs = tp->t_maxseg - bbr->rc_last_options;
	bbr->r_ctl.rc_high_rwnd = tp->snd_wnd;
	bbr->r_init_rtt = 1;

	counter_u64_add(bbr_flows_nohdwr_pacing, 1);
	if (bbr_allow_hdwr_pacing)
		bbr->bbr_hdw_pace_ena = 1;
	else
		bbr->bbr_hdw_pace_ena = 0;
	if (bbr_sends_full_iwnd)
		bbr->bbr_init_win_cheat = 1;
	else
		bbr->bbr_init_win_cheat = 0;
	bbr->r_ctl.bbr_utter_max = bbr_hptsi_utter_max;
	bbr->r_ctl.rc_drain_pg = bbr_drain_gain;
	bbr->r_ctl.rc_startup_pg = bbr_high_gain;
	bbr->rc_loss_exit = bbr_exit_startup_at_loss;
	bbr->r_ctl.bbr_rttprobe_gain_val = bbr_rttprobe_gain;
	bbr->r_ctl.bbr_hptsi_per_second = bbr_hptsi_per_second;
	bbr->r_ctl.bbr_hptsi_segments_delay_tar = bbr_hptsi_segments_delay_tar;
	bbr->r_ctl.bbr_hptsi_segments_max = bbr_hptsi_segments_max;
	bbr->r_ctl.bbr_hptsi_segments_floor = bbr_hptsi_segments_floor;
	bbr->r_ctl.bbr_hptsi_bytes_min = bbr_hptsi_bytes_min;
	bbr->r_ctl.bbr_cross_over = bbr_cross_over;
	bbr->r_ctl.rc_rtt_shrinks = cts;
	if (bbr->rc_use_google) {
		setup_time_filter(&bbr->r_ctl.rc_delrate,
				  FILTER_TYPE_MAX,
				  BBR_NUM_RTTS_FOR_GOOG_DEL_LIMIT);
		setup_time_filter_small(&bbr->r_ctl.rc_rttprop,
					FILTER_TYPE_MIN, (11 * USECS_IN_SECOND));
	} else {
		setup_time_filter(&bbr->r_ctl.rc_delrate,
				  FILTER_TYPE_MAX,
				  bbr_num_pktepo_for_del_limit);
		setup_time_filter_small(&bbr->r_ctl.rc_rttprop,
					FILTER_TYPE_MIN, (bbr_filter_len_sec * USECS_IN_SECOND));
	}
	if (bbr_uses_idle_restart)
		bbr->rc_use_idle_restart = 1;
	else
		bbr->rc_use_idle_restart = 0;
	bbr->r_ctl.rc_bbr_cur_del_rate = 0;
	bbr->r_ctl.rc_initial_hptsi_bw = bbr_initial_bw_bps;
	if (bbr_resends_use_tso)
		bbr->rc_resends_use_tso = 1;
	if (tp->snd_una != tp->snd_max) {
		/* Create a send map for the current outstanding data */
		struct bbr_sendmap *rsm;

		rsm = bbr_alloc(bbr);
		if (rsm == NULL) {
			free(tp->t_fb_ptr);
			tp->t_fb_ptr = NULL;
			return (ENOMEM);
		}
		rsm->r_rtt_not_allowed = 1;
		rsm->r_tim_lastsent[0] = cts;
		rsm->r_rtr_cnt = 1;
		rsm->r_rtr_bytes = 0;
		rsm->r_start = tp->snd_una;
		rsm->r_end = tp->snd_max;
		rsm->r_dupack = 0;
		rsm->r_delivered = bbr->r_ctl.rc_delivered;
		rsm->r_ts_valid = 0;
		rsm->r_del_ack_ts = tp->ts_recent;
		rsm->r_del_time = cts;
		if (bbr->r_ctl.r_app_limited_until)
			rsm->r_app_limited = 1;
		else
			rsm->r_app_limited = 0;
		TAILQ_INSERT_TAIL(&bbr->r_ctl.rc_map, rsm, r_next);
		TAILQ_INSERT_TAIL(&bbr->r_ctl.rc_tmap, rsm, r_tnext);
		rsm->r_in_tmap = 1;
		if (bbr->rc_bbr_state == BBR_STATE_PROBE_BW)
			rsm->r_bbr_state = bbr_state_val(bbr);
		else
			rsm->r_bbr_state = 8;
	}
	if (bbr_use_rack_resend_cheat && (bbr->rc_use_google == 0))
		bbr->bbr_use_rack_cheat = 1;
	if (bbr_incr_timers && (bbr->rc_use_google == 0))
		bbr->r_ctl.rc_incr_tmrs = 1;
	if (bbr_include_tcp_oh && (bbr->rc_use_google == 0))
		bbr->r_ctl.rc_inc_tcp_oh = 1;
	if (bbr_include_ip_oh && (bbr->rc_use_google == 0))
		bbr->r_ctl.rc_inc_ip_oh = 1;
	if (bbr_include_enet_oh && (bbr->rc_use_google == 0))
		bbr->r_ctl.rc_inc_enet_oh = 1;

	if (TCPS_HAVEESTABLISHED(tp->t_state) &&
	    (tp->t_srtt)) {
		uint32_t rtt;

		rtt = (TICKS_2_USEC(tp->t_srtt) >> TCP_RTT_SHIFT);
		apply_filter_min_small(&bbr->r_ctl.rc_rttprop, rtt, cts);
	}
	/* announce the settings and state */
	tcp_bbr_tso_size_check(bbr, cts);
	/*
	 * Now call the generic function to start a timer. This will place
	 * the TCB on the hptsi wheel if a timer is needed with appropriate
	 * flags.
	 */
	bbr_stop_all_timers(tp);
	bbr_start_hpts_timer(bbr, tp, cts, 5, 0, 0);
	return (0);
}

static void
bbr_fini(struct tcpcb *tp, int32_t tcb_is_purged)
{
	if (tp->t_fb_ptr) {
		uint32_t calc;
		struct tcp_bbr *bbr;
		struct bbr_sendmap *rsm;

		bbr = (struct tcp_bbr *)tp->t_fb_ptr;
#if 0
		if (bbr->r_ctl.crte)
			tcp_rel_pacing_rate(bbr->r_ctl.crte, bbr->rc_tp);
#endif
		bbr->rc_tp = NULL;
#if 0
		if (tp->t_inpcb) {
			/* Backout any flags2 we applied */
			tp->t_inpcb->inp_flags2 &= ~INP_CANNOT_DO_ECN;
			tp->t_inpcb->inp_flags2 &= ~INP_SUPPORTS_MBUFQ;
			tp->t_inpcb->inp_flags2 &= ~INP_MBUF_QUEUE_READY;
		}
#endif
		if (bbr->bbr_hdrw_pacing)
			counter_u64_add(bbr_flows_whdwr_pacing, -1);
		else
			counter_u64_add(bbr_flows_nohdwr_pacing, -1);
#if 0
		if (bbr->r_ctl.crte != NULL) {
			tcp_rel_pacing_rate(bbr->r_ctl.crte, tp);
			bbr->r_ctl.crte = NULL;
		}
#endif
		rsm = TAILQ_FIRST(&bbr->r_ctl.rc_map);
		while (rsm) {
			TAILQ_REMOVE(&bbr->r_ctl.rc_map, rsm, r_next);
			free(rsm);
			rsm = TAILQ_FIRST(&bbr->r_ctl.rc_map);
		}
		rsm = TAILQ_FIRST(&bbr->r_ctl.rc_free);
		while (rsm) {
			TAILQ_REMOVE(&bbr->r_ctl.rc_free, rsm, r_next);
			free(rsm);
			rsm = TAILQ_FIRST(&bbr->r_ctl.rc_free);
		}
		calc = bbr->r_ctl.rc_high_rwnd - bbr->r_ctl.rc_init_rwnd;
		if (calc > (bbr->r_ctl.rc_init_rwnd / 10))
			BBR_STAT_INC(bbr_dynamic_rwnd);
		else
			BBR_STAT_INC(bbr_static_rwnd);
		bbr->r_ctl.rc_free_cnt = 0;
		free(tp->t_fb_ptr);
		tp->t_fb_ptr = NULL;
	}
	/* Make sure snd_nxt is correctly set */
	tp->snd_nxt = tp->snd_max;
}

static void
bbr_set_state(struct tcpcb *tp, struct tcp_bbr *bbr, uint32_t win)
{
	switch (tp->t_state) {
	case TCPS_SYN_SENT:
		bbr->r_state = TCPS_SYN_SENT;
		bbr->r_substate = bbr_do_syn_sent;
		break;
	case TCPS_SYN_RECEIVED:
		bbr->r_state = TCPS_SYN_RECEIVED;
		bbr->r_substate = bbr_do_syn_recv;
		break;
	case TCPS_ESTABLISHED:
		bbr->r_ctl.rc_init_rwnd = max(win, bbr->rc_tp->snd_wnd);
		bbr->r_state = TCPS_ESTABLISHED;
		bbr->r_substate = bbr_do_established;
		break;
	case TCPS_CLOSE_WAIT:
		bbr->r_state = TCPS_CLOSE_WAIT;
		bbr->r_substate = bbr_do_close_wait;
		break;
	case TCPS_FIN_WAIT_1:
		bbr->r_state = TCPS_FIN_WAIT_1;
		bbr->r_substate = bbr_do_fin_wait_1;
		break;
	case TCPS_CLOSING:
		bbr->r_state = TCPS_CLOSING;
		bbr->r_substate = bbr_do_closing;
		break;
	case TCPS_LAST_ACK:
		bbr->r_state = TCPS_LAST_ACK;
		bbr->r_substate = bbr_do_lastack;
		break;
	case TCPS_FIN_WAIT_2:
		bbr->r_state = TCPS_FIN_WAIT_2;
		bbr->r_substate = bbr_do_fin_wait_2;
		break;
	case TCPS_LISTEN:
	case TCPS_CLOSED:
	case TCPS_TIME_WAIT:
	default:
		break;
	};
}

static void
bbr_substate_change(struct tcp_bbr *bbr, uint32_t cts, int32_t line, int dolog)
{
	/*
	 * Now what state are we going into now? Is there adjustments
	 * needed?
	 */
#if 0
	int32_t old_state, old_gain;
#else
        int32_t old_state;
#endif

	old_state = bbr_state_val(bbr);
#if 0
	old_gain = bbr->r_ctl.rc_bbr_hptsi_gain;
#endif
	if (bbr_state_val(bbr) == BBR_SUB_LEVEL1) {
		/* Save the lowest srtt we saw in our end of the sub-state */
		bbr->rc_hit_state_1 = 0;
		if (bbr->r_ctl.bbr_smallest_srtt_this_state != 0xffffffff)
			bbr->r_ctl.bbr_smallest_srtt_state2 = bbr->r_ctl.bbr_smallest_srtt_this_state;
	}
	bbr->rc_bbr_substate++;
	if (bbr->rc_bbr_substate >= BBR_SUBSTATE_COUNT) {
		/* Cycle back to first state-> gain */
		bbr->rc_bbr_substate = 0;
	}
	if (bbr_state_val(bbr) == BBR_SUB_GAIN) {
		/*
		 * We enter the gain(5/4) cycle (possibly less if
		 * shallow buffer detection is enabled)
		 */
		if (bbr->skip_gain) {
			/*
			 * Hardware pacing has set our rate to
			 * the max and limited our b/w just
			 * do level i.e. no gain.
			 */
			bbr->r_ctl.rc_bbr_hptsi_gain = bbr_hptsi_gain[BBR_SUB_LEVEL1];
		} else if (bbr->gain_is_limited &&
			   bbr->bbr_hdrw_pacing &&
			   bbr->r_ctl.crte) {
#if 0
			/*
			 * We can't gain above the hardware pacing
			 * rate which is less than our rate + the gain
			 * calculate the gain needed to reach the hardware
			 * pacing rate..
			 */
			uint64_t bw, rate, gain_calc;

			bw = bbr_get_bw(bbr);
			rate = bbr->r_ctl.crte->rate;
			if ((rate > bw) &&
			    (((bw *  (uint64_t)bbr_hptsi_gain[BBR_SUB_GAIN]) / (uint64_t)BBR_UNIT) > rate)) {
				gain_calc = (rate * BBR_UNIT) / bw;
				if (gain_calc < BBR_UNIT)
					gain_calc = BBR_UNIT;
				bbr->r_ctl.rc_bbr_hptsi_gain = (uint16_t)gain_calc;
			} else {
				bbr->r_ctl.rc_bbr_hptsi_gain = bbr_hptsi_gain[BBR_SUB_GAIN];
			}
#endif
		} else
			bbr->r_ctl.rc_bbr_hptsi_gain = bbr_hptsi_gain[BBR_SUB_GAIN];
		if ((bbr->rc_use_google == 0) && (bbr_gain_to_target == 0)) {
			bbr->r_ctl.rc_bbr_state_atflight = cts;
		} else
			bbr->r_ctl.rc_bbr_state_atflight = 0;
	} else if (bbr_state_val(bbr) == BBR_SUB_DRAIN) {
		bbr->rc_hit_state_1 = 1;
		bbr->r_ctl.rc_exta_time_gd = 0;
		bbr->r_ctl.flightsize_at_drain = ctf_flight_size(bbr->rc_tp,
						     (bbr->r_ctl.rc_sacked + bbr->r_ctl.rc_lost_bytes));
		if (bbr_state_drain_2_tar) {
			bbr->r_ctl.rc_bbr_state_atflight = 0;
		} else
			bbr->r_ctl.rc_bbr_state_atflight = cts;
		bbr->r_ctl.rc_bbr_hptsi_gain = bbr_hptsi_gain[BBR_SUB_DRAIN];
	} else {
		/* All other cycles hit here 2-7 */
		if ((old_state == BBR_SUB_DRAIN) && bbr->rc_hit_state_1) {
			if (bbr_sub_drain_slam_cwnd &&
			    (bbr->rc_use_google == 0) &&
			    (bbr->rc_tp->snd_cwnd < bbr->r_ctl.rc_saved_cwnd)) {
				bbr->rc_tp->snd_cwnd = bbr->r_ctl.rc_saved_cwnd;
			}
			if ((cts - bbr->r_ctl.rc_bbr_state_time) > bbr_get_rtt(bbr, BBR_RTT_PROP))
				bbr->r_ctl.rc_exta_time_gd += ((cts - bbr->r_ctl.rc_bbr_state_time) -
							       bbr_get_rtt(bbr, BBR_RTT_PROP));
			else
				bbr->r_ctl.rc_exta_time_gd = 0;
			if (bbr->r_ctl.rc_exta_time_gd) {
				bbr->r_ctl.rc_level_state_extra = bbr->r_ctl.rc_exta_time_gd;
				/* Now chop up the time for each state (div by 7) */
				bbr->r_ctl.rc_level_state_extra /= 7;
				if (bbr_rand_ot && bbr->r_ctl.rc_level_state_extra) {
					/* Add a randomization */
					bbr_randomize_extra_state_time(bbr);
				}
			}
		}
		bbr->r_ctl.rc_bbr_state_atflight = max(1, cts);
		bbr->r_ctl.rc_bbr_hptsi_gain = bbr_hptsi_gain[bbr_state_val(bbr)];
	}
	if (bbr->rc_use_google) {
		bbr->r_ctl.rc_bbr_state_atflight = max(1, cts);
	}
	bbr->r_ctl.bbr_lost_at_state = bbr->r_ctl.rc_lost;
	bbr->r_ctl.rc_bbr_cwnd_gain = bbr_cwnd_gain;

	if (SEQ_GT(cts, bbr->r_ctl.rc_bbr_state_time)) {
		uint32_t time_in;

		time_in = cts - bbr->r_ctl.rc_bbr_state_time;
		if (bbr->rc_bbr_state == BBR_STATE_PROBE_BW) {
			counter_u64_add(bbr_state_time[(old_state + 5)], time_in);
		} else {
			counter_u64_add(bbr_state_time[bbr->rc_bbr_state], time_in);
		}
	}
	bbr->r_ctl.bbr_smallest_srtt_this_state = 0xffffffff;
	bbr_set_state_target(bbr, __LINE__);
	if (bbr_sub_drain_slam_cwnd &&
	    (bbr->rc_use_google == 0) &&
	    (bbr_state_val(bbr) == BBR_SUB_DRAIN)) {
		/* Slam down the cwnd */
		bbr->r_ctl.rc_saved_cwnd = bbr->rc_tp->snd_cwnd;
		bbr->rc_tp->snd_cwnd = bbr->r_ctl.rc_target_at_state;
		if (bbr_sub_drain_app_limit) {
			/* Go app limited if we are on a long drain */
			bbr->r_ctl.r_app_limited_until = (bbr->r_ctl.rc_delivered +
							  ctf_flight_size(bbr->rc_tp,
							      (bbr->r_ctl.rc_sacked +
							       bbr->r_ctl.rc_lost_bytes)));
		}
	}
	if (bbr->rc_lt_use_bw) {
		/* In policed mode we clamp pacing_gain to BBR_UNIT */
		bbr->r_ctl.rc_bbr_hptsi_gain = BBR_UNIT;
	}
	/* Google changes TSO size every cycle */
	if (bbr->rc_use_google)
		tcp_bbr_tso_size_check(bbr, cts);
	bbr->r_ctl.gain_epoch = cts;
	bbr->r_ctl.rc_bbr_state_time = cts;
	bbr->r_ctl.substate_pe = bbr->r_ctl.rc_pkt_epoch;
}

static void
bbr_set_probebw_google_gains(struct tcp_bbr *bbr, uint32_t cts, uint32_t losses)
{
	if ((bbr_state_val(bbr) == BBR_SUB_DRAIN) &&
	    (google_allow_early_out == 1) &&
	    (bbr->r_ctl.rc_flight_at_input <= bbr->r_ctl.rc_target_at_state)) {
		/* We have reached out target flight size possibly early */
		goto change_state;
	}
	if (TSTMP_LT(cts, bbr->r_ctl.rc_bbr_state_time)) {
		return;
	}
	if ((cts - bbr->r_ctl.rc_bbr_state_time) < bbr_get_rtt(bbr, BBR_RTT_PROP)) {
		/*
		 * Must be a rttProp movement forward before
		 * we can change states.
		 */
		return;
	}
	if (bbr_state_val(bbr) == BBR_SUB_GAIN) {
		/*
		 * The needed time has passed but for
		 * the gain cycle extra rules apply:
		 * 1) If we have seen loss, we exit
		 * 2) If we have not reached the target
		 *    we stay in GAIN (gain-to-target).
		 */
		if (google_consider_lost && losses)
			goto change_state;
		if (bbr->r_ctl.rc_target_at_state > bbr->r_ctl.rc_flight_at_input) {
			return;
		}
	}
change_state:
	/* For gain we must reach our target, all others last 1 rttProp */
	bbr_substate_change(bbr, cts, __LINE__, 1);
}

static void
bbr_set_probebw_gains(struct tcp_bbr *bbr, uint32_t cts, uint32_t losses)
{
	uint32_t flight, bbr_cur_cycle_time;

	if (bbr->rc_use_google) {
		bbr_set_probebw_google_gains(bbr, cts, losses);
		return;
	}
	if (cts == 0) {
		/*
		 * Never alow cts to be 0 we
		 * do this so we can judge if
		 * we have set a timestamp.
		 */
		cts = 1;
	}
	if (bbr_state_is_pkt_epoch)
		bbr_cur_cycle_time = bbr_get_rtt(bbr, BBR_RTT_PKTRTT);
	else
		bbr_cur_cycle_time = bbr_get_rtt(bbr, BBR_RTT_PROP);

	if (bbr->r_ctl.rc_bbr_state_atflight == 0) {
		if (bbr_state_val(bbr) == BBR_SUB_DRAIN) {
			flight = ctf_flight_size(bbr->rc_tp,
				     (bbr->r_ctl.rc_sacked + bbr->r_ctl.rc_lost_bytes));
			if (bbr_sub_drain_slam_cwnd && bbr->rc_hit_state_1) {
				/* Keep it slam down */
				if (bbr->rc_tp->snd_cwnd > bbr->r_ctl.rc_target_at_state) {
					bbr->rc_tp->snd_cwnd = bbr->r_ctl.rc_target_at_state;
				}
				if (bbr_sub_drain_app_limit) {
					/* Go app limited if we are on a long drain */
					bbr->r_ctl.r_app_limited_until = (bbr->r_ctl.rc_delivered + flight);
				}
			}
			if (TSTMP_GT(cts, bbr->r_ctl.gain_epoch) &&
			    (((cts - bbr->r_ctl.gain_epoch) > bbr_get_rtt(bbr, BBR_RTT_PROP)) ||
			     (flight >= bbr->r_ctl.flightsize_at_drain))) {
				/*
				 * Still here after the same time as
				 * the gain. We need to drain harder
				 * for the next srtt. Reduce by a set amount
				 * the gain drop is capped at DRAIN states
				 * value (88).
				 */
				bbr->r_ctl.flightsize_at_drain = flight;
				if (bbr_drain_drop_mul &&
				    bbr_drain_drop_div &&
				    (bbr_drain_drop_mul < bbr_drain_drop_div)) {
					/* Use your specific drop value (def 4/5 = 20%) */
					bbr->r_ctl.rc_bbr_hptsi_gain *= bbr_drain_drop_mul;
					bbr->r_ctl.rc_bbr_hptsi_gain /= bbr_drain_drop_div;
				} else {
					/* You get drop of 20% */
					bbr->r_ctl.rc_bbr_hptsi_gain *= 4;
					bbr->r_ctl.rc_bbr_hptsi_gain /= 5;
				}
				if (bbr->r_ctl.rc_bbr_hptsi_gain <= bbr_drain_floor) {
					/* Reduce our gain again to the bottom  */
					bbr->r_ctl.rc_bbr_hptsi_gain = max(bbr_drain_floor, 1);
				}
				/*
				 * Extend out so we wait another
				 * epoch before dropping again.
				 */
				bbr->r_ctl.gain_epoch = cts;
			}
			if (flight <= bbr->r_ctl.rc_target_at_state) {
				if (bbr_sub_drain_slam_cwnd &&
				    (bbr->rc_use_google == 0) &&
				    (bbr->rc_tp->snd_cwnd < bbr->r_ctl.rc_saved_cwnd)) {
					bbr->rc_tp->snd_cwnd = bbr->r_ctl.rc_saved_cwnd;
				}
				bbr->r_ctl.rc_bbr_state_atflight = max(cts, 1);
			}
		} else {
			/* Its a gain  */
			if (bbr->r_ctl.rc_lost > bbr->r_ctl.bbr_lost_at_state) {
				bbr->r_ctl.rc_bbr_state_atflight = max(cts, 1);
				goto change_state;
			}
			if ((ctf_outstanding(bbr->rc_tp) >= bbr->r_ctl.rc_target_at_state) ||
			    ((ctf_outstanding(bbr->rc_tp) +  bbr->rc_tp->t_maxseg - 1) >=
			     bbr->rc_tp->snd_wnd)) {
				bbr->r_ctl.rc_bbr_state_atflight = max(cts, 1);
			}
		}
		/**
		 * We fall through and return always one of two things has
		 * occured.
		 * 1) We are still not at target
		 *    <or>
		 * 2) We reached the target and set rc_bbr_state_atflight
		 *    which means we no longer hit this block
		 *    next time we are called.
		 */
		return;
	}
change_state:
	if (TSTMP_LT(cts, bbr->r_ctl.rc_bbr_state_time))
		return;
	if ((cts - bbr->r_ctl.rc_bbr_state_time) < bbr_cur_cycle_time) {
		/* Less than a full time-period has passed */
		return;
	}
	if (bbr->r_ctl.rc_level_state_extra &&
	    (bbr_state_val(bbr) > BBR_SUB_DRAIN) &&
	    ((cts - bbr->r_ctl.rc_bbr_state_time) <
	     (bbr_cur_cycle_time + bbr->r_ctl.rc_level_state_extra))) {
		/* Less than a full time-period + extra has passed */
		return;
	}
	if (bbr_gain_gets_extra_too &&
	    bbr->r_ctl.rc_level_state_extra &&
	    (bbr_state_val(bbr) == BBR_SUB_GAIN) &&
	    ((cts - bbr->r_ctl.rc_bbr_state_time) <
	     (bbr_cur_cycle_time + bbr->r_ctl.rc_level_state_extra))) {
		/* Less than a full time-period + extra has passed */
		return;
	}
	bbr_substate_change(bbr, cts, __LINE__, 1);
}

static uint32_t
bbr_get_a_state_target(struct tcp_bbr *bbr, uint32_t gain)
{
	uint32_t mss, tar;

	if (bbr->rc_use_google) {
		/* Google just uses the cwnd target */
		tar = bbr_get_target_cwnd(bbr, bbr_get_bw(bbr), gain);
	} else {
		mss = min((bbr->rc_tp->t_maxseg - bbr->rc_last_options),
			  bbr->r_ctl.rc_pace_max_segs);
		/* Get the base cwnd with gain rounded to a mss */
		tar = roundup(bbr_get_raw_target_cwnd(bbr, bbr_get_bw(bbr),
						      gain), mss);
		/* Make sure it is within our min */
		if (tar < get_min_cwnd(bbr))
			return (get_min_cwnd(bbr));
	}
	return (tar);
}

static void
bbr_set_state_target(struct tcp_bbr *bbr, int line)
{
	uint32_t tar;

	if ((bbr->rc_bbr_state == BBR_STATE_PROBE_RTT) &&
	    ((bbr->r_ctl.bbr_rttprobe_gain_val == 0) || bbr->rc_use_google)) {
		/* Special case using old probe-rtt method */
		tar = bbr_rtt_probe_cwndtarg * (bbr->rc_tp->t_maxseg - bbr->rc_last_options);
	} else {
		/* Non-probe-rtt case and reduced probe-rtt  */
		if ((bbr->rc_bbr_state == BBR_STATE_PROBE_BW) &&
		    (bbr->r_ctl.rc_bbr_hptsi_gain > BBR_UNIT)) {
			/* For gain cycle we use the hptsi gain */
			tar = bbr_get_a_state_target(bbr, bbr->r_ctl.rc_bbr_hptsi_gain);
		} else if ((bbr_target_is_bbunit) || bbr->rc_use_google) {
			/*
			 * If configured, or for google all other states
			 * get BBR_UNIT.
			 */
			tar = bbr_get_a_state_target(bbr, BBR_UNIT);
		} else {
			/*
			 * Or we set a target based on the pacing gain
			 * for non-google mode and default (non-configured).
			 * Note we don't set a target goal below drain (192).
			 */
			if (bbr->r_ctl.rc_bbr_hptsi_gain < bbr_hptsi_gain[BBR_SUB_DRAIN])  {
				tar = bbr_get_a_state_target(bbr, bbr_hptsi_gain[BBR_SUB_DRAIN]);
			} else {
				tar = bbr_get_a_state_target(bbr, bbr->r_ctl.rc_bbr_hptsi_gain);
			}
		}
	}
	bbr->r_ctl.rc_target_at_state = tar;
}

static void
bbr_enter_probe_rtt(struct tcp_bbr *bbr, uint32_t cts, int32_t line)
{
	/* Change to probe_rtt */
	uint32_t time_in;

	bbr->r_ctl.bbr_lost_at_state = bbr->r_ctl.rc_lost;
	bbr->r_ctl.flightsize_at_drain = ctf_flight_size(bbr->rc_tp,
					     (bbr->r_ctl.rc_sacked + bbr->r_ctl.rc_lost_bytes));
	bbr->r_ctl.r_app_limited_until = (bbr->r_ctl.flightsize_at_drain
					  + bbr->r_ctl.rc_delivered);
	/* Setup so we force feed the filter */
	if (bbr->rc_use_google || bbr_probertt_sets_rtt)
		bbr->rc_prtt_set_ts = 1;
	if (SEQ_GT(cts, bbr->r_ctl.rc_bbr_state_time)) {
		time_in = cts - bbr->r_ctl.rc_bbr_state_time;
		counter_u64_add(bbr_state_time[bbr->rc_bbr_state], time_in);
	}
	bbr->r_ctl.rc_rtt_shrinks = cts;
	bbr->r_ctl.last_in_probertt = cts;
	bbr->r_ctl.rc_probertt_srttchktim = cts;
	bbr->r_ctl.rc_bbr_state_time = cts;
	bbr->rc_bbr_state = BBR_STATE_PROBE_RTT;
	/* We need to force the filter to update */

	if ((bbr_sub_drain_slam_cwnd) &&
	    bbr->rc_hit_state_1 &&
	    (bbr->rc_use_google == 0) &&
	    (bbr_state_val(bbr) == BBR_SUB_DRAIN)) {
		if (bbr->rc_tp->snd_cwnd > bbr->r_ctl.rc_saved_cwnd)
			bbr->r_ctl.rc_saved_cwnd = bbr->rc_tp->snd_cwnd;
	} else
		bbr->r_ctl.rc_saved_cwnd = bbr->rc_tp->snd_cwnd;
	/* Update the lost */
	bbr->r_ctl.rc_lost_at_startup = bbr->r_ctl.rc_lost;
	if ((bbr->r_ctl.bbr_rttprobe_gain_val == 0) || bbr->rc_use_google){
		/* Set to the non-configurable default of 4 (PROBE_RTT_MIN)  */
		bbr->rc_tp->snd_cwnd = bbr_rtt_probe_cwndtarg * (bbr->rc_tp->t_maxseg - bbr->rc_last_options);
		bbr->r_ctl.rc_bbr_hptsi_gain = BBR_UNIT;
		bbr->r_ctl.rc_bbr_cwnd_gain = BBR_UNIT;
		bbr->r_ctl.rc_target_at_state = bbr->rc_tp->snd_cwnd;
	} else {
		/*
		 * We bring it down slowly by using a hptsi gain that is
		 * probably 75%. This will slowly float down our outstanding
		 * without tampering with the cwnd.
		 */
		bbr->r_ctl.rc_bbr_hptsi_gain = bbr->r_ctl.bbr_rttprobe_gain_val;
		bbr->r_ctl.rc_bbr_cwnd_gain = BBR_UNIT;
		bbr_set_state_target(bbr, __LINE__);
		if (bbr_prtt_slam_cwnd &&
		    (bbr->rc_tp->snd_cwnd > bbr->r_ctl.rc_target_at_state)) {
			bbr->rc_tp->snd_cwnd = bbr->r_ctl.rc_target_at_state;
		}
	}
	if (ctf_flight_size(bbr->rc_tp,
		(bbr->r_ctl.rc_sacked + bbr->r_ctl.rc_lost_bytes)) <=
	    bbr->r_ctl.rc_target_at_state) {
		/* We are at target */
		bbr->r_ctl.rc_bbr_enters_probertt = cts;
	} else {
		/* We need to come down to reach target before our time begins */
		bbr->r_ctl.rc_bbr_enters_probertt = 0;
	}
	bbr->r_ctl.rc_pe_of_prtt = bbr->r_ctl.rc_pkt_epoch;
	BBR_STAT_INC(bbr_enter_probertt);
}

static void
bbr_check_probe_rtt_limits(struct tcp_bbr *bbr, uint32_t cts)
{
	/*
	 * Sanity check on probe-rtt intervals.
	 * In crazy situations where we are competing
	 * against new-reno flows with huge buffers
	 * our rtt-prop interval could come to dominate
	 * things if we can't get through a full set
	 * of cycles, we need to adjust it.
	 */
	if (bbr_can_adjust_probertt &&
	    (bbr->rc_use_google == 0)) {
		uint32_t cur_rttp, fval, newval, baseval;

		/* Are we to small and go into probe-rtt to often? */
		baseval = (bbr_get_rtt(bbr, BBR_RTT_PROP) * (BBR_SUBSTATE_COUNT + 1));
		cur_rttp = roundup(baseval, USECS_IN_SECOND);
		fval = bbr_filter_len_sec * USECS_IN_SECOND;
		if (bbr_is_ratio == 0) {
			if (fval > bbr_rtt_probe_limit)
				newval = cur_rttp + (fval - bbr_rtt_probe_limit);
			else
				newval = cur_rttp;
		} else {
			int mul;

			mul = fval / bbr_rtt_probe_limit;
			newval = cur_rttp * mul;
		}
		if (cur_rttp > 	bbr->r_ctl.rc_probertt_int) {
			bbr->r_ctl.rc_probertt_int = cur_rttp;
			reset_time_small(&bbr->r_ctl.rc_rttprop, newval);
		} else {
			/*
			 * No adjustments were made
			 * do we need to shrink it?
			 */
			if (bbr->r_ctl.rc_probertt_int > bbr_rtt_probe_limit) {
				if (cur_rttp <= bbr_rtt_probe_limit) {
					/*
					 * Things have calmed down lets
					 * shrink all the way to default
					 */
					bbr->r_ctl.rc_probertt_int = bbr_rtt_probe_limit;
					reset_time_small(&bbr->r_ctl.rc_rttprop,
							 (bbr_filter_len_sec * USECS_IN_SECOND));
					cur_rttp = bbr_rtt_probe_limit;
					newval = (bbr_filter_len_sec * USECS_IN_SECOND);
				} else {
					/*
					 * Well does some adjustment make sense?
					 */
					if (cur_rttp < bbr->r_ctl.rc_probertt_int) {
						/* We can reduce interval time some */
						bbr->r_ctl.rc_probertt_int = cur_rttp;
						reset_time_small(&bbr->r_ctl.rc_rttprop, newval);
					}
				}
			}
		}
	}
}

static void
bbr_exit_probe_rtt(struct tcpcb *tp, struct tcp_bbr *bbr, uint32_t cts)
{
	/* Exit probe-rtt */

	if (tp->snd_cwnd < bbr->r_ctl.rc_saved_cwnd) {
		tp->snd_cwnd = bbr->r_ctl.rc_saved_cwnd;
	}
	bbr->rc_hit_state_1 = 0;
	bbr->r_ctl.rc_rtt_shrinks = cts;
	bbr->r_ctl.last_in_probertt = cts;
	bbr->r_ctl.bbr_lost_at_state = bbr->r_ctl.rc_lost;
	bbr->r_ctl.r_app_limited_until = (ctf_flight_size(tp,
					      (bbr->r_ctl.rc_sacked + bbr->r_ctl.rc_lost_bytes)) +
					  bbr->r_ctl.rc_delivered);
	if (SEQ_GT(cts, bbr->r_ctl.rc_bbr_state_time)) {
		uint32_t time_in;

		time_in = cts - bbr->r_ctl.rc_bbr_state_time;
		counter_u64_add(bbr_state_time[bbr->rc_bbr_state], time_in);
	}
	if (bbr->rc_filled_pipe) {
		/* Switch to probe_bw */
		bbr->rc_bbr_state = BBR_STATE_PROBE_BW;
		bbr->rc_bbr_substate = bbr_pick_probebw_substate(bbr, cts);
		bbr->r_ctl.rc_bbr_cwnd_gain = bbr_cwnd_gain;
		bbr_substate_change(bbr, cts, __LINE__, 0);
	} else {
		/* Back to startup */
		bbr->rc_bbr_state = BBR_STATE_STARTUP;
		bbr->r_ctl.rc_bbr_state_time = cts;
		/*
		 * We don't want to give a complete free 3
		 * measurements until we exit, so we use
		 * the number of pe's we were in probe-rtt
		 * to add to the startup_epoch. That way
		 * we will still retain the old state.
		 */
		bbr->r_ctl.rc_bbr_last_startup_epoch += (bbr->r_ctl.rc_pkt_epoch - bbr->r_ctl.rc_pe_of_prtt);
		bbr->r_ctl.rc_lost_at_startup = bbr->r_ctl.rc_lost;
		/* Make sure to use the lower pg when shifting back in */
		if (bbr->r_ctl.rc_lost &&
		    bbr_use_lower_gain_in_startup &&
		    (bbr->rc_use_google == 0))
			bbr->r_ctl.rc_bbr_hptsi_gain = bbr_startup_lower;
		else
			bbr->r_ctl.rc_bbr_hptsi_gain = bbr->r_ctl.rc_startup_pg;
		bbr->r_ctl.rc_bbr_cwnd_gain = bbr->r_ctl.rc_startup_pg;
		/* Probably not needed but set it anyway */
		bbr_set_state_target(bbr, __LINE__);
	}
	bbr_check_probe_rtt_limits(bbr, cts);
}

static int32_t inline
bbr_should_enter_probe_rtt(struct tcp_bbr *bbr, uint32_t cts)
{
	if ((bbr->rc_past_init_win == 1) &&
	    (bbr->rc_in_persist == 0) &&
	    (bbr_calc_time(cts, bbr->r_ctl.rc_rtt_shrinks) >= bbr->r_ctl.rc_probertt_int)) {
		return (1);
	}
	if (bbr_can_force_probertt &&
	    (bbr->rc_in_persist == 0) &&
	    (TSTMP_GT(cts, bbr->r_ctl.last_in_probertt)) &&
	    ((cts - bbr->r_ctl.last_in_probertt) > bbr->r_ctl.rc_probertt_int)) {
		return (1);
	}
	return (0);
}

static int32_t
bbr_google_startup(struct tcp_bbr *bbr, uint32_t cts, int32_t  pkt_epoch)
{
	uint64_t btlbw, gain;
	if (pkt_epoch == 0) {
		/*
		 * Need to be on a pkt-epoch to continue.
		 */
		return (0);
	}
	btlbw = bbr_get_full_bw(bbr);
	gain = ((bbr->r_ctl.rc_bbr_lastbtlbw *
		 (uint64_t)bbr_start_exit) / (uint64_t)100) + bbr->r_ctl.rc_bbr_lastbtlbw;
	if (btlbw >= gain) {
		bbr->r_ctl.rc_bbr_last_startup_epoch = bbr->r_ctl.rc_pkt_epoch;
		bbr->r_ctl.rc_bbr_lastbtlbw = btlbw;
	}
	if ((bbr->r_ctl.rc_pkt_epoch - bbr->r_ctl.rc_bbr_last_startup_epoch) >= BBR_STARTUP_EPOCHS)
		return (1);
	return(0);
}

static int32_t inline
bbr_state_startup(struct tcp_bbr *bbr, uint32_t cts, int32_t epoch, int32_t pkt_epoch)
{
	/* Have we gained 25% in the last 3 packet based epoch's? */
	uint64_t btlbw, gain;
	int do_exit;
	int delta, rtt_gain;

	if ((bbr->rc_tp->snd_una == bbr->rc_tp->snd_max) &&
	    (bbr_calc_time(cts, bbr->r_ctl.rc_went_idle_time) >= bbr_rtt_probe_time)) {
		/*
		 * This qualifies as a RTT_PROBE session since we drop the
		 * data outstanding to nothing and waited more than
		 * bbr_rtt_probe_time.
		 */
		bbr_set_reduced_rtt(bbr, cts, __LINE__);
	}
	if (bbr_should_enter_probe_rtt(bbr, cts)) {
		bbr_enter_probe_rtt(bbr, cts, __LINE__);
		return (0);
	}
	if (bbr->rc_use_google)
		return (bbr_google_startup(bbr, cts,  pkt_epoch));

	if ((bbr->r_ctl.rc_lost > bbr->r_ctl.rc_lost_at_startup) &&
	    (bbr_use_lower_gain_in_startup)) {
		/* Drop to a lower gain 1.5 x since we saw loss */
		bbr->r_ctl.rc_bbr_hptsi_gain = bbr_startup_lower;
	}
	if (pkt_epoch == 0) {
		/*
		 * Need to be on a pkt-epoch to continue.
		 */
		return (0);
	}
	if (bbr_rtt_gain_thresh) {
		/*
		 * Do we allow a flow to stay
		 * in startup with no loss and no
		 * gain in rtt over a set threshold?
		 */
		if (bbr->r_ctl.rc_pkt_epoch_rtt &&
		    bbr->r_ctl.startup_last_srtt &&
		    (bbr->r_ctl.rc_pkt_epoch_rtt > bbr->r_ctl.startup_last_srtt)) {
			delta = bbr->r_ctl.rc_pkt_epoch_rtt - bbr->r_ctl.startup_last_srtt;
			rtt_gain = (delta * 100) / bbr->r_ctl.startup_last_srtt;
		} else
			rtt_gain = 0;
		if ((bbr->r_ctl.startup_last_srtt == 0)  ||
		    (bbr->r_ctl.rc_pkt_epoch_rtt < bbr->r_ctl.startup_last_srtt))
			/* First time or new lower value */
			bbr->r_ctl.startup_last_srtt = bbr->r_ctl.rc_pkt_epoch_rtt;

		if ((bbr->r_ctl.rc_lost == 0) &&
		    (rtt_gain < bbr_rtt_gain_thresh)) {
			/*
			 * No loss, and we are under
			 * our gain threhold for
			 * increasing RTT.
			 */
			if (bbr->r_ctl.rc_bbr_last_startup_epoch < bbr->r_ctl.rc_pkt_epoch)
				bbr->r_ctl.rc_bbr_last_startup_epoch++;
			return (0);
		}
	}
	if ((bbr->r_ctl.r_measurement_count == bbr->r_ctl.last_startup_measure) &&
	    (bbr->r_ctl.rc_lost_at_startup == bbr->r_ctl.rc_lost) &&
	    (!IN_RECOVERY(bbr->rc_tp->t_flags))) {
		/*
		 * We only assess if we have a new measurement when
		 * we have no loss and are not in recovery.
		 * Drag up by one our last_startup epoch so we will hold
		 * the number of non-gain we have already accumulated.
		 */
		if (bbr->r_ctl.rc_bbr_last_startup_epoch < bbr->r_ctl.rc_pkt_epoch)
			bbr->r_ctl.rc_bbr_last_startup_epoch++;
		return (0);
	}
	/* Case where we reduced the lost (bad retransmit) */
	if (bbr->r_ctl.rc_lost_at_startup > bbr->r_ctl.rc_lost)
		bbr->r_ctl.rc_lost_at_startup = bbr->r_ctl.rc_lost;
	bbr->r_ctl.last_startup_measure = bbr->r_ctl.r_measurement_count;
	btlbw = bbr_get_full_bw(bbr);
	if (bbr->r_ctl.rc_bbr_hptsi_gain == bbr_startup_lower)
		gain = ((bbr->r_ctl.rc_bbr_lastbtlbw *
			 (uint64_t)bbr_low_start_exit) / (uint64_t)100) + bbr->r_ctl.rc_bbr_lastbtlbw;
	else
		gain = ((bbr->r_ctl.rc_bbr_lastbtlbw *
			 (uint64_t)bbr_start_exit) / (uint64_t)100) + bbr->r_ctl.rc_bbr_lastbtlbw;
	do_exit = 0;
	if (btlbw > bbr->r_ctl.rc_bbr_lastbtlbw)
		bbr->r_ctl.rc_bbr_lastbtlbw = btlbw;
	if (btlbw >= gain) {
		bbr->r_ctl.rc_bbr_last_startup_epoch = bbr->r_ctl.rc_pkt_epoch;
		/* Update the lost so we won't exit in next set of tests */
		bbr->r_ctl.rc_lost_at_startup = bbr->r_ctl.rc_lost;
	}
	if ((bbr->rc_loss_exit &&
	     (bbr->r_ctl.rc_lost > bbr->r_ctl.rc_lost_at_startup) &&
	     (bbr->r_ctl.rc_pkt_epoch_loss_rate > bbr_startup_loss_thresh)) &&
	    ((bbr->r_ctl.rc_pkt_epoch - bbr->r_ctl.rc_bbr_last_startup_epoch) >= BBR_STARTUP_EPOCHS)) {
		/*
		 * If we had no gain,  we had loss and that loss was above
		 * our threshould, the rwnd is not constrained, and we have
		 * had at least 3 packet epochs exit. Note that this is
		 * switched off by sysctl. Google does not do this by the
		 * way.
		 */
		if ((ctf_flight_size(bbr->rc_tp,
			 (bbr->r_ctl.rc_sacked + bbr->r_ctl.rc_lost_bytes)) +
		     (2 * max(bbr->r_ctl.rc_pace_max_segs, bbr->rc_tp->t_maxseg))) <= bbr->rc_tp->snd_wnd) {
			do_exit = 1;
		} else {
			/* Just record an updated loss value */
			bbr->r_ctl.rc_lost_at_startup = bbr->r_ctl.rc_lost;
		}
	} else
		bbr->r_ctl.rc_lost_at_startup = bbr->r_ctl.rc_lost;
	if (((bbr->r_ctl.rc_pkt_epoch - bbr->r_ctl.rc_bbr_last_startup_epoch) >= BBR_STARTUP_EPOCHS) ||
	    do_exit) {
		/* Return 1 to exit the startup state. */
		return (1);
	}
	/* Stay in startup */
	return (0);
}

static void
bbr_state_change(struct tcp_bbr *bbr, uint32_t cts, int32_t epoch, int32_t pkt_epoch, uint32_t losses)
{
	/*
	 * A tick occured in the rtt epoch do we need to do anything?
	 */
	if (bbr->rc_bbr_state == BBR_STATE_STARTUP) {
		/* Do we exit the startup state? */
		if (bbr_state_startup(bbr, cts, epoch, pkt_epoch)) {
			uint32_t time_in;

			bbr->rc_filled_pipe = 1;
			bbr->r_ctl.bbr_lost_at_state = bbr->r_ctl.rc_lost;
			if (SEQ_GT(cts, bbr->r_ctl.rc_bbr_state_time)) {
				time_in = cts - bbr->r_ctl.rc_bbr_state_time;
				counter_u64_add(bbr_state_time[bbr->rc_bbr_state], time_in);
			} else
				time_in = 0;
			if (bbr->rc_no_pacing)
				bbr->rc_no_pacing = 0;
			bbr->r_ctl.rc_bbr_state_time = cts;
			bbr->r_ctl.rc_bbr_hptsi_gain = bbr->r_ctl.rc_drain_pg;
			bbr->rc_bbr_state = BBR_STATE_DRAIN;
			bbr_set_state_target(bbr, __LINE__);
			if ((bbr->rc_use_google == 0) &&
			    bbr_slam_cwnd_in_main_drain) {
				/* Here we don't have to worry about probe-rtt */
				bbr->r_ctl.rc_saved_cwnd = bbr->rc_tp->snd_cwnd;
				bbr->rc_tp->snd_cwnd = bbr->r_ctl.rc_target_at_state;
			}
			bbr->r_ctl.rc_bbr_cwnd_gain = bbr_high_gain;
			if (ctf_flight_size(bbr->rc_tp,
			        (bbr->r_ctl.rc_sacked + bbr->r_ctl.rc_lost_bytes)) <=
			    bbr->r_ctl.rc_target_at_state) {
				/*
				 * Switch to probe_bw if we are already
				 * there
				 */
				bbr->rc_bbr_substate = bbr_pick_probebw_substate(bbr, cts);
				bbr_substate_change(bbr, cts, __LINE__, 0);
				bbr->rc_bbr_state = BBR_STATE_PROBE_BW;
			}
		}
	} else if (bbr->rc_bbr_state == BBR_STATE_IDLE_EXIT) {
		uint32_t inflight;
		struct tcpcb *tp;

		tp = bbr->rc_tp;
		inflight = ctf_flight_size(tp,
			      (bbr->r_ctl.rc_sacked + bbr->r_ctl.rc_lost_bytes));
		if (inflight >= bbr->r_ctl.rc_target_at_state) {
			/* We have reached a flight of the cwnd target */
			bbr->rc_bbr_state = BBR_STATE_PROBE_BW;
			bbr->r_ctl.rc_bbr_hptsi_gain = BBR_UNIT;
			bbr->r_ctl.rc_bbr_cwnd_gain = BBR_UNIT;
			bbr_set_state_target(bbr, __LINE__);
			/*
			 * Rig it so we don't do anything crazy and
			 * start fresh with a new randomization.
			 */
			bbr->r_ctl.bbr_smallest_srtt_this_state = 0xffffffff;
			bbr->rc_bbr_substate = BBR_SUB_LEVEL6;
			bbr_substate_change(bbr, cts, __LINE__, 1);
		}
	} else if (bbr->rc_bbr_state == BBR_STATE_DRAIN) {
		/* Has in-flight reached the bdp (or less)? */
		uint32_t inflight;
		struct tcpcb *tp;

		tp = bbr->rc_tp;
		inflight = ctf_flight_size(tp,
			      (bbr->r_ctl.rc_sacked + bbr->r_ctl.rc_lost_bytes));
		if ((bbr->rc_use_google == 0) &&
		    bbr_slam_cwnd_in_main_drain &&
		    (bbr->rc_tp->snd_cwnd > bbr->r_ctl.rc_target_at_state)) {
			/*
			 * Here we don't have to worry about probe-rtt
			 * re-slam it, but keep it slammed down.
			 */
			bbr->rc_tp->snd_cwnd = bbr->r_ctl.rc_target_at_state;
		}
		if (inflight <= bbr->r_ctl.rc_target_at_state) {
			/* We have drained */
			bbr->rc_bbr_state = BBR_STATE_PROBE_BW;
			bbr->r_ctl.bbr_lost_at_state = bbr->r_ctl.rc_lost;
			if (SEQ_GT(cts, bbr->r_ctl.rc_bbr_state_time)) {
				uint32_t time_in;

				time_in = cts - bbr->r_ctl.rc_bbr_state_time;
				counter_u64_add(bbr_state_time[bbr->rc_bbr_state], time_in);
			}
			if ((bbr->rc_use_google == 0) &&
			    bbr_slam_cwnd_in_main_drain &&
			    (tp->snd_cwnd < bbr->r_ctl.rc_saved_cwnd)) {
				/* Restore the cwnd */
				tp->snd_cwnd = bbr->r_ctl.rc_saved_cwnd;
			}
			/* Setup probe-rtt has being done now RRS-HERE */
			bbr->r_ctl.rc_rtt_shrinks = cts;
			bbr->r_ctl.last_in_probertt = cts;
			/* Randomly pick a sub-state */
			bbr->rc_bbr_substate = bbr_pick_probebw_substate(bbr, cts);
			bbr_substate_change(bbr, cts, __LINE__, 0);
		}
	} else if (bbr->rc_bbr_state == BBR_STATE_PROBE_RTT) {
		uint32_t flight;

		flight = ctf_flight_size(bbr->rc_tp,
			     (bbr->r_ctl.rc_sacked + bbr->r_ctl.rc_lost_bytes));
		bbr->r_ctl.r_app_limited_until = (flight + bbr->r_ctl.rc_delivered);
		if (((bbr->r_ctl.bbr_rttprobe_gain_val == 0) || bbr->rc_use_google) &&
		    (bbr->rc_tp->snd_cwnd > bbr->r_ctl.rc_target_at_state)) {
			/*
			 * We must keep cwnd at the desired MSS.
			 */
			bbr->rc_tp->snd_cwnd = bbr_rtt_probe_cwndtarg * (bbr->rc_tp->t_maxseg - bbr->rc_last_options);
		} else if ((bbr_prtt_slam_cwnd) &&
			   (bbr->rc_tp->snd_cwnd > bbr->r_ctl.rc_target_at_state)) {
			/* Re-slam it */
			bbr->rc_tp->snd_cwnd = bbr->r_ctl.rc_target_at_state;
		}
		if (bbr->r_ctl.rc_bbr_enters_probertt == 0) {
			/* Has outstanding reached our target? */
			if (flight <= bbr->r_ctl.rc_target_at_state) {
				bbr->r_ctl.rc_bbr_enters_probertt = cts;
				/* If time is exactly 0, be 1usec off */
				if (bbr->r_ctl.rc_bbr_enters_probertt == 0)
					bbr->r_ctl.rc_bbr_enters_probertt = 1;
				if (bbr->rc_use_google == 0) {
					/*
					 * Restore any lowering that as occured to
					 * reach here
					 */
					if (bbr->r_ctl.bbr_rttprobe_gain_val)
						bbr->r_ctl.rc_bbr_hptsi_gain = bbr->r_ctl.bbr_rttprobe_gain_val;
					else
						bbr->r_ctl.rc_bbr_hptsi_gain = BBR_UNIT;
				}
			}
			if ((bbr->r_ctl.rc_bbr_enters_probertt == 0) &&
			    (bbr->rc_use_google == 0) &&
			    bbr->r_ctl.bbr_rttprobe_gain_val &&
			    (((cts - bbr->r_ctl.rc_probertt_srttchktim) > bbr_get_rtt(bbr, bbr_drain_rtt)) ||
			     (flight >= bbr->r_ctl.flightsize_at_drain))) {
				/*
				 * We have doddled with our current hptsi
				 * gain an srtt and have still not made it
				 * to target, or we have increased our flight.
				 * Lets reduce the gain by xx%
				 * flooring the reduce at DRAIN (based on
				 * mul/div)
				 */
				int red;

				bbr->r_ctl.flightsize_at_drain = flight;
				bbr->r_ctl.rc_probertt_srttchktim = cts;
				red = max((bbr->r_ctl.bbr_rttprobe_gain_val / 10), 1);
				if ((bbr->r_ctl.rc_bbr_hptsi_gain - red) > max(bbr_drain_floor, 1)) {
					/* Reduce our gain again */
					bbr->r_ctl.rc_bbr_hptsi_gain -= red;
				} else if (bbr->r_ctl.rc_bbr_hptsi_gain > max(bbr_drain_floor, 1)) {
					/* one more chance before we give up */
					bbr->r_ctl.rc_bbr_hptsi_gain = max(bbr_drain_floor, 1);
				} else {
					/* At the very bottom */
					bbr->r_ctl.rc_bbr_hptsi_gain = max((bbr_drain_floor-1), 1);
				}
			}
		}
		if (bbr->r_ctl.rc_bbr_enters_probertt &&
		    (TSTMP_GT(cts, bbr->r_ctl.rc_bbr_enters_probertt)) &&
		    ((cts - bbr->r_ctl.rc_bbr_enters_probertt) >= bbr_rtt_probe_time)) {
			/* Time to exit probe RTT normally */
			bbr_exit_probe_rtt(bbr->rc_tp, bbr, cts);
		}
	} else if (bbr->rc_bbr_state == BBR_STATE_PROBE_BW) {
		if ((bbr->rc_tp->snd_una == bbr->rc_tp->snd_max) &&
		    (bbr_calc_time(cts, bbr->r_ctl.rc_went_idle_time) >= bbr_rtt_probe_time)) {
			/*
			 * This qualifies as a RTT_PROBE session since we
			 * drop the data outstanding to nothing and waited
			 * more than bbr_rtt_probe_time.
			 */
			bbr_set_reduced_rtt(bbr, cts, __LINE__);
		}
		if (bbr_should_enter_probe_rtt(bbr, cts)) {
			bbr_enter_probe_rtt(bbr, cts, __LINE__);
		} else {
			bbr_set_probebw_gains(bbr, cts, losses);
		}
	}
}

static void
bbr_check_bbr_for_state(struct tcp_bbr *bbr, uint32_t cts, int32_t line, uint32_t losses)
{
	int32_t epoch = 0;

	if ((cts - bbr->r_ctl.rc_rcv_epoch_start) >= bbr_get_rtt(bbr, BBR_RTT_PROP)) {
		bbr_set_epoch(bbr, cts, line);
		/* At each epoch doe lt bw sampling */
		epoch = 1;
	}
	bbr_state_change(bbr, cts, epoch, bbr->rc_is_pkt_epoch_now, losses);
}

static int
bbr_do_segment_nounlock(struct mbuf *m, struct tcphdr *th, struct socket *so,
    struct tcpcb *tp, int32_t drop_hdrlen, int32_t tlen, uint8_t iptos,
    int32_t nxt_pkt, struct timeval *tv)
{
	int32_t thflags, retval;
	uint32_t cts, lcts;
	uint32_t tiwin;
	struct tcpopt to;
	struct tcp_bbr *bbr;
	struct bbr_sendmap *rsm;
#if 0
	struct timeval ltv;
#endif
	int32_t did_out = 0;
	uint32_t lost;

#if 0
	nsegs = tlen ? tcp_nsegs(tlen, tp, th): 1;
#endif
	bbr = (struct tcp_bbr *)tp->t_fb_ptr;
	thflags = th->th_flags;
	/*
	 * If this is either a state-changing packet or current state isn't
	 * established, we require a write lock on tcbinfo.  Otherwise, we
	 * allow the tcbinfo to be in either alocked or unlocked, as the
	 * caller may have unnecessarily acquired a write lock due to a
	 * race.
	 */
	KASSERT(tp->t_state > TCPS_LISTEN, ("%s: TCPS_LISTEN",
	    __func__));
	KASSERT(tp->t_state != TCPS_TIME_WAIT, ("%s: TCPS_TIME_WAIT",
	    __func__));

	tp->t_rcvtime = ticks;
	/*
	 * Unscale the window into a 32-bit value. For the SYN_SENT state
	 * the scale is zero.
	 */
	tiwin = th->th_win << tp->snd_scale;

#if 0
	if (m->m_flags & M_TSTMP) {
		/* Prefer the hardware timestamp if present */
		struct timespec ts;

		mbuf_tstmp2timespec(m, &ts);
		bbr->rc_tv.tv_sec = ts.tv_sec;
		bbr->rc_tv.tv_usec = ts.tv_nsec / 1000;
		bbr->r_ctl.rc_rcvtime = cts = tcp_tv_to_usectick(&bbr->rc_tv);
	} else if (m->m_flags & M_TSTMP_LRO) {
		/* Next the arrival timestamp */
		struct timespec ts;

		mbuf_tstmp2timespec(m, &ts);
		bbr->rc_tv.tv_sec = ts.tv_sec;
		bbr->rc_tv.tv_usec = ts.tv_nsec / 1000;
		bbr->r_ctl.rc_rcvtime = cts = tcp_tv_to_usectick(&bbr->rc_tv);
	} else
#endif
        {
		/*
		 * Ok just get the current time.
		 */
		bbr->r_ctl.rc_rcvtime = lcts = cts = tcp_get_usecs(&bbr->rc_tv);
	}
	/*
	 * Parse options on any incoming segment.
	 */
	tcp_dooptions(tp, &to, (u_char *)(th + 1),
	    (th->th_off << 2) - sizeof(struct tcphdr),
	    (thflags & TH_SYN) ? TO_SYN : 0);

	/*
	 * If timestamps were negotiated during SYN/ACK and a
	 * segment without a timestamp is received, silently drop
	 * the segment, unless it is a RST segment or missing timestamps are
	 * tolerated.
	 * See section 3.2 of RFC 7323.
	 */
	if ((tp->t_flags & TF_RCVD_TSTMP) && !(to.to_flags & TOF_TS) &&
	    ((thflags & TH_RST) == 0) && (V_tcp_tolerate_missing_ts == 0)) {
		retval = 0;
		m_freem(m);
		goto done_with_input;
	}
	/*
	 * If echoed timestamp is later than the current time, fall back to
	 * non RFC1323 RTT calculation.  Normalize timestamp if syncookies
	 * were used when this connection was established.
	 */
	if ((to.to_flags & TOF_TS) && (to.to_tsecr != 0)) {
		to.to_tsecr -= tp->ts_offset;
		if (TSTMP_GT(to.to_tsecr, tcp_tv_to_mssectick(&bbr->rc_tv)))
			to.to_tsecr = 0;
	}
	/*
	 * If its the first time in we need to take care of options and
	 * verify we can do SACK for rack!
	 */
	if (bbr->r_state == 0) {
		/*
		 * Process options only when we get SYN/ACK back. The SYN
		 * case for incoming connections is handled in tcp_syncache.
		 * According to RFC1323 the window field in a SYN (i.e., a
		 * <SYN> or <SYN,ACK>) segment itself is never scaled. XXX
		 * this is traditional behavior, may need to be cleaned up.
		 */
#if 0
		if (bbr->rc_inp == NULL) {
			bbr->rc_inp = tp->t_inpcb;
		}
#endif
		/*
		 * We need to init rc_inp here since its not init'd when
		 * bbr_init is called
		 */
		if (tp->t_state == TCPS_SYN_SENT && (thflags & TH_SYN)) {
			if ((to.to_flags & TOF_SCALE) &&
			    (tp->t_flags & TF_REQ_SCALE)) {
				tp->t_flags |= TF_RCVD_SCALE;
				tp->snd_scale = to.to_wscale;
			} else
				tp->t_flags &= ~TF_REQ_SCALE;
			/*
			 * Initial send window.  It will be updated with the
			 * next incoming segment to the scaled value.
			 */
			tp->snd_wnd = th->th_win;
			if ((to.to_flags & TOF_TS) &&
			    (tp->t_flags & TF_REQ_TSTMP)) {
				tp->t_flags |= TF_RCVD_TSTMP;
				tp->ts_recent = to.to_tsval;
				tp->ts_recent_age = tcp_tv_to_mssectick(&bbr->rc_tv);
			} else
			    tp->t_flags &= ~TF_REQ_TSTMP;
			if (to.to_flags & TOF_MSS)
				tcp_mss(tp, to.to_mss);
			if ((tp->t_flags & TF_SACK_PERMIT) &&
			    (to.to_flags & TOF_SACKPERM) == 0)
				tp->t_flags &= ~TF_SACK_PERMIT;
		}
		/*
		 * At this point we are at the initial call. Here we decide
		 * if we are doing RACK or not. We do this by seeing if
		 * TF_SACK_PERMIT is set, if not rack is *not* possible and
		 * we switch to the default code.
		 */
		if ((tp->t_flags & TF_SACK_PERMIT) == 0) {
			/* Bail */
#if 0
			tcp_switch_back_to_default(tp);
#endif
			(*tp->t_fb->tfb_tcp_do_segment) (m, th, so, tp, drop_hdrlen,
			    tlen, iptos);
			return (1);
		}
		/* Set the flag */
#if 0
		bbr->r_is_v6 = (tp->t_inpcb->inp_vflag & INP_IPV6) != 0;
		tcp_set_hpts(tp->t_inpcb);
#endif
		sack_filter_clear(&bbr->r_ctl.bbr_sf, th->th_ack);
	}
	if (thflags & TH_ACK) {
		/* Track ack types */
		if (to.to_flags & TOF_SACK)
			BBR_STAT_INC(bbr_acks_with_sacks);
		else
			BBR_STAT_INC(bbr_plain_acks);
	}
	/*
	 * This is the one exception case where we set the rack state
	 * always. All other times (timers etc) we must have a rack-state
	 * set (so we assure we have done the checks above for SACK).
	 */
	if (thflags & TH_FIN)
		tcp_log_end_status(tp, TCP_EI_STATUS_CLIENT_FIN);
	if (bbr->r_state != tp->t_state)
		bbr_set_state(tp, bbr, tiwin);

	if (SEQ_GT(th->th_ack, tp->snd_una) && (rsm = TAILQ_FIRST(&bbr->r_ctl.rc_map)) != NULL)
		kern_prefetch(rsm, &prev_state);
	bbr->rc_ack_was_delayed = 0;
	lost = bbr->r_ctl.rc_lost;
	bbr->rc_is_pkt_epoch_now = 0;
#if 0
	if (m->m_flags & (M_TSTMP|M_TSTMP_LRO)) {
		/* Get the real time into lcts and figure the real delay */
		lcts = tcp_get_usecs(&ltv);
		if (TSTMP_GT(lcts, cts)) {
			bbr->r_ctl.rc_ack_hdwr_delay = lcts - cts;
			bbr->rc_ack_was_delayed = 1;
			if (TSTMP_GT(bbr->r_ctl.rc_ack_hdwr_delay,
				     bbr->r_ctl.highest_hdwr_delay))
				bbr->r_ctl.highest_hdwr_delay = bbr->r_ctl.rc_ack_hdwr_delay;
		} else {
			bbr->r_ctl.rc_ack_hdwr_delay = 0;
			bbr->rc_ack_was_delayed = 0;
		}
	} else
#endif
	{
		bbr->r_ctl.rc_ack_hdwr_delay = 0;
		bbr->rc_ack_was_delayed = 0;
	}
	if ((thflags & TH_SYN) && (thflags & TH_FIN) && V_drop_synfin) {
		retval = 0;
		m_freem(m);
		goto done_with_input;
	}
	/*
	 * If a segment with the ACK-bit set arrives in the SYN-SENT state
	 * check SEQ.ACK first as described on page 66 of RFC 793, section 3.9.
	 */
	if ((tp->t_state == TCPS_SYN_SENT) && (thflags & TH_ACK) &&
	    (SEQ_LEQ(th->th_ack, tp->iss) || SEQ_GT(th->th_ack, tp->snd_max))) {
		tcp_log_end_status(tp, TCP_EI_STATUS_RST_IN_FRONT);
		ctf_do_dropwithreset_conn(m, tp, th, BANDLIM_RST_OPENPORT, tlen);
		return (1);
	}
	if (tiwin > bbr->r_ctl.rc_high_rwnd)
		bbr->r_ctl.rc_high_rwnd = tiwin;
	bbr->r_ctl.rc_flight_at_input = ctf_flight_size(tp,
					    (bbr->r_ctl.rc_sacked + bbr->r_ctl.rc_lost_bytes));
	bbr->rtt_valid = 0;
	if (to.to_flags & TOF_TS) {
		bbr->rc_ts_valid = 1;
		bbr->r_ctl.last_inbound_ts = to.to_tsval;
	} else {
		bbr->rc_ts_valid = 0;
		bbr->r_ctl.last_inbound_ts = 0;
	}
	retval = (*bbr->r_substate) (m, th, so,
	    tp, &to, drop_hdrlen,
	    tlen, tiwin, thflags, nxt_pkt, iptos);
	if (nxt_pkt == 0)
		BBR_STAT_INC(bbr_rlock_left_ret0);
	else
		BBR_STAT_INC(bbr_rlock_left_ret1);
	if (retval == 0) {
		/*
		 * If retval is 1 the tcb is unlocked and most likely the tp
		 * is gone.
		 */
		tcp_bbr_xmit_timer_commit(bbr, tp, cts);
		if (bbr->rc_is_pkt_epoch_now)
			bbr_set_pktepoch(bbr, cts, __LINE__);
		bbr_check_bbr_for_state(bbr, cts, __LINE__, (bbr->r_ctl.rc_lost - lost));
		if (nxt_pkt == 0) {
			if (bbr->r_wanted_output != 0) {
				bbr->rc_output_starts_timer = 0;
				did_out = 1;
				(void)tp->t_fb->tfb_tcp_output(tp);
			} else
				bbr_start_hpts_timer(bbr, tp, cts, 6, 0, 0);
		}
		if ((nxt_pkt == 0) &&
		    ((bbr->r_ctl.rc_hpts_flags & PACE_TMR_MASK) == 0) &&
		    (SEQ_GT(tp->snd_max, tp->snd_una) ||
		     (tp->t_flags & TF_DELACK) ||
		     ((V_tcp_always_keepalive || tcp_getsocket(tp)->so_options & SO_KEEPALIVE) &&
		      (tp->t_state <= TCPS_CLOSING)))) {
			/*
			 * We could not send (probably in the hpts but
			 * stopped the timer)?
			 */
			if ((tp->snd_max == tp->snd_una) &&
			    ((tp->t_flags & TF_DELACK) == 0) &&
#if 0
			    (bbr->rc_inp->inp_in_hpts) &&
#endif
			    (bbr->r_ctl.rc_hpts_flags & PACE_PKT_OUTPUT)) {
				/*
				 * keep alive not needed if we are hptsi
				 * output yet
				 */
				;
			} else {
#if 0
				if (bbr->rc_inp->inp_in_hpts) {
					tcp_hpts_remove(bbr->rc_inp, HPTS_REMOVE_OUTPUT);
					if ((bbr->r_ctl.rc_hpts_flags & PACE_PKT_OUTPUT) &&
					    (TSTMP_GT(lcts, bbr->rc_pacer_started))) {
						uint32_t del;

						del = lcts - bbr->rc_pacer_started;
						if (bbr->r_ctl.rc_last_delay_val > del) {
							BBR_STAT_INC(bbr_force_timer_start);
							bbr->r_ctl.rc_last_delay_val -= del;
							bbr->rc_pacer_started = lcts;
						} else {
							/* We are late */
							bbr->r_ctl.rc_last_delay_val = 0;
							BBR_STAT_INC(bbr_force_output);
							(void)tp->t_fb->tfb_tcp_output(tp);
						}
					}
				}
				bbr_start_hpts_timer(bbr, tp, cts, 8, bbr->r_ctl.rc_last_delay_val,
				    0);
#endif
			}
		} else if ((bbr->rc_output_starts_timer == 0) && (nxt_pkt == 0)) {
			/* Do we have the correct timer running? */
			bbr_timer_audit(tp, bbr, lcts, &so->so_snd);
		}
		/* Do we have a new state */
		if (bbr->r_state != tp->t_state)
			bbr_set_state(tp, bbr, tiwin);
done_with_input:
		if (did_out)
			bbr->r_wanted_output = 0;
	}
	return (retval);
}

static void
bbr_do_segment(struct mbuf *m, struct tcphdr *th, struct socket *so,
    struct tcpcb *tp, int32_t drop_hdrlen, int32_t tlen, uint8_t iptos)
{
	struct timeval tv;

#if 0
	/* First lets see if we have old packets */
	if (tp->t_in_pkt) {
		if (ctf_do_queued_segments(so, tp, 1)) {
			m_freem(m);
			return;
		}
	}
#endif
#if 0
	if (m->m_flags & M_TSTMP_LRO) {
		tv.tv_sec = m->m_pkthdr.rcv_tstmp /1000000000;
		tv.tv_usec = (m->m_pkthdr.rcv_tstmp % 1000000000)/1000;
	} else
#endif
	{
		/* Should not be should we kassert instead? */
		tcp_get_usecs(&tv);
	}
	bbr_do_segment_nounlock(m, th, so, tp, drop_hdrlen, tlen, iptos, 0, &tv);
}

/*
 * Return how much data can be sent without violating the
 * cwnd or rwnd.
 */

static inline uint32_t
bbr_what_can_we_send(struct tcpcb *tp, struct tcp_bbr *bbr, uint32_t sendwin,
    uint32_t avail, int32_t sb_offset, uint32_t cts)
{
	uint32_t len;

	if (ctf_outstanding(tp) >= tp->snd_wnd) {
		/* We never want to go over our peers rcv-window */
		len = 0;
	} else {
		uint32_t flight;

		flight = ctf_flight_size(tp, (bbr->r_ctl.rc_sacked + bbr->r_ctl.rc_lost_bytes));
		if (flight >= sendwin) {
			/*
			 * We have in flight what we are allowed by cwnd (if
			 * it was rwnd blocking it would have hit above out
			 * >= tp->snd_wnd).
			 */
			return (0);
		}
		len = sendwin - flight;
		if ((len + ctf_outstanding(tp)) > tp->snd_wnd) {
			/* We would send too much (beyond the rwnd) */
			len = tp->snd_wnd - ctf_outstanding(tp);
		}
		if ((len + sb_offset) > avail) {
			/*
			 * We don't have that much in the SB, how much is
			 * there?
			 */
			len = avail - sb_offset;
		}
	}
	return (len);
}

static inline void
bbr_do_error_accounting(struct tcpcb *tp, struct tcp_bbr *bbr, struct bbr_sendmap *rsm, int32_t len, int32_t error)
{
}

static inline void
bbr_do_send_accounting(struct tcpcb *tp, struct tcp_bbr *bbr, struct bbr_sendmap *rsm, int32_t len, int32_t error)
{
	if (error) {
		bbr_do_error_accounting(tp, bbr, rsm, len, error);
		return;
	}
	if (rsm) {
		if (rsm->r_flags & BBR_TLP) {
			/*
			 * TLP should not count in retran count, but in its
			 * own bin
			 */
		} else {
			/* Retransmit */
			tp->t_sndrexmitpack++;
			KMOD_TCPSTAT_INC(tcps_sndrexmitpack);
			KMOD_TCPSTAT_ADD(tcps_sndrexmitbyte, len);
		}
		/*
		 * Logs in 0 - 8, 8 is all non probe_bw states 0-7 is
		 * sub-state
		 */
		counter_u64_add(bbr_state_lost[rsm->r_bbr_state], len);
		if (bbr->rc_bbr_state != BBR_STATE_PROBE_BW) {
			/* Non probe_bw log in 1, 2, or 4. */
			counter_u64_add(bbr_state_resend[bbr->rc_bbr_state], len);
		} else {
			/*
			 * Log our probe state 3, and log also 5-13 to show
			 * us the recovery sub-state for the send. This
			 * means that 3 == (5+6+7+8+9+10+11+12+13)
			 */
			counter_u64_add(bbr_state_resend[BBR_STATE_PROBE_BW], len);
			counter_u64_add(bbr_state_resend[(bbr_state_val(bbr) + 5)], len);
		}
		/* Place in both 16's the totals of retransmitted */
		counter_u64_add(bbr_state_lost[16], len);
		counter_u64_add(bbr_state_resend[16], len);
		/* Place in 17's the total sent */
		counter_u64_add(bbr_state_resend[17], len);
		counter_u64_add(bbr_state_lost[17], len);

	} else {
		/* New sends */
		KMOD_TCPSTAT_INC(tcps_sndpack);
		KMOD_TCPSTAT_ADD(tcps_sndbyte, len);
		/* Place in 17's the total sent */
		counter_u64_add(bbr_state_resend[17], len);
		counter_u64_add(bbr_state_lost[17], len);
	}
}

static void
bbr_cwnd_limiting(struct tcpcb *tp, struct tcp_bbr *bbr, uint32_t in_level)
{
	if (bbr->rc_filled_pipe && bbr_target_cwnd_mult_limit && (bbr->rc_use_google == 0)) {
		/*
		 * Limit the cwnd to not be above N x the target plus whats
		 * is outstanding. The target is based on the current b/w
		 * estimate.
		 */
		uint32_t target;

		target = bbr_get_target_cwnd(bbr, bbr_get_bw(bbr), BBR_UNIT);
		target += ctf_outstanding(tp);
		target *= bbr_target_cwnd_mult_limit;
		if (tp->snd_cwnd > target)
			tp->snd_cwnd = target;
	}
}

static int
bbr_window_update_needed(struct tcpcb *tp, struct socket *so, uint32_t recwin, int32_t maxseg)
{
	/*
	 * "adv" is the amount we could increase the window, taking into
	 * account that we are limited by TCP_MAXWIN << tp->rcv_scale.
	 */
	int32_t adv;
	int32_t oldwin;

	adv = recwin;
	if (SEQ_GT(tp->rcv_adv, tp->rcv_nxt)) {
		oldwin = (tp->rcv_adv - tp->rcv_nxt);
		if (adv > oldwin)
			adv -= oldwin;
		else {
			/* We can't increase the window */
			adv = 0;
		}
	} else
		oldwin = 0;

	/*
	 * If the new window size ends up being the same as or less
	 * than the old size when it is scaled, then don't force
	 * a window update.
	 */
	if (oldwin >> tp->rcv_scale >= (adv + oldwin) >> tp->rcv_scale)
		return (0);

	if (adv >= (2 * maxseg) &&
	    (adv >= (so->so_rcv.sb_hiwat / 4) ||
	    recwin <= (so->so_rcv.sb_hiwat / 8) ||
	    so->so_rcv.sb_hiwat <= 8 * maxseg)) {
		return (1);
	}
	if (2 * adv >= (int32_t) so->so_rcv.sb_hiwat)
		return (1);
	return (0);
}

/*
 * Return 0 on success and a errno on failure to send.
 * Note that a 0 return may not mean we sent anything
 * if the TCB was on the hpts. A non-zero return
 * does indicate the error we got from ip[6]_output.
 */
static int
bbr_output_wtime(struct tcpcb *tp, const struct timeval *tv)
{
	struct socket *so;
	int32_t len;
	uint32_t cts;
	uint32_t recwin, sendwin;
	int32_t sb_offset;
	int32_t flags, abandon, error = 0;
	struct mbuf *m;
#ifdef TCPDEBUG
	struct ipovly *ipov = NULL;
#endif
	struct tcp_bbr *bbr;
	struct tcphdr *th;
	u_char opt[TCP_MAXOLEN];
	unsigned ipoptlen, optlen, hdrlen;
	uint32_t bbr_seq;
	uint32_t delay_calc=0;
	uint8_t doing_tlp = 0;
	uint8_t local_options;
	uint8_t more_to_rxt=0;
	int32_t prefetch_so_done = 0;
	int32_t prefetch_rsm = 0;
	uint32_t tot_len = 0;
	uint32_t rtr_cnt = 0;
	uint32_t maxseg, pace_max_segs, p_maxseg;
	volatile int32_t sack_rxmit;
	struct bbr_sendmap *rsm = NULL;
	int32_t tso;
	struct tcpopt to;
	int32_t slot = 0;
#if 0
	struct inpcb *inp;
#endif
	struct sockbuf *sb;
#if 0
	uint32_t hpts_calling;
#endif
#ifdef INET6
	struct ip6_hdr *ip6 = NULL;
	int32_t isipv6;
#endif
	uint8_t app_limited = BBR_JR_SENT_DATA;
	bbr = (struct tcp_bbr *)tp->t_fb_ptr;
	/* We take a cache hit here */
	memcpy(&bbr->rc_tv, tv, sizeof(struct timeval));
	cts = tcp_tv_to_usectick(&bbr->rc_tv);
#if 0
	inp = bbr->rc_inp;
#endif
	so = tcp_getsocket(tp);
	sb = &so->so_snd;
	kern_prefetch(sb, &maxseg);
	maxseg = tp->t_maxseg - bbr->rc_last_options;
	if (bbr_minseg(bbr) < maxseg) {
		tcp_bbr_tso_size_check(bbr, cts);
	}
	/* Remove any flags that indicate we are pacing on the inp  */
	pace_max_segs = bbr->r_ctl.rc_pace_max_segs;
	p_maxseg = min(maxseg, pace_max_segs);

#ifdef INET6
	if (bbr->r_state) {
		/* Use the cache line loaded if possible */
		isipv6 = bbr->r_is_v6;
	} else {
		isipv6 = (inp->inp_vflag & INP_IPV6) != 0;
	}
#endif
#if 0
	if (((bbr->r_ctl.rc_hpts_flags & PACE_PKT_OUTPUT) == 0) &&
	    inp->inp_in_hpts) {
		/*
		 * We are on the hpts for some timer but not hptsi output.
		 * Possibly remove from the hpts so we can send/recv etc.
		 */
		if ((tp->t_flags & TF_ACKNOW) == 0) {
			/*
			 * No immediate demand right now to send an ack, but
			 * the user may have read, making room for new data
			 * (a window update). If so we may want to cancel
			 * whatever timer is running (KEEP/DEL-ACK?) and
			 * continue to send out a window update. Or we may
			 * have gotten more data into the socket buffer to
			 * send.
			 */
			recwin = lmin(lmax(sbspace(&so->so_rcv), 0),
				      (long)TCP_MAXWIN << tp->rcv_scale);
			if ((bbr_window_update_needed(tp, so, recwin, maxseg) == 0) &&
			    ((tcp_outflags[tp->t_state] & TH_RST) == 0) &&
			    ((sbavail(sb) + ((tcp_outflags[tp->t_state] & TH_FIN) ? 1 : 0)) <=
			    (tp->snd_max - tp->snd_una))) {
				/*
				 * Nothing new to send and no window update
				 * is needed to send. Lets just return and
				 * let the timer-run off.
				 */
				return (0);
			}
		}
		tcp_hpts_remove(inp, HPTS_REMOVE_OUTPUT);
		bbr_timer_cancel(bbr, __LINE__, cts);
	}
#endif
	if (bbr->r_ctl.rc_last_delay_val) {
		/* Calculate a rough delay for early escape to sending  */
		if (SEQ_GT(cts, bbr->rc_pacer_started))
			delay_calc = cts - bbr->rc_pacer_started;
		if (delay_calc >= bbr->r_ctl.rc_last_delay_val)
			delay_calc -= bbr->r_ctl.rc_last_delay_val;
		else
			delay_calc = 0;
	}
#if 0
	/* Mark that we have called bbr_output(). */
	if ((bbr->r_timer_override) ||
	    (tp->t_state < TCPS_ESTABLISHED)) {
		/* Timeouts or early states are exempt */
		if (inp->inp_in_hpts)
			tcp_hpts_remove(inp, HPTS_REMOVE_OUTPUT);
	} else if (inp->inp_in_hpts) {
		if ((bbr->r_ctl.rc_last_delay_val) &&
		    (bbr->r_ctl.rc_hpts_flags & PACE_PKT_OUTPUT) &&
		    delay_calc) {
			/*
			 * We were being paced for output and the delay has
			 * already exceeded when we were supposed to be
			 * called, lets go ahead and pull out of the hpts
			 * and call output.
			 */
			counter_u64_add(bbr_out_size[TCP_MSS_ACCT_LATE], 1);
			bbr->r_ctl.rc_last_delay_val = 0;
			tcp_hpts_remove(inp, HPTS_REMOVE_OUTPUT);
		} else if (tp->t_state == TCPS_CLOSED) {
			bbr->r_ctl.rc_last_delay_val = 0;
			tcp_hpts_remove(inp, HPTS_REMOVE_OUTPUT);
		} else {
			/*
			 * On the hpts, you shall not pass! even if ACKNOW
			 * is on, we will when the hpts fires, unless of
			 * course we are overdue.
			 */
			counter_u64_add(bbr_out_size[TCP_MSS_ACCT_INPACE], 1);
			return (0);
		}
	}
#endif
	bbr->rc_cwnd_limited = 0;
	if (bbr->r_ctl.rc_last_delay_val) {
		/* recalculate the real delay and deal with over/under  */
		if (SEQ_GT(cts, bbr->rc_pacer_started))
			delay_calc = cts - bbr->rc_pacer_started;
		else
			delay_calc = 0;
		if (delay_calc >= bbr->r_ctl.rc_last_delay_val)
			/* Setup the delay which will be added in */
			delay_calc -= bbr->r_ctl.rc_last_delay_val;
		else {
			/*
			 * We are early setup to adjust
			 * our slot time.
			 */
			uint64_t merged_val;

			bbr->r_ctl.rc_agg_early += (bbr->r_ctl.rc_last_delay_val - delay_calc);
			bbr->r_agg_early_set = 1;
			if (bbr->r_ctl.rc_hptsi_agg_delay) {
				if (bbr->r_ctl.rc_hptsi_agg_delay >= bbr->r_ctl.rc_agg_early) {
					/* Nope our previous late cancels out the early */
					bbr->r_ctl.rc_hptsi_agg_delay -= bbr->r_ctl.rc_agg_early;
					bbr->r_agg_early_set = 0;
					bbr->r_ctl.rc_agg_early = 0;
				} else {
					bbr->r_ctl.rc_agg_early -= bbr->r_ctl.rc_hptsi_agg_delay;
					bbr->r_ctl.rc_hptsi_agg_delay = 0;
				}
			}
			merged_val = bbr->rc_pacer_started;
			merged_val <<= 32;
			merged_val |= bbr->r_ctl.rc_last_delay_val;
			bbr->r_ctl.rc_last_delay_val = 0;
			BBR_STAT_INC(bbr_early);
			delay_calc = 0;
		}
	} else {
		/* We were not delayed due to hptsi */
		if (bbr->r_agg_early_set)
			bbr->r_ctl.rc_agg_early = 0;
		bbr->r_agg_early_set = 0;
		delay_calc = 0;
	}
	if (delay_calc) {
		/*
		 * We had a hptsi delay which means we are falling behind on
		 * sending at the expected rate. Calculate an extra amount
		 * of data we can send, if any, to put us back on track.
		 */
		if ((bbr->r_ctl.rc_hptsi_agg_delay + delay_calc) < bbr->r_ctl.rc_hptsi_agg_delay)
			bbr->r_ctl.rc_hptsi_agg_delay = 0xffffffff;
		else
			bbr->r_ctl.rc_hptsi_agg_delay += delay_calc;
	}
	sendwin = min(tp->snd_wnd, tp->snd_cwnd);
	if ((tp->snd_una == tp->snd_max) &&
	    (bbr->rc_bbr_state != BBR_STATE_IDLE_EXIT) &&
	    (sbavail(sb))) {
		/*
		 * Ok we have been idle with nothing outstanding
		 * we possibly need to start fresh with either a new
		 * suite of states or a fast-ramp up.
		 */
		bbr_restart_after_idle(bbr,
				       cts, bbr_calc_time(cts, bbr->r_ctl.rc_went_idle_time));
	}
	/*
	 * Now was there a hptsi delay where we are behind? We only count
	 * being behind if: a) We are not in recovery. b) There was a delay.
	 * <and> c) We had room to send something.
	 *
	 */
#if 0
	hpts_calling = inp->inp_hpts_calls;
	inp->inp_hpts_calls = 0;
	if (bbr->r_ctl.rc_hpts_flags & PACE_TMR_MASK) {
		if (bbr_process_timers(tp, bbr, cts, hpts_calling)) {
			counter_u64_add(bbr_out_size[TCP_MSS_ACCT_ATIMER], 1);
			return (0);
		}
	}
	bbr->rc_inp->inp_flags2 &= ~INP_MBUF_QUEUE_READY;
	if (hpts_calling &&
	    (bbr->r_ctl.rc_hpts_flags & PACE_PKT_OUTPUT)) {
		bbr->r_ctl.rc_last_delay_val = 0;
	}
#endif
	bbr->r_timer_override = 0;
	bbr->r_wanted_output = 0;
	/*
	 * Before sending anything check for a state update. For hpts
	 * calling without input this is important. If its input calling
	 * then this was already done.
	 */
	if (bbr->rc_use_google == 0)
		bbr_check_bbr_for_state(bbr, cts, __LINE__, 0);
again:
	/*
	 * If we've recently taken a timeout, snd_max will be greater than
	 * snd_max. BBR in general does not pay much attention to snd_nxt
	 * for historic reasons the persist timer still uses it. This means
	 * we have to look at it. All retransmissions that are not persits
	 * use the rsm that needs to be sent so snd_nxt is ignored. At the
	 * end of this routine we pull snd_nxt always up to snd_max.
	 */
	doing_tlp = 0;
	error = 0;
	tso = 0;
	slot = 0;
	sendwin = min(tp->snd_wnd, tp->snd_cwnd);
	sb_offset = tp->snd_max - tp->snd_una;
	flags = tcp_outflags[tp->t_state];
	sack_rxmit = 0;
	len = 0;
	rsm = NULL;
	if (flags & TH_RST) {
                recwin = 0; /* to prevent maybe-uninitialized */
		goto send;
	}
recheck_resend:
	while (bbr->r_ctl.rc_free_cnt < bbr_min_req_free) {
		/* We need to always have one in reserve */
		rsm = bbr_alloc(bbr);
		if (rsm == NULL) {
			error = ENOMEM;
			/* Lie to get on the hpts */
			tot_len = tp->t_maxseg;
#if 0
			if (hpts_calling)
				/* Retry in a ms */
				slot = 1001;
#endif
			goto just_return_nolock;
		}
		TAILQ_INSERT_TAIL(&bbr->r_ctl.rc_free, rsm, r_next);
		bbr->r_ctl.rc_free_cnt++;
		rsm = NULL;
	}
	/* What do we send, a resend? */
	if (bbr->r_ctl.rc_resend == NULL) {
		/* Check for rack timeout */
		bbr->r_ctl.rc_resend = bbr_check_recovery_mode(tp, bbr, cts);
		if (bbr->r_ctl.rc_resend) {
			bbr_cong_signal(tp, NULL, CC_NDUPACK, bbr->r_ctl.rc_resend);
		}
	}
	if (bbr->r_ctl.rc_resend) {
		rsm = bbr->r_ctl.rc_resend;
		/* Remove any TLP flags its a RACK or T-O */
		rsm->r_flags &= ~BBR_TLP;
		bbr->r_ctl.rc_resend = NULL;
		if (SEQ_LT(rsm->r_start, tp->snd_una)) {
			/* TSNH */
			rsm = NULL;
			goto recheck_resend;
		}
		rtr_cnt++;
		if (rsm->r_flags & BBR_HAS_SYN) {
			/* Only retransmit a SYN by itself */
			len = 0;
			if ((flags & TH_SYN) == 0) {
				/* Huh something is wrong */
				rsm->r_start++;
				if (rsm->r_start == rsm->r_end) {
					/* Clean it up, somehow we missed the ack? */
					bbr_log_syn(tp, NULL);
				} else {
					/* TFO with data? */
					rsm->r_flags &= ~BBR_HAS_SYN;
					len = rsm->r_end - rsm->r_start;
				}
			} else {
				/* Retransmitting SYN */
				rsm = NULL;
                                recwin = 0; /* to prevent maybe-uninitialized */
				goto send;
			}
		} else
			len = rsm->r_end - rsm->r_start;
		if ((bbr->rc_resends_use_tso == 0) &&
		    (len > maxseg)) {
			len = maxseg;
			more_to_rxt = 1;
		}
		sb_offset = rsm->r_start - tp->snd_una;
		if (len > 0) {
			sack_rxmit = 1;
			KMOD_TCPSTAT_INC(tcps_sack_rexmits);
			KMOD_TCPSTAT_ADD(tcps_sack_rexmit_bytes,
			    min(len, maxseg));
		} else {
			/* I dont think this can happen */
			rsm = NULL;
			goto recheck_resend;
		}
		BBR_STAT_INC(bbr_resends_set);
	} else if (bbr->r_ctl.rc_tlp_send) {
		/*
		 * Tail loss probe
		 */
		doing_tlp = 1;
		rsm = bbr->r_ctl.rc_tlp_send;
		bbr->r_ctl.rc_tlp_send = NULL;
		sack_rxmit = 1;
		len = rsm->r_end - rsm->r_start;
		rtr_cnt++;
		if ((bbr->rc_resends_use_tso == 0) && (len > maxseg))
			len = maxseg;

		if (SEQ_GT(tp->snd_una, rsm->r_start)) {
			/* TSNH */
			rsm = NULL;
			goto recheck_resend;
		}
		sb_offset = rsm->r_start - tp->snd_una;
		BBR_STAT_INC(bbr_tlp_set);
	}
	/*
	 * Enforce a connection sendmap count limit if set
	 * as long as we are not retransmiting.
	 */
	if ((rsm == NULL) &&
	    (V_tcp_map_entries_limit > 0) &&
	    (bbr->r_ctl.rc_num_maps_alloced >= V_tcp_map_entries_limit)) {
		BBR_STAT_INC(bbr_alloc_limited);
		if (!bbr->alloc_limit_reported) {
			bbr->alloc_limit_reported = 1;
			BBR_STAT_INC(bbr_alloc_limited_conns);
		}
		goto just_return_nolock;
	}
	/*
	 * Get standard flags, and add SYN or FIN if requested by 'hidden'
	 * state flags.
	 */
	if (tp->t_flags & TF_NEEDFIN && (rsm == NULL))
		flags |= TH_FIN;
	if (tp->t_flags & TF_NEEDSYN)
		flags |= TH_SYN;

	if (rsm && (rsm->r_flags & BBR_HAS_FIN)) {
		/* we are retransmitting the fin */
		len--;
		if (len) {
			/*
			 * When retransmitting data do *not* include the
			 * FIN. This could happen from a TLP probe if we
			 * allowed data with a FIN.
			 */
			flags &= ~TH_FIN;
		}
	} else if (rsm) {
		if (flags & TH_FIN)
			flags &= ~TH_FIN;
	}
	if ((sack_rxmit == 0) && (prefetch_rsm == 0)) {
		void *end_rsm;

		end_rsm = TAILQ_LAST_FAST(&bbr->r_ctl.rc_tmap, bbr_sendmap, r_tnext);
		if (end_rsm)
			kern_prefetch(end_rsm, &prefetch_rsm);
		prefetch_rsm = 1;
	}
	/*
	 * If snd_nxt == snd_max and we have transmitted a FIN, the
	 * sb_offset will be > 0 even if so_snd.sb_cc is 0, resulting in a
	 * negative length.  This can also occur when TCP opens up its
	 * congestion window while receiving additional duplicate acks after
	 * fast-retransmit because TCP will reset snd_nxt to snd_max after
	 * the fast-retransmit.
	 *
	 * In the normal retransmit-FIN-only case, however, snd_nxt will be
	 * set to snd_una, the sb_offset will be 0, and the length may wind
	 * up 0.
	 *
	 * If sack_rxmit is true we are retransmitting from the scoreboard
	 * in which case len is already set.
	 */
	if (sack_rxmit == 0) {
		uint32_t avail;

		avail = sbavail(sb);
		if (SEQ_GT(tp->snd_max, tp->snd_una))
			sb_offset = tp->snd_max - tp->snd_una;
		else
			sb_offset = 0;
		if (bbr->rc_tlp_new_data) {
			/* TLP is forcing out new data */
			uint32_t tlplen;

			doing_tlp = 1;
			tlplen = maxseg;

			if (tlplen > (uint32_t)(avail - sb_offset)) {
				tlplen = (uint32_t)(avail - sb_offset);
			}
			if (tlplen > tp->snd_wnd) {
				len = tp->snd_wnd;
			} else {
				len = tlplen;
			}
			bbr->rc_tlp_new_data = 0;
		} else {
			len = bbr_what_can_we_send(tp, bbr, sendwin, avail, sb_offset, cts);
			if ((len < p_maxseg) &&
			    (bbr->rc_in_persist == 0) &&
			    (ctf_outstanding(tp) >= (2 * p_maxseg)) &&
			    ((avail - sb_offset) >= p_maxseg)) {
				/*
				 * We are not completing whats in the socket
				 * buffer (i.e. there is at least a segment
				 * waiting to send) and we have 2 or more
				 * segments outstanding. There is no sense
				 * of sending a little piece. Lets defer and
				 * and wait until we can send a whole
				 * segment.
				 */
				len = 0;
			}
			if (bbr->rc_in_persist) {
				/*
				 * We are in persists, figure out if
				 * a retransmit is available (maybe the previous
				 * persists we sent) or if we have to send new
				 * data.
				 */
				rsm = TAILQ_FIRST(&bbr->r_ctl.rc_map);
				if (rsm) {
					len = rsm->r_end - rsm->r_start;
					if (rsm->r_flags & BBR_HAS_FIN)
						len--;
					if ((bbr->rc_resends_use_tso == 0) && (len > maxseg))
						len = maxseg;
					if (len > 1)
						BBR_STAT_INC(bbr_persist_reneg);
					/*
					 * XXXrrs we could force the len to
					 * 1 byte here to cause the chunk to
					 * split apart.. but that would then
					 * mean we always retransmit it as
					 * one byte even after the window
					 * opens.
					 */
					sack_rxmit = 1;
					sb_offset = rsm->r_start - tp->snd_una;
				} else {
					/*
					 * First time through in persists or peer
					 * acked our one byte. Though we do have
					 * to have something in the sb.
					 */
					len = 1;
					sb_offset = 0;
					if (avail == 0)
					    len = 0;
				}
			}
		}
	}
	if (prefetch_so_done == 0) {
		kern_prefetch(so, &prefetch_so_done);
		prefetch_so_done = 1;
	}
	/*
	 * Lop off SYN bit if it has already been sent.  However, if this is
	 * SYN-SENT state and if segment contains data and if we don't know
	 * that foreign host supports TAO, suppress sending segment.
	 */
	if ((flags & TH_SYN) && (rsm == NULL) &&
	    SEQ_GT(tp->snd_max, tp->snd_una)) {
		if (tp->t_state != TCPS_SYN_RECEIVED)
			flags &= ~TH_SYN;
		/*
		 * When sending additional segments following a TFO SYN|ACK,
		 * do not include the SYN bit.
		 */
		sb_offset--, len++;
		if (sbavail(sb) == 0)
			len = 0;
	} else if ((flags & TH_SYN) && rsm) {
		/*
		 * Subtract one from the len for the SYN being
		 * retransmitted.
		 */
		len--;
	}
	/*
	 * Be careful not to send data and/or FIN on SYN segments. This
	 * measure is needed to prevent interoperability problems with not
	 * fully conformant TCP implementations.
	 */
	if ((flags & TH_SYN) && (tp->t_flags & TF_NOOPT)) {
		len = 0;
		flags &= ~TH_FIN;
	}
	/* Without fast-open there should never be data sent on a SYN */
	if ((flags & TH_SYN)/* && (!IS_FASTOPEN(tp->t_flags))*/)
		len = 0;
	if (len <= 0) {
		/*
		 * If FIN has been sent but not acked, but we haven't been
		 * called to retransmit, len will be < 0.  Otherwise, window
		 * shrank after we sent into it.  If window shrank to 0,
		 * cancel pending retransmit, pull snd_nxt back to (closed)
		 * window, and set the persist timer if it isn't already
		 * going.  If the window didn't close completely, just wait
		 * for an ACK.
		 *
		 * We also do a general check here to ensure that we will
		 * set the persist timer when we have data to send, but a
		 * 0-byte window. This makes sure the persist timer is set
		 * even if the packet hits one of the "goto send" lines
		 * below.
		 */
		len = 0;
		if ((tp->snd_wnd == 0) &&
		    (TCPS_HAVEESTABLISHED(tp->t_state)) &&
		    (tp->snd_una == tp->snd_max) &&
		    (sb_offset < (int)sbavail(sb))) {
			/*
			 * Not enough room in the rwnd to send
			 * a paced segment out.
			 */
			bbr_enter_persist(tp, bbr, cts, __LINE__);
		}
	} else if ((rsm == NULL) &&
		   (doing_tlp == 0) &&
		   (len < bbr->r_ctl.rc_pace_max_segs)) {
		/*
		 * We are not sending a full segment for
		 * some reason. Should we not send anything (think
		 * sws or persists)?
		 */
		if ((tp->snd_wnd < min((bbr->r_ctl.rc_high_rwnd/2), bbr_minseg(bbr))) &&
		    (TCPS_HAVEESTABLISHED(tp->t_state)) &&
		    (len < (int)(sbavail(sb) - sb_offset))) {
			/*
			 * Here the rwnd is less than
			 * the pacing size, this is not a retransmit,
			 * we are established and
			 * the send is not the last in the socket buffer
			 * lets not send, and possibly enter persists.
			 */
			len = 0;
			if (tp->snd_max == tp->snd_una)
				bbr_enter_persist(tp, bbr, cts, __LINE__);
		} else if ((tp->snd_cwnd >= bbr->r_ctl.rc_pace_max_segs) &&
			   (ctf_flight_size(tp, (bbr->r_ctl.rc_sacked +
						 bbr->r_ctl.rc_lost_bytes)) > (2 * maxseg)) &&
			   (len < (int)(sbavail(sb) - sb_offset)) &&
			   (len < bbr_minseg(bbr))) {
			/*
			 * Here we are not retransmitting, and
			 * the cwnd is not so small that we could
			 * not send at least a min size (rxt timer
			 * not having gone off), We have 2 segments or
			 * more already in flight, its not the tail end
			 * of the socket buffer  and the cwnd is blocking
			 * us from sending out minimum pacing segment size.
			 * Lets not send anything.
			 */
			bbr->rc_cwnd_limited = 1;
			len = 0;
		} else if (((tp->snd_wnd - ctf_outstanding(tp)) <
			    min((bbr->r_ctl.rc_high_rwnd/2), bbr_minseg(bbr))) &&
			   (ctf_flight_size(tp, (bbr->r_ctl.rc_sacked +
						 bbr->r_ctl.rc_lost_bytes)) > (2 * maxseg)) &&
			   (len < (int)(sbavail(sb) - sb_offset)) &&
			   (TCPS_HAVEESTABLISHED(tp->t_state))) {
			/*
			 * Here we have a send window but we have
			 * filled it up and we can't send another pacing segment.
			 * We also have in flight more than 2 segments
			 * and we are not completing the sb i.e. we allow
			 * the last bytes of the sb to go out even if
			 * its not a full pacing segment.
			 */
			len = 0;
		}
	}
	/* len will be >= 0 after this point. */
	KASSERT(len >= 0, ("[%s:%d]: len < 0", __func__, __LINE__));
	/*
	 *
	 */
	if (bbr->rc_in_persist &&
	    len &&
	    (rsm == NULL) &&
	    (len < min((bbr->r_ctl.rc_high_rwnd/2), bbr->r_ctl.rc_pace_max_segs))) {
		/*
		 * We are in persist, not doing a retransmit and don't have enough space
		 * yet to send a full TSO. So is it at the end of the sb
		 * if so we need to send else nuke to 0 and don't send.
		 */
		int sbleft;
		if (sbavail(sb) > sb_offset)
			sbleft = sbavail(sb) - sb_offset;
		else
			sbleft = 0;
		if (sbleft >= min((bbr->r_ctl.rc_high_rwnd/2), bbr->r_ctl.rc_pace_max_segs)) {
			/* not at end of sb lets not send */
			len = 0;
		}
	}
	/*
	 * Decide if we can use TCP Segmentation Offloading (if supported by
	 * hardware).
	 *
	 * TSO may only be used if we are in a pure bulk sending state.  The
	 * presence of TCP-MD5, SACK retransmits, SACK advertizements and IP
	 * options prevent using TSO.  With TSO the TCP header is the same
	 * (except for the sequence number) for all generated packets.  This
	 * makes it impossible to transmit any options which vary per
	 * generated segment or packet.
	 *
	 * IPv4 handling has a clear separation of ip options and ip header
	 * flags while IPv6 combines both in in6p_outputopts. ip6_optlen()
	 * does the right thing below to provide length of just ip options
	 * and thus checking for ipoptlen is enough to decide if ip options
	 * are present.
	 */
	if ((tp->t_flags & TF_TSO) && V_tcp_do_tso &&
	    (len > maxseg) &&
	    ((tp->t_flags & TF_SIGNATURE) == 0) &&
	    tp->rcv_numsacks == 0 &&
	    ipoptlen == 0)
		tso = 1;

	recwin = lmin(lmax(sbspace(&so->so_rcv), 0),
	    (long)TCP_MAXWIN << tp->rcv_scale);
	/*
	 * Sender silly window avoidance.   We transmit under the following
	 * conditions when len is non-zero:
	 *
	 * - We have a full segment (or more with TSO) - This is the last
	 * buffer in a write()/send() and we are either idle or running
	 * NODELAY - we've timed out (e.g. persist timer) - we have more
	 * then 1/2 the maximum send window's worth of data (receiver may be
	 * limited the window size) - we need to retransmit
	 */
	if (rsm)
		goto send;
	if (len) {
		if (sack_rxmit)
			goto send;
		if (len >= p_maxseg)
			goto send;
		/*
		 * NOTE! on localhost connections an 'ack' from the remote
		 * end may occur synchronously with the output and cause us
		 * to flush a buffer queued with moretocome.  XXX
		 *
		 */
		if (((tp->t_flags & TF_MORETOCOME) == 0) &&	/* normal case */
		    ((tp->t_flags & TF_NODELAY) ||
		    ((uint32_t)len + (uint32_t)sb_offset) >= sbavail(&so->so_snd))/* &&
		    (tp->t_flags & TF_NOPUSH) == 0*/) {
			goto send;
		}
		if ((tp->snd_una == tp->snd_max) && len) {	/* Nothing outstanding */
			goto send;
		}
		if (len >= tp->max_sndwnd / 2 && tp->max_sndwnd > 0) {
			goto send;
		}
	}
	/*
	 * Sending of standalone window updates.
	 *
	 * Window updates are important when we close our window due to a
	 * full socket buffer and are opening it again after the application
	 * reads data from it.  Once the window has opened again and the
	 * remote end starts to send again the ACK clock takes over and
	 * provides the most current window information.
	 *
	 * We must avoid the silly window syndrome whereas every read from
	 * the receive buffer, no matter how small, causes a window update
	 * to be sent.  We also should avoid sending a flurry of window
	 * updates when the socket buffer had queued a lot of data and the
	 * application is doing small reads.
	 *
	 * Prevent a flurry of pointless window updates by only sending an
	 * update when we can increase the advertized window by more than
	 * 1/4th of the socket buffer capacity.  When the buffer is getting
	 * full or is very small be more aggressive and send an update
	 * whenever we can increase by two mss sized segments. In all other
	 * situations the ACK's to new incoming data will carry further
	 * window increases.
	 *
	 * Don't send an independent window update if a delayed ACK is
	 * pending (it will get piggy-backed on it) or the remote side
	 * already has done a half-close and won't send more data.  Skip
	 * this if the connection is in T/TCP half-open state.
	 */
	if (recwin > 0 && !(tp->t_flags & TF_NEEDSYN) &&
	    !(tp->t_flags & TF_DELACK) &&
	    !TCPS_HAVERCVDFIN(tp->t_state)) {
		/* Check to see if we should do a window update */
		if (bbr_window_update_needed(tp, so, recwin, maxseg))
			goto send;
	}
	/*
	 * Send if we owe the peer an ACK, RST, SYN.  ACKNOW
	 * is also a catch-all for the retransmit timer timeout case.
	 */
	if (tp->t_flags & TF_ACKNOW) {
		goto send;
	}
	if (flags & TH_RST) {
		/* Always send a RST if one is due */
		goto send;
	}
	if ((flags & TH_SYN) && (tp->t_flags & TF_NEEDSYN) == 0) {
		goto send;
	}
	/*
	 * If our state indicates that FIN should be sent and we have not
	 * yet done so, then we need to send.
	 */
	if (flags & TH_FIN &&
	    ((tp->t_flags & TF_SENTFIN) == 0)) {
		goto send;
	}
	/*
	 * No reason to send a segment, just return.
	 */
just_return:
just_return_nolock:
	if (tot_len)
		slot = bbr_get_pacing_delay(bbr, bbr->r_ctl.rc_bbr_hptsi_gain, tot_len, cts, 0);
	if (bbr->rc_no_pacing)
		slot = 0;
	if (tot_len == 0) {
		if ((ctf_outstanding(tp) + min((bbr->r_ctl.rc_high_rwnd/2), bbr_minseg(bbr))) >=
		    tp->snd_wnd) {
			BBR_STAT_INC(bbr_rwnd_limited);
			app_limited = BBR_JR_RWND_LIMITED;
			bbr_cwnd_limiting(tp, bbr, ctf_outstanding(tp));
			if ((bbr->rc_in_persist == 0) &&
			    TCPS_HAVEESTABLISHED(tp->t_state) &&
			    (tp->snd_max == tp->snd_una) &&
			    sbavail(&tcp_getsocket(tp)->so_snd)) {
				/* No send window.. we must enter persist */
				bbr_enter_persist(tp, bbr, bbr->r_ctl.rc_rcvtime, __LINE__);
			}
		} else if (ctf_outstanding(tp) >= sbavail(sb)) {
			BBR_STAT_INC(bbr_app_limited);
			app_limited = BBR_JR_APP_LIMITED;
			bbr_cwnd_limiting(tp, bbr, ctf_outstanding(tp));
		} else if ((ctf_flight_size(tp, (bbr->r_ctl.rc_sacked +
						 bbr->r_ctl.rc_lost_bytes)) + p_maxseg) >= tp->snd_cwnd) {
			BBR_STAT_INC(bbr_cwnd_limited);
 			app_limited = BBR_JR_CWND_LIMITED;
			bbr_cwnd_limiting(tp, bbr, ctf_flight_size(tp, (bbr->r_ctl.rc_sacked +
									bbr->r_ctl.rc_lost_bytes)));
			bbr->rc_cwnd_limited = 1;
		} else {
			BBR_STAT_INC(bbr_app_limited);
			app_limited = BBR_JR_APP_LIMITED;
			bbr_cwnd_limiting(tp, bbr, ctf_outstanding(tp));
		}
		bbr->r_ctl.rc_hptsi_agg_delay = 0;
		bbr->r_agg_early_set = 0;
		bbr->r_ctl.rc_agg_early = 0;
		bbr->r_ctl.rc_last_delay_val = 0;
	} else if (bbr->rc_use_google == 0)
		bbr_check_bbr_for_state(bbr, cts, __LINE__, 0);
	/* Are we app limited? */
	if ((app_limited == BBR_JR_APP_LIMITED) ||
	    (app_limited == BBR_JR_RWND_LIMITED)) {
		/**
		 * We are application limited.
		 */
		bbr->r_ctl.r_app_limited_until = (ctf_flight_size(tp, (bbr->r_ctl.rc_sacked +
								       bbr->r_ctl.rc_lost_bytes)) + bbr->r_ctl.rc_delivered);
	}
	if (tot_len == 0)
		counter_u64_add(bbr_out_size[TCP_MSS_ACCT_JUSTRET], 1);
	/* Dont update the time if we did not send */
	bbr->r_ctl.rc_last_delay_val = 0;
	bbr->rc_output_starts_timer = 1;
	bbr_start_hpts_timer(bbr, tp, cts, 9, slot, tot_len);
	if (SEQ_LT(tp->snd_nxt, tp->snd_max)) {
		/* Make sure snd_nxt is drug up */
		tp->snd_nxt = tp->snd_max;
	}
	return (error);

send:
	if (doing_tlp == 0) {
		/*
		 * Data not a TLP, and its not the rxt firing. If it is the
		 * rxt firing, we want to leave the tlp_in_progress flag on
		 * so we don't send another TLP. It has to be a rack timer
		 * or normal send (response to acked data) to clear the tlp
		 * in progress flag.
		 */
		bbr->rc_tlp_in_progress = 0;
		bbr->rc_tlp_rtx_out = 0;
	} else {
		/*
		 * Its a TLP.
		 */
		bbr->rc_tlp_in_progress = 1;
	}
	bbr_timer_cancel(bbr, __LINE__, cts);
	if (rsm == NULL) {
		if (sbused(sb) > 0) {
			/*
			 * This is sub-optimal. We only send a stand alone
			 * FIN on its own segment.
			 */
			if (flags & TH_FIN) {
				flags &= ~TH_FIN;
				if ((len == 0) && ((tp->t_flags & TF_ACKNOW) == 0)) {
					/* Lets not send this */
					slot = 0;
					goto just_return;
				}
			}
		}
	} else {
		/*
		 * We do *not* send a FIN on a retransmit if it has data.
		 * The if clause here where len > 1 should never come true.
		 */
		if ((len > 0) &&
		    (((rsm->r_flags & BBR_HAS_FIN) == 0) &&
		    (flags & TH_FIN))) {
			flags &= ~TH_FIN;
			len--;
		}
	}
	if (len > 0) {
		if ((tp->snd_una == tp->snd_max) &&
		    (bbr_calc_time(cts, bbr->r_ctl.rc_went_idle_time) >= bbr_rtt_probe_time)) {
			/*
			 * This qualifies as a RTT_PROBE session since we
			 * drop the data outstanding to nothing and waited
			 * more than bbr_rtt_probe_time.
			 */
			bbr_set_reduced_rtt(bbr, cts, __LINE__);
		}
	}
	/*
	 * Before ESTABLISHED, force sending of initial options unless TCP
	 * set not to do any options. NOTE: we assume that the IP/TCP header
	 * plus TCP options always fit in a single mbuf, leaving room for a
	 * maximum link header, i.e. max_linkhdr + sizeof (struct tcpiphdr)
	 * + optlen <= MCLBYTES
	 */
	optlen = 0;
	hdrlen = sizeof(struct tcphdr);

	/*
	 * Compute options for segment. We only have to care about SYN and
	 * established connection segments.  Options for SYN-ACK segments
	 * are handled in TCP syncache.
	 */
	to.to_flags = 0;
	local_options = 0;
	if ((tp->t_flags & TF_NOOPT) == 0) {
		/* Maximum segment size. */
		if (flags & TH_SYN) {
			to.to_mss = tcp_mssopt(tp);
			to.to_flags |= TOF_MSS;
		}
		/* Window scaling. */
		if ((flags & TH_SYN) && (tp->t_flags & TF_REQ_SCALE)) {
			to.to_wscale = tp->request_r_scale;
			to.to_flags |= TOF_SCALE;
		}
		/* Timestamps. */
		if ((tp->t_flags & TF_RCVD_TSTMP) ||
		    ((flags & TH_SYN) && (tp->t_flags & TF_REQ_TSTMP))) {
			to.to_tsval = 	tcp_tv_to_mssectick(&bbr->rc_tv) + tp->ts_offset;
			to.to_tsecr = tp->ts_recent;
			to.to_flags |= TOF_TS;
			local_options += TCPOLEN_TIMESTAMP + 2;
		}
		/* Selective ACK's. */
		if (flags & TH_SYN)
			to.to_flags |= TOF_SACKPERM;
		else if (TCPS_HAVEESTABLISHED(tp->t_state) &&
		    tp->rcv_numsacks > 0) {
			to.to_flags |= TOF_SACK;
			to.to_nsacks = tp->rcv_numsacks;
			to.to_sacks = (u_char *)tp->sackblks;
		}

		/* Processing the options. */
		hdrlen += (optlen = tcp_addoptions(tp, &to, opt));
	}
	ipoptlen = 0;
	if (bbr->rc_last_options != local_options) {
		/*
		 * Cache the options length this generally does not change
		 * on a connection. We use this to calculate TSO.
		 */
		bbr->rc_last_options = local_options;
	}
	maxseg = tp->t_maxseg - (ipoptlen + optlen);
	p_maxseg = min(maxseg, pace_max_segs);
	/*
	 * Adjust data length if insertion of options will bump the packet
	 * length beyond the t_maxseg length. Clear the FIN bit because we
	 * cut off the tail of the segment.
	 */
	if (len > maxseg) {
		if (len != 0 && (flags & TH_FIN)) {
			flags &= ~TH_FIN;
		}
		if (tso) {
			uint32_t moff;
			int32_t max_len;

			KASSERT(ipoptlen == 0,
			    ("%s: TSO can't do IP options", __func__));

			/*
			 * Check if we should limit by maximum payload
			 * length:
			 */
			if (tp->t_tsomax != 0) {
				/* compute maximum TSO length */
#if 0   /* from TREX_FBSD integration */
				max_len = (tp->t_tsomax - hdrlen -
				    max_linkhdr);
#else
				max_len = tp->t_tsomax - optlen;
#endif
				if (max_len <= 0) {
					len = 0;
				} else if (len > max_len) {
					len = max_len;
				}
			}
			/*
			 * Prevent the last segment from being fractional
			 * unless the send sockbuf can be emptied:
			 */
			if ((sb_offset + len) < sbavail(sb)) {
				moff = len % (uint32_t)maxseg;
				if (moff != 0) {
					len -= moff;
				}
			}
			/*
			 * In case there are too many small fragments don't
			 * use TSO:
			 */
			if (len <= maxseg) {
				len = maxseg;
				tso = 0;
			}
		} else {
			/* Not doing TSO */
			if (optlen + ipoptlen >= tp->t_maxseg) {
				/*
				 * Since we don't have enough space to put
				 * the IP header chain and the TCP header in
				 * one packet as required by RFC 7112, don't
				 * send it. Also ensure that at least one
				 * byte of the payload can be put into the
				 * TCP segment.
				 */
				error = EMSGSIZE;
				sack_rxmit = 0;
				goto out;
			}
			len = maxseg;
		}
	} else {
		/* Not doing TSO */
		tso = 0;
	}
	KASSERT(len + hdrlen + ipoptlen <= IP_MAXPACKET,
	    ("%s: len > IP_MAXPACKET", __func__));
	/*
	 * This KASSERT is here to catch edge cases at a well defined place.
	 * Before, those had triggered (random) panic conditions further
	 * down.
	 */
	KASSERT(len >= 0, ("[%s:%d]: len < 0", __func__, __LINE__));
	if ((len == 0) &&
	    (flags & TH_FIN) &&
	    (sbused(sb))) {
		/*
		 * We have outstanding data, don't send a fin by itself!.
		 */
		slot = 0;
		goto just_return;
	}

        struct tcp_pkt pkt;

        pkt.m_optlen = optlen;

	/*
	 * Grab a header mbuf, attaching a copy of data to be transmitted,
	 * and initialize the header from the template for sends on this
	 * connection.
	 */
	if (len) {
		/*
		 * We place a limit on sending with hptsi.
		 */
		if ((rsm == NULL) && len > pace_max_segs)
			len = pace_max_segs;
		if (len <= maxseg)
			tso = 0;

		if (tcp_build_dpkt(tp, sb_offset, len, hdrlen, &pkt) != 0) {
			BBR_STAT_INC(bbr_failed_mbuf_aloc);
			error = ENOBUFS;
			sack_rxmit = 0;
			goto out;
		}

		/*
		 * If we're sending everything we've got, set PUSH. (This
		 * will keep happy those implementations which only give
		 * data to the user when a buffer fills or a PUSH comes in.)
		 */
                /* TREX_FBSD: Force PUSH in case of NODELAY of client side */
		if ((sb_offset + len == sbused(sb) && sbused(sb) && !(flags & TH_SYN)) ||
                    (tp->t_flags & TF_NODELAY_PUSH)) {
			flags |= TH_PUSH;
		}
	} else {
		if (tp->t_flags & TF_ACKNOW)
			KMOD_TCPSTAT_INC(tcps_sndacks);
		else if (flags & (TH_SYN | TH_FIN | TH_RST))
			KMOD_TCPSTAT_INC(tcps_sndctrl);
		else
			KMOD_TCPSTAT_INC(tcps_sndwinup);

		if (tcp_build_cpkt(tp, hdrlen, &pkt) != 0) {
			BBR_STAT_INC(bbr_failed_mbuf_aloc);
			error = ENOBUFS;
			/* Fudge the send time since we could not send */
			sack_rxmit = 0;
			goto out;
		}
	}
	m = (struct mbuf *)pkt.m_buf;
	th = (struct tcphdr *)pkt.lpTcp;
	/*
	 * If we are doing retransmissions, then snd_nxt will not reflect
	 * the first unsent octet.  For ACK only packets, we do not want the
	 * sequence number of the retransmitted packet, we want the sequence
	 * number of the next unsent octet.  So, if there is no data (and no
	 * SYN or FIN), use snd_max instead of snd_nxt when filling in
	 * ti_seq.  But if we are in persist state, snd_max might reflect
	 * one byte beyond the right edge of the window, so use snd_nxt in
	 * that case, since we know we aren't doing a retransmission.
	 * (retransmit and persist are mutually exclusive...)
	 */
	if (sack_rxmit == 0) {
		if (len && ((flags & (TH_FIN | TH_SYN | TH_RST)) == 0)) {
			/* New data (including new persists) */
			th->th_seq = htonl(tp->snd_max);
			bbr_seq = tp->snd_max;
		} else if (flags & TH_SYN) {
			/* Syn's always send from iss */
			th->th_seq = htonl(tp->iss);
			bbr_seq = tp->iss;
		} else if (flags & TH_FIN) {
			if (flags & TH_FIN && tp->t_flags & TF_SENTFIN) {
				/*
				 * If we sent the fin already its 1 minus
				 * snd_max
				 */
				th->th_seq = (htonl(tp->snd_max - 1));
				bbr_seq = (tp->snd_max - 1);
			} else {
				/* First time FIN use snd_max */
				th->th_seq = htonl(tp->snd_max);
				bbr_seq = tp->snd_max;
			}
		} else {
			/*
			 * len == 0 and not persist we use snd_max, sending
			 * an ack unless we have sent the fin then its 1
			 * minus.
			 */
			/*
			 * XXXRRS Question if we are in persists and we have
			 * nothing outstanding to send and we have not sent
			 * a FIN, we will send an ACK. In such a case it
			 * might be better to send (tp->snd_una - 1) which
			 * would force the peer to ack.
			 */
			if (tp->t_flags & TF_SENTFIN) {
				th->th_seq = htonl(tp->snd_max - 1);
				bbr_seq = (tp->snd_max - 1);
			} else {
				th->th_seq = htonl(tp->snd_max);
				bbr_seq = tp->snd_max;
			}
		}
	} else {
		/* All retransmits use the rsm to guide the send */
		th->th_seq = htonl(rsm->r_start);
		bbr_seq = rsm->r_start;
	}
	th->th_ack = htonl(tp->rcv_nxt);
	if (optlen) {
		bcopy(opt, th + 1, optlen);
		th->th_off = (sizeof(struct tcphdr) + optlen) >> 2;
	}
	th->th_flags = flags;
	/*
	 * Calculate receive window.  Don't shrink window, but avoid silly
	 * window syndrome.
	 */
	if ((flags & TH_RST) || ((recwin < (so->so_rcv.sb_hiwat / 4) &&
				  recwin < maxseg)))
		recwin = 0;
	if (SEQ_GT(tp->rcv_adv, tp->rcv_nxt) &&
	    recwin < (tp->rcv_adv - tp->rcv_nxt))
		recwin = (tp->rcv_adv - tp->rcv_nxt);
	if (recwin > TCP_MAXWIN << tp->rcv_scale)
		recwin = TCP_MAXWIN << tp->rcv_scale;

	/*
	 * According to RFC1323 the window field in a SYN (i.e., a <SYN> or
	 * <SYN,ACK>) segment itself is never scaled.  The <SYN,ACK> case is
	 * handled in syncache.
	 */
	if (flags & TH_SYN)
		th->th_win = htons((u_short)
		    (min(sbspace(&so->so_rcv), TCP_MAXWIN)));
	else {
		/* Avoid shrinking window with window scaling. */
		recwin = roundup2(recwin, 1 << tp->rcv_scale);
		th->th_win = htons((u_short)(recwin >> tp->rcv_scale));
	}
	/*
	 * Adjust the RXWIN0SENT flag - indicate that we have advertised a 0
	 * window.  This may cause the remote transmitter to stall.  This
	 * flag tells soreceive() to disable delayed acknowledgements when
	 * draining the buffer.  This can occur if the receiver is
	 * attempting to read more data than can be buffered prior to
	 * transmitting on the connection.
	 */
	if (th->th_win == 0) {
		tp->t_sndzerowin++;
		tp->t_flags |= TF_RXWIN0SENT;
	} else
		tp->t_flags &= ~TF_RXWIN0SENT;
	/*
	 * We don't support urgent data, but drag along
	 * the pointer in case of a stack switch.
	 */
	tp->snd_up = tp->snd_una;

#ifdef TCPDEBUG
	/*
	 * Trace.
	 */
	if (so->so_options & SO_DEBUG) {
		tcp_trace(TA_OUTPUT, tp->t_state, tp, NULL, th, 0);
	}
#endif				/* TCPDEBUG */

	/*
	 * Fill in IP length and desired time to live and send to IP level.
	 * There should be a better way to handle ttl and tos; we could keep
	 * them in the template, but need a way to checksum without them.
	 */
	/*
	 * m->m_pkthdr.len should have been set before cksum calcuration,
	 * because in6_cksum() need it.
	 */
        error = tcp_ip_output(tp, m, 0);
out:

	/*
	 * In transmit state, time the transmission and arrange for the
	 * retransmit.  In persist state, just set snd_max.
	 */
	if (error == 0) {
#if 0   // BBR_INT: has no effect
		tcp_account_for_send(tp, len, (rsm != NULL), doing_tlp, 0);
#endif
		if (TCPS_HAVEESTABLISHED(tp->t_state) &&
		    (tp->t_flags & TF_SACK_PERMIT) &&
		    tp->rcv_numsacks > 0)
			tcp_clean_dsack_blocks(tp);
		/* We sent an ack clear the bbr_segs_rcvd count */
		bbr->output_error_seen = 0;
		bbr->oerror_cnt = 0;
		bbr->bbr_segs_rcvd = 0;
		if (len == 0)
			counter_u64_add(bbr_out_size[TCP_MSS_ACCT_SNDACK], 1);
		/* Do accounting for new sends */
		if ((len > 0) && (rsm == NULL)) {
			int idx;
			if (tp->snd_una == tp->snd_max) {
				/*
				 * Special case to match google, when
				 * nothing is in flight the delivered
				 * time does get updated to the current
				 * time (see tcp_rate_bsd.c).
				 */
				bbr->r_ctl.rc_del_time = cts;
			}
			if (len >= maxseg) {
				idx = (len / maxseg) + 3;
				if (idx >= TCP_MSS_ACCT_ATIMER)
					counter_u64_add(bbr_out_size[(TCP_MSS_ACCT_ATIMER - 1)], 1);
				else
					counter_u64_add(bbr_out_size[idx], 1);
			} else {
				/* smaller than a MSS */
				idx = len / (bbr_hptsi_bytes_min - bbr->rc_last_options);
				if (idx >= TCP_MSS_SMALL_MAX_SIZE_DIV)
					idx = (TCP_MSS_SMALL_MAX_SIZE_DIV - 1);
				counter_u64_add(bbr_out_size[(idx + TCP_MSS_SMALL_SIZE_OFF)], 1);
			}
		}
	}
	abandon = 0;
	/*
	 * We must do the send accounting before we log the output,
	 * otherwise the state of the rsm could change and we account to the
	 * wrong bucket.
	 */
	if (len > 0) {
		bbr_do_send_accounting(tp, bbr, rsm, len, error);
		if (error == 0) {
			if (tp->snd_una == tp->snd_max)
				bbr->r_ctl.rc_tlp_rxt_last_time = cts;
		}
	}
	bbr_log_output(bbr, tp, &to, len, bbr_seq, (uint8_t) flags, error,
	    cts, NULL, &abandon, rsm, 0, sb);
	if (abandon) {
		/*
		 * If bbr_log_output destroys the TCB or sees a TH_RST being
		 * sent we should hit this condition.
		 */
		return (0);
	}
	if (bbr->rc_in_persist == 0) {
		/*
		 * Advance snd_nxt over sequence space of this segment.
		 */
		if (error)
			/* We don't log or do anything with errors */
			goto skip_upd;

		if (tp->snd_una == tp->snd_max &&
		    (len || (flags & (TH_SYN | TH_FIN)))) {
			/*
			 * Update the time we just added data since none was
			 * outstanding.
			 */
			bbr->rc_tp->t_acktime  = ticks;
		}
		if (flags & (TH_SYN | TH_FIN) && (rsm == NULL)) {
			if (flags & TH_SYN) {
				/*
				 * Smack the snd_max to iss + 1
				 * if its a FO we will add len below.
				 */
				tp->snd_max = tp->iss + 1;
			}
			if ((flags & TH_FIN) && ((tp->t_flags & TF_SENTFIN) == 0)) {
				tp->snd_max++;
				tp->t_flags |= TF_SENTFIN;
			}
		}
		if (sack_rxmit == 0)
			tp->snd_max += len;
skip_upd:
		if ((error == 0) && len)
			tot_len += len;
	} else {
		/* Persists case */
		int32_t xlen = len;

		if (error)
			goto nomore;

		if (flags & TH_SYN)
			++xlen;
		if ((flags & TH_FIN) && ((tp->t_flags & TF_SENTFIN) == 0)) {
			++xlen;
			tp->t_flags |= TF_SENTFIN;
		}
		if (xlen && (tp->snd_una == tp->snd_max)) {
			/*
			 * Update the time we just added data since none was
			 * outstanding.
			 */
			bbr->rc_tp->t_acktime = ticks;
		}
		if (sack_rxmit == 0)
			tp->snd_max += xlen;
		tot_len += (len + optlen + ipoptlen);
	}
nomore:
	if (error) {
		/*
		 * Failures do not advance the seq counter above. For the
		 * case of ENOBUFS we will fall out and become ack-clocked.
		 * capping the cwnd at the current flight.
		 * Everything else will just have to retransmit with the timer
		 * (no pacer).
		 */
		BBR_STAT_INC(bbr_saw_oerr);
		/* Clear all delay/early tracks */
		bbr->r_ctl.rc_hptsi_agg_delay = 0;
		bbr->r_ctl.rc_agg_early = 0;
		bbr->r_agg_early_set = 0;
		bbr->output_error_seen = 1;
		if (bbr->oerror_cnt < 0xf)
			bbr->oerror_cnt++;
		if (bbr_max_net_error_cnt && (bbr->oerror_cnt >= bbr_max_net_error_cnt)) {
			/* drop the session */
			tcp_set_inp_to_drop(inp, ENETDOWN);
		}
		switch (error) {
		case ENOBUFS:
			/*
			 * Make this guy have to get ack's to send
			 * more but lets make sure we don't
			 * slam him below a T-O (1MSS).
			 */
			if (bbr->rc_bbr_state != BBR_STATE_PROBE_RTT) {
				tp->snd_cwnd = ctf_flight_size(tp, (bbr->r_ctl.rc_sacked +
								    bbr->r_ctl.rc_lost_bytes)) - maxseg;
				if (tp->snd_cwnd < maxseg)
					tp->snd_cwnd = maxseg;
			}
			slot = (bbr_error_base_paceout + 1) << bbr->oerror_cnt;
			BBR_STAT_INC(bbr_saw_enobuf);
			if (bbr->bbr_hdrw_pacing)
				counter_u64_add(bbr_hdwr_pacing_enobuf, 1);
			else
				counter_u64_add(bbr_nohdwr_pacing_enobuf, 1);
			/*
			 * Here even in the enobuf's case we want to do our
			 * state update. The reason being we may have been
			 * called by the input function. If so we have had
			 * things change.
			 */
			error = 0;
			goto enobufs;
		case EMSGSIZE:
			/*
			 * For some reason the interface we used initially
			 * to send segments changed to another or lowered
			 * its MTU. If TSO was active we either got an
			 * interface without TSO capabilits or TSO was
			 * turned off. If we obtained mtu from ip_output()
			 * then update it and try again.
			 */
			/* Turn on tracing (or try to) */
			{
				int old_maxseg;

				old_maxseg = tp->t_maxseg;
				BBR_STAT_INC(bbr_saw_emsgsiz);
#if 0
				if (mtu != 0)
					tcp_mss_update(tp, -1, mtu, NULL, NULL);
#endif
				if (old_maxseg <= tp->t_maxseg) {
					/* Huh it did not shrink? */
					tp->t_maxseg = old_maxseg - 40;
				}
				/*
				 * Nuke all other things that can interfere
				 * with slot
				 */
				if ((tot_len + len) && (len >= tp->t_maxseg)) {
					slot = bbr_get_pacing_delay(bbr,
					    bbr->r_ctl.rc_bbr_hptsi_gain,
					    (tot_len + len), cts, 0);
					if (slot < bbr_error_base_paceout)
						slot = (bbr_error_base_paceout + 2) << bbr->oerror_cnt;
				} else
					slot = (bbr_error_base_paceout + 2) << bbr->oerror_cnt;
				bbr->rc_output_starts_timer = 1;
				bbr_start_hpts_timer(bbr, tp, cts, 10, slot,
				    tot_len);
				return (error);
			}
		case EPERM:
			tp->t_softerror = error;
			/* Fall through */
		case EHOSTDOWN:
		case EHOSTUNREACH:
		case ENETDOWN:
		case ENETUNREACH:
			if (TCPS_HAVERCVDSYN(tp->t_state)) {
				tp->t_softerror = error;
			}
			/* FALLTHROUGH */
		default:
			slot = (bbr_error_base_paceout + 3) << bbr->oerror_cnt;
			bbr->rc_output_starts_timer = 1;
			bbr_start_hpts_timer(bbr, tp, cts, 11, slot, 0);
			return (error);
		}
	}
	KMOD_TCPSTAT_INC(tcps_sndtotal);
#if 0   // BBR_INT: no route support
	if ((bbr->bbr_hdw_pace_ena) &&
	    (bbr->bbr_attempt_hdwr_pace == 0) &&
	    (bbr->rc_past_init_win) &&
	    (bbr->rc_bbr_state != BBR_STATE_STARTUP) &&
	    (get_filter_value(&bbr->r_ctl.rc_delrate)) &&
	    (inp->inp_route.ro_nh &&
	     inp->inp_route.ro_nh->nh_ifp)) {
		/*
		 * We are past the initial window and
		 * have at least one measurement so we
		 * could use hardware pacing if its available.
		 * We have an interface and we have not attempted
		 * to setup hardware pacing, lets try to now.
		 */
		uint64_t rate_wanted;
		int err = 0;

		rate_wanted = bbr_get_hardware_rate(bbr);
		bbr->bbr_attempt_hdwr_pace = 1;
		bbr->r_ctl.crte = tcp_set_pacing_rate(bbr->rc_tp,
						      inp->inp_route.ro_nh->nh_ifp,
						      rate_wanted,
						      (RS_PACING_GEQ|RS_PACING_SUB_OK),
						      &err, NULL);
		if (bbr->r_ctl.crte) {
			BBR_STAT_INC(bbr_hdwr_rl_add_ok);
			counter_u64_add(bbr_flows_nohdwr_pacing, -1);
			counter_u64_add(bbr_flows_whdwr_pacing, 1);
			bbr->bbr_hdrw_pacing = 1;
			/* Now what is our gain status? */
			if (bbr->r_ctl.crte->rate < rate_wanted) {
				/* We have a problem */
				bbr_setup_less_of_rate(bbr, cts,
						       bbr->r_ctl.crte->rate, rate_wanted);
			} else {
				/* We are good */
				bbr->gain_is_limited = 0;
				bbr->skip_gain = 0;
			}
			tcp_bbr_tso_size_check(bbr, cts);
		} else {
			BBR_STAT_INC(bbr_hdwr_rl_add_fail);
		}
	}
#endif
#if 0
	if (bbr->bbr_hdrw_pacing) {
		/*
		 * Worry about cases where the route
		 * changes or something happened that we
		 * lost our hardware pacing possibly during
		 * the last ip_output call.
		 */
		if (inp->inp_snd_tag == NULL) {
			/* A change during ip output disabled hw pacing? */
			bbr->bbr_hdrw_pacing = 0;
		} else if ((inp->inp_route.ro_nh == NULL) ||
		    (inp->inp_route.ro_nh->nh_ifp != inp->inp_snd_tag->ifp)) {
			/*
			 * We had an interface or route change,
			 * detach from the current hdwr pacing
			 * and setup to re-attempt next go
			 * round.
			 */
			bbr->bbr_hdrw_pacing = 0;
			bbr->bbr_attempt_hdwr_pace = 0;
			tcp_rel_pacing_rate(bbr->r_ctl.crte, bbr->rc_tp);
			tcp_bbr_tso_size_check(bbr, cts);
		}
	}
#endif
	/*
	 * Data sent (as far as we can tell). If this advertises a larger
	 * window than any other segment, then remember the size of the
	 * advertised window. Any pending ACK has now been sent.
	 */
	if (SEQ_GT(tp->rcv_nxt + recwin, tp->rcv_adv))
		tp->rcv_adv = tp->rcv_nxt + recwin;

	tp->last_ack_sent = tp->rcv_nxt;
	if ((error == 0) &&
	    (bbr->r_ctl.rc_pace_max_segs > tp->t_maxseg) &&
	    (doing_tlp == 0) &&
	    (tso == 0) &&
	    (len > 0) &&
	    ((flags & TH_RST) == 0) &&
	    ((flags & TH_SYN) == 0) &&
	    (IN_RECOVERY(tp->t_flags) == 0) &&
	    (bbr->rc_in_persist == 0) &&
	    (tot_len < bbr->r_ctl.rc_pace_max_segs)) {
		/*
		 * For non-tso we need to goto again until we have sent out
		 * enough data to match what we are hptsi out every hptsi
		 * interval.
		 */
		if (SEQ_LT(tp->snd_nxt, tp->snd_max)) {
			/* Make sure snd_nxt is drug up */
			tp->snd_nxt = tp->snd_max;
		}
		if (rsm != NULL) {
			rsm = NULL;
			goto skip_again;
		}
		rsm = NULL;
		sack_rxmit = 0;
		tp->t_flags &= ~(TF_ACKNOW | TF_DELACK);
		goto again;
	}
skip_again:
	if ((error == 0) && (flags & TH_FIN))
		tcp_log_end_status(tp, TCP_EI_STATUS_SERVER_FIN);
	if ((error == 0) && (flags & TH_RST))
		tcp_log_end_status(tp, TCP_EI_STATUS_SERVER_RST);
	if (((flags & (TH_RST | TH_SYN | TH_FIN)) == 0) && tot_len) {
		/*
		 * Calculate/Re-Calculate the hptsi slot in usecs based on
		 * what we have sent so far
		 */
		slot = bbr_get_pacing_delay(bbr, bbr->r_ctl.rc_bbr_hptsi_gain, tot_len, cts, 0);
		if (bbr->rc_no_pacing)
			slot = 0;
	}
	tp->t_flags &= ~(TF_ACKNOW | TF_DELACK);
enobufs:
	if (bbr->rc_use_google == 0)
		bbr_check_bbr_for_state(bbr, cts, __LINE__, 0);
	bbr_cwnd_limiting(tp, bbr, ctf_flight_size(tp, (bbr->r_ctl.rc_sacked +
							bbr->r_ctl.rc_lost_bytes)));
	bbr->rc_output_starts_timer = 1;
	if (bbr->bbr_use_rack_cheat &&
	    (more_to_rxt ||
	     ((bbr->r_ctl.rc_resend = bbr_check_recovery_mode(tp, bbr, cts)) != NULL))) {
		/* Rack cheats and shotguns out all rxt's 1ms apart */
		if (slot > 1000)
			slot = 1000;
	}
	if (bbr->bbr_hdrw_pacing && (bbr->hw_pacing_set == 0)) {
		/*
		 * We don't change the tso size until some number of sends
		 * to give the hardware commands time to get down
		 * to the interface.
		 */
		bbr->r_ctl.bbr_hdwr_cnt_noset_snt++;
		if (bbr->r_ctl.bbr_hdwr_cnt_noset_snt >= bbr_hdwr_pacing_delay_cnt) {
			bbr->hw_pacing_set = 1;
			tcp_bbr_tso_size_check(bbr, cts);
		}
	}
	bbr_start_hpts_timer(bbr, tp, cts, 12, slot, tot_len);
	if (SEQ_LT(tp->snd_nxt, tp->snd_max)) {
		/* Make sure snd_nxt is drug up */
		tp->snd_nxt = tp->snd_max;
	}
	return (error);

}

/*
 * See bbr_output_wtime() for return values.
 */
static int
bbr_output(struct tcpcb *tp)
{
	int32_t ret;
	struct timeval tv = { 0 };

	(void)tcp_get_usecs(&tv);
	ret = bbr_output_wtime(tp, &tv);
	return (ret);
}

struct tcp_function_block __tcp_bbr = {
	.tfb_tcp_block_name = "bbr",
	.tfb_tcp_output = bbr_output,
#if 0   // BBR_INT
	.tfb_do_queued_segments = ctf_do_queued_segments,
	.tfb_do_segment_nounlock = bbr_do_segment_nounlock,
#endif  // BBR_INT
	.tfb_tcp_do_segment = bbr_do_segment,
	.tfb_tcp_fb_init = bbr_init,
	.tfb_tcp_fb_fini = bbr_fini,
	.tfb_tcp_rexmit_tmr = bbr_remxt_tmr,
};

