# BBR INTEGRATION

This note is the record how I integrate BBR source code from FreeBSD 13.1 to T-Rex TCP stack.
Since the TCP stack was integrated from FreeBSD 13.0, there are some changes. But I will not apply them in general.

## FILES

Basic files from `netinet/tcp_stacks/`

  - `sack_filter.c`[,`sack_filter.h`]:
  - `rack_bbr_common.c`[,`rack_bbr_common.h`]:
  - `bbr.c`[,`tcp_bbr.h`]:

  - `rack.c`[,`tcp_rack.h`]: not in this scope

Additional files to integrate features

  - from `sys/tim_filter.h`,`kern/subr_filter.c`: used to get BW and RTT in BBR


## FEATURES

### Configurable Features

Excluded (removed from the source code)

  - `IPSEC`
  - `IPSEC_SUPPORT`
  - `TCP_SIGNATURE`
  - `DIAGNOSTIC`
  - `KERN_TLS`
  - `MAC`
  - `RATELIMIT`
  - `STATS`
  - `TCP_HHOOK`
  - `TCP_OFFLOAD`
  - `BBR_INVARIANTS`

  - `NETFLIX_COPY_ARGS`: not defined/used
  - `NETFLIX_PEAKRATE`: not defined/used
  - `NETFLIX_SB_LIMITS`: not defined/used
  - `NETFLIX_STATS`: not defined/used

  (from rack.c)
  - `INVARIANTS`
  - `TCP_ACCOUNTING`
  - `TCP_BLOCKBOX`

Included (left in the source code)

  - `TCPDEBUG`: support for `-debug` build (`tcp_trace()`)
  - `INET`: remove `#ifdef`
  - `INET6`: remove `#ifdef` and ipv6 dependancy

  - `_KERNEL`


### Controlled Features

Excluded

  - `bbr_include_ip_oh`
  - `bbr_include_enet_oh`

Included

  - `bbr_include_tcp_oh`


### Other Features

  - `TCP_PROBE5()`: code removed - (1)
  - `tcp_log_event_()`: code removed - additional feature; `tcp_log_buf.c` required.

  - `tcp_rexmit_drop_options`: code removed - (1)
  - `IS_FASTOPEN`: code removed - (1)
  - `tcpip_maketemplate()`: code block replaced by `tcp_respond()`
  - `tcp_do_autorcvbuf`/`tcp_do_autosndbuf`: code removed - (1)
  - `tcp_fast_finwait2_recycle`: removed - (1)

  - `TP_MAXIDLE(tp)`: replaced by `TCPTV_2MSL` for `tcp_timer_activate()` to reduce closing time.
  - `tp->t_port` usage: from `NETFLIX_TCPOUDP` at 3.0, code removed
  - `SB_TLS_IFNET`: code removed - hw TLS is not supported

  - `tcp_twstart()`: replaced by `tcp_timer_twstart()`

  - `PMTUD(Path MTU Discovery)`: code removed - (1)
  - `route support`: code removed - (1)

  - `module support`: code removed - (1)
  - `sysctl support`: code removed - (1)

  - `tcp_function_block`: remove unsupported functions
    - ??`ctf_do_queued_segments`
    - `bbr_ctloutput`(`tcp_set_sockopt` and `tcp_get_sockopt`)
    - `bbr_stopall`, `bbr_timer_activate`, `bbr_timer_active`, `bbr_timer_stop`
    - `bbr_handoff_ok`, `bbr_mtu_chg`, `bbr_pru_options`

  - `bbr_log_...`: remove unsupported log features

  (1) removed in the original stack also


### Required Features

#### PACER

"BBR uses pacing as the primary control. A cwnd control is left in as a safety net, for cases where the pacing rate temporarily exceeds the delivery rate. This is normal in BBR during bandwidth probes, and also occurs when the delivery rate reduces." -- <https://groups.google.com/g/bbr-dev/c/KHvgqYIl1cE>

But the pacing by HW is optional and will not be integrated in this phase.
It is controlled by RATELIMIT feature in `tcp_ratelimit.c`. So it is not included.


#### Time Filter

`struct time_filter` is used to calculate RTT and bandwidth in BBR.
BBR uses the routines provided by `sys/tim_filter.h` and `kern/subr_filter.c`.


#### HPTS

The main purpose of HPTS is to provide a mechanism for pacing packets out onto the wire.
BBR would schedule `tcp_output()` itself by calling `tcp_hpts_insert(tp, ...)`.

Several routines are associated to TCP stack implementation.
So the routines should be kept but the timer event handler could be replaced by T-Rex one.
`netinet/tcp_hpts.h` and `netinet/tcp_hpts.c` files implemented this feature.



## QUESTIONS AND ISSUES

### original stack updates (3.0 -> 3.1) are required?

### HPTS files are required?

### `bbr->rc_tp` cannot be equal to `tp`? 

### `bbr_log_...` functions are required?

### `arc4random_uniform` is required?

### `bbr_use_google_algo` is required?



## CHANGES

`uma_zalloc()`,`uma_zfree()`,`uma_zdestroy()` -> replaced by `malloc` and `free`
