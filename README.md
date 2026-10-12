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

# ไฟล์ output หลังจาก build:

```text
build/
└── lb.exe                ← binary ที่ deploy บน target
deploy/
├── stage.dat             ← sentinel file ที่ต้องวางบน target
└── deploy_checklist.txt  ← checklist step-by-step สำหรับ deploy
```