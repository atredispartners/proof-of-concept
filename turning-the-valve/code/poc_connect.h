#pragma once
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include "steam_service_types.h"

#define RVA_GLOBAL_SERVICE_OBJ 0x17EE690   // sept2 -- must match the installed build

// Locate steamclient64.dll via the Steam install path in the registry.
static int resolve_steamclient(char *out, DWORD cch)
{
    for (int i = 0; i < 2; i++) {
        HKEY root = i ? HKEY_LOCAL_MACHINE : HKEY_CURRENT_USER;
        const char *sub = i ? "SOFTWARE\\WOW6432Node\\Valve\\Steam" : "SOFTWARE\\Valve\\Steam";
        const char *val = i ? "InstallPath" : "SteamPath";
        HKEY k;
        if (RegOpenKeyExA(root, sub, 0, KEY_READ, &k) == ERROR_SUCCESS) {
            char path[MAX_PATH]; DWORD len = sizeof(path), type = 0;
            if (RegQueryValueExA(k, val, NULL, &type, (LPBYTE)path, &len) == ERROR_SUCCESS && type == REG_SZ) {
                for (char *p = path; *p; p++) if (*p == '/') *p = '\\';
                _snprintf(out, cch, "%s\\steamclient64.dll", path);
                RegCloseKey(k);
                if (GetFileAttributesA(out) != INVALID_FILE_ATTRIBUTES) return 1;
            }
            RegCloseKey(k);
        }
    }
    lstrcpynA(out, "C:\\Program Files (x86)\\Steam\\steamclient64.dll", cch);
    return GetFileAttributesA(out) != INVALID_FILE_ATTRIBUTES;
}

// Load steamclient64.dll and complete the CIPC handshake to the SYSTEM service
static CSteamServiceWin32 *steam_connect(const char *dll_path, int untrusted)
{
    char path[MAX_PATH] = {0};
    if (dll_path && dll_path[0]) lstrcpynA(path, dll_path, sizeof(path));
    else if (!resolve_steamclient(path, sizeof(path))) {
        printf("[!] could not locate steamclient64.dll (pass the path as an argument)\n");
        return NULL;
    }
    printf("[*] steamclient64 : %s\n", path);

    HMODULE h = LoadLibraryExA(path, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
    if (!h) {
        printf("[!] LoadLibraryEx failed: %lu (run from the Steam dir if deps are missing)\n", GetLastError());
        return NULL;
    }

    CSteamServiceWin32 *svc = (CSteamServiceWin32 *)((uint8_t *)h + RVA_GLOBAL_SERVICE_OBJ);
    if (!svc->vtbl->Connect(svc)) {
        printf("[!] Connect failed -- is the Steam Client Service running?\n");
        return NULL;
    }
    printf("[+] connected to SYSTEM SteamService (pipe %d)\n", svc->hSteamPipe);
    return svc;
}
