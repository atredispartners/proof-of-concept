// steam_service_types.h
// Reconstructed layouts for steamclient64's SteamService client (sept2 build).
// Unverified fields/slots are padding
#pragma once
#include <windows.h>
#include <stddef.h>
#include <stdint.h>

typedef struct CSteamServiceWin32          CSteamServiceWin32;
typedef struct IClientInstallUtilsMap      IClientInstallUtilsMap;
typedef struct IClientModuleManagerMap     IClientModuleManagerMap;
typedef struct IClientProcessMonitorMap    IClientProcessMonitorMap;
typedef struct IRegistryInterfaceMap       IRegistryInterfaceMap;
typedef struct IClientSecureDesktopMap     IClientSecureDesktopMap;
typedef struct IClientWindowsHWMonitorMap  IClientWindowsHWMonitorMap;

typedef struct CSteamServiceWin32_vtbl {
    uint8_t (__fastcall *Connect)(CSteamServiceWin32 *self);                     // 0 
    void    (__fastcall *Disconnect)(CSteamServiceWin32 *self);                  // 1
    void    *slot2, *slot3;
    uint8_t (__fastcall *BIsSteamServiceDllLoaded)(CSteamServiceWin32 *self);    // 4
    uint8_t (__fastcall *ServiceStart)(CSteamServiceWin32 *self);                // 5
} CSteamServiceWin32_vtbl;

struct CSteamServiceWin32 {
    const CSteamServiceWin32_vtbl *vtbl;                 // 0x00
    uint8_t                     ipcClient[0xA0];         // 0x08  embedded CIPCClient
    int32_t                     hSteamPipe;              // 0xA8  connection id
    int32_t                     _unk_AC;
    IClientInstallUtilsMap     *pInstallUtils;           // 0xB0
    IClientModuleManagerMap    *pModuleManager;          // 0xB8
    IClientProcessMonitorMap   *pProcessMonitor;         // 0xC0
    IRegistryInterfaceMap      *pRegistry;               // 0xC8
    IClientSecureDesktopMap    *pSecureDesktop;          // 0xD0
    IClientWindowsHWMonitorMap *pHWMonitor;              // 0xD8
    HMODULE                     hSteamServiceDll;        // 0xE0
    uint8_t                     _unk_E8;                 // 0xE8
    uint8_t                     _pad_E9[3];
    int32_t                     nConnectFailures;        // 0xEC
};
C_ASSERT(sizeof(CSteamServiceWin32) == 0xF0);
C_ASSERT(offsetof(CSteamServiceWin32, pInstallUtils)  == 0xB0);
C_ASSERT(offsetof(CSteamServiceWin32, pSecureDesktop) == 0xD0);

#define INTERFACE_MAP_FIELDS(VT)                                               \
    const VT *vtbl;          /* 0x00 */                                        \
    int32_t   _unk_08;       /* 0x08 */                                        \
    int32_t   hPipe;         /* 0x0C  == CSteamServiceWin32.hSteamPipe */      \
    uint8_t   token;         /* 0x10  per-interface RunInterface token */      \
    uint8_t   _pad_11[7];                                                      \
    void     *pDispatcher;   /* 0x18 */

typedef struct IClientInstallUtilsMap_vtbl {
    void    *slot0_7[8];
    uint8_t (__fastcall *InstallStreamingAudioDrivers)(IClientInstallUtilsMap *self);   // 8
    uint32_t(__fastcall *InstallXboxDriver)(IClientInstallUtilsMap *self);              // 9
    void    *slot10_14[5];
    uint8_t (__fastcall *InstallVrLinkDongleDriver)(IClientInstallUtilsMap *self,
                                                    const char *driverDir);             // 15
    void    *slot16_20[5];
    uint32_t(__fastcall *AddInstallScriptToWhiteList)(IClientInstallUtilsMap *self,
                                                    const char *scriptPath,
                                                    const char *installDir);            // 21
    uint8_t (__fastcall *RunInstallScript)(IClientInstallUtilsMap *self,
                                           const char *scriptPath, int appId,
                                           uint8_t uninstall);                          // 22
} IClientInstallUtilsMap_vtbl;

struct IClientInstallUtilsMap { INTERFACE_MAP_FIELDS(IClientInstallUtilsMap_vtbl) };
C_ASSERT(offsetof(IClientInstallUtilsMap_vtbl, InstallVrLinkDongleDriver)   == 15 * sizeof(void *));
C_ASSERT(offsetof(IClientInstallUtilsMap_vtbl, AddInstallScriptToWhiteList) == 21 * sizeof(void *));
C_ASSERT(offsetof(IClientInstallUtilsMap_vtbl, RunInstallScript)            == 22 * sizeof(void *));

typedef struct IClientModuleManagerMap_vtbl {
    uint8_t (__fastcall *LoadModule)(IClientModuleManagerMap *self, uint32_t moduleId,
                                     const void *pData, uint32_t cbData);               // 0
    void    *slot1_2[2];
    uint32_t(__fastcall *CallFunctionAsync)(IClientModuleManagerMap *self, uint32_t moduleId,
                                            uint32_t flags, uint32_t p2, uint32_t p3,
                                            uint32_t p4, uint32_t p5, const void *pIn,
                                            uint32_t cbIn, uint32_t outSize);           // 3
} IClientModuleManagerMap_vtbl;

struct IClientModuleManagerMap { INTERFACE_MAP_FIELDS(IClientModuleManagerMap_vtbl) };
C_ASSERT(offsetof(IClientModuleManagerMap_vtbl, CallFunctionAsync) == 3 * sizeof(void *));

#define MODULE_FLAG_CHILD_PROCESS 0x08   // flags bit 3 -> child process, no signature check

#define REG_HIVE_HKLM      1
#define REG_HIVE_HKLM_64   (REG_HIVE_HKLM | 0x20)   // 33
#define REG_HIVE_HKLM_32   (REG_HIVE_HKLM | 0x10)   // 17

typedef struct IRegistryInterfaceMap_vtbl {
    void    *slot0;
    uint8_t (__fastcall *BGetValueStr)(IRegistryInterfaceMap *self, int eHive, const char *pchKey,
                                       const char *pchValue, char *pchOut, uint32_t cchOut);         // 1
    void    *slot2_4[3];
    uint8_t (__fastcall *BSetValueStr)(IRegistryInterfaceMap *self, int eHive, const char *pchKey,
                                       const char *pchValue, const char *pchData);                   // 5
    void    *slot6_9[4];
    uint8_t (__fastcall *BDeleteKey)(IRegistryInterfaceMap *self, int eHive, const char *pchKey);    // 10
    uint8_t (__fastcall *BKeyExists)(IRegistryInterfaceMap *self, int eHive, const char *pchKey);    // 11
} IRegistryInterfaceMap_vtbl;

struct IRegistryInterfaceMap { INTERFACE_MAP_FIELDS(IRegistryInterfaceMap_vtbl) };
C_ASSERT(offsetof(IRegistryInterfaceMap_vtbl, BSetValueStr) == 5  * sizeof(void *));
C_ASSERT(offsetof(IRegistryInterfaceMap_vtbl, BDeleteKey)   == 10 * sizeof(void *));

typedef struct IClientSecureDesktopMap_vtbl {
    uint8_t (__fastcall *BStartStreaming)(IClientSecureDesktopMap *self);   // 0
    void    (__fastcall *StopStreaming)(IClientSecureDesktopMap *self);     // 1
    void    (__fastcall *SendSAS)(IClientSecureDesktopMap *self);           // 2
} IClientSecureDesktopMap_vtbl;

struct IClientSecureDesktopMap { INTERFACE_MAP_FIELDS(IClientSecureDesktopMap_vtbl) };

typedef struct IClientWindowsHWMonitorMap_vtbl {
    void     (__fastcall *StartMonitoring)(IClientWindowsHWMonitorMap *self);    // 0
    void     (__fastcall *StopMonitoring)(IClientWindowsHWMonitorMap *self);     // 1
    void     (__fastcall *RefreshInformation)(IClientWindowsHWMonitorMap *self); // 2
    uint32_t (__fastcall *GetCPUTemperature)(IClientWindowsHWMonitorMap *self);  // 3
} IClientWindowsHWMonitorMap_vtbl;

struct IClientWindowsHWMonitorMap { INTERFACE_MAP_FIELDS(IClientWindowsHWMonitorMap_vtbl) };

struct IClientProcessMonitorMap { INTERFACE_MAP_FIELDS(void) };
