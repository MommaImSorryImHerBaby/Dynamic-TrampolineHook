// -- author: DADDY --
// -- trampoline hook for ASLR disabled binaries --
#define _CRT_SECURE_NO_WARNINGS
// precompiled headers
#include "pch.h"

#include <Windows.h>
#include <stdio.h>

const DWORD64 TARGET_ADDRESS = 0x0000000140015420;


BYTE originalBytes[14];
DWORD64 trampolineAddress = 0;


void log(const char* message)
{
    FILE* f;
    fopen_s(&f, "debug.txt", "a");
    if (f)
    {
        fprintf(f, "[HOOK] [%llu] %s\n", GetTickCount64(), message);
        fclose(f);
    }
}

void HookHandler()
{
    // log 
    log("Game::run(); is executing");
    // visible in DBG-view
    OutputDebugStringA("Game::run() intercepted!");

    log("Game::run(); has been executed");

    MessageBeep(MB_ICONINFORMATION);

    MessageBoxA(NULL,
        "HOOK ACTIVATED!\n\n"
        "Game::run function is executing right now.",
        "SUCCESS",
        MB_OK | MB_ICONEXCLAMATION);
}

bool InstallHookWithLogging()
{
    log("=== Starting hook installation ===");
    log("Target address: 0x140015420");

    // allocate trampoline
    trampolineAddress = (DWORD64)VirtualAlloc(
        NULL, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!trampolineAddress)
    {
        log("ERROR: Failed to allocate trampoline");
        return false;
    }

    log("Trampoline allocated at: 0x%llX");

    // Save original bytes
    DWORD oldProtect;
    if (!VirtualProtect((LPVOID)TARGET_ADDRESS, 14, PAGE_EXECUTE_READWRITE, &oldProtect))
    {
        log("ERROR: VirtualProtect failed");
        return false;
    }
    // save og bytes
    memcpy(originalBytes, (LPVOID)TARGET_ADDRESS, 14);
    log("Original bytes saved");

    // copy stolen bytes to trampoline
    memcpy((LPVOID)trampolineAddress, originalBytes, 14);

    // add jump back to original+14
    BYTE jumpBack[14] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 };
    *(DWORD64*)&jumpBack[6] = TARGET_ADDRESS + 14;
    memcpy((LPVOID)(trampolineAddress + 14), jumpBack, 14);

    // JMP to our handler
    BYTE jumpToHandler[14] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 };
    *(DWORD64*)&jumpToHandler[6] = (DWORD64)HookHandler;

    // log the jump details
    char buffer[256];
    sprintf_s(buffer, "Jumping from 0x%llX to handler at 0x%llX",
        TARGET_ADDRESS, (DWORD64)HookHandler);
    log(buffer);

    // apply the hook
    memcpy((LPVOID)TARGET_ADDRESS, jumpToHandler, 14);

    VirtualProtect((LPVOID)TARGET_ADDRESS, 14, oldProtect, &oldProtect);
    FlushInstructionCache(GetCurrentProcess(), (LPVOID)TARGET_ADDRESS, 14);

    log("Hook installed successfully!");

    // marker file for debugging
    FILE* marker;
    fopen_s(&marker, "addresses.txt", "w");
    if (marker)
    {
        fprintf(marker, "Hook installed at: %llu\n", GetTickCount64());
        fprintf(marker, "Target: 0x%llX\n", TARGET_ADDRESS);
        fprintf(marker, "Handler: 0x%llX\n", (DWORD64)HookHandler);
        fprintf(marker, "Trampoline: 0x%llX\n", trampolineAddress);
        fclose(marker);
    }

    return true;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);

        //  log all injection
        log("DLL injected into process");

        // show immediate feedback
        MessageBoxA(NULL,
            "Hook DLL Loaded!\n\n"
            "Check debug.txt for logs.\n"
            "The hook is now active.",
            "DLL INJECTED",
            MB_OK | MB_ICONINFORMATION);

        InstallHookWithLogging(); // install the actual trampoline
    }

    return TRUE;
}