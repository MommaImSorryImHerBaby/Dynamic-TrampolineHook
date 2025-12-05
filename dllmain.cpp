// -- author: DADDY --
// -- trampoline hook for ASLR disabled binaries --
#define _CRT_SECURE_NO_WARNINGS
// precompiled headers
#include "pch.h"

#include <Windows.h>
#include <stdio.h>

// static address 
const DWORD64 TARGET_ADDRESS = 0x0000000140015420;

BYTE originalBytes[14];
DWORD64 trampolineAddress = 0;
static int hookCallCount = 0;

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

// func type for our trampoline
typedef void(__fastcall* TrampolineFunc)(void* thisptr);
// pointer to trampoline function
TrampolineFunc trampolineFunction = nullptr;


// the actual hooker 
void __fastcall Hooked_GameRun (void* thisptr)
{ // increment the call count for the trampoline
    hookCallCount++;
    // check the call count
    if (hookCallCount == 1)
    {
        log("Game::run(); FIRST execution intercepted!");
        // just beep to imply success
        MessageBeep(MB_OK);
    }

    else if (hookCallCount % 60 == 0)
    {
        char countMsg[100];
        sprintf_s(countMsg, "Game::run(); execution #%d", hookCallCount);
        log(countMsg);
    }

    if (trampolineFunction)
    {
        trampolineFunction(thisptr);
    }

    else
    {
        log("ERROR: Trampoline function is NULL!");
    }
}

bool Trampoline()
{
    log("-- starting hook installation --");
    log("Target address: 0x140015420");

    // allocate trampoline
    trampolineAddress = (DWORD64)VirtualAlloc(
        NULL, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!trampolineAddress)
    {
        log("ERROR: Failed to allocate trampoline");
        return false;
    }
    // debug msg
    char trampMsg[100];
    sprintf_s(trampMsg, "Trampoline allocated at: 0x%llX", trampolineAddress);
    log(trampMsg);

    DWORD oldProtect;
    if (!VirtualProtect((LPVOID)TARGET_ADDRESS, 14, PAGE_EXECUTE_READWRITE, &oldProtect))
    {
        log("ERROR: VirtualProtect failed");
        return false;
    }

    // save og bytes
    memcpy(originalBytes, (LPVOID)TARGET_ADDRESS, 14);

    // log what we found
    char bytesMsg[256];
    sprintf_s(bytesMsg, "Original bytes: ");
    for (int i = 0; i < 14; i++) {
        char byteStr[4];
        sprintf_s(byteStr, "%02X ", originalBytes[i]);
        strcat_s(bytesMsg, byteStr);
    }
    log(bytesMsg);

    // copy stolen bytes to trampoline
    memcpy((LPVOID)trampolineAddress, originalBytes, 14);
    log("Original bytes copied to trampoline");

    // add jump back to original+14
    BYTE jumpBack[14] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 };
    *(DWORD64*)&jumpBack[6] = TARGET_ADDRESS + 14;
    memcpy((LPVOID)(trampolineAddress + 14), jumpBack, 14);
    log("Jump back from trampoline installed");

    // Set up trampoline function pointer
    trampolineFunction = (TrampolineFunc)trampolineAddress;

    // JMP to our handler
    BYTE jumpToHandler[14] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 };
    *(DWORD64*)&jumpToHandler[6] = (DWORD64)Hooked_GameRun;

    char buffer[256];
    sprintf_s(buffer, "Jumping from 0x%llX to handler at 0x%llX",
        TARGET_ADDRESS, (DWORD64)Hooked_GameRun);
    log(buffer);

    // apply the hook
    memcpy((LPVOID)TARGET_ADDRESS, jumpToHandler, 14);
    // the hook automatically trampolines back if theres nothing holding the game_loop back
    VirtualProtect((LPVOID)TARGET_ADDRESS, 14, oldProtect, &oldProtect);
    FlushInstructionCache(GetCurrentProcess(), (LPVOID)TARGET_ADDRESS, 14);

    log("Hook installed successfully!"); 

    // log all addresses
    sprintf_s(buffer, "Target Address: 0x%llX", TARGET_ADDRESS);
    log(buffer);
    sprintf_s(buffer, "Handler Address: 0x%llX", (DWORD64)Hooked_GameRun);
    log(buffer);
    sprintf_s(buffer, "Trampoline Address: 0x%llX", trampolineAddress);
    log(buffer);

    return true;
}


// entry point 
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);

        // log("DLL injected into process");

        // show immediate feedback
        MessageBoxA(NULL,
            "Hook DLL Loaded!\n\n"
            "Check debug.txt for logs.\n"
            "The hook is now active.",
            "DLL INJECTED",
            MB_OK | MB_ICONINFORMATION);

        Trampoline(); // LOL!
    }

    return TRUE;
}
