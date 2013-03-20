// https://code.google.com/p/sin32boomerang/source/browse/trunk/SIN32/HotPatch.h

#define _s(s) (sizeof(s)/sizeof(*s))
//Alignment of all structures (if not explicitly written)
//must be 8 for x86 and 16 for the others

////////////////////////////////////////////////////////////
typedef enum _HOTPATCH_FIXUP_TYPE {
  HOTP_Fixup_None = 0,
  HOTP_Fixup_VA32 = 1,
  HOTP_Fixup_PC32 = 2,
  HOTP_Fixup_VA64 = 3,
  HOTP_Fixup_PC64 = 4 //?
} HOTPATCH_FIXUP_TYPE;

//sizeof(HOTPATCH_FIXUP_ENTRY) must be 2
typedef struct _HOTPATCH_FIXUP_ENTRY {
  WORD RvaOffset : 12;
  WORD /*HOTPATCH_FIXUP_TYPE*/ FixupType : 4;
} HOTPATCH_FIXUP_ENTRY, *PHOTPATCH_FIXUP_ENTRY;

typedef struct _HOTPATCH_FIXUP_REGION {
  unsigned int RvaHi : 20;
  unsigned int Count : 12;
  WORD /*HOTPATCH_FIXUP_ENTRY*/ Fixup[2]; //count always even
} HOTPATCH_FIXUP_REGION, *PHOTPATCH_FIXUP_REGION;

////////////////////////////////////////////////////////////
typedef enum _HOTPATCH_VALIDATION_OPTIONS {
  HOTP_Valid_Hook_Target = 1 //skip
} HOTPATCH_VALIDATION_OPTIONS;

typedef struct _HOTPATCH_VALIDATION {
  DWORD SourceRva;
  DWORD TargetRva;
  WORD ByteCount;
  WORD /*HOTPATCH_VALIDATION_OPTIONS*/ OptionFlags;
} HOTPATCH_VALIDATION, *PHOTPATCH_VALIDATION;

////////////////////////////////////////////////////////////
typedef enum _HOTPATCH_HOOK_TYPE {
  HOTP_Hook_None = 0,
  HOTP_Hook_VA32 = 1,
  HOTP_Hook_X86_JMP = 2,
  HOTP_Hook_PCREL32 = 3, //not yet implemented
  HOTP_Hook_X86_JMP2B = 4,
  HOTP_Hook_VA64 = 16,
  HOTP_Hook_IA64_BRL = 32,
  HOTP_Hook_IA64_BR = 33, //not yet implemented
  HOTP_Hook_AMD64_IND = 48,
  HOTP_Hook_AMD64_CNT = 49
} HOTPATCH_HOOK_TYPE;

typedef struct _HOTPATCH_HOOK {
  WORD /*HOTPATCH_HOOK_TYPE*/ HookType;
  WORD HookOptions; //0..5 - size of available space
  DWORD HookRva;
  DWORD HotpRva;
  DWORD ValidationRva;
} HOTPATCH_HOOK, *PHOTPATCH_HOOK;

////////////////////////////////////////////////////////////
typedef enum _HOTPATCH_MODULE_ID_METHOD {
  HOTP_ID_None = 0,
  HOTP_ID_PeHeaderHash1 = 1, //not yet supported
  HOTP_ID_PeHeaderHash2 = 2,
  HOTP_ID_PeChecksum = 3,
  HOTP_ID_PeDebugSignature = 16 //not yet supported
} HOTPATCH_MODULE_ID_METHOD;


#define DEBUG_SIGNATURE_HOTPATCH  0xD201
#define DEBUG_SIGNATURE_COLDPATCH 0xD202

typedef struct _HOTPATCH_DEBUG_SIGNATURE {
  WORD HotpatchVersion;
  WORD Signature;
} HOTPATCH_DEBUG_SIGNATURE, *PHOTPATCH_DEBUG_SIGNATURE;

typedef struct _HOTPATCH_DEBUG_DATA {
  ULONGLONG PEHashData;
  ULONGLONG ChecksumData;
} HOTPATCH_DEBUG_DATA, *PHOTPATCH_DEBUG_DATA;

////////////////////////////////////////////////////////////
#define HOTP_SECTION_NAME ".hotp1  "
#define HOTP_SECTION_NAMELL 0x20203170746F682ELL
#define HOTP_SECTION_MIN_SIZE 80

#define HOTP_SIGNATURE 0x31544F48 //'HOT1'
#define HOTP_VERSION_1 0x00010000

typedef struct _HOTPATCH_HEADER {
  DWORD Signature;
  DWORD Version;
  DWORD FixupRgnCount;
  DWORD FixupRgnRva;
  DWORD ValidationCount;
  DWORD ValidationArrayRva;
  DWORD HookCount;
  DWORD HookArrayRva;
  ULONGLONG OrigHotpBaseAddress;
  ULONGLONG OrigTargetBaseAddress;
  DWORD TargetNameRva;
  DWORD ModuleIdMethod;
  union {
    ULONGLONG Quad;
    GUID Guid;
    struct {
      GUID Guid;
      DWORD Age;
    } PdbSig;
    BYTE Hash128[16];
    BYTE Hash160[20];
  } TargetModuleIdValue;
} HOTPATCH_HEADER, *PHOTPATCH_HEADER;

////////////////////////////////////////////////////////////
#define SystemHotpatchInformation 0x45

//coldpatch sub-functions
#define HOTP_RENAME_FILES    0x10000000 //RenameInfo //pre-Vista
#define HOTP_UPDATE_SYSDLL   0x40000000 //no info requred
#define HOTP_UPDATE_KNOWNDLL 0x08000000 //AtomicSwap

//hotpatch sub-functions
#define HOTP_USE_MODULE      0x20000000 //KernelInfo or InjectionInfo when calling Nt/ZwSetSystemInformation
                                        //UserModeInfo when calling LdrHotPatchRoutine
#define HOTP_INJECT_THREAD   0x01000000 //InjectionInfo, HOTPATCH_USE_MODULE must be set //Vista
#define HOTP_KERNEL_MODULE   0x80000000 //KernelInfo, HOTPATCH_USE_MODULE must be set
//if none of the three flags above is set, CodeInfo is evaluated and applied directly

//hotpatch commands/states
#define HOTP_PATCH_APPLY     0x00000001 //command for KernelInfo or UserModeInfo (HOTPATCH_USE_MODULE is set)
                                        //0 - remove, 1 - apply the patch
#define HOTP_PATCH_STATUS    0x00000001 //command for CodeInfo: 0 - apply, 1 - remove the patch
                                        //status for CodeInfo: after CodeInfo ^ before CodeInfo ? success : failure 
#define HOTP_PATCH_FAILURE   0x00800000 //intermediate flag

typedef struct _HOTPATCH_HOOK_DESCRIPTOR {
  ULONG_PTR TargetAddress;
  LPVOID MappedAddress;
  DWORD CodeOffset;
  DWORD CodeSize;
  DWORD OrigCodeOffset;
  DWORD ValidationOffset;
  DWORD ValidationSize;
} HOTPATCH_HOOK_DESCRIPTOR, *PHOTPATCH_HOOK_DESCRIPTOR;

typedef struct _IO_STATUS_BLOCK {
  union {
    LONG Status;
    PVOID Pointer;
  };
  ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef struct _FILE_RENAME_INFORMATION {
  BOOLEAN ReplaceIfExists;
  HANDLE RootDirectory;
  ULONG FileNameLength;
  WCHAR FileName[1];
} FILE_RENAME_INFORMATION, *PFILE_RENAME_INFORMATION;

typedef struct _SYSTEM_HOTPATCH_CODE_INFORMATION {
  DWORD Flags;
  DWORD InfoSize;
  union {
    struct {
      DWORD DescriptorsCount;
      HOTPATCH_HOOK_DESCRIPTOR CodeDescriptors[1];
    } CodeInfo;

    struct {
      WORD NameOffset;
      WORD NameLegth;
    } KernelInfo;

    struct {
      WORD NameOffset;
      WORD NameLegth;
      WORD TargetNameOffset;
      WORD TargetNameLegth;
      BOOLEAN PatchingFinished;
    } UserModeInfo;

    struct {
      WORD NameOffset;
      WORD NameLegth;
      WORD TargetNameOffset;
      WORD TargetNameLegth;
      BOOLEAN PatchingFinished;
      DWORD ReturnCode;
      HANDLE TargetProcess;
    } InjectionInfo;

    struct {
      HANDLE FileHandle1;
      PIO_STATUS_BLOCK IoStatusBlock1;
      PVOID /*PFILE_RENAME_INFORMATION*/ RenameInformation1;
      DWORD RenameInformationLength1;
      HANDLE FileHandle2;
      PIO_STATUS_BLOCK IoStatusBlock2;
      PVOID /*PFILE_RENAME_INFORMATION*/ RenameInformation2;
      DWORD RenameInformationLength2;
    } RenameInfo;
  
    struct {
      HANDLE ParentDirectory;
      HANDLE ObjectHandle1;
      HANDLE ObjectHandle2;
    } AtomicSwap;
  };
} SYSTEM_HOTPATCH_CODE_INFORMATION, *PSYSTEM_HOTPATCH_CODE_INFORMATION;



#define PATCHFLAG_COLDPATCH_VALID 0x00010000

typedef struct _RTL_PATCH_HEADER {
  LIST_ENTRY PatchList;
  HMODULE PatchImageBase;
  struct _RTL_PATCH_HEADER * NextPatch;
  ULONG PatchFlags;
  LONG PatchRefCount;
  PHOTPATCH_HEADER HotpatchHeader;
  UNICODE_STRING TargetDllName;
  HMODULE TargetDllBase;
  PLDR_DATA_TABLE_ENTRY TargetLdrDataTableEntry;
  PLDR_DATA_TABLE_ENTRY PatchLdrDataTableEntry;
  PSYSTEM_HOTPATCH_CODE_INFORMATION CodeInfo;
} RTL_PATCH_HEADER, *PRTL_PATCH_HEADER;



const HOTPATCH_FIXUP_REGION FixupRgns[] = {
  {0, 0, {0, 0}}
};
const BYTE nopPadding[] = {0x90, 0x90, 0x90, 0x90, 0x90}
const BYTE int3Padding[] = {0xCC, 0xCC, 0xCC, 0xCC, 0xCC};
const BYTE HotPatchBytes[] = {0x8B, 0xFF};

HOTPATCH_VALIDATION Validations[] = {
  {0, 0x106B, 5, HOTP_Valid_Hook_Target},//target rva of either nopPadding or int3Padding..
  {0, 0x1070, 2, HOTP_Valid_Hook_Target}//target rva for mov edi,edi..
};

HOTPATCH_HOOK Hooks[] = {
  {HOTP_Hook_X86_JMP,   5, 0x106B, +0, 0},
  {HOTP_Hook_X86_JMP2B, 2, 0x1070, -7, 0}
};
#pragma data_seg(".hotp1  ")
HOTPATCH_HEADER HotPatch = {
  HOTP_SIGNATURE,
  HOTP_VERSION_1,
  _s(FixupRgns),
  0,
  _s(Validations),
  0,
  _s(Hooks),
  0,
  0x33330000,
  0x22220000,
  0,
  HOTP_ID_None
};
#pragma data_seg()
#define TARGET_NAME "ntdll.dll"

ULONG_PTR SourceBase = hDll;
HotPatch.FixupRgnRva = (DWORD)((ULONG_PTR)FixupRgns - SourceBase);
HotPatch.ValidationArrayRva = (DWORD)((ULONG_PTR)Validations - SourceBase);
HotPatch.HookArrayRva = (DWORD)((ULONG_PTR)Hooks - SourceBase);
HotPatch.TargetNameRva = (DWORD)((ULONG_PTR)TARGET_NAME - SourceBase);

Validations[0].SourceRva = (DWORD)((ULONG_PTR)int3Padding - SourceBase);
Validations[1].SourceRva = (DWORD)((ULONG_PTR)HotPatchBytes - SourceBase);

Hooks[0].HotpRva = (DWORD)((ULONG_PTR)NewDivide -SourceBase);
Hooks[0].ValidationRva = (DWORD)((ULONG_PTR)&Validations[0] -SourceBase);
Hooks[1].ValidationRva = (DWORD)((ULONG_PTR)&Validations[1] -SourceBase);