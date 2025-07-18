
void FUN_100b79e4(void)

{
  char in_AL;
  uint unaff_EBX;
  int unaff_EBP;
  void *unaff_ESI;
  uint unaff_EDI;
  
  if (in_AL == '\0') {
    __ArrayUnwind(unaff_ESI,unaff_EBX,unaff_EDI,*(_func_void_void_ptr **)(unaff_EBP + 0x14));
  }
  return;
}


void FUN_100b79e4(void)

{
  char in_AL;
  uint unaff_EBX;
  int unaff_EBP;
  void *unaff_ESI;
  uint unaff_EDI;
  
  if (in_AL == '\0') {
    __ArrayUnwind(unaff_ESI,unaff_EBX,unaff_EDI,*(_func_void_void_ptr **)(unaff_EBP + 0x14));
  }
  return;
}


void FUN_100b79e4(void)

{
  char in_AL;
  uint unaff_EBX;
  int unaff_EBP;
  void *unaff_ESI;
  uint unaff_EDI;
  
  if (in_AL == '\0') {
    __ArrayUnwind(unaff_ESI,unaff_EBX,unaff_EDI,*(_func_void_void_ptr **)(unaff_EBP + 0x14));
  }
  return;
}


void FUN_100b79e4(void)

{
  char in_AL;
  uint unaff_EBX;
  int unaff_EBP;
  void *unaff_ESI;
  uint unaff_EDI;
  
  if (in_AL == '\0') {
    __ArrayUnwind(unaff_ESI,unaff_EBX,unaff_EDI,*(_func_void_void_ptr **)(unaff_EBP + 0x14));
  }
  return;
}


void FUN_100b79e4(void)

{
  char in_AL;
  uint unaff_EBX;
  int unaff_EBP;
  void *unaff_ESI;
  uint unaff_EDI;
  
  if (in_AL == '\0') {
    __ArrayUnwind(unaff_ESI,unaff_EBX,unaff_EDI,*(_func_void_void_ptr **)(unaff_EBP + 0x14));
  }
  return;
}


void FUN_100b79e4(void)

{
  char in_AL;
  uint unaff_EBX;
  int unaff_EBP;
  void *unaff_ESI;
  uint unaff_EDI;
  
  if (in_AL == '\0') {
    __ArrayUnwind(unaff_ESI,unaff_EBX,unaff_EDI,*(_func_void_void_ptr **)(unaff_EBP + 0x14));
  }
  return;
}


void FUN_100b79e4(void)

{
  char in_AL;
  uint unaff_EBX;
  int unaff_EBP;
  void *unaff_ESI;
  uint unaff_EDI;
  
  if (in_AL == '\0') {
    __ArrayUnwind(unaff_ESI,unaff_EBX,unaff_EDI,*(_func_void_void_ptr **)(unaff_EBP + 0x14));
  }
  return;
}


void FUN_100b79e4(void)

{
  char in_AL;
  uint unaff_EBX;
  int unaff_EBP;
  void *unaff_ESI;
  uint unaff_EDI;
  
  if (in_AL == '\0') {
    __ArrayUnwind(unaff_ESI,unaff_EBX,unaff_EDI,*(_func_void_void_ptr **)(unaff_EBP + 0x14));
  }
  return;
}
/*
                             s_?CreateAO_SourceProtectionInstan_100ffe56     XREF[1]:     100fd148(*)  
        100ffe56 3f 43 72        ds         "?CreateAO_SourceProtectionInstance@@YAJPAPAUI
                 65 61 74 
                 65 41 4f 

*/
                 
/* WARNING: Function: __alloca_probe replaced with injection: alloca_probe */
/* public: virtual long __stdcall AO_Controller::get_SourceProtection(struct IDispatch * *) */

/*long AO_Controller::get_SourceProtection(IDispatch **param_1)*/

/* long __cdecl CreateAO_SourceProtectionInstance(struct IDispatch * *) */

long __cdecl CreateAO_SourceProtectionInstance(IDispatch **param_1)

{
  long lVar1;
  int *local_8;
  
                    /* 0x2be30  114  ?CreateAO_SourceProtectionInstance@@YAJPAPAUIDispatch@@@Z */
  lVar1 = FUN_1002be70(&local_8);
  if (-1 < lVar1) {
    (**(code **)(*local_8 + 4))(local_8);
    lVar1 = (**(code **)*local_8)(local_8,&DAT_100e1360,param_1);
    (**(code **)(*local_8 + 8))(local_8);
  }
  return lVar1;
}


{
  IDispatch *This;
  long lVar1;
  AFX_MODULE_STATE *pAVar2;
  ulong uVar3;
  IDispatch **in_stack_00000008;
  uint uStack_1038;
  AFX_MAINTAIN_STATE2 local_20 [8];
  ulong local_18;
  undefined1 *local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    /* 0x1cfd0  433  ?get_SourceProtection@AO_Controller@@UAGJPAPAUIDispatch@@@Z */
  local_8 = 0xffffffff;
  puStack_c = &LAB_100bcae8;
  local_10 = ExceptionList;
  local_18 = 0x1001cfec;
  uStack_1038 = DAT_1010c8d4 ^ (uint)&stack0xfffffffc;
  local_14 = (undefined1 *)&uStack_1038;
  ExceptionList = &local_10;
  if (in_stack_00000008 == (IDispatch **)0x0) {
    local_14 = (undefined1 *)&uStack_1038;
    lVar1 = FUN_100322e0((IID *)&DAT_100cdfd0,0x80004003,0);
    ExceptionList = local_10;
    return lVar1;
  }
  *in_stack_00000008 = (IDispatch *)0x0;
  if (AO_LogixServices::ms_ServerFaulted != false) {
    local_14 = (undefined1 *)&uStack_1038;
    lVar1 = FUN_100322e0((IID *)&DAT_100cdfd0,0x80043a12,0);
    ExceptionList = local_10;
    return lVar1;
  }
  pAVar2 = (AFX_MODULE_STATE *)FUN_100b73ce();
  AFX_MAINTAIN_STATE2::AFX_MAINTAIN_STATE2(local_20,pAVar2);
  local_18 = 0x8000ffff;
  local_8 = 1;
  This = param_1[0x2e];
  if (This == (IDispatch *)0x0) {
    uVar3 = CreateAO_SourceProtectionInstance(in_stack_00000008);
    local_18 = uVar3;
    FUN_1000b1c0(param_1 + 0x2e,(int *)*in_stack_00000008);
  }
  else {
    uVar3 = (*This->lpVtbl->QueryInterface)(This,(IID *)&DAT_100e1360,in_stack_00000008);
    uVar3 = FUN_100322e0((IID *)&DAT_100cdfd0,uVar3,0);
    local_8 = 0;
    local_18 = uVar3;
  }
  lVar1 = FUN_100322e0((IID *)&DAT_100cdfd0,uVar3,0);
  local_8 = 0xffffffff;
  AFX_MAINTAIN_STATE2::~AFX_MAINTAIN_STATE2(local_20);
  ExceptionList = local_10;
  return lVar1;
}



/* public: __thiscall AO_LogixServices::~AO_LogixServices(void) */

void __thiscall AO_LogixServices::~AO_LogixServices(AO_LogixServices *this)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 uStack_8;
  
                    /* 0x3e40  45  ??1AO_LogixServices@@QAE@XZ */
  uStack_8 = 0xffffffff;
  puStack_c = &LAB_100c08b0;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  LOCK();
  ms_ObjectCount = ms_ObjectCount + -1;
  UNLOCK();
  VariantClear((VARIANTARG *)(this + 0x10));
  *(undefined4 *)(this + 0x10) = 0;
  *(undefined4 *)(this + 0x14) = 0;
  *(undefined4 *)(this + 0x18) = 0;
  *(undefined4 *)(this + 0x1c) = 0;
  ExceptionList = local_10;
  return;
}

/**/
                             **************************************************************
                             * public: __thiscall AO_LogixServices::~AO_LogixServices(... *
                             **************************************************************
                             void __thiscall ~AO_LogixServices(AO_LogixServices * this)
                               assume FS_OFFSET = 0xffdff000
             void              <VOID>         <RETURN>
             AO_LogixServic    ECX:4 (auto)   this
             undefined4        Stack[-0x10]:4 local_10                                XREF[2]:     10003e5a(*), 
                                                                                                   10003e81(R)  
                             0x3e40  45  ??1AO_LogixServices@@QAE@XZ
                             Ordinal_45                                      XREF[9]:     Entry Point(*), 
                             ??1AO_LogixServices@@QAE@XZ                                  FUN_1002ca40:1002ca6d(c), 
                             AO_LogixServices::~AO_LogixServices                          FUN_1002cf60:1002cfbc(c), 
                                                                                          Unwind@100b9310:100b9313(c), 
                                                                                          Unwind@100b9590:100b9593(c), 
                                                                                          Unwind@100beb20:100beb23(c), 
                                                                                          Unwind@100bebd0:100bebd3(c), 
                                                                                          Unwind@100bed9b:100bed9e(c), 
                                                                                          100fc918(*)  
        10003e40 55              PUSH       EBP
        10003e41 8b ec           MOV        EBP,ESP
        10003e43 6a ff           PUSH       -0x1
        10003e45 68 b0 08        PUSH       LAB_100c08b0
                 0c 10
        10003e4a 64 a1 00        MOV        EAX,FS:[0x0]=>ExceptionList                      = 00000000
                 00 00 00
        10003e50 50              PUSH       EAX
        10003e51 56              PUSH       ESI
        10003e52 a1 d4 c8        MOV        EAX,[DAT_1010c8d4]                               = BB40E64Eh
                 10 10
        10003e57 33 c5           XOR        EAX,EBP
        10003e59 50              PUSH       EAX
        10003e5a 8d 45 f4        LEA        EAX=>local_10,[EBP + -0xc]
        10003e5d 64 a3 00        MOV        FS:[0x0]=>ExceptionList,EAX                      = 00000000
                 00 00 00
        10003e63 f0 ff 0d        DEC.LOCK   dword ptr [AO_LogixServices::ms_ObjectCount]
                 b8 1f 11 10
        10003e6a 8d 71 10        LEA        ESI,[this + 0x10]
        10003e6d 56              PUSH       ESI                                              VARIANTARG * pvarg for VariantCl
        10003e6e ff 15 88        CALL       dword ptr [->OLEAUT32.DLL::VariantClear]         = 80000009
                 c1 0c 10
        10003e74 33 c0           XOR        EAX,EAX
        10003e76 89 06           MOV        dword ptr [ESI],EAX
        10003e78 89 46 04        MOV        dword ptr [ESI + 0x4],EAX
        10003e7b 89 46 08        MOV        dword ptr [ESI + 0x8],EAX
        10003e7e 89 46 0c        MOV        dword ptr [ESI + 0xc],EAX
        10003e81 8b 4d f4        MOV        this,dword ptr [EBP + local_10]
        10003e84 64 89 0d        MOV        dword ptr FS:[0x0]=>ExceptionList,this           = 00000000
                 00 00 00 00
        10003e8b 59              POP        this
        10003e8c 5e              POP        ESI
        10003e8d 8b e5           MOV        ESP,EBP
        10003e8f 5d              POP        EBP
        10003e90 c3              RET
        10003e91 cc cc cc        align      align(15)
                 cc cc cc 
                 cc cc cc 

*/


/* WARNING: Function: __alloca_probe replaced with injection: alloca_probe */
/* public: virtual long __stdcall AO_Controller::get_SourceProtection(struct IDispatch * *) */

long AO_Controller::get_SourceProtection(IDispatch **param_1)

{
  IDispatch *This;
  long lVar1;
  AFX_MODULE_STATE *pAVar2;
  ulong uVar3;
  IDispatch **in_stack_00000008;
  uint uStack_1038;
  AFX_MAINTAIN_STATE2 local_20 [8];
  ulong local_18;
  undefined1 *local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    /* 0x1cfd0  433  ?get_SourceProtection@AO_Controller@@UAGJPAPAUIDispatch@@@Z */
  local_8 = 0xffffffff;
  puStack_c = &LAB_100bcae8;
  local_10 = ExceptionList;
  local_18 = 0x1001cfec;
  uStack_1038 = DAT_1010c8d4 ^ (uint)&stack0xfffffffc;
  local_14 = (undefined1 *)&uStack_1038;
  ExceptionList = &local_10;
  if (in_stack_00000008 == (IDispatch **)0x0) {
    local_14 = (undefined1 *)&uStack_1038;
    lVar1 = FUN_100322e0((IID *)&DAT_100cdfd0,0x80004003,0);
    ExceptionList = local_10;
    return lVar1;
  }
  *in_stack_00000008 = (IDispatch *)0x0;
  if (AO_LogixServices::ms_ServerFaulted != false) {
    local_14 = (undefined1 *)&uStack_1038;
    lVar1 = FUN_100322e0((IID *)&DAT_100cdfd0,0x80043a12,0);
    ExceptionList = local_10;
    return lVar1;
  }
  pAVar2 = (AFX_MODULE_STATE *)FUN_100b73ce();
  AFX_MAINTAIN_STATE2::AFX_MAINTAIN_STATE2(local_20,pAVar2);
  local_18 = 0x8000ffff;
  local_8 = 1;
  This = param_1[0x2e];
  if (This == (IDispatch *)0x0) {
    uVar3 = CreateAO_SourceProtectionInstance(in_stack_00000008);
    local_18 = uVar3;
    FUN_1000b1c0(param_1 + 0x2e,(int *)*in_stack_00000008);
  }
  else {
    uVar3 = (*This->lpVtbl->QueryInterface)(This,(IID *)&DAT_100e1360,in_stack_00000008);
    uVar3 = FUN_100322e0((IID *)&DAT_100cdfd0,uVar3,0);
    local_8 = 0;
    local_18 = uVar3;
  }
  lVar1 = FUN_100322e0((IID *)&DAT_100cdfd0,uVar3,0);
  local_8 = 0xffffffff;
  AFX_MAINTAIN_STATE2::~AFX_MAINTAIN_STATE2(local_20);
  ExceptionList = local_10;
  return lVar1;
}


/* long __cdecl CreateAO_SourceProtectionInstance(struct IDispatch * *) */

long __cdecl CreateAO_SourceProtectionInstance(IDispatch **param_1)

{
  long lVar1;
  int *local_8;
  
                    /* 0x2be30  114  ?CreateAO_SourceProtectionInstance@@YAJPAPAUIDispatch@@@Z */
  lVar1 = FUN_1002be70(&local_8);
  if (-1 < lVar1) {
    (**(code **)(*local_8 + 4))(local_8);
    lVar1 = (**(code **)*local_8)(local_8,&DAT_100e1360,param_1);
    (**(code **)(*local_8 + 8))(local_8);
  }
  return lVar1;
}

/*
                             **************************************************************
                             * class RxExternalPasswordSourceProtectionProvider RTTI T... *
                             **************************************************************
                             RxExternalPasswordSourceProtectionProvider::RT  XREF[2]:     100e43f8(*), 100e441c(*)  
        1010eecc 44 13 0e        TypeDesc
                 10 00 00 
                 00 00
                             Zero-length Component: char[0] RxExternalPasswordSourceProtec
        1010eed4 2e 3f 41        char[52]   ".?AVRxExternalPasswordSourceProtectionProvide
                 56 52 78 
                 45 78 74 
           1010eed4 [0]            '.', '?', 'A', 'V',
           1010eed8 [4]            'R', 'x', 'E', 'x',
           1010eedc [8]            't', 'e', 'r', 'n',
           1010eee0 [12]           'a', 'l', 'P', 'a',
           1010eee4 [16]           's', 's', 'w', 'o',
           1010eee8 [20]           'r', 'd', 'S', 'o',
           1010eeec [24]           'u', 'r', 'c', 'e',
           1010eef0 [28]           'P', 'r', 'o', 't',
           1010eef4 [32]           'e', 'c', 't', 'i',
           1010eef8 [36]           'o', 'n', 'P', 'r',
           1010eefc [40]           'o', 'v', 'i', 'd',
           1010ef00 [44]           'e', 'r', '@', '@',
           1010ef04 [48]           00h, 00h, 00h, 00h
                             **************************************************************
                             * class RxIPasswordSourceProtectionProvider RTTI Type Des... *
                             **************************************************************
                             RxIPasswordSourceProtectionProvider::RTTI_Type  XREF[1]:     100e4438(*)  
        1010ef08 44 13 0e        TypeDesc
                 10 00 00 
                 00 00
                             Zero-length Component: char[0] RxIPasswordSourceProtectionPro
        1010ef10 2e 3f 41        char[44]   ".?AVRxIPasswordSourceProtectionProvider@@"
                 56 52 78 
                 49 50 61 
           1010ef10 [0]            '.', '?', 'A', 'V',
           1010ef14 [4]            'R', 'x', 'I', 'P',
           1010ef18 [8]            'a', 's', 's', 'w',
           1010ef1c [12]           'o', 'r', 'd', 'S',
           1010ef20 [16]           'o', 'u', 'r', 'c',
           1010ef24 [20]           'e', 'P', 'r', 'o',
           1010ef28 [24]           't', 'e', 'c', 't',
           1010ef2c [28]           'i', 'o', 'n', 'P',
           1010ef30 [32]           'r', 'o', 'v', 'i',
           1010ef34 [36]           'd', 'e', 'r', '@',
           1010ef38 [40]           '@', 00h, 00h, 00h
                             **************************************************************
                             * class AO_SourceProtection RTTI Type Descriptor             *
                             **************************************************************
                             AO_SourceProtection::RTTI_Type_Descriptor       XREF[1]:     100e44a8(*)  
        1010ef3c 44 13 0e        TypeDesc
                 10 00 00 
                 00 00
           1010ef3c 44 13 0e 10     void *    type_info::vftable      pVFTable                          XREF[1]:     100e44a8(*)  
           1010ef40 00 00 00 00     void *    00000000                spare
                             Zero-length Component: char[0] AO_SourceProtection::RTTI_Type
        1010ef44 2e 3f 41        char[28]   ".?AVAO_SourceProtection@@"                      TypeDescriptor.name
                 56 41 4f 
                 5f 53 6f 
                             **************************************************************
                             * class ATL::IDispatchImpl<struct ISourceProtection,&stru... *
                             **************************************************************
                             ATL::IDispatchImpl<>::RTTI_Type_Descriptor      XREF[1]:     100e44c4(*)  
        1010ef60 44 13 0e        TypeDesc
                 10 00 00 
                 00 00
                             Zero-length Component: char[0] ATL::IDispatchImpl<struct_ISou
        1010ef68 2e 3f 41        char[156]  ".?AV?$IDispatchImpl@UISourceProtection@@$1?DI   TypeDescriptor.name
                 56 3f 24 
                 49 44 69 
        1010f004 00              ??         00h
        1010f005 00              ??         00h
        1010f006 00              ??         00h
        1010f007 00              ??         00h

                             **************************************************************
                             * class AO_SourceProtection RTTI Type Descriptor             *
                             **************************************************************
                             AO_SourceProtection::RTTI_Type_Descriptor       XREF[1]:     100e44a8(*)  
        1010ef3c 44 13 0e        TypeDesc
                 10 00 00 
                 00 00
           1010ef3c 44 13 0e 10     void *    type_info::vftable      pVFTable                          XREF[1]:     100e44a8(*)  
           1010ef40 00 00 00 00     void *    00000000                spare
                             Zero-length Component: char[0] AO_SourceProtection::RTTI_Type
        1010ef44 2e 3f 41        char[28]   ".?AVAO_SourceProtection@@"
                 56 41 4f 
                 5f 53 6f 
           1010ef44 [0]            '.', '?', 'A', 'V',
           1010ef48 [4]            'A', 'O', '_', 'S',
           1010ef4c [8]            'o', 'u', 'r', 'c',
           1010ef50 [12]           'e', 'P', 'r', 'o',
           1010ef54 [16]           't', 'e', 'c', 't',
           1010ef58 [20]           'i', 'o', 'n', '@',
           1010ef5c [24]           '@', 00h, 00h, 00h
                             Zero-length Component: char[0] ATL::IDispatchImpl<struct_ISou
        1010ef68 2e 3f 41        char[156]  ".?AV?$IDispatchImpl@UISourceProtection@@$1?DI
                 56 3f 24 
                 49 44 69 
           1010ef68 [0]            '.', '?', 'A', 'V',
           1010ef6c [4]            '?', '$', 'I', 'D',
           1010ef70 [8]            'i', 's', 'p', 'a',
           1010ef74 [12]           't', 'c', 'h', 'I',
           1010ef78 [16]           'm', 'p', 'l', '@',
           1010ef7c [20]           'U', 'I', 'S', 'o',
           1010ef80 [24]           'u', 'r', 'c', 'e',
           1010ef84 [28]           'P', 'r', 'o', 't',
           1010ef88 [32]           'e', 'c', 't', 'i',
           1010ef8c [36]           'o', 'n', '@', '@',
           1010ef90 [40]           '$', '1', '?', 'D',
           1010ef94 [44]           'I', 'I', 'D', '_',
           1010ef98 [48]           'I', 'S', 'o', 'u',
           1010ef9c [52]           'r', 'c', 'e', 'P',
           1010efa0 [56]           'r', 'o', 't', 'e',
           1010efa4 [60]           'c', 't', 'i', 'o',
           1010efa8 [64]           'n', '@', '@', '3',
           1010efac [68]           'U', '_', 'G', 'U',
           1010efb0 [72]           'I', 'D', '@', '@',
           1010efb4 [76]           'B', '$', '1', '?',
           1010efb8 [80]           'L', 'I', 'B', 'I',
           1010efbc [84]           'D', '_', 'R', 'S',
           1010efc0 [88]           'L', 'o', 'g', 'i',
           1010efc4 [92]           'x', '5', '0', '0',
           1010efc8 [96]           '0', 'S', 'e', 'r',
           1010efcc [100]          'v', 'i', 'c', 'e',
           1010efd0 [104]          's', 'L', 'i', 'b',
           1010efd4 [108]          '@', '@', '3', 'U',
           1010efd8 [112]          '3', '@', 'B', '$',
           1010efdc [116]          '0', 'B', 'D', '@',
           1010efe0 [120]          '$', '0', 'A', '@',
           1010efe4 [124]          'V', 'C', 'C', 'o',
           1010efe8 [128]          'm', 'T', 'y', 'p',
           1010efec [132]          'e', 'I', 'n', 'f',
           1010eff0 [136]          'o', 'H', 'o', 'l',
           1010eff4 [140]          'd', 'e', 'r', '@',
           1010eff8 [144]          'A', 'T', 'L', '@',
           1010effc [148]          '@', '@', 'A', 'T',
           1010f000 [152]          'L', '@', '@', 00h
        1010f004 00              ??         00h
        1010f005 00              ??         00h
        1010f006 00              ??         00h
        1010f007 00              ??         00h


*/


undefined4 * __fastcall FUN_1002bc90(undefined4 *param_1)

{
  uint uVar1;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_100be9d3;
  local_10 = ExceptionList;
  uVar1 = DAT_1010c8d4 ^ (uint)&stack0xfffffffc;
  ExceptionList = &local_10;
  *param_1 = ISourceProtection::vftable;
  param_1[2] = 0;
  param_1[3] = 0;
  local_8 = 1;
  *param_1 = ATL::CComObject<>::vftable;
  param_1[1] = ATL::CComObject<>::vftable;
  (**(code **)(*DAT_10111fb0 + 4))(uVar1);
  ExceptionList = local_10;
  return param_1;
}



/* WARNING: Function: __alloca_probe replaced with injection: alloca_probe */
/* public: virtual long __stdcall AO_Controller::ExportL5KToFile(unsigned short *,short) */

long AO_Controller::ExportL5KToFile(ushort *param_1,short param_2)

{
  char cVar1;
  long lVar2;
  AFX_MODULE_STATE *pAVar3;
  int iVar4;
  undefined2 in_stack_0000000a;
  short in_stack_0000000c;
  uint uStack_10c4;
  undefined4 local_ac [30];
  CFile local_34 [20];
  AFX_MAINTAIN_STATE2 local_20 [8];
  ulong local_18;
  undefined1 *local_14;
  void *local_10;
  undefined1 *puStack_c;
  uint local_8;
  
                    /* 0xe9d0  153  ?ExportL5KToFile@AO_Controller@@UAGJPAGF@Z */
  local_8 = 0xffffffff;
  puStack_c = &LAB_100baf2b;
  local_10 = ExceptionList;
  local_18 = 0x1000e9ec;
  uStack_10c4 = DAT_1010c8d4 ^ (uint)&stack0xfffffffc;
  local_14 = (undefined1 *)&uStack_10c4;
  ExceptionList = &local_10;
  if (AO_LogixServices::ms_ServerFaulted) {
    local_14 = (undefined1 *)&uStack_10c4;
    lVar2 = FUN_100322e0((IID *)&DAT_100cdfd0,0x80043a12,0);
    ExceptionList = local_10;
    return lVar2;
  }
  pAVar3 = (AFX_MODULE_STATE *)FUN_100b73ce();
  AFX_MAINTAIN_STATE2::AFX_MAINTAIN_STATE2(local_20,pAVar3);
  local_8 = 0;
  if (*(int *)(param_1 + 0x38) == 0) {
    lVar2 = FUN_100322e0((IID *)&DAT_100cdfd0,0x80004003,0);
    goto LAB_1000ead3;
  }
  local_18 = 0x8000ffff;
  FUN_100316f0(local_ac,(int)param_1,(uint)(in_stack_0000000c == -1));
  local_8._1_3_ = (undefined3)(local_8 >> 8);
  local_8._0_1_ = 2;
  cVar1 = FUN_10016eb0();
  if (cVar1 == '\0') {
    CFile::CFile(local_34);
    local_8._0_1_ = 3;
    iVar4 = CFile::Open(local_34,_param_2,0x1001,(CFileException *)0x0);
    if (iVar4 != 0) {
      local_18 = Ordinal_32227(local_34,local_ac,1);
      if (local_18 == 1) {
        local_18 = Ordinal_17116();
      }
      CFile::Close(local_34);
      local_8 = CONCAT31(local_8._1_3_,2);
      CFile::~CFile(local_34);
      goto LAB_1000eaa9;
    }
    lVar2 = FUN_100322e0((IID *)&DAT_100cdfd0,0x80042024,0);
    local_8 = CONCAT31(local_8._1_3_,2);
    CFile::~CFile(local_34);
  }
  else {
    local_18 = ExportL5KToSPP((AO_Controller *)param_1,(ushort *)_param_2,in_stack_0000000c);
LAB_1000eaa9:
    local_8 = 1;
    lVar2 = FUN_100322e0((IID *)&DAT_100cdfd0,local_18,0);
  }
  local_8 = local_8 & 0xffffff00;
  FUN_10031830(local_ac);
LAB_1000ead3:
  local_8 = 0xffffffff;
  AFX_MAINTAIN_STATE2::~AFX_MAINTAIN_STATE2(local_20);
  ExceptionList = local_10;
  return lVar2;
}


/* WARNING: Function: __alloca_probe replaced with injection: alloca_probe */
/* public: virtual long __stdcall AO_Controller::ExportXMLToFile(long,unsigned short *,enum
   lgxExportOptions,short,unsigned short *,enum lgxExportStatus *) */

long AO_Controller::ExportXMLToFile
               (long param_1,ushort *param_2,lgxExportOptions param_3,short param_4,ushort *param_5,
               lgxExportStatus *param_6)

{
  char cVar1;
  long lVar2;
  AFX_MODULE_STATE *pAVar3;
  int iVar4;
  CStringT<> *extraout_ECX;
  uint uVar5;
  ushort in_stack_00000012;
  undefined4 *in_stack_0000001c;
  undefined1 auStack_1108 [12];
  wchar_t **ppwStack_10fc;
  ushort *puStack_10f8;
  ushort *puStack_10f4;
  lgxExportStatus *plStack_10f0;
  undefined4 uStack_10ec;
  lgxExportOptions lStack_10e8;
  undefined1 *puStack_10e4;
  CStringT<> *pCStack_10d8;
  uint uStack_10c8;
  undefined1 local_b0 [72];
  undefined4 local_68 [8];
  undefined4 local_48;
  undefined4 local_44;
  AFX_MAINTAIN_STATE2 local_40 [8];
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30;
  ulonglong local_2c;
  CStringT<> local_24 [4];
  CStringT<> local_20 [4];
  CStringT<> local_1c [4];
  int local_18;
  undefined1 *local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    /* 0xee00  155
                       ?ExportXMLToFile@AO_Controller@@UAGJJPAGW4lgxExportOptions@@F0PAW4lgxExportSt atus@@@Z
                        */
  local_8 = 0xffffffff;
  puStack_c = &LAB_100bb031;
  local_10 = ExceptionList;
  local_18 = 0x1000ee1c;
  uStack_10c8 = DAT_1010c8d4 ^ (uint)&stack0xfffffffc;
  local_14 = (undefined1 *)&uStack_10c8;
  ExceptionList = &local_10;
  if (in_stack_0000001c == (undefined4 *)0x0) {
    pCStack_10d8 = (CStringT<> *)0x1000ee4a;
    local_14 = (undefined1 *)&uStack_10c8;
    lVar2 = FUN_100322e0((IID *)&DAT_100cdfd0,0x80004003,0);
    ExceptionList = local_10;
    return lVar2;
  }
  *in_stack_0000001c = 2;
  if (AO_LogixServices::ms_ServerFaulted != false) {
    pCStack_10d8 = (CStringT<> *)0x1000ee84;
    local_14 = (undefined1 *)&uStack_10c8;
    lVar2 = FUN_100322e0((IID *)&DAT_100cdfd0,0x80043a12,0);
    ExceptionList = local_10;
    return lVar2;
  }
  pAVar3 = (AFX_MODULE_STATE *)FUN_100b73ce();
  AFX_MAINTAIN_STATE2::AFX_MAINTAIN_STATE2(local_40,pAVar3);
  local_18 = 0x8000ffff;
  local_8._0_1_ = 1;
  local_8._1_3_ = 0;
  if (param_2 == (ushort *)0x0) {
    param_2 = (ushort *)0xffffffff;
  }
  local_2c = TranslateExportOptions(_param_4);
  uVar5 = (uint)local_2c;
  if (*(char *)(param_1 + 0x8d) != '\0') {
    uVar5 = uVar5 | 0x400;
    local_2c = local_2c | 0x400;
  }
  cVar1 = FUN_10016eb0();
  if (cVar1 != '\0') {
    ATL::CStringT<>::CStringT<>(local_1c);
    local_8._0_1_ = 2;
    ATL::CStringT<>::CStringT<>(local_24);
    local_8._0_1_ = 3;
    ATL::CStringT<>::CStringT<>(local_20);
    local_8._0_1_ = 4;
    if ((in_stack_00000012 & 0x400) == 0) {
      pCStack_10d8 = local_1c;
      puStack_10e4 = (undefined1 *)param_3;
      puStack_10f8 = (ushort *)0x1000ef62;
      puStack_10f4 = param_2;
      FUN_1000a670(&plStack_10f0);
      puStack_10f4 = *(ushort **)(param_1 + 0x70);
      local_8._0_1_ = 4;
      puStack_10f8 = (ushort *)0x1000ef76;
      local_18 = Ordinal_1317();
    }
    else {
      local_18 = ExportXmlToStringForTrackedComponents
                           ((AO_Controller *)param_1,(CStringT<> *)local_20);
    }
    if (-1 < local_18) {
      pCStack_10d8 = (CStringT<> *)0x1000ef96;
      ATL::CStringT<>::CStringT<>((CStringT<> *)&stack0xffffef30,local_1c);
      local_8._0_1_ = 6;
      pCStack_10d8 = extraout_ECX;
      ATL::CStringT<>::CStringT<>((CStringT<> *)&pCStack_10d8,(wchar_t *)param_6);
      local_8._0_1_ = 4;
      local_18 = Ordinal_7947();
    }
    local_8._0_1_ = 3;
    ATL::CStringT<>::~CStringT<>(local_20);
    local_8._0_1_ = 2;
    ATL::CStringT<>::~CStringT<>(local_24);
    local_8 = CONCAT31(local_8._1_3_,1);
    ATL::CStringT<>::~CStringT<>(local_1c);
    local_8 = 0;
    lVar2 = FUN_1000f153();
    return lVar2;
  }
  if ((in_stack_00000012 & 0x400) == 0) {
    pCStack_10d8 = (CStringT<> *)0x0;
    lStack_10e8 = param_3;
    ppwStack_10fc = (wchar_t **)0x1000f11e;
    puStack_10f8 = param_2;
    puStack_10e4 = (undefined1 *)uVar5;
    FUN_1000a670(&puStack_10f4);
    puStack_10f8 = *(ushort **)(param_1 + 0x70);
    local_8 = CONCAT31(local_8._1_3_,1);
    ppwStack_10fc = (wchar_t **)0x1000f132;
    local_18 = Ordinal_1411();
    local_8 = 0;
    lVar2 = FUN_1000f153();
    return lVar2;
  }
  local_38 = 0;
  local_34 = 0;
  local_30 = 0;
  local_8._0_1_ = 8;
  pCStack_10d8 = (CStringT<> *)0x0;
  iVar4 = Ordinal_27425();
  if (-1 < iVar4) {
    local_48 = 0x90488e;
    local_44 = 0x100;
    local_2c = 0x1000090488e;
    Ordinal_12476();
    local_8._0_1_ = 9;
    puStack_10e4 = (undefined1 *)0x1000f072;
    FUN_1000a5f0(local_68,&local_38);
    local_8._0_1_ = 10;
    puStack_10e4 = local_b0;
    lStack_10e8 = 0;
    uStack_10ec = 0;
    plStack_10f0 = param_6;
    puStack_10f4 = (ushort *)0x100;
    puStack_10f8 = (ushort *)0x90488e;
    ppwStack_10fc = &param_3_100ce108;
    FUN_1000a5f0(auStack_1108,&local_38);
    local_8._0_1_ = 10;
    lVar2 = Ordinal_1411(*(undefined4 *)(param_1 + 0x70));
    local_8._0_1_ = 9;
    FUN_1000b040(local_68);
    local_8._0_1_ = 8;
    Ordinal_8878();
    local_8 = CONCAT31(local_8._1_3_,1);
    FUN_1000aba0(&local_38);
    local_8 = 0xffffffff;
    AFX_MAINTAIN_STATE2::~AFX_MAINTAIN_STATE2(local_40);
    ExceptionList = local_10;
    return lVar2;
  }
  local_8 = CONCAT31(local_8._1_3_,1);
  FUN_1000aba0(&local_38);
  local_8 = 0;
  lVar2 = FUN_1000f153();
  return lVar2;
}


/* WARNING: Function: __alloca_probe replaced with injection: alloca_probe */
/* public: virtual long __stdcall AO_Controller::ExportXMLToString(long,unsigned short *,enum
   lgxExportOptions,short,enum lgxExportStatus *,unsigned short * *) */

long AO_Controller::ExportXMLToString
               (long param_1,ushort *param_2,lgxExportOptions param_3,short param_4,
               lgxExportStatus *param_5,ushort **param_6)

{
  bool bVar1;
  AFX_MODULE_STATE *pAVar2;
  wchar_t *pwVar3;
  long lVar4;
  uint uVar5;
  ushort in_stack_00000012;
  undefined4 *in_stack_0000001c;
  undefined4 auStack_1068 [3];
  lgxExportOptions lStack_105c;
  uint uStack_1058;
  undefined4 uStack_1054;
  CStringT<> *pCStack_1050;
  ulong uVar6;
  uint uStack_1040;
  AFX_MAINTAIN_STATE2 local_28 [8];
  undefined8 local_20;
  int local_18;
  undefined1 *local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    /* 0xf200  156
                       ?ExportXMLToString@AO_Controller@@UAGJJPAGW4lgxExportOptions@@FPAW4lgxExportS tatus@@PAPAG@Z
                        */
  local_8 = 0xffffffff;
  puStack_c = &LAB_100bb069;
  local_10 = ExceptionList;
  local_18 = 0x1000f21c;
  uStack_1040 = DAT_1010c8d4 ^ (uint)&stack0xfffffffc;
  local_14 = (undefined1 *)&uStack_1040;
  ExceptionList = &local_10;
  if (param_6 != (ushort **)0x0) {
    *param_6 = (ushort *)0x2;
  }
  if ((in_stack_0000001c == (undefined4 *)0x0) ||
     (*in_stack_0000001c = 0, param_6 == (ushort **)0x0)) {
    uVar6 = 0x80004003;
  }
  else {
    *param_6 = (ushort *)0x2;
    if (AO_LogixServices::ms_ServerFaulted == false) {
      pAVar2 = (AFX_MODULE_STATE *)FUN_100b73ce();
      AFX_MAINTAIN_STATE2::AFX_MAINTAIN_STATE2(local_28,pAVar2);
      local_8 = 0;
      bVar1 = CheckIEViaStringForSPP((AO_Controller *)param_1);
      if (!bVar1) {
        pCStack_1050 = (CStringT<> *)0x1000f2a6;
        lVar4 = FUN_100322e0((IID *)&DAT_100cdfd0,0x80043a29,0);
        local_8 = 0xffffffff;
        AFX_MAINTAIN_STATE2::~AFX_MAINTAIN_STATE2(local_28);
        ExceptionList = local_10;
        return lVar4;
      }
      local_18 = 0x8000ffff;
      local_8._0_1_ = 1;
      local_20 = TranslateExportOptions(_param_4);
      uVar5 = (uint)local_20;
      if (*(char *)(param_1 + 0x8d) != '\0') {
        uVar5 = uVar5 | 0x400;
        local_20 = local_20 | 0x400;
      }
      ATL::CStringT<>::CStringT<>((CStringT<> *)&stack0x0000001c);
      local_8._0_1_ = 2;
      if ((in_stack_00000012 & 0x400) == 0) {
        uStack_1054 = local_20._4_4_;
        lStack_105c = param_3;
        uStack_1058 = uVar5;
        pCStack_1050 = (CStringT<> *)&stack0x0000001c;
        FUN_1000a670(auStack_1068);
        local_8._0_1_ = 2;
        local_18 = Ordinal_1317(*(undefined4 *)(param_1 + 0x70));
      }
      else {
        local_18 = ExportXmlToStringForTrackedComponents
                             ((AO_Controller *)param_1,(CStringT<> *)&stack0x0000001c);
      }
      if (-1 < local_18) {
        pwVar3 = ATL::CStringT<>::AllocSysString((CStringT<> *)&stack0x0000001c);
        *in_stack_0000001c = pwVar3;
      }
      local_8 = CONCAT31(local_8._1_3_,1);
      ATL::CStringT<>::~CStringT<>((CStringT<> *)&stack0x0000001c);
      local_8 = 0;
      lVar4 = FUN_1000f3ad();
      return lVar4;
    }
    uVar6 = 0x80043a12;
  }
  pCStack_1050 = (CStringT<> *)0x1000f418;
  local_14 = (undefined1 *)&uStack_1040;
  lVar4 = FUN_100322e0((IID *)&DAT_100cdfd0,uVar6,0);
  ExceptionList = local_10;
  return lVar4;
}


/* protected: long __thiscall AO_Controller::ExportXmlToStringForTrackedComponents(class
   ATL::CStringT<unsigned short,class StrTraitMFC_DLL<unsigned short,class ATL::ChTraitsCRT<unsigned
   short> > > &) */

long __thiscall
AO_Controller::ExportXmlToStringForTrackedComponents(AO_Controller *this,CStringT<> *param_1)

{
  int iVar1;
  long lVar2;
  undefined4 uStack_c0;
  undefined4 uStack_bc;
  undefined4 uStack_b8;
  wchar_t **ppwStack_b4;
  undefined4 uStack_b0;
  undefined4 uStack_ac;
  CStringT<> *pCStack_a8;
  void *local_30;
  undefined4 local_2c;
  int local_28;
  void *local_24;
  int local_20;
  int local_1c;
  undefined1 *local_18;
  undefined1 *local_14;
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
                    /* 0xf430  157
                       ?ExportXmlToStringForTrackedComponents@AO_Controller@@IAEJAAV?$CStringT@GV?$S trTraitMFC_DLL@GV?$ChTraitsCRT@G@ATL@@@@@ATL@@@Z
                        */
  local_8 = 0xffffffff;
  puStack_c = &LAB_100bb0c9;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  ATL::CSimpleStringT<wchar_t,1>::Empty((CSimpleStringT<wchar_t,1> *)param_1);
  local_24 = (void *)0x0;
  local_20 = 0;
  local_1c = 0;
  local_8 = 0;
  iVar1 = Ordinal_27425();
  if (iVar1 < 0) {
    lVar2 = -0x7fffbffb;
  }
  else {
    Ordinal_12476();
    local_8._1_3_ = (uint3)((uint)local_8 >> 8);
    local_30 = (void *)0x0;
    local_28 = 0;
    local_8._0_1_ = 2;
    local_2c = 0;
    pCStack_a8 = (CStringT<> *)0x1000f4e5;
    FUN_10009850(&local_30,local_24,local_20);
    pCStack_a8 = param_1;
    uStack_ac = 0x100;
    uStack_b0 = 0x190488e;
    ppwStack_b4 = &param_3_100ce108;
    local_14 = (undefined1 *)&uStack_c0;
    local_18 = (undefined1 *)&uStack_c0;
    uStack_c0 = 0;
    uStack_b8 = 0;
    local_8._0_1_ = 4;
    uStack_bc = 0;
    FUN_10009850(&uStack_c0,local_24,local_20);
    local_8._0_1_ = 3;
    lVar2 = Ordinal_1317(*(undefined4 *)(this + 0x70));
    local_8._0_1_ = 1;
    if (local_30 != (void *)0x0) {
      pCStack_a8 = (CStringT<> *)0x1000f571;
      FUN_100185a0(local_30,local_28 - (int)local_30 >> 2,4);
      local_30 = (void *)0x0;
      local_2c = 0;
      local_28 = 0;
    }
    local_8 = (uint)local_8._1_3_ << 8;
    Ordinal_8878();
  }
  local_8 = 0xffffffff;
  if (local_24 != (void *)0x0) {
    FUN_100185a0(local_24,local_1c - (int)local_24 >> 2,4);
  }
  ExceptionList = local_10;
  return lVar2;
}


/* protected: long __thiscall AO_Controller::ExtendedStatus(long,class CStringArray *) */

long __thiscall
AO_Controller::ExtendedStatus(AO_Controller *this,long param_1,CStringArray *param_2)

{
  long lVar1;
  
                    /* 0xf5f0  158  ?ExtendedStatus@AO_Controller@@IAEJJPAVCStringArray@@@Z */
  lVar1 = FUN_100322e0((IID *)&DAT_100cdfd0,param_1,(int)param_2);
  return lVar1;
}


/* public: virtual long __stdcall AO_Controller::GetCachedResourceObjects(unsigned long,unsigned
   long,struct tagSAFEARRAY * *) */

long AO_Controller::GetCachedResourceObjects(ulong param_1,ulong param_2,tagSAFEARRAY **param_3)

{
  undefined4 *puVar1;
  int iVar2;
  uint uVar3;
  AFX_MODULE_STATE *pAVar4;
  int iVar5;
  ulong uVar6;
  undefined4 *this;
  SAFEARRAY *psa;
  undefined4 ****ppppuVar7;
  long extraout_EAX;
  undefined4 *puVar8;
  undefined4 *in_stack_00000010;
  undefined4 *puVar9;
  AFX_MAINTAIN_STATE2 local_bc [8];
  undefined4 *local_b4;
  int local_b0;
  undefined4 local_ac;
  undefined4 local_a8;
  undefined4 local_a4 [4];
  void *local_94;
  undefined4 local_90 [13];
  undefined4 local_5c [3];
  int local_50 [9];
  undefined4 ***local_2c [4];
  uint local_1c;
  uint local_18;
  uint local_14;
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
                    /* 0x10be0  211
                       ?GetCachedResourceObjects@AO_Controller@@UAGJKKPAPAUtagSAFEARRAY@@@Z */
  local_8 = 0xffffffff;
  puStack_c = &LAB_100bb2c1;
  local_10 = ExceptionList;
  uVar3 = DAT_1010c8d4 ^ (uint)&stack0xfffffffc;
  ExceptionList = &local_10;
  local_14 = uVar3;
  if ((in_stack_00000010 == (undefined4 *)0x0) || (*(int *)(param_1 + 0x70) == 0)) {
    FUN_100322e0((IID *)&DAT_100cdfd0,0x80004003,0);
  }
  else if (AO_LogixServices::ms_ServerFaulted) {
    FUN_100322e0((IID *)&DAT_100cdfd0,0x80043a12,0);
  }
  else {
    pAVar4 = (AFX_MODULE_STATE *)FUN_100b73ce();
    AFX_MAINTAIN_STATE2::AFX_MAINTAIN_STATE2(local_bc,pAVar4);
    local_8 = 0;
    if (*(int *)(param_1 + 0xbc) == 0) {
      FUN_100322e0((IID *)&DAT_100cdfd0,0x8000ffff,0);
    }
    else {
      local_b4 = local_a4;
      local_b0 = 0;
      local_ac = 0;
      local_a8 = 4;
      local_8._0_1_ = 1;
      local_8._1_3_ = 0;
      iVar2 = **(int **)(param_1 + 0xbc);
      iVar5 = FUN_1003d180();
      uVar6 = (**(code **)(iVar2 + 0x18))(param_2,param_3,&local_b4,iVar5,uVar3);
      if ((int)uVar6 < 0) {
        FUN_100322e0((IID *)&DAT_100cdfd0,uVar6,0);
      }
      else {
        FUN_100378a0(local_5c);
        local_8._0_1_ = 2;
        puVar1 = local_b4 + local_b0;
        for (puVar8 = local_b4; puVar8 != puVar1; puVar8 = puVar8 + 1) {
          FUN_100376b0(local_90,(void *)*puVar8);
          local_8._0_1_ = 3;
          puVar9 = local_90;
          this = FUN_10009600(local_50);
          FUN_10038cd0(this,puVar9);
          local_8._0_1_ = 2;
          FUN_10037bf0(local_90);
        }
        FUN_10082a30((int *)&local_b4);
        FUN_10036540(local_5c,(int *)local_2c);
        local_8 = CONCAT31(local_8._1_3_,4);
        psa = SafeArrayCreateVector(0x11,0,local_1c);
        *in_stack_00000010 = psa;
        if (psa == (SAFEARRAY *)0x0) {
          uVar6 = 0x8007000e;
        }
        else {
          local_94 = (void *)0x0;
          uVar6 = SafeArrayAccessData(psa,&local_94);
          if ((int)uVar6 < 0) {
            SafeArrayDestroy((SAFEARRAY *)*in_stack_00000010);
          }
          else {
            ppppuVar7 = local_2c;
            if (0xf < local_18) {
              ppppuVar7 = (undefined4 ****)local_2c[0];
            }
            FUN_1001e2e0(local_94,local_1c,ppppuVar7,local_1c);
            uVar6 = SafeArrayUnaccessData((SAFEARRAY *)*in_stack_00000010);
            if ((int)uVar6 < 0) {
              SafeArrayDestroy((SAFEARRAY *)*in_stack_00000010);
            }
          }
        }
        FUN_100322e0((IID *)&DAT_100cdfd0,uVar6,0);
        local_8._0_1_ = 2;
        FUN_1000a9a0(local_2c);
        local_8._0_1_ = 1;
        FUN_10037ca0(local_5c);
      }
      local_8 = (uint)local_8._1_3_ << 8;
      FUN_10037b00((int *)&local_b4);
    }
    local_8 = 0xffffffff;
    AFX_MAINTAIN_STATE2::~AFX_MAINTAIN_STATE2(local_bc);
  }
  ExceptionList = local_10;
  __security_check_cookie(local_14 ^ (uint)&stack0xfffffffc);
  return extraout_EAX;
}


/* WARNING: Function: __alloca_probe replaced with injection: alloca_probe */
/* public: virtual long __stdcall AO_Controller::ImportL5KFromFile(unsigned short *,short) */

long AO_Controller::ImportL5KFromFile(ushort *param_1,short param_2)

{
  char cVar1;
  long lVar2;
  AFX_MODULE_STATE *pAVar3;
  undefined4 uVar4;
  int iVar5;
  undefined2 in_stack_0000000a;
  short in_stack_0000000c;
  uint uStack_10b4;
  undefined4 local_9c [29];
  CFile *local_28;
  AFX_MAINTAIN_STATE2 local_24 [8];
  undefined4 local_1c;
  int *local_18;
  undefined1 *local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    /* 0x134e0  275  ?ImportL5KFromFile@AO_Controller@@UAGJPAGF@Z */
  local_8 = 0xffffffff;
  puStack_c = &LAB_100bb895;
  local_10 = ExceptionList;
  local_18 = (int *)0x100134fc;
  uStack_10b4 = DAT_1010c8d4 ^ (uint)&stack0xfffffffc;
  local_14 = (undefined1 *)&uStack_10b4;
  ExceptionList = &local_10;
  if (AO_LogixServices::ms_ServerFaulted) {
    local_14 = (undefined1 *)&uStack_10b4;
    lVar2 = FUN_100322e0((IID *)&DAT_100cdfd0,0x80043a12,0);
    ExceptionList = local_10;
    return lVar2;
  }
  pAVar3 = (AFX_MODULE_STATE *)FUN_100b73ce();
  AFX_MAINTAIN_STATE2::AFX_MAINTAIN_STATE2(local_24,pAVar3);
  local_8 = 0;
  if (*(int *)(param_1 + 0x38) == 0) {
    lVar2 = FUN_100322e0((IID *)&DAT_100cdfd0,0x8000ffff,0);
LAB_100136a1:
    local_8 = 0xffffffff;
    AFX_MAINTAIN_STATE2::~AFX_MAINTAIN_STATE2(local_24);
    ExceptionList = local_10;
    return lVar2;
  }
  local_1c = 0x8000ffff;
  local_18 = (int *)0x0;
  local_8._1_3_ = 0;
  local_8._0_1_ = 2;
  cVar1 = FUN_10016eb0();
  if (cVar1 == '\0') {
    local_28 = (CFile *)operator_new(0x14);
    local_8._0_1_ = 3;
    if (local_28 == (CFile *)0x0) {
      uVar4 = 0;
    }
    else {
      uVar4 = CFile::CFile(local_28);
    }
    local_8._0_1_ = 2;
    FUN_1001e210(&local_18,uVar4);
    iVar5 = (**(code **)(*local_18 + 0x2c))(_param_2,0,0);
    if (iVar5 == 0) {
      lVar2 = FUN_100322e0((IID *)&DAT_100cdfd0,0x80042024,0);
      local_8 = CONCAT31(local_8._1_3_,1);
      if (local_18 != (int *)0x0) {
        (**(code **)(*local_18 + 4))(1);
      }
      goto LAB_100136a1;
    }
  }
  else {
    OpenL5KViaSPP((AO_Controller *)param_1,_param_2,(unique_ptr<> *)&local_18);
  }
  FUN_100316f0(local_9c,(int)param_1,(uint)(in_stack_0000000c == -1));
  local_8._0_1_ = 4;
  local_1c = Ordinal_8466(local_18,local_9c);
  (**(code **)(*local_18 + 0x58))();
  local_8._0_1_ = 2;
  FUN_10031830(local_9c);
  local_8 = CONCAT31(local_8._1_3_,1);
  if (local_18 != (int *)0x0) {
    (**(code **)(*local_18 + 4))(1);
  }
  local_8 = 0;
  lVar2 = FUN_1001367b();
  return lVar2;
}


/* WARNING: Function: __alloca_probe replaced with injection: alloca_probe */
/* public: virtual long __stdcall AO_Controller::ImportRawXMLFromString(long,unsigned short
   *,unsigned short *,short,unsigned short *,enum lgxImportOptions,unsigned short *,short,enum
   lgxImportStatus *,long *) */

long AO_Controller::ImportRawXMLFromString
               (long param_1,ushort *param_2,ushort *param_3,short param_4,ushort *param_5,
               lgxImportOptions param_6,ushort *param_7,short param_8,lgxImportStatus *param_9,
               long *param_10)

{
  bool bVar1;
  AFX_MODULE_STATE *pAVar2;
  wchar_t *pwVar3;
  long lVar4;
  undefined2 in_stack_00000012;
  undefined4 *in_stack_0000002c;
  ulong uVar5;
  uint uStack_1038;
  AFX_MAINTAIN_STATE2 local_20 [8];
  BSTR local_18;
  undefined1 *local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    /* 0x136f0  276
                       ?ImportRawXMLFromString@AO_Controller@@UAGJJPAG0F0W4lgxImportOptions@@0FPAW4l gxImportStatus@@PAJ@Z
                        */
  local_8 = 0xffffffff;
  puStack_c = &LAB_100bb8d0;
  local_10 = ExceptionList;
  local_18 = L"噓ꅗ죔တ씳赐\xf445ꍤ";
  uStack_1038 = DAT_1010c8d4 ^ (uint)&stack0xfffffffc;
  local_14 = (undefined1 *)&uStack_1038;
  ExceptionList = &local_10;
  if (param_10 != (long *)0x0) {
    *param_10 = 3;
  }
  if ((in_stack_0000002c == (undefined4 *)0x0) ||
     (*in_stack_0000002c = 0xffffffff, param_10 == (long *)0x0)) {
    uVar5 = 0x80004003;
  }
  else {
    if (AO_LogixServices::ms_ServerFaulted == false) {
      pAVar2 = (AFX_MODULE_STATE *)FUN_100b73ce();
      AFX_MAINTAIN_STATE2::AFX_MAINTAIN_STATE2(local_20,pAVar2);
      local_8 = 0;
      bVar1 = CheckIEViaStringForSPP((AO_Controller *)param_1);
      if (!bVar1) {
        lVar4 = FUN_100322e0((IID *)&DAT_100cdfd0,0x80043a29,0);
        local_8 = 0xffffffff;
        AFX_MAINTAIN_STATE2::~AFX_MAINTAIN_STATE2(local_20);
        ExceptionList = local_10;
        return lVar4;
      }
      local_18 = SysAllocString(
                               L"<?xml version=\'1.0\' encoding=\'UTF-16\' ?><RSLogix5000Content Sch emaRevision=\'1.0\' SoftwareRevision=\'17.0\' TargetType=\'"
                               );
      if (local_18 == (BSTR)0x0) {
        FUN_100046c0(-0x7ff8fff2);
      }
      local_8 = CONCAT31((int3)((uint)local_8 >> 8),2);
      FUN_1000b380(&local_18,_param_4);
      FUN_1000b380(&local_18,L"\' ContainsContext=\'");
      pwVar3 = L"true";
      if ((short)param_5 != -1) {
        pwVar3 = L"false";
      }
      FUN_1000b380(&local_18,pwVar3);
      FUN_1000b380(&local_18,(short *)&DAT_100ce8c4);
      FUN_1000b380(&local_18,(short *)param_6);
      FUN_1000b380(&local_18,L"</RSLogix5000Content>");
      local_8 = 1;
      lVar4 = FUN_1001384f();
      return lVar4;
    }
    uVar5 = 0x80043a12;
  }
  local_14 = (undefined1 *)&uStack_1038;
  lVar4 = FUN_100322e0((IID *)&DAT_100cdfd0,uVar5,0);
  ExceptionList = local_10;
  return lVar4;
}


/* WARNING: Function: __alloca_probe replaced with injection: alloca_probe */
/* public: virtual long __stdcall AO_Controller::ImportXMLFromFile(long,unsigned short *,unsigned
   short *,enum lgxImportOptions,unsigned short *,short,enum lgxImportStatus *,long *) */

long AO_Controller::ImportXMLFromFile
               (long param_1,ushort *param_2,ushort *param_3,lgxImportOptions param_4,
               ushort *param_5,short param_6,lgxImportStatus *param_7,long *param_8)

{
  char cVar1;
  bool bVar2;
  AFX_MODULE_STATE *pAVar3;
  int iVar4;
  uint uVar5;
  long lVar6;
  long extraout_EAX;
  undefined2 in_stack_0000001a;
  undefined4 *in_stack_00000024;
  ulong uVar7;
  uint uStack_1164;
  undefined1 local_14c [108];
  undefined1 local_e0 [120];
  undefined1 *local_68;
  long *local_64;
  uint local_60;
  AFX_MAINTAIN_STATE2 local_5c [8];
  ushort *local_54;
  wchar_t *local_50;
  long *local_48;
  long local_44;
  CStringT<> local_40 [4];
  undefined1 *local_3c;
  CStringT<> local_38 [4];
  int local_34;
  undefined4 local_30 [6];
  uint local_18;
  undefined1 *local_14;
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
                    /* 0x138f0  277
                       ?ImportXMLFromFile@AO_Controller@@UAGJJPAG0W4lgxImportOptions@@0FPAW4lgxImpor tStatus@@PAJ@Z
                        */
  local_8 = 0xffffffff;
  puStack_c = &LAB_100bb93b;
  local_10 = ExceptionList;
  uStack_1164 = DAT_1010c8d4 ^ (uint)&stack0xfffffffc;
  local_14 = (undefined1 *)&uStack_1164;
  ExceptionList = &local_10;
  local_44 = param_1;
  local_54 = param_3;
  local_50 = (wchar_t *)param_4;
  local_64 = param_8;
  local_48 = param_8;
  if (param_8 != (long *)0x0) {
    *param_8 = 3;
  }
  local_18 = uStack_1164;
  if ((in_stack_00000024 == (undefined4 *)0x0) ||
     (*in_stack_00000024 = 0xffffffff, param_8 == (long *)0x0)) {
    uVar7 = 0x80004003;
  }
  else {
    if (AO_LogixServices::ms_ServerFaulted == false) {
      pAVar3 = (AFX_MODULE_STATE *)FUN_100b73ce();
      AFX_MAINTAIN_STATE2::AFX_MAINTAIN_STATE2(local_5c,pAVar3);
      local_8 = 0;
      if (*(int *)(param_1 + 0x70) == 0) {
        uVar7 = 0x80004003;
LAB_100139a1:
        FUN_100322e0((IID *)&DAT_100cdfd0,uVar7,0);
      }
      else {
        FUN_10009f00(local_30,L"EnableAOPClient");
        local_8._0_1_ = 1;
        cVar1 = Ordinal_230();
        local_8 = (uint)local_8._1_3_ << 8;
        FUN_1000aa20(local_30);
        if (cVar1 != '\0') {
          *(undefined1 *)(param_1 + 0x8d) = 1;
        }
        if ((*(char *)(param_1 + 0x8d) == '\0') && (iVar4 = Ordinal_22749(), iVar4 == 0)) {
          uVar7 = 0x80044125;
          goto LAB_100139a1;
        }
        local_34 = -0x7fff0001;
        local_8._0_1_ = 2;
        Ordinal_742();
        local_8._0_1_ = 3;
        Ordinal_37045();
        local_8._0_1_ = 4;
        ATL::CStringT<>::CStringT<>(local_40,_param_6);
        local_8._0_1_ = 5;
        bVar2 = ATL::CSimpleStringT<wchar_t,1>::IsEmpty((CSimpleStringT<wchar_t,1> *)local_40);
        if (bVar2) {
          local_3c = local_14c;
LAB_10013ad8:
          uVar5 = FUN_100176e0((uint)param_5);
          if (*(char *)(param_1 + 0x8d) != '\0') {
            uVar5 = uVar5 | 0x80000000;
          }
          if (param_2 == (ushort *)0x0) {
            param_2 = (ushort *)0xffffffff;
          }
          local_60 = uVar5;
          if ((uVar5 & 8) == 0) {
            cVar1 = FUN_10016eb0();
            if (cVar1 == '\0') {
              local_34 = Ordinal_1770(*(undefined4 *)(param_1 + 0x70),param_2,local_54,uVar5,
                                      local_50);
            }
            else {
              FUN_10009e30(local_38);
              local_8._0_1_ = 6;
              local_68 = &stack0xffffee84;
              ATL::CStringT<>::CStringT<>((CStringT<> *)&stack0xffffee84,local_50);
              local_8 = CONCAT31(local_8._1_3_,6);
              local_34 = Ordinal_33506();
              if (-1 < local_34) {
                local_34 = Ordinal_1039(*(undefined4 *)(param_1 + 0x70),param_2,local_54,uVar5,
                                        local_38);
              }
              local_8._1_3_ = (uint3)((uint)local_8 >> 8);
              local_8._0_1_ = 5;
              ATL::CStringT<>::~CStringT<>(local_38);
            }
          }
          else {
            local_34 = -0x7ffbbed8;
          }
          local_8._0_1_ = 4;
          ATL::CStringT<>::~CStringT<>(local_40);
          local_8._0_1_ = 3;
          Ordinal_9299();
          local_8 = CONCAT31(local_8._1_3_,2);
          Ordinal_244();
          local_8 = 0;
          lVar6 = FUN_10013c03();
          return lVar6;
        }
        local_34 = Ordinal_8();
        if (-1 < local_34) {
          local_3c = local_e0;
          goto LAB_10013ad8;
        }
        FUN_100322e0((IID *)&DAT_100cdfd0,0x80043a13,0);
        local_8._0_1_ = 4;
        ATL::CStringT<>::~CStringT<>(local_40);
        local_8._0_1_ = 3;
        Ordinal_9299();
        local_8 = CONCAT31(local_8._1_3_,2);
        Ordinal_244();
      }
      local_8 = 0xffffffff;
      AFX_MAINTAIN_STATE2::~AFX_MAINTAIN_STATE2(local_5c);
      goto LAB_10013c66;
    }
    uVar7 = 0x80043a12;
  }
  local_14 = (undefined1 *)&uStack_1164;
  FUN_100322e0((IID *)&DAT_100cdfd0,uVar7,0);
LAB_10013c66:
  ExceptionList = local_10;
  __security_check_cookie(local_18 ^ (uint)&stack0xfffffffc);
  return extraout_EAX;
}


/* WARNING: Function: __alloca_probe replaced with injection: alloca_probe */
/* public: virtual long __stdcall AO_Controller::ImportXMLFromString(long,unsigned short *,unsigned
   short *,enum lgxImportOptions,unsigned short *,short,enum lgxImportStatus *,long *) */

long AO_Controller::ImportXMLFromString
               (long param_1,ushort *param_2,ushort *param_3,lgxImportOptions param_4,
               ushort *param_5,short param_6,lgxImportStatus *param_7,long *param_8)

{
  wchar_t *pwVar1;
  bool bVar2;
  char cVar3;
  AFX_MODULE_STATE *pAVar4;
  int iVar5;
  uint uVar6;
  undefined4 uVar7;
  long lVar8;
  long extraout_EAX;
  undefined2 in_stack_0000001a;
  int *in_stack_00000024;
  ulong uVar9;
  uint uStack_1158;
  undefined1 local_140 [108];
  undefined1 local_d4 [120];
  long *local_5c;
  ushort *local_58;
  uint local_54;
  AFX_MAINTAIN_STATE2 local_50 [8];
  wchar_t *local_48;
  long *local_44;
  long local_40;
  CStringT<> local_3c [4];
  wchar_t *local_38;
  int local_34;
  undefined4 local_30 [6];
  uint local_18;
  undefined1 *local_14;
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
                    /* 0x13c90  278
                       ?ImportXMLFromString@AO_Controller@@UAGJJPAG0W4lgxImportOptions@@0FPAW4lgxImp ortStatus@@PAJ@Z
                        */
  local_8 = 0xffffffff;
  puStack_c = &LAB_100bb9aa;
  local_10 = ExceptionList;
  uStack_1158 = DAT_1010c8d4 ^ (uint)&stack0xfffffffc;
  local_14 = (undefined1 *)&uStack_1158;
  ExceptionList = &local_10;
  local_40 = param_1;
  local_58 = param_3;
  local_48 = (wchar_t *)param_4;
  local_38 = _param_6;
  local_5c = param_8;
  local_44 = param_8;
  if (param_8 != (long *)0x0) {
    *param_8 = 3;
  }
  local_18 = uStack_1158;
  if ((in_stack_00000024 == (int *)0x0) || (*in_stack_00000024 = -1, param_8 == (long *)0x0)) {
    uVar9 = 0x80004003;
  }
  else {
    if (AO_LogixServices::ms_ServerFaulted == false) {
      pAVar4 = (AFX_MODULE_STATE *)FUN_100b73ce();
      AFX_MAINTAIN_STATE2::AFX_MAINTAIN_STATE2(local_50,pAVar4);
      local_8 = 0;
      if (*(int *)(param_1 + 0x70) == 0) {
        uVar9 = 0x80004003;
LAB_10013d41:
        FUN_100322e0((IID *)&DAT_100cdfd0,uVar9,0);
      }
      else {
        bVar2 = CheckIEViaStringForSPP((AO_Controller *)param_1);
        if (!bVar2) {
          uVar9 = 0x80043a29;
          goto LAB_10013d41;
        }
        FUN_10009f00(local_30,L"EnableAOPClient");
        local_8._0_1_ = 1;
        cVar3 = Ordinal_230(local_30);
        local_8 = (uint)local_8._1_3_ << 8;
        FUN_1000aa20(local_30);
        if (cVar3 != '\0') {
          *(undefined1 *)(param_1 + 0x8d) = 1;
        }
        if (*(char *)(param_1 + 0x8d) == '\0') {
          iVar5 = Ordinal_22749();
          if (iVar5 == 0) {
            uVar9 = 0x80044125;
            goto LAB_10013d41;
          }
        }
        pwVar1 = local_38;
        local_34 = -0x7fff0001;
        local_8._0_1_ = 2;
        Ordinal_742(local_38,*(undefined4 *)(param_1 + 0x70));
        local_8._0_1_ = 3;
        Ordinal_37045(*(undefined4 *)(param_1 + 0x70));
        local_8._0_1_ = 4;
        ATL::CStringT<>::CStringT<>(local_3c,pwVar1);
        local_8._0_1_ = 5;
        bVar2 = ATL::CSimpleStringT<wchar_t,1>::IsEmpty((CSimpleStringT<wchar_t,1> *)local_3c);
        if (bVar2) {
          local_38 = (wchar_t *)local_140;
LAB_10013e8c:
          if (param_2 == (ushort *)0x0) {
            param_2 = (ushort *)0xffffffff;
          }
          uVar6 = FUN_100176e0((uint)param_5);
          if (*(char *)(param_1 + 0x8d) != '\0') {
            uVar6 = uVar6 | 0x80000000;
          }
          local_54 = uVar6;
          if ((uVar6 & 8) == 0) {
            uVar7 = ATL::CStringT<>::CStringT<>((CStringT<> *)&local_48,local_48);
            local_8._0_1_ = 6;
            local_34 = Ordinal_400(*(undefined4 *)(param_1 + 0x70),param_2,local_58,uVar6,uVar7,
                                   local_38);
            local_8._0_1_ = 5;
            ATL::CStringT<>::~CStringT<>((CStringT<> *)&local_48);
          }
          else {
            local_34 = 0x80044128;
          }
          if (*in_stack_00000024 == -1) {
            *in_stack_00000024 = 0;
          }
          local_8._0_1_ = 4;
          ATL::CStringT<>::~CStringT<>(local_3c);
          local_8._0_1_ = 3;
          Ordinal_9299();
          local_8 = CONCAT31(local_8._1_3_,2);
          Ordinal_244();
          local_8 = 0;
          lVar8 = FUN_10013f5f();
          return lVar8;
        }
        local_34 = Ordinal_8();
        if (-1 < local_34) {
          local_38 = (wchar_t *)local_d4;
          goto LAB_10013e8c;
        }
        FUN_100322e0((IID *)&DAT_100cdfd0,0x80043a13,0);
        local_8._0_1_ = 4;
        ATL::CStringT<>::~CStringT<>(local_3c);
        local_8._0_1_ = 3;
        Ordinal_9299();
        local_8 = CONCAT31(local_8._1_3_,2);
        Ordinal_244();
      }
      local_8 = 0xffffffff;
      AFX_MAINTAIN_STATE2::~AFX_MAINTAIN_STATE2(local_50);
      goto LAB_10013fba;
    }
    uVar9 = 0x80043a12;
  }
  local_14 = (undefined1 *)&uStack_1158;
  FUN_100322e0((IID *)&DAT_100cdfd0,uVar9,0);
LAB_10013fba:
  ExceptionList = local_10;
  __security_check_cookie(local_18 ^ (uint)&stack0xfffffffc);
  return extraout_EAX;
}


/* private: long __thiscall AO_Controller::OpenL5KViaSPP(unsigned short *,class
   std::unique_ptr<class CFile,struct std::default_delete<class CFile> > &) */

long __thiscall
AO_Controller::OpenL5KViaSPP(AO_Controller *this,ushort *param_1,unique_ptr<> *param_2)

{
  int *piVar1;
  IAtlStringMgr *pIVar2;
  int iVar3;
  CMemFile *this_00;
  undefined4 extraout_ECX;
  wchar_t *pwStack_34;
  undefined4 uStack_30;
  CStringT<> local_18 [7];
  undefined1 local_11;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    /* 0x14fe0  320
                       ?OpenL5KViaSPP@AO_Controller@@AAEJPAGAAV?$unique_ptr@VCFile@@U?$default_delet e@VCFile@@@std@@@std@@@Z
                        */
  local_8 = 0xffffffff;
  puStack_c = &LAB_100bbbb5;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  ATL::CStringT<>::CStringT<>(local_18);
  local_8 = 0;
  pIVar2 = (IAtlStringMgr *)FUN_10006170();
  uStack_30 = 0x10015029;
  ATL::CSimpleStringT<wchar_t,1>::SetManager((CSimpleStringT<wchar_t,1> *)local_18,pIVar2);
  local_8 = 1;
  uStack_30 = 1;
  pwStack_34 = (wchar_t *)extraout_ECX;
  ATL::CStringT<>::CStringT<>((CStringT<> *)&pwStack_34,(wchar_t *)param_1);
  local_8._1_3_ = (undefined3)((uint)local_8 >> 8);
  local_8._0_1_ = 1;
  iVar3 = Ordinal_33506();
  if (-1 < iVar3) {
    uStack_30 = 0x10015067;
    this_00 = (CMemFile *)operator_new(0x2c);
    local_8._0_1_ = 4;
    if (this_00 == (CMemFile *)0x0) {
      this_00 = (CMemFile *)0x0;
    }
    else {
      uStack_30 = 0x10015083;
      CMemFile::CMemFile(this_00,0x400);
      *(undefined ***)this_00 = RxSecureMemFile::vftable;
    }
    local_8 = CONCAT31(local_8._1_3_,1);
    piVar1 = *(int **)param_2;
    *(CMemFile **)param_2 = this_00;
    if (piVar1 != (int *)0x0) {
      uStack_30 = 0x100150ab;
      (**(code **)(*piVar1 + 4))();
    }
    uStack_30 = *(undefined4 *)param_2;
    pwStack_34 = 
    L"쒃贈\xec4dᗿ츈ဌjɪｐＷ吕೉謐茏ჄƋɪjj僿謴贏\xf355䗆óŪ譒！䑐ྋjjjƋ僿謴／ࡵƋ僿㌤쟶ﱅ\xffff\xffff䶍￬〕೎謐识\xf44 d襤\r"
    ;
    Ordinal_331();
    pwStack_34 = ATL::CSimpleStringT<wchar_t,1>::GetString((CSimpleStringT<wchar_t,1> *)local_18);
    uStack_30 = 2;
    Ordinal_35286(*(undefined4 *)param_2);
    uStack_30 = 0;
    pwStack_34 = (wchar_t *)0x0;
    (**(code **)(**(int **)param_2 + 0x34))();
    local_11 = 0;
    (**(code **)(**(int **)param_2 + 0x44))(&local_11,1);
    (**(code **)(**(int **)param_2 + 0x34))(0,0,0);
    (**(code **)(**(int **)param_2 + 0x24))(param_1);
    iVar3 = 0;
  }
  local_8 = 0xffffffff;
  ATL::CStringT<>::~CStringT<>(local_18);
  ExceptionList = local_10;
  return iVar3;
}


/* WARNING: Function: __alloca_probe replaced with injection: alloca_probe */
/* public: virtual long __stdcall AO_Controller::PartialImportFromL5XFile(long,unsigned short
   *,unsigned short *,unsigned short *,enum lgxPartialImportOptions,unsigned short *,unsigned short
   *,short,enum lgxImportStatus *,long *) */

long AO_Controller::PartialImportFromL5XFile
               (long param_1,ushort *param_2,ushort *param_3,ushort *param_4,
               lgxPartialImportOptions param_5,ushort *param_6,ushort *param_7,short param_8,
               lgxImportStatus *param_9,long *param_10)

{
  void *pvVar1;
  ushort *puVar2;
  bool bVar3;
  char cVar4;
  long lVar5;
  AFX_MODULE_STATE *pAVar6;
  undefined2 in_stack_00000022;
  undefined4 *in_stack_0000002c;
  uint uStack_1160;
  ushort local_148 [58];
  ushort local_d4 [60];
  undefined1 local_5c [12];
  lgxImportStatus **local_50;
  undefined4 local_40 [5];
  undefined1 local_2a;
  AFX_MAINTAIN_STATE2 local_24 [8];
  ushort *local_1c;
  int local_18;
  undefined1 *local_14;
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  puVar2 = param_6;
  pvVar1 = ExceptionList;
                    /* 0x15130  322
                       ?PartialImportFromL5XFile@AO_Controller@@UAGJJPAG00W4lgxPartialImportOptions@ @00FPAW4lgxImportStatus@@PAJ@Z
                        */
  local_8 = 0xffffffff;
  puStack_c = &LAB_100bbc24;
  local_10 = ExceptionList;
  local_18 = 0x1001514c;
  uStack_1160 = DAT_1010c8d4 ^ (uint)&stack0xfffffffc;
  local_14 = (undefined1 *)&uStack_1160;
  ExceptionList = &local_10;
  if ((in_stack_0000002c == (undefined4 *)0x0) || (param_10 == (long *)0x0)) {
    local_14 = (undefined1 *)&uStack_1160;
    lVar5 = FUN_100322e0((IID *)&DAT_100cdfd0,0x80004003,0);
    ExceptionList = local_10;
    return lVar5;
  }
  *param_10 = 3;
  *in_stack_0000002c = 0xffffffff;
  if (8 < ((byte)param_6 & 0xf)) {
    ExceptionList = pvVar1;
    return -0x7ff8ffa9;
  }
  local_1c = (ushort *)0xffffffff;
  if (param_2 != (ushort *)0x0) {
    local_1c = param_2;
  }
  ATL::CStringT<>::CStringT<>((CStringT<> *)&param_6,(wchar_t *)param_7);
  local_8 = 0;
  if (AO_LogixServices::ms_ServerFaulted != false) {
    lVar5 = FUN_100322e0((IID *)&DAT_100cdfd0,0x80043a12,0);
LAB_10015454:
    local_8 = 0xffffffff;
    ATL::CStringT<>::~CStringT<>((CStringT<> *)&param_6);
    ExceptionList = local_10;
    return lVar5;
  }
  pAVar6 = (AFX_MODULE_STATE *)FUN_100b73ce();
  AFX_MAINTAIN_STATE2::AFX_MAINTAIN_STATE2(local_24,pAVar6);
  local_8._1_3_ = (uint3)((uint)local_8 >> 8);
  local_18 = -0x7fff0001;
  local_8._0_1_ = 2;
  FUN_100316f0(local_148,param_1,(uint)((short)param_9 == -1));
  local_8._0_1_ = 3;
  param_2 = local_148;
  Ordinal_742();
  local_8._0_1_ = 4;
  bVar3 = ATL::CSimpleStringT<wchar_t,1>::IsEmpty((CSimpleStringT<wchar_t,1> *)&param_6);
  if (!bVar3) {
    local_18 = Ordinal_8();
    if (local_18 < 0) {
      lVar5 = FUN_100322e0((IID *)&DAT_100cdfd0,0x80043a13,0);
      local_8._0_1_ = 3;
      Ordinal_244();
      local_8._0_1_ = 2;
      FUN_10031830((undefined4 *)local_148);
      local_8 = (uint)local_8._1_3_ << 8;
      AFX_MAINTAIN_STATE2::~AFX_MAINTAIN_STATE2(local_24);
      goto LAB_10015454;
    }
    param_2 = local_d4;
  }
  Ordinal_1529();
  local_8._0_1_ = 5;
  if (((uint)puVar2 & 0x4000) != 0) {
    local_2a = 1;
  }
  if (((uint)puVar2 & 8) == 0) {
    if (((uint)puVar2 & 2) == 0) {
      if (((uint)puVar2 & 1) != 0) {
        local_40[0] = 1;
      }
    }
    else {
      local_40[0] = 2;
    }
  }
  else {
    local_40[0] = 0;
  }
  Ordinal_669();
  local_8._0_1_ = 6;
  FUN_10009e30((CStringT<> *)&param_9);
  local_8._0_1_ = 7;
  cVar4 = FUN_10016eb0();
  if (cVar4 == '\0') {
    Ordinal_223();
    local_18 = 0;
  }
  else {
    param_7 = (ushort *)&stack0xffffee8c;
    ATL::CStringT<>::CStringT<>((CStringT<> *)&stack0xffffee8c,(wchar_t *)param_4);
    local_8._0_1_ = 7;
    local_18 = Ordinal_33506();
    local_50 = &param_9;
    if (local_18 < 0) goto LAB_100153b0;
  }
  local_18 = Ordinal_155(*(undefined4 *)(param_1 + 0x70),local_1c,param_3,local_40,local_5c,param_5,
                         _param_8,param_2);
LAB_100153b0:
  local_8._0_1_ = 6;
  ATL::CStringT<>::~CStringT<>((CStringT<> *)&param_9);
  local_8._0_1_ = 5;
  Ordinal_78();
  local_8._0_1_ = 4;
  Ordinal_116();
  local_8._0_1_ = 3;
  Ordinal_244();
  local_8 = CONCAT31(local_8._1_3_,2);
  FUN_10031830((undefined4 *)local_148);
  local_8 = 1;
  lVar5 = FUN_10015416();
  return lVar5;
}


/* WARNING: Function: __alloca_probe replaced with injection: alloca_probe */
/* public: virtual long __stdcall AO_Controller::PartialImportRungsFromL5XFile(long,unsigned short
   *,unsigned short *,long,long,enum lgxPartialImportOptions,unsigned short *,unsigned short
   *,short,enum lgxImportStatus *,long *) */

long AO_Controller::PartialImportRungsFromL5XFile
               (long param_1,ushort *param_2,ushort *param_3,long param_4,long param_5,
               lgxPartialImportOptions param_6,ushort *param_7,ushort *param_8,short param_9,
               lgxImportStatus *param_10,long *param_11)

{
  void *pvVar1;
  ushort *puVar2;
  bool bVar3;
  char cVar4;
  long lVar5;
  AFX_MODULE_STATE *pAVar6;
  ushort *puVar7;
  undefined2 in_stack_00000026;
  undefined4 *in_stack_00000030;
  uint uStack_115c;
  ushort local_144 [58];
  ushort local_d0 [60];
  undefined1 local_58 [12];
  lgxImportStatus **local_4c;
  undefined4 local_3c [5];
  undefined1 local_26;
  AFX_MAINTAIN_STATE2 local_20 [8];
  int local_18;
  undefined1 *local_14;
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  puVar2 = param_7;
  pvVar1 = ExceptionList;
                    /* 0x154b0  323
                       ?PartialImportRungsFromL5XFile@AO_Controller@@UAGJJPAG0JJW4lgxPartialImportOp tions@@00FPAW4lgxImportStatus@@PAJ@Z
                        */
  local_8 = 0xffffffff;
  puStack_c = &LAB_100bbca4;
  local_10 = ExceptionList;
  local_18 = 0x100154cc;
  uStack_115c = DAT_1010c8d4 ^ (uint)&stack0xfffffffc;
  local_14 = (undefined1 *)&uStack_115c;
  ExceptionList = &local_10;
  if ((in_stack_00000030 == (undefined4 *)0x0) || (param_11 == (long *)0x0)) {
    local_14 = (undefined1 *)&uStack_115c;
    lVar5 = FUN_100322e0((IID *)&DAT_100cdfd0,0x80004003,0);
    ExceptionList = local_10;
    return lVar5;
  }
  *param_11 = 3;
  *in_stack_00000030 = 0xffffffff;
  if (8 < ((byte)param_7 & 0xf)) {
    ExceptionList = pvVar1;
    return -0x7ff8ffa9;
  }
  puVar7 = (ushort *)0xffffffff;
  if (param_2 != (ushort *)0x0) {
    puVar7 = param_2;
  }
  ATL::CStringT<>::CStringT<>((CStringT<> *)&stack0x00000030,(wchar_t *)param_8);
  local_8 = 0;
  if (AO_LogixServices::ms_ServerFaulted == false) {
    pAVar6 = (AFX_MODULE_STATE *)FUN_100b73ce();
    AFX_MAINTAIN_STATE2::AFX_MAINTAIN_STATE2(local_20,pAVar6);
    local_8._1_3_ = (uint3)((uint)local_8 >> 8);
    local_18 = -0x7fff0001;
    local_8._0_1_ = 2;
    FUN_100316f0(local_144,param_1,(uint)((short)param_10 == -1));
    local_8._0_1_ = 3;
    param_7 = local_144;
    Ordinal_742();
    local_8._0_1_ = 4;
    bVar3 = ATL::CSimpleStringT<wchar_t,1>::IsEmpty((CSimpleStringT<wchar_t,1> *)&stack0x00000030);
    if (!bVar3) {
      local_18 = Ordinal_8();
      if (local_18 < 0) {
        lVar5 = FUN_100322e0((IID *)&DAT_100cdfd0,0x80043a13,0);
        local_8._0_1_ = 3;
        Ordinal_244();
        local_8._0_1_ = 2;
        FUN_10031830((undefined4 *)local_144);
        local_8 = (uint)local_8._1_3_ << 8;
        AFX_MAINTAIN_STATE2::~AFX_MAINTAIN_STATE2(local_20);
        goto LAB_100157cd;
      }
      param_7 = local_d0;
    }
    Ordinal_1529();
    local_8._0_1_ = 5;
    if (((uint)puVar2 & 0x4000) != 0) {
      local_26 = 1;
    }
    if (((uint)puVar2 & 8) == 0) {
      if (((uint)puVar2 & 2) == 0) {
        if (((uint)puVar2 & 1) != 0) {
          local_3c[0] = 1;
        }
      }
      else {
        local_3c[0] = 2;
      }
    }
    else {
      local_3c[0] = 0;
    }
    Ordinal_669();
    local_8._0_1_ = 6;
    FUN_10009e30((CStringT<> *)&param_10);
    local_8._0_1_ = 7;
    cVar4 = FUN_10016eb0();
    if (cVar4 == '\0') {
      Ordinal_223();
      local_18 = 0;
    }
    else {
      ATL::CStringT<>::CStringT<>((CStringT<> *)&stack0xffffee90,(wchar_t *)param_4);
      local_8._0_1_ = 7;
      local_18 = Ordinal_33506();
      local_4c = &param_10;
    }
    local_18 = Ordinal_155(*(undefined4 *)(param_1 + 0x70),puVar7,param_3,local_3c,local_58,0,
                           _param_9,param_7);
    local_8._0_1_ = 6;
    ATL::CStringT<>::~CStringT<>((CStringT<> *)&param_10);
    local_8._0_1_ = 5;
    Ordinal_78();
    local_8._0_1_ = 4;
    Ordinal_116();
    local_8._0_1_ = 3;
    Ordinal_244();
    local_8 = CONCAT31(local_8._1_3_,2);
    FUN_10031830((undefined4 *)local_144);
    local_8 = 1;
    lVar5 = FUN_1001578b();
    return lVar5;
  }
  lVar5 = FUN_100322e0((IID *)&DAT_100cdfd0,0x80043a12,0);
LAB_100157cd:
  local_8 = 0xffffffff;
  ATL::CStringT<>::~CStringT<>((CStringT<> *)&stack0x00000030);
  ExceptionList = local_10;
  return lVar5;
}


/* WARNING: Function: __alloca_probe replaced with injection: alloca_probe */
/* public: virtual long __stdcall AO_Controller::UnlockController(void) */

long AO_Controller::UnlockController(void)

{
  long lVar1;
  AFX_MODULE_STATE *pAVar2;
  int in_stack_00000004;
  uint uStack_1038;
  AFX_MAINTAIN_STATE2 local_20 [8];
  undefined4 local_18;
  undefined1 *local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    /* 0x17740  354  ?UnlockController@AO_Controller@@UAGJXZ */
  local_8 = 0xffffffff;
  puStack_c = &LAB_100bc0b8;
  local_10 = ExceptionList;
  local_18 = 0x1001775c;
  uStack_1038 = DAT_1010c8d4 ^ (uint)&stack0xfffffffc;
  local_14 = (undefined1 *)&uStack_1038;
  ExceptionList = &local_10;
  if (AO_LogixServices::ms_ServerFaulted) {
    local_14 = (undefined1 *)&uStack_1038;
    lVar1 = FUN_100322e0((IID *)&DAT_100cdfd0,0x80043a12,0);
    ExceptionList = local_10;
    return lVar1;
  }
  pAVar2 = (AFX_MODULE_STATE *)FUN_100b73ce();
  AFX_MAINTAIN_STATE2::AFX_MAINTAIN_STATE2(local_20,pAVar2);
  local_8 = 0;
  if (*(int *)(in_stack_00000004 + 0x70) == 0) {
    lVar1 = FUN_100322e0((IID *)&DAT_100cdfd0,0x80004003,0);
    local_8 = 0xffffffff;
    AFX_MAINTAIN_STATE2::~AFX_MAINTAIN_STATE2(local_20);
    ExceptionList = local_10;
    return lVar1;
  }
  local_18 = 0x8000ffff;
  local_8 = 1;
  (**(code **)(*(int *)(*(int *)(in_stack_00000004 + 0x70) + 0xc0) + 4))();
  local_18 = 0;
  local_8 = 0;
  lVar1 = FUN_10017804();
  return lVar1;
}


/* WARNING: Function: __alloca_probe replaced with injection: alloca_probe */
/* public: virtual long __stdcall AO_LogixServices::CheckGlobalAccessRights(enum
   lgxGlobalSecuredAction) */

long AO_LogixServices::CheckGlobalAccessRights(lgxGlobalSecuredAction param_1)

{
  long lVar1;
  AFX_MODULE_STATE *pAVar2;
  undefined4 in_stack_00000008;
  ulong uVar3;
  uint uStack_1038;
  AFX_MAINTAIN_STATE2 local_20 [8];
  ulong local_18;
  undefined1 *local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    /* 0x4780  99
                       ?CheckGlobalAccessRights@AO_LogixServices@@UAGJW4lgxGlobalSecuredAction@@@Z
                        */
  local_8 = 0xffffffff;
  puStack_c = &LAB_100b9618;
  local_10 = ExceptionList;
  local_18 = 0x1000479c;
  uStack_1038 = DAT_1010c8d4 ^ (uint)&stack0xfffffffc;
  local_14 = (undefined1 *)&uStack_1038;
  ExceptionList = &local_10;
  if (ms_ServerFaulted) {
    local_14 = (undefined1 *)&uStack_1038;
    lVar1 = FUN_100322e0((IID *)&DAT_100cd230,0x80043a12,0);
    ExceptionList = local_10;
    return lVar1;
  }
  pAVar2 = (AFX_MODULE_STATE *)FUN_100b73ce();
  AFX_MAINTAIN_STATE2::AFX_MAINTAIN_STATE2(local_20,pAVar2);
  if (*(char *)(param_1 + 0x1c) == '\0') {
    uVar3 = 0x8000ffff;
  }
  else {
    local_18 = 0x8000ffff;
    local_8 = 1;
    Ordinal_25340();
    uVar3 = Ordinal_35833(in_stack_00000008);
    local_18 = uVar3;
  }
  local_8 = 0;
  lVar1 = FUN_100322e0((IID *)&DAT_100cd230,uVar3,0);
  local_8 = 0xffffffff;
  AFX_MAINTAIN_STATE2::~AFX_MAINTAIN_STATE2(local_20);
  ExceptionList = local_10;
  return lVar1;
}


/* WARNING: Function: __alloca_probe replaced with injection: alloca_probe */
/* public: virtual long __stdcall AO_LogixServices::GetInfoFromL5XFile(unsigned short *,unsigned
   short * *,unsigned short * *,unsigned short * *,unsigned short * *,unsigned short * *,unsigned
   short * *,unsigned short * *,unsigned short * *,unsigned short * *,unsigned short * *) */

long AO_LogixServices::GetInfoFromL5XFile
               (ushort *param_1,ushort **param_2,ushort **param_3,ushort **param_4,ushort **param_5,
               ushort **param_6,ushort **param_7,ushort **param_8,ushort **param_9,ushort **param_10
               ,ushort **param_11)

{
  long lVar1;
  AFX_MODULE_STATE *pAVar2;
  wchar_t *pwVar3;
  undefined4 *in_stack_00000030;
  ulong uVar4;
  uint uStack_1094;
  undefined1 local_7c [4];
  CStringT<> local_78 [4];
  CStringT<> local_74 [4];
  CStringT<> local_70 [4];
  CStringT<> local_6c [4];
  CStringT<> local_68 [4];
  CStringT<> local_64 [4];
  CStringT<> local_60 [4];
  CStringT<> local_5c [24];
  CStringT<> local_44 [8];
  CStringT<> local_3c [28];
  AFX_MAINTAIN_STATE2 local_20 [8];
  ulong local_18;
  undefined1 *local_14;
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
                    /* 0x5dc0  229  ?GetInfoFromL5XFile@AO_LogixServices@@UAGJPAGPAPAG111111111@Z */
  local_8 = 0xffffffff;
  puStack_c = &LAB_100b9891;
  local_10 = ExceptionList;
  local_18 = 0x10005ddc;
  uStack_1094 = DAT_1010c8d4 ^ (uint)&stack0xfffffffc;
  local_14 = (undefined1 *)&uStack_1094;
  ExceptionList = &local_10;
  if (ms_ServerFaulted) {
    local_14 = (undefined1 *)&uStack_1094;
    lVar1 = FUN_100322e0((IID *)&DAT_100cd230,0x80043a12,0);
    ExceptionList = local_10;
    return lVar1;
  }
  pAVar2 = (AFX_MODULE_STATE *)FUN_100b73ce();
  AFX_MAINTAIN_STATE2::AFX_MAINTAIN_STATE2(local_20,pAVar2);
  local_8 = 0;
  if ((char)param_1[0xe] == '\0') {
    uVar4 = 0x8000ffff;
  }
  else {
    if ((((((param_2 != (ushort **)0x0) && (param_3 != (ushort **)0x0)) &&
          (param_4 != (ushort **)0x0)) &&
         ((param_5 != (ushort **)0x0 && (param_6 != (ushort **)0x0)))) &&
        ((param_7 != (ushort **)0x0 && ((param_8 != (ushort **)0x0 && (param_9 != (ushort **)0x0))))
        )) && ((param_10 != (ushort **)0x0 &&
               ((param_11 != (ushort **)0x0 && (in_stack_00000030 != (undefined4 *)0x0)))))) {
      local_18 = 0x8000ffff;
      Ordinal_1462();
      local_8._1_3_ = (uint3)((uint)local_8 >> 8);
      local_8._0_1_ = 2;
      local_18 = Ordinal_447(param_2,local_7c);
      if (-1 < (int)local_18) {
        pwVar3 = ATL::CStringT<>::AllocSysString(local_3c);
        *param_3 = (ushort *)pwVar3;
        pwVar3 = ATL::CStringT<>::AllocSysString(local_74);
        *param_4 = (ushort *)pwVar3;
        pwVar3 = ATL::CStringT<>::AllocSysString(local_70);
        *param_5 = (ushort *)pwVar3;
        pwVar3 = ATL::CStringT<>::AllocSysString(local_6c);
        *param_6 = (ushort *)pwVar3;
        pwVar3 = ATL::CStringT<>::AllocSysString(local_70);
        *param_5 = (ushort *)pwVar3;
        pwVar3 = ATL::CStringT<>::AllocSysString(local_68);
        *param_7 = (ushort *)pwVar3;
        pwVar3 = ATL::CStringT<>::AllocSysString(local_64);
        *param_8 = (ushort *)pwVar3;
        pwVar3 = ATL::CStringT<>::AllocSysString(local_60);
        *param_9 = (ushort *)pwVar3;
        pwVar3 = ATL::CStringT<>::AllocSysString(local_5c);
        *param_10 = (ushort *)pwVar3;
        pwVar3 = ATL::CStringT<>::AllocSysString(local_78);
        *param_11 = (ushort *)pwVar3;
        pwVar3 = ATL::CStringT<>::AllocSysString(local_44);
        *in_stack_00000030 = pwVar3;
        local_8 = 1;
        lVar1 = FUN_10005f9d();
        return lVar1;
      }
      lVar1 = FUN_100322e0((IID *)&DAT_100cd230,local_18,0);
      local_8 = (uint)local_8._1_3_ << 8;
      Ordinal_1471();
      goto LAB_10005ffe;
    }
    uVar4 = 0x80070057;
  }
  lVar1 = FUN_100322e0((IID *)&DAT_100cd230,uVar4,0);
LAB_10005ffe:
  local_8 = 0xffffffff;
  AFX_MAINTAIN_STATE2::~AFX_MAINTAIN_STATE2(local_20);
  ExceptionList = local_10;
  return lVar1;
}


/* public: __thiscall AO_LogixServices::~AO_LogixServices(void) */

void __thiscall AO_LogixServices::~AO_LogixServices(AO_LogixServices *this)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 uStack_8;
  
                    /* 0x3e40  45  ??1AO_LogixServices@@QAE@XZ */
  uStack_8 = 0xffffffff;
  puStack_c = &LAB_100c08b0;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  LOCK();
  ms_ObjectCount = ms_ObjectCount + -1;
  UNLOCK();
  VariantClear((VARIANTARG *)(this + 0x10));
  *(undefined4 *)(this + 0x10) = 0;
  *(undefined4 *)(this + 0x14) = 0;
  *(undefined4 *)(this + 0x18) = 0;
  *(undefined4 *)(this + 0x1c) = 0;
  ExceptionList = local_10;
  return;
}


void __cdecl FUN_100185a0(void *param_1,uint param_2,uint param_3)

{
  void *pvVar1;
  uint uVar2;
  
  if ((uint)(0xffffffff / (ulonglong)param_3) < param_2) {
                    /* WARNING: Could not recover jumptable at 0x100185b2. Too many branches */
                    /* WARNING: Subroutine does not return */
                    /* WARNING: Treating indirect jump as call */
    _invalid_parameter_noinfo_noreturn();
    return;
  }
  if (0xfff < param_2 * param_3) {
    if (((uint)param_1 & 0x1f) != 0) {
                    /* WARNING: Could not recover jumptable at 0x100185cb. Too many branches */
                    /* WARNING: Subroutine does not return */
                    /* WARNING: Treating indirect jump as call */
      _invalid_parameter_noinfo_noreturn();
      return;
    }
    pvVar1 = *(void **)((int)param_1 + -4);
    if (param_1 <= pvVar1) {
                    /* WARNING: Could not recover jumptable at 0x100185d8. Too many branches */
                    /* WARNING: Subroutine does not return */
                    /* WARNING: Treating indirect jump as call */
      _invalid_parameter_noinfo_noreturn();
      return;
    }
    uVar2 = (int)param_1 - (int)pvVar1;
    if (uVar2 < 4) {
                    /* WARNING: Could not recover jumptable at 0x100185e5. Too many branches */
                    /* WARNING: Subroutine does not return */
                    /* WARNING: Treating indirect jump as call */
      _invalid_parameter_noinfo_noreturn();
      return;
    }
    param_1 = pvVar1;
    if (0x23 < uVar2) {
                    /* WARNING: Could not recover jumptable at 0x100185f0. Too many branches */
                    /* WARNING: Subroutine does not return */
                    /* WARNING: Treating indirect jump as call */
      _invalid_parameter_noinfo_noreturn();
      return;
    }
  }
  operator_delete(param_1);
  return;
}

/*
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined __cdecl FUN_100185a0(void * param_1, uint para
                               assume FS_OFFSET = 0xffdff000
             undefined         <UNASSIGNED>   <RETURN>
             void *            Stack[0x4]:4   param_1                                 XREF[2]:     100185c4(R), 
                                                                                                   100185f6(R)  
             uint              Stack[0x8]:4   param_2                                 XREF[1]:     100185a6(R)  
             uint              Stack[0xc]:4   param_3                                 XREF[2]:     100185ab(R), 
                                                                                                   100185b8(R)  
                             FUN_100185a0                                    XREF[450]:   Catch@1000994f:10009956(c), 
                                                                                          FUN_1000a930:1000a97d(c), 
                                                                                          FUN_1000a9a0:1000a9d3(c), 
                                                                                          FUN_1000aa20:1000aa53(c), 
                                                                                          FUN_1000aaa0:1000aaed(c), 
                                                                                          FUN_1000ab40:1000ab74(c), 
                                                                                          FUN_1000aba0:1000abd7(c), 
                                                                                          FUN_1000b040:1000b082(c), 
                                                                                          Catch@1001834c:10018353(c), 
                                                                                          Catch@100183f2:100183f9(c), 
                                                                                          Catch@10018559:1001856a(c), 
                                                                                          Catch@10018846:1001884e(c), 
                                                                                          FUN_10018990:100189a2(c), 
                                                                                          FUN_1001ea30:1001ea67(c), 
                                                                                          FUN_10020b20:10020b35(c), 
                                                                                          Catch@100244bd:100244ce(c), 
                                                                                          FUN_1003e430:1003e46f(c), 
                                                                                          FUN_100427a0:100427ef(c), 
                                                                                          FUN_10042830:10042880(c), 
                                                                                          FUN_10042c80:10042cb4(c), [more]
        100185a0 55              PUSH       EBP
        100185a1 8b ec           MOV        EBP,ESP
        100185a3 83 c8 ff        OR         EAX,0xffffffff
        100185a6 8b 4d 0c        MOV        ECX,dword ptr [EBP + param_2]
        100185a9 33 d2           XOR        EDX,EDX
        100185ab f7 75 10        DIV        dword ptr [EBP + param_3]
        100185ae 3b c8           CMP        ECX,EAX
        100185b0 76 06           JBE        LAB_100185b8
        100185b2 ff 25 78        JMP        dword ptr [->API-MS-WIN-CRT-RUNTIME-L1-1-0.DLL
                 cc 0c 10
                             LAB_100185b8                                    XREF[1]:     100185b0(j)  
        100185b8 0f af 4d 10     IMUL       ECX,dword ptr [EBP + param_3]
        100185bc 81 f9 00        CMP        ECX,0x1000
                 10 00 00
        100185c2 72 32           JC         LAB_100185f6
        100185c4 8b 45 08        MOV        EAX,dword ptr [EBP + param_1]
        100185c7 a8 1f           TEST       AL,0x1f
        100185c9 74 06           JZ         LAB_100185d1
        100185cb ff 25 78        JMP        dword ptr [->API-MS-WIN-CRT-RUNTIME-L1-1-0.DLL
                 cc 0c 10
                             LAB_100185d1                                    XREF[1]:     100185c9(j)  
        100185d1 8b 48 fc        MOV        ECX,dword ptr [EAX + -0x4]
        100185d4 3b c8           CMP        ECX,EAX
        100185d6 72 06           JC         LAB_100185de
        100185d8 ff 25 78        JMP        dword ptr [->API-MS-WIN-CRT-RUNTIME-L1-1-0.DLL
                 cc 0c 10
                             LAB_100185de                                    XREF[1]:     100185d6(j)  
        100185de 2b c1           SUB        EAX,ECX
        100185e0 83 f8 04        CMP        EAX,0x4
        100185e3 73 06           JNC        LAB_100185eb
        100185e5 ff 25 78        JMP        dword ptr [->API-MS-WIN-CRT-RUNTIME-L1-1-0.DLL
                 cc 0c 10
                             LAB_100185eb                                    XREF[1]:     100185e3(j)  
        100185eb 83 f8 23        CMP        EAX,0x23
        100185ee 76 09           JBE        LAB_100185f9
        100185f0 ff 25 78        JMP        dword ptr [->API-MS-WIN-CRT-RUNTIME-L1-1-0.DLL
                 cc 0c 10
                             LAB_100185f6                                    XREF[1]:     100185c2(j)  
        100185f6 8b 4d 08        MOV        ECX,dword ptr [EBP + param_1]
                             LAB_100185f9                                    XREF[1]:     100185ee(j)  
        100185f9 51              PUSH       ECX                                              void * param_1 for operator_delete
        100185fa e8 5b ea        CALL       MFC140U.DLL::operator_delete                     void operator_delete(void * para
                 09 00
        100185ff 83 c4 04        ADD        ESP,0x4
        10018602 5d              POP        EBP
        10018603 c3              RET
        10018604 cc cc cc        align      align(12)
                 cc cc cc 
                 cc cc cc 

*/


void __cdecl FUN_100185a0(void *param_1,uint param_2,uint param_3)

{
  void *pvVar1;
  uint uVar2;
  
  if ((uint)(0xffffffff / (ulonglong)param_3) < param_2) {
                    /* WARNING: Could not recover jumptable at 0x100185b2. Too many branches */
                    /* WARNING: Subroutine does not return */
                    /* WARNING: Treating indirect jump as call */
    _invalid_parameter_noinfo_noreturn();
    return;
  }
  if (0xfff < param_2 * param_3) {
    if (((uint)param_1 & 0x1f) != 0) {
                    /* WARNING: Could not recover jumptable at 0x100185cb. Too many branches */
                    /* WARNING: Subroutine does not return */
                    /* WARNING: Treating indirect jump as call */
      _invalid_parameter_noinfo_noreturn();
      return;
    }
    pvVar1 = *(void **)((int)param_1 + -4);
    if (param_1 <= pvVar1) {
                    /* WARNING: Could not recover jumptable at 0x100185d8. Too many branches */
                    /* WARNING: Subroutine does not return */
                    /* WARNING: Treating indirect jump as call */
      _invalid_parameter_noinfo_noreturn();
      return;
    }
    uVar2 = (int)param_1 - (int)pvVar1;
    if (uVar2 < 4) {
                    /* WARNING: Could not recover jumptable at 0x100185e5. Too many branches */
                    /* WARNING: Subroutine does not return */
                    /* WARNING: Treating indirect jump as call */
      _invalid_parameter_noinfo_noreturn();
      return;
    }
    param_1 = pvVar1;
    if (0x23 < uVar2) {
                    /* WARNING: Could not recover jumptable at 0x100185f0. Too many branches */
                    /* WARNING: Subroutine does not return */
                    /* WARNING: Treating indirect jump as call */
      _invalid_parameter_noinfo_noreturn();
      return;
    }
  }
  operator_delete(param_1);
  return;
}
/*
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined __cdecl FUN_100185a0(void * param_1, uint para
                               assume FS_OFFSET = 0xffdff000
             undefined         <UNASSIGNED>   <RETURN>
             void *            Stack[0x4]:4   param_1                                 XREF[2]:     100185c4(R), 
                                                                                                   100185f6(R)  
             uint              Stack[0x8]:4   param_2                                 XREF[1]:     100185a6(R)  
             uint              Stack[0xc]:4   param_3                                 XREF[2]:     100185ab(R), 
                                                                                                   100185b8(R)  
                             FUN_100185a0                                    XREF[450]:   Catch@1000994f:10009956(c), 
                                                                                          FUN_1000a930:1000a97d(c), 
                                                                                          FUN_1000a9a0:1000a9d3(c), 
                                                                                          FUN_1000aa20:1000aa53(c), 
                                                                                          FUN_1000aaa0:1000aaed(c), 
                                                                                          FUN_1000ab40:1000ab74(c), 
                                                                                          FUN_1000aba0:1000abd7(c), 
                                                                                          FUN_1000b040:1000b082(c), 
                                                                                          Catch@1001834c:10018353(c), 
                                                                                          Catch@100183f2:100183f9(c), 
                                                                                          Catch@10018559:1001856a(c), 
                                                                                          Catch@10018846:1001884e(c), 
                                                                                          FUN_10018990:100189a2(c), 
                                                                                          FUN_1001ea30:1001ea67(c), 
                                                                                          FUN_10020b20:10020b35(c), 
                                                                                          Catch@100244bd:100244ce(c), 
                                                                                          FUN_1003e430:1003e46f(c), 
                                                                                          FUN_100427a0:100427ef(c), 
                                                                                          FUN_10042830:10042880(c), 
                                                                                          FUN_10042c80:10042cb4(c), [more]
        100185a0 55              PUSH       EBP
        100185a1 8b ec           MOV        EBP,ESP
        100185a3 83 c8 ff        OR         EAX,0xffffffff
        100185a6 8b 4d 0c        MOV        ECX,dword ptr [EBP + param_2]
        100185a9 33 d2           XOR        EDX,EDX
        100185ab f7 75 10        DIV        dword ptr [EBP + param_3]
        100185ae 3b c8           CMP        ECX,EAX
        100185b0 76 06           JBE        LAB_100185b8
        100185b2 ff 25 78        JMP        dword ptr [->API-MS-WIN-CRT-RUNTIME-L1-1-0.DLL
                 cc 0c 10
                             LAB_100185b8                                    XREF[1]:     100185b0(j)  
        100185b8 0f af 4d 10     IMUL       ECX,dword ptr [EBP + param_3]
        100185bc 81 f9 00        CMP        ECX,0x1000
                 10 00 00
        100185c2 72 32           JC         LAB_100185f6
        100185c4 8b 45 08        MOV        EAX,dword ptr [EBP + param_1]
        100185c7 a8 1f           TEST       AL,0x1f
        100185c9 74 06           JZ         LAB_100185d1
        100185cb ff 25 78        JMP        dword ptr [->API-MS-WIN-CRT-RUNTIME-L1-1-0.DLL
                 cc 0c 10
                             LAB_100185d1                                    XREF[1]:     100185c9(j)  
        100185d1 8b 48 fc        MOV        ECX,dword ptr [EAX + -0x4]
        100185d4 3b c8           CMP        ECX,EAX
        100185d6 72 06           JC         LAB_100185de
        100185d8 ff 25 78        JMP        dword ptr [->API-MS-WIN-CRT-RUNTIME-L1-1-0.DLL
                 cc 0c 10
                             LAB_100185de                                    XREF[1]:     100185d6(j)  
        100185de 2b c1           SUB        EAX,ECX
        100185e0 83 f8 04        CMP        EAX,0x4
        100185e3 73 06           JNC        LAB_100185eb
        100185e5 ff 25 78        JMP        dword ptr [->API-MS-WIN-CRT-RUNTIME-L1-1-0.DLL
                 cc 0c 10
                             LAB_100185eb                                    XREF[1]:     100185e3(j)  
        100185eb 83 f8 23        CMP        EAX,0x23
        100185ee 76 09           JBE        LAB_100185f9
        100185f0 ff 25 78        JMP        dword ptr [->API-MS-WIN-CRT-RUNTIME-L1-1-0.DLL
                 cc 0c 10
                             LAB_100185f6                                    XREF[1]:     100185c2(j)  
        100185f6 8b 4d 08        MOV        ECX,dword ptr [EBP + param_1]
                             LAB_100185f9                                    XREF[1]:     100185ee(j)  
        100185f9 51              PUSH       ECX                                              void * param_1 for operator_delete
        100185fa e8 5b ea        CALL       MFC140U.DLL::operator_delete                     void operator_delete(void * para
                 09 00
        100185ff 83 c4 04        ADD        ESP,0x4
        10018602 5d              POP        EBP
        10018603 c3              RET
        10018604 cc cc cc        align      align(12)
                 cc cc cc 
                 cc cc cc 

                 */

                 /*

                             **************************************************************
                             *                POINTER to EXTERNAL FUNCTION                *
                             **************************************************************
                             void __thiscall ~AFX_MAINTAIN_STATE2(AFX_MAINTAIN_STATE2
             void              <VOID>         <RETURN>
             AFX_MAINTAIN_S    ECX:4 (auto)   this
                             1052  Ordinal_1052  <<not bound>>
                             PTR_~AFX_MAINTAIN_STATE2_100ccd78               XREF[1]:     ~AFX_MAINTAIN_STATE2:100b70a8  
        100ccd78 1c 04 00 80     addr       MFC140U.DLL::AFX_MAINTAIN_STATE2::~AFX_MAINTAI
                             **************************************************************
                             *                POINTER to EXTERNAL FUNCTION                *
                             **************************************************************
                             undefined __thiscall AFX_MAINTAIN_STATE2(AFX_MAINTAIN_ST
             undefined         <UNASSIGNED>   <RETURN>
             AFX_MAINTAIN_S    ECX:4 (auto)   this
             AFX_MODULE_STA    Stack[0x4]:4   param_1
                             324  Ordinal_324  <<not bound>>
                             PTR_AFX_MAINTAIN_STATE2_100ccd7c                XREF[1]:     AFX_MAINTAIN_STATE2:100b70a2  
        100ccd7c 44 01 00 80     addr       MFC140U.DLL::AFX_MAINTAIN_STATE2::AFX_MAINTAIN
*/