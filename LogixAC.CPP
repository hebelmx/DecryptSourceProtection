
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void __thiscall
FUN_1030ed60(void *this,uint *param_1,uint param_2,uint *param_3,uint *param_4,int *param_5,
            uint *param_6,char param_7)

{
  uint uVar1;
  uint uVar2;
  char cVar3;
  uint uVar4;
  undefined4 uVar5;
  UINT_PTR UVar6;
  int *piVar7;
  int iVar8;
  uint *puVar9;
  int iVar10;
  uint *puVar11;
  bool bVar12;
  uint *puVar13;
  uint local_39c [36];
  uint *local_30c;
  uint *local_308;
  uint local_304;
  undefined **local_300;
  undefined **ppuStack_2fc;
  uint *puStack_2f8;
  uint uStack_2f4;
  undefined4 local_2f0;
  undefined4 uStack_2ec;
  int iStack_2e8;
  undefined4 uStack_2e4;
  undefined4 local_2e0;
  uint *local_2dc;
  uint *local_2d8;
  uint *local_2d4;
  uint local_2d0 [84];
  undefined4 local_180 [10];
  uint local_158;
  uint uStack_154;
  uint uStack_150;
  uint uStack_14c;
  undefined1 local_58;
  uint local_54;
  uint uStack_50;
  uint uStack_4c;
  uint uStack_48;
  uint local_44;
  uint uStack_40;
  uint uStack_3c;
  uint uStack_38;
  undefined8 local_34;
  void *local_2c;
  int *local_28;
  uint *local_24;
  uint local_20 [4];
  uint local_10;
  void *local_c;
  undefined1 *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_1037d592;
  local_c = ExceptionList;
  local_10 = DAT_1039d850 ^ (uint)local_39c;
  uVar4 = DAT_1039d850 ^ (uint)&stack0xfffffc5c;
  ExceptionList = &local_c;
  cVar3 = (char)param_6;
  local_2d4 = param_1;
  local_2d8 = param_4;
  local_308 = (uint *)(param_2 & 0xf);
  local_30c = param_3;
  local_2c = this;
  if (((cVar3 == '\0') || ((local_308 != (uint *)0xa && (local_308 != (uint *)0xb)))) &&
     (uVar5 = FUN_10314aa0(this,(uint *)&local_2d4), (char)uVar5 == '\0')) goto LAB_1030f8db;
  UVar6 = 0x90;
  if (cVar3 == '\0') {
    UVar6 = 0x28;
  }
  uVar5 = FUN_10313c10(this,param_3,UVar6);
  if (((char)uVar5 == '\0') || (uVar5 = FUN_10313c10(this,local_2d8,4), (char)uVar5 == '\0'))
  goto LAB_1030f8db;
  switch(local_308) {
  case (uint *)0x0:
  case (uint *)0x1:
  case (uint *)0x2:
    FUN_10307540(this,(uint)local_2d4,param_2,param_3,(undefined8 *)local_2d8,(undefined8 *)param_5,
                 cVar3);
    goto LAB_1030f8db;
  case (uint *)0x3:
  case (uint *)0x4:
  case (uint *)0x5:
  case (uint *)0x6:
  case (uint *)0x7:
  case (uint *)0x8:
  case (uint *)0x9:
    local_304 = param_2 >> 8 & 0xffffff01;
    if (local_308 != (uint *)0x3) {
      local_24 = (uint *)0x20;
      piVar7 = (int *)0x10;
      if ((char)local_304 != '\0') {
        piVar7 = (int *)0x20;
      }
      if (param_5 < piVar7) goto switchD_1030ee60_default;
    }
    if ((param_5 != (int *)0x0) && (((char)local_304 == '\0' || (local_308 != (uint *)0x3)))) {
      local_2dc = local_2d8;
      local_28 = param_5;
      if (cVar3 == '\0') {
        if ((*param_3 & 0x20000) != 0) {
          FUN_102f40e0(&local_24);
          FUN_102f40f0((uint *)&local_24,(byte *)local_2d8,(uint)local_28);
          uVar4 = FUN_102f40c0((uint *)&local_24);
          param_3[5] = uVar4;
        }
        local_44 = param_3[4];
        uStack_40 = param_3[5];
        uStack_3c = param_3[6];
        uStack_38 = param_3[7];
        uStack_50 = param_3[1];
        uStack_4c = param_3[2];
        uStack_48 = param_3[3];
        local_34 = *(undefined8 *)(param_3 + 8);
        local_300 = &PTR_FUN_1026fc0c;
        ppuStack_2fc = (undefined **)0x0;
        local_54 = *param_3 & 0xfffcffff;
        puStack_2f8 = (uint *)0x0;
        uStack_2f4 = 0;
        local_2f0 = 1;
        uStack_2ec = _DAT_10278570;
        iStack_2e8 = iRam10278574;
        uStack_2e4 = uRam10278578;
        local_2e0 = uRam1027857c;
        local_4 = 0;
        puStack_2f8 = (uint *)FUN_10355247(0x30);
        local_2f0 = 0x30;
        local_20[0] = 0x30;
        uStack_2f4 = 0x30;
        if (iStack_2e8 == 1) {
          FUN_10357120(puStack_2f8,0,0x30);
          local_20[0] = uStack_2f4;
        }
        ppuStack_2fc = &PTR_FUN_102779e0;
        uStack_2f4 = local_20[0];
        if ((char)local_300 == '\0') {
          uVar4 = param_3[7];
          uVar1 = param_3[8];
          uVar2 = param_3[9];
          puVar13 = (uint *)0x0;
          if (local_20[0] != 0) {
            puVar13 = puStack_2f8;
          }
          *puVar13 = param_3[6];
          puVar13[1] = uVar4;
          puVar13[2] = uVar1;
          puVar13[3] = uVar2;
          puVar13 = (uint *)0x0;
          if (local_20[0] != 0) {
            puVar13 = puStack_2f8;
          }
          iVar8 = FUN_10307540(this,local_2d0[0],0,&uStack_50,(undefined8 *)puVar13,
                               (undefined8 *)0x10,'\0');
          if (iVar8 != 0) {
            uVar4 = 0x10;
            goto LAB_1030f1ed;
          }
        }
        else {
          local_2d8 = (uint *)0x0;
          switch(local_304) {
          case 4:
          case 6:
          case 8:
            local_2d8 = (uint *)0x0;
            puVar13 = (uint *)0x0;
            if (local_20[0] != 0) {
              puVar13 = puStack_2f8;
            }
            uVar4 = local_2d4[1];
            uVar1 = local_2d4[2];
            uVar2 = local_2d4[3];
            *puVar13 = *local_2d4;
            puVar13[1] = uVar4;
            puVar13[2] = uVar1;
            puVar13[3] = uVar2;
            break;
          case 5:
          case 7:
          case 9:
            local_2d8 = (uint *)0x1;
            puVar13 = (uint *)0x0;
            if (local_20[0] != 0) {
              puVar13 = puStack_2f8;
            }
            uVar4 = local_2d4[1];
            uVar1 = local_2d4[2];
            uVar2 = local_2d4[3];
            puVar13[4] = *local_2d4;
            puVar13[5] = uVar4;
            puVar13[6] = uVar1;
            puVar13[7] = uVar2;
          }
          iVar8 = FUN_10307540(this,local_2d0[0],local_2d8,&uStack_50,(undefined8 *)local_2d4,
                               (undefined8 *)0x10,'\0');
          if (iVar8 != 0) {
            uVar4 = local_2d4[1];
            uVar1 = local_2d4[2];
            uVar2 = local_2d4[3];
            if (local_2d8 == (uint *)0x0) {
              puVar13 = (uint *)0x0;
              if (uStack_2f4 != 0) {
                puVar13 = puStack_2f8;
              }
              puVar13[4] = *local_2d4;
              puVar13[5] = uVar4;
              puVar13[6] = uVar1;
              puVar13[7] = uVar2;
            }
            else {
              puVar13 = (uint *)0x0;
              if (uStack_2f4 != 0) {
                puVar13 = puStack_2f8;
              }
              *puVar13 = *local_2d4;
              puVar13[1] = uVar4;
              puVar13[2] = uVar1;
              puVar13[3] = uVar2;
            }
            uVar4 = param_3[7];
            uVar1 = param_3[8];
            uVar2 = param_3[9];
            puVar13 = (uint *)0x0;
            if (uStack_2f4 != 0) {
              puVar13 = puStack_2f8;
            }
            puVar13[8] = param_3[6];
            puVar13[9] = uVar4;
            puVar13[10] = uVar1;
            puVar13[0xb] = uVar2;
            local_2d8 = local_2d4 + 4;
            local_24 = param_6 + -4;
            uVar4 = local_20[0];
LAB_1030f1ed:
            puVar9 = (uint *)0x0;
            if (uStack_2f4 != 0) {
              puVar9 = puStack_2f8;
            }
            puVar13 = local_2d8;
            cVar3 = FUN_10310980((uint)param_3,(undefined8 *)puVar9,uVar4,local_2d8,
                                 (uint *)&local_24);
            if (cVar3 != '\0') {
              if ((char)local_300 != '\0') {
                local_24 = local_24 + 4;
                local_2d8 = local_2d4;
              }
              if ((*param_3 & 0x10000) != 0) {
                FUN_102f40e0(local_20);
                puVar13 = local_24;
                FUN_102f40f0(local_20,(byte *)local_2d8,(uint)local_24);
                uVar4 = FUN_102f40c0(local_20);
                bVar12 = param_3[5] == uVar4;
LAB_1030f288:
                if (!bVar12) {
                    /* WARNING: Load size is inaccurate */
                  (**(code **)(*this + 4))(0xcb);
                  goto LAB_1030f29a;
                }
              }
LAB_1030f60d:
              ppuStack_2fc = &PTR_FUN_102779e0;
              FUN_10289d60(&ppuStack_2fc);
              if (local_24 == param_6) goto LAB_1030f8db;
              uVar4 = 0xca;
              break;
            }
          }
        }
      }
      else {
        if ((*param_3 & 0x20000) != 0) {
          FUN_102f40e0(&local_24);
          FUN_102f40f0((uint *)&local_24,(byte *)local_2d8,(uint)local_28);
          uVar4 = FUN_102f40c0((uint *)&local_24);
          param_3[9] = uVar4;
        }
        local_300 = &PTR_FUN_1026fc0c;
        local_2f0 = 0;
        puVar13 = param_3;
        puVar9 = local_39c;
        for (iVar8 = 0x24; iVar8 != 0; iVar8 = iVar8 + -1) {
          *puVar9 = *puVar13;
          puVar13 = puVar13 + 1;
          puVar9 = puVar9 + 1;
        }
        local_39c[0] = local_39c[0] & 0xfffcffff;
        ppuStack_2fc = (undefined **)0x0;
        puStack_2f8 = (uint *)0x0;
        uStack_2f4 = 0;
        local_2f0 = CONCAT31(local_2f0._1_3_,1);
        uStack_2ec = _DAT_10278570;
        iStack_2e8 = iRam10278574;
        uStack_2e4 = uRam10278578;
        local_2e0 = uRam1027857c;
        local_4 = 2;
        puStack_2f8 = (uint *)FUN_10355247(0x30);
        local_2f0 = 0x30;
        local_20[0] = 0x30;
        uStack_2f4 = 0x30;
        if (iStack_2e8 == 1) {
          FUN_10357120(puStack_2f8,0,0x30);
          local_20[0] = uStack_2f4;
        }
        this = local_28;
        puVar9 = local_308;
        ppuStack_2fc = &PTR_FUN_102779e0;
        uStack_2f4 = local_20[0];
        if ((char)local_300 == '\0') {
          puVar13 = (uint *)0x0;
          if (local_20[0] != 0) {
            puVar13 = puStack_2f8;
          }
          uVar4 = local_308[0x19];
          uVar1 = local_308[0x1a];
          uVar2 = local_308[0x1b];
          *puVar13 = local_308[0x18];
          puVar13[1] = uVar4;
          puVar13[2] = uVar1;
          puVar13[3] = uVar2;
          puVar13 = (uint *)0x0;
          if (local_20[0] != 0) {
            puVar13 = puStack_2f8;
          }
          iVar8 = FUN_10307540(local_28,local_2d0[0],0,local_39c + 1,(undefined8 *)puVar13,
                               (undefined8 *)0x10,param_7);
          if (iVar8 != 0) {
            uVar4 = 0x10;
            goto LAB_1030f56d;
          }
        }
        else {
          iVar8 = 0;
          switch(local_304) {
          case 4:
          case 6:
          case 8:
            iVar8 = 0;
            puVar13 = (uint *)0x0;
            if (local_20[0] != 0) {
              puVar13 = puStack_2f8;
            }
            uVar4 = local_2d4[1];
            uVar1 = local_2d4[2];
            uVar2 = local_2d4[3];
            *puVar13 = *local_2d4;
            puVar13[1] = uVar4;
            puVar13[2] = uVar1;
            puVar13[3] = uVar2;
            break;
          case 5:
          case 7:
          case 9:
            iVar8 = 1;
            puVar13 = (uint *)0x0;
            if (local_20[0] != 0) {
              puVar13 = puStack_2f8;
            }
            uVar4 = local_2d4[1];
            uVar1 = local_2d4[2];
            uVar2 = local_2d4[3];
            puVar13[4] = *local_2d4;
            puVar13[5] = uVar4;
            puVar13[6] = uVar1;
            puVar13[7] = uVar2;
          }
          iVar10 = FUN_10307540(local_28,local_2d0[0],iVar8,local_39c + 1,(undefined8 *)local_2d4,
                                (undefined8 *)0x10,param_7);
          if (iVar10 != 0) {
            uVar4 = local_2d4[1];
            uVar1 = local_2d4[2];
            uVar2 = local_2d4[3];
            if (iVar8 == 0) {
              puVar13 = (uint *)0x0;
              if (uStack_2f4 != 0) {
                puVar13 = puStack_2f8;
              }
              puVar13[4] = *local_2d4;
              puVar13[5] = uVar4;
              puVar13[6] = uVar1;
              puVar13[7] = uVar2;
            }
            else {
              puVar13 = (uint *)0x0;
              if (uStack_2f4 != 0) {
                puVar13 = puStack_2f8;
              }
              *puVar13 = *local_2d4;
              puVar13[1] = uVar4;
              puVar13[2] = uVar1;
              puVar13[3] = uVar2;
            }
            puVar13 = (uint *)0x0;
            if (uStack_2f4 != 0) {
              puVar13 = puStack_2f8;
            }
            uVar4 = local_308[0x19];
            uVar1 = local_308[0x1a];
            uVar2 = local_308[0x1b];
            puVar13[8] = local_308[0x18];
            puVar13[9] = uVar4;
            puVar13[10] = uVar1;
            puVar13[0xb] = uVar2;
            local_2d8 = local_2d4 + 4;
            local_24 = param_6 + -4;
            uVar4 = local_20[0];
            puVar9 = local_308;
LAB_1030f56d:
            puVar11 = (uint *)0x0;
            if (uStack_2f4 != 0) {
              puVar11 = puStack_2f8;
            }
            puVar13 = local_2d8;
            cVar3 = FUN_10310980((uint)param_3,(undefined8 *)puVar11,uVar4,local_2d8,
                                 (uint *)&local_24);
            if (cVar3 != '\0') {
              if ((char)local_300 != '\0') {
                local_24 = local_24 + 4;
                local_2d8 = local_2d4;
              }
              if ((*puVar9 & 0x10000) != 0) {
                FUN_102f40e0(&local_28);
                puVar13 = local_24;
                FUN_102f40f0((uint *)&local_28,(byte *)local_2d8,(uint)local_24);
                uVar4 = FUN_102f40c0((uint *)&local_28);
                bVar12 = puVar9[9] == uVar4;
                goto LAB_1030f288;
              }
              goto LAB_1030f60d;
            }
          }
        }
      }
LAB_1030f29a:
      local_4 = 0xffffffff;
      local_300 = &PTR_FUN_102779e0;
      FUN_10289d60(&local_300);
      goto LAB_1030f8db;
    }
  default:
switchD_1030ee60_default:
    puVar13 = (uint *)0x69;
    break;
  case (uint *)0xa:
  case (uint *)0xb:
    if ((cVar3 == '\0') || (local_2d4 != (uint *)0x0)) goto switchD_1030ee60_default;
    if (local_2d8 != (uint *)0x0) {
      if (((((((int *)0xf < param_5) && (*param_3 == 0)) && (param_3[1] == 0)) &&
           ((param_3[2] == 0 && (param_3[3] == 0)))) &&
          ((param_3[4] == 0 && ((param_3[9] == 0 && (param_3[8] == 0)))))) &&
         ((((short)param_3[6] == 0 &&
           (((*(short *)((int)param_3 + 0x1a) == 0 && ((short)param_3[7] == 0)) &&
            (*(short *)((int)param_3 + 0x16) == 0)))) &&
          (((*(short *)((int)param_3 + 0x1e) == 0 && ((short)param_3[5] == 0)) &&
           ((param_2 & 0xfffffff4) == 0)))))) {
        local_58 = 0;
        FUN_102f1430(local_180,0);
        local_158 = param_3[0x18];
        uStack_154 = param_3[0x19];
        uStack_150 = param_3[0x1a];
        uStack_14c = param_3[0x1b];
        local_4 = 4;
        FUN_102f23a0(local_2d0);
        local_4._0_1_ = 5;
        FUN_102f2020((undefined8 *)local_2d0);
        FUN_102f2380((int)local_2d0,(undefined1 *)local_20,0x10);
        if (local_308 == (uint *)0xa) {
          FUN_1029ec90(local_180,param_3 + 0x14,0x10);
          if (param_5 == (int *)0x10) {
            FUN_102f1a80((int)local_180,(int)local_2d8,0x10,(int)local_2d8);
          }
          else {
            FUN_102f1ac0((int)local_180,local_2d8,(uint)param_5,local_2d8);
          }
          FUN_1029ec90(local_180,local_20,0x10);
        }
        else {
          if (local_308 != (uint *)0xb) {
                    /* WARNING: Load size is inaccurate */
            (**(code **)(*this + 4))(0x69);
            local_4 = CONCAT31(local_4._1_3_,4);
            FUN_102f2360((int)local_2d0);
            local_4 = 0xffffffff;
            FUN_102f1a40((int)local_180);
            goto LAB_1030f8db;
          }
          FUN_10300da0(local_180,param_3 + 0x14,0x10);
          if (param_5 == (int *)0x10) {
            FUN_102f1530((int)local_180,(int)local_2d8,0x10,(int)local_2d8);
          }
          else {
            FUN_102f1570((int)local_180,(int)local_2d8,(uint)param_5,local_2d8);
          }
          FUN_10300da0(local_180,local_20,0x10);
        }
        local_4 = CONCAT31(local_4._1_3_,4);
        FUN_102f2360((int)local_2d0);
        local_4 = 0xffffffff;
        FUN_102f1a40((int)local_180);
        goto LAB_1030f8db;
      }
      goto switchD_1030ee60_default;
    }
    puVar13 = (uint *)0x71;
  }
                    /* WARNING: Load size is inaccurate */
  (**(code **)(*this + 4))(puVar13,uVar4);
LAB_1030f8db:
  ExceptionList = local_c;
  FUN_103561f4(local_10 ^ (uint)local_39c);
  return;
}




void __cdecl FUN_102f2020(undefined8 *param_1)

{
  uint local_b4 [28];
  DWORD local_44 [8];
  uint local_24 [8];
  uint local_4;
  
  local_4 = DAT_1039d850 ^ (uint)local_b4;
  if (param_1 != (undefined8 *)0x0) {
    FUN_102fdf00(local_b4);
    FUN_102f20e0((BYTE *)local_44,0x20);
    FUN_102fdf50(local_b4,(undefined8 *)local_44,0x20);
    FUN_102f21a0(local_44);
    FUN_102fdf50(local_b4,(undefined8 *)local_44,0x20);
    FUN_102fde30(local_24,local_b4);
    FUN_102f2290(param_1,(undefined8 *)local_24,0x20);
    *(undefined4 *)((int)param_1 + 0x24) = 1;
  }
  FUN_103561f4(local_4 ^ (uint)local_b4);
  return;
}


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void __thiscall
FUN_1030ed60(void *this,uint *param_1,uint param_2,uint *param_3,uint *param_4,int *param_5,
            uint *param_6,char param_7)

{
  uint uVar1;
  uint uVar2;
  char cVar3;
  uint uVar4;
  undefined4 uVar5;
  UINT_PTR UVar6;
  int *piVar7;
  int iVar8;
  uint *puVar9;
  int iVar10;
  uint *puVar11;
  bool bVar12;
  uint *puVar13;
  uint local_39c [36];
  uint *local_30c;
  uint *local_308;
  uint local_304;
  undefined **local_300;
  undefined **ppuStack_2fc;
  uint *puStack_2f8;
  uint uStack_2f4;
  undefined4 local_2f0;
  undefined4 uStack_2ec;
  int iStack_2e8;
  undefined4 uStack_2e4;
  undefined4 local_2e0;
  uint *local_2dc;
  uint *local_2d8;
  uint *local_2d4;
  uint local_2d0 [84];
  undefined4 local_180 [10];
  uint local_158;
  uint uStack_154;
  uint uStack_150;
  uint uStack_14c;
  undefined1 local_58;
  uint local_54;
  uint uStack_50;
  uint uStack_4c;
  uint uStack_48;
  uint local_44;
  uint uStack_40;
  uint uStack_3c;
  uint uStack_38;
  undefined8 local_34;
  void *local_2c;
  int *local_28;
  uint *local_24;
  uint local_20 [4];
  uint local_10;
  void *local_c;
  undefined1 *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_1037d592;
  local_c = ExceptionList;
  local_10 = DAT_1039d850 ^ (uint)local_39c;
  uVar4 = DAT_1039d850 ^ (uint)&stack0xfffffc5c;
  ExceptionList = &local_c;
  cVar3 = (char)param_6;
  local_2d4 = param_1;
  local_2d8 = param_4;
  local_308 = (uint *)(param_2 & 0xf);
  local_30c = param_3;
  local_2c = this;
  if (((cVar3 == '\0') || ((local_308 != (uint *)0xa && (local_308 != (uint *)0xb)))) &&
     (uVar5 = FUN_10314aa0(this,(uint *)&local_2d4), (char)uVar5 == '\0')) goto LAB_1030f8db;
  UVar6 = 0x90;
  if (cVar3 == '\0') {
    UVar6 = 0x28;
  }
  uVar5 = FUN_10313c10(this,param_3,UVar6);
  if (((char)uVar5 == '\0') || (uVar5 = FUN_10313c10(this,local_2d8,4), (char)uVar5 == '\0'))
  goto LAB_1030f8db;
  switch(local_308) {
  case (uint *)0x0:
  case (uint *)0x1:
  case (uint *)0x2:
    FUN_10307540(this,(uint)local_2d4,param_2,param_3,(undefined8 *)local_2d8,(undefined8 *)param_5,
                 cVar3);
    goto LAB_1030f8db;
  case (uint *)0x3:
  case (uint *)0x4:
  case (uint *)0x5:
  case (uint *)0x6:
  case (uint *)0x7:
  case (uint *)0x8:
  case (uint *)0x9:
    local_304 = param_2 >> 8 & 0xffffff01;
    if (local_308 != (uint *)0x3) {
      local_24 = (uint *)0x20;
      piVar7 = (int *)0x10;
      if ((char)local_304 != '\0') {
        piVar7 = (int *)0x20;
      }
      if (param_5 < piVar7) goto switchD_1030ee60_default;
    }
    if ((param_5 != (int *)0x0) && (((char)local_304 == '\0' || (local_308 != (uint *)0x3)))) {
      local_2dc = local_2d8;
      local_28 = param_5;
      if (cVar3 == '\0') {
        if ((*param_3 & 0x20000) != 0) {
          FUN_102f40e0(&local_24);
          FUN_102f40f0((uint *)&local_24,(byte *)local_2d8,(uint)local_28);
          uVar4 = FUN_102f40c0((uint *)&local_24);
          param_3[5] = uVar4;
        }
        local_44 = param_3[4];
        uStack_40 = param_3[5];
        uStack_3c = param_3[6];
        uStack_38 = param_3[7];
        uStack_50 = param_3[1];
        uStack_4c = param_3[2];
        uStack_48 = param_3[3];
        local_34 = *(undefined8 *)(param_3 + 8);
        local_300 = &PTR_FUN_1026fc0c;
        ppuStack_2fc = (undefined **)0x0;
        local_54 = *param_3 & 0xfffcffff;
        puStack_2f8 = (uint *)0x0;
        uStack_2f4 = 0;
        local_2f0 = 1;
        uStack_2ec = _DAT_10278570;
        iStack_2e8 = iRam10278574;
        uStack_2e4 = uRam10278578;
        local_2e0 = uRam1027857c;
        local_4 = 0;
        puStack_2f8 = (uint *)FUN_10355247(0x30);
        local_2f0 = 0x30;
        local_20[0] = 0x30;
        uStack_2f4 = 0x30;
        if (iStack_2e8 == 1) {
          FUN_10357120(puStack_2f8,0,0x30);
          local_20[0] = uStack_2f4;
        }
        ppuStack_2fc = &PTR_FUN_102779e0;
        uStack_2f4 = local_20[0];
        if ((char)local_300 == '\0') {
          uVar4 = param_3[7];
          uVar1 = param_3[8];
          uVar2 = param_3[9];
          puVar13 = (uint *)0x0;
          if (local_20[0] != 0) {
            puVar13 = puStack_2f8;
          }
          *puVar13 = param_3[6];
          puVar13[1] = uVar4;
          puVar13[2] = uVar1;
          puVar13[3] = uVar2;
          puVar13 = (uint *)0x0;
          if (local_20[0] != 0) {
            puVar13 = puStack_2f8;
          }
          iVar8 = FUN_10307540(this,local_2d0[0],0,&uStack_50,(undefined8 *)puVar13,
                               (undefined8 *)0x10,'\0');
          if (iVar8 != 0) {
            uVar4 = 0x10;
            goto LAB_1030f1ed;
          }
        }
        else {
          local_2d8 = (uint *)0x0;
          switch(local_304) {
          case 4:
          case 6:
          case 8:
            local_2d8 = (uint *)0x0;
            puVar13 = (uint *)0x0;
            if (local_20[0] != 0) {
              puVar13 = puStack_2f8;
            }
            uVar4 = local_2d4[1];
            uVar1 = local_2d4[2];
            uVar2 = local_2d4[3];
            *puVar13 = *local_2d4;
            puVar13[1] = uVar4;
            puVar13[2] = uVar1;
            puVar13[3] = uVar2;
            break;
          case 5:
          case 7:
          case 9:
            local_2d8 = (uint *)0x1;
            puVar13 = (uint *)0x0;
            if (local_20[0] != 0) {
              puVar13 = puStack_2f8;
            }
            uVar4 = local_2d4[1];
            uVar1 = local_2d4[2];
            uVar2 = local_2d4[3];
            puVar13[4] = *local_2d4;
            puVar13[5] = uVar4;
            puVar13[6] = uVar1;
            puVar13[7] = uVar2;
          }
          iVar8 = FUN_10307540(this,local_2d0[0],local_2d8,&uStack_50,(undefined8 *)local_2d4,
                               (undefined8 *)0x10,'\0');
          if (iVar8 != 0) {
            uVar4 = local_2d4[1];
            uVar1 = local_2d4[2];
            uVar2 = local_2d4[3];
            if (local_2d8 == (uint *)0x0) {
              puVar13 = (uint *)0x0;
              if (uStack_2f4 != 0) {
                puVar13 = puStack_2f8;
              }
              puVar13[4] = *local_2d4;
              puVar13[5] = uVar4;
              puVar13[6] = uVar1;
              puVar13[7] = uVar2;
            }
            else {
              puVar13 = (uint *)0x0;
              if (uStack_2f4 != 0) {
                puVar13 = puStack_2f8;
              }
              *puVar13 = *local_2d4;
              puVar13[1] = uVar4;
              puVar13[2] = uVar1;
              puVar13[3] = uVar2;
            }
            uVar4 = param_3[7];
            uVar1 = param_3[8];
            uVar2 = param_3[9];
            puVar13 = (uint *)0x0;
            if (uStack_2f4 != 0) {
              puVar13 = puStack_2f8;
            }
            puVar13[8] = param_3[6];
            puVar13[9] = uVar4;
            puVar13[10] = uVar1;
            puVar13[0xb] = uVar2;
            local_2d8 = local_2d4 + 4;
            local_24 = param_6 + -4;
            uVar4 = local_20[0];
LAB_1030f1ed:
            puVar9 = (uint *)0x0;
            if (uStack_2f4 != 0) {
              puVar9 = puStack_2f8;
            }
            puVar13 = local_2d8;
            cVar3 = FUN_10310980((uint)param_3,(undefined8 *)puVar9,uVar4,local_2d8,
                                 (uint *)&local_24);
            if (cVar3 != '\0') {
              if ((char)local_300 != '\0') {
                local_24 = local_24 + 4;
                local_2d8 = local_2d4;
              }
              if ((*param_3 & 0x10000) != 0) {
                FUN_102f40e0(local_20);
                puVar13 = local_24;
                FUN_102f40f0(local_20,(byte *)local_2d8,(uint)local_24);
                uVar4 = FUN_102f40c0(local_20);
                bVar12 = param_3[5] == uVar4;
LAB_1030f288:
                if (!bVar12) {
                    /* WARNING: Load size is inaccurate */
                  (**(code **)(*this + 4))(0xcb);
                  goto LAB_1030f29a;
                }
              }
LAB_1030f60d:
              ppuStack_2fc = &PTR_FUN_102779e0;
              FUN_10289d60(&ppuStack_2fc);
              if (local_24 == param_6) goto LAB_1030f8db;
              uVar4 = 0xca;
              break;
            }
          }
        }
      }
      else {
        if ((*param_3 & 0x20000) != 0) {
          FUN_102f40e0(&local_24);
          FUN_102f40f0((uint *)&local_24,(byte *)local_2d8,(uint)local_28);
          uVar4 = FUN_102f40c0((uint *)&local_24);
          param_3[9] = uVar4;
        }
        local_300 = &PTR_FUN_1026fc0c;
        local_2f0 = 0;
        puVar13 = param_3;
        puVar9 = local_39c;
        for (iVar8 = 0x24; iVar8 != 0; iVar8 = iVar8 + -1) {
          *puVar9 = *puVar13;
          puVar13 = puVar13 + 1;
          puVar9 = puVar9 + 1;
        }
        local_39c[0] = local_39c[0] & 0xfffcffff;
        ppuStack_2fc = (undefined **)0x0;
        puStack_2f8 = (uint *)0x0;
        uStack_2f4 = 0;
        local_2f0 = CONCAT31(local_2f0._1_3_,1);
        uStack_2ec = _DAT_10278570;
        iStack_2e8 = iRam10278574;
        uStack_2e4 = uRam10278578;
        local_2e0 = uRam1027857c;
        local_4 = 2;
        puStack_2f8 = (uint *)FUN_10355247(0x30);
        local_2f0 = 0x30;
        local_20[0] = 0x30;
        uStack_2f4 = 0x30;
        if (iStack_2e8 == 1) {
          FUN_10357120(puStack_2f8,0,0x30);
          local_20[0] = uStack_2f4;
        }
        this = local_28;
        puVar9 = local_308;
        ppuStack_2fc = &PTR_FUN_102779e0;
        uStack_2f4 = local_20[0];
        if ((char)local_300 == '\0') {
          puVar13 = (uint *)0x0;
          if (local_20[0] != 0) {
            puVar13 = puStack_2f8;
          }
          uVar4 = local_308[0x19];
          uVar1 = local_308[0x1a];
          uVar2 = local_308[0x1b];
          *puVar13 = local_308[0x18];
          puVar13[1] = uVar4;
          puVar13[2] = uVar1;
          puVar13[3] = uVar2;
          puVar13 = (uint *)0x0;
          if (local_20[0] != 0) {
            puVar13 = puStack_2f8;
          }
          iVar8 = FUN_10307540(local_28,local_2d0[0],0,local_39c + 1,(undefined8 *)puVar13,
                               (undefined8 *)0x10,param_7);
          if (iVar8 != 0) {
            uVar4 = 0x10;
            goto LAB_1030f56d;
          }
        }
        else {
          iVar8 = 0;
          switch(local_304) {
          case 4:
          case 6:
          case 8:
            iVar8 = 0;
            puVar13 = (uint *)0x0;
            if (local_20[0] != 0) {
              puVar13 = puStack_2f8;
            }
            uVar4 = local_2d4[1];
            uVar1 = local_2d4[2];
            uVar2 = local_2d4[3];
            *puVar13 = *local_2d4;
            puVar13[1] = uVar4;
            puVar13[2] = uVar1;
            puVar13[3] = uVar2;
            break;
          case 5:
          case 7:
          case 9:
            iVar8 = 1;
            puVar13 = (uint *)0x0;
            if (local_20[0] != 0) {
              puVar13 = puStack_2f8;
            }
            uVar4 = local_2d4[1];
            uVar1 = local_2d4[2];
            uVar2 = local_2d4[3];
            puVar13[4] = *local_2d4;
            puVar13[5] = uVar4;
            puVar13[6] = uVar1;
            puVar13[7] = uVar2;
          }
          iVar10 = FUN_10307540(local_28,local_2d0[0],iVar8,local_39c + 1,(undefined8 *)local_2d4,
                                (undefined8 *)0x10,param_7);
          if (iVar10 != 0) {
            uVar4 = local_2d4[1];
            uVar1 = local_2d4[2];
            uVar2 = local_2d4[3];
            if (iVar8 == 0) {
              puVar13 = (uint *)0x0;
              if (uStack_2f4 != 0) {
                puVar13 = puStack_2f8;
              }
              puVar13[4] = *local_2d4;
              puVar13[5] = uVar4;
              puVar13[6] = uVar1;
              puVar13[7] = uVar2;
            }
            else {
              puVar13 = (uint *)0x0;
              if (uStack_2f4 != 0) {
                puVar13 = puStack_2f8;
              }
              *puVar13 = *local_2d4;
              puVar13[1] = uVar4;
              puVar13[2] = uVar1;
              puVar13[3] = uVar2;
            }
            puVar13 = (uint *)0x0;
            if (uStack_2f4 != 0) {
              puVar13 = puStack_2f8;
            }
            uVar4 = local_308[0x19];
            uVar1 = local_308[0x1a];
            uVar2 = local_308[0x1b];
            puVar13[8] = local_308[0x18];
            puVar13[9] = uVar4;
            puVar13[10] = uVar1;
            puVar13[0xb] = uVar2;
            local_2d8 = local_2d4 + 4;
            local_24 = param_6 + -4;
            uVar4 = local_20[0];
            puVar9 = local_308;
LAB_1030f56d:
            puVar11 = (uint *)0x0;
            if (uStack_2f4 != 0) {
              puVar11 = puStack_2f8;
            }
            puVar13 = local_2d8;
            cVar3 = FUN_10310980((uint)param_3,(undefined8 *)puVar11,uVar4,local_2d8,
                                 (uint *)&local_24);
            if (cVar3 != '\0') {
              if ((char)local_300 != '\0') {
                local_24 = local_24 + 4;
                local_2d8 = local_2d4;
              }
              if ((*puVar9 & 0x10000) != 0) {
                FUN_102f40e0(&local_28);
                puVar13 = local_24;
                FUN_102f40f0((uint *)&local_28,(byte *)local_2d8,(uint)local_24);
                uVar4 = FUN_102f40c0((uint *)&local_28);
                bVar12 = puVar9[9] == uVar4;
                goto LAB_1030f288;
              }
              goto LAB_1030f60d;
            }
          }
        }
      }
LAB_1030f29a:
      local_4 = 0xffffffff;
      local_300 = &PTR_FUN_102779e0;
      FUN_10289d60(&local_300);
      goto LAB_1030f8db;
    }
  default:
switchD_1030ee60_default:
    puVar13 = (uint *)0x69;
    break;
  case (uint *)0xa:
  case (uint *)0xb:
    if ((cVar3 == '\0') || (local_2d4 != (uint *)0x0)) goto switchD_1030ee60_default;
    if (local_2d8 != (uint *)0x0) {
      if (((((((int *)0xf < param_5) && (*param_3 == 0)) && (param_3[1] == 0)) &&
           ((param_3[2] == 0 && (param_3[3] == 0)))) &&
          ((param_3[4] == 0 && ((param_3[9] == 0 && (param_3[8] == 0)))))) &&
         ((((short)param_3[6] == 0 &&
           (((*(short *)((int)param_3 + 0x1a) == 0 && ((short)param_3[7] == 0)) &&
            (*(short *)((int)param_3 + 0x16) == 0)))) &&
          (((*(short *)((int)param_3 + 0x1e) == 0 && ((short)param_3[5] == 0)) &&
           ((param_2 & 0xfffffff4) == 0)))))) {
        local_58 = 0;
        FUN_102f1430(local_180,0);
        local_158 = param_3[0x18];
        uStack_154 = param_3[0x19];
        uStack_150 = param_3[0x1a];
        uStack_14c = param_3[0x1b];
        local_4 = 4;
        FUN_102f23a0(local_2d0);
        local_4._0_1_ = 5;
        FUN_102f2020((undefined8 *)local_2d0);
        FUN_102f2380((int)local_2d0,(undefined1 *)local_20,0x10);
        if (local_308 == (uint *)0xa) {
          FUN_1029ec90(local_180,param_3 + 0x14,0x10);
          if (param_5 == (int *)0x10) {
            FUN_102f1a80((int)local_180,(int)local_2d8,0x10,(int)local_2d8);
          }
          else {
            FUN_102f1ac0((int)local_180,local_2d8,(uint)param_5,local_2d8);
          }
          FUN_1029ec90(local_180,local_20,0x10);
        }
        else {
          if (local_308 != (uint *)0xb) {
                    /* WARNING: Load size is inaccurate */
            (**(code **)(*this + 4))(0x69);
            local_4 = CONCAT31(local_4._1_3_,4);
            FUN_102f2360((int)local_2d0);
            local_4 = 0xffffffff;
            FUN_102f1a40((int)local_180);
            goto LAB_1030f8db;
          }
          FUN_10300da0(local_180,param_3 + 0x14,0x10);
          if (param_5 == (int *)0x10) {
            FUN_102f1530((int)local_180,(int)local_2d8,0x10,(int)local_2d8);
          }
          else {
            FUN_102f1570((int)local_180,(int)local_2d8,(uint)param_5,local_2d8);
          }
          FUN_10300da0(local_180,local_20,0x10);
        }
        local_4 = CONCAT31(local_4._1_3_,4);
        FUN_102f2360((int)local_2d0);
        local_4 = 0xffffffff;
        FUN_102f1a40((int)local_180);
        goto LAB_1030f8db;
      }
      goto switchD_1030ee60_default;
    }
    puVar13 = (uint *)0x71;
  }
                    /* WARNING: Load size is inaccurate */
  (**(code **)(*this + 4))(puVar13,uVar4);
LAB_1030f8db:
  ExceptionList = local_c;
  FUN_103561f4(local_10 ^ (uint)local_39c);
  return;
}


undefined4 * __fastcall FUN_10302cc0(undefined4 *param_1)

{
  undefined4 uVar1;
  void *local_c;
  undefined1 *puStack_8;
  undefined4 local_4;
  
  puStack_8 = &LAB_1037c4cc;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  *param_1 = &PTR_FUN_1027810c;
  local_4 = 0;
  param_1[1] = 0;
  param_1[2] = 0;
  uVar1 = FUN_10296260((int *)0x0,(int *)0x0);
  param_1[1] = uVar1;
  local_4._0_1_ = 1;
  param_1[4] = 0;
  FUN_10326780(param_1 + 5);
  local_4._0_1_ = 2;
  FUN_102ea2d0(param_1 + 0x16);
  local_4._0_1_ = 3;
  param_1[0x17] = 0;
  param_1[0x18] = 0;
  uVar1 = FUN_10310f70();
  param_1[0x17] = uVar1;
  local_4._0_1_ = 4;
  FUN_102f23a0(param_1 + 0x1a);
  local_4 = CONCAT31(local_4._1_3_,5);
  *(undefined1 *)(param_1 + 0x6e) = 0;
  param_1[0x19] = 0;
  FUN_10326940((int)(param_1 + 5));
  *(undefined1 *)(param_1 + 3) = 0;
  GetTickCount();
  FUN_102f23f0((undefined8 *)(param_1 + 0x1a));
  ExceptionList = local_c;
  return param_1;
}


undefined4 * __fastcall FUN_102891b0(undefined4 *param_1)

{
  undefined4 uVar1;
  void *local_c;
  undefined1 *puStack_8;
  undefined1 local_4;
  undefined3 uStack_3;
  
  puStack_8 = &LAB_103712f8;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  *param_1 = &PTR_FUN_1026f360;
  param_1[1] = 0;
  *(undefined2 *)(param_1 + 2) = 0;
  param_1[3] = 0;
  param_1[4] = 0;
  param_1[0xb] = 0xf;
  param_1[10] = 0;
  *(undefined1 *)(param_1 + 6) = 0;
  param_1[5] = &PTR_FUN_1026fbfc;
  param_1[0x12] = 0xf;
  param_1[0x11] = 0;
  *(undefined1 *)(param_1 + 0xd) = 0;
  param_1[0xc] = &PTR_FUN_1026fbfc;
  param_1[0x19] = 0xf;
  param_1[0x18] = 0;
  *(undefined1 *)(param_1 + 0x14) = 0;
  param_1[0x13] = &PTR_FUN_1026fbfc;
  *(undefined1 *)(param_1 + 0x1a) = 0;
  param_1[0x1b] = 0;
  param_1[0x20] = 0;
  param_1[0x21] = 0;
  param_1[0x22] = 0;
  *(undefined1 *)(param_1 + 0x23) = 1;
  param_1[0x24] = 1;
  param_1[0x25] = 0;
  param_1[0x26] = 0;
  param_1[0x27] = 0;
  param_1[0x1f] = &PTR_FUN_102779e0;
  param_1[0x1d] = 0;
  param_1[0x1e] = 0;
  local_4 = 1;
  uStack_3 = 0;
  *(undefined1 *)(param_1 + 0xad) = 0;
  FUN_102f1430(param_1 + 99,0);
  param_1[0xae] = 0;
  param_1[0xb1] = 0;
  param_1[0xb2] = 0;
  param_1[0xb3] = 0;
  local_4 = 3;
  param_1[0xb4] = 0;
  param_1[0xb5] = 0;
  uVar1 = FUN_1028d490();
  param_1[0xb4] = uVar1;
  param_1[0xb6] = 0;
  param_1[0xb7] = 0;
  param_1[0xb8] = 0;
  param_1[0xbb] = 0;
  param_1[0xbc] = 0;
  param_1[0xbd] = 0;
  local_4 = 6;
  FUN_102f23a0(param_1 + 0xbe);
  param_1[0x117] = 0;
  param_1[0x118] = 0;
  param_1[0x119] = 0;
  *(undefined1 *)(param_1 + 0x11a) = 1;
  param_1[0x11b] = 1;
  param_1[0x11c] = 0;
  param_1[0x11d] = 0;
  param_1[0x11e] = 0;
  param_1[0x116] = &PTR_FUN_102779e0;
  _local_4 = CONCAT31(uStack_3,8);
  FUN_1028bca0((int)param_1);
  ExceptionList = local_c;
  return param_1;
}

undefined4 * __fastcall FUN_10302cc0(undefined4 *param_1)

{
  undefined4 uVar1;
  void *local_c;
  undefined1 *puStack_8;
  undefined4 local_4;
  
  puStack_8 = &LAB_1037c4cc;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  *param_1 = &PTR_FUN_1027810c;
  local_4 = 0;
  param_1[1] = 0;
  param_1[2] = 0;
  uVar1 = FUN_10296260((int *)0x0,(int *)0x0);
  param_1[1] = uVar1;
  local_4._0_1_ = 1;
  param_1[4] = 0;
  FUN_10326780(param_1 + 5);
  local_4._0_1_ = 2;
  FUN_102ea2d0(param_1 + 0x16);
  local_4._0_1_ = 3;
  param_1[0x17] = 0;
  param_1[0x18] = 0;
  uVar1 = FUN_10310f70();
  param_1[0x17] = uVar1;
  local_4._0_1_ = 4;
  FUN_102f23a0(param_1 + 0x1a);
  local_4 = CONCAT31(local_4._1_3_,5);
  *(undefined1 *)(param_1 + 0x6e) = 0;
  param_1[0x19] = 0;
  FUN_10326940((int)(param_1 + 5));
  *(undefined1 *)(param_1 + 3) = 0;
  GetTickCount();
  FUN_102f23f0((undefined8 *)(param_1 + 0x1a));
  ExceptionList = local_c;
  return param_1;
}



undefined4 * __fastcall FUN_102891b0(undefined4 *param_1)

{
  undefined4 uVar1;
  void *local_c;
  undefined1 *puStack_8;
  undefined1 local_4;
  undefined3 uStack_3;
  
  puStack_8 = &LAB_103712f8;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  *param_1 = &PTR_FUN_1026f360;
  param_1[1] = 0;
  *(undefined2 *)(param_1 + 2) = 0;
  param_1[3] = 0;
  param_1[4] = 0;
  param_1[0xb] = 0xf;
  param_1[10] = 0;
  *(undefined1 *)(param_1 + 6) = 0;
  param_1[5] = &PTR_FUN_1026fbfc;
  param_1[0x12] = 0xf;
  param_1[0x11] = 0;
  *(undefined1 *)(param_1 + 0xd) = 0;
  param_1[0xc] = &PTR_FUN_1026fbfc;
  param_1[0x19] = 0xf;
  param_1[0x18] = 0;
  *(undefined1 *)(param_1 + 0x14) = 0;
  param_1[0x13] = &PTR_FUN_1026fbfc;
  *(undefined1 *)(param_1 + 0x1a) = 0;
  param_1[0x1b] = 0;
  param_1[0x20] = 0;
  param_1[0x21] = 0;
  param_1[0x22] = 0;
  *(undefined1 *)(param_1 + 0x23) = 1;
  param_1[0x24] = 1;
  param_1[0x25] = 0;
  param_1[0x26] = 0;
  param_1[0x27] = 0;
  param_1[0x1f] = &PTR_FUN_102779e0;
  param_1[0x1d] = 0;
  param_1[0x1e] = 0;
  local_4 = 1;
  uStack_3 = 0;
  *(undefined1 *)(param_1 + 0xad) = 0;
  FUN_102f1430(param_1 + 99,0);
  param_1[0xae] = 0;
  param_1[0xb1] = 0;
  param_1[0xb2] = 0;
  param_1[0xb3] = 0;
  local_4 = 3;
  param_1[0xb4] = 0;
  param_1[0xb5] = 0;
  uVar1 = FUN_1028d490();
  param_1[0xb4] = uVar1;
  param_1[0xb6] = 0;
  param_1[0xb7] = 0;
  param_1[0xb8] = 0;
  param_1[0xbb] = 0;
  param_1[0xbc] = 0;
  param_1[0xbd] = 0;
  local_4 = 6;
  FUN_102f23a0(param_1 + 0xbe);
  param_1[0x117] = 0;
  param_1[0x118] = 0;
  param_1[0x119] = 0;
  *(undefined1 *)(param_1 + 0x11a) = 1;
  param_1[0x11b] = 1;
  param_1[0x11c] = 0;
  param_1[0x11d] = 0;
  param_1[0x11e] = 0;
  param_1[0x116] = &PTR_FUN_102779e0;
  _local_4 = CONCAT31(uStack_3,8);
  FUN_1028bca0((int)param_1);
  ExceptionList = local_c;
  return param_1;
}


void __cdecl FUN_102f23a0(undefined4 *param_1)

{
  if (param_1 != (undefined4 *)0x0) {
    param_1[4] = 0;
    param_1[5] = 0;
    param_1[6] = 0;
    param_1[7] = 0;
    *param_1 = 0;
    param_1[1] = 0;
    param_1[2] = 0;
    param_1[3] = 0;
    param_1[8] = 0;
    param_1[9] = 0;
    FUN_102f1430(param_1 + 10,0);
  }
  return;
}


undefined4 * __fastcall FUN_102891b0(undefined4 *param_1)

{
  undefined4 uVar1;
  void *local_c;
  undefined1 *puStack_8;
  undefined1 local_4;
  undefined3 uStack_3;
  
  puStack_8 = &LAB_103712f8;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  *param_1 = &PTR_FUN_1026f360;
  param_1[1] = 0;
  *(undefined2 *)(param_1 + 2) = 0;
  param_1[3] = 0;
  param_1[4] = 0;
  param_1[0xb] = 0xf;
  param_1[10] = 0;
  *(undefined1 *)(param_1 + 6) = 0;
  param_1[5] = &PTR_FUN_1026fbfc;
  param_1[0x12] = 0xf;
  param_1[0x11] = 0;
  *(undefined1 *)(param_1 + 0xd) = 0;
  param_1[0xc] = &PTR_FUN_1026fbfc;
  param_1[0x19] = 0xf;
  param_1[0x18] = 0;
  *(undefined1 *)(param_1 + 0x14) = 0;
  param_1[0x13] = &PTR_FUN_1026fbfc;
  *(undefined1 *)(param_1 + 0x1a) = 0;
  param_1[0x1b] = 0;
  param_1[0x20] = 0;
  param_1[0x21] = 0;
  param_1[0x22] = 0;
  *(undefined1 *)(param_1 + 0x23) = 1;
  param_1[0x24] = 1;
  param_1[0x25] = 0;
  param_1[0x26] = 0;
  param_1[0x27] = 0;
  param_1[0x1f] = &PTR_FUN_102779e0;
  param_1[0x1d] = 0;
  param_1[0x1e] = 0;
  local_4 = 1;
  uStack_3 = 0;
  *(undefined1 *)(param_1 + 0xad) = 0;
  FUN_102f1430(param_1 + 99,0);
  param_1[0xae] = 0;
  param_1[0xb1] = 0;
  param_1[0xb2] = 0;
  param_1[0xb3] = 0;
  local_4 = 3;
  param_1[0xb4] = 0;
  param_1[0xb5] = 0;
  uVar1 = FUN_1028d490();
  param_1[0xb4] = uVar1;
  param_1[0xb6] = 0;
  param_1[0xb7] = 0;
  param_1[0xb8] = 0;
  param_1[0xbb] = 0;
  param_1[0xbc] = 0;
  param_1[0xbd] = 0;
  local_4 = 6;
  FUN_102f23a0(param_1 + 0xbe);
  param_1[0x117] = 0;
  param_1[0x118] = 0;
  param_1[0x119] = 0;
  *(undefined1 *)(param_1 + 0x11a) = 1;
  param_1[0x11b] = 1;
  param_1[0x11c] = 0;
  param_1[0x11d] = 0;
  param_1[0x11e] = 0;
  param_1[0x116] = &PTR_FUN_102779e0;
  _local_4 = CONCAT31(uStack_3,8);
  FUN_1028bca0((int)param_1);
  ExceptionList = local_c;
  return param_1;
}



void FUN_1028d490(void)

{
  code *pcVar1;
  int iVar2;
  undefined **appuStack_14 [3];
  char *pcStack_8;
  
  pcStack_8 = (char *)0x1028d497;
  iVar2 = FUN_10355a16(0x60);
  if (iVar2 != 0) {
    *(int *)iVar2 = iVar2;
    if ((int *)(iVar2 + 4) != (int *)0x0) {
      *(int *)(iVar2 + 4) = iVar2;
    }
    if ((int *)(iVar2 + 8) != (int *)0x0) {
      *(int *)(iVar2 + 8) = iVar2;
    }
    *(undefined2 *)(iVar2 + 0xc) = 0x101;
    return;
  }
  pcStack_8 = s_bad_allocation_1027892c;
  FUN_10356f9f(appuStack_14,&pcStack_8);
  appuStack_14[0] = &PTR_FUN_10278924;
  FUN_10356203((int *)appuStack_14,&DAT_103919a4);
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}


void FUN_1028d490(void)

{
  code *pcVar1;
  int iVar2;
  undefined **appuStack_14 [3];
  char *pcStack_8;
  
  pcStack_8 = (char *)0x1028d497;
  iVar2 = FUN_10355a16(0x60);
  if (iVar2 != 0) {
    *(int *)iVar2 = iVar2;
    if ((int *)(iVar2 + 4) != (int *)0x0) {
      *(int *)(iVar2 + 4) = iVar2;
    }
    if ((int *)(iVar2 + 8) != (int *)0x0) {
      *(int *)(iVar2 + 8) = iVar2;
    }
    *(undefined2 *)(iVar2 + 0xc) = 0x101;
    return;
  }
  pcStack_8 = s_bad_allocation_1027892c;
  FUN_10356f9f(appuStack_14,&pcStack_8);
  appuStack_14[0] = &PTR_FUN_10278924;
  FUN_10356203((int *)appuStack_14,&DAT_103919a4);
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}



void __thiscall FUN_103479b0(void *this,uint param_1)

{
  char cVar1;
  int iVar2;
  uint uVar3;
  undefined4 uVar4;
  uint local_16c;
  void *local_168;
  char local_161;
  undefined4 local_160 [10];
  undefined1 local_138 [256];
  char local_38;
  uint *local_34;
  uint local_30;
  undefined4 uStack_2c;
  undefined4 uStack_28;
  undefined4 uStack_24;
  uint *local_20;
  undefined4 uStack_1c;
  undefined4 uStack_18;
  undefined4 uStack_14;
  uint local_10;
  void *local_c;
  undefined1 *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_10380d7b;
  local_c = ExceptionList;
  local_10 = DAT_1039d850 ^ (uint)&local_16c;
  ExceptionList = &local_c;
  local_168 = *(void **)((int)*(void **)((int)this + 0x68) + 0x448);
  iVar2 = FUN_10341270(*(void **)((int)this + 0x68),*(int *)((int)this + 0x24));
  if (iVar2 != 0) {
                    /* WARNING: Load size is inaccurate */
    local_16c = CONCAT31(local_16c._1_3_,(char)(*this >> 1)) & 0xffffff01;
    uVar3 = FUN_10348150(this,(uint *)&local_34,(char)local_16c);
                    /* WARNING: Load size is inaccurate */
    *(uint *)this = *this | 8;
    *(uint *)((int)this + 0x54) = uVar3;
    uVar4 = FUN_10347d00(this,uVar3 | 1,&local_30,local_34,param_1);
    local_161 = (char)uVar4;
    cVar1 = FUN_10346860(*(void **)((int)this + 0x68),*(int *)((int)this + 0x24),param_1);
    if (cVar1 != '\0') {
      FUN_103477b0(local_168,*(int *)((int)this + 0x24));
    }
    if (local_161 != '\0') {
      local_38 = '\0';
      uStack_18 = 0;
      uStack_14 = 0;
      local_20 = local_34;
      uStack_1c = *(undefined4 *)((int)this + 0x28);
      *(uint *)((int)this + 0x58) = local_30;
      *(undefined4 *)((int)this + 0x5c) = uStack_2c;
      *(undefined4 *)((int)this + 0x60) = uStack_28;
      *(undefined4 *)((int)this + 100) = uStack_24;
      FUN_102f1430(local_160,0);
      local_4 = 0;
      FUN_102f1f90(local_160,&local_20,0x10,(uint)(local_38 != '\0'),local_138);
      FUN_102f2000((int)local_160);
      FUN_102f1510((int)local_160);
      local_4 = 0xffffffff;
      FUN_102f1a40((int)local_160);
    }
  }
  ExceptionList = local_c;
  FUN_103561f4(local_10 ^ (uint)&local_16c);
  return;
}


void __thiscall FUN_10301630(void *this,undefined8 *param_1,uint *param_2)

{
  uint uStack_154;
  undefined4 local_144 [10];
  undefined1 local_11c [256];
  char local_1c;
  uint local_18;
  undefined1 *local_14;
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  puStack_c = &LAB_1037c37b;
  local_10 = ExceptionList;
  uStack_154 = DAT_1039d850 ^ (uint)&stack0xfffffffc;
  local_14 = (undefined1 *)&uStack_154;
  ExceptionList = &local_10;
  local_8 = 0;
  local_1c = '\0';
  local_18 = uStack_154;
  FUN_102f1430(local_144,0);
  local_8._0_1_ = 1;
  FUN_102f1f90(local_144,(int)this + 4,0x10,(uint)(local_1c != '\0'),local_11c);
  FUN_102f1eb0((int)local_144,param_1,*param_2,(int)param_1);
  local_8 = (uint)local_8._1_3_ << 8;
  FUN_102f1a40((int)local_144);
  ExceptionList = local_10;
  FUN_103561f4(local_18 ^ (uint)&stack0xfffffffc);
  return;
}


void __thiscall FUN_103014c0(void *this,uint *param_1,uint *param_2)

{
  uint uStack_154;
  undefined4 local_144 [10];
  undefined4 local_11c;
  undefined4 uStack_118;
  undefined4 uStack_114;
  undefined4 uStack_110;
  char local_1c;
  uint local_18;
  undefined1 *local_14;
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  puStack_c = &LAB_1037c33b;
  local_10 = ExceptionList;
  uStack_154 = DAT_1039d850 ^ (uint)&stack0xfffffffc;
  local_14 = (undefined1 *)&uStack_154;
  ExceptionList = &local_10;
  local_8 = 0;
  local_1c = '\0';
  local_18 = uStack_154;
  FUN_102f1430(local_144,0);
  local_8._0_1_ = 1;
  FUN_102f1f90(local_144,(int)this + 4,0x10,(uint)(local_1c != '\0'),&local_11c);
  local_11c = *(undefined4 *)((int)this + 0x14);
  uStack_118 = *(undefined4 *)((int)this + 0x18);
  uStack_114 = *(undefined4 *)((int)this + 0x1c);
  uStack_110 = *(undefined4 *)((int)this + 0x20);
  FUN_102f1ac0((int)local_144,param_1,*param_2,param_1);
  local_8 = (uint)local_8._1_3_ << 8;
  FUN_102f1a40((int)local_144);
  ExceptionList = local_10;
  FUN_103561f4(local_18 ^ (uint)&stack0xfffffffc);
  return;
}


void __thiscall FUN_103013e0(void *this,undefined8 *param_1,uint *param_2)

{
  uint uStack_154;
  undefined4 local_144 [10];
  undefined1 local_11c [256];
  char local_1c;
  uint local_18;
  undefined1 *local_14;
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  puStack_c = &LAB_1037c2fb;
  local_10 = ExceptionList;
  uStack_154 = DAT_1039d850 ^ (uint)&stack0xfffffffc;
  local_14 = (undefined1 *)&uStack_154;
  ExceptionList = &local_10;
  local_8 = 0;
  local_1c = '\0';
  local_18 = uStack_154;
  FUN_102f1430(local_144,0);
  local_8._0_1_ = 1;
  FUN_102f1f90(local_144,(int)this + 4,0x10,(uint)(local_1c != '\0'),local_11c);
  FUN_102f2000((int)local_144);
  FUN_102f1940((int)local_144,param_1,*param_2,(undefined4 *)param_1);
  local_8 = (uint)local_8._1_3_ << 8;
  FUN_102f1a40((int)local_144);
  ExceptionList = local_10;
  FUN_103561f4(local_18 ^ (uint)&stack0xfffffffc);
  return;
}


void __thiscall FUN_103014c0(void *this,uint *param_1,uint *param_2)

{
  uint uStack_154;
  undefined4 local_144 [10];
  undefined4 local_11c;
  undefined4 uStack_118;
  undefined4 uStack_114;
  undefined4 uStack_110;
  char local_1c;
  uint local_18;
  undefined1 *local_14;
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  puStack_c = &LAB_1037c33b;
  local_10 = ExceptionList;
  uStack_154 = DAT_1039d850 ^ (uint)&stack0xfffffffc;
  local_14 = (undefined1 *)&uStack_154;
  ExceptionList = &local_10;
  local_8 = 0;
  local_1c = '\0';
  local_18 = uStack_154;
  FUN_102f1430(local_144,0);
  local_8._0_1_ = 1;
  FUN_102f1f90(local_144,(int)this + 4,0x10,(uint)(local_1c != '\0'),&local_11c);
  local_11c = *(undefined4 *)((int)this + 0x14);
  uStack_118 = *(undefined4 *)((int)this + 0x18);
  uStack_114 = *(undefined4 *)((int)this + 0x1c);
  uStack_110 = *(undefined4 *)((int)this + 0x20);
  FUN_102f1ac0((int)local_144,param_1,*param_2,param_1);
  local_8 = (uint)local_8._1_3_ << 8;
  FUN_102f1a40((int)local_144);
  ExceptionList = local_10;
  FUN_103561f4(local_18 ^ (uint)&stack0xfffffffc);
  return;
}


void __thiscall FUN_10301300(void *this,uint *param_1,uint *param_2)

{
  uint uStack_154;
  undefined4 local_144 [10];
  undefined4 local_11c;
  undefined4 uStack_118;
  undefined4 uStack_114;
  undefined4 uStack_110;
  char local_1c;
  uint local_18;
  undefined1 *local_14;
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  puStack_c = &LAB_1037c2bb;
  local_10 = ExceptionList;
  uStack_154 = DAT_1039d850 ^ (uint)&stack0xfffffffc;
  local_14 = (undefined1 *)&uStack_154;
  ExceptionList = &local_10;
  local_8 = 0;
  local_1c = '\0';
  local_18 = uStack_154;
  FUN_102f1430(local_144,0);
  local_8._0_1_ = 1;
  FUN_102f1f90(local_144,(int)this + 4,0x10,(uint)(local_1c != '\0'),&local_11c);
  local_11c = *(undefined4 *)((int)this + 0x14);
  uStack_118 = *(undefined4 *)((int)this + 0x18);
  uStack_114 = *(undefined4 *)((int)this + 0x1c);
  uStack_110 = *(undefined4 *)((int)this + 0x20);
  FUN_102f1710((int)local_144,param_1,*param_2,param_1);
  local_8 = (uint)local_8._1_3_ << 8;
  FUN_102f1a40((int)local_144);
  ExceptionList = local_10;
  FUN_103561f4(local_18 ^ (uint)&stack0xfffffffc);
  return;
}




void __thiscall FUN_10300fb0(void *this,int param_1,uint *param_2)

{
  uint uStack_154;
  undefined4 local_144 [10];
  undefined4 local_11c;
  undefined4 uStack_118;
  undefined4 uStack_114;
  undefined4 uStack_110;
  char local_1c;
  uint local_18;
  undefined1 *local_14;
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  puStack_c = &LAB_1037c23b;
  local_10 = ExceptionList;
  uStack_154 = DAT_1039d850 ^ (uint)&stack0xfffffffc;
  local_14 = (undefined1 *)&uStack_154;
  ExceptionList = &local_10;
  local_8 = 0;
  local_1c = '\0';
  local_18 = uStack_154;
  FUN_102f1430(local_144,0);
  local_8._0_1_ = 1;
  FUN_102f1f90(local_144,(int)this + 4,0x10,(uint)(local_1c != '\0'),&local_11c);
  FUN_102f2000((int)local_144);
  local_11c = *(undefined4 *)((int)this + 0x14);
  uStack_118 = *(undefined4 *)((int)this + 0x18);
  uStack_114 = *(undefined4 *)((int)this + 0x1c);
  uStack_110 = *(undefined4 *)((int)this + 0x20);
  FUN_102f1570((int)local_144,param_1,*param_2,(uint *)param_1);
  local_8 = (uint)local_8._1_3_ << 8;
  FUN_102f1a40((int)local_144);
  ExceptionList = local_10;
  FUN_103561f4(local_18 ^ (uint)&stack0xfffffffc);
  return;
}


void __cdecl FUN_102f23a0(undefined4 *param_1)

{
  if (param_1 != (undefined4 *)0x0) {
    param_1[4] = 0;
    param_1[5] = 0;
    param_1[6] = 0;
    param_1[7] = 0;
    *param_1 = 0;
    param_1[1] = 0;
    param_1[2] = 0;
    param_1[3] = 0;
    param_1[8] = 0;
    param_1[9] = 0;
    FUN_102f1430(param_1 + 10,0);
  }
  return;
}

