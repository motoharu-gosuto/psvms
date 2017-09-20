#include <psp2kern/kernel/modulemgr.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/cpu.h>

#include <taihen.h>
#include <module.h>
#include <string.h>

#include "global_log.h"
#include "msif_types.h"

int get_msif_code_base(uintptr_t* base)
{
  *base = 0;

  tai_module_info_t ms_info;
  ms_info.size = sizeof(tai_module_info_t);
  if (taiGetModuleInfoForKernel(KERNEL_PID, "SceMsif", &ms_info) >= 0)
  {
    uintptr_t addr = 0;
    int ofstRes = module_get_offset(KERNEL_PID, ms_info.modid, 0, 0x00, &addr);
    if(ofstRes == 0)
    {
      *base = addr;
    }
  }
  
  return 0;
}

int get_msif_data_base(uintptr_t* base)
{
  *base = 0;

  tai_module_info_t ms_info;
  ms_info.size = sizeof(tai_module_info_t);
  if (taiGetModuleInfoForKernel(KERNEL_PID, "SceMsif", &ms_info) >= 0)
  {
    uintptr_t addr = 0;
    int ofstRes = module_get_offset(KERNEL_PID, ms_info.modid, 1, 0x00, &addr);
    if(ofstRes == 0)
    {
      *base = addr;
    }
  }
  
  return 0;
}

int get_msif_fptr_table_base(SceMsif_fptr_table** ftable)
{
  *ftable = 0;

  tai_module_info_t ms_info;
  ms_info.size = sizeof(tai_module_info_t);
  if (taiGetModuleInfoForKernel(KERNEL_PID, "SceMsif", &ms_info) >= 0)
  {
    uintptr_t addr = 0;
    int ofstRes = module_get_offset(KERNEL_PID, ms_info.modid, 1, 0x10, &addr);
    if(ofstRes == 0)
    {
      *ftable = *((SceMsif_fptr_table**)addr);
    }
  }

  return 0;
}

int get_msif_ctx_base(SceMsif_ctx** msif_ctx)
{
  *msif_ctx = 0;

  tai_module_info_t ms_info;
  ms_info.size = sizeof(tai_module_info_t);
  if (taiGetModuleInfoForKernel(KERNEL_PID, "SceMsif", &ms_info) >= 0)
  {
    uintptr_t addr = 0;
    int ofstRes = module_get_offset(KERNEL_PID, ms_info.modid, 1, 0x1480, &addr);
    if(ofstRes == 0)
    {
      *msif_ctx = (SceMsif_ctx*)addr;
    }
  }

  return 0;
}

int print_bytes(const char* data, int len)
{
  for(int i = 0; i < len; i++)
  {
    snprintf(sprintfBuffer, 256, "%02x", data[i]);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
  }

  FILE_GLOBAL_WRITE_LEN("\n");

  return 0;
} 

int get_card_string()
{
  FILE_GLOBAL_WRITE_LEN("Startup psvmc driver\n");
  
  uintptr_t code_base = 0;
  get_msif_code_base(&code_base);

  snprintf(sprintfBuffer, 256, "code_base: %x\n", code_base);
  FILE_GLOBAL_WRITE_LEN(sprintfBuffer);

  uintptr_t data_base = 0;
  get_msif_data_base(&data_base);

  snprintf(sprintfBuffer, 256, "data_base: %x\n", data_base);
  FILE_GLOBAL_WRITE_LEN(sprintfBuffer);

  SceMsif_fptr_table* ftable = 0;
  get_msif_fptr_table_base(&ftable);  

  snprintf(sprintfBuffer, 256, "ftable: %x\n", ftable);
  FILE_GLOBAL_WRITE_LEN(sprintfBuffer);

  SceMsif_ctx* msif_ctx;
  get_msif_ctx_base(&msif_ctx);

  snprintf(sprintfBuffer, 256, "msif_ctx: %x\n", msif_ctx);
  FILE_GLOBAL_WRITE_LEN(sprintfBuffer);

  if(msif_ctx > 0 && ftable > 0)
  {
    if(msif_ctx->subctx > 0 && ftable->get_card_string > 0)
    {
      snprintf(sprintfBuffer, 256, "get_card_string: %x\n", ftable->get_card_string);
      FILE_GLOBAL_WRITE_LEN(sprintfBuffer);

      snprintf(sprintfBuffer, 256, "subctx: %x\n", msif_ctx->subctx);
      FILE_GLOBAL_WRITE_LEN(sprintfBuffer);

      char card_info[0x30];
      memset(card_info, 0, 0x30);

      char* some_flag_ptr = (((char*)msif_ctx->subctx) + 0xA04);
      *some_flag_ptr = 0;
      

      int res = ftable->get_card_string(msif_ctx->subctx, card_info);

      snprintf(sprintfBuffer, 256, "res: %x\n", res);
      FILE_GLOBAL_WRITE_LEN(sprintfBuffer);

      if(res >= 0)
      {
        snprintf(sprintfBuffer, 256, "info: %s\n", card_info);
        FILE_GLOBAL_WRITE_LEN(sprintfBuffer);

        print_bytes(card_info, 0x30);
      }
    }
  }

  return 0;
}

#define SceSblSsMgrForDriver_NID 0x61E9428D
#define SceSblAuthMgrForKernel_NID 0x7ABF5135

typedef int (execute_dmac5_command_0x01_01be0374_t)(char *src, char *dst, int size, int key_slot, int key_size, int arg_4);
execute_dmac5_command_0x01_01be0374_t* execute_dmac5_command_0x01_01be0374 = 0;

int initialize_functions()
{
  int res = module_get_export_func(KERNEL_PID, "SceSblSsMgr", SceSblSsMgrForDriver_NID, 0x01be0374, (uintptr_t*)&execute_dmac5_command_0x01_01be0374);
  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to set execute_dmac5_command_0x01_01be0374 : %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
    return -1;
  }
  
  FILE_GLOBAL_WRITE_LEN("set execute_dmac5_command_0x01_01be0374\n");

  return 0;
}

tai_hook_ref_t sceSblAuthMgrSetDmac5Key_hook_ref = 0;
SceUID sceSblAuthMgrSetDmac5Key_hook_id = 0;

int sceSblAuthMgrSetDmac5Key_hook(char *key, int key_size, int slot_id, int key_id)
{
  int res = TAI_CONTINUE(int, sceSblAuthMgrSetDmac5Key_hook_ref, key, key_size, slot_id, key_id);

  snprintf(sprintfBuffer, 256, "sceSblAuthMgrSetDmac5Key_hook : %x %x %x %x %x\n", key, key_size, slot_id, key_id, res);
  FILE_GLOBAL_WRITE_LEN(sprintfBuffer);

  return res;
}

int initialize_hooks()
{
  tai_module_info_t sbl_auth_mgr_info;
  sbl_auth_mgr_info.size = sizeof(tai_module_info_t);
  if(taiGetModuleInfoForKernel(KERNEL_PID, "SceSblAuthMgr", &sbl_auth_mgr_info) >= 0)
  {
    sceSblAuthMgrSetDmac5Key_hook_id = taiHookFunctionExportForKernel(KERNEL_PID, &sceSblAuthMgrSetDmac5Key_hook_ref, "SceSblAuthMgr", SceSblAuthMgrForKernel_NID, 0x122acdea, sceSblAuthMgrSetDmac5Key_hook);

    if(sceSblAuthMgrSetDmac5Key_hook_id < 0)
      FILE_GLOBAL_WRITE_LEN("Failed to init sceSblAuthMgrSetDmac5Key_hook\n");
    else
      FILE_GLOBAL_WRITE_LEN("Init sceSblAuthMgrSetDmac5Key_hook\n");
  }

  return 0;
}

int deinitialize_hooks()
{
  if(sceSblAuthMgrSetDmac5Key_hook_id > 0)
  {
    int res = taiHookReleaseForKernel(sceSblAuthMgrSetDmac5Key_hook_id, sceSblAuthMgrSetDmac5Key_hook_ref);
    
    if(res < 0)
    {
      FILE_GLOBAL_WRITE_LEN("Failed to deinit sceSblAuthMgrSetDmac5Key_hook\n");
    }
    else
    {
      FILE_GLOBAL_WRITE_LEN("Deinit sceSblAuthMgrSetDmac5Key_hook\n");
    }
    
    sceSblAuthMgrSetDmac5Key_hook_id = -1;
  }

  return 0;
}

#define SceDmacmgrKeyringReg_PADDR 0xE04E0000
#define SCE_KERNEL_MEMBLOCK_TYPE_UNK1 0x20100206
#define SCE_KERNEL_MEMBLOCK_TYPE_UNK2 0x20100806

SceUID keyring_uid = -1;
void* keyring_ptr = 0;

#define DMAC5_KEYSIZE 0x20

//Key slots 0x0-0x7 and 0x1D can be modified directly using dmac5keyring. 
#define DMAC5_KEYRING_KEY_0 0
#define DMAC5_KEYRING_KEY_1 1
#define DMAC5_KEYRING_KEY_2 2
#define DMAC5_KEYRING_KEY_3 3
#define DMAC5_KEYRING_KEY_4 4
#define DMAC5_KEYRING_KEY_5 5
#define DMAC5_KEYRING_KEY_6 6
#define DMAC5_KEYRING_KEY_7 7
#define DMAC5_KEYRING_KEY_1D 0x1D

typedef struct SceDmacmgrKeyringReg_t
{
  char key_00[DMAC5_KEYSIZE];
  char key_01[DMAC5_KEYSIZE];
  char key_02[DMAC5_KEYSIZE];
  char key_03[DMAC5_KEYSIZE];
  char key_04[DMAC5_KEYSIZE];
  char key_05[DMAC5_KEYSIZE];
  char key_06[DMAC5_KEYSIZE];
  char key_07[DMAC5_KEYSIZE];
  char key_08[DMAC5_KEYSIZE];
  char key_09[DMAC5_KEYSIZE];
  char key_0A[DMAC5_KEYSIZE];
  char key_0B[DMAC5_KEYSIZE];
  char key_0C[DMAC5_KEYSIZE];
  char key_0D[DMAC5_KEYSIZE];
  char key_0E[DMAC5_KEYSIZE];
  char key_0F[DMAC5_KEYSIZE];
  char key_10[DMAC5_KEYSIZE];
  char key_11[DMAC5_KEYSIZE];
  char key_12[DMAC5_KEYSIZE];
  char key_13[DMAC5_KEYSIZE];
  char key_14[DMAC5_KEYSIZE];
  char key_15[DMAC5_KEYSIZE];
  char key_16[DMAC5_KEYSIZE];
  char key_17[DMAC5_KEYSIZE];
  char key_18[DMAC5_KEYSIZE];
  char key_19[DMAC5_KEYSIZE];
  char key_1A[DMAC5_KEYSIZE];
  char key_1B[DMAC5_KEYSIZE];
  char key_1C[DMAC5_KEYSIZE];
  char key_1D[DMAC5_KEYSIZE];
  char key_1E[DMAC5_KEYSIZE];
  char key_1F[DMAC5_KEYSIZE];
  uint32_t kernel_accessibility;
} SceDmacmgrKeyringReg_t;

int init_keyring()
{
  SceKernelAllocMemBlockKernelOpt opt;
  memset(&opt, 0, sizeof(SceKernelAllocMemBlockKernelOpt));
  opt.size = sizeof(SceKernelAllocMemBlockKernelOpt);
  opt.attr = 2;
  opt.paddr = SceDmacmgrKeyringReg_PADDR;

  keyring_uid = ksceKernelAllocMemBlock("SceDmacmgrKeyringReg", SCE_KERNEL_MEMBLOCK_TYPE_UNK1, 0x1000, &opt);
  if(keyring_uid < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to allocate/map SceDmacmgrKeyringReg : %x\n", keyring_uid);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
    return -1;
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("Allocated/Mapped SceDmacmgrKeyringReg\n");
  }

  int res = ksceKernelGetMemBlockBase(keyring_uid, &keyring_ptr);
  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to get SceDmacmgrKeyringReg address : %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
    return -1;
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("Got SceDmacmgrKeyringReg address\n");
  }

  return 0;
}

int deinit_keyring()
{
  if(keyring_uid > 0 && keyring_ptr > 0)
  {
    int res = ksceKernelFreeMemBlock(keyring_uid);
    if(res)
    {
      snprintf(sprintfBuffer, 256, "failed to dealloc SceDmacmgrKeyringReg : %x\n", res);
      FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
      return -1;
    }
    else
    {
      FILE_GLOBAL_WRITE_LEN("Deallocated SceDmacmgrKeyringReg\n");
    }
  }

  return 0;
}

int set_key(char* key, int index)
{
  if(index > 31)
    return -1;

  if(keyring_ptr == 0)
    return -1;

  char* ofst = (char*)keyring_ptr + index * DMAC5_KEYSIZE;
  memcpy(ofst, key, DMAC5_KEYSIZE);

  //int res = ksceKernelCpuDcacheAndL2InvalidateRange(ofst, DMAC5_KEYSIZE);
  //if(res < 0)
  //  return res;

  return 0;
}

int test_dmac5()
{
  char key[0x20] = {0};
  int res = set_key(key, DMAC5_KEYRING_KEY_1D);
  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to set_key : %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
    return -1;
  }

  char* input = "The gray fox jumped over the dog";
  char output[0x40];
  memset(output, 0, 0x40);

  int size = strnlen(input, 0x40);

  res = execute_dmac5_command_0x01_01be0374(input, output, size, DMAC5_KEYRING_KEY_1D, 0x80, 1);
  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to execute_dmac5_command_0x01_01be0374 : %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
  }
  else
  {
    snprintf(sprintfBuffer, 256, "executed dmac5 for slot : %x\n", DMAC5_KEYRING_KEY_1D);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
  }

  char expected[0x20] = {0x7a,	0xca,	0xfe,	0x12,	0xba,	0xd9,	0x97,	0xb7,	0x90,	0x2c,	0xb9,	0xcd,	0xb9,	0x20,	0xbd,	0xd5,
                         0xc8,	0xd8,	0xee,	0xd9,	0x97,	0x30,	0x47,	0x21,	0x07,	0x2a,	0x0d,	0xe0,	0xdd,	0x1e,	0x0c,	0x4e,};

  if(memcmp(expected, output, 0x20) == 0)
  {
    FILE_GLOBAL_WRITE_LEN("Confirmed AES-128-ECB encrypt\n");
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("Unexpected result\n");
  }

  return 0;
}

int module_start(SceSize argc, const void *args) 
{
  if(initialize_hooks() < 0)
    return SCE_KERNEL_START_SUCCESS;

  if(initialize_functions() < 0)
    return SCE_KERNEL_START_SUCCESS;

  if(init_keyring() < 0)
    return SCE_KERNEL_START_SUCCESS;

  test_dmac5();

  return SCE_KERNEL_START_SUCCESS;
}
 
//Alias to inhibit compiler warning
void _start() __attribute__ ((weak, alias ("module_start")));
 
int module_stop(SceSize argc, const void *args) 
{
  deinitialize_hooks();

  deinit_keyring();

  return SCE_KERNEL_STOP_SUCCESS;
}
