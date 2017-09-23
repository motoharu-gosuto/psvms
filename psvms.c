#include <psp2kern/kernel/modulemgr.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/cpu.h>

#include <taihen.h>
#include <module.h>
#include <string.h>

#include "global_log.h"
#include "msif_types.h"

//good online generator for AES CBC/ECB, DES CBC/ECB
//http://aes.online-domain-tools.com/

//AES-CMAC example
//https://stackoverflow.com/questions/29163493/aes-cmac-calculation-c-sharp

//other hashes online
//http://www.sha1-online.com/

//hmac here
//https://www.liavaag.org/English/SHA-Generator/HMAC/

//AES-CTR library
//https://www.example-code.com/csharp/crypt2_aes_ctr.asp

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
typedef int (execute_dmac5_command_0x02_8b4700cb_t)(char *src, char *dst, int size, int key_slot, int key_size, int arg_4);

typedef int (execute_dmac5_command_0x41_37dd5cbf_t)(char *src, char *dst, int size, int key_slot, int key_size, int arg_4);
typedef int (execute_dmac5_command_0x42_8eafb18a_t)(char *src, char *dst, int size, int key_slot, int key_size, int arg_4);

typedef int (execute_dmac5_command_0x49_05b38698_t)(char *src, char *dst, int size, int key_slot, int key_size, char* iv, int arg_8);
typedef int (execute_dmac5_command_0x4A_926bccf0_t)(char *src, char *dst, int size, int key_slot, int key_size, char* iv, int arg_8);

typedef int (execute_dmac5_command_0x01_c517770d_t)(char *src, char *dst, int size, char* key, int key_size, int arg_4);
typedef int (execute_dmac5_command_0x02_7c978be7_t)(char *src, char *dst, int size, char* key, int key_size, int arg_4);

typedef int (execute_dmac5_command_0x01_0f7d28af_t)(char *src, char *dst, int size, char *key, int key_size, int key_id, int arg_8);
typedef int (execute_dmac5_command_0x02_197acf6f_t)(char *src, char *dst, int size, char *key, int key_size, int key_id, int arg_8);

typedef int (execute_dmac5_command_0x09_e6e1ad15_t)(char *src, char *dst, int size, char *key, int key_size, char *iv, int arg_8);
typedef int (execute_dmac5_command_0x0A_121fa69f_t)(char *src, char *dst, int size, char *key, int key_size, char *iv, int arg_8);

typedef int (execute_dmac5_command_0x09_711c057a_t)(char *src, char *dst, int size, char *key, int key_size, char *iv, int key_id, int arg_C);
typedef int (execute_dmac5_command_0x0A_1901cb5e_t)(char *src, char *dst, int size, char *key, int key_size, char *iv, int key_id, int arg_C);

typedef int (execute_dmac5_command_0x03_eb3af9b5_t)(char *src, char *dst, int size, char *iv, int mask_enable, int command_bit);
typedef int (execute_dmac5_command_0x23_6704d985_t)(char *src, char *dst, int size, char *key, char *iv, int mask_enable, int command_bit);
typedef int (execute_dmac5_command_0x33_79f38554_t)(char *src, char *dst, int size, char *key, char *iv, int mask_enable, int command_bit);

typedef int (execute_dmac5_command_0x3B_1b14658d_t)(char *src, char *dst, int size, char *key, int key_size, char *iv, int mask_enable, int command_bit);
typedef int (execute_dmac5_command_0x3B_ea6acb6d_t)(char *src, char *dst, int size, int slot_id, int key_size, char *iv, int mask_enable, int command_bit);
typedef int (execute_dmac5_command_0x3B_83b058f5_t)(char *src, char *dst, int size, char *key, int key_size, char *iv, int key_id, int mask_enable, int command_bit);

typedef int (execute_dmac5_command_0x23_92e37656_t)(char *src, char *dst, int size, char *key, char *iv, int key_id, int mask_enable, int command_bit);

typedef int (execute_dmac5_command_0x21_82b5dcef_t)(char *src, char *dst, int size, char *key, int key_size, char *iv, int mask_enable);
typedef int (execute_dmac5_command_0x22_7d46768c_t)(char *src, char *dst, int size, char *key, int key_size, char *iv, int mask_enable);

execute_dmac5_command_0x01_01be0374_t* execute_dmac5_command_0x01_01be0374 = 0;
execute_dmac5_command_0x02_8b4700cb_t* execute_dmac5_command_0x02_8b4700cb = 0;

execute_dmac5_command_0x41_37dd5cbf_t* execute_dmac5_command_0x41_37dd5cbf = 0;
execute_dmac5_command_0x42_8eafb18a_t* execute_dmac5_command_0x42_8eafb18a = 0;

execute_dmac5_command_0x49_05b38698_t* execute_dmac5_command_0x49_05b38698 = 0;
execute_dmac5_command_0x4A_926bccf0_t* execute_dmac5_command_0x4A_926bccf0 = 0;

execute_dmac5_command_0x01_c517770d_t* execute_dmac5_command_0x01_c517770d = 0;
execute_dmac5_command_0x02_7c978be7_t* execute_dmac5_command_0x02_7c978be7 = 0;

execute_dmac5_command_0x01_0f7d28af_t* execute_dmac5_command_0x01_0f7d28af = 0;
execute_dmac5_command_0x02_197acf6f_t* execute_dmac5_command_0x02_197acf6f = 0;

execute_dmac5_command_0x09_e6e1ad15_t* execute_dmac5_command_0x09_e6e1ad15 = 0;
execute_dmac5_command_0x0A_121fa69f_t* execute_dmac5_command_0x0A_121fa69f = 0;

execute_dmac5_command_0x09_711c057a_t* execute_dmac5_command_0x09_711c057a = 0;
execute_dmac5_command_0x0A_1901cb5e_t* execute_dmac5_command_0x0A_1901cb5e = 0;

execute_dmac5_command_0x03_eb3af9b5_t* execute_dmac5_command_0x03_eb3af9b5 = 0;
execute_dmac5_command_0x23_6704d985_t* execute_dmac5_command_0x23_6704d985 = 0;
execute_dmac5_command_0x33_79f38554_t* execute_dmac5_command_0x33_79f38554 = 0;

execute_dmac5_command_0x3B_1b14658d_t* execute_dmac5_command_0x3B_1b14658d = 0;
execute_dmac5_command_0x3B_ea6acb6d_t* execute_dmac5_command_0x3B_ea6acb6d = 0;
execute_dmac5_command_0x3B_83b058f5_t* execute_dmac5_command_0x3B_83b058f5 = 0;

execute_dmac5_command_0x23_92e37656_t* execute_dmac5_command_0x23_92e37656 = 0;

execute_dmac5_command_0x21_82b5dcef_t* execute_dmac5_command_0x21_82b5dcef = 0;
execute_dmac5_command_0x22_7d46768c_t* execute_dmac5_command_0x22_7d46768c = 0;

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

  res = module_get_export_func(KERNEL_PID, "SceSblSsMgr", SceSblSsMgrForDriver_NID, 0x8b4700cb, (uintptr_t*)&execute_dmac5_command_0x02_8b4700cb);
  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to set execute_dmac5_command_0x02_8b4700cb : %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
    return -1;
  }
  
  FILE_GLOBAL_WRITE_LEN("set execute_dmac5_command_0x02_8b4700cb\n");

  res = module_get_export_func(KERNEL_PID, "SceSblSsMgr", SceSblSsMgrForDriver_NID, 0x37dd5cbf, (uintptr_t*)&execute_dmac5_command_0x41_37dd5cbf);
  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to set execute_dmac5_command_0x41_37dd5cbf : %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
    return -1;
  }
  
  FILE_GLOBAL_WRITE_LEN("set execute_dmac5_command_0x41_37dd5cbf\n");

  res = module_get_export_func(KERNEL_PID, "SceSblSsMgr", SceSblSsMgrForDriver_NID, 0x8eafb18a, (uintptr_t*)&execute_dmac5_command_0x42_8eafb18a);
  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to set execute_dmac5_command_0x42_8eafb18a : %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
    return -1;
  }
  
  FILE_GLOBAL_WRITE_LEN("set execute_dmac5_command_0x42_8eafb18a\n");

  res = module_get_export_func(KERNEL_PID, "SceSblSsMgr", SceSblSsMgrForDriver_NID, 0x05b38698, (uintptr_t*)&execute_dmac5_command_0x49_05b38698);
  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to set execute_dmac5_command_0x49_05b38698 : %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
    return -1;
  }
  
  FILE_GLOBAL_WRITE_LEN("set execute_dmac5_command_0x49_05b38698\n");

  res = module_get_export_func(KERNEL_PID, "SceSblSsMgr", SceSblSsMgrForDriver_NID, 0x926bccf0, (uintptr_t*)&execute_dmac5_command_0x4A_926bccf0);
  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to set execute_dmac5_command_0x4A_926bccf0 : %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
    return -1;
  }
  
  FILE_GLOBAL_WRITE_LEN("set execute_dmac5_command_0x4A_926bccf0\n");

  res = module_get_export_func(KERNEL_PID, "SceSblSsMgr", SceSblSsMgrForDriver_NID, 0xc517770d, (uintptr_t*)&execute_dmac5_command_0x01_c517770d);
  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to set execute_dmac5_command_0x01_c517770d : %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
    return -1;
  }
  
  FILE_GLOBAL_WRITE_LEN("set execute_dmac5_command_0x01_c517770d\n");

  res = module_get_export_func(KERNEL_PID, "SceSblSsMgr", SceSblSsMgrForDriver_NID, 0x7c978be7, (uintptr_t*)&execute_dmac5_command_0x02_7c978be7);
  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to set execute_dmac5_command_0x02_7c978be7 : %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
    return -1;
  }
  
  FILE_GLOBAL_WRITE_LEN("set execute_dmac5_command_0x02_7c978be7\n");

  res = module_get_export_func(KERNEL_PID, "SceSblSsMgr", SceSblSsMgrForDriver_NID, 0x0f7d28af, (uintptr_t*)&execute_dmac5_command_0x01_0f7d28af);
  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to set execute_dmac5_command_0x01_0f7d28af : %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
    return -1;
  }
  
  FILE_GLOBAL_WRITE_LEN("set execute_dmac5_command_0x01_0f7d28af\n");

  res = module_get_export_func(KERNEL_PID, "SceSblSsMgr", SceSblSsMgrForDriver_NID, 0x197acf6f, (uintptr_t*)&execute_dmac5_command_0x02_197acf6f);
  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to set execute_dmac5_command_0x02_197acf6f : %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
    return -1;
  }
  
  FILE_GLOBAL_WRITE_LEN("set execute_dmac5_command_0x02_197acf6f\n");

  res = module_get_export_func(KERNEL_PID, "SceSblSsMgr", SceSblSsMgrForDriver_NID, 0xe6e1ad15, (uintptr_t*)&execute_dmac5_command_0x09_e6e1ad15);
  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to set execute_dmac5_command_0x09_e6e1ad15 : %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
    return -1;
  }
  
  FILE_GLOBAL_WRITE_LEN("set execute_dmac5_command_0x09_e6e1ad15\n");

  res = module_get_export_func(KERNEL_PID, "SceSblSsMgr", SceSblSsMgrForDriver_NID, 0x121fa69f, (uintptr_t*)&execute_dmac5_command_0x0A_121fa69f);
  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to set execute_dmac5_command_0x0A_121fa69f : %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
    return -1;
  }
  
  FILE_GLOBAL_WRITE_LEN("set execute_dmac5_command_0x0A_121fa69f\n");

  res = module_get_export_func(KERNEL_PID, "SceSblSsMgr", SceSblSsMgrForDriver_NID, 0x711c057a, (uintptr_t*)&execute_dmac5_command_0x09_711c057a);
  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to set execute_dmac5_command_0x09_711c057a : %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
    return -1;
  }
  
  FILE_GLOBAL_WRITE_LEN("set execute_dmac5_command_0x09_711c057a\n");
  
  res = module_get_export_func(KERNEL_PID, "SceSblSsMgr", SceSblSsMgrForDriver_NID, 0x1901cb5e, (uintptr_t*)&execute_dmac5_command_0x0A_1901cb5e);
  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to set execute_dmac5_command_0x0A_1901cb5e : %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
    return -1;
  }
  
  FILE_GLOBAL_WRITE_LEN("set execute_dmac5_command_0x0A_1901cb5e\n");

  res = module_get_export_func(KERNEL_PID, "SceSblSsMgr", SceSblSsMgrForDriver_NID, 0xeb3af9b5, (uintptr_t*)&execute_dmac5_command_0x03_eb3af9b5);
  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to set execute_dmac5_command_0x03_eb3af9b5 : %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
    return -1;
  }
  
  FILE_GLOBAL_WRITE_LEN("set execute_dmac5_command_0x03_eb3af9b5\n");

  res = module_get_export_func(KERNEL_PID, "SceSblSsMgr", SceSblSsMgrForDriver_NID, 0x6704d985, (uintptr_t*)&execute_dmac5_command_0x23_6704d985);
  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to set execute_dmac5_command_0x23_6704d985 : %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
    return -1;
  }
  
  FILE_GLOBAL_WRITE_LEN("set execute_dmac5_command_0x23_6704d985\n");

  res = module_get_export_func(KERNEL_PID, "SceSblSsMgr", SceSblSsMgrForDriver_NID, 0x79f38554, (uintptr_t*)&execute_dmac5_command_0x33_79f38554);
  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to set execute_dmac5_command_0x33_79f38554 : %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
    return -1;
  }
  
  FILE_GLOBAL_WRITE_LEN("set execute_dmac5_command_0x33_79f38554\n");

  res = module_get_export_func(KERNEL_PID, "SceSblSsMgr", SceSblSsMgrForDriver_NID, 0x1b14658d, (uintptr_t*)&execute_dmac5_command_0x3B_1b14658d);
  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to set execute_dmac5_command_0x3B_1b14658d : %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
    return -1;
  }
  
  FILE_GLOBAL_WRITE_LEN("set execute_dmac5_command_0x3B_1b14658d\n");

  res = module_get_export_func(KERNEL_PID, "SceSblSsMgr", SceSblSsMgrForDriver_NID, 0xea6acb6d, (uintptr_t*)&execute_dmac5_command_0x3B_ea6acb6d);
  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to set execute_dmac5_command_0x3B_ea6acb6d : %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
    return -1;
  }
  
  FILE_GLOBAL_WRITE_LEN("set execute_dmac5_command_0x3B_ea6acb6d\n");

  res = module_get_export_func(KERNEL_PID, "SceSblSsMgr", SceSblSsMgrForDriver_NID, 0x83b058f5, (uintptr_t*)&execute_dmac5_command_0x3B_83b058f5);
  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to set execute_dmac5_command_0x3B_83b058f5 : %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
    return -1;
  }
  
  FILE_GLOBAL_WRITE_LEN("set execute_dmac5_command_0x3B_83b058f5\n");

  res = module_get_export_func(KERNEL_PID, "SceSblSsMgr", SceSblSsMgrForDriver_NID, 0x92e37656, (uintptr_t*)&execute_dmac5_command_0x23_92e37656);
  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to set execute_dmac5_command_0x23_92e37656 : %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
    return -1;
  }
  
  FILE_GLOBAL_WRITE_LEN("set execute_dmac5_command_0x23_92e37656\n");

  res = module_get_export_func(KERNEL_PID, "SceSblSsMgr", SceSblSsMgrForDriver_NID, 0x82b5dcef, (uintptr_t*)&execute_dmac5_command_0x21_82b5dcef);
  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to set execute_dmac5_command_0x21_82b5dcef : %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
    return -1;
  }
  
  FILE_GLOBAL_WRITE_LEN("set execute_dmac5_command_0x21_82b5dcef\n");

  res = module_get_export_func(KERNEL_PID, "SceSblSsMgr", SceSblSsMgrForDriver_NID, 0x7d46768c, (uintptr_t*)&execute_dmac5_command_0x22_7d46768c);
  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to set execute_dmac5_command_0x22_7d46768c : %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
    return -1;
  }
  
  FILE_GLOBAL_WRITE_LEN("set execute_dmac5_command_0x22_7d46768c\n");

  return 0;
}

//==========================================

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

//===========================================

SceUID slot_table_start_patch = -1;
SceUID slot_table_end_patch = -1;

int enable_slot_table_patches()
{
  tai_module_info_t sbl_ss_mgr_info;
  sbl_ss_mgr_info.size = sizeof(tai_module_info_t);
  if(taiGetModuleInfoForKernel(KERNEL_PID, "SceSblSsMgr", &sbl_ss_mgr_info) >= 0)
  {
    char start_patch[2] = {0x12, 0x25};
    slot_table_start_patch = taiInjectDataForKernel(KERNEL_PID, sbl_ss_mgr_info.modid, 0, 0x00B9A882 - 0x00B98000, start_patch, 2); //patch MOVS R5, #0xC to MOVS R5, #0x12

    char end_patch[2] = {0x1E, 0x2D};
    slot_table_end_patch = taiInjectDataForKernel(KERNEL_PID, sbl_ss_mgr_info.modid, 0, 0x00B9A8A6 - 0x00B98000, end_patch, 2); //patch CMP R5, #0x18 to CMP R5, #0x1E
  }

  return 0;
}

int disable_slot_table_patches()
{
  if(slot_table_start_patch >=0)
  {
    taiInjectReleaseForKernel(slot_table_start_patch);
    slot_table_start_patch = -1;
  }

  if(slot_table_end_patch >=0)
  {
    taiInjectReleaseForKernel(slot_table_end_patch);
    slot_table_end_patch = -1;
  }

  return 0;
}

//===========================================

int disable_key_slot(int slot_id)
{
  if(slot_id < 0x12)
    return -1;

  int rel_slot_idx = slot_id - 0x12;

  tai_module_info_t info;
  info.size = sizeof(tai_module_info_t);
  if (taiGetModuleInfoForKernel(KERNEL_PID, "SceSblSsMgr", &info) >= 0)
  {
    uintptr_t addr = 0;
    int ofstRes = module_get_offset(KERNEL_PID, info.modid, 1, 0x44 + 0x234 + rel_slot_idx * 0x2C, &addr);
    if(ofstRes == 0)
    {
      *((char*)addr) = 1;
    }
  }

  return 0;
}

int enable_key_slot(int slot_id)
{
  if(slot_id < 0x12)
    return -1;

  int rel_slot_idx = slot_id - 0x12;

  tai_module_info_t info;
  info.size = sizeof(tai_module_info_t);
  if (taiGetModuleInfoForKernel(KERNEL_PID, "SceSblSsMgr", &info) >= 0)
  {
    uintptr_t addr = 0;
    int ofstRes = module_get_offset(KERNEL_PID, info.modid, 1, 0x44 + 0x234 + rel_slot_idx * 0x2C, &addr);
    if(ofstRes == 0)
    {
      *((char*)addr) = 0;
    }
  }

  return 0;
}

//============================================

int test_dmac5_1_2_128_slot()
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
    snprintf(sprintfBuffer, 256, "executed dmac5 cmd 1 for slot : %x\n", DMAC5_KEYRING_KEY_1D);
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

  char dec[0x40];
  memset(dec, 0, 0x40);

  res = execute_dmac5_command_0x02_8b4700cb(output, dec, 0x20, DMAC5_KEYRING_KEY_1D, 0x80, 1);
  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to execute_dmac5_command_0x02_8b4700cb : %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
  }
  else
  {
    snprintf(sprintfBuffer, 256, "executed dmac5 cmd 2 for slot : %x\n", DMAC5_KEYRING_KEY_1D);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
  }

  if(memcmp(dec, input, 0x20) == 0)
  {
    FILE_GLOBAL_WRITE_LEN("Confirmed AES-128-ECB decrypt\n");
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("Unexpected result\n");
  }

  return 0;
}

int test_dmac5_1_2_192_slot()
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

  res = execute_dmac5_command_0x01_01be0374(input, output, size, DMAC5_KEYRING_KEY_1D, 0xC0, 1);
  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to execute_dmac5_command_0x01_01be0374 : %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
  }
  else
  {
    snprintf(sprintfBuffer, 256, "executed dmac5 cmd 1 for slot : %x\n", DMAC5_KEYRING_KEY_1D);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
  }

  char expected[0x20] = {0x56,	0xf1,	0xd6,	0xc9,	0xde,	0x42,	0x5b,	0xa0,	0xa0,	0x8f,	0x9f,	0xad,	0xd1,	0x98,	0x6e,	0xe5,
                         0x64,	0x1b,	0xc3,	0x72,	0x9c,	0x3b,	0x02,	0x37,	0x57,	0xf4,	0xf9,	0x0e,	0x25,	0xec,	0x79,	0x20,};

  if(memcmp(expected, output, 0x20) == 0)
  {
    FILE_GLOBAL_WRITE_LEN("Confirmed AES-192-ECB encrypt\n");
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("Unexpected result\n");
  }

  char dec[0x40];
  memset(dec, 0, 0x40);

  res = execute_dmac5_command_0x02_8b4700cb(output, dec, 0x20, DMAC5_KEYRING_KEY_1D, 0xC0, 1);
  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to execute_dmac5_command_0x02_8b4700cb : %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
  }
  else
  {
    snprintf(sprintfBuffer, 256, "executed dmac5 cmd 2 for slot : %x\n", DMAC5_KEYRING_KEY_1D);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
  }

  if(memcmp(dec, input, 0x20) == 0)
  {
    FILE_GLOBAL_WRITE_LEN("Confirmed AES-192-ECB decrypt\n");
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("Unexpected result\n");
  }

  return 0;
}

int test_dmac5_1_2_256_slot()
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

  res = execute_dmac5_command_0x01_01be0374(input, output, size, DMAC5_KEYRING_KEY_1D, 0x100, 1);
  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to execute_dmac5_command_0x01_01be0374 : %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
  }
  else
  {
    snprintf(sprintfBuffer, 256, "executed dmac5 cmd 1 for slot : %x\n", DMAC5_KEYRING_KEY_1D);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
  }

  char expected[0x20] = {0x24,	0x72,	0xbe,	0x98,	0x0c,	0x96,	0x02,	0xea,	0x59,	0x94,	0x28,	0x5f,	0x61,	0x3b,	0xca,	0xa0,
                         0x51,	0x99,	0xa1,	0x05,	0x5d,	0x69,	0x1e,	0x57,	0x70,	0xa5,	0x87,	0xa4,	0x6a,	0xc1,	0x60,	0x69,};

  if(memcmp(expected, output, 0x20) == 0)
  {
    FILE_GLOBAL_WRITE_LEN("Confirmed AES-256-ECB encrypt\n");
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("Unexpected result\n");
  }

  char dec[0x40];
  memset(dec, 0, 0x40);

  res = execute_dmac5_command_0x02_8b4700cb(output, dec, 0x20, DMAC5_KEYRING_KEY_1D, 0x100, 1);
  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to execute_dmac5_command_0x02_8b4700cb : %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
  }
  else
  {
    snprintf(sprintfBuffer, 256, "executed dmac5 cmd 2 for slot : %x\n", DMAC5_KEYRING_KEY_1D);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
  }

  if(memcmp(dec, input, 0x20) == 0)
  {
    FILE_GLOBAL_WRITE_LEN("Confirmed AES-256-ECB decrypt\n");
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("Unexpected result\n");
  }

  return 0;
}

//============================================

int test_dmac5_1_2_128_key()
{
  char key[0x20] = {0};

  char* input = "The gray fox jumped over the dog";
  char output[0x40];
  memset(output, 0, 0x40);

  int size = strnlen(input, 0x40);

  int res = execute_dmac5_command_0x01_c517770d(input, output, size, key, 0x80, 1);
  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to execute_dmac5_command_0x01_c517770d : %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("executed dmac5 cmd 1\n");
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

  char dec[0x40];
  memset(dec, 0, 0x40);

  res = execute_dmac5_command_0x02_7c978be7(output, dec, 0x20, key, 0x80, 1);
  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to execute_dmac5_command_0x02_7c978be7 : %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("executed dmac5 cmd 2\n");
  }

  if(memcmp(dec, input, 0x20) == 0)
  {
    FILE_GLOBAL_WRITE_LEN("Confirmed AES-128-ECB decrypt\n");
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("Unexpected result\n");
  }

  return 0;
}

int test_dmac5_1_2_192_key()
{
  char key[0x20] = {0};

  char* input = "The gray fox jumped over the dog";
  char output[0x40];
  memset(output, 0, 0x40);

  int size = strnlen(input, 0x40);

  int res = execute_dmac5_command_0x01_c517770d(input, output, size, key, 0xC0, 1);
  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to execute_dmac5_command_0x01_c517770d : %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("executed dmac5 cmd 1\n");
  }

  char expected[0x20] = {0x56,	0xf1,	0xd6,	0xc9,	0xde,	0x42,	0x5b,	0xa0,	0xa0,	0x8f,	0x9f,	0xad,	0xd1,	0x98,	0x6e,	0xe5,
                         0x64,	0x1b,	0xc3,	0x72,	0x9c,	0x3b,	0x02,	0x37,	0x57,	0xf4,	0xf9,	0x0e,	0x25,	0xec,	0x79,	0x20,};

  if(memcmp(expected, output, 0x20) == 0)
  {
    FILE_GLOBAL_WRITE_LEN("Confirmed AES-192-ECB encrypt\n");
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("Unexpected result\n");
  }

  char dec[0x40];
  memset(dec, 0, 0x40);

  res = execute_dmac5_command_0x02_7c978be7(output, dec, 0x20, key, 0xC0, 1);
  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to execute_dmac5_command_0x02_7c978be7 : %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("executed dmac5 cmd 2\n");
  }

  if(memcmp(dec, input, 0x20) == 0)
  {
    FILE_GLOBAL_WRITE_LEN("Confirmed AES-192-ECB decrypt\n");
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("Unexpected result\n");
  }

  return 0;
}

int test_dmac5_1_2_256_key()
{
  char key[0x20] = {0};

  char* input = "The gray fox jumped over the dog";
  char output[0x40];
  memset(output, 0, 0x40);

  int size = strnlen(input, 0x40);

  int res = execute_dmac5_command_0x01_c517770d(input, output, size, key, 0x100, 1);
  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to execute_dmac5_command_0x01_c517770d : %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("executed dmac5 cmd 1\n");
  }

  char expected[0x20] = {0x24,	0x72,	0xbe,	0x98,	0x0c,	0x96,	0x02,	0xea,	0x59,	0x94,	0x28,	0x5f,	0x61,	0x3b,	0xca,	0xa0,
                         0x51,	0x99,	0xa1,	0x05,	0x5d,	0x69,	0x1e,	0x57,	0x70,	0xa5,	0x87,	0xa4,	0x6a,	0xc1,	0x60,	0x69,};

  if(memcmp(expected, output, 0x20) == 0)
  {
    FILE_GLOBAL_WRITE_LEN("Confirmed AES-256-ECB encrypt\n");
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("Unexpected result\n");
  }

  char dec[0x40];
  memset(dec, 0, 0x40);

  res = execute_dmac5_command_0x02_7c978be7(output, dec, 0x20, key, 0x100, 1);
  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to execute_dmac5_command_0x02_7c978be7 : %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("executed dmac5 cmd 2\n");
  }

  if(memcmp(dec, input, 0x20) == 0)
  {
    FILE_GLOBAL_WRITE_LEN("Confirmed AES-256-ECB decrypt\n");
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("Unexpected result\n");
  }

  return 0;
}

//============================================

int g_disable_set_key = 0;
char g_key[0x20] = {0};
int g_key_index = 0;

#define DMAC5_KEY_ID_0 0

//if we would want to test this crypto function we need to hook sceSblAuthMgrSetDmac5Key and set our key here
//however by default - 0xC slot_id is used. and max slot is 0x17
//then slot_id is returned from the wrapper function and used everywhere
//this is 0xC-0x17 is an unchangeable range of slots
//however this range can be patched

int enable_1d_slot_id(char* key)
{
  //first we change slot id range
  enable_slot_table_patches();

  //then way to go around is to disable all key slots till 0x1D
  for(int i = 0x12; i < DMAC5_KEYRING_KEY_1D; i++)
    disable_key_slot(i);

  //then we indicate to the hook that defalt set key behavior should be overrided
  //with specified key and slot id
  g_disable_set_key = 1;
  memcpy(g_key, key, 0x20);
  g_key_index = DMAC5_KEYRING_KEY_1D;

  return 0;
}

int disable_1d_slot_id()
{
  g_disable_set_key = 0;
  
  //enable slots back
  for(int i = 0x12; i < DMAC5_KEYRING_KEY_1D; i++)
    enable_key_slot(i);

  //restore slot id range
  disable_slot_table_patches();

  return 0;
}

int test_dmac5_1_2_128_key_id()
{
  char key[0x20] = {0};

  char* input = "The gray fox jumped over the dog";
  char output[0x40];
  memset(output, 0, 0x40);

  int size = strnlen(input, 0x40);

  enable_1d_slot_id(key);

  int res = execute_dmac5_command_0x01_0f7d28af(input, output, size, key, 0x80, DMAC5_KEY_ID_0, 1);
  
  disable_1d_slot_id();

  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to execute_dmac5_command_0x01_0f7d28af : %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("executed dmac5 cmd 1\n");
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

  char dec[0x40];
  memset(dec, 0, 0x40);

  enable_1d_slot_id(key);

  res = execute_dmac5_command_0x02_197acf6f(output, dec, 0x20, key, 0x80, DMAC5_KEY_ID_0, 1);

  disable_1d_slot_id();

  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to execute_dmac5_command_0x02_197acf6f : %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("executed dmac5 cmd 2\n");
  }

  if(memcmp(dec, input, 0x20) == 0)
  {
    FILE_GLOBAL_WRITE_LEN("Confirmed AES-128-ECB decrypt\n");
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("Unexpected result\n");
  }

  return 0;
}

int test_dmac5_1_2_192_key_id()
{
  char key[0x20] = {0};

  char* input = "The gray fox jumped over the dog";
  char output[0x40];
  memset(output, 0, 0x40);

  int size = strnlen(input, 0x40);

  enable_1d_slot_id(key);

  int res = execute_dmac5_command_0x01_0f7d28af(input, output, size, key, 0xC0, DMAC5_KEY_ID_0, 1);
  
  disable_1d_slot_id();

  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to execute_dmac5_command_0x01_0f7d28af : %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("executed dmac5 cmd 1\n");
  }

  char expected[0x20] = {0x56,	0xf1,	0xd6,	0xc9,	0xde,	0x42,	0x5b,	0xa0,	0xa0,	0x8f,	0x9f,	0xad,	0xd1,	0x98,	0x6e,	0xe5,
                         0x64,	0x1b,	0xc3,	0x72,	0x9c,	0x3b,	0x02,	0x37,	0x57,	0xf4,	0xf9,	0x0e,	0x25,	0xec,	0x79,	0x20,};

  if(memcmp(expected, output, 0x20) == 0)
  {
    FILE_GLOBAL_WRITE_LEN("Confirmed AES-192-ECB encrypt\n");
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("Unexpected result\n");
  }  

  char dec[0x40];
  memset(dec, 0, 0x40);

  enable_1d_slot_id(key);

  res = execute_dmac5_command_0x02_197acf6f(output, dec, 0x20, key, 0xC0, DMAC5_KEY_ID_0, 1);

  disable_1d_slot_id();

  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to execute_dmac5_command_0x02_197acf6f : %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("executed dmac5 cmd 2\n");
  }

  if(memcmp(dec, input, 0x20) == 0)
  {
    FILE_GLOBAL_WRITE_LEN("Confirmed AES-192-ECB decrypt\n");
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("Unexpected result\n");
  }

  return 0;
}

int test_dmac5_1_2_256_key_id()
{
  char key[0x20] = {0};

  char* input = "The gray fox jumped over the dog";
  char output[0x40];
  memset(output, 0, 0x40);

  int size = strnlen(input, 0x40);

  enable_1d_slot_id(key);

  int res = execute_dmac5_command_0x01_0f7d28af(input, output, size, key, 0x100, DMAC5_KEY_ID_0, 1);
  
  disable_1d_slot_id();

  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to execute_dmac5_command_0x01_0f7d28af : %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("executed dmac5 cmd 1\n");
  }

  char expected[0x20] = {0x24,	0x72,	0xbe,	0x98,	0x0c,	0x96,	0x02,	0xea,	0x59,	0x94,	0x28,	0x5f,	0x61,	0x3b,	0xca,	0xa0,
                         0x51,	0x99,	0xa1,	0x05,	0x5d,	0x69,	0x1e,	0x57,	0x70,	0xa5,	0x87,	0xa4,	0x6a,	0xc1,	0x60,	0x69,};

  if(memcmp(expected, output, 0x20) == 0)
  {
    FILE_GLOBAL_WRITE_LEN("Confirmed AES-256-ECB encrypt\n");
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("Unexpected result\n");
  }  

  char dec[0x40];
  memset(dec, 0, 0x40);

  enable_1d_slot_id(key);

  res = execute_dmac5_command_0x02_197acf6f(output, dec, 0x20, key, 0x100, DMAC5_KEY_ID_0, 1);

  disable_1d_slot_id();

  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to execute_dmac5_command_0x02_197acf6f : %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("executed dmac5 cmd 2\n");
  }

  if(memcmp(dec, input, 0x20) == 0)
  {
    FILE_GLOBAL_WRITE_LEN("Confirmed AES-256-ECB decrypt\n");
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("Unexpected result\n");
  }

  return 0;
}

//============================================

int test_dmac5_9_A_128_key()
{
  char key[0x20] = {0};

  char* input = "The gray fox jumped over the dog";
  char output[0x40];
  memset(output, 0, 0x40);

  int size = strnlen(input, 0x40);

  char iv[0x10];
  memset(iv, 0, 0x10);
  iv[0] = 1;

  int res = execute_dmac5_command_0x09_e6e1ad15(input, output, size, key, 0x80, iv, 1);
  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to execute_dmac5_command_0x09_e6e1ad15 : %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("executed dmac5 cmd 9\n");
  }

  char expected[0x20] = {0x05,	0x4b,	0x05,	0xc1,	0x41,	0xa6,	0xcc,	0xad,	0x7b,	0xc6,	0xef,	0x41,	0x5c,	0x14,	0x16,	0x6b,
                         0xa8,	0xcd,	0x83,	0x6f,	0x06,	0xec,	0x92,	0x0b,	0xae,	0x00,	0x34,	0xd2,	0xf9,	0xb6,	0xf4,	0x45,};

  if(memcmp(expected, output, 0x20) == 0)
  {
    FILE_GLOBAL_WRITE_LEN("Confirmed AES-128-CBC encrypt\n");
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("Unexpected result\n");
  }  

  char dec[0x40];
  memset(dec, 0, 0x40);

  //have to set again - it will be changed
  memset(iv, 0, 0x10);
  iv[0] = 1;

  res = execute_dmac5_command_0x0A_121fa69f(output, dec, 0x20, key, 0x80, iv, 1);
  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to execute_dmac5_command_0x0A_121fa69f : %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("executed dmac5 cmd A\n");
  }

  if(memcmp(dec, input, 0x20) == 0)
  {
    FILE_GLOBAL_WRITE_LEN("Confirmed AES-128-CBC decrypt\n");
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("Unexpected result\n");
  }

  return 0;
}

int test_dmac5_9_A_192_key()
{
  char key[0x20] = {0};
  
    char* input = "The gray fox jumped over the dog";
    char output[0x40];
    memset(output, 0, 0x40);
  
    int size = strnlen(input, 0x40);
  
    char iv[0x10];
    memset(iv, 0, 0x10);
    iv[0] = 1;
  
    int res = execute_dmac5_command_0x09_e6e1ad15(input, output, size, key, 0xC0, iv, 1);
    if(res < 0)
    {
      snprintf(sprintfBuffer, 256, "failed to execute_dmac5_command_0x09_e6e1ad15 : %x\n", res);
      FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
    }
    else
    {
      FILE_GLOBAL_WRITE_LEN("executed dmac5 cmd 9\n");
    }
  
    char expected[0x20] = {0x61,	0xa9,	0x4c,	0xa8,	0xfa,	0xdd,	0x5d,	0xa9,	0xc0,	0x7b,	0xd0,	0xd4,	0xdc,	0x52,	0x53,	0x78,
                           0xf2,	0x6d,	0x47,	0xea,	0x74,	0xcf,	0xaa,	0x94,	0x5b,	0xea,	0x34,	0xc2,	0x2e,	0x68,	0x0c,	0xf0,};
  
    if(memcmp(expected, output, 0x20) == 0)
    {
      FILE_GLOBAL_WRITE_LEN("Confirmed AES-192-CBC encrypt\n");
    }
    else
    {
      FILE_GLOBAL_WRITE_LEN("Unexpected result\n");
    }  
  
    char dec[0x40];
    memset(dec, 0, 0x40);
  
    //have to set again - it will be changed
    memset(iv, 0, 0x10);
    iv[0] = 1;
  
    res = execute_dmac5_command_0x0A_121fa69f(output, dec, 0x20, key, 0xC0, iv, 1);
    if(res < 0)
    {
      snprintf(sprintfBuffer, 256, "failed to execute_dmac5_command_0x0A_121fa69f : %x\n", res);
      FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
    }
    else
    {
      FILE_GLOBAL_WRITE_LEN("executed dmac5 cmd A\n");
    }
  
    if(memcmp(dec, input, 0x20) == 0)
    {
      FILE_GLOBAL_WRITE_LEN("Confirmed AES-192-CBC decrypt\n");
    }
    else
    {
      FILE_GLOBAL_WRITE_LEN("Unexpected result\n");
    }
  
    return 0;
}

int test_dmac5_9_A_256_key()
{
  char key[0x20] = {0};
  
    char* input = "The gray fox jumped over the dog";
    char output[0x40];
    memset(output, 0, 0x40);
  
    int size = strnlen(input, 0x40);
  
    char iv[0x10];
    memset(iv, 0, 0x10);
    iv[0] = 1;
  
    int res = execute_dmac5_command_0x09_e6e1ad15(input, output, size, key, 0x100, iv, 1);
    if(res < 0)
    {
      snprintf(sprintfBuffer, 256, "failed to execute_dmac5_command_0x09_e6e1ad15 : %x\n", res);
      FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
    }
    else
    {
      FILE_GLOBAL_WRITE_LEN("executed dmac5 cmd 9\n");
    }
  
    char expected[0x20] = {0x5a,	0xbd,	0x1e,	0x26,	0xbd,	0xe4,	0xa1,	0x66,	0x31,	0x8d,	0x6c,	0x2a,	0xa0,	0x8f,	0xb5,	0x7c,
                           0xc1,	0xea,	0xfc,	0xf7,	0x16,	0x86,	0xeb,	0x7a,	0xfb,	0x39,	0xa6,	0xd6,	0xe1,	0x61,	0x9d,	0x1e,};
  
    if(memcmp(expected, output, 0x20) == 0)
    {
      FILE_GLOBAL_WRITE_LEN("Confirmed AES-256-CBC encrypt\n");
    }
    else
    {
      FILE_GLOBAL_WRITE_LEN("Unexpected result\n");
    }  
  
    char dec[0x40];
    memset(dec, 0, 0x40);
  
    //have to set again - it will be changed
    memset(iv, 0, 0x10);
    iv[0] = 1;
  
    res = execute_dmac5_command_0x0A_121fa69f(output, dec, 0x20, key, 0x100, iv, 1);
    if(res < 0)
    {
      snprintf(sprintfBuffer, 256, "failed to execute_dmac5_command_0x0A_121fa69f : %x\n", res);
      FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
    }
    else
    {
      FILE_GLOBAL_WRITE_LEN("executed dmac5 cmd A\n");
    }
  
    if(memcmp(dec, input, 0x20) == 0)
    {
      FILE_GLOBAL_WRITE_LEN("Confirmed AES-256-CBC decrypt\n");
    }
    else
    {
      FILE_GLOBAL_WRITE_LEN("Unexpected result\n");
    }
  
    return 0;
}

//============================================

int test_dmac5_9_A_128_key_id()
{
  char key[0x20] = {0};
  
  char* input = "The gray fox jumped over the dog";
  char output[0x40];
  memset(output, 0, 0x40);

  int size = strnlen(input, 0x40);

  char iv[0x10];
  memset(iv, 0, 0x10);
  iv[0] = 1;

  enable_1d_slot_id(key);

  int res = execute_dmac5_command_0x09_711c057a(input, output, size, key, 0x80, iv, DMAC5_KEY_ID_0, 1);

  disable_1d_slot_id();

  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to execute_dmac5_command_0x09_711c057a : %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("executed dmac5 cmd 9\n");
  }

  char expected[0x20] = {0x05,	0x4b,	0x05,	0xc1,	0x41,	0xa6,	0xcc,	0xad,	0x7b,	0xc6,	0xef,	0x41,	0x5c,	0x14,	0x16,	0x6b,
                         0xa8,	0xcd,	0x83,	0x6f,	0x06,	0xec,	0x92,	0x0b,	0xae,	0x00,	0x34,	0xd2,	0xf9,	0xb6,	0xf4,	0x45,};

  if(memcmp(expected, output, 0x20) == 0)
  {
    FILE_GLOBAL_WRITE_LEN("Confirmed AES-128-CBC encrypt\n");
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("Unexpected result\n");
  }  

  char dec[0x40];
  memset(dec, 0, 0x40);

  //have to set again - it will be changed
  memset(iv, 0, 0x10);
  iv[0] = 1;

  enable_1d_slot_id(key);

  res = execute_dmac5_command_0x0A_1901cb5e(output, dec, 0x20, key, 0x80, iv, DMAC5_KEY_ID_0, 1);

  disable_1d_slot_id();

  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to execute_dmac5_command_0x0A_1901cb5e : %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("executed dmac5 cmd A\n");
  }

  if(memcmp(dec, input, 0x20) == 0)
  {
    FILE_GLOBAL_WRITE_LEN("Confirmed AES-128-CBC decrypt\n");
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("Unexpected result\n");
  }

  return 0;
}

int test_dmac5_9_A_192_key_id()
{
  char key[0x20] = {0};
  
  char* input = "The gray fox jumped over the dog";
  char output[0x40];
  memset(output, 0, 0x40);

  int size = strnlen(input, 0x40);

  char iv[0x10];
  memset(iv, 0, 0x10);
  iv[0] = 1;

  enable_1d_slot_id(key);

  int res = execute_dmac5_command_0x09_711c057a(input, output, size, key, 0xC0, iv, DMAC5_KEY_ID_0, 1);

  disable_1d_slot_id();

  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to execute_dmac5_command_0x09_711c057a : %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("executed dmac5 cmd 9\n");
  }

  char expected[0x20] = {0x61,	0xa9,	0x4c,	0xa8,	0xfa,	0xdd,	0x5d,	0xa9,	0xc0,	0x7b,	0xd0,	0xd4,	0xdc,	0x52,	0x53,	0x78,
                         0xf2,	0x6d,	0x47,	0xea,	0x74,	0xcf,	0xaa,	0x94,	0x5b,	0xea,	0x34,	0xc2,	0x2e,	0x68,	0x0c,	0xf0,};

  if(memcmp(expected, output, 0x20) == 0)
  {
    FILE_GLOBAL_WRITE_LEN("Confirmed AES-192-CBC encrypt\n");
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("Unexpected result\n");
  }  

  char dec[0x40];
  memset(dec, 0, 0x40);

  //have to set again - it will be changed
  memset(iv, 0, 0x10);
  iv[0] = 1;

  enable_1d_slot_id(key);

  res = execute_dmac5_command_0x0A_1901cb5e(output, dec, 0x20, key, 0xC0, iv, DMAC5_KEY_ID_0, 1);

  disable_1d_slot_id();

  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to execute_dmac5_command_0x0A_1901cb5e : %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("executed dmac5 cmd A\n");
  }

  if(memcmp(dec, input, 0x20) == 0)
  {
    FILE_GLOBAL_WRITE_LEN("Confirmed AES-192-CBC decrypt\n");
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("Unexpected result\n");
  }

  return 0;
}

int test_dmac5_9_A_256_key_id()
{
  char key[0x20] = {0};
  
  char* input = "The gray fox jumped over the dog";
  char output[0x40];
  memset(output, 0, 0x40);

  int size = strnlen(input, 0x40);

  char iv[0x10];
  memset(iv, 0, 0x10);
  iv[0] = 1;

  enable_1d_slot_id(key);

  int res = execute_dmac5_command_0x09_711c057a(input, output, size, key, 0x100, iv, DMAC5_KEY_ID_0, 1);

  disable_1d_slot_id();

  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to execute_dmac5_command_0x09_711c057a : %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("executed dmac5 cmd 9\n");
  }

  char expected[0x20] = {0x5a,	0xbd,	0x1e,	0x26,	0xbd,	0xe4,	0xa1,	0x66,	0x31,	0x8d,	0x6c,	0x2a,	0xa0,	0x8f,	0xb5,	0x7c,
                         0xc1,	0xea,	0xfc,	0xf7,	0x16,	0x86,	0xeb,	0x7a,	0xfb,	0x39,	0xa6,	0xd6,	0xe1,	0x61,	0x9d,	0x1e,};

  if(memcmp(expected, output, 0x20) == 0)
  {
    FILE_GLOBAL_WRITE_LEN("Confirmed AES-256-CBC encrypt\n");
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("Unexpected result\n");
  }  

  char dec[0x40];
  memset(dec, 0, 0x40);

  //have to set again - it will be changed
  memset(iv, 0, 0x10);
  iv[0] = 1;

  enable_1d_slot_id(key);

  res = execute_dmac5_command_0x0A_1901cb5e(output, dec, 0x20, key, 0x100, iv, DMAC5_KEY_ID_0, 1);

  disable_1d_slot_id();

  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to execute_dmac5_command_0x0A_1901cb5e : %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("executed dmac5 cmd A\n");
  }

  if(memcmp(dec, input, 0x20) == 0)
  {
    FILE_GLOBAL_WRITE_LEN("Confirmed AES-256-CBC decrypt\n");
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("Unexpected result\n");
  }

  return 0;
}

//============================================

int test_dmac5_41_42()
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

  res = execute_dmac5_command_0x41_37dd5cbf(input, output, size, DMAC5_KEYRING_KEY_1D, 0xC0, 1);
  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to execute_dmac5_command_0x41_37dd5cbf : %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
  }
  else
  {
    snprintf(sprintfBuffer, 256, "executed dmac5 cmd 41 for slot : %x\n", DMAC5_KEYRING_KEY_1D);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
  }

  char expected[0x20] = {0x93,	0x64,	0x35,	0x52,	0x08,	0xb8,	0x5e,	0xb2,	0xe8,	0xd0,	0x6d,	0xba,	0x0c,	0x81,	0x55,	0x0d,
                         0x47,	0xee,	0xa3,	0x74,	0x2e,	0x56,	0xe7,	0x36,	0x41,	0x00,	0x7f,	0x7c,	0xf7,	0x92,	0x92,	0x7e,};

  if(memcmp(expected, output, 0x20) == 0)
  {
    FILE_GLOBAL_WRITE_LEN("Confirmed DES-64-ECB encrypt\n");
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("Unexpected result\n");
  }

  print_bytes(output, 0x40);

  char dec[0x40];
  memset(dec, 0, 0x40);

  res = execute_dmac5_command_0x42_8eafb18a(output, dec, 0x20, DMAC5_KEYRING_KEY_1D, 0xC0, 1);
  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to execute_dmac5_command_0x42_8eafb18a : %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
  }
  else
  {
    snprintf(sprintfBuffer, 256, "executed dmac5 cmd 42 for slot : %x\n", DMAC5_KEYRING_KEY_1D);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
  }

  if(memcmp(dec, input, 0x20) == 0)
  {
    FILE_GLOBAL_WRITE_LEN("Confirmed DES-64-ECB decrypt\n");
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("Unexpected result\n");
  }

  return 0;
}

int test_dmac5_49_4A()
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

  char iv[8];
  memset(iv, 0, 0x8);
  iv[0] = 1;

  res = execute_dmac5_command_0x49_05b38698(input, output, size, DMAC5_KEYRING_KEY_1D, 0xC0, iv, 1);
  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to execute_dmac5_command_0x49_05b38698 : %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
  }
  else
  {
    snprintf(sprintfBuffer, 256, "executed dmac5 cmd 49 for slot : %x\n", DMAC5_KEYRING_KEY_1D);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
  }

  char expected[0x20] = {0x4b,	0x7a,	0xa6,	0x0a,	0xd2,	0x95,	0x15,	0xbf,	0x1c,	0x42,	0xff,	0x5a,	0x72,	0xcb,	0x92,	0xac,
                         0x50,	0x49,	0x61,	0x59,	0x77,	0xe4,	0xec,	0xef,	0xc5,	0xe1,	0x9d,	0xa3,	0x20,	0xb2,	0x6a,	0x97,};

  if(memcmp(expected, output, 0x20) == 0)
  {
    FILE_GLOBAL_WRITE_LEN("Confirmed DES-64-CBC encrypt\n");
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("Unexpected result\n");
  }

  FILE_GLOBAL_WRITE_LEN("data\n");
  print_bytes(output, 0x40);
  FILE_GLOBAL_WRITE_LEN("iv\n");
  print_bytes(iv, 0x08);

  char dec[0x40];
  memset(dec, 0, 0x40);

  //have to set again - it will be changed
  memset(iv, 0, 0x8);
  iv[0] = 1;

  res = execute_dmac5_command_0x4A_926bccf0(output, dec, 0x20, DMAC5_KEYRING_KEY_1D, 0xC0, iv, 1);
  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to execute_dmac5_command_0x4A_926bccf0 : %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
  }
  else
  {
    snprintf(sprintfBuffer, 256, "executed dmac5 cmd 4A for slot : %x\n", DMAC5_KEYRING_KEY_1D);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
  }

  if(memcmp(dec, input, 0x20) == 0)
  {
    FILE_GLOBAL_WRITE_LEN("Confirmed DES-64-CBC decrypt\n");
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("Unexpected result\n");
  }

  return 0;
}

//============================================

int test_sha1()
{
  char* input = "The gray fox jumped over the dog";
  char output[0x40];
  memset(output, 0, 0x40);

  int size = strnlen(input, 0x40);

  //allocating 40 byte iv just in case
  char iv[0x28];
  memset(iv, 0, 0x28);
  iv[0] = 0; //set IV to 0 currently

  int res = execute_dmac5_command_0x03_eb3af9b5(input, output, size, iv, 1, 0x000); //works
  //int res = execute_dmac5_command_0x03_eb3af9b5(input, output, size, iv, 1, 0x400);
  //int res = execute_dmac5_command_0x03_eb3af9b5(input, output, size, iv, 1, 0x800); //works
  //int res = execute_dmac5_command_0x03_eb3af9b5(input, output, size, iv, 1, 0xC00);

  //snprintf(sprintfBuffer, 256, "sha1 result : %x\n", res);
  //FILE_GLOBAL_WRITE_LEN(sprintfBuffer);

  print_bytes(output, 0x40);

  char expected[0x14] = {0x0c, 0x99, 0x04, 0x6b, 0x6a, 0xa2, 0x44, 0x25, 0x11, 0x1e, 0x07, 0x21, 0xd2, 0x07, 0x85, 0x6a, 0xab, 0xd5, 0x64, 0x18};

  if(memcmp(expected, output, 0x14) == 0)
  {
    FILE_GLOBAL_WRITE_LEN("Confirmed SHA-1\n");
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("Unexpected result\n");
  }

  return 0;
}

int test_hmac_sha1_0()
{
  char key[0x20] = {0}; //key length is always set to 0x100 bits

  char* input = "The gray fox jumped over the dog";
  char output[0x40];
  memset(output, 0, 0x40);

  int size = strnlen(input, 0x40);

  //allocating 40 byte iv just in case
  char iv[0x28];
  memset(iv, 0, 0x28);
  iv[0] = 0; //set IV to 0 currently

  int res = execute_dmac5_command_0x23_6704d985(input, output, size, key, 0, 1, 0x000); //works without iv
  //int res = execute_dmac5_command_0x23_6704d985(input, output, size, key, 0, 1, 0x400); //works without iv but does not produce result
  //int res = execute_dmac5_command_0x23_6704d985(input, output, size, key, 0, 1, 0x800); //works without iv but produces unexpected digest
  //int res = execute_dmac5_command_0x23_6704d985(input, output, size, key, 0, 1, 0xC00); //works without iv but does not produce result

  //snprintf(sprintfBuffer, 256, "hmac-sha1 result : %x\n", res);
  //FILE_GLOBAL_WRITE_LEN(sprintfBuffer);

  print_bytes(output, 0x40);

  char expected[0x14] = {0xe3, 0xaf, 0xf3, 0xe8, 0xef, 0x5c, 0xeb, 0xa1, 0x35, 0xa9, 0xe5, 0x53, 0xf7, 0x0e, 0x2d, 0xea, 0xbb, 0x0e, 0xe0, 0x78};

  if(memcmp(expected, output, 0x14) == 0)
  {
    FILE_GLOBAL_WRITE_LEN("Confirmed HMAC-SHA-1\n");
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("Unexpected result\n");
  }

  return 0;
}

int test_hmac_sha1_1()
{
  char key[0x20] = {0}; //key length is always set to 0x100 bits
  key[0x0] = 1;

  char* input = "The gray fox jumped over the dog";
  char output[0x40];
  memset(output, 0, 0x40);

  int size = strnlen(input, 0x40);

  //allocating 40 byte iv just in case
  char iv[0x28];
  memset(iv, 0, 0x28);
  iv[0] = 0; //set IV to 0 currently

  int res = execute_dmac5_command_0x23_6704d985(input, output, size, key, iv, 1, 0x000); //works
  //int res = execute_dmac5_command_0x23_6704d985(input, output, size, key, iv, 1, 0x400);
  //int res = execute_dmac5_command_0x23_6704d985(input, output, size, key, iv, 1, 0x800); //works
  //int res = execute_dmac5_command_0x23_6704d985(input, output, size, key, iv, 1, 0xC00);

  //snprintf(sprintfBuffer, 256, "hmac-sha1 result : %x\n", res);
  //FILE_GLOBAL_WRITE_LEN(sprintfBuffer);

  //print_bytes(output, 0x40);

  char expected[0x14] = {0x20, 0xc7, 0xef, 0x4e, 0x9b, 0x51, 0xbd, 0xbb, 0xa2, 0x21, 0x66, 0xf4, 0x46, 0xd7, 0x89, 0x31, 0x2a, 0x9e, 0x45, 0x14};

  if(memcmp(expected, output, 0x14) == 0)
  {
    FILE_GLOBAL_WRITE_LEN("Confirmed HMAC-SHA-1\n");
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("Unexpected result\n");
  }

  return 0;
}

int test_hmac_sha1_1f()
{
  char key[0x20] = {0}; //key length is always set to 0x100 bits
  key[0x1F] = 1;

  char* input = "The gray fox jumped over the dog";
  char output[0x40];
  memset(output, 0, 0x40);

  int size = strnlen(input, 0x40);

  //allocating 40 byte iv just in case
  char iv[0x28];
  memset(iv, 0, 0x28);
  iv[0] = 0; //set IV to 0 currently

  int res = execute_dmac5_command_0x23_6704d985(input, output, size, key, iv, 1, 0x000); //works
  //int res = execute_dmac5_command_0x23_6704d985(input, output, size, key, iv, 1, 0x400);
  //int res = execute_dmac5_command_0x23_6704d985(input, output, size, key, iv, 1, 0x800); //works
  //int res = execute_dmac5_command_0x23_6704d985(input, output, size, key, iv, 1, 0xC00);

  //snprintf(sprintfBuffer, 256, "hmac-sha1 result : %x\n", res);
  //FILE_GLOBAL_WRITE_LEN(sprintfBuffer);

  //print_bytes(output, 0x40);

  char expected[0x14] = {0xf3, 0x40, 0xe2, 0x55, 0x60, 0xbc, 0x01, 0x9d, 0x1a, 0x6f, 0x42, 0x36, 0xe2, 0x35, 0x77, 0x03, 0xc9, 0xde, 0xda, 0x42,};

  if(memcmp(expected, output, 0x14) == 0)
  {
    FILE_GLOBAL_WRITE_LEN("Confirmed HMAC-SHA-1\n");
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("Unexpected result\n");
  }

  return 0;
}

int test_hmac_sha256()
{
  char key[0x20] = {0}; //key length is always set to 0x100 bits
  key[0x1F] = 1;

  char* input = "The gray fox jumped over the dog";
  char output[0x40];
  memset(output, 0, 0x40);

  int size = strnlen(input, 0x40);

  //allocating 40 byte iv just in case
  char iv[0x28];
  memset(iv, 0, 0x28);
  iv[0] = 0; //set IV to 0 currently

  int res = execute_dmac5_command_0x33_79f38554(input, output, size, key, 0, 1, 0x000);

  //snprintf(sprintfBuffer, 256, "hmac-sha1 result : %x\n", res);
  //FILE_GLOBAL_WRITE_LEN(sprintfBuffer);

  //print_bytes(output, 0x40);

  char expected[0x20] = {0x11, 0xC5, 0x87, 0xF8, 0x84, 0xF7, 0x84, 0xF1, 0x25, 0x51, 0x79, 0x66, 0x9E, 0x37, 0xFF, 0x91, 
                         0x20, 0xB2, 0x38, 0x29, 0xD3, 0x1C, 0x00, 0x14, 0x82, 0x45, 0xBC, 0x2B, 0x37, 0x64, 0xE8, 0x69};

  if(memcmp(expected, output, 0x20) == 0)
  {
    FILE_GLOBAL_WRITE_LEN("Confirmed HMAC-SHA-256\n");
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("Unexpected result\n");
  }

  return 0;
}

//============================================

int test_aes_128_cmac_key()
{
  char key[0x20] = {0};

  char* input = "The gray fox jumped over the dog";
  char output[0x40];
  memset(output, 0, 0x40);

  int size = strnlen(input, 0x40);

  //allocating 40 byte iv just in case
  char iv[0x28];
  memset(iv, 0, 0x28);
  iv[0] = 0; //set IV to 0 currently

  int res = execute_dmac5_command_0x3B_1b14658d(input, output, size, key, 0x80, 0, 1, 0x000);

  //snprintf(sprintfBuffer, 256, "hmac-sha1 result : %x\n", res);
  //FILE_GLOBAL_WRITE_LEN(sprintfBuffer);

  //print_bytes(output, 0x40);

  char expected[0x10] = {0xee, 0xa8, 0x4e, 0xc9, 0xc3, 0x15, 0xda, 0xf8, 0x42, 0xd0, 0xd7, 0x2a, 0x90, 0xb0, 0x24, 0x23,};

  if(memcmp(expected, output, 0x10) == 0)
  {
    FILE_GLOBAL_WRITE_LEN("Confirmed AES-128-CMAC\n");
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("Unexpected result\n");
  }

  return 0;
}

int test_aes_192_cmac_key()
{
  char key[0x20] = {0};

  char* input = "The gray fox jumped over the dog";
  char output[0x40];
  memset(output, 0, 0x40);

  int size = strnlen(input, 0x40);

  //allocating 40 byte iv just in case
  char iv[0x28];
  memset(iv, 0, 0x28);
  iv[0] = 0; //set IV to 0 currently

  int res = execute_dmac5_command_0x3B_1b14658d(input, output, size, key, 0xC0, 0, 1, 0x000);

  //snprintf(sprintfBuffer, 256, "hmac-sha1 result : %x\n", res);
  //FILE_GLOBAL_WRITE_LEN(sprintfBuffer);

  //print_bytes(output, 0x40);  

  char expected[0x10] = {0x6d, 0x88, 0x9d, 0x57, 0x41, 0x5f, 0xca, 0xc4, 0x26, 0x61, 0x1b, 0x15, 0x13, 0x36, 0x9e, 0xd6,};

  if(memcmp(expected, output, 0x10) == 0)
  {
    FILE_GLOBAL_WRITE_LEN("Confirmed AES-192-CMAC\n");
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("Unexpected result\n");
  }

  return 0;
}

int test_aes_256_cmac_key()
{
  char key[0x20] = {0};

  char* input = "The gray fox jumped over the dog";
  char output[0x40];
  memset(output, 0, 0x40);

  int size = strnlen(input, 0x40);

  //allocating 40 byte iv just in case
  char iv[0x28];
  memset(iv, 0, 0x28);
  iv[0] = 0; //set IV to 0 currently

  int res = execute_dmac5_command_0x3B_1b14658d(input, output, size, key, 0x100, 0, 1, 0x000);

  //snprintf(sprintfBuffer, 256, "hmac-sha1 result : %x\n", res);
  //FILE_GLOBAL_WRITE_LEN(sprintfBuffer);

  //print_bytes(output, 0x40);

  char expected[0x10] = {0x14, 0xf9, 0x4d, 0x0e, 0x15, 0x33, 0x9d, 0x8e, 0x85, 0xa5, 0xc2, 0x2c, 0xe5, 0xdd, 0x55, 0x44,};

  if(memcmp(expected, output, 0x10) == 0)
  {
    FILE_GLOBAL_WRITE_LEN("Confirmed AES-256-CMAC\n");
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("Unexpected result\n");
  }

  return 0;
}

//============================================

int test_aes_128_cmac_slot()
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

  //allocating 40 byte iv just in case
  char iv[0x28];
  memset(iv, 0, 0x28);
  iv[0] = 0; //set IV to 0 currently

  res = execute_dmac5_command_0x3B_ea6acb6d(input, output, size, DMAC5_KEYRING_KEY_1D, 0x80, 0, 1, 0x000);

  //snprintf(sprintfBuffer, 256, "hmac-sha1 result : %x\n", res);
  //FILE_GLOBAL_WRITE_LEN(sprintfBuffer);

  //print_bytes(output, 0x40);

  char expected[0x10] = {0xee, 0xa8, 0x4e, 0xc9, 0xc3, 0x15, 0xda, 0xf8, 0x42, 0xd0, 0xd7, 0x2a, 0x90, 0xb0, 0x24, 0x23,};

  if(memcmp(expected, output, 0x10) == 0)
  {
    FILE_GLOBAL_WRITE_LEN("Confirmed AES-128-CMAC\n");
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("Unexpected result\n");
  }  

  return 0;
}

int test_aes_192_cmac_slot()
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

  //allocating 40 byte iv just in case
  char iv[0x28];
  memset(iv, 0, 0x28);
  iv[0] = 0; //set IV to 0 currently

  res = execute_dmac5_command_0x3B_ea6acb6d(input, output, size, DMAC5_KEYRING_KEY_1D, 0xC0, 0, 1, 0x000);

  //snprintf(sprintfBuffer, 256, "hmac-sha1 result : %x\n", res);
  //FILE_GLOBAL_WRITE_LEN(sprintfBuffer);

  //print_bytes(output, 0x40);

  char expected[0x10] = {0x6d, 0x88, 0x9d, 0x57, 0x41, 0x5f, 0xca, 0xc4, 0x26, 0x61, 0x1b, 0x15, 0x13, 0x36, 0x9e, 0xd6,};

  if(memcmp(expected, output, 0x10) == 0)
  {
    FILE_GLOBAL_WRITE_LEN("Confirmed AES-192-CMAC\n");
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("Unexpected result\n");
  }  

  return 0;
}

int test_aes_256_cmac_slot()
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

  //allocating 40 byte iv just in case
  char iv[0x28];
  memset(iv, 0, 0x28);
  iv[0] = 0; //set IV to 0 currently

  res = execute_dmac5_command_0x3B_ea6acb6d(input, output, size, DMAC5_KEYRING_KEY_1D, 0x100, 0, 1, 0x000);

  //snprintf(sprintfBuffer, 256, "hmac-sha1 result : %x\n", res);
  //FILE_GLOBAL_WRITE_LEN(sprintfBuffer);

  //print_bytes(output, 0x40);

  char expected[0x10] = {0x14, 0xf9, 0x4d, 0x0e, 0x15, 0x33, 0x9d, 0x8e, 0x85, 0xa5, 0xc2, 0x2c, 0xe5, 0xdd, 0x55, 0x44,};

  if(memcmp(expected, output, 0x10) == 0)
  {
    FILE_GLOBAL_WRITE_LEN("Confirmed AES-256-CMAC\n");
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("Unexpected result\n");
  }  

  return 0;
}

//============================================

int test_aes_128_cmac_key_id()
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

  //allocating 40 byte iv just in case
  char iv[0x28];
  memset(iv, 0, 0x28);
  iv[0] = 0; //set IV to 0 currently

  enable_1d_slot_id(key);

  res = execute_dmac5_command_0x3B_83b058f5(input, output, size, key, 0x80, 0, DMAC5_KEY_ID_0, 1, 0x000);

  disable_1d_slot_id();

  //snprintf(sprintfBuffer, 256, "hmac-sha1 result : %x\n", res);
  //FILE_GLOBAL_WRITE_LEN(sprintfBuffer);

  //print_bytes(output, 0x40);

  char expected[0x10] = {0xee, 0xa8, 0x4e, 0xc9, 0xc3, 0x15, 0xda, 0xf8, 0x42, 0xd0, 0xd7, 0x2a, 0x90, 0xb0, 0x24, 0x23,};

  if(memcmp(expected, output, 0x10) == 0)
  {
    FILE_GLOBAL_WRITE_LEN("Confirmed AES-128-CMAC\n");
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("Unexpected result\n");
  }  

  return 0;
}

int test_aes_192_cmac_key_id()
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

  //allocating 40 byte iv just in case
  char iv[0x28];
  memset(iv, 0, 0x28);
  iv[0] = 0; //set IV to 0 currently

  enable_1d_slot_id(key);

  res = execute_dmac5_command_0x3B_83b058f5(input, output, size, key, 0xC0, 0, DMAC5_KEY_ID_0, 1, 0x000);

  disable_1d_slot_id();

  //snprintf(sprintfBuffer, 256, "hmac-sha1 result : %x\n", res);
  //FILE_GLOBAL_WRITE_LEN(sprintfBuffer);

  //print_bytes(output, 0x40);

  char expected[0x10] = {0x6d, 0x88, 0x9d, 0x57, 0x41, 0x5f, 0xca, 0xc4, 0x26, 0x61, 0x1b, 0x15, 0x13, 0x36, 0x9e, 0xd6,};

  if(memcmp(expected, output, 0x10) == 0)
  {
    FILE_GLOBAL_WRITE_LEN("Confirmed AES-192-CMAC\n");
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("Unexpected result\n");
  }  

  return 0;
}

int test_aes_256_cmac_key_id()
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

  //allocating 40 byte iv just in case
  char iv[0x28];
  memset(iv, 0, 0x28);
  iv[0] = 0; //set IV to 0 currently

  enable_1d_slot_id(key);

  res = execute_dmac5_command_0x3B_83b058f5(input, output, size, key, 0x100, 0, DMAC5_KEY_ID_0, 1, 0x000);

  disable_1d_slot_id();

  //snprintf(sprintfBuffer, 256, "hmac-sha1 result : %x\n", res);
  //FILE_GLOBAL_WRITE_LEN(sprintfBuffer);

  //print_bytes(output, 0x40);

  char expected[0x10] = {0x14, 0xf9, 0x4d, 0x0e, 0x15, 0x33, 0x9d, 0x8e, 0x85, 0xa5, 0xc2, 0x2c, 0xe5, 0xdd, 0x55, 0x44,};

  if(memcmp(expected, output, 0x10) == 0)
  {
    FILE_GLOBAL_WRITE_LEN("Confirmed AES-256-CMAC\n");
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("Unexpected result\n");
  }  

  return 0;
}

//============================================

int test_hmac_sha1_key_id()
{
  char key[0x20] = {0}; //key length is always set to 0x100 bits
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

  //allocating 40 byte iv just in case
  char iv[0x28];
  memset(iv, 0, 0x28);
  iv[0] = 0; //set IV to 0 currently

  enable_1d_slot_id(key);

  res = execute_dmac5_command_0x23_92e37656(input, output, size, key, 0, DMAC5_KEY_ID_0, 1, 0x000); //works without iv

  disable_1d_slot_id();

  //snprintf(sprintfBuffer, 256, "hmac-sha1 result : %x\n", res);
  //FILE_GLOBAL_WRITE_LEN(sprintfBuffer);

  //print_bytes(output, 0x40);

  char expected[0x14] = {0xe3, 0xaf, 0xf3, 0xe8, 0xef, 0x5c, 0xeb, 0xa1, 0x35, 0xa9, 0xe5, 0x53, 0xf7, 0x0e, 0x2d, 0xea, 0xbb, 0x0e, 0xe0, 0x78};

  if(memcmp(expected, output, 0x14) == 0)
  {
    FILE_GLOBAL_WRITE_LEN("Confirmed HMAC-SHA-1\n");
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("Unexpected result\n");
  }

  return 0;
}

//============================================

int test_dmac5_21_22_128_key()
{
  char key[0x20] = {0};

  char* input = "The gray fox jumped over the dog";
  char output[0x40];
  memset(output, 0, 0x40);

  int size = strnlen(input, 0x40);

  char iv[0x10];
  memset(iv, 0, 0x10);
  iv[0] = 1;

  int res = execute_dmac5_command_0x21_82b5dcef(input, output, size, key, 0x80, iv, 1);
  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to execute_dmac5_command_0x21_82b5dcef : %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("executed dmac5 cmd 21\n");
  }

  //print_bytes(output, 0x40);

  char expected[0x20] = { 0x0C, 0x8A, 0x99, 0xEE, 0x9D, 0x0C, 0x51, 0x18, 0x16, 0x19, 0x72, 0x2F, 0x84, 0x8D, 0x30, 0x37, 
                          0x73, 0xED, 0xBE, 0xEE, 0x0F, 0xC0, 0xC6, 0xE0, 0xD3, 0x5C, 0xAA, 0xDC, 0x51, 0xD6, 0x91, 0x1F};                         

  if(memcmp(expected, output, 0x20) == 0)
  {
    FILE_GLOBAL_WRITE_LEN("Confirmed AES-128-CTR encrypt\n");
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("Unexpected result\n");
  }  

  char dec[0x40];
  memset(dec, 0, 0x40);

  //have to set again - it will be changed
  memset(iv, 0, 0x10);
  iv[0] = 1;

  res = execute_dmac5_command_0x22_7d46768c(output, dec, 0x20, key, 0x80, iv, 1);
  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to execute_dmac5_command_0x22_7d46768c : %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("executed dmac5 cmd 22\n");
  }

  if(memcmp(dec, input, 0x20) == 0)
  {
    FILE_GLOBAL_WRITE_LEN("Confirmed AES-128-CTR decrypt\n");
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("Unexpected result\n");
  }

  return 0;
}

int test_dmac5_21_22_192_key()
{
  char key[0x20] = {0};
  
  char* input = "The gray fox jumped over the dog";
  char output[0x40];
  memset(output, 0, 0x40);

  int size = strnlen(input, 0x40);

  char iv[0x10];
  memset(iv, 0, 0x10);
  iv[0] = 1;

  int res = execute_dmac5_command_0x21_82b5dcef(input, output, size, key, 0xC0, iv, 1);
  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to execute_dmac5_command_0x21_82b5dcef : %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("executed dmac5 cmd 21\n");
  }

  char expected[0x20] = {0x99, 0x5B, 0xD7, 0xAA, 0xA0, 0x01, 0x96, 0x32, 0x80, 0x68, 0xBE, 0x8B, 0x32, 0x3D, 0x51, 0x58, 
                         0xE8, 0x82, 0x40, 0x5C, 0x68, 0x86, 0x9B, 0x33, 0x3C, 0x52, 0x16, 0x26, 0xA4, 0xD4, 0x99, 0x67};
  
  if(memcmp(expected, output, 0x20) == 0)
  {
    FILE_GLOBAL_WRITE_LEN("Confirmed AES-192-CTR encrypt\n");
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("Unexpected result\n");
  }  

  char dec[0x40];
  memset(dec, 0, 0x40);

  //have to set again - it will be changed
  memset(iv, 0, 0x10);
  iv[0] = 1;

  res = execute_dmac5_command_0x22_7d46768c(output, dec, 0x20, key, 0xC0, iv, 1);
  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to execute_dmac5_command_0x22_7d46768c : %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("executed dmac5 cmd 22\n");
  }

  if(memcmp(dec, input, 0x20) == 0)
  {
    FILE_GLOBAL_WRITE_LEN("Confirmed AES-192-CTR decrypt\n");
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("Unexpected result\n");
  }

  return 0;
}

int test_dmac5_21_22_256_key()
{
  char key[0x20] = {0};
  
  char* input = "The gray fox jumped over the dog";
  char output[0x40];
  memset(output, 0, 0x40);

  int size = strnlen(input, 0x40);

  char iv[0x10];
  memset(iv, 0, 0x10);
  iv[0] = 1;

  int res = execute_dmac5_command_0x21_82b5dcef(input, output, size, key, 0x100, iv, 1);
  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to execute_dmac5_command_0x21_82b5dcef : %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("executed dmac5 cmd 21\n");
  }

  char expected[0x20] = { 0x07, 0x67, 0xEF, 0xDB, 0xA0, 0x37, 0x57, 0xC0, 0x89, 0x05, 0xDB, 0x89, 0xE4, 0xA1, 0x06, 0xE6, 
                          0xBE, 0xC2, 0x24, 0x1D, 0x22, 0x16, 0x0E, 0x1C, 0x27, 0x3A, 0xAD, 0xB6, 0x9A, 0x97, 0xF2, 0x7F};

  if(memcmp(expected, output, 0x20) == 0)
  {
    FILE_GLOBAL_WRITE_LEN("Confirmed AES-256-CTR encrypt\n");
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("Unexpected result\n");
  }  

  char dec[0x40];
  memset(dec, 0, 0x40);

  //have to set again - it will be changed
  memset(iv, 0, 0x10);
  iv[0] = 1;

  res = execute_dmac5_command_0x22_7d46768c(output, dec, 0x20, key, 0x100, iv, 1);
  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to execute_dmac5_command_0x22_7d46768c : %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("executed dmac5 cmd 22\n");
  }

  if(memcmp(dec, input, 0x20) == 0)
  {
    FILE_GLOBAL_WRITE_LEN("Confirmed AES-256-CTR decrypt\n");
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("Unexpected result\n");
  }

  return 0;
}

//============================================

int test_dmac5_21_128_specific()
{
  char key[0x20] = {0};
  
  char input[0x100] = {0};

  char output[0x100];
  memset(output, 0, 0x100);

  char iv[0x10];
  memset(iv, 0, 0x10);
  iv[0] = 1;
  //iv[15] = 1;

  int res = execute_dmac5_command_0x21_82b5dcef(input, output, 0x100, key, 0x80, iv, 1);
  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to execute_dmac5_command_0x21_82b5dcef : %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("executed dmac5 cmd 21\n");
  }

  print_bytes(output, 0x100);

  //iv 0000000000000000000000000000000
  /*
  char expected[0x100] = {
    0x66, 0xE9, 0x4B, 0xD4, 0xEF, 0x8A, 0x2C, 0x3B, 0x88, 0x4C, 0xFA, 0x59, 0xCA, 0x34, 0x2B, 0x2E, 
    0x58, 0xE2, 0xFC, 0xCE, 0xFA, 0x7E, 0x30, 0x61, 0x36, 0x7F, 0x1D, 0x57, 0xA4, 0xE7, 0x45, 0x5A, 
    0x03, 0x88, 0xDA, 0xCE, 0x60, 0xB6, 0xA3, 0x92, 0xF3, 0x28, 0xC2, 0xB9, 0x71, 0xB2, 0xFE, 0x78, 
    0xF7, 0x95, 0xAA, 0xAB, 0x49, 0x4B, 0x59, 0x23, 0xF7, 0xFD, 0x89, 0xFF, 0x94, 0x8B, 0xC1, 0xE0, 
    0x20, 0x02, 0x11, 0x21, 0x4E, 0x73, 0x94, 0xDA, 0x20, 0x89, 0xB6, 0xAC, 0xD0, 0x93, 0xAB, 0xE0, 
    0xC9, 0x4D, 0xA2, 0x19, 0x11, 0x8E, 0x29, 0x7D, 0x7B, 0x7E, 0xBC, 0xBC, 0xC9, 0xC3, 0x88, 0xF2, 
    0x8A, 0xDE, 0x7D, 0x85, 0xA8, 0xEE, 0x35, 0x61, 0x6F, 0x71, 0x24, 0xA9, 0xD5, 0x27, 0x02, 0x91, 
    0x95, 0xB8, 0x4D, 0x1B, 0x96, 0xC6, 0x90, 0xFF, 0x2F, 0x2D, 0xE3, 0x0B, 0xF2, 0xEC, 0x89, 0xE0, 
    0x02, 0x53, 0x78, 0x6E, 0x12, 0x65, 0x04, 0xF0, 0xDA, 0xB9, 0x0C, 0x48, 0xA3, 0x03, 0x21, 0xDE, 
    0x33, 0x45, 0xE6, 0xB0, 0x46, 0x1E, 0x7C, 0x9E, 0x6C, 0x6B, 0x7A, 0xFE, 0xDD, 0xE8, 0x3F, 0x40, 
    0xDE, 0xB3, 0xFA, 0x67, 0x94, 0xF8, 0xFD, 0x8F, 0x55, 0xA8, 0x8D, 0xCB, 0xDA, 0x9D, 0x68, 0xF2, 
    0x13, 0x7C, 0xC9, 0xC8, 0x34, 0x20, 0x07, 0x7E, 0x7C, 0xF2, 0x8A, 0xB2, 0x69, 0x6B, 0x0D, 0xF0, 
    0x5D, 0x11, 0x45, 0x2B, 0x58, 0xAC, 0x50, 0xAA, 0x2E, 0xB3, 0xA1, 0x95, 0xB6, 0x1B, 0x87, 0xE5, 
    0xC6, 0x5A, 0x6D, 0xD5, 0xD7, 0xF7, 0xA8, 0x40, 0x65, 0xD5, 0xA1, 0x7F, 0xF4, 0x62, 0x73, 0x08, 
    0x60, 0x02, 0x49, 0x6D, 0xB6, 0x3F, 0xA4, 0xB9, 0x1B, 0xEE, 0x38, 0x7F, 0xA3, 0x03, 0x0C, 0x95, 
    0xA7, 0x3F, 0x8D, 0x04, 0x37, 0xE0, 0x91, 0x5F, 0xBC, 0xE5, 0xD7, 0xA6, 0x2D, 0x8D, 0xAB, 0x0A};
  */

  //iv 0100000000000000000000000000000
  char expected[0x100] = {
    0x58, 0xE2, 0xFC, 0xCE, 0xFA, 0x7E, 0x30, 0x61, 0x36, 0x7F, 0x1D, 0x57, 0xA4, 0xE7, 0x45, 0x5A, 
    0x03, 0x88, 0xDA, 0xCE, 0x60, 0xB6, 0xA3, 0x92, 0xF3, 0x28, 0xC2, 0xB9, 0x71, 0xB2, 0xFE, 0x78, 
    0xF7, 0x95, 0xAA, 0xAB, 0x49, 0x4B, 0x59, 0x23, 0xF7, 0xFD, 0x89, 0xFF, 0x94, 0x8B, 0xC1, 0xE0, 
    0x20, 0x02, 0x11, 0x21, 0x4E, 0x73, 0x94, 0xDA, 0x20, 0x89, 0xB6, 0xAC, 0xD0, 0x93, 0xAB, 0xE0, 
    0xC9, 0x4D, 0xA2, 0x19, 0x11, 0x8E, 0x29, 0x7D, 0x7B, 0x7E, 0xBC, 0xBC, 0xC9, 0xC3, 0x88, 0xF2, 
    0x8A, 0xDE, 0x7D, 0x85, 0xA8, 0xEE, 0x35, 0x61, 0x6F, 0x71, 0x24, 0xA9, 0xD5, 0x27, 0x02, 0x91, 
    0x95, 0xB8, 0x4D, 0x1B, 0x96, 0xC6, 0x90, 0xFF, 0x2F, 0x2D, 0xE3, 0x0B, 0xF2, 0xEC, 0x89, 0xE0, 
    0x02, 0x53, 0x78, 0x6E, 0x12, 0x65, 0x04, 0xF0, 0xDA, 0xB9, 0x0C, 0x48, 0xA3, 0x03, 0x21, 0xDE, 
    0x33, 0x45, 0xE6, 0xB0, 0x46, 0x1E, 0x7C, 0x9E, 0x6C, 0x6B, 0x7A, 0xFE, 0xDD, 0xE8, 0x3F, 0x40, 
    0xDE, 0xB3, 0xFA, 0x67, 0x94, 0xF8, 0xFD, 0x8F, 0x55, 0xA8, 0x8D, 0xCB, 0xDA, 0x9D, 0x68, 0xF2, 
    0x13, 0x7C, 0xC9, 0xC8, 0x34, 0x20, 0x07, 0x7E, 0x7C, 0xF2, 0x8A, 0xB2, 0x69, 0x6B, 0x0D, 0xF0, 
    0x5D, 0x11, 0x45, 0x2B, 0x58, 0xAC, 0x50, 0xAA, 0x2E, 0xB3, 0xA1, 0x95, 0xB6, 0x1B, 0x87, 0xE5, 
    0xC6, 0x5A, 0x6D, 0xD5, 0xD7, 0xF7, 0xA8, 0x40, 0x65, 0xD5, 0xA1, 0x7F, 0xF4, 0x62, 0x73, 0x08, 
    0x60, 0x02, 0x49, 0x6D, 0xB6, 0x3F, 0xA4, 0xB9, 0x1B, 0xEE, 0x38, 0x7F, 0xA3, 0x03, 0x0C, 0x95, 
    0xA7, 0x3F, 0x8D, 0x04, 0x37, 0xE0, 0x91, 0x5F, 0xBC, 0xE5, 0xD7, 0xA6, 0x2D, 0x8D, 0xAB, 0x0A, 
    0x58, 0xB2, 0x43, 0x1B, 0xC0, 0xBE, 0xDE, 0x02, 0x55, 0x0F, 0x40, 0x23, 0x89, 0x69, 0xEC, 0x78};
  
  if(memcmp(expected, output, 0x10) == 0)
  {
    FILE_GLOBAL_WRITE_LEN("Confirmed AES-128-CTR\n");
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("Unexpected result\n");
  } 

  return 0;
}

int test_dmac5_22_128_specific()
{
  char key[0x20] = {0};
  
  char input[0x100] = {0};

  char output[0x100];
  memset(output, 0, 0x100);

  char iv[0x10];
  memset(iv, 0, 0x10);
  iv[0] = 1;
  //iv[15] = 1;

  int res = execute_dmac5_command_0x22_7d46768c(input, output, 0x100, key, 0x80, iv, 1);
  if(res < 0)
  {
    snprintf(sprintfBuffer, 256, "failed to execute_dmac5_command_0x22_7d46768c : %x\n", res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("executed dmac5 cmd 22\n");
  }

  print_bytes(output, 0x100);

  //iv 0000000000000000000000000000000
  /*
  char expected[0x100] = {
    0x66, 0xE9, 0x4B, 0xD4, 0xEF, 0x8A, 0x2C, 0x3B, 0x88, 0x4C, 0xFA, 0x59, 0xCA, 0x34, 0x2B, 0x2E, 
    0x58, 0xE2, 0xFC, 0xCE, 0xFA, 0x7E, 0x30, 0x61, 0x36, 0x7F, 0x1D, 0x57, 0xA4, 0xE7, 0x45, 0x5A, 
    0x03, 0x88, 0xDA, 0xCE, 0x60, 0xB6, 0xA3, 0x92, 0xF3, 0x28, 0xC2, 0xB9, 0x71, 0xB2, 0xFE, 0x78, 
    0xF7, 0x95, 0xAA, 0xAB, 0x49, 0x4B, 0x59, 0x23, 0xF7, 0xFD, 0x89, 0xFF, 0x94, 0x8B, 0xC1, 0xE0, 
    0x20, 0x02, 0x11, 0x21, 0x4E, 0x73, 0x94, 0xDA, 0x20, 0x89, 0xB6, 0xAC, 0xD0, 0x93, 0xAB, 0xE0, 
    0xC9, 0x4D, 0xA2, 0x19, 0x11, 0x8E, 0x29, 0x7D, 0x7B, 0x7E, 0xBC, 0xBC, 0xC9, 0xC3, 0x88, 0xF2, 
    0x8A, 0xDE, 0x7D, 0x85, 0xA8, 0xEE, 0x35, 0x61, 0x6F, 0x71, 0x24, 0xA9, 0xD5, 0x27, 0x02, 0x91, 
    0x95, 0xB8, 0x4D, 0x1B, 0x96, 0xC6, 0x90, 0xFF, 0x2F, 0x2D, 0xE3, 0x0B, 0xF2, 0xEC, 0x89, 0xE0, 
    0x02, 0x53, 0x78, 0x6E, 0x12, 0x65, 0x04, 0xF0, 0xDA, 0xB9, 0x0C, 0x48, 0xA3, 0x03, 0x21, 0xDE, 
    0x33, 0x45, 0xE6, 0xB0, 0x46, 0x1E, 0x7C, 0x9E, 0x6C, 0x6B, 0x7A, 0xFE, 0xDD, 0xE8, 0x3F, 0x40, 
    0xDE, 0xB3, 0xFA, 0x67, 0x94, 0xF8, 0xFD, 0x8F, 0x55, 0xA8, 0x8D, 0xCB, 0xDA, 0x9D, 0x68, 0xF2, 
    0x13, 0x7C, 0xC9, 0xC8, 0x34, 0x20, 0x07, 0x7E, 0x7C, 0xF2, 0x8A, 0xB2, 0x69, 0x6B, 0x0D, 0xF0, 
    0x5D, 0x11, 0x45, 0x2B, 0x58, 0xAC, 0x50, 0xAA, 0x2E, 0xB3, 0xA1, 0x95, 0xB6, 0x1B, 0x87, 0xE5, 
    0xC6, 0x5A, 0x6D, 0xD5, 0xD7, 0xF7, 0xA8, 0x40, 0x65, 0xD5, 0xA1, 0x7F, 0xF4, 0x62, 0x73, 0x08, 
    0x60, 0x02, 0x49, 0x6D, 0xB6, 0x3F, 0xA4, 0xB9, 0x1B, 0xEE, 0x38, 0x7F, 0xA3, 0x03, 0x0C, 0x95, 
    0xA7, 0x3F, 0x8D, 0x04, 0x37, 0xE0, 0x91, 0x5F, 0xBC, 0xE5, 0xD7, 0xA6, 0x2D, 0x8D, 0xAB, 0x0A};
    */

  //iv 0100000000000000000000000000000
  char expected[0x100] = {
    0x58, 0xE2, 0xFC, 0xCE, 0xFA, 0x7E, 0x30, 0x61, 0x36, 0x7F, 0x1D, 0x57, 0xA4, 0xE7, 0x45, 0x5A, 
    0x03, 0x88, 0xDA, 0xCE, 0x60, 0xB6, 0xA3, 0x92, 0xF3, 0x28, 0xC2, 0xB9, 0x71, 0xB2, 0xFE, 0x78, 
    0xF7, 0x95, 0xAA, 0xAB, 0x49, 0x4B, 0x59, 0x23, 0xF7, 0xFD, 0x89, 0xFF, 0x94, 0x8B, 0xC1, 0xE0, 
    0x20, 0x02, 0x11, 0x21, 0x4E, 0x73, 0x94, 0xDA, 0x20, 0x89, 0xB6, 0xAC, 0xD0, 0x93, 0xAB, 0xE0, 
    0xC9, 0x4D, 0xA2, 0x19, 0x11, 0x8E, 0x29, 0x7D, 0x7B, 0x7E, 0xBC, 0xBC, 0xC9, 0xC3, 0x88, 0xF2, 
    0x8A, 0xDE, 0x7D, 0x85, 0xA8, 0xEE, 0x35, 0x61, 0x6F, 0x71, 0x24, 0xA9, 0xD5, 0x27, 0x02, 0x91, 
    0x95, 0xB8, 0x4D, 0x1B, 0x96, 0xC6, 0x90, 0xFF, 0x2F, 0x2D, 0xE3, 0x0B, 0xF2, 0xEC, 0x89, 0xE0, 
    0x02, 0x53, 0x78, 0x6E, 0x12, 0x65, 0x04, 0xF0, 0xDA, 0xB9, 0x0C, 0x48, 0xA3, 0x03, 0x21, 0xDE, 
    0x33, 0x45, 0xE6, 0xB0, 0x46, 0x1E, 0x7C, 0x9E, 0x6C, 0x6B, 0x7A, 0xFE, 0xDD, 0xE8, 0x3F, 0x40, 
    0xDE, 0xB3, 0xFA, 0x67, 0x94, 0xF8, 0xFD, 0x8F, 0x55, 0xA8, 0x8D, 0xCB, 0xDA, 0x9D, 0x68, 0xF2, 
    0x13, 0x7C, 0xC9, 0xC8, 0x34, 0x20, 0x07, 0x7E, 0x7C, 0xF2, 0x8A, 0xB2, 0x69, 0x6B, 0x0D, 0xF0, 
    0x5D, 0x11, 0x45, 0x2B, 0x58, 0xAC, 0x50, 0xAA, 0x2E, 0xB3, 0xA1, 0x95, 0xB6, 0x1B, 0x87, 0xE5, 
    0xC6, 0x5A, 0x6D, 0xD5, 0xD7, 0xF7, 0xA8, 0x40, 0x65, 0xD5, 0xA1, 0x7F, 0xF4, 0x62, 0x73, 0x08, 
    0x60, 0x02, 0x49, 0x6D, 0xB6, 0x3F, 0xA4, 0xB9, 0x1B, 0xEE, 0x38, 0x7F, 0xA3, 0x03, 0x0C, 0x95, 
    0xA7, 0x3F, 0x8D, 0x04, 0x37, 0xE0, 0x91, 0x5F, 0xBC, 0xE5, 0xD7, 0xA6, 0x2D, 0x8D, 0xAB, 0x0A, 
    0x58, 0xB2, 0x43, 0x1B, 0xC0, 0xBE, 0xDE, 0x02, 0x55, 0x0F, 0x40, 0x23, 0x89, 0x69, 0xEC, 0x78};
  
  if(memcmp(expected, output, 0x10) == 0)
  {
    FILE_GLOBAL_WRITE_LEN("Confirmed AES-128-CTR\n");
  }
  else
  {
    FILE_GLOBAL_WRITE_LEN("Unexpected result\n");
  } 

  return 0;
}

//============================================

tai_hook_ref_t sceSblAuthMgrSetDmac5Key_hook_ref = 0;
SceUID sceSblAuthMgrSetDmac5Key_hook_id = 0;

int sceSblAuthMgrSetDmac5Key_hook(char *key, int key_size, int slot_id, int key_id)
{
  if(g_disable_set_key > 0)
  {
    set_key(g_key, g_key_index);

    int res = 0;
    snprintf(sprintfBuffer, 256, "sceSblAuthMgrSetDmac5Key_hook disable : %x %x %x %x %x\n", key, key_size, slot_id, key_id, res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);

    return res;
  }
  else
  {
    int res = TAI_CONTINUE(int, sceSblAuthMgrSetDmac5Key_hook_ref, key, key_size, slot_id, key_id);
    
    snprintf(sprintfBuffer, 256, "sceSblAuthMgrSetDmac5Key_hook : %x %x %x %x %x\n", key, key_size, slot_id, key_id, res);
    FILE_GLOBAL_WRITE_LEN(sprintfBuffer);
  
    return res;
  }
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

//============================================

int module_start(SceSize argc, const void *args) 
{
  if(initialize_hooks() < 0)
    return SCE_KERNEL_START_SUCCESS;

  if(initialize_functions() < 0)
    return SCE_KERNEL_START_SUCCESS;

  if(init_keyring() < 0)
    return SCE_KERNEL_START_SUCCESS;

  //test_dmac5_1_2_128_slot();
  //test_dmac5_1_2_192_slot();
  //test_dmac5_1_2_256_slot();
  
  //test_dmac5_1_2_128_key();
  //test_dmac5_1_2_192_key();
  //test_dmac5_1_2_256_key();

  //test_dmac5_1_2_128_key_id();
  //test_dmac5_1_2_192_key_id();
  //test_dmac5_1_2_256_key_id();

  //test_dmac5_9_A_128_key();
  //test_dmac5_9_A_192_key();
  //test_dmac5_9_A_256_key();

  //test_dmac5_9_A_128_key_id();
  //test_dmac5_9_A_192_key_id();
  //test_dmac5_9_A_256_key_id();

  //test_dmac5_41_42();
  //test_dmac5_49_4A();

  //test_sha1();

  //test_hmac_sha1_0();
  //test_hmac_sha1_1();
  //test_hmac_sha1_1f();

  //test_hmac_sha256();

  //test_aes_128_cmac_key();
  //test_aes_192_cmac_key();
  //test_aes_256_cmac_key();

  //test_aes_128_cmac_slot();
  //test_aes_192_cmac_slot();
  //test_aes_256_cmac_slot();

  //test_aes_128_cmac_key_id();
  //test_aes_192_cmac_key_id();
  //test_aes_256_cmac_key_id();

  //test_hmac_sha1_key_id();

  test_dmac5_21_22_128_key();
  test_dmac5_21_22_192_key();
  test_dmac5_21_22_256_key();

  //test_dmac5_21_128_specific();
  //test_dmac5_22_128_specific();

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
