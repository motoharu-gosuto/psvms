#pragma once

#include <stdint.h>

#pragma pack(push, 1)

//----------------

//ksceKernelGetPaddrList types are not in vitasdk

typedef struct addr_pair
{
    uint32_t addr;
    uint32_t length;
}addr_pair;

//----------------

//fast mutex is not defined in vitasdk

typedef struct fast_mutex
{
   char unk_data[0x40];
} fast_mutex;

//----------------

struct SceMsif_subctx;

typedef struct msif_init_ctx //size is unknown
{
   uint32_t index; // 0x0 some index or number 0, 1, 2, 3, 4, 5
   
   //...
   
   struct SceMsif_subctx* sub_ctx; // 0x38
   
   //...
   
}msif_init_ctx;

typedef struct ctx_C00 // size is unknown
{
   uint32_t unk_0;
   uint32_t unk_4;
   uint32_t evid_bits_8;
   
   //...
   
}ctx_C00;

typedef struct SceMsif_subctx // size is probably 0xC40
{
   uint32_t unk_0;
   
   //....
   
   ctx_C00* unk_C00;
   uint32_t unk_C10; //bits
   
   //....
   
}SceMsif_subctx;

typedef struct SceMsif_ctx //size is 0x440
{
   void* SceMsif_memblock1_base; // 0x0
   SceUID SceMsif_memblock1_id; // 0x4 - size 0x1000 - mapped to 0xE0900000
   uint32_t unk_8; // = 0
   SceUID SceMsif_evid; // 0xC
   
   fast_mutex SceMsif_fast_mutex; //0x10 - size is 0x40
   
   SceUID SceMsif_memblock2_id; // 0x50
   uint32_t unk_54;
   uint32_t intr_mutex; // 0x58 = 0 - used for suspend resume intr
   
   uint8_t unk_5C;
   uint8_t slow_mode_state; //5D = 0/1
   uint8_t unk_5E; // timewide byte
   uint8_t unk_5F; // timewide byte
   
   void* range_60; //some range that is invalidated
   uint32_t range_len_64; //length of the range
   uint32_t size_180; // 0x68 - size of data in unk_180 buffer
   uint32_t size_1C0; // 0x6C - size of data in unk_1C0 buffer
   
   void* paddr_70; // 0x70 - physical address of unk_180
   void* paddr_74; // 0x74 - physical address of unk_1C0
   void* SceMsif_memblock2_base; // 0x78 - size 0x18000 (0xC0 sectors of size 0x200)
   struct SceMsif_subctx* subctx; // 0x7C offset (840)
   
   struct addr_pair paddr_list_80[4];

   uint8_t unk_A0[0xE0];
   
   uint8_t unk_180[0x40]; // probably some buffer for accessing device. size confirmed.
   
   uint8_t unk_1C0[0x40]; // probably some buffer for accessing device. size confirmed.
   
   SceInt64 wide_time_intr_SceMsifSmshc; //0x200 - set in SceMsifSmshc interrupt handler
   SceInt64 wide_time; //0x208 - some time set in different functions
   
   void* paddr_210; // 0x210 - physical address of SceMsif_memblock2_base
   
   uint32_t unk_214;
   
   uint8_t sector_buffer[0x200]; // 0x218 - read buffer of size 0x200 - used to read MBR and execute other single sector read ops
   
   uint32_t unk_418;
   uint32_t unk_41C;
   
   uint32_t unk_420;
   uint32_t unk_424;
   SceUID SceMsifSleepCtrl_evid; // 428
   SceUID SceMsifSleepCtrl_thid; // 42C - thread id
   
   uint32_t suspend_resume_curr_state; // 0x430 = 0
   uint32_t suspend_resume_prev_state; // 0x434 = 0
   uint32_t unk_438;
   uint32_t unk_43C;

}SceMsif_ctx;

typedef struct SceMsif_fptr_table 
{
	int (*fun_1)(SceMsif_subctx *subctx, int unk1, int unk2, int unk3);
	int (*read_sectors)(SceMsif_subctx *subctx, int sector, int nSectors, void *buffer);
	int (*write_sectors)(SceMsif_subctx *subctx, int sector, int nSectors, void *buffer);
	int (*get_card_string)(SceMsif_subctx *subctx, void *dst_30);
	int (*fun_5)(SceMsif_subctx *subctx, int unk1);
	int (*fun_6)(SceMsif_subctx *subctx, int device_init_flag);
	int (*msif_sbl_auth)(SceMsif_subctx *subctx, int num);
	int (*fun_8)(SceMsif_subctx *subctx);
	int (*fun_9)(SceMsif_subctx *subctx);
	int (*fun_10)(SceMsif_subctx *subctx);
	int (*fun_11)(SceMsif_subctx *subctx);
} SceMsif_fptr_table;

#pragma pack(pop)