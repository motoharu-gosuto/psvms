#include <psp2kern/kernel/modulemgr.h>

#include "global_log.h"

int module_start(SceSize argc, const void *args) 
{
  FILE_GLOBAL_WRITE_LEN("Startup psvmc driver\n");

  return SCE_KERNEL_START_SUCCESS;
}
 
//Alias to inhibit compiler warning
void _start() __attribute__ ((weak, alias ("module_start")));
 
int module_stop(SceSize argc, const void *args) 
{
  return SCE_KERNEL_STOP_SUCCESS;
}
