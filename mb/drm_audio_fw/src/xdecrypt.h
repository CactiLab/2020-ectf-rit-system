// ==============================================================
// Vivado(TM) HLS - High-Level Synthesis from C, C++ and SystemC v2019.1 (64-bit)
// Copyright 1986-2019 Xilinx, Inc. All Rights Reserved.
// ==============================================================
#ifndef XDECRYPT_H
#define XDECRYPT_H

#ifdef __cplusplus
extern "C" {
#endif

/***************************** Include Files *********************************/
#ifndef __linux__
#include "xil_types.h"
#include "xil_assert.h"
#include "xstatus.h"
#include "xil_io.h"
#else
#include <stdint.h>
#include <assert.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stddef.h>
#endif
#include "xdecrypt_hw.h"

/**************************** Type Definitions ******************************/
#ifdef __linux__
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
#else
typedef struct {
    u16 DeviceId;
    u32 Aes_bus_s_BaseAddress;
} XDecrypt_Config;
#endif

typedef struct {
    u32 Aes_bus_s_BaseAddress;
    u32 IsReady;
} XDecrypt;

/***************** Macros (Inline Functions) Definitions *********************/
#ifndef __linux__
#define XDecrypt_WriteReg(BaseAddress, RegOffset, Data) \
    Xil_Out32((BaseAddress) + (RegOffset), (u32)(Data))
#define XDecrypt_ReadReg(BaseAddress, RegOffset) \
    Xil_In32((BaseAddress) + (RegOffset))
#else
#define XDecrypt_WriteReg(BaseAddress, RegOffset, Data) \
    *(volatile u32*)((BaseAddress) + (RegOffset)) = (u32)(Data)
#define XDecrypt_ReadReg(BaseAddress, RegOffset) \
    *(volatile u32*)((BaseAddress) + (RegOffset))

#define Xil_AssertVoid(expr)    assert(expr)
#define Xil_AssertNonvoid(expr) assert(expr)

#define XST_SUCCESS             0
#define XST_DEVICE_NOT_FOUND    2
#define XST_OPEN_DEVICE_FAILED  3
#define XIL_COMPONENT_IS_READY  1
#endif

/************************** Function Prototypes *****************************/
#ifndef __linux__
int XDecrypt_Initialize(XDecrypt *InstancePtr, u16 DeviceId);
XDecrypt_Config* XDecrypt_LookupConfig(u16 DeviceId);
int XDecrypt_CfgInitialize(XDecrypt *InstancePtr, XDecrypt_Config *ConfigPtr);
#else
int XDecrypt_Initialize(XDecrypt *InstancePtr, const char* InstanceName);
int XDecrypt_Release(XDecrypt *InstancePtr);
#endif

void XDecrypt_Start(XDecrypt *InstancePtr);
u32 XDecrypt_IsDone(XDecrypt *InstancePtr);
u32 XDecrypt_IsIdle(XDecrypt *InstancePtr);
u32 XDecrypt_IsReady(XDecrypt *InstancePtr);
void XDecrypt_EnableAutoRestart(XDecrypt *InstancePtr);
void XDecrypt_DisableAutoRestart(XDecrypt *InstancePtr);

u32 XDecrypt_Get_CipherText_BaseAddress(XDecrypt *InstancePtr);
u32 XDecrypt_Get_CipherText_HighAddress(XDecrypt *InstancePtr);
u32 XDecrypt_Get_CipherText_TotalBytes(XDecrypt *InstancePtr);
u32 XDecrypt_Get_CipherText_BitWidth(XDecrypt *InstancePtr);
u32 XDecrypt_Get_CipherText_Depth(XDecrypt *InstancePtr);
u32 XDecrypt_Write_CipherText_Words(XDecrypt *InstancePtr, int offset, int *data, int length);
u32 XDecrypt_Read_CipherText_Words(XDecrypt *InstancePtr, int offset, int *data, int length);
u32 XDecrypt_Write_CipherText_Bytes(XDecrypt *InstancePtr, int offset, char *data, int length);
u32 XDecrypt_Read_CipherText_Bytes(XDecrypt *InstancePtr, int offset, char *data, int length);
u32 XDecrypt_Get_PlainText_BaseAddress(XDecrypt *InstancePtr);
u32 XDecrypt_Get_PlainText_HighAddress(XDecrypt *InstancePtr);
u32 XDecrypt_Get_PlainText_TotalBytes(XDecrypt *InstancePtr);
u32 XDecrypt_Get_PlainText_BitWidth(XDecrypt *InstancePtr);
u32 XDecrypt_Get_PlainText_Depth(XDecrypt *InstancePtr);
u32 XDecrypt_Write_PlainText_Words(XDecrypt *InstancePtr, int offset, int *data, int length);
u32 XDecrypt_Read_PlainText_Words(XDecrypt *InstancePtr, int offset, int *data, int length);
u32 XDecrypt_Write_PlainText_Bytes(XDecrypt *InstancePtr, int offset, char *data, int length);
u32 XDecrypt_Read_PlainText_Bytes(XDecrypt *InstancePtr, int offset, char *data, int length);

void XDecrypt_InterruptGlobalEnable(XDecrypt *InstancePtr);
void XDecrypt_InterruptGlobalDisable(XDecrypt *InstancePtr);
void XDecrypt_InterruptEnable(XDecrypt *InstancePtr, u32 Mask);
void XDecrypt_InterruptDisable(XDecrypt *InstancePtr, u32 Mask);
void XDecrypt_InterruptClear(XDecrypt *InstancePtr, u32 Mask);
u32 XDecrypt_InterruptGetEnabled(XDecrypt *InstancePtr);
u32 XDecrypt_InterruptGetStatus(XDecrypt *InstancePtr);

#ifdef __cplusplus
}
#endif

#endif
