// ==============================================================
// Vivado(TM) HLS - High-Level Synthesis from C, C++ and SystemC v2019.1 (64-bit)
// Copyright 1986-2019 Xilinx, Inc. All Rights Reserved.
// ==============================================================
/***************************** Include Files *********************************/
#include "xdecrypt.h"

/************************** Function Implementation *************************/
#ifndef __linux__
int XDecrypt_CfgInitialize(XDecrypt *InstancePtr, XDecrypt_Config *ConfigPtr) {
    Xil_AssertNonvoid(InstancePtr != NULL);
    Xil_AssertNonvoid(ConfigPtr != NULL);

    InstancePtr->Aes_bus_s_BaseAddress = ConfigPtr->Aes_bus_s_BaseAddress;
    InstancePtr->IsReady = XIL_COMPONENT_IS_READY;

    return XST_SUCCESS;
}
#endif

void XDecrypt_Start(XDecrypt *InstancePtr) {
    u32 Data;

    Xil_AssertVoid(InstancePtr != NULL);
    Xil_AssertVoid(InstancePtr->IsReady == XIL_COMPONENT_IS_READY);

    Data = XDecrypt_ReadReg(InstancePtr->Aes_bus_s_BaseAddress, XDECRYPT_AES_BUS_S_ADDR_AP_CTRL) & 0x80;
    XDecrypt_WriteReg(InstancePtr->Aes_bus_s_BaseAddress, XDECRYPT_AES_BUS_S_ADDR_AP_CTRL, Data | 0x01);
}

u32 XDecrypt_IsDone(XDecrypt *InstancePtr) {
    u32 Data;

    Xil_AssertNonvoid(InstancePtr != NULL);
    Xil_AssertNonvoid(InstancePtr->IsReady == XIL_COMPONENT_IS_READY);

    Data = XDecrypt_ReadReg(InstancePtr->Aes_bus_s_BaseAddress, XDECRYPT_AES_BUS_S_ADDR_AP_CTRL);
    return (Data >> 1) & 0x1;
}

u32 XDecrypt_IsIdle(XDecrypt *InstancePtr) {
    u32 Data;

    Xil_AssertNonvoid(InstancePtr != NULL);
    Xil_AssertNonvoid(InstancePtr->IsReady == XIL_COMPONENT_IS_READY);

    Data = XDecrypt_ReadReg(InstancePtr->Aes_bus_s_BaseAddress, XDECRYPT_AES_BUS_S_ADDR_AP_CTRL);
    return (Data >> 2) & 0x1;
}

u32 XDecrypt_IsReady(XDecrypt *InstancePtr) {
    u32 Data;

    Xil_AssertNonvoid(InstancePtr != NULL);
    Xil_AssertNonvoid(InstancePtr->IsReady == XIL_COMPONENT_IS_READY);

    Data = XDecrypt_ReadReg(InstancePtr->Aes_bus_s_BaseAddress, XDECRYPT_AES_BUS_S_ADDR_AP_CTRL);
    // check ap_start to see if the pcore is ready for next input
    return !(Data & 0x1);
}

void XDecrypt_EnableAutoRestart(XDecrypt *InstancePtr) {
    Xil_AssertVoid(InstancePtr != NULL);
    Xil_AssertVoid(InstancePtr->IsReady == XIL_COMPONENT_IS_READY);

    XDecrypt_WriteReg(InstancePtr->Aes_bus_s_BaseAddress, XDECRYPT_AES_BUS_S_ADDR_AP_CTRL, 0x80);
}

void XDecrypt_DisableAutoRestart(XDecrypt *InstancePtr) {
    Xil_AssertVoid(InstancePtr != NULL);
    Xil_AssertVoid(InstancePtr->IsReady == XIL_COMPONENT_IS_READY);

    XDecrypt_WriteReg(InstancePtr->Aes_bus_s_BaseAddress, XDECRYPT_AES_BUS_S_ADDR_AP_CTRL, 0);
}

u32 XDecrypt_Get_CipherText_BaseAddress(XDecrypt *InstancePtr) {
    Xil_AssertNonvoid(InstancePtr != NULL);
    Xil_AssertNonvoid(InstancePtr->IsReady == XIL_COMPONENT_IS_READY);

    return (InstancePtr->Aes_bus_s_BaseAddress + XDECRYPT_AES_BUS_S_ADDR_CIPHERTEXT_BASE);
}

u32 XDecrypt_Get_CipherText_HighAddress(XDecrypt *InstancePtr) {
    Xil_AssertNonvoid(InstancePtr != NULL);
    Xil_AssertNonvoid(InstancePtr->IsReady == XIL_COMPONENT_IS_READY);

    return (InstancePtr->Aes_bus_s_BaseAddress + XDECRYPT_AES_BUS_S_ADDR_CIPHERTEXT_HIGH);
}

u32 XDecrypt_Get_CipherText_TotalBytes(XDecrypt *InstancePtr) {
    Xil_AssertNonvoid(InstancePtr != NULL);
    Xil_AssertNonvoid(InstancePtr->IsReady == XIL_COMPONENT_IS_READY);

    return (XDECRYPT_AES_BUS_S_ADDR_CIPHERTEXT_HIGH - XDECRYPT_AES_BUS_S_ADDR_CIPHERTEXT_BASE + 1);
}

u32 XDecrypt_Get_CipherText_BitWidth(XDecrypt *InstancePtr) {
    Xil_AssertNonvoid(InstancePtr != NULL);
    Xil_AssertNonvoid(InstancePtr->IsReady == XIL_COMPONENT_IS_READY);

    return XDECRYPT_AES_BUS_S_WIDTH_CIPHERTEXT;
}

u32 XDecrypt_Get_CipherText_Depth(XDecrypt *InstancePtr) {
    Xil_AssertNonvoid(InstancePtr != NULL);
    Xil_AssertNonvoid(InstancePtr->IsReady == XIL_COMPONENT_IS_READY);

    return XDECRYPT_AES_BUS_S_DEPTH_CIPHERTEXT;
}

u32 XDecrypt_Write_CipherText_Words(XDecrypt *InstancePtr, int offset, int *data, int length) {
    Xil_AssertNonvoid(InstancePtr != NULL);
    Xil_AssertNonvoid(InstancePtr -> IsReady == XIL_COMPONENT_IS_READY);

    int i;

    if ((offset + length)*4 > (XDECRYPT_AES_BUS_S_ADDR_CIPHERTEXT_HIGH - XDECRYPT_AES_BUS_S_ADDR_CIPHERTEXT_BASE + 1))
        return 0;

    for (i = 0; i < length; i++) {
        *(int *)(InstancePtr->Aes_bus_s_BaseAddress + XDECRYPT_AES_BUS_S_ADDR_CIPHERTEXT_BASE + (offset + i)*4) = *(data + i);
    }
    return length;
}

u32 XDecrypt_Read_CipherText_Words(XDecrypt *InstancePtr, int offset, int *data, int length) {
    Xil_AssertNonvoid(InstancePtr != NULL);
    Xil_AssertNonvoid(InstancePtr -> IsReady == XIL_COMPONENT_IS_READY);

    int i;

    if ((offset + length)*4 > (XDECRYPT_AES_BUS_S_ADDR_CIPHERTEXT_HIGH - XDECRYPT_AES_BUS_S_ADDR_CIPHERTEXT_BASE + 1))
        return 0;

    for (i = 0; i < length; i++) {
        *(data + i) = *(int *)(InstancePtr->Aes_bus_s_BaseAddress + XDECRYPT_AES_BUS_S_ADDR_CIPHERTEXT_BASE + (offset + i)*4);
    }
    return length;
}

u32 XDecrypt_Write_CipherText_Bytes(XDecrypt *InstancePtr, int offset, char *data, int length) {
    Xil_AssertNonvoid(InstancePtr != NULL);
    Xil_AssertNonvoid(InstancePtr -> IsReady == XIL_COMPONENT_IS_READY);

    int i;

    if ((offset + length) > (XDECRYPT_AES_BUS_S_ADDR_CIPHERTEXT_HIGH - XDECRYPT_AES_BUS_S_ADDR_CIPHERTEXT_BASE + 1))
        return 0;

    for (i = 0; i < length; i++) {
        *(char *)(InstancePtr->Aes_bus_s_BaseAddress + XDECRYPT_AES_BUS_S_ADDR_CIPHERTEXT_BASE + offset + i) = *(data + i);
    }
    return length;
}

u32 XDecrypt_Read_CipherText_Bytes(XDecrypt *InstancePtr, int offset, char *data, int length) {
    Xil_AssertNonvoid(InstancePtr != NULL);
    Xil_AssertNonvoid(InstancePtr -> IsReady == XIL_COMPONENT_IS_READY);

    int i;

    if ((offset + length) > (XDECRYPT_AES_BUS_S_ADDR_CIPHERTEXT_HIGH - XDECRYPT_AES_BUS_S_ADDR_CIPHERTEXT_BASE + 1))
        return 0;

    for (i = 0; i < length; i++) {
        *(data + i) = *(char *)(InstancePtr->Aes_bus_s_BaseAddress + XDECRYPT_AES_BUS_S_ADDR_CIPHERTEXT_BASE + offset + i);
    }
    return length;
}

u32 XDecrypt_Get_PlainText_BaseAddress(XDecrypt *InstancePtr) {
    Xil_AssertNonvoid(InstancePtr != NULL);
    Xil_AssertNonvoid(InstancePtr->IsReady == XIL_COMPONENT_IS_READY);

    return (InstancePtr->Aes_bus_s_BaseAddress + XDECRYPT_AES_BUS_S_ADDR_PLAINTEXT_BASE);
}

u32 XDecrypt_Get_PlainText_HighAddress(XDecrypt *InstancePtr) {
    Xil_AssertNonvoid(InstancePtr != NULL);
    Xil_AssertNonvoid(InstancePtr->IsReady == XIL_COMPONENT_IS_READY);

    return (InstancePtr->Aes_bus_s_BaseAddress + XDECRYPT_AES_BUS_S_ADDR_PLAINTEXT_HIGH);
}

u32 XDecrypt_Get_PlainText_TotalBytes(XDecrypt *InstancePtr) {
    Xil_AssertNonvoid(InstancePtr != NULL);
    Xil_AssertNonvoid(InstancePtr->IsReady == XIL_COMPONENT_IS_READY);

    return (XDECRYPT_AES_BUS_S_ADDR_PLAINTEXT_HIGH - XDECRYPT_AES_BUS_S_ADDR_PLAINTEXT_BASE + 1);
}

u32 XDecrypt_Get_PlainText_BitWidth(XDecrypt *InstancePtr) {
    Xil_AssertNonvoid(InstancePtr != NULL);
    Xil_AssertNonvoid(InstancePtr->IsReady == XIL_COMPONENT_IS_READY);

    return XDECRYPT_AES_BUS_S_WIDTH_PLAINTEXT;
}

u32 XDecrypt_Get_PlainText_Depth(XDecrypt *InstancePtr) {
    Xil_AssertNonvoid(InstancePtr != NULL);
    Xil_AssertNonvoid(InstancePtr->IsReady == XIL_COMPONENT_IS_READY);

    return XDECRYPT_AES_BUS_S_DEPTH_PLAINTEXT;
}

u32 XDecrypt_Write_PlainText_Words(XDecrypt *InstancePtr, int offset, int *data, int length) {
    Xil_AssertNonvoid(InstancePtr != NULL);
    Xil_AssertNonvoid(InstancePtr -> IsReady == XIL_COMPONENT_IS_READY);

    int i;

    if ((offset + length)*4 > (XDECRYPT_AES_BUS_S_ADDR_PLAINTEXT_HIGH - XDECRYPT_AES_BUS_S_ADDR_PLAINTEXT_BASE + 1))
        return 0;

    for (i = 0; i < length; i++) {
        *(int *)(InstancePtr->Aes_bus_s_BaseAddress + XDECRYPT_AES_BUS_S_ADDR_PLAINTEXT_BASE + (offset + i)*4) = *(data + i);
    }
    return length;
}

u32 XDecrypt_Read_PlainText_Words(XDecrypt *InstancePtr, int offset, int *data, int length) {
    Xil_AssertNonvoid(InstancePtr != NULL);
    Xil_AssertNonvoid(InstancePtr -> IsReady == XIL_COMPONENT_IS_READY);

    int i;

    if ((offset + length)*4 > (XDECRYPT_AES_BUS_S_ADDR_PLAINTEXT_HIGH - XDECRYPT_AES_BUS_S_ADDR_PLAINTEXT_BASE + 1))
        return 0;

    for (i = 0; i < length; i++) {
        *(data + i) = *(int *)(InstancePtr->Aes_bus_s_BaseAddress + XDECRYPT_AES_BUS_S_ADDR_PLAINTEXT_BASE + (offset + i)*4);
    }
    return length;
}

u32 XDecrypt_Write_PlainText_Bytes(XDecrypt *InstancePtr, int offset, char *data, int length) {
    Xil_AssertNonvoid(InstancePtr != NULL);
    Xil_AssertNonvoid(InstancePtr -> IsReady == XIL_COMPONENT_IS_READY);

    int i;

    if ((offset + length) > (XDECRYPT_AES_BUS_S_ADDR_PLAINTEXT_HIGH - XDECRYPT_AES_BUS_S_ADDR_PLAINTEXT_BASE + 1))
        return 0;

    for (i = 0; i < length; i++) {
        *(char *)(InstancePtr->Aes_bus_s_BaseAddress + XDECRYPT_AES_BUS_S_ADDR_PLAINTEXT_BASE + offset + i) = *(data + i);
    }
    return length;
}

u32 XDecrypt_Read_PlainText_Bytes(XDecrypt *InstancePtr, int offset, char *data, int length) {
    Xil_AssertNonvoid(InstancePtr != NULL);
    Xil_AssertNonvoid(InstancePtr -> IsReady == XIL_COMPONENT_IS_READY);

    int i;

    if ((offset + length) > (XDECRYPT_AES_BUS_S_ADDR_PLAINTEXT_HIGH - XDECRYPT_AES_BUS_S_ADDR_PLAINTEXT_BASE + 1))
        return 0;

    for (i = 0; i < length; i++) {
        *(data + i) = *(char *)(InstancePtr->Aes_bus_s_BaseAddress + XDECRYPT_AES_BUS_S_ADDR_PLAINTEXT_BASE + offset + i);
    }
    return length;
}

void XDecrypt_InterruptGlobalEnable(XDecrypt *InstancePtr) {
    Xil_AssertVoid(InstancePtr != NULL);
    Xil_AssertVoid(InstancePtr->IsReady == XIL_COMPONENT_IS_READY);

    XDecrypt_WriteReg(InstancePtr->Aes_bus_s_BaseAddress, XDECRYPT_AES_BUS_S_ADDR_GIE, 1);
}

void XDecrypt_InterruptGlobalDisable(XDecrypt *InstancePtr) {
    Xil_AssertVoid(InstancePtr != NULL);
    Xil_AssertVoid(InstancePtr->IsReady == XIL_COMPONENT_IS_READY);

    XDecrypt_WriteReg(InstancePtr->Aes_bus_s_BaseAddress, XDECRYPT_AES_BUS_S_ADDR_GIE, 0);
}

void XDecrypt_InterruptEnable(XDecrypt *InstancePtr, u32 Mask) {
    u32 Register;

    Xil_AssertVoid(InstancePtr != NULL);
    Xil_AssertVoid(InstancePtr->IsReady == XIL_COMPONENT_IS_READY);

    Register =  XDecrypt_ReadReg(InstancePtr->Aes_bus_s_BaseAddress, XDECRYPT_AES_BUS_S_ADDR_IER);
    XDecrypt_WriteReg(InstancePtr->Aes_bus_s_BaseAddress, XDECRYPT_AES_BUS_S_ADDR_IER, Register | Mask);
}

void XDecrypt_InterruptDisable(XDecrypt *InstancePtr, u32 Mask) {
    u32 Register;

    Xil_AssertVoid(InstancePtr != NULL);
    Xil_AssertVoid(InstancePtr->IsReady == XIL_COMPONENT_IS_READY);

    Register =  XDecrypt_ReadReg(InstancePtr->Aes_bus_s_BaseAddress, XDECRYPT_AES_BUS_S_ADDR_IER);
    XDecrypt_WriteReg(InstancePtr->Aes_bus_s_BaseAddress, XDECRYPT_AES_BUS_S_ADDR_IER, Register & (~Mask));
}

void XDecrypt_InterruptClear(XDecrypt *InstancePtr, u32 Mask) {
    Xil_AssertVoid(InstancePtr != NULL);
    Xil_AssertVoid(InstancePtr->IsReady == XIL_COMPONENT_IS_READY);

    XDecrypt_WriteReg(InstancePtr->Aes_bus_s_BaseAddress, XDECRYPT_AES_BUS_S_ADDR_ISR, Mask);
}

u32 XDecrypt_InterruptGetEnabled(XDecrypt *InstancePtr) {
    Xil_AssertNonvoid(InstancePtr != NULL);
    Xil_AssertNonvoid(InstancePtr->IsReady == XIL_COMPONENT_IS_READY);

    return XDecrypt_ReadReg(InstancePtr->Aes_bus_s_BaseAddress, XDECRYPT_AES_BUS_S_ADDR_IER);
}

u32 XDecrypt_InterruptGetStatus(XDecrypt *InstancePtr) {
    Xil_AssertNonvoid(InstancePtr != NULL);
    Xil_AssertNonvoid(InstancePtr->IsReady == XIL_COMPONENT_IS_READY);

    return XDecrypt_ReadReg(InstancePtr->Aes_bus_s_BaseAddress, XDECRYPT_AES_BUS_S_ADDR_ISR);
}

