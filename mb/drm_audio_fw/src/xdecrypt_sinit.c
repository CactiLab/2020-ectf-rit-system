// ==============================================================
// Vivado(TM) HLS - High-Level Synthesis from C, C++ and SystemC v2019.1 (64-bit)
// Copyright 1986-2019 Xilinx, Inc. All Rights Reserved.
// ==============================================================
#ifndef __linux__

#include "xstatus.h"
#include "xparameters.h"
#include "xdecrypt.h"

XDecrypt_Config XDecrypt_ConfigTable[];

XDecrypt_Config *XDecrypt_LookupConfig(u16 DeviceId) {
	XDecrypt_Config *ConfigPtr = NULL;

	int Index;

	for (Index = 0; Index < XPAR_XDECRYPT_NUM_INSTANCES; Index++) {
		if (XDecrypt_ConfigTable[Index].DeviceId == DeviceId) {
			ConfigPtr = &XDecrypt_ConfigTable[Index];
			break;
		}
	}

	return ConfigPtr;
}

int XDecrypt_Initialize(XDecrypt *InstancePtr, u16 DeviceId) {
	XDecrypt_Config *ConfigPtr;

	Xil_AssertNonvoid(InstancePtr != NULL);

	ConfigPtr = XDecrypt_LookupConfig(DeviceId);
	if (ConfigPtr == NULL) {
		InstancePtr->IsReady = 0;
		return (XST_DEVICE_NOT_FOUND);
	}

	return XDecrypt_CfgInitialize(InstancePtr, ConfigPtr);
}

#endif

