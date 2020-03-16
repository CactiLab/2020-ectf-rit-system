// ==============================================================
// Vivado(TM) HLS - High-Level Synthesis from C, C++ and SystemC v2019.1 (64-bit)
// Copyright 1986-2019 Xilinx, Inc. All Rights Reserved.
// ==============================================================
// AES_bus_s
// 0x00 : Control signals
//        bit 0  - ap_start (Read/Write/COH)
//        bit 1  - ap_done (Read/COR)
//        bit 2  - ap_idle (Read)
//        bit 3  - ap_ready (Read)
//        bit 7  - auto_restart (Read/Write)
//        others - reserved
// 0x04 : Global Interrupt Enable Register
//        bit 0  - Global Interrupt Enable (Read/Write)
//        others - reserved
// 0x08 : IP Interrupt Enable Register (Read/Write)
//        bit 0  - Channel 0 (ap_done)
//        bit 1  - Channel 1 (ap_ready)
//        others - reserved
// 0x0c : IP Interrupt Status Register (Read/TOW)
//        bit 0  - Channel 0 (ap_done)
//        bit 1  - Channel 1 (ap_ready)
//        others - reserved
// 0x10 ~
// 0x1f : Memory 'CipherText' (16 * 8b)
//        Word n : bit [ 7: 0] - CipherText[4n]
//                 bit [15: 8] - CipherText[4n+1]
//                 bit [23:16] - CipherText[4n+2]
//                 bit [31:24] - CipherText[4n+3]
// 0x20 ~
// 0x2f : Memory 'PlainText' (16 * 8b)
//        Word n : bit [ 7: 0] - PlainText[4n]
//                 bit [15: 8] - PlainText[4n+1]
//                 bit [23:16] - PlainText[4n+2]
//                 bit [31:24] - PlainText[4n+3]
// (SC = Self Clear, COR = Clear on Read, TOW = Toggle on Write, COH = Clear on Handshake)

#define XDECRYPT_AES_BUS_S_ADDR_AP_CTRL         0x00
#define XDECRYPT_AES_BUS_S_ADDR_GIE             0x04
#define XDECRYPT_AES_BUS_S_ADDR_IER             0x08
#define XDECRYPT_AES_BUS_S_ADDR_ISR             0x0c
#define XDECRYPT_AES_BUS_S_ADDR_CIPHERTEXT_BASE 0x10
#define XDECRYPT_AES_BUS_S_ADDR_CIPHERTEXT_HIGH 0x1f
#define XDECRYPT_AES_BUS_S_WIDTH_CIPHERTEXT     8
#define XDECRYPT_AES_BUS_S_DEPTH_CIPHERTEXT     16
#define XDECRYPT_AES_BUS_S_ADDR_PLAINTEXT_BASE  0x20
#define XDECRYPT_AES_BUS_S_ADDR_PLAINTEXT_HIGH  0x2f
#define XDECRYPT_AES_BUS_S_WIDTH_PLAINTEXT      8
#define XDECRYPT_AES_BUS_S_DEPTH_PLAINTEXT      16

