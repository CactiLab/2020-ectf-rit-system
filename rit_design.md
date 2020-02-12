# 2020 MITRE Collegiate eCTF RIT System Design and Implementation

## Missing functionalities

 * The MITRE reference system does not support music sharing persistent between boots.

## Potential attacks

 * Software vulnerabilties in the fw can be exploited to run arbitray code on the MicroBlaze soft core.

 ## Verified attacks

 1. Based on https://www.xilinx.com/html_docs/xilinx2018_1/SDK_Doc/SDK_tasks/sdk_t_tcf_attach_debug_linux_kernel_tcf.html, we are able to debug the board by using **Xilinx System Debugger**. And that makes it very easy to access the memory, even read and write to the block memory.
 * Attack steps:
    * Step1: Using Xilinx System Dubegger to connect the board
    * Step2: Finding out the address we want to access
    * Step3: Access the address (read and write)

## Design

 1. For the verified attack #1: disable the `debugging function` from microblaze and delete the `MDM` block. (reference: https://www.xilinx.com/support/documentation/sw_manuals/xilinx11/platform_studio/ps_p_dbg_sw_mb_enabling_debug_logic_on_mb_processors.htm)

## Implementation

 * `boot-image/` 
