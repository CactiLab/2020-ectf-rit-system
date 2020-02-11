# 2020 MITRE Collegiate eCTF RIT System Design and Implementation

## Missing functionalities

 * The MITRE reference system does not support music sharing persistent between boots.

## Potential attacks

 * Software vulnerabilties in the fw can be exploited to run arbitray code on the MicroBlaze soft core.
 * Based on https://www.xilinx.com/html_docs/xilinx2018_1/SDK_Doc/SDK_tasks/sdk_t_tcf_attach_debug_linux_kernel_tcf.html, we are able to debug the Linux system by using **Xilinx System Debugger**. And that makes it very easy to access the memory, even read and write to the block memory.

## Design

 * Disable the debug from microblaze and delete the MDM block.

## Implementation

 * `boot-image/` 
