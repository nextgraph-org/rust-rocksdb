/*******************************************************************************
* Copyright (C) 2002 Intel Corporation
*
* Licensed under the Apache License, Version 2.0 (the 'License');
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
* 
* http://www.apache.org/licenses/LICENSE-2.0
* 
* Unless required by applicable law or agreed to in writing,
* software distributed under the License is distributed on an 'AS IS' BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions
* and limitations under the License.
* 
*******************************************************************************/

/* 
// 
//  Purpose:
//     Cryptography Primitive.
//     SP-boxes for DES Cipher
// 
//  Contents:
//     DESspbox
// 
// 
*/


#include "owndefs.h"
#include "owncp.h"
#include "pcpdes.h"


#if defined( _IPP_DATA )

#if (IMPLEMENTATION == MITIGATED)
const __ALIGN64 Ipp32u DESspbox[16*16] = { // mitigated version
   /* spc_0 */
   0x0f0c0207,0x0c0a0b04,0x0906070b,0x0a00040d,0x03050802,0x0509060f,0x0e030108,0x000e0d01,
   0x0a050f00,0x05090207,0x0c03010e,0x060c080b,0x0d06030f,0x000a0904,0x070d0402,0x0b010e08,
   /* spc_1 */
   0x0a09000f,0x09030506,0x03040e01,0x040a0b0c,0x010e0708,0x0c00020d,0x060b0d07,0x0f050802,
   0x0d030b0c,0x00060c0f,0x0e080502,0x070d0201,0x0600010b,0x0a090f04,0x0305080e,0x090a0407,
   /* spc_2 */
   0x0d080b05,0x0a0d0106,0x04030209,0x07040c0f,0x080b0600,0x05020f0c,0x030e0907,0x0e01000a,
   0x0204080b,0x0d03060c,0x070a0b00,0x040f0106,0x0f01050e,0x0a0d0902,0x0c070009,0x03080e05,
   /* spc_3 */
   0x0f08050e,0x0a0d0300,0x0c010907,0x01020e09,0x0804060b,0x04030d06,0x070a000c,0x020f0b05,
   0x09020c0b,0x03080506,0x0a04000d,0x04070b00,0x020e0f01,0x0e05080f,0x0d03060a,0x0709010c,
   /* spc_4 */
   0x0f010204,0x060b050e,0x030c0802,0x00070e0d,0x090a0403,0x0c000b05,0x0a0f0d08,0x07090106,
   0x060a0d07,0x050c0802,0x000f0304,0x0a01040b,0x0f00010d,0x0209070e,0x09050e03,0x0c060b08,
   /* spc_5 */
   0x0e000903,0x08070409,0x020c0f05,0x0d0a0306,0x000b0708,0x0b0e0104,0x05020a0f,0x060d0c01,
   0x0d060205,0x0600090e,0x080b0402,0x010c0f09,0x07080c0f,0x000d0a03,0x0e070304,0x0b01050a,
   /* spc_6 */
   0x050c0802,0x000a030f,0x06090d04,0x09060e01,0x0f03020d,0x0a050c00,0x010e0b07,0x0408070b,
   0x0907060b,0x07040802,0x000a0b0d,0x0c010508,0x0a0c0d00,0x040f0209,0x0f03010e,0x03060e05,
   /* spc_7 */
   0x00050e0b,0x0f0a0906,0x050c0201,0x0a03070d,0x06090d04,0x0c00030f,0x0b070802,0x010e0408,
   0x0f030408,0x0c000205,0x0906070b,0x0609010e,0x030a080f,0x0a07050c,0x000d0e01,0x0d040b02,

   /* compact_shift_box_0 */
   0x00000000,0x00000200,0x00020000,0x00020200,0x00800000,0x00800200,0x00820000,0x00820200,
   0x80000000,0x80000200,0x80020000,0x80020200,0x80800000,0x80800200,0x80820000,0x80820200,
   /* compact_shift_box_1 */
   0x00000000,0x00002000,0x10000000,0x10002000,0x00000004,0x00002004,0x10000004,0x10002004,
   0x00040000,0x00042000,0x10040000,0x10042000,0x00040004,0x00042004,0x10040004,0x10042004,
   /* compact_shift_box_2 */
   0x00000000,0x01000000,0x00010000,0x01010000,0x40000000,0x41000000,0x40010000,0x41010000,
   0x00000040,0x01000040,0x00010040,0x01010040,0x40000040,0x41000040,0x40010040,0x41010040,
   /* compact_shift_box_3 */
   0x00000000,0x04000000,0x00100000,0x04100000,0x00000400,0x04000400,0x00100400,0x04100400,
   0x00000002,0x04000002,0x00100002,0x04100002,0x00000402,0x04000402,0x00100402,0x04100402,
   /* compact_shift_box_4 */
   0x00000000,0x00000100,0x00004000,0x00004100,0x02000000,0x02000100,0x02004000,0x02004100,
   0x00000008,0x00000108,0x00004008,0x00004108,0x02000008,0x02000108,0x02004008,0x02004108,
   /* compact_shift_box_5 */
   0x00000000,0x00000010,0x20000000,0x20000010,0x00000800,0x00000810,0x20000800,0x20000810,
   0x00080000,0x00080010,0x20080000,0x20080010,0x00080800,0x00080810,0x20080800,0x20080810,
   /* compact_shift_box_6 */
   0x00000000,0x00000001,0x00001000,0x00001001,0x00400000,0x00400001,0x00401000,0x00401001,
   0x00000080,0x00000081,0x00001080,0x00001081,0x00400080,0x00400081,0x00401080,0x00401081,
   /* compact_shift_box_7 */
   0x00000000,0x00000020,0x08000000,0x08000020,0x00008000,0x00008020,0x08008000,0x08008020,
   0x00200000,0x00200020,0x08200000,0x08200020,0x00208000,0x00208020,0x08208000,0x08208020
};
#endif

#endif /* _IPP_DATA */
