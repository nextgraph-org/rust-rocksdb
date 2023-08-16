/*******************************************************************************
* Copyright (C) 2023 Intel Corporation
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
//     Initialization functions for internal methods and pointers
//     AES cipher context
//     AES-GCM context
//
*/

#if !defined(_PCP_AES_INIT_INTERNAL_H)
#define _PCP_AES_INIT_INTERNAL_H

#include "owndefs.h"

#define cpAes_setup_ptrs_and_methods OWNAPI(cpAes_setup_ptrs_and_methods)
IPP_OWN_DECL(void, cpAes_setup_ptrs_and_methods, (IppsAESSpec * pCtx))

#define cpAesGCM_setup_ptrs_and_methods OWNAPI(cpAesGCM_setup_ptrs_and_methods)
IPP_OWN_DECL(void, cpAesGCM_setup_ptrs_and_methods, (IppsAES_GCMState * pCtx, Ipp64u keyByteLen))

#endif /* _PCP_AES_INIT_INTERNAL_H */
