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
//     SHA512 message digest
// 
//  Contents:
//        ippsSHA512Init()
//
*/

#include "owndefs.h"
#include "owncp.h"
#include "pcphash.h"
#include "pcphash_rmf.h"
#include "pcptool.h"
#include "pcpsha512stuff.h"

/*F*
//    Name: ippsSHA512Init
//
// Purpose: Init SHA512
//
// Returns:                Reason:
//    ippStsNullPtrErr        pState == NULL
//    ippStsNoErr             no errors
//
// Parameters:
//    pState      pointer to the SHA512 state
//
*F*/
IPPFUN(IppStatus, ippsSHA512Init,(IppsSHA512State* pState))
{
   return InitSHA512(pState, sha512_iv);
}
