/*******************************************************************************
* Copyright (C) 2010 Intel Corporation
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
//     Intel(R) Integrated Performance Primitives. Cryptography Primitives.
//     Internal EC over GF(p^m) basic Definitions & Function Prototypes
//
//     Context:
//        gfec_MulPoint()
//
*/

#include "owndefs.h"
#include "owncp.h"
#include "pcpgfpecstuff.h"
#include "gsscramble.h"

#if 0
IPP_OWN_DEFN (IppsGFpECPoint*, gfec_MulPoint, (IppsGFpECPoint* pR, const IppsGFpECPoint* pP, const BNU_CHUNK_T* pScalar, int scalarLen, IppsGFpECState* pEC, Ipp8u* pScratchBuffer))
{
   FIX_BNU(pScalar, scalarLen);
   {
      gsModEngine* pGForder = ECP_MONT_R(pEC);

      BNU_CHUNK_T* pTmpScalar = cpGFpGetPool(1, pGForder); /* length of scalar does not exceed length of order */
      int orderBits = MOD_BITSIZE(pGForder);
      int orderLen  = MOD_LEN(pGForder);
      cpGFpElementCopyPad(pTmpScalar,orderLen+1, pScalar,scalarLen);

      gfec_point_mul(ECP_POINT_X(pR), ECP_POINT_X(pP),
                  (Ipp8u*)pTmpScalar, orderBits,
                  pEC, pScratchBuffer);
      cpGFpReleasePool(1, pGForder);

      ECP_POINT_FLAGS(pR) = gfec_IsPointAtInfinity(pR)? 0 : ECP_FINITE_POINT;
      return pR;
   }
}
#endif
IPP_OWN_DEFN (IppsGFpECPoint*, gfec_MulPoint, (IppsGFpECPoint* pR, const IppsGFpECPoint* pP, const BNU_CHUNK_T* pScalar, int scalarLen, IppsGFpECState* pEC, Ipp8u* pScratchBuffer))
{
   FIX_BNU(pScalar, scalarLen);
   {
      gsModEngine* pME = GFP_PMA(ECP_GFP(pEC));

      BNU_CHUNK_T* pTmpScalar = cpGFpGetPool(2, pME);
      int orderBits = ECP_ORDBITSIZE(pEC);
      int orderLen = BITS_BNU_CHUNK(orderBits);
      cpGFpElementCopyPad(pTmpScalar, orderLen + 1, pScalar, scalarLen);

      gfec_point_mul(ECP_POINT_X(pR), ECP_POINT_X(pP),
         (Ipp8u*)pTmpScalar, orderBits,
         pEC, pScratchBuffer);
      cpGFpReleasePool(2, pME);

      ECP_POINT_FLAGS(pR) = gfec_IsPointAtInfinity(pR) ? 0 : ECP_FINITE_POINT;
      return pR;
   }
}
