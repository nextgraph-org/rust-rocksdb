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
//     Cryptography Primitives.
//     EC over GF(p) Operations
//
//     Context:
//        ippsGFpECSetPointHash_rmf()
//
*/

#include "owndefs.h"
#include "owncp.h"
#include "pcpgfpecstuff.h"
#include "pcphash.h"
#include "pcphash_rmf.h"


/*F*
// Name: ippsGFpECSetPointHash_rmf
//
// Purpose: Constructs a point on an elliptic curve based on the hash of the input message
//
// Returns:                   Reason:
//    ippStsNullPtrErr               pPoint == NULL
//                                   pEC == NULL
//                                   pScratchBuffer == NULL
//                                   (msgLen && !pMsg)
//                                   pMethod == NULL
//
//    ippStsContextMatchErr          invalid pEC->idCtx
//                                   invalid pPoint->idCtx
//
//    ippStsBadArgErr                !GFP_IS_BASIC(pGFE)
//
//    ippStsOutOfRangeErr            ECP_POINT_FELEN(pPoint)!=GFP_FELEN()
//
//    ippStsQuadraticNonResidueErr   square of the Y-coordinate of
//                                   the pPoint is a quadratic non-residue modulo
//
//    ippStsLengthErr                msgLen<0
//
//    ippStsNoErr                    no error
//
// Parameters:
//    hdr              Header of the input message
//    pMsg             Pointer to the input message
//    msgLen           Length of the input message
//    pPoint           Pointer to the IppsGFpECPoint context
//    pEC              Pointer to the context of the elliptic curve
//    pMethod          Pointer to the hash method
//    pScratchBuffer   Pointer to the scratch buffer
//
// Note:
//    Is not a fact that computed point belongs to BP-related subgroup BP
//
*F*/
IPPFUN(IppStatus, ippsGFpECSetPointHash_rmf,(Ipp32u hdr, const Ipp8u* pMsg, int msgLen, IppsGFpECPoint* pPoint,
                                             IppsGFpECState* pEC, const IppsHashMethod* pMethod,
                                             Ipp8u* pScratchBuffer))
{
   IppsGFpState*  pGF;
   gsModEngine* pGFE;

   /* test method pointer */
   IPP_BAD_PTR1_RET(pMethod);

   /* test message length */
   IPP_BADARG_RET((msgLen<0), ippStsLengthErr);
   /* test message pointer */
   IPP_BADARG_RET((msgLen && !pMsg), ippStsNullPtrErr);

   IPP_BAD_PTR3_RET(pPoint, pEC, pScratchBuffer);
   IPP_BADARG_RET( !VALID_ECP_ID(pEC), ippStsContextMatchErr );

   pGF = ECP_GFP(pEC);
   pGFE = GFP_PMA(pGF);

   IPP_BADARG_RET( !GFP_IS_BASIC(pGFE), ippStsBadArgErr );
   IPP_BADARG_RET( !ECP_POINT_VALID_ID(pPoint), ippStsContextMatchErr );

   IPP_BADARG_RET( ECP_POINT_FELEN(pPoint)!=GFP_FELEN(pGFE), ippStsOutOfRangeErr);

   {
      int elemLen = GFP_FELEN(pGFE);
      BNU_CHUNK_T* pModulus = GFP_MODULUS(pGFE);

      Ipp8u md[IPP_SHA512_DIGEST_BITSIZE/BYTESIZE];
      int hashLen = pMethod->hashLen;
      BNU_CHUNK_T hashVal[BITS_BNU_CHUNK(IPP_SHA512_DIGEST_BITSIZE)+1];
      int hashValLen;

      IppsHashState_rmf hashCtx;
      ippsHashInit_rmf(&hashCtx, pMethod);

      {
         BNU_CHUNK_T* pPoolElm = cpGFpGetPool(1, pGFE);

         /* convert hdr => hdrStr */
         BNU_CHUNK_T locHdr = (BNU_CHUNK_T)hdr;
         Ipp8u hdrOctStr[sizeof(hdr/*locHdr*/)];
         cpToOctStr_BNU(hdrOctStr, sizeof(hdrOctStr), &locHdr, 1);

         /* compute md = hash(hrd||msg) */
         ippsHashUpdate_rmf(hdrOctStr, sizeof(hdrOctStr), &hashCtx);
         ippsHashUpdate_rmf(pMsg, msgLen, &hashCtx);
         ippsHashFinal_rmf(md, &hashCtx);

         /* convert hash into the integer */
         hashValLen = cpFromOctStr_BNU(hashVal, md, hashLen);
         hashValLen = cpMod_BNU(hashVal, hashValLen, pModulus, elemLen);
         cpGFpSet(pPoolElm, hashVal, hashValLen, pGFE);

         if( gfec_MakePoint(pPoint, pPoolElm, pEC)) {
            /* choose even y-coordinate of the point (see SafeID Specs v2) */
            BNU_CHUNK_T* pY = ECP_POINT_Y(pPoint);
            GFP_METHOD(pGFE)->decode(pPoolElm, pY, pGFE); /* due to P(X,Y,Z=1) just decode Y->y */
            if(pPoolElm[0] & 1)
               cpGFpNeg(pY, pY, pGFE);

            /* update point if cofactor>1 */
            if(ECP_SUBGROUP(pEC))
                gfec_MulPoint(pPoint, pPoint, ECP_COFACTOR(pEC), GFP_FELEN(pGFE), /*0,*/ pEC, pScratchBuffer);

            cpGFpReleasePool(1, pGFE);
            return ippStsNoErr;
         }
      }

      cpGFpReleasePool(1, pGFE);
      return ippStsQuadraticNonResidueErr;
   }
}
