/*******************************************************************************
 * Copyright (C) 2022 Intel Corporation
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

#include <internal/common/ifma_defs.h>
#include <internal/sm4/sm4_gcm_mb.h>

DLL_PUBLIC
mbx_status16 mbx_sm4_gcm_update_iv_mb16(const int8u *const pa_iv[SM4_LINES], const int iv_len[SM4_LINES], SM4_GCM_CTX_mb16 *p_context)
{
   int buf_no;
   mbx_status16 status = 0;
   __mmask16 mb_mask   = 0xFFFF;

   /* Check input pointers */
   if (NULL == pa_iv || NULL == iv_len || NULL == p_context) {
      status = MBX_SET_STS16_ALL(MBX_STATUS_NULL_PARAM_ERR);
      return status;
   }

   /* Check state */
   if (sm4_gcm_update_iv != SM4_GCM_CONTEXT_STATE(p_context)) {
      status = MBX_SET_STS16_ALL(MBX_STATUS_MISMATCH_PARAM_ERR);
      return status;
   }

   /* Don't process buffers with input pointers equal to zero and set bad status for IV with zero length */
   for (buf_no = 0; buf_no < SM4_LINES; buf_no++) {
      if (pa_iv[buf_no] == NULL) {
         status = MBX_SET_STS16(status, buf_no, MBX_STATUS_NULL_PARAM_ERR);
         mb_mask &= ~(0x1 << rearrangeOrder[buf_no]);
      }
      if (iv_len[buf_no] < 0) {
         status = MBX_SET_STS16(status, buf_no, MBX_STATUS_MISMATCH_PARAM_ERR);
         mb_mask &= ~(0x1 << rearrangeOrder[buf_no]);
      }
   }

   if (MBX_IS_ANY_OK_STS16(status)) {
      __mmask16 overflow_mask = sm4_gcm_update_iv_mb16(pa_iv, iv_len, mb_mask, p_context);

      /* Set bad status for buffers with overflowed lengths */
      for (buf_no = 0; buf_no < SM4_LINES; buf_no++) {
         if (overflow_mask >> buf_no & 1) {
            status = MBX_SET_STS16(status, buf_no, MBX_STATUS_MISMATCH_PARAM_ERR);
         }
      }
   }

   return status;
}
