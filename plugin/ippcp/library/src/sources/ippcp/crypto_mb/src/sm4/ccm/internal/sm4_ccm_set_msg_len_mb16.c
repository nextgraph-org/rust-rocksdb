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

#include <internal/sm4/sm4_ccm_mb.h>

void sm4_ccm_set_msg_len_mb16(const int64u msg_len[SM4_LINES], __mmask16 mb_mask, SM4_CCM_CTX_mb16 *p_context)
{
    int64u *msg_len_ctx = SM4_CCM_CONTEXT_MSG_LEN(p_context);
    unsigned i;

    for (i = 0; i < SM4_LINES; i++)
        if (mb_mask & (1 << i))
            msg_len_ctx[i] = msg_len[i];
}
