;===============================================================================
; Copyright (C) 2014 Intel Corporation
;
; Licensed under the Apache License, Version 2.0 (the 'License');
; you may not use this file except in compliance with the License.
; You may obtain a copy of the License at
; 
; http://www.apache.org/licenses/LICENSE-2.0
; 
; Unless required by applicable law or agreed to in writing,
; software distributed under the License is distributed on an 'AS IS' BASIS,
; WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
; See the License for the specific language governing permissions
; and limitations under the License.
; 
;===============================================================================

;
;
;     Purpose:  Cryptography Primitive.
;               Big Number Arithmetic (Montgomery Reduction)
;
;     Content:
;        cpMontRedAdc_BNU()
;
;     History:
;      This implementation used instead of previous one
;      (see pcpmontredictw7as.asm)
;
;      Extra reduction (R=A-M) has been added to perform MontReduction safe
;
;






%include "asmdefs.inc"
%include "ia_emm.inc"

%if (_IPP == _IPP_W7) || (_IPP == _IPP_T7)
%include "pcpvariant.inc"
%include "pcpbnu.inc"

%if _USE_NN_MONTMUL_ == _NUSE


%macro MULADD_wt_carry 1.nolist
  %xdefine %%i %1

   movd     mm7,DWORD [eax]         ;; pM[0]
   movd     mm2,DWORD [edx+4*(%%i)]   ;; pBuffer[i]
   pmuludq  mm7,mm0                    ;; t = pM[0] * u
   paddq    mm7,mm2                    ;;    +pBuffer[i]
   movd     DWORD [edx+4*(%%i)],mm7   ;; pBuffer[i] = LO(t)
   psrlq    mm7,32                     ;; carryLcl = HI(t)
%endmacro


%macro MULADD1 3.nolist
  %xdefine %%i %1
  %xdefine %%j %2
  %xdefine %%nsize %3

   movd     mm1,DWORD [eax+4*%%j]     ;; pM[j]
   movd     mm2,DWORD [edx+4*(%%i+%%j)] ;; pBuffer[i+j]
   pmuludq  mm1,mm0                    ;; t = pM[j] * u
   paddq    mm1,mm2                    ;;    +pBuffer[i+j]
   paddq    mm7,mm1                    ;;    +carryLcl
   movd     DWORD [edx+4*(%%i+%%j)],mm7 ;; pBuffer[i+j] = LO(t)
   psrlq    mm7,32                     ;; carryLcl = HI(t)
%endmacro

; INNER_LOOP1 is defined in pcpbnu.inc as well
%ifmacro INNER_LOOP1 2
%unmacro INNER_LOOP1 2
%endif
%macro INNER_LOOP1 2.nolist
  %xdefine %%i %1
  %xdefine %%size %2

   %assign %%j  0
   movd     mm0,DWORD [edx+4*%%i]        ;; pBuffer[i]

   pmuludq  mm0,mm5                       ;; u = (Ipp32u)( m0*pBuffer[i] )
   movd     mm4,DWORD [edx+4*(%%i+%%size)] ;; w = pBuffer[i+mSize]
   paddq    mm4,mm6                       ;;    +carryGbl

   %rep %%size
      %if %%j == 0
         MULADD_wt_carry %%i
      %else
         MULADD1 %%i,%%j,%%size
      %endif
      %assign %%j  %%j + 1
   %endrep

   paddq    mm7,mm4                       ;; w+= carryLcl

   movd     DWORD [edx+4*(%%i+%%size)],mm7 ;; pBuffer[i+mSize] = LO(w)
   pshufw   mm6,mm7,11111110b             ;; carryGbl = HI(w)
%endmacro


; OUTER_LOOP1 is defined in pcpbnu.inc as well
%ifmacro OUTER_LOOP1 1
%unmacro OUTER_LOOP1 1
%endif
%macro OUTER_LOOP1 1.nolist
  %xdefine %%nsize %1

   movd     mm5,DWORD m0     ; m0
   pandn    mm6,mm6              ; init carryGbl = 0

   %assign %%i  0
   %rep %%nsize
      INNER_LOOP1 %%i,%%nsize
      %assign %%i  %%i + 1
   %endrep

   psrlq    mm7,32
%endmacro



%macro UNROLL8 0.nolist
   movd     mm1,DWORD [eax+ecx]
   movd     mm2,DWORD [edx+ecx]
   movd     mm3,DWORD [eax+ecx+4]
   movd     mm4,DWORD [edx+ecx+4]
   movd     mm5,DWORD [eax+ecx+8]
   movd     mm6,DWORD [edx+ecx+8]

   pmuludq  mm1,mm0
   paddq    mm1,mm2
   pmuludq  mm3,mm0
   paddq    mm3,mm4
   pmuludq  mm5,mm0
   paddq    mm5,mm6

   movd     mm2,DWORD [edx+ecx+12]
   paddq    mm7,mm1
   movd     mm1,DWORD [eax+ecx+12]

   pmuludq  mm1,mm0
   paddq    mm1,mm2
   movd     mm2,DWORD [edx+ecx+24]
   movd     DWORD [edx+ecx],mm7

   psrlq    mm7,32
   paddq    mm7,mm3

   movd     mm3,DWORD [eax+ecx+16]
   movd     mm4,DWORD [edx+ecx+16]

   pmuludq mm3,mm0

   movd     DWORD [edx+ecx+4],mm7

   psrlq    mm7,32
   paddq    mm3,mm4
   movd     mm4,DWORD [edx+ecx+28]
   paddq    mm7,mm5
   movd     mm5,DWORD [eax+ecx+20]
   movd     mm6,DWORD [edx+ecx+20]

   pmuludq  mm5,mm0
   movd     DWORD [edx+ecx+8],mm7
   psrlq    mm7,32

   paddq    mm5,mm6
   paddq    mm7,mm1

   movd     mm1,DWORD [eax+ecx+24]

   pmuludq  mm1,mm0

   movd     DWORD [edx+ecx+12],mm7
   psrlq    mm7,32

   paddq    mm1,mm2
   paddq    mm7,mm3

   movd     mm3,DWORD [eax+ecx+28]
   pmuludq  mm3,mm0

   movd     DWORD [edx+ecx+16],mm7
   psrlq    mm7,32
   paddq    mm3,mm4
   paddq    mm7,mm5

   movd     DWORD [edx+ecx+20],mm7
   psrlq    mm7,32

   paddq    mm7,mm1
   movd     DWORD [edx+ecx+24],mm7
   psrlq    mm7,32

   paddq    mm7,mm3

   movd     DWORD [edx+ecx+28],mm7
   psrlq    mm7,32
%endmacro


%macro UNROLL16 0.nolist
   movd     mm1,DWORD [eax+ecx]
   movd     mm2,DWORD [edx+ecx]
   movd     mm3,DWORD [eax+ecx+4]
   movd     mm4,DWORD [edx+ecx+4]
   movd     mm5,DWORD [eax+ecx+8]
   movd     mm6,DWORD [edx+ecx+8]

   pmuludq  mm1,mm0
   paddq    mm1,mm2
   pmuludq  mm3,mm0
   paddq    mm3,mm4
   pmuludq  mm5,mm0
   paddq    mm5,mm6

   movd     mm2,DWORD [edx+ecx+12]
   paddq    mm7,mm1
   movd     mm1,DWORD [eax+ecx+12]

   pmuludq  mm1,mm0
   paddq    mm1,mm2
   movd     mm2,DWORD [edx+ecx+24]
   movd     DWORD [edx+ecx],mm7

   psrlq    mm7,32
   paddq    mm7,mm3

   movd     mm3,DWORD [eax+ecx+16]
   movd     mm4,DWORD [edx+ecx+16]

   pmuludq  mm3,mm0

   movd DWORD [edx+ecx+4],mm7

   psrlq    mm7,32
   paddq    mm3,mm4
   movd     mm4,DWORD [edx+ecx+28]
   paddq    mm7,mm5
   movd     mm5,DWORD [eax+ecx+20]
   movd     mm6,DWORD [edx+ecx+20]

   pmuludq  mm5,mm0
   movd     DWORD [edx+ecx+8],mm7
   psrlq    mm7,32

   paddq    mm5,mm6
   movd     mm6,DWORD [edx+ecx+32]
   paddq    mm7,mm1

   movd     mm1,DWORD [eax+ecx+24]

   pmuludq  mm1,mm0

   movd     DWORD [edx+ecx+12],mm7
   psrlq    mm7,32

   paddq    mm1,mm2
   movd     mm2,DWORD [edx+ecx+36]
   paddq    mm7,mm3

   movd     mm3,DWORD [eax+ecx+28]
   pmuludq  mm3,mm0

   movd     DWORD [edx+ecx+16],mm7
   psrlq    mm7,32
   paddq    mm3,mm4
   movd     mm4,DWORD [edx+ecx+40]
   paddq    mm7,mm5

   movd     mm5,DWORD [eax+ecx+32]
   pmuludq  mm5,mm0

   movd     DWORD [edx+ecx+20],mm7
   psrlq    mm7,32

   paddq    mm5,mm6
   movd     mm6,DWORD [edx+ecx+44]
   paddq    mm7,mm1
   movd     mm1,DWORD [eax+ecx+36]
   pmuludq  mm1,mm0
   movd     DWORD [edx+ecx+24],mm7
   psrlq    mm7,32

   paddq    mm1,mm2
   movd     mm2,DWORD [edx+ecx+48]
   paddq    mm7,mm3
   movd     mm3,DWORD [eax+ecx+40]
   pmuludq  mm3,mm0

   movd     DWORD [edx+ecx+28],mm7
   psrlq    mm7,32
   paddq    mm3,mm4
   movd     mm4,DWORD [edx+ecx+52]
   paddq    mm7,mm5

   movd     mm5,DWORD [eax+ecx+44]
   pmuludq  mm5,mm0

   movd     DWORD [edx+ecx+32],mm7
   psrlq    mm7,32
   paddq    mm5,mm6
   movd     mm6,DWORD [edx+ecx+56]
   paddq    mm7,mm1

   movd     mm1,DWORD [eax+ecx+48]
   pmuludq  mm1,mm0

   movd     DWORD [edx+ecx+36],mm7
   psrlq    mm7,32

   paddq    mm1,mm2
   movd     mm2,DWORD [edx+ecx+60]
   paddq    mm7,mm3

   movd     mm3,DWORD [eax+ecx+52]
   pmuludq  mm3,mm0

   movd     DWORD [edx+ecx+40],mm7
   psrlq    mm7,32
   paddq    mm3,mm4
   paddq    mm7,mm5

   movd     mm5,DWORD [eax+ecx+56]

   pmuludq  mm5,mm0
   movd     DWORD [edx+ecx+44],mm7
   psrlq    mm7,32
   paddq    mm5,mm6
   paddq    mm7,mm1

   movd     mm1,DWORD [eax+ecx+60]

   pmuludq  mm1,mm0
   movd     DWORD [edx+ecx+48],mm7
   psrlq    mm7,32

   paddq    mm7,mm3
   movd     DWORD [edx+ecx+52],mm7
   psrlq    mm7,32
   paddq    mm1,mm2
   paddq    mm7,mm5
   movd     DWORD [edx+ecx+56],mm7
   psrlq    mm7,32

   paddq    mm7,mm1
   movd     DWORD [edx+ecx+60],mm7
   psrlq    mm7,32
%endmacro



segment .text align=IPP_ALIGN_FACTOR


;*************************************************************
;* void cpMontRedAdc_BNU(Ipp32u* pR,
;*                       Ipp32u* pBuffer,
;*                 const Ipp32u* pModulo, int mSize, Ipp32u m0)
;*
;*************************************************************

;;
;; Lib = W7
;;
;; Caller = ippsMontMul
;;
IPPASM cpMontRedAdc_BNU,PUBLIC
  USES_GPR esi,edi,ebx,ebp

   mov   ebp, esp ; save original esp to use it to reach parameters

%xdefine pR      [ebp + ARG_1 + 0*sizeof(dword)] ; pointer to the reduction
%xdefine pBuffer [ebp + ARG_1 + 1*sizeof(dword)] ; pointer to the product
%xdefine pModulo [ebp + ARG_1 + 2*sizeof(dword)] ; pointer to the modulo
%xdefine mSize   [ebp + ARG_1 + 3*sizeof(dword)] ; modulo size
%xdefine m0      [ebp + ARG_1 + 4*sizeof(dword)] ; helper

   mov      eax,pModulo       ; modulo address
   mov      edi,mSize         ; modulo size
   mov      edx,pBuffer       ; temp product address

;
; spesial cases
;
.tst_reduct4:
   cmp      edi,4             ; special case
   jne      .tst_reduct5
   OUTER_LOOP1 4
   add      edx,4*4
   jmp      .finish

.tst_reduct5:
   cmp      edi,5             ; special case
   jne      .tst_reduct6
   OUTER_LOOP1 5
   add      edx,4*5
   jmp      .finish

.tst_reduct6:
   cmp      edi,6             ; special case
   jne      .tst_reduct7
   OUTER_LOOP1 6
   add      edx,4*6
   jmp      .finish

.tst_reduct7:
   cmp      edi,7             ; special case
   jne      .tst_reduct8
   OUTER_LOOP1 7
   add      edx,4*7
   jmp      .finish

.tst_reduct8:
   cmp      edi,8             ; special case
   jne      .tst_reduct9
   OUTER_LOOP1 8
   add      edx,4*8
   jmp      .finish

.tst_reduct9:
   cmp      edi,9             ; special case
   jne      .tst_reduct10
   OUTER_LOOP1 9
   add      edx,4*9
   jmp      .finish

.tst_reduct10:
   cmp      edi,10            ; special case
   jne      .tst_reduct11
   OUTER_LOOP1 10
   add      edx,4*10
   jmp      .finish

.tst_reduct11:
   cmp      edi,11            ; special case
   jne      .tst_reduct12
   OUTER_LOOP1 11
   add      edx,4*11
   jmp      .finish

.tst_reduct12:
   cmp      edi,12            ; special case
   jne      .tst_reduct13
   OUTER_LOOP1 12
   add      edx,4*12
   jmp      .finish

.tst_reduct13:
   cmp      edi,13            ; special case
   jne      .tst_reduct14
   OUTER_LOOP1 13
   add      edx,4*13
   jmp      .finish

.tst_reduct14:
   cmp      edi,14            ; special case
   jne      .tst_reduct15
   OUTER_LOOP1 14
   add      edx,4*14
   jmp      .finish

.tst_reduct15:
   cmp      edi,15            ; special case
   jne      .tst_reduct16
   OUTER_LOOP1 15
   add      edx,4*15
   jmp      .finish

.tst_reduct16:
   cmp      edi,16            ; special case
   jne      .reduct_general
   OUTER_LOOP1 16
   add      edx,4*16
   jmp      .finish

;
; general case
;
.reduct_general:
   sub      esp,4             ; allocate slot for carryGbl

   pandn    mm6,mm6           ; init carryGbl = 0

   mov      ebx,edi
   shl      ebx,2             ; modulo size in bytes (outer counter)
   shl      edi,2

.mainLoop:
   movd     mm0,DWORD m0        ; m0 helper
   movd     mm1,DWORD [edx]      ; pBuffer[i]
   movd     DWORD [esp],mm6      ; save carryGbl

   pmuludq  mm0,mm1                 ; u = (Ipp32u)( m0*pBuffer[i] )

   xor      ecx,ecx                 ; inner index
   pandn    mm7,mm7                 ; int carryLcl = 0

;
; case: 0 != mSize%8
;
   mov      esi,edi                 ; copy modulo size copy
   and      esi,7*4                 ; and test (inner counter)
   jz       .testSize_8

.small_loop:
   movd     mm1,DWORD [eax+ecx]  ; pModulo[]
   movd     mm2,DWORD [edx+ecx]  ; pBuffer[]

   pmuludq  mm1,mm0                 ; t = pModulo[]*u
   paddq    mm2,mm1                 ;    +pBuffer[]
   paddq    mm7,mm2                 ;    +carryLcl
   movd     DWORD [edx+ecx],mm7  ; pBuffer[] = LO(t)
   psrlq    mm7,32                  ; carryLcl  = HI(t)

   add      ecx,4
   cmp      ecx,esi
   jl       .small_loop

;
; case: mSize==8
;
.testSize_8:
   mov      esi,edi                 ; copy modulo size copy
   and      esi,8*4                 ; and test
   jz       .testSize_16

   UNROLL8
   add      ecx,8*4

;
; case: mSize==16*n
;
.testSize_16:
   mov      esi,edi                 ; copy modulo size copy
   and      esi,0FFFFFFC0h          ; and test
   jz       .next_term

.unroll16_loop:
   UNROLL16
   add      ecx,16*4
   cmp      ecx,esi
   jl       .unroll16_loop

.next_term:
   movd     mm1,DWORD [edx+ecx]  ; pBuffer[]
   movd     mm6,DWORD [esp]      ; carryGbl
   paddq    mm7,mm1                 ; t = pBuffer[]+carryLcl
   paddq    mm6,mm7                 ;    +carryGbl
   movd     DWORD [edx+ecx],mm6  ; pBuffer[] = LO(t)
   psrlq    mm6,32                  ; carryGbl  = HI(t)

   add      edx,4                   ; advance pBuffer
   sub      ebx,4                   ; decrease outer counter
   jg       .mainLoop

   add      esp,4                   ; release slot for carryGbl
   shr      edi,2                   ; restore mSize


;;
;; finish
;;
.finish:
   pxor     mm7,mm7                 ; converr carryGbl into the mask
   psubd    mm7,mm6

   mov      esi,pR                  ; pointer to the result
   mov      ebx,edi                 ; restore mSize
   pandn    mm0,mm0                 ; borrow=0
   xor      ecx,ecx                 ; index =0
   ; perform pR[] = pBuffer[] - pModulus[]
.subtract_loop:
   movd     mm1,DWORD [edx+ecx*4]; pBuffer[]
   movd     mm2,DWORD [eax+ecx*4]; pModulus[]

   psubq    mm1,mm2
   paddq    mm1,mm0
   movd     DWORD [esi+ecx*4],mm1
   pshufw   mm0,mm1,11111110b

   add      ecx,1
   cmp      ecx,edi
   jl       .subtract_loop

   pcmpeqd  mm6,mm6                 ; convert borrow into the mask
   pxor     mm0,mm6
   por      mm0,mm7                 ; common (carryGbl and borrow) mask

   pcmpeqd  mm7,mm7                 ; mask and
   pxor     mm7,mm0                 ; ~mask

   xor      ecx,ecx                 ; index =0
   ; masked copy: pR[] = (mask & pR[]) | (~mask & pBuffer[])
.masked_copy_loop:
   movd     mm1,DWORD [esi+ecx*4]; pR[]
   pand     mm1,mm0
   movd     mm2,DWORD [edx+ecx*4]; pBuffer[]
   pand     mm2,mm7
   por      mm1,mm2
   movd     DWORD [esi+ecx*4],mm1; pR[]

   add      ecx,1
   cmp      ecx,edi
   jl       .masked_copy_loop

   emms
   REST_GPR
   ret
ENDFUNC cpMontRedAdc_BNU

%endif ;; _IPP_W7 || _IPP_T7
%endif ;; _USE_NN_MONTMUL_
