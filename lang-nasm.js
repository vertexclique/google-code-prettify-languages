// Copyright (C) 2014 Mahmut Bulut
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.


/**
 * @fileoverview
 * Registers a language handler for NASM (Netwide Assembler Syntax - Intel)
 *
 *
 * To use, include prettify.js and this file in your HTML page.
 * Then put your code in an HTML tag like
 *      <pre class="prettyprint lang-nasm">(my NASM code)</pre>
 *      or
 *      <pre class="prettyprint lang-asm">(my NASM code)</pre>
 *
 *
 * The regular expressions were adapted from:
 * https://github.com/SalGnt/Sublime-NASM/blob/master/Syntaxes/NASM.tmLanguage
 * 
 * 
 * @author Mahmut Bulut
 */

PR['registerLangHandler'](
    PR['createSimpleLexer'](
        [
         // Whitespace
         
         [PR['PR_PLAIN'],       /^[\t\n\r \xA0]+/, null, '\t\n\r \xA0'],
         // A double quoted, possibly multi-line, string.
         [PR['PR_STRING'],      /^!?\"(?:[^\"\\]|\\[\s\S])*(?:\"|$)/, null, '"'],

         [PR['PR_COMMENT'],     /;[^\r\n]*/, null, ';']
         
        ],
        [

         [PR['PR_DECLARATION'], /^(?:db|dw|dd|dq|dt|do|resb|resw|resd|resq|rest|reso|incbin|equ|times|byte|word|dword|qword|tbyte|nosplit|near|far|org|label|struc|endstruc|istruc|iend|at|align|alignb|ends|offset|short|length|size|public|goto|seg|repeat|until)\b/i],

         [PR['PR_KEYWORD'],     /^(?:aaa|aad|aam|aas|adc|add|and|call|cbw|clc|cld|cli|cmc|cmp|cmpsb|cmpsw|cwd|daa|das|dec|div|esc|hlt|idiv|imul|in|inc|int|into|iret|ja|jae|jb|jbe|jc|jcxz|je|jg|jge|jl|jle|jna|jnae|jnb|jnbe|jnc|jne|jng|jnge|jnl|jnle|jno|jnp|jns|jnz|jo|jp|jpe|jpo|js|jz|jmp|lahf|lar|lds|lea|les|lock|lodsb|lodsw|loop|loope|loopz|loopnz|loopne|mov|movs|movsb|movsw|mul|neg|nop|not|or|out|pop|popf|push|pushf|rcl|rcr|rep|repe|repne|repnz|repz|ret|retn|retf|rol|ror|sahf|sal|sar|sbb|scasb|scasw|shl|shr|stc|std|sti|stosb|stosw|sub|test|wait|xchg|xlat|xor|bsf|bsr|bt|btc|btr|bts|cdq|cmpsd|cwde|insb|insw|insd|iret|iretd|jcxz|jecxz|lsf|lgs|lss|lodsd|loopw|loopd|loopew|looped|loopzw|loopzd|loopnew|loopned|loopnzw|loopnzd|movsw|movsd|movsx|movzx|popad|popfd|pushad|pushfd|scasd|seta|setae|setb|setbe|setc|sete|setg|setge|setl|setle|setna|setnae|setnb|setnbe|setnc|setne|setng|setnge|setnl|setnle|setno|setnp|setns|setnz|seto|setp|setpe|setpo|sets|setz|shld|shrd|stosb|stosw|aesenc|aesenclast|aesdec|aesdeclast|aeskeygenassist|aesimc|vfmaddpd|vfmaddps|vfmaddsd|vfmaddss|vfmaddsubpd|vfmaddsubps|vfmsubaddpd|vfmsubaddps|vfmsubpd|vfmsubps|vfmsubsd|vfmsubss|vfnmaddpd|vfnmaddps|vfnmaddsd|vfnmaddss|vfnmsubpd|vfnmsubps|vfnmsubsd|vfnmsubss|mpsadbw|phminposuw|pmulld|pmuldq|dpps|dppd|blendps|blendpd|blendvps|blendvpd|pblendvb|pblendw|pminsb|pmaxsb|pminuw|pmaxuw|pminud|pmaxud|pminsd|pmaxsd|roundps|roundss|roundpd|roundsd|insertps|pinsrb|pinsrd|pinsrq|extractps|pextrb|pextrw|pextrd|pextrq|pmovsxbw|pmovzxbw|pmovsxbd|pmovzxbd|pmovsxbq|pmovzxbq|pmovsxwd|pmovzxwd|pmovsxwq|pmovzxwq|pmovsxdq|pmovzxdq|ptest|pcmpeqq|packusdw|movntdqa|lzcnt|popcnt|extrq|insertq|movntsd|movntss|crc32|pcmpestri|pcmpestrm|pcmpistri|pcmpistrm|pcmpgtq|addsubpd|addsubps|haddpd|haddps|hsubpd|hsubps|movddup|movshdup|movsldup|psignw|psignd|psignb|pshufb|pmulhrsw|pmaddubsw|phsubw|phsubsw|phsubd|phaddw|phaddsw|phaddd|palignr|pabsw|pabsd|pabsb|clflush|lfence|maskmovdqu|mfence|movntdq|movnti|movntpd|pause|addpd|addsd|andnpd|andpd|cmppd|cmpsd|comisd|cvtdq2pd|cvtdq2ps|cvtpd2dq|cvtpd2pi|cvtpd2ps|cvtpi2pd|cvtps2dq|cvtps2pd|cvtsd2si|cvtsd2ss|cvtsi2sd|cvtss2sd|cvttpd2dq|cvttpd2pi|cvttps2dq|cvttsd2si|divpd|divsd|maxpd|maxsd|minpd|minsd|movapd|movhpd|movlpd|movmskpd|movsd|movupd|mulpd|mulsd|orpd|shufpd|sqrtpd|sqrtsd|subpd|subsd|ucomisd|unpckhpd|unpcklpd|xorpd|movdq2q|movdqa|movdqu|movq2dq|paddq|psubq|pmuludq|pshufhw|pshuflw|pshufd|pslldq|psrldq|punpckhqdq|punpcklqdq|andnps|andps|orps|pavgb|pavgw|pextrw|pinsrw|pmaxsw|pmaxub|pminsw|pminub|pmovmskb|pmulhuw|psadbw|pshufw|xorps|maskmovq|psadbw|pmaxsw|pminsw|movntq|pmulhuw|pavgw|pavgb|pmaxub|pminub|pmovmskb|shufps|pextrw|pinsrw|cmpss|cmpps|sfence|stmxcsr|ldmxcsr|pshufw|maxss|maxps|divss|divps|minss|minps|subss|subps|mulss|mulps|addss|addps|xorps|orps|andnps|andps|rcpss|rcpps|rsqrtss|rsqrtp|sqrtss|sqrtps|comiss|ucomiss|cvtss2si|cvtps2pi|cvttss2si|cvttps2pi|movntps|cvtsi2ss|cvtpi2ps|movaps|movaps|prefetch2|prefetch1|prefetch0|prefetchnta|movhps|movlhps|movhps|unpckhps|unpcklps|movlps|movhlps|movlps|movss|movups|movss|movups|addps|addss|cmpps|cmpss|comiss|cvtpi2ps|cvtps2pi|cvtsi2ss|cvtss2si|cvttps2pi|cvttss2si|divps|divss|ldmxcsr|maxps|maxss|minps|minss|movaps|movhlps|movhps|movlhps|movlps|movmskps|movntps|movss|movups|mulps|mulss|rcpps|rcpss|rsqrtps|rsqrtss|shufps|sqrtps|sqrtss|stmxcsr|subps|subss|ucomiss|unpckhps|unpcklps|syscall|sysret|femms|pavgusb|pf2id|pfacc|pfadd|pfcmpeq|pfcmpge|pfcmpgt|pfmax|pfmin|pfmul|pfrcp|pfrcpit1|pfrcpit2|pfrsqit1|pfrsqrt|pfsub|pfsubr|pi2fd|pmulhrw|prefetch|prefetchw|pf2iw|pfnacc|pfpnacc|pi2fw|pswapd|cpuid|cmpxchg8b|rdmsr|rdtsc|wrmsr|rsm|bswap|cmpxchg|invd|invlpg|wbinvd|xadd|cmova|cmovae|cmovb|cmovbe|cmovc|cmove|cmovg|cmovge|cmovl|cmovle|cmovna|cmovnae|cmovnb|cmovnbe|cmovnc|cmovne|cmovng|cmovnge|cmovnl|cmovnle|cmovno|cmovnp|cmovns|cmovnz|cmovo|cmovp|cmovpe|cmovpo|cmovs|cmovz|sysenter|sysexit|ud2|fcmov|fcmovb|fcmovbe|fcmove|fcmovnb|fcmovnbe|fcmovne|fcmovnu|fcmovu|fcomi|fcomip|fucomi|fucomip|rdpmc|emms|movd|movq|packssdw|packsswb|packuswb|paddb|paddd|paddsb|paddsw|paddusb|paddusw|paddw|pand|pandn|pcmpeqb|pcmpeqd|pcmpeqw|pcmpgtb|pcmpgtd|pcmpgtw|pmaddwd|pmulhw|pmullw|por|pslld|psllq|psllw|psrad|psraw|psrld|psrlq|psrlw|psubb|psubd|psubsb|psubsw|psubusb|psubusw|psubw|punpckhbw|punpckhdq|punpckhwd|punpcklbw|punpckldq|punpcklwd|pxor|paveb|paddsiw|pmagw|pdistib|psubsiw|pmvzb|pmulhrw|pmvnzb|pmvlzb|pmvgezb|pmulhriw|pmachriw|arpl|clts|lar|lgdt|lidt|lldt|lmsw|loadall|lsl|ltr|sgdt|sidt|sldt|smsw|str|verr|verw|bound|enter|ins|leave|outs|popa|pusha)\b/i, null],

         [PR['PR_PLAIN'],       /^[%@!](?:[-a-zA-Z$._][-a-zA-Z$._0-9]*|\d+)/],
         
         [PR['PR_LITERAL'],     /^\d+\.\d+/],
         
         [PR['PR_LITERAL'],     /^(?:\d+|0[xX][a-fA-F0-9]+)/],

         [PR['PR_TYPE'],        /^(?:main|\.code|\.data|\.stack|\.model|\.end|%include|%define|%assign|%strlen|%substr|%macro|%endmacro|%rep|%rotate|%o|%ifndef|%elif|%else|%endif|%error|%ifmacro|%ifnmacro|%elifmacro|%elifnmacro|%ifctx|%ifnctx|%elifctx|%elifnctx|%ifind|%elifind|%ifnind|%elifnind|%ifindi|%elifindi|%ifnidni|%elifnidni|%ifid|%ifnum|%ifstr|%push|%pop|%clear|%arg|%stacksize|%local|%line|%if|%!|__float8__|__float16__|__float32__|__float64__|__float80m__|__float80e__|__float128l__|__float128h__|__Infinity__|__NaN__|__QNaN__|__SNaN__|__NASM_MAJOR__|__NASM_MINOR__|__NASM_SUBMINOR__|__NASM_PATCHLEVEL__|__NASM_VERSION_ID__|__NASM_VER__|__FILE__|__LINE__|__BITS__|__DATE__|__TIME__|__DATE_NUM__|__TIME_NUM__|__UTC_DATE__|__UTC_TIME__|__UTC_DATE_NUM__|__UTC_TIME_NUM__|__POSIX_TIME__|__SECT__|bits 16|bits 32|bits 64|use16|use32|use64|\[bits 16\]|\[bits 32\]|\[bits 64\]|default|section|segment|absolute|extern|global|common|cpu)\b/i],

         // punctuation
         [PR['PR_PUNCTUATION'], /^[()\[\]{},=*<>:]|\.\.\.$/]
        ]),
    ['nasm', 'asm']);
