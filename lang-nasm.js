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
[PR['PR_PLAIN'],       /\b(?i:al|ah|ax|eax|bl|bh|bx|ebx|cl|ch|cx|ecx|dl|dh|dx|edx|si|esi|di|edi|bp|ebp|sp|esp|cs|ds|ss|es|fs|gs|ip|eip|eflags|id|vip|vif|ac|vm|rf|nt|iopl|of|df|if|tf|sf|zf|af|pf|cf|st0|st1|st2|st3|st4|st5|st6|st7|ss0|ss1|ss2|esp0|esp1|esp2|mm0|mm1|mm2|mm3|mm4|mm5|mm6|mm7|xmm0|xmm1|xmm2|xmm3|xmm4|xmm5|xmm6|xmm7|xmcrt|cr0|cr2|cr3|cr4|gdtr|ldtr|idtr|dr0|dr1|dr2|dr3|dr6|dr7|msr|rax|rbx|rcx|rdx|rsi|rdi|rsp|rbp|r8|r9|r10|r11|r12|r13|r14|r15|r8d|r9d|r10d|r11d|r12d|r13d|r14d|r15d|r8w|r9w|r10w|r11w|r12w|r13w|r14w|r15w|r8l|r9l|r10l|r11l|r12l|r13l|r14l|r15l)\b/],

         // A double quoted, possibly multi-line, string.
         [PR['PR_STRING'],      /^!?\"(?:[^\"\\]|\\[\s\S])*(?:\"|$)/, null, '"'],

         [PR['PR_COMMENT'],     /;[^\r\n]*/, null, ';']
         
        ],
        [

         
         [PR['PR_KEYWORD'],     /^[A-Za-z_][0-9A-Za-z_]*/, null],
         
         [PR['PR_LITERAL'],     /^\d+\.\d+/],
         
         [PR['PR_LITERAL'],     /^(?:\d+|0[xX][a-fA-F0-9]+)/],

         // punctuation
          
        ]),
    ['nasm', 'asm']);
