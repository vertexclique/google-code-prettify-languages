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

         [PR['PR_KEYWORD'],     /(aaa|aad|aam|aas|adc|add|and|call|cbw|clc|cld|cli|cmc|cmp|cmpsb|cmpsw|cwd|daa|das|dec|div|esc|hlt|idiv|imul|in|inc|int|into|iret|ja|jae|jb|jbe|jc|jcxz|je|jg|jge|jl|jle|jna|jnae|jnb|jnbe|jnc|jne|jng|jnge|jnl|jnle|jno|jnp|jns|jnz|jo|jp|jpe|jpo|js|jz|jmp|lahf|lar|lds|lea|les|lock|lodsb|lodsw|loop|loope|loopz|loopnz|loopne|mov|movs|movsb|movsw|mul|neg|nop|not|or|out|pop|popf|push|pushf|rcl|rcr|rep|repe|repne|repnz|repz|ret|retn|retf|rol|ror|sahf|sal|sar|sbb|scasb|scasw|shl|shr|stc|std|sti|stosb|stosw|sub|test|wait|xchg|xlat|xor)*/, null],
         
         [PR['PR_COMMENT'],     /;[^\r\n]*/, null, ';']
        ],
        [

         [PR['PR_PLAIN'],       /^[%@!](?:[-a-zA-Z$._][-a-zA-Z$._0-9]*|\d+)/],

         [PR['PR_LITERAL'],     /^\d+\.\d+/],
         
         [PR['PR_LITERAL'],     /^(?:\d+|0[xX][a-fA-F0-9]+)/],

         // punctuation
          
        ]),
    ['nasm', 'asm']);
