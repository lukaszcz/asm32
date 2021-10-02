;;; calc.asm - test program; assembly: make test
;;; Łukasz Czajka

        section .text
        global _start
        extern printf, fgets, sscanf, exit
_start:
        push calc
        call printf
        add esp, 4

        push promptd
        call printf
        add esp, 4
        push [line_size]
        push line
        call get_line
        add esp, 8
        mov al, [line]
        mov [oper], al
        cmp al, 'q'
        je near oper_quit

l1:	push prompt1
        call printf
        add esp, 4
        push num1
        push str2
        call read_number
        add esp, 8
        cmp eax, 1
        jne l1

l2:	push prompt2
        call printf
        add esp, 4
        push num2
        push str2
        call read_number
        add esp, 8
        cmp eax, 1
        jne l2

        mov eax, [num1]
        cmp byte [oper], '+'
        je oper_add
        cmp byte [oper], '-'
        je oper_sub
        cmp byte [oper], '*'
        je oper_mul
        cmp byte [oper], '/'
        je oper_div
        cmp byte [oper], '^'
        je oper_pow
        push wrong_oper
        call printf
        add esp, 4
        jmp _start

oper_add:
        add eax, [num2]
        jmp pisz_wynik
oper_sub:
        sub eax, [num2]
        jmp pisz_wynik
oper_mul:
        mov edx, 0
        mul dword [num2]
        jmp pisz_wynik
oper_div:
        cmp dword [num2], 0
        je div_by_zero
        mov edx, 0
        div dword [num2]
        jmp pisz_wynik
oper_pow:
        mov edx, 0
        mov ebx, [num2]
        mov eax, 1
l:	cmp ebx, 0
        jle pisz_wynik
        mul dword [num1]
        sub ebx, 1
        jmp l
oper_quit:
        mov ebx, 0
        mov eax, 1
        int 0x80
pisz_wynik:
        push eax
        push wynik_str
        call printf
        add esp, 8
        jmp _start
div_by_zero:
        push div_zero_str
        call printf
        add esp, 4
        jmp _start

read_number:
        push ebp
        mov ebp, esp
        push [line_size]
        push line
        call get_line
        add esp, 8
        mov eax, ebp
        add eax, 12
        push [eax]
        sub eax, 4
        push [eax]
        push line
        call sscanf
        add esp, 12
        pop ebp
        ret

get_line:
        push ebp
        mov ebp, esp
        mov eax, ebp
        add eax, 12
        mov ebx, [eax]          ; ebx - dlugosc bufora
        sub eax, 4
        mov ecx, [eax]		; ecx - adres bufora
        mov edi, ecx
        mov esi, ecx
        add esi, ebx
ll:	push edi
        push esi
        push ecx
        mov edx, 1
        mov ecx, edi
        mov ebx, 0		; 0 = STDIN
        mov eax, 3              ; 3 = SYS_READ
        int 0x80
        pop ecx
        pop esi
        pop edi
        cmp byte [edi], 0x0A
        je ok
        add edi, 1
        cmp edi, esi
        jne ll
        sub edi, 1
ok:	mov byte [edi], 0
        pop ebp
        ret

        section .data
num1:		dd 0
num2:		dd 0
calc:		db 0x0A, 'Kalkulator.', 0xA, 0
promptd:	db 'Wpisz dzialanie (+,-,*,/,^,q).', 0x0A, 0
prompt1:	db 'Wpisz pierwszy argument.', 0x0A, 0
prompt2:	db 'Wpisz drugi argument.', 0x0A, 0
wrong_oper:	db 'Zle dzialanie.', 0x0A, 0
wynik_str:	db 'Wynik: %d', 0x0A, 0
div_zero_str:	db 'Dzielenie przez zero.', 0x0A, 0
str1:		db '%c', 0x0A, 0
str2:		db '%u', 0x0A, 0
oper:		db 0
line:		db 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
line_size:	dd 12
