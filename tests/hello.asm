        section .text
        global _start      ;Declaracja dla linkera (ld)
_start:                    ;Początek programu (punkt wejścia)
        mov edx,13         ;długość bufora
        mov ecx,napis      ;adres bufora
        mov ebx,1          ;standardowe wyjście
        mov eax,4          ;write
        int 0x80           ;wywołanie systemowe
        mov ebx,0          ;poprawny powrót (arg 1)
        mov eax,1          ;exit
        int 0x80           ;wywołanie systemowe
        section .data
;; Komunikat do wypisania
napis: db 'Hello World!',0xA
