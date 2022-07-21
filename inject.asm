BITS 64

SECTION .text
global main

main:
; save context
push rax
push rcx
push rdx
push rsi
push rdi
push r11

mov rax, 0x000a72656b636168
push rax
mov rax, 0x206e7520706f7274
push rax
mov rax, 0x207369757320654a
push rax

mov rsi, rsp
mov rdx, 23
mov rdi, 1
mov rax, 1
syscall					; syscall write: rdi(fd), rsi(buf *), rdx(count)

add rsp, 24

; load context
pop r11
pop rdi
pop rsi
pop rdx
pop rcx
pop rax

; return
ret
