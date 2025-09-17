---
title: "0xL4ugh - 'dance'"
description: "A writeup for a reversing challenge from the 0xL4ugh CTF involving runtime bytecode modification."
date: 2024-06-24
updated: 2025-09-06
categories: ["Writeups", "rev"]
tags: ["0xL4ugh CTF", "0xL4ugh CTF 2024"]
---

This is my solution for the "dance" crackme me which was created by Stoopid for the 0xL4ugh CTF 2024. You can find it on [crackmes.one](https://crackmes.one/crackme/65e5f47f199e6a5d372a404d).

## A first look

Running the binary it helpfully informs us that it requires a flag to be passed as a command line argument:

```
usage: ./dance <flag>
```

If we run it with just any flag it takes a while but then returns `nop`.

Taking a look at it in Ghidra, we can see that the following main function:

```c,linenos
int main(int argc,char **argv) {
    uint wstatus;
    __pid_t pid;

    if (argc == 2) {
        pid = fork();
        if (pid == 0) {
            child_main(argv[1]);
        }
        ptrace(PTRACE_ATTACH,(long)pid,(void *)0x0,(void *)0x0);
                        /* while (waitpid(pid, &wstatus, 0), WTERMSIG(wstatus) != 0) { */
        while (waitpid(pid,(int *)&wstatus,0), (wstatus & 0x7f) != 0) {
                        /* if (!WIFCONTINUED(wstatus)) { */
            if (wstatus != 0xFFFF) {
                ptrace(PTRACE_CONT,(long)pid,(void*)0x0,(void*)0x0);
            }
        }
        return 0;
    }
    printf("usage: %s <flag>\n",*argv);
                      /* WARNING: Subroutine does not return */
    exit(1);
}
```

Besides printing the usage message, it forks the process and the parent process will then continue to monitor its child process, continuing it when it stops with an exit code that isn't zero.

The behaviour of the child process is more interesting, it forks the process again and will then execute the following code in the new child process:

```c,linenos,linenostart=27
    ptrace(PTRACE_TRACEME,0,(void *)0x0,(void *)0x0);
    fd = memfd_create("",0);
    snprintf(fd_path,"/proc/self/fd/%d",(ulong)fd);
    int_arr8[0] = 0x6c6c6548;
    int_arr8[1] = 0x74202c6f;
    int_arr8[2] = 0x20746168;
    int_arr8[3] = 0x6f207369;
    int_arr8[4] = 0x6b20656e;
    int_arr8[5] = 0x66207965;
    int_arr8[6] = 0x7920726f;
    int_arr8[7] = 0x2e2e756f;
    int_arr3[0] = 0x6563696e;
    int_arr3[1] = 0x766f6d5f;
    int_arr3[2] = 0x293a5f65;
    init_struct1(&struct1_inst,int_arr8,int_arr3,0);
    decrypt_elf(&struct1_inst,cryptic_data,cryptic_data_length);
                    /* write cryptic_data to fd */
    for (i = cryptic_data_length; 0 < (long)i; i = i - written) {
        written = write(fd,cryptic_data + (cryptic_data_length - i),i);
    }
    handle = dlopen(fd_path,2);
    dance_with_me = (code *)dlsym(handle,"dance_with_me");
    success = (*dance_with_me)(flag_input);
    if (success == 0) {
        puts("ok");
    } else {
        puts("nop");
    }
    dlclose(handle);
                    /* WARNING: Subroutine does not return */
    exit(0);
```

It seems to decrypt a large chunk of garbage data which is embedded in the binary and write it to a temporary file. Right after that it loads the temporary file as a shared library and executes the function `int dance_with_me(char *flag)` from it. Dependending on the result of the function call it will then print either "nop" or "ok".

## Extracting the second stage

From this it seems like the decrypted binary must contain the functionality for validating the flag. Using gdb we can simply set `follow-fork-mode` to `child` and set a breakpoint before the temporary file is loaded and copy it from `/proc/<pid>/fd/3`.

Looking at the `dance_with_me` function in Ghidra however we see this:

```
                    **************************************************************
                    *                          FUNCTION                          *
                    **************************************************************
                    undefined dance_with_me()
     undefined         AL:1          <RETURN>
                    dance_with_me                                 XREF[1]:    Entry Point(*)
00101484 cc             ??          CCh
00101485 cc             ??          CCh
00101486 cc             ??          CCh
00101487 cc             ??          CCh
00101488 cc             ??          CCh
00101489 cc             ??          CCh
0010148a cc             ??          CCh
0010148b cc             ??          CCh
0010148c cc             ??          CCh
0010148d cc             ??          CCh
0010148e cc             ??          CCh
0010148f cc             ??          CCh
```

I don't know about you, but this doesn't look like normal code to me. Looking a bit closer it seems like the entire `.text` section of the binary only contains the one byte `int3` instruction. Calling this instruction will cause a SIGTRAP signal to be sent to the parent process and the `ptrace(PTRACE_TRACEME, ...)` lets us know that the parent process is most likely catching these signals, so let's take a look at what that process does with them.

## Understanding the middle process

In ghidra we can see the following code for the middle process:

```c,linenos,linenostart=60
    ptrace(PTRACE_ATTACH,(long)pid,(void *)0x0,(void *)0x0);
    do {
        do {
            waitpid(pid,(int *)&wstatus,0);
                          /* if (WTERMSIG(wstatus == 0) {
                             if child exited normally quit */
            if ((wstatus & 0x7f) == 0) {
                return;
            }
                          /* wait for child to terminate irregularly */
            } while (wstatus == 0xffff);
                            /* if (WIFSTOPPED(wstatus) && WSTOPSIG(wstatus) == SIGTRAP) {
                               (if the child was stopped by SIGTRAP as sent by INT3 */
            if (((wstatus & 0xff) == 0x7f) && ((wstatus & 0xff00) == 0x500)) {
                            /* remove code that was previously written to the child */
            if ((last_data_length != 0) && (last_INT3 != 0)) {
                write_to_process_memory(pid,last_INT3,(uint64_t *)BYTE_ARRAY_0010302b,last_data_length);
            }
            ptrace(PTRACE_GETREGS,(long)pid,(void *)0x0,&user_regs);
            rip_cropped = (int)user_regs.rip - 1U & 0xfff;
            rip_hash = hash_rip((byte *)&rip_cropped,4);
            rip_hash = ~rip_hash;
            j = -1;
            do {
                j = j + 1;
                if (rip_hash == instruction_array[(uint)j].rip_hash) break;
            } while (instruction_array[(uint)j].rip_hash != 0);
            write_to_process_memory
                      (pid,user_regs.rip - 1,(uint64_t *)instruction_array[(uint)j].data,
                       (ulong)instruction_array[(uint)j].length);
            last_data_length = (ulong)instruction_array[(uint)j].length;
            last_INT3 = user_regs.rip - 1;
            user_regs.rip = user_regs.rip - 1;
            ptrace(PTRACE_SETREGS,(long)pid,(void *)0x0,&user_regs);
        }
        ptrace(PTRACE_CONT,(long)pid,(void *)0x0,(void *)0x0);
    } while ( true );
```

So we can already see `ptrace` calls that decrease the program counter by one, so when an `int3` instruction is executed and this code is triggered the program counter will be moved back in front of the instruction.

However we can also see that the program counter is not just decreased by one, but also transformed using some function, with the result being used to access some array. The resulting data is then passed to a function (which I have named `write_to_process_memory`) with the following code:

```c,linenos,linenostart=22
    while (remaining != 0) {
        remaining = remaining - 1;
        ret_code = ptrace(PTRACE_POKEDATA,(long)pid,out_ptr,(void *)*in_ptr);
        if (ret_code == -1) goto error;
        in_ptr = in_ptr + 1;
        out_ptr = out_ptr + 1;
    }
```

This code writes the supplied data into the memory of the child process eight bytes at a time. The rest of the code in the function (which is not shown above) just handles data that is not a multiple of eight in length.

The last thing we can see in the signal handling is that the location of the last write to the child process memory is saved and on the next write it will use this to remove the previously written data from the memory of the child process.

Bringing all of this together, we know that the middle process replaces the code of the child process during execution and removes it after it was executed.

This means that to analyse the flag verification process, we will first have to apply the patches done at runtime to the extracted binary of the second stage, so that we can then anaylse that in ghidra.

## Populating the second stage
To achieve this I first reimplemented the function that transforms the program counter (which is called `hash_rip` in the screenshots above) like so:

```c
unsigned int *rip_translation = (unsigned int *)&rip_translation_char;

unsigned int hash_rip(uint8_t *rip_ptr, long length) {
    long i;
    uint8_t *input;
    unsigned int outp;

    outp = 0xffffffff;
    input = rip_ptr;
    for (i = length; i != 0; i--) {
        outp = rip_translation[(*input ^ outp) & 0xFF] ^ outp >> 8;
        input++;
    }
    return outp;
}

unsigned int rip2hash(uint64_t *rip) {
    uint64_t rip_int = *rip;
    unsigned int rip_cropped = (rip_int - 1) & 0xfff;
    return ~hash_rip((uint8_t *)&rip_cropped, 4);
}
```
(`rip_translation_char` is the array used in the binary, copied from ghidra via 'Copy Special' as a C Array)

Here `rip2hash` represents the everything done to the value of the program counter when the signal is caught. This implementation is almost entirely a copy-paste-job from ghidra and was tested on multiple examples so it should work.

Next I implemented the lookup of program counter to data to be written into the memory of the child process:

```c
typedef struct {
    unsigned int hash;
    uint8_t length;
    uint8_t data[19];
} instruction_data;

instruction_data *instructions_array = (instruction_data *)&instructions_bytes;

uint8_t *addr2instruction(const uint64_t addr, uint8_t *length) {
    uint64_t rip = addr + 1;
    unsigned int hash = rip2hash(&rip);
    for (int i = 0; instructions_array[i].hash != 0; i++) {
        if (instructions_array[i].hash != hash) continue;
        *length = instructions_array[i].length;
        return instructions_array[i].data;
    }
    return 0;
}
```

(`instructions_bytes` was copied from ghidra like `rip_translation_char`)

Note that the address is incremented by one like it would be after the `int3` instruction at that location was executed.

With this I implemented a `write_all` function which takes an address, a path to the extracted .text section of an elf and the virtual base address of the .text section and overwrites all consecutive addresses that it can find data for:

```c
uint8_t write_addr(uint64_t addr, FILE *file, uint64_t base_addr) {
    fseek(file, addr - base_addr, SEEK_SET);
    uint8_t length = 0;
    uint8_t *data = addr2instruction(addr, &length);
    if (data) {
        fwrite(data, length, 1, file);
        for (size_t i = 0; i < length; i++) {
            printf("  Byte: %x\n", data[i]);
        }
    }
    return length;
}

void write_all(uint64_t addr, const char *path, uint64_t base_addr) {
    FILE *file = fopen(path, "r+b");
    if (file) {
        // successfully opened file
        uint8_t written;
        while (true) {
            written = write_addr(addr, file, base_addr);
            if (written) {
                printf("Wrote %d bytes to %#0x (off: %#0x)\n", written, addr, addr-base_addr);
                addr += written;
            } else
                break;
        }
        fclose(file);
        return;
    }
    printf("couldnt open file\n");
    exit(1);
}
```

Using all of this I implemented a simple command line utility to populate the second stage:

```c
void extract_text_section(const char *elf_file_name, const char *section_file_name) {
    const char cmd_template[] = "objcopy --dump-section .text=%s %s";
    char *full_cmd = malloc(strlen(cmd_template)+strlen(elf_file_name)+strlen(section_file_name));
    sprintf(full_cmd, cmd_template, section_file_name, elf_file_name);
    system(full_cmd);
    free(full_cmd);
}

void replace_text_section(const char *elf_file_name, const char *section_file_name) {
    const char cmd_template[] = "objcopy --update-section .text=%s %s %s";
    char *full_cmd = malloc(strlen(cmd_template)+strlen(section_file_name)+(strlen(elf_file_name)*2));
    sprintf(full_cmd, cmd_template, section_file_name, elf_file_name, elf_file_name);
    system(full_cmd);
    free(full_cmd);
}

int main(int argc, char **argv) {
    if (argc != 4) {
        printf("usage: %s <skeleton_elf> <address> <base address>\n", argv[0]);
        printf("address and base address should either both include the ghidra offset or neither\n");
        return 1;
    }
    
    uint64_t addr;
    sscanf(argv[2], "%lx", &addr);

    uint64_t base_addr;
    sscanf(argv[3], "%lx", &base_addr);
    
    const char temp_file_name[] = "input_elf.text";

    // extract .text section
    extract_text_section(argv[1], temp_file_name);

    // populate it
    write_all(addr, temp_file_name, base_addr);

    // replace .text section with modified version
    replace_text_section(argv[1], temp_file_name);
}
```

This uses `objcopy` to extract and replace the .text section of the ELF. One could also parse the ELF via C code (which I originally did), but this is much more complicated and turned out to be a waste of time.

Using this we can populate the binary with the following command: `./populate dance-stage2-skeleton 0x10a0 0x10a0`. In this command `0x10a0` is the virtual base address of the .text section in memory, meaning it tries to populate the entire .text section. In this case this worked without problems because there was an entry for every byte of the .text section, but on different binaries it might be neccessary to run this multiple times with different addresses that weren't populated before.

## Analysing the populated second stage
Loading the second stage into ghidra we see that the `dance_with_me` function references multiple other functions, how ever only two of them take in the flag, so let's take a look at the first one:

```c,linenos,linenostart=176
    do {
        // ...
        *current_char = *current_char ^ *(byte *)((long)garbage + *(long *)(garbage + 16));
        *(long *)(garbage + 16) = *(long *)(garbage + 16) + 1;
        current_char = current_char + 1;
    } while (current_char != flag + length);
```

In the screenshot you can see that the flag is iterated over character by character and each character is encrypted with bytes from a large buffer. The loop also contains more code which manipulates the data in this buffer, however since neither these manipulations nor the accesses use the flag it self and only depend on hard coded values, I didn't look much closer into that part of the function and just assumed that it generates key bytes for the xor encryption independent of the input.

The other function that takes in the flag (after it was encrypted as described above) is this one:

```c,linenos
int strcmp(byte *flag,byte *param_2,int length) {
    int i;
    byte *str2;
    byte *str1;

    i = length;
    str2 = param_2;
    str1 = flag;
    while ( true ) {
        if (i < 1) {
            return 0;
        }
        if (*str1 != *str2) break;
        i = i + -1;
        str1 = str1 + 1;
        str2 = str2 + 1;
    }
    return (uint)*str1 - (uint)*str2;
}
```

Which can be easily recognized as an implementation of `strcmp`.

One other interesting function that I found looks like this:

```c,linenos,linenostart=24
    local_10 = fopen("/proc/self/maps","r");
    if (local_10 == (FILE *)0x0) {
        puts("i\'m dead");
        exit(1);
        uVar2 = 1;
    } else {
        do {
            pcVar3 = fgets(local_1438,0x1400,local_10);
            if (pcVar3 == (char *)0x0) break;
            local_2468[0] = 0;
            iVar1 = __isoc99_sscanf(local_1438,"%lx-%lx %s %lx %x:%x %u %s\n",&local_1440,&local_1448,
                                    local_144d,local_1458,local_145c,local_145a,local_246c,local_2468);
            local_18 = (long)iVar1;
        while ((local_144d[0] != 'r') || (local_144b != 'x'));
        fclose(local_10);
        local_20 = FUN_0010118c(local_1440 + 0x100,local_1448);
        if (local_20 == 0) {
            exit(42);
        }
        local_28 = FUN_0010118c(local_20 + 0x10,local_1448);
        if (local_28 == 0) {
            exit(42);
        }
        local_2c = FUN_00101ac0(local_20,local_28 - local_20);
        if (local_2c == 0x5285f228) {
            uVar2 = 0;
        } else {
            puts("i\'m dead");
            exit(0x2a);
            uVar2 = 1;
        }
    }
    return uVar2;
}
```

It seems to validate the memory layout without actually affecting the verification of the flag in any way besides terminating the process if the verification fails.

Putting all of this together we get code for the `dance_with_me` function that looks like this:

```c,linenos,linenostart=73
    flag_len = strlen(flag);
    init_keygenerator(keygenerator,&local_68,&local_74,0);
    cVar1 = memory_map_verification();
    if (cVar1 == 1) {
        puts("i\'m dead");
        outp = 1;
    } else {
        encrypt_flag(keygenerator,flag,flag_len);
        if (flag_len < 49) {
            outp = 1;
        } else {
            iVar2 = strcmp(flag,correct_ciphertext,49);
            if (iVar2 == 0) {
                outp = 0;
            } else {
                outp = 1;
            }
        }
    }
    return outp;
```

## Extracting the flag
Knowing that the flag is xor encrypted and the resulting ciphertext compared to a hard coded one, we should be able to run it with gdb and modify the arguments of the encryption to instead decrypt the hardcoded ciphertext. We can achieve this by replacing the flag argument of `encrypt_flag` with the expected ciphertext.

To do this we can simply write a program in C which loads the function and runs it, like so:

```c
#include <stdio.h>

int dance_with_me(char *flag);

void main() {
    dance_with_me("1111111111111111111111111111111111111111111111111");
}
```

However If we compile this and load it into gdb we get this:

```
cannot open shared object file: No such file or directory
```

Ok this is a quick fix. Simply run `export LD_LIBRARY_PATH=$PWD` which tells the dynamic linker where to find the shared object.

However running it now we still can't debug it:

```
[Inferior 1 (process 8105) exited with code 052]
```

After way too much confusion on my end, I finally remembered that certain code from a shared object is executed when it is loaded. Knowing this we can look at the different init functions in ghidra and find this:

```c,linenos
void _INIT_1(void) {
    memory_map_verification();
    return;
}
```

We already know `memory_map_verification` from earlier, it verifies the memory layout and terminates the process with exit code 42 if it is wrong. And as it turns out 052<sub>8</sub> = 42<sub>10</sub> which is the exact return code that gdb was telling us about.

Knowing this we can simply patch the `memory_map_verification` to completely disable it:

```
                    **************************************************************
                    *                          FUNCTION                          *
                    **************************************************************
                    undefined memory_map_verification()
     undefined         AL:1          <RETURN>
                      ...
                    memory_map_verification                       XREF[4]:    ...
0010125b c3             RET
```

Running it now we have no problems and can simply proceed as planned to get the flag:

```
pwndbg> print (char*) $rbp-0x40
$3 = 0x7fffffffdc90 "0xL4ugh{i_h0p3_you_l1k3d_ptr4c3_and_lat1n_danc3s}\336\377\377\377\177"
```
