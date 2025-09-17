---
title: "GPN - 'Honeypot'"
description: "A writeup for the 'honeypot' challenge from the GPN 2025."
date: 2025-07-09T20:00:00+02:00
categories: ["Writeups", "rev"]
tags: ["GPN", "GPN 2025"]
---

> I've just bought this property in a very priviledged part of the system.
> 
> But there seem to be(e) awfully many bees around. I just hope I can find a way out of this thing the developer has constructed here before I get stung...

**Solver:** computerdores, sohn123

**Categories:** rev

**Flag:** `GPNCTF{on_a_scale_from_1_to_10_h0w_WOULd_yOU_r4t3_yOUr_t00lIN6?}`

## Writeup
### Run Script
The first thing we can look at is the `running.md` and the `run.sh`:
```bash
#!/bin/bash

set +m

pgid=$(ps -o pgid= $$ | xargs)

sleep infinity & sleeppid=$!
trap "kill $sleeppid" SIGUSR1

run_governor() {
  java --enable-native-access=ALL-UNNAMED -jar $1 "$sleeppid" "-$pgid"
}

run_governor "$1" &

waitpid $sleeppid

echo "Enter your favourite way of printing your flag"

TARGET=flag

while :; do
    read -n 1 direction
    echo

    case $direction in
      h)
        head $TARGET &
        ;;
      t)
        tail $TARGET &
        ;;
      c)
        cat $TARGET &
        ;;
      b)
        base64 $TARGET | base64 -d &
        ;;
      *)
        echo "Invalid"
        kill -9 -- "-$pgid"
        ;;
    esac
done
```
From the `running.md` we know that the `run.sh` is supposed to be invoked with `honeypot.jar` as its first parameter.
Looking at the `run.sh` we can see that it first invokes the `honeypot.jar` as a background process and then waits for another process to be killed. After the process has been killed, the script then repeatedly asks the user to select one out of four programs to be executed on the flag file (head, tail, cat, or base64).

### Java Code
After decompiling the `honeypot.jar` we can see that its entrypoint calls the `run` method on the `Honeypot` class:
```java
public static Object run(String sleepPid, String[] killCommand) throws IOException, NoSuchAlgorithmException {
    boolean has_failed = false;
    Honeypot program = (Honeypot)BPFProgram.load(Honeypot.class);
    try {
        program.autoAttachPrograms();
        Thread thread = new Thread(() -> {
            try {
                Thread.sleep(28000L);
            }
            catch (InterruptedException interruptedException) {
                // empty catch block
            }
            System.out.println("Timed out");
            try {
                Runtime.getRuntime().exec(killCommand);
            }
            catch (IOException e) {
                throw new RuntimeException(e);
            }
        });
        program.attachScheduler();
        Runtime.getRuntime().exec(new String[]{"kill", "-SIGUSR1", sleepPid});
        thread.start();
        boolean placedKey = false;
        Thread traceReader = new Thread(() -> {
            while (true) {
                program.consumeAndThrow();
                System.out.println(TraceLog.getInstance().readFields().msg());
            }
        });
        traceReader.start();
        while (true) {
            if (program.var2.get().booleanValue() && !placedKey) {
                MessageDigest digest = MessageDigest.getInstance("SHA-512");
                Object[] collectedWrappedBytes = program.var6.get();
                byte[] collectedBytes = new byte[collectedWrappedBytes.length];
                for (int i = 0; i < collectedWrappedBytes.length; ++i) {
                    collectedBytes[i] = (Byte)collectedWrappedBytes[i];
                }
                byte[] digestBytes = digest.digest(collectedBytes);
                Byte[] flagXor = new Byte[64];
                for (int i = 0; i < flagXor.length; ++i) {
                    flagXor[i] = digestBytes[i];
                }
                program.var10.set(flagXor);
                placedKey = true;
            }
            if (!program.var1.get().booleanValue()) continue;
            if (!has_failed) {
                System.out.println("Failed");
            }
            has_failed = true;
            Runtime.getRuntime().exec(killCommand);
        }
    }
    catch (Throwable throwable) {
        if (program != null) {
            try {
                program.close();
            }
            catch (Throwable throwable2) {
                throwable.addSuppressed(throwable2);
            }
        }
        throw throwable;
    }
}
```
This function does three things:
1. It kills the process that the run.sh is waiting on,
2. starts a Berkley Packet Filter (BPF) program,
3. and observes fields of that program during its execution and modifies others based on their values.

Futher, looking at the `HoneypotImpl` class we can see the plaintext source code of the BPF program that is started there. It consists of a header file with type definitions and a source file with the implementation of the program.

### BPF Program
Given that the plaintext source code is available to us, we only need to work through it and assign sensible names to get a better understanding of what it does.

After doign that, the first thing we will look at is this syscall handler:

```C
SEC("tp/syscalls/sys_enter_openat") int handle_sys_enter_openat(struct OpenAtCtx *ctx) {
  u8 path[16] = "";
  BPF_SNPRINTF(path, sizeof(path), "%s", (*(ctx)).openAt.filename);
  if ((bpf_strncmp((const u8*)path, 4, (const u8*)"flag") != 0)) {
    return 0;
  }
  struct task_struct *task = bpf_get_current_task_btf();
  ({auto ___pointery__0 = (*(task)).pid; !bpf_map_push_elem(&var8, &___pointery__0, BPF_ANY);});
  ({auto ___pointery__0 = (*(task)).pid; auto ___pointery__1 = 1; !bpf_map_update_elem(&var9, &___pointery__0, &___pointery__1, BPF_ANY);});
  s32 cpu = scx_bpf_task_cpu((const struct task_struct*)task);
  scx_bpf_kick_cpu(cpu, (long)(SCX_KICK_PREEMPT));

  enum OP_CODE blockDirectionResult = get_op(task);
  exec_op(blockDirectionResult);
  
  if ((!trigger_set_key)) {
    s32 row = get_current_row();
    bpf_trace_printk("Nope, want to try something else?", sizeof("Nope, want to try something else?"), row, var4[row]);
  }
  
  return 1;
}
```

Whenever a program tries to open the flag file, this handler maps the name of the program to a value from the OP_CODE enum. Each of the four programs which can be invoked by the user in `run.sh` have a separate enum value and represent a different operation, all others get mapped to `OPC_NONE`.
Finally, it calls `exec_op` with the enum value representing one of the four possible operations.

#### exec\_op
The function mainly operates on two arrays `var3` and `var4`.
Furthermore, it keeps a counter of how often it has been executed, which we called `current_step`.
Those two arrays together with the `current_step` counter constitute the main runtime state and are modified by the method in every execution.

Another field it interacts with is the `key_src` array. In every iteration one value is written into this array at the index `current_step`. This array's content will later be used to compute the key for decrypting the flag.

This is what the `exec_op` function looks like:
```C
s32 exec_op(enum OP_CODE op_code) { // f2
  if ((op_code == OPC_NONE)) {
    return 0;
  }

  s32 row = get_current_row();  // 0 <= row < 64
  u64 character = (var4[row]) & (~(var3[row]));
  s32 col = get_column(character);  // 0 <= col < 64
  s8 value = grid[(row * 64) + col];

  if ((current_step >= 500)) {
    trigger_failure = 1;
    return 1;
  }

  key_src[current_step] = value;
  current_step = current_step + 1;

  // all of the following operations:
  // - set var3[row] to var4[row]
  // - increase the number of bits set in var4[row] (otherwise failure is triggered)
  s32 placed_row = row;
  if (op_code == OPC_HEAD) {
    // row--
    if ((row > 0) && (row < 64)) { // row != 0
      placed_row = row - 1;
      var3[row] = var4[row];
      var4[placed_row] |= character;

    } else {
      var4[placed_row] = var3[placed_row];
    }

  } else if (op_code == OPC_TAIL) {
    // row++
    if (row < 63) {  // row != 63
      placed_row = row + 1;
      var3[row] = var4[row];
      var4[placed_row] |= character;
    } else {
      var4[placed_row] = var3[placed_row];
    }

  } else if (op_code == OPC_CAT) {
    var3[row] = var4[row];
    var4[placed_row] = (var3[row]) | (character << 1);

  } else if (op_code == OPC_BASE64) {
    var3[row] = var4[row];
    var4[placed_row] = (var3[row]) | (character >> 1);
  }

  if (((row == 63) && (character == 1L))) {
    trigger_set_key = 1; // success
  } else if (((var4[placed_row]) == ((s64)var3[placed_row]))) {
    trigger_failure = 1;
  }
  
  return 0;
}
```
It first computes the current row, which is just the smallest positive number for which `var3` and `var4` have different values.
Next, it sets `key_src` at the index `current_step` to a value (here called `character`) calculated from the values of `var3` and `var4` at the current row.
It then modifies `var3` and `var4` based on the current row and the operation it was called with.

Last but not least, it does two checks:
1. If it has reached the 64th row and the `character` is 1, it sets a flag which triggers `Honeypot.run` to compute the decryption by hashing `key_src`. The resulting key is written to `key`.
2. If the field of `var4` which was modified by the operation does not differ from the value in `var3` at the same index, another flag is set which causes `Honeypot.run` to abort execution and report failure.

This same flag for triggering failure is also used to abort if `current_step` reaches 500.

The value of `key` is used in a syscall handler for reads of the flag file to decrypt the content of the file and return the plaintext instead of the ciphertext actually contained by the file.

With this knowledge of what the program does we can now implement a solver.

### Solver
To get the flag we need to find a sequence of operations which is valid in every step and ends at the 64th row with the `character` value being 1.

At this point we thought the decision tree for choosing the operation sequence to be quite slim, because we believed that the specific transformations applied by `exec_op` to `var3` and `var4` would very often cause one of the validated conditions to fail. For this reason we opted to implement a very simple depth-first search solver.

The solver traverses the decision tree and applies the appropriate transformations to the state. When it encounters a state which would cause `exec_op` to trigger failure it abandons the entire subtree as `exec_op` would trigger failure in that case. This is the final solve script:

```python
from enum import Enum
from hashlib import sha512

class OP_CODE(Enum):
    NONE = 0
    HEAD = 1
    TAIL = 2
    CAT = 3
    B64 = 4

C1 = [ ... ]
C2 = [ ... ]
GRID = [v % 256 for v in C2]

MIN_VALUE = pow(2,63)
U64_MASK = pow(2,64) - 1

# Init stuff
KEY_SRC = [0] * 500

VAR3 = C1[:]
VAR4 = C1[:]
VAR4[0] = VAR3[0] ^ (1 << 63)

class State:
    op_idx: int
    var3: list[int]
    var4: list[int]
    key_src: list[int]

    def __init__(self, op_idx: int = 0, var3: list[int] = VAR3, var4: list[int] = VAR4, key_src: list[int] = KEY_SRC):
        self.op_idx = op_idx
        self.var3 = var3
        self.var4 = var4
        self.key_src = key_src

    def _get_current_row(self) -> int:
        for i in range(64):
            if self.var3[i] != self.var4[i]:
                return i
        return 0
    
    def _get_current_col(self, character) -> int:
        cur = character
        i = 0
        while i < 64 and cur != MIN_VALUE:
            cur <<= 1
            cur &= U64_MASK
            i += 1
        if i >= 64:
            return 0
        return i
    
    def _phi(self, a: int, b: int) -> int:
        return a & (~b)

    def solve(self) -> list[int] | None:
        row = self._get_current_row()
        character = self._phi(self.var4[row], self.var3[row])
        col = self._get_current_col(character)
        value = GRID[(row * 64) + col]

        if self.op_idx >= 500:
            return None

        self.key_src[self.op_idx] = value
        self.op_idx += 1

        res = None
        for opc in OP_CODE:
            change_row = row

            var3 = self.var3[:]
            var4 = self.var4[:]

            match opc:
                case OP_CODE.HEAD:
                    if row > 0 and row < 64:
                        change_row = row - 1
                        var3[row] = var4[row]
                        var4[change_row] |= character
                    else:
                        var4[change_row] = var3[change_row]
                case OP_CODE.TAIL:
                    if row < 63:
                        change_row = row + 1
                        var3[row] = var4[row]
                        var4[change_row] |= character
                    else:
                        var4[change_row] = var3[change_row]
                case OP_CODE.CAT:
                    var3[row] = var4[row]
                    var4[change_row] = var3[row] | ((character << 1) & U64_MASK)
                case OP_CODE.B64:
                    var3[row] = var4[row]
                    var4[change_row] = var3[row] | character >> 1
                case OP_CODE.NONE:
                    continue
                case _:
                    raise RuntimeError()
            
            if row == 63 and character == 1:
                return self.key_src
            elif var4[change_row] == var3[change_row]:
                continue

            res = State(self.op_idx, var3, var4, self.key_src.copy()).solve()
            if res is not None:
                break
        return res



if __name__ == "__main__":
    state = State()
    ks = state.solve()
    key = sha512(bytes(ks)).digest()
    with open("flag", "rb") as f:
        cipher = f.read()
    plain = [k ^ c for k, c in zip(key, cipher)]
    print(bytes(plain).decode())
```

Running this solver will immediately output the following flag, proving our hypothesis that the tree quite slim:
```
> python solve.py
GPNCTF{on_a_scale_from_1_to_10_h0w_WOULd_yOU_r4t3_yOUr_t00lIN6?}
``` 
