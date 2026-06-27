---
title: UEFI Crackme
date: 2026-06-28
extra:
  started_writing: 2026-06-26
---

Recently, my laptop (an Acer A315-23) decided to randomly enable secure boot and since my linux install is obviously not signed, it proceeded to not boot anymore.
Given that I had work to do, I immediately went to disable it, only to realise I had at some point set a password for my UEFI.
The only problem: I didn't remember it, only that I had set something simple.
And so it happened that I tried 3 incorrect UEFI passwords and was greeted with this:

```
┌────────────────────────────────────────┐
│ Enter Unlock Password(Key: xxXXxxXXxx) │
├────────────────────────────────────────┤
│█                                       │
└────────────────────────────────────────┘
```

Which immediately prompted the question: "What the hell is an Unlock Password and why is it telling me about a key?"
After a bit of googling, it seemed to me that this is intended to be a way for Acer to sell UEFI unlocks to people, with the key being used as a nonce.

And while, later the same day, I managed to guess my UEFI password (it was "1"), I was immediately hooked on reversing this.
Afterall, this is basically an in-the-wild crackme and with CTF [kinda, sorta, maybe being dead](https://kabir.au/blog/the-ctf-scene-is-dead), I am a rev-starved rev-addict.

## Extracting UEFI image

The first step was of course getting my hands on a UEFI image I can reverse.
Luckily, Acer provides a seemingly complete list of released versions of the UEFI firmware with download links on their website.

After downloading the image for the version currently installed on my Laptop (1.19), it took me quite a bit to actually get something to reverse.
Because as all manufacturers seem to do, Acer ships a single executable UEFI updater that you are supposed to run.
Using binwalk's `--extract` functionality quickly yielded me a bunch of files, whose names seemed reminiscent of extracted Insyde UEFI's I had found [online](https://github.com/eabase/UEFI-Repair-Guide-Wiki/blob/master/Insyde-Flash-Firmware-Tool-(H2OFFT).md).
After some googling, I was able to identify two of the included files as UEFI image files: `Z8E_multi.fd` and `Z8E2_multi.fd`.

At this point I found the `uefitool` package with the `uefiextract` tool.
I used this to extract a bunch of PE32 EFI modules from the image (I used `Z8E2_multi.fd`, the stuff relevant to this post seemed to be the same in both files).
Looking through those modules, it wasn't long until I found my target: `A01UnlockPassword`.

## Reversing the UEFI Module

Looking into the UEFI module my first step was to look for the strings I had already seen while interacting with the unlock mechanism.
I was quickly able to identify this formatting call:

```C
sub_4014d0(msg, 0x200, u"%s(Key:%s)", buffer);
```

Which lead me to this string comparison of a string computed in the same method: 

```C
generate_upw_bin(&buf, 0xa, &out);
bytes_to_wstr(&out, unlock_password);
// ...
else if (wstrcmp(unlock_password, input?))
    rsi = EFI_SECURITY_VIOLATION;
```

And while I had obviously not named these methods as you see them here yet, it did immediately seem like this comparison would be the actual check.
From here I discovered that the only input for the generation (the "Key" we are shown) seemed to be a value loaded from a UEFI Variable in the parent function:

```C
VariableName = u"AUPS"; // with fallback to u"AUPH" and u"AUPU" if variable is not set
status = gRT->GetVariable(VariableName, &UnknownVendorGuid, 0, &DataSize, &variable_data);
result_1 = ask_unlock_pw((char*)arg1 - 0x30, variable_data, arg2, r9_2);

if (result_1 >= EFI_SUCCESS) {
    gRT->SetVariable(VariableName, &UnknownVendorGuid, 
        EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS
            | EFI_VARIABLE_RUNTIME_ACCESS, 
        0, nullptr);
    result = EFI_SUCCESS;
}
```

As you can see all candidates for the varible name contain "AUP" which probably stands for "Acer Unlock Password".
These variables are all associated with the UEFI Vendor GUID `89CB0E8D-393C-4830-BFFF65D9147E8C3B`, which I was not able to conclusively attribute.
I suspect that it belongs either to Acer or to Insyde, since the latter is/was also involved in the development of this UEFI FW.

We can also see that the variable is cleared, if the unlock password (UPW) is entered correctly, making sure that each UPW can only be used once.
I also found the function responsible for generating new keys for the UPW generation, however, it makes use of several non-standard UEFI protocols and the current time, so I didn't look into it further.

## Firmware Rehosting

Before getting into the weeds on reversing the generation process, I first wanted to make sure I could validate partial findings and debug a future reimplementation of the process.
For this I turned to firmware rehosting using unicorn.

I wrote up a ~100 line python script that would load the PE32 into memory and prepare the emulator for running the `generate_upw_bin` function on its own.
For this I simply had it load the necessary parameters for the function into memory and wrote some hooks to tell me intermediate results and stop execution after the function was finished.

This meant that on the second evening of this project, I was already able to generate Unlock Passwords via this rehosting setup.

## Reversing the UPW generation

With this context information I decided to dive into the function I called `generate_upw_bin`.
It is responsible for generating an 8 byte value whose hex representation will be the UPW.
The only input it takes is the ascii decimal representation of the key.

Looking into the function, I could see that it is made up of three steps that each yield an intermediate buffer.
Because I suspected that they didn't come up with this entirely on their own, I used an LLM to help identify these steps and was met with great success.
After validating the claims of LLM via my rehosting setup, I had already minimal python code for two thirds of the process.
It turned out that the first step was simply calculating the SHA 256 digest, while the third step was just calculating the reversed ECMA182 variant of CRC64.

This left just the second step to reverse engineer, which proved a little more interesting.
It turns out that they implemented two custom shuffling routines, which produce a plaintext and a key from the SHA 256 digest.
These are then fed into 10-round AES128 and the resulting cipher text is fed into the aforementioned CRC64 to produce the final output.

## Password Generator

With the insights gained from reverse engineering this, it was relatively simple to write a python reimplementation of the password generation.
I was debating whether to release this, however, during my research I found a third party website where you can buy these Unlock Passswords.
And the existance of this third party site means that any modicum of a security benefit from Secure Boot is already gone on these devices anyway.
Because of that I am releasing this, because it benefits right to repair and makes sure that even if Acer shuts down their version of this, people can still unlock their UEFIs.

With that said, you can find the python script on my github: [Computerdores/acer-uefi-upw-gen](https://github.com/Computerdores/acer-uefi-upw-gen).
Also, if you have an Acer Laptop feel free to test it and let me know if it works, as I only know that it works on my Acer A315-23.
