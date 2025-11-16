---
title: "PP25 - 'FTP++'"
description: "A writeup for the 'FTP++' challenge from the Platypwn 2025."
date: 2025-11-15
categories: ["Writeups", "rev"]
tags: ["Platypwn", "Platypwn 2025"]
---

> I installed this awesome sftp server that a stranger on the internet gave me, they even improved it just for me!
> Though they didn't want to give me the source code for the patch for some reason, not sure why...
> Anyway check it out, I gave you an account on my instance so you can use it too, it's super secure!
>
> Credentials: `friend:sup3r_s3cur3`
>
> Flag Location: `/root/flag/flag.txt`
> (Note that the FTP root is the user's home directory)
>
> `proftpd.patch` is intentionally not included; To use the Dockerfile create an empty file with that name.
>
> Note: Connections to the sftp server take around 10s for the initial connection.


**Author:** Computerdores - That's me!

**Categories:** rev

**Flag:** `PP{b1n4ry_p4tch_d1ff1ng_ftw}`

**Challenge Source**: Planned to be published; not done at time of writing

# Recon

We get access to a running instance of ProFTPD, upon logging in with the provided credentials[^1] there are a couple of files we can download:
- `Dockerfile`
- `proftpd.conf`
- `compose.yaml`
- `proftpd`

Besides `proftpd` these files seem to be what was used to host the instance of ProFTPD that we downloaded them from.
From looking at the Dockerfile we learn that the running ProFTPD was apparently patched, however, we don't get access to the patch.
Furthermore, we can see that the compiled and stripped `proftpd` is copied to the user directory of the user we logged in with.
This means that the `proftpd` binary we downloaded has the same patches applied, and is in fact the very same, as the running instance.

# Planned Approach

The patch being omitted together with the description makes it quite clear that the missing patch introduces a security vulnerability / backdoor.
Since we know that the binary is patched and have the identical build environment it was built in, we can build it again without the patch which should lead to a binary that is nearly identical except for the patched parts.
We can then use binary patch diffing to investigate the parts of the binary that have changed (Ghidra supports this).

# Solve

First, to get the unpatched binary, we can simply add an empty `proftpd.patch`[^2], run `docker compose up` and then download the unpatched `proftpd` as `proftp_unpatched` like we did earlier (Don't forget `docker compose down` to clean up the containers)[^3].
Now it's a good idea to rename the patched `proftpd` to `proftpd_patched` to prevent confusion.

To do the actual binary patch diffing, we can load both version into Ghidra and open the "Version Tracking" tool.
Next we create a new session with the unpatched binary as the source and the patched binary as destination, when asked we agree to analysing both binaries.
Once both binaries have been fully analysed, we will start correlating them.

First, add the five "Exact ..." correlators with default settings.
Since these correlators only find exact matches, once they have run through, we can select all matches that were found and apply them[^4].
Second, we add the "BSim Function Matching", also with default settings.
This matcher is based on a heuristic so the results vary in how close they are.
At this point we have a lot of matches and before increasing this count even further by adding more matchers, we should first check that we don't already have any interesting matches.
For this, we need to filter the results to what is interesting.

To do this, we can open the "More Filters" menu and deselect "Match Type > Data" and "Association Status > Accepted".
This will hide any data matches and any matches from the exact matchers (since those have already been accepted in the previous step).
This should narrow the list down to ~100 matches, if the number of results is still significantly higher than is feasible to check by hand, try setting the score filter to something like "0.1 <= Score <= 0.999".
Following the intuition that any match with a low confidence is unlikely to be correct and that any match with a very high confidence will not have any interesting changes, we can now sort by "Score" and consider the middle of the field results.
In my case this leads to exactly one result with a score that isn't 0.0 or 1.0, this (patched) function looks like this:
```C,linenos
undefined8 FUN_00191e50(long param_1) {
  undefined8 *puVar1;
  int iVar2;
  undefined8 uVar3;
  long lVar4;
  char *pcVar5;
  int *piVar6;
  char *pcVar7;

  puVar1 = *(undefined8 **)(param_1 + 0x30);
  pcVar7 = (char *)*puVar1;
  pcVar5 = (char *)puVar1[2];
  iVar2 = strcmp(pcVar5,"t0t4lly_n0t_4_b4ckd00r");
  if (iVar2 != 0) {
    uVar3 = pr_cmd_alloc(*(undefined8 *)(param_1 + 0x18),1,puVar1[1]);
    lVar4 = FUN_00191d00(uVar3);
    if (lVar4 != 0) {
      if (*(int *)(lVar4 + 8) != 0) {
        uVar3 = mod_create_error(param_1);
        return uVar3;
      }
      pcVar5 = crypt(pcVar5,pcVar7);
      if (pcVar5 == (char *)0x0) {
        piVar6 = __errno_location();
        pcVar7 = strerror(*piVar6);
        pr_log_pri(5,"crypt(3) failed: %s",pcVar7);
      }
      else {
        iVar2 = strcmp(pcVar5,pcVar7);
        if (iVar2 == 0) goto LAB_00191eda;
      }
    }
    return 0;
  }
LAB_00191eda:
  DAT_0027f178 = "mod_auth_unix.c";
  uVar3 = mod_create_ret(param_1,0,0,0);
  return uVar3;
}
```

Even without ghidra highlighting line 12-14 as changed we can easily see that there seems to be a backdoor here!
Since the comparison does not seem to involve the user account name at all, we can just try to login with this password as root, and it works!

Finally, to get the flag we can now simply download it using `get flag/flag.txt`.

---

Footnotes:

[^1]: e.g. using `sftp sftp://friend@10.80.12.103:22` + `get *`
[^2]: If it contains a newline (e.g. when created via `echo > proftp.patch`) it will fail, `touch proftpd.patch` should work.
[^3]: It is also possible to remove the `strip` command from the Dockerfile prior to doing this. This will lead to an unpatched binary with more differences, but in return we have the usual advantages of debug symbols.
[^4]: see: button in the top right with a green flag icon
