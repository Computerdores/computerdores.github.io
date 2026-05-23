---
title: "Analysing the Panchan Botnet"
description: "A writeup analysing a malware sample of the panchan botnet."
date: 2026-05-23
updated: 2026-05-23
categories: ["writeups"]
---

## Intro

A while ago I wanted to reverse engineer some real-world malware and decided to setup an SSH honeypot to see what kind of stuff I might get.
Relatively quickly after that, the first malicious actor uploaded and tried to execute a piece of malware.
However, instead of just executing the malware the infected system provided it with a list of IPv4 addresses which piqued my interest.

In this writeup, I will first outline what I found while reverse engineering the malware.
In the second section, I will talk about mapping the botnet.
Finally, I will point out some prior work on this sample that I found and how their results compare to mine.

## The Malware

I analysed this sample in ghidra and quickly realised that the malware was written in golang.
Since I have not previously worked with golang binaries there were a couple of interesting things I learned:
1. Golang binaries, even when stripped, usually contain a `.gopclntab` section which contains a lot of useful metadata that is usually only part of the stripped debug information (function names, type names, some struct definitions, string locations, ...)
2. Ghidra has support for the golang calling conventions, however, to use these the compiler of the binary has to be set to "golang", instead of the default "gcc".

Generally, the malware is structured in a relatively modular fashion.
Each module gets initialised by the entrypoint and implements different functionality, with some cooperation.
The malware also has call-home functionality which originally informed the operator of newly infected clients.
However, this was implemented using a hardcoded discord webhook url which has since broken.
The auto-incrementing ID of the webhook indicates that the webhook was created before early 2025 and after mid 2021[^1].
Further, the malware implements persistence by copying itself to `/bin/systemd-worker` and creating a systemd service (`systemd-worker.service`)

**Spreader** - This module implements worming functionality to spread the malware.
One approach for this, which was noted by akamai as possibly being novel, is read the ssh `known_hosts` file and using ssh keys on the system to try to connect to and infect the known hosts.
Further, the malware tries a dictionary attack against ssh servers on random IPv4 addresses with just 82 different passwords.
Of the usernames and passwords that are tried, most are relatively expected except for "ジェリーフィッシュ" (jp. jellyfish).
The Akamai writeup suggests that the operator might be japanese, which matches this observation.
The reason for including this password candidate is not clear, my best quess is that perhaps some japanese cloud operator, device manufaturer, or similar used this as a default password.
After the spreader module has compromised a new system, it will copy itself to `./.<random number>/sshd` on the target system and then execute that binary with the IPv4 addresses of several known peers.

**P2P** - The p2p module implements peer-to-peer functionality in order to distribute certain configuration without having to connect to a central C2 server.
For this, the malware listens on port 1919/tcp and once a client connects it sends the eponymous header `pan-chan's mining island hi!`.
This is followed by sending the IPv4 addresses of 5 randomly selected peers.
If the client has any configuration information, it will also share this with the connected peer.
However, if the peer shares any such configuration the client will perform a cryptographic signature validation in order to assure that only the operator of the botnet can issue such configuration.

**Updater** - This module only runs if an update configuration was received by the p2p module.
If so it will further check that the id hash of the update differs from its own hash.
If this is the case, then it will fetch the updated binary from a URL that is provided as part of the update information.
Since none of the clients identified in my research had such update information, no update URL could be found.

**Cryptomining** - This module uses the configuration obtained via the p2p module in order to launch two different crypto miners.
As this part was not particularly interesting to me, I did not reverse engineer this module further.
The writeups by Akamai and Nozomi give more details for those that are interested.

**Anti-Kill** - This module hooks into SIGINT and redirects the signal in order to avoid soft-kills of the process.
However, since it can not prevent SIGKILL from stopping the process, this does not prevent the process from being able to be killed.

**Anti-Taskmanager** - This module monitors the active processes to look for `htop` and `top` and kills both crypto miners if they are detected.
This is likely an attempt to evade detection by sysadmins that try to investigate increased GPU usage.

**Protector** - This module seems to attempt to prevent automated takeover of the system by another malicious actor using a dictionary attack, while still allowing the legitimate owner to login via ssh to prevent detection.
To do this it kills sshd and implements it's functionality itself using `golang.org/x/crypto/ssh`.
However, when a shell session is started after a successfull login it shows the following prompt: `Please type "I am human" to prove that you are human: `.
Only after the user complies is a shell session actually opened.

Overall, this malware seems to be well engineered with a number of non-essential features that improve its persistence and worming.
Further, the operator seems to have learned from past botnets by avoiding a central C2 server that could be taken over and requiring cryptographic signatures for the p2p control messages.

## Mapping the Botnet

Once I realised that the p2p functionality always responds with a random set of 5 peer IPs, I quickly had the idea to use this in order to completely enumerate the botnet.
So after I was mostly done analysing the malware binary, I wrote a script to do just that.
The script would "squeeze" an infected host, by repeatedly connecting to the p2p port until a certain number of consecutive requests return no new peer IP address.
This way, similar to squeezing a sponge, the script would squeeze out most of the useful information without wasting to much time in an attempt to get out absolutely everything.
I then setup the script to squeeze all known previously infected hosts once an hour and let it run for around a week.
In this time the script found ~5k unique peer IP addresses.
Of these around 200 responded at least once and could thus be confirmed to be infected.
However, there was a significant rate of flux in the set of infected, online hosts, as at any point in time roughly 100 of the 200 were last seen online.

In comparison the writeup by Akamai from 2022 only found a total of 200 peers with 40 of them being online.
This could be explained by the botnet simply being smaller in size at the time.
Alternatively, it is possible that Akamai only queried each peer once, which would lead to a smaller set of discovered peers

Nozomi Networks in their writeup from 2024 found around 100 peers that were online.
However, instead of spidering the p2p mesh, they used a dataset of Go-based SSH servers and filtering for those that were actually infected.
Depending on how complete their dataset was and whether there was a netsplit of the p2p botnet at the time, this approach could have either lead to a more complete or to a less complete enumeration.

Klavansec found only roughly 100 total peers of which they confirmed 50 to be up in their writeup from Feburary 2026.
However, according to their description of the enumeration they indeed only queried each infected host once and only went three layers deep.
This would limit the amount of peers they could possibly find to just 125.
This means that their enumeration is most likely incomplete and should not be misunderstood as a complete one.
It is also woth noting that the number of total and online peers that they found is similar to those of Akamai, which might mean that Akamai did indeed only query each peer once.

Overall, I noticed both during different times in my scan and in the numbers of these writeups that the number of infected hosts often hovers closely around 100.
One could speculate that this is due to the operator proactively limiting the size of the botnet.
However, in my opinion it is much more likely that the infection rate is simply very close to the disinfection rate, leading to a relatively stable size of the botnet.
This is further reinforced by the observation that in my scanning none of the hosts returned a mining or update config and that the discord webhook is non-functional when the operator could have fixed this via the update functionality.
As it is the evidence points towards a rogue botnet which due to its worming capabilities has survived on the internet for close to four years today.

## Prior Work

There are a number of previously published writeups on this botnet, which I have also previously referenced in this writeup.
The following subsections will point out some of the differences between these and my research, in bullet points.

### Akamai

- Source: [www.akamai.com](https://www.akamai.com/blog/security-research/new-p2p-botnet-panchan)
- 4 years old (published 2022-06-15)
- several differences
- older version of the botnet
- p2p hello message is different
- admin panel they mention doesn't exist in current version
- doesn't disguise as xinetd, instead now uses sshd
- hash doesn't match hashes from their IoCs
- this version doesn't appear to handle SIGTERM, only SIGINT

### Nozomi Networks Labs

- Source: [www.nozominetworks.com](https://www.nozominetworks.com/blog/the-evolving-panchan-botnet)
- 2 years old (published 2024-07-18)
- overserved same hash of malware
- corroborates my findings
- have additional details on the format of the mining and update config

### klavansec

- Source: [klavansec.substack.com](https://klavansec.substack.com/p/we-mapped-a-live-p2p-botnet-from)
- 3-4 months old (published 2026-02-11)
- overserved same hash of malware
- they observe seeing the same hash and suggest that this might be a secondary operator
  - I find this theory highly questionable
  - a secondary operator would have replaced the public key required for remote configuration and the discord webhook link for call-home
  - both would have changed the hash of the binary
- they also state that "the botnet infrastructure is maintained"
  - I also question this
  - no mining config is shared by currently active peers
  - no update config either
  - this suggests that a long time has passed since either config was issued by the once operator
  - much more likely explanation: after the operator lost interest in the botnet, the worming and persistence capabilities kept the rogue botnet alive
- they state "Akamai and Nozomi gave us context we couldn’t have derived from static analysis alone"
  - as shown above, akamai analysed a different sample that they had on hand
  - this context could have been acquired via static analysis, see above section on the static reverse engineering I did
- "competing miner detection (`ps | grep '[Mm]iner'` — bracket syntax avoids matching the grep process itself)"
  - on all linux systems I have access to, `ps` outputs only the name of the process, not its cmdline
  - this means that the bracket syntax is not needed at all to prevent matching the grep process
  - further this bracket syntax is actually just a regex to match "miner" independent of first letter capitalisation
- all of these are quite trivial to recognise in my opinion
- all of this leads me to believe that the article was written by an LLM without the substantive human review that is necessary
  - this puts the acuracy of the entire article into question

[^1]: Discord webhook ids were around 1370000000000000000 in early 2025 and around 850000000000000000 in mid 2021. While the ID of the webhook used in the malware is 960954050583613549.
