{backmatter}

# Attributions

## Introduction

**Bruce Schneier Sensible Security Model (SSM)**  
[http://www.win.tue.nl/~wstomv/quotes/beyond-fear.html](http://www.win.tue.nl/~wstomv/quotes/beyond-fear.html)

## [VPS](#vps)

**Also being a Telnet replacement**  
[https://technet.microsoft.com/en-us/sysinternals/bb897553.aspx](https://technet.microsoft.com/en-us/sysinternals/bb897553.aspx)

**The PSExec utility requires** a few things on the target system. Details on rapid7  
[https://community.rapid7.com/community/metasploit/blog/2013/03/09/psexec-demystified](https://community.rapid7.com/community/metasploit/blog/2013/03/09/psexec-demystified)

**With this attack you will have had to have obtained the targets** username and password or password hash  
[https://www.offensive-security.com/metasploit-unleashed/psexec-pass-hash/](https://www.offensive-security.com/metasploit-unleashed/psexec-pass-hash/)

**Kali Linux also has the "Pass the Hash toolkit"**  
[https://www.kali.org/tutorials/pass-the-hash-toolkit-winexe-updates/](https://www.kali.org/tutorials/pass-the-hash-toolkit-winexe-updates/)"

**`current_user_psexec`**  
[https://www.rapid7.com/db/modules/exploit/windows/local/current_user_psexec](https://www.rapid7.com/db/modules/exploit/windows/local/current_user_psexec)

**`psexec_command`**  
[https://www.rapid7.com/db/modules/auxiliary/admin/smb/psexec_command](https://www.rapid7.com/db/modules/auxiliary/admin/smb/psexec_command)

**`psexec_loggedin_users`**  
[https://www.rapid7.com/db/modules/auxiliary/scanner/smb/psexec_loggedin_users](https://www.rapid7.com/db/modules/auxiliary/scanner/smb/psexec_loggedin_users)

**`psexec_psh`**  
[https://www.rapid7.com/db/modules/exploit/windows/smb/psexec_psh](https://www.rapid7.com/db/modules/exploit/windows/smb/psexec_psh)

**`psexec_ntdsgrab`**  
[https://www.rapid7.com/db/modules/auxiliary/admin/smb/psexec_ntdsgrab](https://www.rapid7.com/db/modules/auxiliary/admin/smb/psexec_ntdsgrab)

**Native Windows tool "vssadmin"** visible in the source  
[https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/admin/smb/psexec_ntdsgrab.rb#L55](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/admin/smb/psexec_ntdsgrab.rb#L55)

**`wmi`**  
[https://www.rapid7.com/db/modules/exploit/windows/local/wmi](https://www.rapid7.com/db/modules/exploit/windows/local/wmi) 

**WMI Providers** provide interfaces for configuring and monitoring Windows services, along with programming interfaces for consumption via custom built tools  
[https://msdn.microsoft.com/en-us/library/aa394570(v=vs.85).aspx](https://msdn.microsoft.com/en-us/library/aa394570(v=vs.85).aspx) 

**We use the WMI Command-line (WMIC) command** to start a Remote Procedure Call  
https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/post/windows/  
wmic.rb#L48

**Then create a ReverseListenerComm** to tunnel traffic through that session  
[https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/local/wmi.rb#L61](https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/local/wmi.rb#L61)

**By default PowerShell is installed** on Windows Server 2008 R2 and Windows 7 onwards  
[https://blogs.msdn.microsoft.com/powershell/2008/10/28/powershell-will-be-installed-by-default-on-windows-server-08-r2-ws08r2-and-windows-7-w7/](https://blogs.msdn.microsoft.com/powershell/2008/10/28/powershell-will-be-installed-by-default-on-windows-server-08-r2-ws08r2-and-windows-7-w7/)

**psmsf is licensed with BSD License**  
[https://github.com/nixawk/psmsf/blob/master/License.txt](https://github.com/nixawk/psmsf/blob/master/License.txt)

**Trustedsec `unicorn.py`**  
https://github.com/trustedsec/unicorn/blob/6f245ebe0c4ab465f15edea12767604120dd0276/uni  
corn.py#L362-L363

**Upstream of unicorn is `Invoke-Shellcode.ps1`** of the PowerShellMafia PowerSploit project  
https://github.com/PowerShellMafia/PowerSploit/blob/master/CodeExecution/Invoke-Shell  
code.ps1

**Matt blog posted on this technique in 2011**  
[http://www.exploit-monday.com/2011/10/exploiting-powershells-features-not.html](http://www.exploit-monday.com/2011/10/exploiting-powershells-features-not.html)

**Veil-Framework’s Veil-Evasion has a similar set of payloads**  
[https://github.com/Veil-Framework/Veil-Evasion/tree/master/modules/payloads/powershell](https://github.com/Veil-Framework/Veil-Evasion/tree/master/modules/payloads/powershell)

**@harmj0y blog posted on**  
[https://www.veil-framework.com/powershell-payloads/](https://www.veil-framework.com/powershell-payloads/)

**Kevin Dick also wrote a decent blog post**  
http://threat.tevora.com/dissecting-veil-evasion-powershell-payloads-and-converting-to-a-b  
ind-shell/

**Nishang has a collection of scripts** which can create office documents such as Word, Excel, CHM and a handful of others  
https://github.com/samratashok/nishang/tree/1b5aca1a1eb170befccf1d111e8902285d553289/  
Client

**Metasploit had a Meterpreter script** called `persistence.rb`  
[https://www.offensive-security.com/metasploit-unleashed/meterpreter-service/](https://www.offensive-security.com/metasploit-unleashed/meterpreter-service/)

**Now the `exploit/windows/local/persistence` module** is recommended for persistence. AV picks this up on reboot though  
[https://github.com/rapid7/metasploit-framework/issues/6904](https://github.com/rapid7/metasploit-framework/issues/6904)

**PowerSploit has a module called Persistence**  
[https://github.com/PowerShellMafia/PowerSploit/blob/master/Persistence/Persistence.psm1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Persistence/Persistence.psm1)

**Nishang `Add-Persistence.ps1` script**  
https://github.com/samratashok/nishang/blob/1b5aca1a1eb170befccf1d111e8902285d553289/  
Utility/Add-Persistence.ps1

**The Windows computer is considered to be idle if**  
https://social.technet.microsoft.com/Forums/windows/en-US/692783e7-bb73-45d1-95d6-8f2d  
1363d6c7/cant-get-task-schedular-to-run-a-batch-on-idle?forum=w7itprogeneral

**unix-privesc-check**  
[http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)

**Its source code on github**  
[https://github.com/pentestmonkey/unix-privesc-check](https://github.com/pentestmonkey/unix-privesc-check)

**LinEnum is also very good at host reconnaissance**  
[https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum) 

**There are also many other options to use for providing a reverse shell**  
[http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)

**Level 3 Threat Research Labs** published a blog post on this port mapper DoS attack and how it has become very popular since the beginning of August 2015  
[http://blog.level3.com/security/a-new-ddos-reflection-attack-portmapper-an-early-warning-to-the-industry/](http://blog.level3.com/security/a-new-ddos-reflection-attack-portmapper-an-early-warning-to-the-industry/)

**US-CERT also published an alert on UDP-Based Amplification Attacks** outlining the Protocols, Bandwidth Amplification Factor, etc.  
[https://www.us-cert.gov/ncas/alerts/TA14-017A](https://www.us-cert.gov/ncas/alerts/TA14-017A)

**The very front page of the Exim website** states "All versions of Exim previous to version 4.87 are now obsolete and everyone is very strongly recommended to upgrade to a current release.".

**Lax authentication while querying of NIS maps** (easy for a compromised client to take advantage of), as well as the various daemons each having their own individual issues. Not to mention that misconfiguration of NIS or netgroups can also provide easy holes that can be exploited. NIS databases can also be easily accessed by someone who doesn't belong on your network. How? They simply can guess the name of your NIS domain, bind their client to that domain, and run a ypcat command to get the information they are after.  
[https://www.symantec.com/connect/articles/nfs-and-nis-security](https://www.symantec.com/connect/articles/nfs-and-nis-security)

**FTP protocol was not designed with security in mind**  
[https://archive.fo/KyJUa](https://archive.fo/KyJUa)

**By default, when a user enters their password** on the authentication window, it is stored in memory and reused for all subsequent authentications during the same session.  
[https://winscp.net/eng/docs/security_credentials](https://winscp.net/eng/docs/security_credentials)

**These passwords are stored obfuscated**, as the documentation puts it "_stored in a manner that they can easily be recovered_  
[https://winscp.net/eng/docs/security_credentials](https://winscp.net/eng/docs/security_credentials)".

**Check the `EncryptPassword` function on github**  
[https://github.com/mirror/winscp/blob/master/source/core/Security.cpp#L34](https://github.com/mirror/winscp/blob/master/source/core/Security.cpp#L34)

**Although this option exists, it is recommended against**  
[https://winscp.net/eng/docs/faq_password](https://winscp.net/eng/docs/faq_password).

**The exploit `decrypt_password` consumed by the `winscp` metasploit module**  
[https://github.com/rapid7/metasploit-framework/blob/master/lib/rex/parser/winscp.rb#L81](https://github.com/rapid7/metasploit-framework/blob/master/lib/rex/parser/winscp.rb#L81)  
[https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/credentials/winscp.rb#L82](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/credentials/winscp.rb#L82)  
[https://www.rapid7.com/db/modules/post/windows/gather/credentials/winscp](https://www.rapid7.com/db/modules/post/windows/gather/credentials/winscp)  

**Additional details on the cosine-security blog**  
[https://cosine-security.blogspot.co.nz/2011/04/stealing-winscp-saved-passwords.html](https://cosine-security.blogspot.co.nz/2011/04/stealing-winscp-saved-passwords.html)

**This appears to use a custom implementation** of the AES256 block cipher, with a hard-coded 1000 rounds of SHA1  
[https://github.com/mirror/winscp/blob/master/source/core/Cryptography.cpp](https://github.com/mirror/winscp/blob/master/source/core/Cryptography.cpp) 

**Any attacker worth their weight** will try to cover their tracks as they progress  
[http://www.win.tue.nl/~aeb/linux/hh/hh-13.html](http://www.win.tue.nl/~aeb/linux/hh/hh-13.html)

**Taking things further**, an attacker may load a kernel module that modifies the `readdir()` call  
[http://pubs.opengroup.org/onlinepubs/9699919799/functions/readdir.html](http://pubs.opengroup.org/onlinepubs/9699919799/functions/readdir.html)

**Without visibility**, an attacker can access your system(s) and, alter, copy  
[https://github.com/m57/dnsteal](https://github.com/m57/dnsteal)

%% Identify Risks Docker







**As noted by banyan**  
[https://www.banyanops.com/blog/analyzing-docker-hub/](https://www.banyanops.com/blog/analyzing-docker-hub/)  
and the morning paper  
[https://blog.acolyer.org/2017/04/03/a-study-of-security-vulnerabilities-on-docker-hub/](https://blog.acolyer.org/2017/04/03/a-study-of-security-vulnerabilities-on-docker-hub/)

**The Docker overview** says: “_Docker provides the ability to package and run an application in a loosely isolated environment_”  
[https://docs.docker.com/engine/understanding-docker/](https://docs.docker.com/engine/understanding-docker/)

**The Docker Registry project** is an open-source server side application that lets you store and distribute Docker images  
[https://github.com/docker/distribution](https://github.com/docker/distribution)

**Considering these processes run as root**, and have indirect access to most of the Linux Kernel  
[https://theinvisiblethings.blogspot.co.nz/2012/09/how-is-qubes-os-different-from.html](https://theinvisiblethings.blogspot.co.nz/2012/09/how-is-qubes-os-different-from.html)

**All before any security is added on top** in the form of LXC, or libcontainer (now opencontainers/runc)  
[https://github.com/opencontainers/runc](https://github.com/opencontainers/runc)

**The first place to read for solid background** on Linux kernel namespaces is the man-page  
[http://man7.org/linux/man-pages/man7/namespaces.7.html](http://man7.org/linux/man-pages/man7/namespaces.7.html)

**The hosts mounted `host-path` is shared** with all others that mount `host-path`  
[https://docs.docker.com/engine/reference/run/#volume-shared-filesystems](https://docs.docker.com/engine/reference/run/#volume-shared-filesystems) 

**If you omit the `host-path`** you can see the host path that was mounted  
[https://docs.docker.com/engine/tutorials/dockervolumes/#locating-a-volume](https://docs.docker.com/engine/tutorials/dockervolumes/#locating-a-volume) 

**Further details can be found** at the dockervolumes documentation  
[https://docs.docker.com/engine/tutorials/dockervolumes/#volume-labels](https://docs.docker.com/engine/tutorials/dockervolumes/#volume-labels)

**`PID` namespaces are hierarchically nested** in ancestor-descendant relationships to a depth of up to 32 levels  
[https://lwn.net/Articles/531419/](https://lwn.net/Articles/531419/) 

**The default behaviour can however be overridden** to allow a container to be able to access processes within a sibling container, or the hosts `PID` namespace  
[https://docs.docker.com/engine/reference/run/#pid-settings---pid](https://docs.docker.com/engine/reference/run/#pid-settings---pid)

**As an aside, `PID` namespaces give us the functionality** of "_suspending/resuming the set of processes in the container and migrating the container to a new host while the processes inside the container maintain the same PIDs._"  
[http://man7.org/linux/man-pages/man7/pid_namespaces.7.html](http://man7.org/linux/man-pages/man7/pid_namespaces.7.html)  
with a handful of commands  
https://www.fir3net.com/Containers/Docker/the-essential-guide-in-transporting-your-docke  
r-containers.html

**A UTS namespace** is the set of identifiers returned by `uname`  
[http://man7.org/linux/man-pages/man2/clone.2.html](http://man7.org/linux/man-pages/man2/clone.2.html)

**When a container is created**, a UTS namespace is copied (`CLONE_NEWUTS` is set)  
https://github.com/docker/libcontainer/blob/83a102cc68a09d890cce3b6c2e5c14c49e6373a0/S  
PEC.md

**When a container is created** with `--uts="host"` a UTS namespace is inherited from the host  
[https://docs.docker.com/engine/reference/run/#uts-settings---uts](https://docs.docker.com/engine/reference/run/#uts-settings---uts)

**According to the namespaces man page** "_Objects created in an IPC namespace are visible to all other processes that are members of that namespace, but are not visible to processes in other IPC namespaces._"  
[http://man7.org/linux/man-pages/man7/namespaces.7.html](http://man7.org/linux/man-pages/man7/namespaces.7.html)

**This behaviour can be overridden** to allow a (any) container to reuse another containers or the hosts message queues, semaphores, and shared memory via their IPC namespace  
[https://docs.docker.com/engine/reference/run/#ipc-settings---ipc](https://docs.docker.com/engine/reference/run/#ipc-settings---ipc)

**You can see using the command** supplied from the CIS_Docker_1.13.0_Benchmark  
[https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf](https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf)

**There are currently some Docker features** that are incompatible with using user namespaces  
[https://docs.docker.com/engine/reference/commandline/dockerd/#user-namespace-known-restrictions](https://docs.docker.com/engine/reference/commandline/dockerd/#user-namespace-known-restrictions) 

**Docker engine reference** provides additional details around known restrictions of user namespaces  
[https://docs.docker.com/engine/reference/commandline/dockerd/#user-namespace-known-restrictions](https://docs.docker.com/engine/reference/commandline/dockerd/#user-namespace-known-restrictions)

**Cgroups have been available** in the Linux kernel since January 2008 (2.6.24)  
[https://kernelnewbies.org/Linux_2_6_24#head-5b7511c1e918963d347abc8ed4b75215877d3aa3](https://kernelnewbies.org/Linux_2_6_24#head-5b7511c1e918963d347abc8ed4b75215877d3aa3)

**According to the Linux man page for capabilities** "_Linux divides the privileges traditionally associated with superuser into distinct units, known as capabilities, which can be independently enabled and disabled_"  
[http://man7.org/linux/man-pages/man7/capabilities.7.html](http://man7.org/linux/man-pages/man7/capabilities.7.html)

**Dan Walsh** who is one of the experts when it comes to applying least privilege to containers, also discusses these  
[http://rhelblog.redhat.com/2016/10/17/secure-your-containers-with-this-one-weird-trick/](http://rhelblog.redhat.com/2016/10/17/secure-your-containers-with-this-one-weird-trick/)

**Open Container Initiative (OCI) runC specification**  
https://github.com/opencontainers/runc/tree/6c22e77604689db8725fa866f0f2ec0b3e8c3a07#r  
unning-containers

**As stated on the Docker Engine security page** "_One primary risk with running Docker containers is that the default set of capabilities and mounts given to a container may provide incomplete isolation, either independently, or when used in combination with kernel vulnerabilities._"  
[https://docs.docker.com/engine/security/security/](https://docs.docker.com/engine/security/security/)

**The core Unix security model** which is a form of Discretionary Access Control (DAC) was inherited by Linux  
[https://en.wikipedia.org/wiki/Discretionary_access_control](https://en.wikipedia.org/wiki/Discretionary_access_control)

**The Unix DAC was designed in 1969**  
[https://www.linux.com/learn/overview-linux-kernel-security-features](https://www.linux.com/learn/overview-linux-kernel-security-features)

**The first version of SecComp** was merged into the Linux kernel mainline in version 2.6.12 (March 8 2005)  
https://git.kernel.org/cgit/linux/kernel/git/tglx/history.git/commit/?id=d949d0ec9c601f2b148be  
d3cdb5f87c052968554

**In order to enable SecComp for a given process**, you would write a `1` to `/proc/<PID>/seccomp`  
[https://lwn.net/Articles/656307/](https://lwn.net/Articles/656307/)

**Then the addition of the `seccomp()`** System call in 2014 to the kernel version 3.17 along with popular applications such as Chrome/Chromium, OpenSSH  
[https://en.wikipedia.org/wiki/Seccomp](https://en.wikipedia.org/wiki/Seccomp)

**Docker has disabled about 44 system calls** in its default (seccomp) container profile  
[https://docs.docker.com/engine/security/seccomp/](https://docs.docker.com/engine/security/seccomp/)  
[https://github.com/docker/docker/blob/master/profiles/seccomp/default.json](https://github.com/docker/docker/blob/master/profiles/seccomp/default.json)

**The `keyctl` System call** was removed from the default Docker container profile after vulnerability CVE-2016-0728 was discovered, which allows privilege escalation or denial of service  
[https://cve.mitre.org/cgi-bin/cvename.cgi?name=cve-2016-0728](https://cve.mitre.org/cgi-bin/cvename.cgi?name=cve-2016-0728)  
[https://cve.mitre.org/cgi-bin/cvename.cgi?name=cve-2014-3153](https://cve.mitre.org/cgi-bin/cvename.cgi?name=cve-2014-3153)













**These processes have indirect access to most of the Linux Kernel**  
[https://theinvisiblethings.blogspot.co.nz/2012/09/how-is-qubes-os-different-from.html](https://theinvisiblethings.blogspot.co.nz/2012/09/how-is-qubes-os-different-from.html)

**Script Block Logging** records and logs the original obfuscated (XOR, Base64, encryption, etc) script, transcripts, and de-obfuscated code  
[https://www.fireeye.com/blog/threat-research/2016/02/greater_visibilityt.html](https://www.fireeye.com/blog/threat-research/2016/02/greater_visibilityt.html)

**In most cases you will want to shadow your passwords**  
[http://www.tldp.org/HOWTO/Shadow-Password-HOWTO-2.html#ss2.2](http://www.tldp.org/HOWTO/Shadow-Password-HOWTO-2.html#ss2.2)

**Crypt, crypt 3 or crypt(3)** is the Unix C library function designed for password authentication  
https://en.wikipedia.org/wiki/Crypt_(C)

**The default number of rounds have not changed** in at least 9 years  
[https://access.redhat.com/articles/1519843](https://access.redhat.com/articles/1519843)

**The default number of rounds**  
[https://en.wikipedia.org/wiki/Passwd](https://en.wikipedia.org/wiki/Passwd)

**The crypt 3 man page explains it all**  
[http://man7.org/linux/man-pages/man3/crypt.3.html#NOTES](http://man7.org/linux/man-pages/man3/crypt.3.html#NOTES)

**How the rest of the substrings in this field are interpreted** is determined by what is found in the `id` field  
[http://man7.org/linux/man-pages/man3/crypt.3.html#NOTES](http://man7.org/linux/man-pages/man3/crypt.3.html#NOTES)

**The salt can be augmented** by prepending the `rounds=<number of rounds you want, specified in /etc/pam.d/common-password>$` directive.  
[http://backreference.org/2014/04/19/many-ways-to-encrypt-passwords/](http://backreference.org/2014/04/19/many-ways-to-encrypt-passwords/)

**Consider changing to Bcrypt**  
[https://lists.debian.org/debian-user/2011/04/msg00550.html](https://lists.debian.org/debian-user/2011/04/msg00550.html)

**Use bcrypt** with slowpoke blowfish  
[https://serverfault.com/questions/10585/enable-blowfish-based-hash-support-for-crypt/11685](https://serverfault.com/questions/10585/enable-blowfish-based-hash-support-for-crypt/11685)

**There are a handful of files to check and/or modify** in terms of disabling root logins  
[https://www.debian.org/doc/manuals/securing-debian-howto/ch4.en.html#s-restrict-console-login](https://www.debian.org/doc/manuals/securing-debian-howto/ch4.en.html#s-restrict-console-login)

**An alternative to the previous method**  
[https://www.debian.org/doc/manuals/securing-debian-howto/ch4.en.html#s-pam-rootaccess](https://www.debian.org/doc/manuals/securing-debian-howto/ch4.en.html#s-pam-rootaccess)

**AES** block cipher with either key sizes of 128, 192 or 256 bits  
SSH, The Secure Shell: The Definitive Guide (book)

**CAST-128/256** described in Request for Comments (RFC) 2144  
(http://www.rfc-editor.org/rfc/rfc2144.txt), as a DES-like substitution-permutation crypto algorithm  
[http://www.garykessler.net/library/crypto.html](http://www.garykessler.net/library/crypto.html)  
Designed in the early 1990s by Carlisle Adams and Stafford Tavares, available on a worldwide royalty-free basis  
SSH, The Secure Shell: The Definitive Guide (book)

**Blowfish** Has received a fair amount of cryptanalytic scrutiny and has proved impervious to attack so far  
SSH, The Secure Shell: The Definitive Guide (book)

**Twofish** block cipher invented by Bruce Schneier, with the help from a few others, submitted in 1998 to the NIST as a candidate for the AES, to replace DES. It was one of the five finalists in the AES selection process out of 15 submissions. Twofish has no patents and is free for all uses. Key lengths can be 128, 192 or 256 bits. Twofish is also designed to be more flexible than Blowfish.  
SSH, The Secure Shell: The Definitive Guide (book)

**IDEA** (Bruce Schneier in 1996 pronounced it “the best and most secure block algorithm available to the public at this time”)  
[http://docstore.mik.ua/orelly/networking_2ndEd/ssh/ch03_09.htm](http://docstore.mik.ua/orelly/networking_2ndEd/ssh/ch03_09.htm)

**Diffie-Hellman key agreement** was the first public-key system published in open literature  
SSH, The Secure Shell: The Definitive Guide (book)

**The parties engage in an exchange of messages**, at the end of which they share a secret key. It is not feasible for an eavesdropper to determine the shared secret merely from observing the exchanged messages. SSH-2 uses the DH algorithm as it is required (and currently, its only defined) key-exchange method.  
SSH, The Secure Shell: The Definitive Guide (book)

**The MAC is the result of**  
[https://tools.ietf.org/html/rfc4253](https://tools.ietf.org/html/rfc4253)

**Using md5 is less secure**  
[https://en.wikipedia.org/wiki/MD5#Security](https://en.wikipedia.org/wiki/MD5#Security)

**Prior to OpenSSH 6.8** The fingerprint was provided as a hexadecimal md5 hash. Now it is displayed as base64 sha256  
[http://www.openssh.com/txt/release-6.8](http://www.openssh.com/txt/release-6.8) 

**Consider installing and configuring denyhosts**  
[https://www.digitalocean.com/community/articles/how-to-install-denyhosts-on-ubuntu-12-04](https://www.digitalocean.com/community/articles/how-to-install-denyhosts-on-ubuntu-12-04)

**Bitmask VPN client** which does a lot more than traditional VPN clients  
[https://bitmask.net/](https://bitmask.net/)  
[https://dl.bitmask.net/linux/](https://dl.bitmask.net/linux/)

**bitmask is sponsored by the LEAP Encryption Access Project**  
[https://leap.se/](https://leap.se/)

**Set a BIOS password**  
https://kb.vmware.com/selfservice/microsites/search.do?language=en_US&cmd=displayKC  
&externalId=1004129

**The Linux File System Hierarchy (FSH)**  
[http://www.tldp.org/LDP/Linux-Filesystem-Hierarchy/html/index.html](http://www.tldp.org/LDP/Linux-Filesystem-Hierarchy/html/index.html)

**Bind some target mounts onto existing directories**  
[http://www.cyberciti.biz/faq/linux-add-nodev-nosuid-noexec-options-to-temporary-storage-partitions/](http://www.cyberciti.biz/faq/linux-add-nodev-nosuid-noexec-options-to-temporary-storage-partitions/)

**Enabling a read-only `/` mount**  
[https://wiki.debian.org/ReadonlyRoot#Enable_readonly_root](https://wiki.debian.org/ReadonlyRoot#Enable_readonly_root)

**Also consider the pros and cons of increasing your shared memory**  
[http://www.cyberciti.biz/tips/what-is-devshm-and-its-practical-usage.html](http://www.cyberciti.biz/tips/what-is-devshm-and-its-practical-usage.html)

**The portmap service** converts RPC program numbers into TCP/IP (or UDP/IP) protocol port numbers  
[http://www.linux-nis.org/nis-howto/HOWTO/portmapper.html](http://www.linux-nis.org/nis-howto/HOWTO/portmapper.html)

**When a run level is entered**  
[https://debian-administration.org/article/212/An_introduction_to_run-levels](https://debian-administration.org/article/212/An_introduction_to_run-levels)

**Portmapper returns port numbers** of the server programs and rpcbind returns universal addresses  
https://www.ibm.com/support/knowledgecenter/SSLTBW_2.2.0/com.ibm.zos.v2r2.halx001/p  
ortmap.htm

**Less secure IPSec**  
[http://louwrentius.com/why-you-should-not-use-ipsec-for-vpn-connectivity.html](http://louwrentius.com/why-you-should-not-use-ipsec-for-vpn-connectivity.html)

**SCP**  
[https://blog.binarymist.net/2012/03/25/copying-with-scp/](https://blog.binarymist.net/2012/03/25/copying-with-scp/)

**Although Windows support is available**, and easy enough to set-up, as I have done many times  
[https://blog.binarymist.net/2011/12/27/openssh-from-linux-to-windows-7-via-tunneled-rdp/](https://blog.binarymist.net/2011/12/27/openssh-from-linux-to-windows-7-via-tunneled-rdp/)

**Another example is using Rsync over SSH**  
[https://blog.binarymist.net/2011/03/06/rsync-over-ssh-from-linux-workstation-to-freenas/](https://blog.binarymist.net/2011/03/06/rsync-over-ssh-from-linux-workstation-to-freenas/)

**NFSv4 pseudo-file system**. This pseudo-file system is identified as a single, real file system, identified at export with the `fsid=0` option.  
https://www.centos.org/docs/5/html/Deployment_Guide-en-US/s1-nfs-server-config-export  
s.html#id3077674

**NFSv4 has no interaction with these additional daemons**  
[https://www.centos.org/docs/5/html/Deployment_Guide-en-US/ch-nfs.html](https://www.centos.org/docs/5/html/Deployment_Guide-en-US/ch-nfs.html) 

**Simple Log Watcher**  
[https://sourceforge.net/projects/swatch/](https://sourceforge.net/projects/swatch/)

**Use logrotate** to make sure your logs will be around long enough to examine them  
[http://www.rackspace.com/knowledge_center/article/understanding-logrotate-utility](http://www.rackspace.com/knowledge_center/article/understanding-logrotate-utility)

**Rsyslog documentation**  
[http://www.rsyslog.com/doc/master/index.html](http://www.rsyslog.com/doc/master/index.html)

**Rainer Gerhards wrote rsyslog and his blog** provides many good insights into all things system logging  
[http://blog.gerhards.net/2007/08/why-does-world-need-another-syslogd.html](http://blog.gerhards.net/2007/08/why-does-world-need-another-syslogd.html) 

**Simple Event Correlator (SEC)**  
[http://www.gossamer-threads.com/lists/rsyslog/users/6044](http://www.gossamer-threads.com/lists/rsyslog/users/6044)

**Rainer Gerhards discusses why TCP is not as reliable as many think**  
[http://blog.gerhards.net/2008/04/on-unreliability-of-plain-tcp-syslog.html](http://blog.gerhards.net/2008/04/on-unreliability-of-plain-tcp-syslog.html)

**Rainer Gerhards said** “_In rsyslog, every action runs on its own queue and each queue can be set to buffer data if the action is not ready. Of course, you must be able to detect that the action is not ready, which means the remote server is off-line. This can be detected with plain TCP syslog and RELP_“  
http://ftp.ics.uci.edu/pub/centos0/ics-custom-build/BUILD/rsyslog-3.19.8/doc/rsyslog_reliab  
le_forwarding.html

**You can aggregate log files with rsyslog** or by using papertrails `remote_syslog` daemon  
[http://help.papertrailapp.com/kb/configuration/advanced-unix-logging-tips/#rsyslog_aggregate_log_files](http://help.papertrailapp.com/kb/configuration/advanced-unix-logging-tips/#rsyslog_aggregate_log_files) 

**Alerting is available**, including for inactivity of events  
[http://help.papertrailapp.com/kb/how-it-works/alerts/#inactivity](http://help.papertrailapp.com/kb/how-it-works/alerts/#inactivity)

**If you still want to go down the papertrail path**, to get started, work through  
[https://papertrailapp.com/systems/setup](https://papertrailapp.com/systems/setup)

**We need TLS**, check papertrails "Encrypting with TLS" docs  
[http://help.papertrailapp.com/kb/configuration/encrypting-remote-syslog-with-tls-ssl/#rsyslog](http://help.papertrailapp.com/kb/configuration/encrypting-remote-syslog-with-tls-ssl/#rsyslog)

**Simple Event Correlator (SEC)**  
[https://simple-evcorr.github.io/](https://simple-evcorr.github.io/)

**For all your graphical event correlation**, you could use LogAnalyzer  
[http://loganalyzer.adiscon.com/](http://loganalyzer.adiscon.com/) 

**Normalisation** also from Rainer could be useful  
[http://www.liblognorm.com/](http://www.liblognorm.com/)

**Helpful info on the differences between Sysvinit and systemd**  
https://doc.opensuse.org/documentation/html/openSUSE_122/opensuse-reference/cha.syste  
md.html

**Comparison with Upstart, systemd, Runit and even Supervisor**  
[http://www.tuicool.com/articles/qy2EJz3](http://www.tuicool.com/articles/qy2EJz3)

**list of commands that PM2 provides**, most of this functionality can be performed by native tools  
[https://github.com/Unitech/pm2#commands-overview](https://github.com/Unitech/pm2#commands-overview)

**PM2 also seems to provide logging**  
[https://github.com/Unitech/pm2#log-facilities](https://github.com/Unitech/pm2#log-facilities)

**To enable `httpok`** the following lines have to be placed in `supervisord.conf`  
[https://blog.risingstack.com/operating-node-in-production/#isitresponding](https://blog.risingstack.com/operating-node-in-production/#isitresponding) 

**Community provided docs are good**  
[https://serversforhackers.com/monitoring-processes-with-supervisord](https://serversforhackers.com/monitoring-processes-with-supervisord)

**Features that stand out**  
[https://mmonit.com/monit/#about](https://mmonit.com/monit/#about)

**Ability to monitor files, directories, disks, processes, programs**  
[http://slides.com/tildeslash/monit#/23](http://slides.com/tildeslash/monit#/23)  
[http://slides.com/tildeslash/monit#/26](http://slides.com/tildeslash/monit#/26)

**Can perform emergency logrotates**  
[http://slides.com/tildeslash/monit#/21](http://slides.com/tildeslash/monit#/21)

**File Checksum Testing**  
[https://mmonit.com/monit/documentation/monit.html#FILE-CHECKSUM-TESTING](https://mmonit.com/monit/documentation/monit.html#FILE-CHECKSUM-TESTING)  
[http://slides.com/tildeslash/monit#/22](http://slides.com/tildeslash/monit#/22)

**Monitoring space of file-systems**  
[http://slides.com/tildeslash/monit#/24](http://slides.com/tildeslash/monit#/24)

**Monit provides fine grained control** over who/what can access the web interface  
[https://mmonit.com/monit/documentation/monit.html#MONIT-HTTPD](https://mmonit.com/monit/documentation/monit.html#MONIT-HTTPD)

**Source and links to other documentation**  
[https://bitbucket.org/tildeslash/monit/src](https://bitbucket.org/tildeslash/monit/src)

**Adding Monit to systemd**  
[https://mmonit.com/wiki/Monit/Systemd](https://mmonit.com/wiki/Monit/Systemd)

**Release Notes**  
[https://mmonit.com/monit/changes/](https://mmonit.com/monit/changes/)

**There was an accepted answer on Stack Overflow** that discussed a pretty good mix and approach to using the right tools for each job  
[http://stackoverflow.com/questions/7259232/how-to-deploy-node-js-in-cloud-for-high-availability-using-multi-core-reverse-p](http://stackoverflow.com/questions/7259232/how-to-deploy-node-js-in-cloud-for-high-availability-using-multi-core-reverse-p)

**Example of the Monit install**  
[https://mmonit.com/wiki/Monit/Installation](https://mmonit.com/wiki/Monit/Installation)

**Passenger install**  
https://www.phusionpassenger.com/documentation/Users%20guide%20Standalone.html#inst  
allation

**Unix Philosophy**  
[https://en.wikipedia.org/wiki/Unix_philosophy](https://en.wikipedia.org/wiki/Unix_philosophy)

**The comment around "the Unix way" is interesting**  
[https://github.com/phusion/passenger/wiki/Phusion-Passenger:-Meteor-tutorial#what-passenger-doesnt-do](https://github.com/phusion/passenger/wiki/Phusion-Passenger:-Meteor-tutorial#what-passenger-doesnt-do)

**The Handle more traffic** marketing material looked similar to Monit resource testing but without the detail.  
[https://www.phusionpassenger.com/handle_more_traffic](https://www.phusionpassenger.com/handle_more_traffic)  
[https://mmonit.com/monit/documentation/monit.html#RESOURCE-TESTING](https://mmonit.com/monit/documentation/monit.html#RESOURCE-TESTING)

**Reduce maintenance**  
[https://www.phusionpassenger.com/reduce_maintenance](https://www.phusionpassenger.com/reduce_maintenance)

**Improve security**  
[https://www.phusionpassenger.com/improve_security](https://www.phusionpassenger.com/improve_security)

**If Monit is run as the super user**, you can optionally run the program as a different user and/or group  
[https://mmonit.com/monit/documentation/monit.html#PROGRAM-STATUS-TESTING](https://mmonit.com/monit/documentation/monit.html#PROGRAM-STATUS-TESTING)

**Phusion Passenger is a commercial product**  
[https://www.phusionpassenger.com/download](https://www.phusionpassenger.com/download)

**NodeJS tutorial**  
[https://github.com/phusion/passenger/wiki/Phusion-Passenger:-Node.js-tutorial](https://github.com/phusion/passenger/wiki/Phusion-Passenger:-Node.js-tutorial)

**Documentation and support portal**  
[https://www.phusionpassenger.com/documentation_and_support](https://www.phusionpassenger.com/documentation_and_support)

**Design and Architecture**  
[https://www.phusionpassenger.com/documentation/Design%20and%20Architecture.html](https://www.phusionpassenger.com/documentation/Design%20and%20Architecture.html)

**User Guide Index**  
[https://www.phusionpassenger.com/library/](https://www.phusionpassenger.com/library/)

**Nginx specific User Guide**  
[https://www.phusionpassenger.com/documentation/Users%20guide%20Nginx.html](https://www.phusionpassenger.com/documentation/Users%20guide%20Nginx.html)

**Standalone User Guide**  
[https://www.phusionpassenger.com/documentation/Users%20guide%20Standalone.html](https://www.phusionpassenger.com/documentation/Users%20guide%20Standalone.html)

**Source**  
[https://github.com/phusion/passenger](https://github.com/phusion/passenger)

**Passenger is advertised as offering easily viewable statistics**  
[https://www.phusionpassenger.com/identify_and_fix_problems](https://www.phusionpassenger.com/identify_and_fix_problems)

**But it still needs to be turned on and accessible by at least localhost**  
[https://mmonit.com/monit/documentation/monit.html#MONIT-HTTPD](https://mmonit.com/monit/documentation/monit.html#MONIT-HTTPD)

**If you want to receive alerts via email**, then you will need to configure that  
https://mmonit.com/monit/documentation/monit.html#Setting-a-mail-server-  
for-alert-delivery

**All the arguments you can throw at Monit** in the documentaion under
Arguments  
[https://mmonit.com/monit/documentation/monit.html#Arguments](https://mmonit.com/monit/documentation/monit.html#Arguments)

**Monit is very stable**, but if for some reason it dies, then it will not be automatically restarted  
[https://mmonit.com/monit/documentation/monit.html#INIT-SUPPORT](https://mmonit.com/monit/documentation/monit.html#INIT-SUPPORT)

**Systemd NetworkTarget documentation**  
[https://www.freedesktop.org/wiki/Software/systemd/NetworkTarget/](https://www.freedesktop.org/wiki/Software/systemd/NetworkTarget/)

**Useful resources that I have used**  
`kill`ing processes  
[http://www.cyberciti.biz/faq/kill-process-in-linux-or-terminate-a-process-in-unix-or-linux-systems/](http://www.cyberciti.biz/faq/kill-process-in-linux-or-terminate-a-process-in-unix-or-linux-systems/)  
Unix signals  
[https://en.wikipedia.org/wiki/Unix_signal](https://en.wikipedia.org/wiki/Unix_signal)  
Terse guide of systemd commands  
[https://wiki.archlinux.org/index.php/systemd](https://wiki.archlinux.org/index.php/systemd)

**Official Monit Documentation**  
[https://mmonit.com/monit/documentation/monit.html](https://mmonit.com/monit/documentation/monit.html)

**Monit Man page**  
[http://linux.die.net/man/1/monit](http://linux.die.net/man/1/monit)

**Dead Mans Snitch**  
[https://deadmanssnitch.com/](https://deadmanssnitch.com/)

**Simple Event Correlator**  
[https://simple-evcorr.github.io/](https://simple-evcorr.github.io/)

%% Statistics Graphing Countermeasures

**This is where collectd and graphite come to the party**  
[https://collectd.org/](https://collectd.org/)  
[https://graphiteapp.org/](https://graphiteapp.org/)

**AWS CloudWatch via a plugin**  
[https://aws.amazon.com/blogs/aws/new-cloudwatch-plugin-for-collectd/](https://aws.amazon.com/blogs/aws/new-cloudwatch-plugin-for-collectd/)

**Graphana**  
[https://grafana.com/](https://grafana.com/)

**Can take inputs from** a collection of data sources  
[https://grafana.com/plugins?type=datasource](https://grafana.com/plugins?type=datasource)

**AWS CloudWatch**  
[http://docs.grafana.org/features/datasources/cloudwatch/](http://docs.grafana.org/features/datasources/cloudwatch/)

**Better solution**  
[http://blog.takipi.com/graphite-vs-grafana-build-the-best-monitoring-architecture-for-your-application/](http://blog.takipi.com/graphite-vs-grafana-build-the-best-monitoring-architecture-for-your-application/)

**Collectd is capable of cryptographically signing or encrypting** the network traffic it transmits  
[https://collectd.org/wiki/index.php/Networking_introduction#Cryptographic_setup](https://collectd.org/wiki/index.php/Networking_introduction#Cryptographic_setup)

**Graphite has excellent official and community provided documentation**  
[https://graphite.readthedocs.io/en/latest/](https://graphite.readthedocs.io/en/latest/)  
[https://www.digitalocean.com/community/tutorials/how-to-install-and-use-graphite-on-an-ubuntu-14-04-server](https://www.digitalocean.com/community/tutorials/how-to-install-and-use-graphite-on-an-ubuntu-14-04-server)

**Tools that can be integrated with graphite**  
[http://graphite.readthedocs.org/en/latest/tools.html](http://graphite.readthedocs.org/en/latest/tools.html)

**Graphite can take some work to deploy**  
[https://kevinmccarthy.org/2013/07/18/10-things-i-learned-deploying-graphite/](https://kevinmccarthy.org/2013/07/18/10-things-i-learned-deploying-graphite/)

**ansible-graphite playbook**  
[https://github.com/dmichel1/ansible-graphite](https://github.com/dmichel1/ansible-graphite)

**Graphite on a single machine**  
[https://www.digitalocean.com/community/tutorials/how-to-configure-collectd-to-gather-system-metrics-for-graphite-on-ubuntu-14-04](https://www.digitalocean.com/community/tutorials/how-to-configure-collectd-to-gather-system-metrics-for-graphite-on-ubuntu-14-04)

**How this looks**  
[https://pradyumnajoshi.blogspot.co.nz/2015/11/setting-up-collectd-based-monitoring.html](https://pradyumnajoshi.blogspot.co.nz/2015/11/setting-up-collectd-based-monitoring.html)

**Install, configure, and run graphite**  
[https://www.digitalocean.com/community/tutorials/how-to-install-and-use-graphite-on-an-ubuntu-14-04-server](https://www.digitalocean.com/community/tutorials/how-to-install-and-use-graphite-on-an-ubuntu-14-04-server)  
[https://graphite.readthedocs.io/en/latest/install.html](https://graphite.readthedocs.io/en/latest/install.html)

**`collectd`**  
[https://packages.debian.org/stretch/collectd](https://packages.debian.org/stretch/collectd)

**`collectd-core`**  
[https://packages.debian.org/stretch/collectd-core](https://packages.debian.org/stretch/collectd-core)

**`collectd-utils`**  
[https://packages.debian.org/stretch/collectd-utils](https://packages.debian.org/stretch/collectd-utils)

**`write_graphite`**  
[https://collectd.org/wiki/index.php/Plugin:Write_Graphite](https://collectd.org/wiki/index.php/Plugin:Write_Graphite)

**`CPU`**  
[https://collectd.org/wiki/index.php/Plugin:CPU](https://collectd.org/wiki/index.php/Plugin:CPU)

**`Load`**  
[https://collectd.org/wiki/index.php/Plugin:Load](https://collectd.org/wiki/index.php/Plugin:Load)

**`Memory`**  
[https://collectd.org/wiki/index.php/Plugin:Memory](https://collectd.org/wiki/index.php/Plugin:Memory)

**`Disk`**  
[https://collectd.org/wiki/index.php/Plugin:Disk](https://collectd.org/wiki/index.php/Plugin:Disk)

**`Processes`**  
[https://collectd.org/wiki/index.php/Plugin:Processes](https://collectd.org/wiki/index.php/Plugin:Processes)

**Read plugins from the list**  
[https://collectd.org/wiki/index.php/Table_of_Plugins](https://collectd.org/wiki/index.php/Table_of_Plugins)

**Sends the statistics** (name actual-value timestamp-in-epoch) to graphites listening service called carbon  
[https://collectd.org/wiki/index.php/Plugin:Write_Graphite#Example_data](https://collectd.org/wiki/index.php/Plugin:Write_Graphite#Example_data)

**Usually to port 2003**  
[https://graphite.readthedocs.io/en/latest/carbon-daemons.html#carbon-cache-py](https://graphite.readthedocs.io/en/latest/carbon-daemons.html#carbon-cache-py)

**Carbon only accepts a single value per interval**, which is 10 seconds by default  
[https://graphite.readthedocs.io/en/latest/config-carbon.html#storage-schemas-conf](https://graphite.readthedocs.io/en/latest/config-carbon.html#storage-schemas-conf)

%% End Statistics Graphing Countermeasures

**DigitalOcean had a tutorial on setting Tripwire up**  
[https://www.digitalocean.com/community/tutorials/how-to-use-tripwire-to-detect-server-intrusions-on-an-ubuntu-vps](https://www.digitalocean.com/community/tutorials/how-to-use-tripwire-to-detect-server-intrusions-on-an-ubuntu-vps)

**Similar offering to Tripwire for POSIX compliant systems**  
[http://rkhunter.sourceforge.net/](http://rkhunter.sourceforge.net/)

**The OSSEC team**  
[https://ossec.github.io/about.html#ossec-team](https://ossec.github.io/about.html#ossec-team)

**Stealth user base**  
[https://qa.debian.org/popcon.php?package=stealth](https://qa.debian.org/popcon.php?package=stealth)

**The main documentation is on github**  
[https://ossec.github.io/docs/](https://ossec.github.io/docs/)

**Similar docs on readthedocs.io**  
[https://ossec-docs.readthedocs.io/en/latest/](https://ossec-docs.readthedocs.io/en/latest/)

**Mailing list on google groups**  
[https://groups.google.com/forum/#!forum/ossec-list](https://groups.google.com/forum/#!forum/ossec-list)

**Commercial Support**  
https://ossec.github.io/blog/posts/2014-05-12-OSSEC-Commercial-Support-Contracts.m  
arkdown.html

**FAQ**  
[https://ossec-docs.readthedocs.io/en/latest/faq/index.html](https://ossec-docs.readthedocs.io/en/latest/faq/index.html)

**Package meta-data**  
[http://ossec.alienvault.com/repos/apt/debian/dists/jessie/main/binary-amd64/Packages](http://ossec.alienvault.com/repos/apt/debian/dists/jessie/main/binary-amd64/Packages)

**Agent-less route**  
[https://ossec-docs.readthedocs.io/en/latest/manual/agent/agentless-monitoring.html](https://ossec-docs.readthedocs.io/en/latest/manual/agent/agentless-monitoring.html)

**Agent-less scripts**  
[https://ossec-docs.readthedocs.io/en/latest/manual/agent/agentless-scripts.html](https://ossec-docs.readthedocs.io/en/latest/manual/agent/agentless-scripts.html)

**Features in a nut-shell**  
[https://ossec.github.io/docs/manual/non-technical-overview.html?page_id=165](https://ossec.github.io/docs/manual/non-technical-overview.html?page_id=165)

**Source on github**  
[https://github.com/fbb-git/stealth](https://github.com/fbb-git/stealth)

%% Countermeasures Docker

**Cisecurity has an excellent resource** for hardening docker images which the Docker Security team helped with  
[https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf](https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf)

**"_Docker Security Scanning_** _is available as an add-on to Docker hosted private repositories on both Docker Cloud and Docker Hub._", you also have to opt in and pay for it  
https://docs.docker.com/docker-cloud/builds/image-scan  
/#opt-in-to-docker-security-scanning

**Docker Security Scanning** is also now available on the new Enterprise Edition  
[https://blog.docker.com/2017/03/docker-enterprise-edition/](https://blog.docker.com/2017/03/docker-enterprise-edition/)

**Whether un-official or official**  
[https://github.com/docker-library/official-images](https://github.com/docker-library/official-images)

**Docker Content Trust**  
[https://blog.docker.com/2015/08/content-trust-docker-1-8/](https://blog.docker.com/2015/08/content-trust-docker-1-8/)

**Notary**  
[https://github.com/docker/notary](https://github.com/docker/notary)

**`DOCKER_CONTENT_TRUST`** environment variable must be set to `1`  
https://docs.docker.com/engine/security/trust/content_trust/#enable-and-disable-content-tr  
ust-per-shell-or-per-invocation

**`DOCKER_CONTENT_TRUST_SERVER`** must be set to the URL of the Notary server you setup  
[https://docs.docker.com/engine/reference/commandline/cli/#environment-variables](https://docs.docker.com/engine/reference/commandline/cli/#environment-variables)

**They need to generate a key pair**  
[https://docs.docker.com/engine/security/trust/trust_delegation/](https://docs.docker.com/engine/security/trust/trust_delegation/)

**Notary is based on a Go implementation** of The Update Framework (TUF)  
[https://theupdateframework.github.io/](https://theupdateframework.github.io/)

**An example of the NodeGoat image**  
[https://github.com/owasp/nodegoat](https://github.com/owasp/nodegoat)

**The space for tooling** to help find vulnerabilities in code, packages, etc within your Docker images has been noted, and tools provided  
https://community.alfresco.com/community/ecm/blog/2015/12/03/docker-security-tools-aud  
it-and-vulnerability-assessment/

**These tools should form** a part of your secure and trusted build pipeline / software supply-chain  
[https://blog.acolyer.org/2017/04/03/a-study-of-security-vulnerabilities-on-docker-hub/](https://blog.acolyer.org/2017/04/03/a-study-of-security-vulnerabilities-on-docker-hub/)

**Dockerfile linter** that helps you build best practice Docker images  
[https://docs.docker.com/engine/userguide/eng-image/dockerfile_best-practices/](https://docs.docker.com/engine/userguide/eng-image/dockerfile_best-practices/)

**Free and open source auditing tool** for Linux/Unix based systems  
[https://github.com/CISOfy/lynis](https://github.com/CISOfy/lynis)

**Docker plugin available** which allows one to audit Docker  
[https://cisofy.com/lynis/plugins/docker-containers/](https://cisofy.com/lynis/plugins/docker-containers/) 

**Hashes of the CVE data sources**  
[https://github.com/coreos/clair/tree/f66103c7732c9a62ba1d3afc26437ae54953dc01#default-data-sources](https://github.com/coreos/clair/tree/f66103c7732c9a62ba1d3afc26437ae54953dc01#default-data-sources)

**Collector has a pluggable, extensible architecture**  
[https://github.com/banyanops/collector/blob/master/docs/CollectorDetails.md](https://github.com/banyanops/collector/blob/master/docs/CollectorDetails.md)

**Banyanops was the organisation** that blogged about the high number of vulnerable packages on Docker Hub  
[https://www.banyanops.com/blog/analyzing-docker-hub/](https://www.banyanops.com/blog/analyzing-docker-hub/)

**Seen by running `docker network ls`**  
[https://docs.docker.com/engine/reference/commandline/network_ls/](https://docs.docker.com/engine/reference/commandline/network_ls/)

**Docker network**  
[https://docs.docker.com/engine/userguide/networking/](https://docs.docker.com/engine/userguide/networking/)

**Network drivers** created by docker  
[https://docs.docker.com/engine/reference/run/#network-settings](https://docs.docker.com/engine/reference/run/#network-settings)

**`bridge`**  
[https://docs.docker.com/engine/reference/run/#network-bridge](https://docs.docker.com/engine/reference/run/#network-bridge)

**`none`**  
[https://docs.docker.com/engine/reference/run/#network-none](https://docs.docker.com/engine/reference/run/#network-none)

**`host`**  
[https://docs.docker.com/engine/reference/run/#network-host](https://docs.docker.com/engine/reference/run/#network-host)

**`container`**  
[https://docs.docker.com/engine/reference/run/#network-container](https://docs.docker.com/engine/reference/run/#network-container)

**`nsenter`** command  
[http://man7.org/linux/man-pages/man1/nsenter.1.html](http://man7.org/linux/man-pages/man1/nsenter.1.html)

**Understand container communication**  
[https://docs.docker.com/engine/userguide/networking/default_network/container-communication/](https://docs.docker.com/engine/userguide/networking/default_network/container-communication/)

**The username must exist** in the `/etc/passwd` file, the `sbin/nologin` users are valid also  
[https://success.docker.com/KBase/Introduction_to_User_Namespaces_in_Docker_Engine](https://success.docker.com/KBase/Introduction_to_User_Namespaces_in_Docker_Engine)

**"_The UID/GID we want to remap to_** _does not need to match the UID/GID of the username in `/etc/passwd`_"  
[https://success.docker.com/KBase/Introduction_to_User_Namespaces_in_Docker_Engine](https://success.docker.com/KBase/Introduction_to_User_Namespaces_in_Docker_Engine)

**Files will be populated** with a contiguous 65536 length range of subordinate user and group Ids respectively  
[https://docs.docker.com/engine/reference/commandline/dockerd/#starting-the-daemon-with-user-namespaces-enabled](https://docs.docker.com/engine/reference/commandline/dockerd/#starting-the-daemon-with-user-namespaces-enabled)

**Check out the Docker engine reference**  
https://docs.docker.com/engine/reference/commandline/dockerd/#detailed-information-on-su  
buidsubgid-ranges

**Check the Runtime constraints on resources**  
[https://docs.docker.com/engine/reference/run/#runtime-constraints-on-resources](https://docs.docker.com/engine/reference/run/#runtime-constraints-on-resources)

**Limit a container's resources** Admin Guide for Docker Engine  
[https://docs.docker.com/engine/admin/resource_constraints/](https://docs.docker.com/engine/admin/resource_constraints/)

**By default Docker** uses the cgroupfs cgroup driver to interface with the Linux kernel's cgroups  
[https://docs.docker.com/engine/reference/commandline/dockerd/#options-for-the-runtime](https://docs.docker.com/engine/reference/commandline/dockerd/#options-for-the-runtime)

**`docker stats`** command, which will give you a line with your containers CPU usage, Memory usage and Limit, Net I/O, Block I/O, Number of PIDs  
[https://docs.docker.com/engine/reference/commandline/stats/](https://docs.docker.com/engine/reference/commandline/stats/)

**Docker engine runtime metrics**  
[https://docs.docker.com/engine/admin/runmetrics/](https://docs.docker.com/engine/admin/runmetrics/)

**With a little help from the CIS Docker Benchmark** we can use the `PID`s cgroup limit  
[https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf](https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf)

**There are several ways you can minimise your set of capabilities**  
[http://rhelblog.redhat.com/2016/10/17/secure-your-containers-with-this-one-weird-trick/](http://rhelblog.redhat.com/2016/10/17/secure-your-containers-with-this-one-weird-trick/)

**First Linux kernel summit**  
[https://lwn.net/2001/features/KernelSummit/](https://lwn.net/2001/features/KernelSummit/)

**It was decided to** have the developers interested in security create a "_generic interface which could be used by any security policy. The result was the Linux Security Modules (LSM)_" API/framework, which provides many hooks at security critical points within the kernel  
[http://www.hep.by/gnu/kernel/lsm/](http://www.hep.by/gnu/kernel/lsm/)  
[https://lwn.net/Articles/180194/](https://lwn.net/Articles/180194/)  
[https://www.linux.com/learn/overview-linux-kernel-security-features](https://www.linux.com/learn/overview-linux-kernel-security-features) 

**Selectable at build-time** via `CONFIG_DEFAULT_SECURITY`  
[https://www.kernel.org/doc/Documentation/security/LSM.txt](https://www.kernel.org/doc/Documentation/security/LSM.txt)

**Overridden at boot-time** via the `security=...` kernel command line argument  
[https://debian-handbook.info/browse/stable/sect.selinux.html#sect.selinux-setup](https://debian-handbook.info/browse/stable/sect.selinux.html#sect.selinux-setup)

**"_Most LSMs choose to extend the capabilities_** _system, building their checks on top of the defined capability hooks._"  
[https://www.kernel.org/doc/Documentation/security/LSM.txt](https://www.kernel.org/doc/Documentation/security/LSM.txt) 

**AppArmor policy's are created using the profile language**  
[http://wiki.apparmor.net/index.php/ProfileLanguage](http://wiki.apparmor.net/index.php/ProfileLanguage)

**Apparmor page** of Dockers Secure Engine  
[https://docs.docker.com/engine/security/apparmor/](https://docs.docker.com/engine/security/apparmor/)

**SELinux needs to be installed and configured on Debian**  
[https://wiki.debian.org/SELinux/Setup](https://wiki.debian.org/SELinux/Setup)

**SELinux support for the Docker daemon is disabled by default** and needs to be enabled  
[https://github.com/GDSSecurity/Docker-Secure-Deployment-Guidelines](https://github.com/GDSSecurity/Docker-Secure-Deployment-Guidelines)  
[https://docs.docker.com/engine/reference/commandline/dockerd/](https://docs.docker.com/engine/reference/commandline/dockerd/)

**Docker daemon options** can also be set within the daemon configuration file  
[https://docs.docker.com/engine/reference/commandline/dockerd/#daemon-configuration-file](https://docs.docker.com/engine/reference/commandline/dockerd/#daemon-configuration-file)

**Label confinement for the container** can be configured using `--security-opt`  
[https://github.com/GDSSecurity/Docker-Secure-Deployment-Guidelines](https://github.com/GDSSecurity/Docker-Secure-Deployment-Guidelines)

**SELinux Labels for Docker** consist of four parts  
[https://www.projectatomic.io/docs/docker-and-selinux/](https://www.projectatomic.io/docs/docker-and-selinux/)

**SELinux can be enabled in the container** using `setenforce 1`  
[http://www.unix.com/man-page/debian/8/setenforce/](http://www.unix.com/man-page/debian/8/setenforce/)

**SELinux can operate in one of three modes**  
[https://www.centos.org/docs/5/html/5.2/Deployment_Guide/sec-sel-enable-disable-enforcement.html](https://www.centos.org/docs/5/html/5.2/Deployment_Guide/sec-sel-enable-disable-enforcement.html)

**To persist on boot: In Debian**  
[https://debian-handbook.info/browse/stable/sect.selinux.html#sect.selinux-setup](https://debian-handbook.info/browse/stable/sect.selinux.html#sect.selinux-setup)

**Kernel is configured with** `CONFIG_SECCOMP`  
[https://docs.docker.com/engine/security/seccomp/](https://docs.docker.com/engine/security/seccomp/)

**Default seccomp profile for containers** (`default.json`)  
[https://github.com/docker/docker/blob/master/profiles/seccomp/default.json](https://github.com/docker/docker/blob/master/profiles/seccomp/default.json)

**Apply the `--tmpfs` flag**  
[https://docs.docker.com/engine/reference/commandline/run/#mount-tmpfs---tmpfs](https://docs.docker.com/engine/reference/commandline/run/#mount-tmpfs---tmpfs)

**libcontainer**  
[https://github.com/opencontainers/runc/tree/master/libcontainer](https://github.com/opencontainers/runc/tree/master/libcontainer)

**containerd** (daemon for Linux or Windows) is based on the Docker engine's core container runtime  
[https://containerd.io/](https://containerd.io/) 

**runC** is the container runtime that runs containers  
[https://runc.io/](https://runc.io/)

**runC** was created by the OCI  
[https://github.com/opencontainers/runc](https://github.com/opencontainers/runc)

**runC can be installed separately**  
https://docker-saigon.github.io/post/Docker-Internals/#runc:cb6baf67dddd3a71c07abfd705d  
c7d4b

**Host independent** `config.json` and host specific `runtime.json` files  
[https://github.com/containerd/containerd/blob/0.0.5/docs/bundle.md#configs](https://github.com/containerd/containerd/blob/0.0.5/docs/bundle.md#configs)

**You must also construct or export a root filesystem**  
[https://github.com/opencontainers/runc#creating-an-oci-bundle](https://github.com/opencontainers/runc#creating-an-oci-bundle)

**The most common attack vectors** are still attacks focussing on our weakest areas, such as people, password stealing, spear phishing, uploading and execution of web shells, compromising social media accounts, weaponised documents, and ultimately application security, as I have mentioned many times before  
[https://blog.binarymist.net/presentations-publications/#nzjs-2017-the-art-of-exploitation](https://blog.binarymist.net/presentations-publications/#nzjs-2017-the-art-of-exploitation)

**It is pretty clear** that there are far more vulnerabilities affecting VMs than there are affecting containers  
[https://xenbits.xen.org/xsa/](https://xenbits.xen.org/xsa/)  
[https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=docker](https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=docker)

**Bugs listed in the Xen CVEs**  
[https://xenbits.xen.org/xsa/](https://xenbits.xen.org/xsa/)

**Show #7 Understanding Container Security**  
http://www.heavybit.com/library/podcasts/the-secure-developer/ep-7-understanding-contai  
ner-security/

%% End Countermeasures Docker

**There are plenty of tools** available to help  
[http://www.debianhelp.co.uk/backuptools.htm](http://www.debianhelp.co.uk/backuptools.htm) 

**Snort can help with the Prevention** also  
https://www.ibm.com/developerworks/community/blogs/58e72888-6340-46ac-b488-d31aa40  
58e9c/entry/august_8_2012_12_01_pm6?lang=en

**Work through using the likes of**  
harden  
https://www.debian.org/doc/manuals/securing-debian-howto/ch-automatic-harden.en.htm  
l#s6.1  
[https://packages.debian.org/wheezy/harden](https://packages.debian.org/wheezy/harden)  
Lynis for your server  
[https://cisofy.com/lynis/](https://cisofy.com/lynis/)  
harden-surveillance for monitoring your network  
[https://packages.debian.org/wheezy/harden-surveillance](https://packages.debian.org/wheezy/harden-surveillance)

**Consider combining “Port Scan Attack Detector”**  
[https://packages.debian.org/stretch/psad](https://packages.debian.org/stretch/psad)

**With fwsnort**  
[https://packages.debian.org/stretch/fwsnort](https://packages.debian.org/stretch/fwsnort)

**Read up on the “Attacks and Threats”**  
[http://www.tldp.org/HOWTO/Security-Quickstart-HOWTO/appendix.html#THREATS](http://www.tldp.org/HOWTO/Security-Quickstart-HOWTO/appendix.html#THREATS)

%% Costs and Trade-offs

**These are some things you should consider**  
[https://www.owasp.org/images/7/71/2017-04-20-TrustMeImACloud.pdf](https://www.owasp.org/images/7/71/2017-04-20-TrustMeImACloud.pdf)

**Safeguard your SSH access, like using ssh-cron for example**  
[https://fbb-git.github.io/ssh-cron/ssh-cron.1.html](https://fbb-git.github.io/ssh-cron/ssh-cron.1.html)


## [Network](#network)

**Check out the great Thinkst tools**, also discussed near the end of the Network Security show I hosted for Software Enineering Radio with Haroon Meer:

* [https://canarytokens.org/](https://canarytokens.org/)
* [https://canary.tools/](https://canary.tools/)

%% Fortress Mentality Identify Risks

**IBM X-Force 2016 Cyber Security Intelligence Index** provides the following information  
[http://ibm.biz/2016CyberIndex](http://ibm.biz/2016CyberIndex)

**The 2017 IBM X-Force Threat Intelligence Index** provides the following information  
[https://public.dhe.ibm.com/common/ssi/ecm/wg/en/wgl03140usen/WGL03140USEN.PDF](https://public.dhe.ibm.com/common/ssi/ecm/wg/en/wgl03140usen/WGL03140USEN.PDF)

%% End Fortress Mentality Identify Risks

%% Lack of Segmentation Identify Risks

**Being commandeered by attackers to do their bidding**  
[http://www.mirror.co.uk/news/technology-science/technology/hackers-use-fridge-send-spam-3046733#](http://www.mirror.co.uk/news/technology-science/technology/hackers-use-fridge-send-spam-3046733#)

%% End Lack of Segmentation Identify Risks

%% Spoofing EMail Address Identify Risks

**There are also on-line services** that allow the sending of email and specifying any from address  
[http://www.anonymailer.net/](http://www.anonymailer.net/)

%% End Spoofing EMail Address Identify Risks

%% Data Exfiltration, Infiltration Identify Risks

**DropboxC2C** is one project  
[https://github.com/0x09AL/DropboxC2C](https://github.com/0x09AL/DropboxC2C)

**Advanced Penetration Testing** by Wil Allsopp

**Stub resolver**  
[http://www.zytrax.com/books/dns/apa/resolver.html](http://www.zytrax.com/books/dns/apa/resolver.html)

**The query that the stub resolver sends to the recursive DNS resolver** has a special flag called "Recursion Desired" (`RD`) in the DNS request header (see RFC 1035 for details)  
[https://www.ietf.org/rfc/rfc1035.txt](https://www.ietf.org/rfc/rfc1035.txt)

**There are 13 root server clusters** from a-m, as you can see in the `dig +trace` output, with servers from over 380 locations  
[http://www.root-servers.org/](http://www.root-servers.org/)

**The `TXT` record is very flexible**, useful for transferring arbitrary data, including code, commands (see section 3.3.14. `TXT RDATA` format of the specification)  
[https://www.ietf.org/rfc/rfc1035.txt](https://www.ietf.org/rfc/rfc1035.txt)

**The evolution of data exfiltration and infiltration** started with OzymanDNS from Dan Kaminsky in 2004  
[https://room362.com/post/2009/2009310ozymandns-tunneling-ssh-over-dns-html/](https://room362.com/post/2009/2009310ozymandns-tunneling-ssh-over-dns-html/) 

**Tadeusz Pietraszek created DNScat**  
[http://tadek.pietraszek.org/projects/DNScat/](http://tadek.pietraszek.org/projects/DNScat/)

**Ron Bowes created the successor called dnscat2**  
[https://github.com/iagox86/dnscat2](https://github.com/iagox86/dnscat2)

**Additional details are provided on Ron's blog**  
[https://blog.skullsecurity.org/2015/dnscat2-0-05-with-tunnels](https://blog.skullsecurity.org/2015/dnscat2-0-05-with-tunnels)

**Izhan created a howto document** covering the authoritative name server set-up  
[https://github.com/izhan](https://github.com/izhan)  
[https://github.com/iagox86/dnscat2/blob/master/doc/authoritative_dns_setup.md](https://github.com/iagox86/dnscat2/blob/master/doc/authoritative_dns_setup.md)

%% End Data Exfiltration, Infiltration Identify Risks

%% TLS Downgrade Identify Risks

**An excellent resource** for some of the prominent websites in New Zealand  
[https://httpswatch.nz](https://httpswatch.nz)

%% End TLS Downgrade Identify Risks

**Create a jail in FreeNAS**, install OpenVPN in the jail  
https://forums.freenas.org/index.php?threads/how-to-install-openvpn-inside-a-jail-in-freenas-9-2-1-6-with-access-to-remote-hosts-via-nat.22873/

**SyslogAppliance** which is a turn-key VM for any VMware environment  
[http://www.syslogappliance.de/en/](http://www.syslogappliance.de/en/) 

**SyslogAppliance is a purpose built slim Debian instance** with no sshd installed  
[http://www.syslogappliance.de/download/syslogappliance-0.0.6/README.txt](http://www.syslogappliance.de/download/syslogappliance-0.0.6/README.txt)

**SyslogAppliance also supports TLS**  
http://www.syslog.org/forum/profile/?area=showposts;u=29

**LogAnalyzer**  
[http://loganalyzer.adiscon.com/](http://loganalyzer.adiscon.com/)

**Providing log analysis and alerting**  
[http://www.syslogappliance.de/en/features.php](http://www.syslogappliance.de/en/features.php)




**There are many NTP pools** you can choose from  
[https://www.google.ie/search?q=ntp+server+pools](https://www.google.ie/search?q=ntp+server+pools)

**Ntpdate has been deprecated for several years now**  
[http://support.ntp.org/bin/view/Dev/DeprecatingNtpdate](http://support.ntp.org/bin/view/Dev/DeprecatingNtpdate)

**The standard NTP query** program  
[http://doc.ntp.org/4.1.0/ntpq.htm](http://doc.ntp.org/4.1.0/ntpq.htm)

**The `*` in front of the remote** means the server is getting its time successfully from the upstream NTP  
[http://www.pool.ntp.org/en/use.html](http://www.pool.ntp.org/en/use.html)

**See the NTP parameters**  
[http://www.iana.org/assignments/ntp-parameters/ntp-parameters.xhtml](http://www.iana.org/assignments/ntp-parameters/ntp-parameters.xhtml)

%% Lack of Network Intrusion Detection Systems (NIDS) Countermeasures

**Survey of Current Network Intrusion Detection Techniques**  
[http://www1.cse.wustl.edu/~jain/cse571-07/ftp/ids/index.html](http://www1.cse.wustl.edu/~jain/cse571-07/ftp/ids/index.html)

**NIDS can operate with Anomalies**  
[http://www1.cse.wustl.edu/~jain/cse571-07/ftp/ids/index.html#sec4](http://www1.cse.wustl.edu/~jain/cse571-07/ftp/ids/index.html#sec4)

**Snort can be seen used in many different scenarios**. Written in C, and version 3 which is supposed to be multi-threaded is still in its third alpha  
[http://blog.snort.org/2014/12/introducing-snort-30.html](http://blog.snort.org/2014/12/introducing-snort-30.html)

**1 Gbps speeds are well exceeded**  
[https://forum.pfsense.org/index.php?topic=83548.0](https://forum.pfsense.org/index.php?topic=83548.0)

**SANS produced an Open Source IDS Performance Shootout document**  
[https://www.sans.org/reading-room/whitepapers/intrusion/open-source-ids-high-performance-shootout-35772](https://www.sans.org/reading-room/whitepapers/intrusion/open-source-ids-high-performance-shootout-35772)

%% End Lack of Network Intrusion Detection Systems (NIDS) Countermeasures

%% Spoofing Referrer Countermesaures

**Check the OWASP Failure to Restrict URL Access** for countermeasures  
[https://www.owasp.org/index.php/Top_10_2007-Failure_to_Restrict_URL_Access](https://www.owasp.org/index.php/Top_10_2007-Failure_to_Restrict_URL_Access)

**Guide to authorisation**  
[https://www.owasp.org/index.php/Guide_to_Authorization](https://www.owasp.org/index.php/Guide_to_Authorization)

%% End Spoofing Referrer Countermesaures

%% Spoofing EMail Address Countermeasures

**If the victims SMTP server does not perform reverse lookups on the hostname**, an email `from` and `reply-to` fields can be successfully spoofed.  
[http://www.social-engineer.org/framework/se-tools/computer-based/social-engineer-toolkit-set/](http://www.social-engineer.org/framework/se-tools/computer-based/social-engineer-toolkit-set/)

**Sender Policy Framework** (SPF)  
[https://tools.ietf.org/html/rfc7208](https://tools.ietf.org/html/rfc7208)

**Domain Keys Identified Mail** (DKIM)  
[https://tools.ietf.org/html/rfc6376](https://tools.ietf.org/html/rfc6376)

**DKIM signature**, which is comprised of a set of `tag=value` pairs such as `d=<sending domain>`, `p=<public key>`, and others  
[https://tools.ietf.org/html/rfc6376#section-3.2](https://tools.ietf.org/html/rfc6376#section-3.2)

%% End Spoofing EMail Address Countermeasures

%% Data Exfiltration, Infiltration Countermeasures

**Block the cell phone signals**, but in many countries this is illegal  
[https://www.fcc.gov/general/jamming-cell-phones-and-gps-equipment-against-law](https://www.fcc.gov/general/jamming-cell-phones-and-gps-equipment-against-law)

%% End Data Exfiltration, Infiltration Countermeasures

**Doppelganger Domains** An old trick brought back to light by Peter Kim's research  
[http://www.wired.com/2011/09/doppelganger-domains/](http://www.wired.com/2011/09/doppelganger-domains/)  
involving fortune 500 companies where they intercepted 20 GB of email from miss typed addresses.  
Peter Kim discusses in "The Hacker PlayBook" about how he set-up SMTP and SSH doppelganger domains. This is an excellent book that I recommend reading.

**Content Security Policy (CSP)** Slide Deck from Francois Marier  
[http://www.slideshare.net/fmarier/owaspnzday2012](http://www.slideshare.net/fmarier/owaspnzday2012)

**Easy Reading OWASP CSP**  
[https://www.owasp.org/index.php/Content_Security_Policy](https://www.owasp.org/index.php/Content_Security_Policy)

**OWASP CSP Cheat Sheet** which also lists which directives are new in version 2  
[https://www.owasp.org/index.php/Content_Security_Policy_Cheat_Sheet](https://www.owasp.org/index.php/Content_Security_Policy_Cheat_Sheet)

**Evaluate the strength of a CSP policy** by using the google CSP evaluator  
[https://csp-evaluator.withgoogle.com/](https://csp-evaluator.withgoogle.com/)

**MDN easily digestible help** on using CSP  
[https://developer.mozilla.org/en-US/docs/Web/Security/CSP](https://developer.mozilla.org/en-US/docs/Web/Security/CSP)

**Easy, but more in-depth:**

* W3C specification 2. It is the specification after all. Not sure about browser support here yet [http://www.w3.org/TR/CSP2](http://www.w3.org/TR/CSP2).
* W3C specification 1.1 [http://www.w3.org/TR/2014/WD-CSP11-20140211/](http://www.w3.org/TR/2014/WD-CSP11-20140211/) which most browsers currently support [http://caniuse.com/contentsecuritypolicy](http://caniuse.com/contentsecuritypolicy). IE 11 has partial support.

**Sub-resource Integrity (SRI)** W3C specification  
[http://www.w3.org/TR/SRI/](http://www.w3.org/TR/SRI/)

**HSTS**

**hapijs**  
[https://hapijs.com/api/](https://hapijs.com/api/)

**Use helmetjs/hsts**  
[https://github.com/helmetjs/hsts](https://github.com/helmetjs/hsts)  
to enforce `Strict-Transport-Security` in Express  
[https://helmetjs.github.io/docs/hsts/](https://helmetjs.github.io/docs/hsts/)

**Another Slide Deck from Francois Marier** covering HTTP Strict Transport Security (HSTS), Content Security Policy (CSP), Sub-resource Integrity (SRI)  
[https://speakerdeck.com/fmarier/integrity-protection-for-third-party-javascript](https://speakerdeck.com/fmarier/integrity-protection-for-third-party-javascript)

**MDN easily digestible help** on using HSTS  
[https://developer.mozilla.org/en-US/docs/Web/Security/HTTP_strict_transport_security](https://developer.mozilla.org/en-US/docs/Web/Security/HTTP_strict_transport_security)

**Easy Reading: OWASP**  
[https://www.owasp.org/index.php/HTTP_Strict_Transport_Security](https://www.owasp.org/index.php/HTTP_Strict_Transport_Security)

**IETF specification**  
[https://tools.ietf.org/html/draft-ietf-websec-strict-transport-sec-14](https://tools.ietf.org/html/draft-ietf-websec-strict-transport-sec-14)

**Most browsers currently have support**. IE < 10 does not. 11 has back ported support for Windows 8.1 and 7 [https://blogs.windows.com/msedgedev/2015/06/09/http-strict-transport-security-comes-to-internet-explorer-11-on-windows-8-1-and-windows-7/](https://blogs.windows.com/msedgedev/2015/06/09/http-strict-transport-security-comes-to-internet-explorer-11-on-windows-8-1-and-windows-7/)

**SSLStrip2 - dns2proxy attack demonstrated at BlackHat Asia in 2014 by LeonardoNve**

**Stackoverflow question and answer**  
http://stackoverflow.com/questions/29320182/hsts-bypass-with-sslstrip-dns2proxy/2935717  
0#29357170

**Questions and definitive answers by Leonardo Nve**  
[https://github.com/LeonardoNve/sslstrip2/issues/4](https://github.com/LeonardoNve/sslstrip2/issues/4)

%% What Kevin used, but was against IE 8 https://cyberarms.wordpress.com/2014/10/16/mana-tutorial-the-intelligent-rogue-wi-fi-router/

**Security stackexchange questions and answers**  
http://security.stackexchange.com/questions/91092/how-does-bypassing-hsts-with-sslstrip-wo  
rk-exactly

**Good write-up on how to compromise HSTS** Including NTP vector.  
[https://jetcat.nl/blog/bypassing-http-strict-transport-security-hsts](https://jetcat.nl/blog/bypassing-http-strict-transport-security-hsts)

%% http://null-byte.wonderhowto.com/how-to/defeating-hsts-and-bypassing-https-with-dns-server-changes-and-mitmf-0162322/
%% http://jackktutorials.com/forums/showthread.php?pid=5972
%% https://github.com/LeonardoNve/sslstrip2
%% https://github.com/byt3bl33d3r/MITMf
%% https://github.com/sensepost/mana
%% https://github.com/byt3bl33d3r/sslstrip2
%% 




**All of the CAs now use intermediate certificates** to sign your certificate, so that they can keep their root certificate off line. Similar to what I did with GPG in my blog post  
[http://blog.binarymist.net/2015/01/31/gnupg-key-pair-with-sub-keys/#master-key-pair-generation](http://blog.binarymist.net/2015/01/31/gnupg-key-pair-with-sub-keys/#master-key-pair-generation).

**This URL is known as the Certification Revocation List (CRL)** distribution point.  
[http://en.wikipedia.org/wiki/Revocation_list](http://en.wikipedia.org/wiki/Revocation_list)  

**The next stage of the evolution was Online Certificate Status Protocol (OCSP)**  
[http://en.wikipedia.org/wiki/Online_Certificate_Status_Protocol](http://en.wikipedia.org/wiki/Online_Certificate_Status_Protocol)  
which came about in 1998  
[http://tools.ietf.org/html/rfc6960#page-31](http://tools.ietf.org/html/rfc6960#page-31).

**pinning** [http://en.wikipedia.org/wiki/HTTP_Public_Key_Pinning](http://en.wikipedia.org/wiki/HTTP_Public_Key_Pinning)

**You can read more about pinning** on the OWASP Certificate and Public Key Pinning page  
[https://www.owasp.org/index.php/Certificate_and_Public_Key_Pinning](https://www.owasp.org/index.php/Certificate_and_Public_Key_Pinning)  
and also the specification  
[https://tools.ietf.org/html/draft-ietf-websec-key-pinning-21](https://tools.ietf.org/html/draft-ietf-websec-key-pinning-21).

**Details of what An OCSP request should look like** can be seen in 2.1 of the OCSP specification  
[http://tools.ietf.org/html/rfc6960#section-2.1](http://tools.ietf.org/html/rfc6960#section-2.1).

**Details of what the OCSP response will look like** can be seen in 2.2 of the OCSP specification  
[http://tools.ietf.org/html/rfc6960#section-2.2](http://tools.ietf.org/html/rfc6960#section-2.2).

**OCSP Stapling**  
[http://en.wikipedia.org/wiki/OCSP_stapling](http://en.wikipedia.org/wiki/OCSP_stapling)

**You can read the specification for OCSP stapling** officially known as the TLS "Certificate Status Request" extension in the TLS Extensions: Extensions Definitions  
[http://tools.ietf.org/html/rfc6066#section-8](http://tools.ietf.org/html/rfc6066#section-8).

**digicert** [https://www.digicert.com/help/](https://www.digicert.com/help/)

**ssl labs** [https://www.ssllabs.com/ssltest/](https://www.ssllabs.com/ssltest/)

**OCSP Must-Staple** [https://wiki.mozilla.org/CA:ImprovingRevocation](https://wiki.mozilla.org/CA:ImprovingRevocation)

**X.509 Certificate Revocation Evolution**  
[https://www.grc.com/revocation/ocsp-must-staple.htm](https://www.grc.com/revocation/ocsp-must-staple.htm)  
[http://twit.cachefly.net/audio/sn/sn0453/sn0453.mp3](http://twit.cachefly.net/audio/sn/sn0453/sn0453.mp3)  
[https://www.grc.com/sn/sn-453-notes.pdf](https://www.grc.com/sn/sn-453-notes.pdf)  
[https://www.grc.com/sn/sn-453.htm](https://www.grc.com/sn/sn-453.htm)

## [Cloud](#cloud)

**Most of these questions were already part of my Cloud vs In-house** talk at the Saturn Architects conference  
[http://blog.binarymist.net/presentations-publications/#does-your-cloud-solution-look-like-a-mushroom](http://blog.binarymist.net/presentations-publications/#does-your-cloud-solution-look-like-a-mushroom)

**Hosting providers can be, and in many cases are forced** by governing authorities to give up your and your customers secrets  
[http://www.stuff.co.nz/business/industries/67546433/Spies-request-data-from-Trade-Me](http://www.stuff.co.nz/business/industries/67546433/Spies-request-data-from-Trade-Me)  
[https://www.stuff.co.nz/business/95116991/trade-me-fields-thousands-of-requests-for-member-information](https://www.stuff.co.nz/business/95116991/trade-me-fields-thousands-of-requests-for-member-information)

**The attack and demise of Code Spaces**  
https://cloudacademy.com/blog/how-codespaces-was-killed-by-security-issues-on-aws-the-b  
est-practices-to-avoid-it/

**Discussed this with Haroon Meer** on the Network Security show I hosted for Software Engineering Radio  
[http://www.se-radio.net/2017/09/se-radio-episode-302-haroon-meer-on-network-security/](http://www.se-radio.net/2017/09/se-radio-episode-302-haroon-meer-on-network-security/)

**The default on AWS EC2 instances** is to have a single user (root)  
[https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/managing-users.html](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/managing-users.html)

**dockerfile-from-image**  
[https://github.com/CenturyLinkLabs/dockerfile-from-image](https://github.com/CenturyLinkLabs/dockerfile-from-image)

**ImageLayers**  
[https://imagelayers.io/](https://imagelayers.io/) 

**Single default AWS account root user** you are given when you first sign up to AWS  
[https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html)

**Amazon**  
[https://aws.amazon.com/serverless/](https://aws.amazon.com/serverless/)  
**Has Lambda**  
[https://aws.amazon.com/lambda/](https://aws.amazon.com/lambda/)

**GCP**  
[https://cloud.google.com/serverless/](https://cloud.google.com/serverless/)  
**Has Cloud Functions**  
[https://cloud.google.com/functions/](https://cloud.google.com/functions/)

**Azure has Functions**  
[https://azure.microsoft.com/en-us/services/functions/](https://azure.microsoft.com/en-us/services/functions/)

**Rich Jones demonstrated** what can happen if you fail at the above three points in AWS in his talk "Gone in 60 Milliseconds"  
[https://www.youtube.com/watch?v=YZ058hmLuv0](https://www.youtube.com/watch?v=YZ058hmLuv0)

**Containers are used**  
[https://docs.aws.amazon.com/lambda/latest/dg/lambda-introduction.html](https://docs.aws.amazon.com/lambda/latest/dg/lambda-introduction.html)

**Billing DoS**  
[https://thenewstack.io/zombie-toasters-eat-startup/](https://thenewstack.io/zombie-toasters-eat-startup/)  
**Is a real issue**  
[https://sourcebox.be/blog/2017/08/07/serverless-a-lesson-learned-the-hard-way/](https://sourcebox.be/blog/2017/08/07/serverless-a-lesson-learned-the-hard-way/)

**AWS Lambda will by default** allow any given function a concurrent execution of 1000 per region  
[https://docs.aws.amazon.com/lambda/latest/dg/concurrent-executions.html#concurrent-execution-safety-limit](https://docs.aws.amazon.com/lambda/latest/dg/concurrent-executions.html#concurrent-execution-safety-limit)

**CIS AWS Foundations document**  
[https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf](https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf)

**AWS Shared Responsibility Model**  
[https://aws.amazon.com/compliance/shared-responsibility-model/](https://aws.amazon.com/compliance/shared-responsibility-model/)

**CloudTrail**  
[https://aws.amazon.com/cloudtrail/](https://aws.amazon.com/cloudtrail/)

**AWS also provides Virtual Private Cloud**  
[https://aws.amazon.com/vpc/](https://aws.amazon.com/vpc/)

**Including Serverless**  
[https://aws.amazon.com/serverless/](https://aws.amazon.com/serverless/)

**AWS also offers four different types of VPN connections** to your VPC  
[https://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/vpn-connections.html](https://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/vpn-connections.html)

**Some of the CSPs log aggregators** could be flaky for example  
https://read.acloud.guru/things-you-should-know-before-using-awss-elasticsearch-service-7  
cd70c9afb4f

**As usual, AWS has good documentation** around what sort of log events are captured  
[https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html)

**Plethora of services you can integrate with CloudTrail**  
https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-supported-services  
.html

**Define AWS Lambda functions**  
[https://docs.aws.amazon.com/lambda/latest/dg/with-cloudtrail.html](https://docs.aws.amazon.com/lambda/latest/dg/with-cloudtrail.html)

**AWS CloudWatch** can be used to collect and track your resource and application metrics  
https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/WhatIsCloudWatch.  
html

**Make sure you have an exit and/or migration strategy planned**  
[http://blog.sysfore.com/do-you-have-your-cloud-exit-plan-ready/](http://blog.sysfore.com/do-you-have-your-cloud-exit-plan-ready/)

**CSPs proprietary API based technique** for migrating your data  
http://searchcloudstorage.techtarget.com/opinion/The-need-for-a-cloud-exit-strategy-and-w  
hat-we-can-learn-from-Nirvanix

**Nirvanix**  
http://searchcloudstorage.techtarget.com/news/2240205813/Nirvanix-cloud-customers-face-  
worse-nightmares

**The less you depend on your CSPs proprietary services**, the less benefit you will be getting from them  
http://www.theserverside.com/feature/Getting-out-is-harder-than-getting-in-The-importanc  
e-of-a-cloud-exit-strategy

**EC2 Instance Store Encryption**  
https://aws.amazon.com/blogs/security/how-to-protect-data-at-rest-with-amazon-ec2-instan  
ce-store-encryption/

**Elastic File System (EFS) encryption**  
https://aws.amazon.com/about-aws/whats-new/2017/08/amazon-efs-now-supports-encryptio  
n-of-data-at-rest/

**Ben Humphreys spoke about this at CHCon**  
[https://2016.chcon.nz/talks.html#1245](https://2016.chcon.nz/talks.html#1245)

**AWS has a list of their compliance certificates**  
[https://pages.awscloud.com/compliance-contact-us.html](https://pages.awscloud.com/compliance-contact-us.html)

**AWS allow customers to submit requests to penetration test**  
[https://aws.amazon.com/security/penetration-testing](https://aws.amazon.com/security/penetration-testing)

**GCP does not require penetration testers** to contact them before beginning testing of their GCP hosted services  
[https://cloud.google.com/security/](https://cloud.google.com/security/)

**Heroku are happy for you to penetration test** your applications running on their PaaS  
[https://devcenter.heroku.com/articles/pentest-instructions](https://devcenter.heroku.com/articles/pentest-instructions)

**Azure allows penetration testing** of your applications and services running in Azure  
https://blogs.msdn.microsoft.com/azuresecurity/2016/08/29/pen-testing-from-azure-vir  
tual-machines/

**AWS has a bug bounty program**  
[https://hackerone.com/amazon-web-services](https://hackerone.com/amazon-web-services)

**Heroku offer a bug bounty program**  
[https://hackerone.com/heroku](https://hackerone.com/heroku)

**Azure offer a bug bounty program**  
[https://hackerone.com/azure](https://hackerone.com/azure)

**Physical and People chapters in Fascicle 0** of this book series  
[https://leanpub.com/holistic-infosec-for-web-developers](https://leanpub.com/holistic-infosec-for-web-developers)

**I have blogged**  
[https://blog.binarymist.net/?s=tdd](https://blog.binarymist.net/?s=tdd)  
**Spoken and run workshops** on the topic of testability  
[https://blog.binarymist.net/presentations-publications/](https://blog.binarymist.net/presentations-publications/)

**Liskov Substitution Principle**  
[https://blog.binarymist.net/2010/10/11/lsp-dbc-and-nets-support/](https://blog.binarymist.net/2010/10/11/lsp-dbc-and-nets-support/)

**Docker restart policy**  
[https://docs.docker.com/engine/admin/start-containers-automatically/](https://docs.docker.com/engine/admin/start-containers-automatically/)

**In AWS**  
[https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege)  
**You need to keep a close watch on which permissions**  
[https://docs.aws.amazon.com/IAM/latest/UserGuide/access_permissions.html](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_permissions.html)  
**Are assigned to policies**  
[https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html)

**Enable Multi Factor Authentication**  
[https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#enable-mfa-for-privileged-users](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#enable-mfa-for-privileged-users)

**AWS DelegateManagementofMFA_policydocument template**  
https://s3.amazonaws.com/awsiammedia/public/sample/Delegat  
eManagementofMFA/DelegateManagementofMFA_policydocument_060115.txt

**AWS has documentation on the process**  
[https://aws.amazon.com/blogs/security/how-to-delegate-management-of-multi-factor-authentication-to-aws-iam-users/](https://aws.amazon.com/blogs/security/how-to-delegate-management-of-multi-factor-authentication-to-aws-iam-users/) 

**The Access Advisor** tab  
[https://aws.amazon.com/blogs/security/remove-unnecessary-permissions-in-your-iam-policies-by-using-service-last-accessed-data/](https://aws.amazon.com/blogs/security/remove-unnecessary-permissions-in-your-iam-policies-by-using-service-last-accessed-data/)

**IAM Policy Simulator**  
[https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_testing-policies.html](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_testing-policies.html)

**AWS Trusted Advisor**  
[https://aws.amazon.com/premiumsupport/trustedadvisor/](https://aws.amazon.com/premiumsupport/trustedadvisor/)

**Accessible from the Console**  
[https://console.aws.amazon.com/trustedadvisor/](https://console.aws.amazon.com/trustedadvisor/)

**Have solid change control in place**. AWS Config can assist with this  
[https://aws.amazon.com/config/](https://aws.amazon.com/config/)  
**AWS Config** continuously monitors and records  
[https://docs.aws.amazon.com/config/latest/developerguide/](https://docs.aws.amazon.com/config/latest/developerguide/)

**As part of the VPS and container builds**, there should be specific users created  
[https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/managing-users.html](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/managing-users.html)

**Drive a least privilege policy**  
[https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege)

**Configuring a strong password policy** for your users  
https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#configure-strong-pa  
ssword-policy 

**Implement multi-factor authentication**  
[https://aws.amazon.com/iam/details/mfa/](https://aws.amazon.com/iam/details/mfa/)

**As usual, AWS has plenty of documentation**  
https://aws.amazon.com/blogs/security/how-to-receive-notifications-when-your-aws-accoun  
ts-root-access-keys-are-used/

**Set-up monitoring and notifications** on activity of your AWS account root user. AWS documentation explains how to do this  
[https://aws.amazon.com/blogs/mt/monitor-and-notify-on-aws-account-root-user-activity/](https://aws.amazon.com/blogs/mt/monitor-and-notify-on-aws-account-root-user-activity/) 

**Canarytoken**  
[https://canarytokens.org/](https://canarytokens.org/)

**Jay**  
[https://twitter.com/HeyJayza](https://twitter.com/HeyJayza)  
**Also wrote a blog post** on the thinkst blog  
[http://blog.thinkst.com/2017/09/canarytokens-new-member-aws-api-key.html](http://blog.thinkst.com/2017/09/canarytokens-new-member-aws-api-key.html)

**AWS EC2 for example provide auto-expire, auto-renew**  
[https://aws.amazon.com/blogs/security/how-to-rotate-access-keys-for-iam-users/](https://aws.amazon.com/blogs/security/how-to-rotate-access-keys-for-iam-users/)

**Storage of Secrets**  
https://www.programmableweb.com/news/why-exposed-api-keys-and-sensitive-data-are-gro  wing-cause-concern/analysis/2015/01/05


**Github provides guidance** on removing sensitive data from a repository  
[https://help.github.com/articles/removing-sensitive-data-from-a-repository/](https://help.github.com/articles/removing-sensitive-data-from-a-repository/)

**Consider using git-crypt**  
[https://github.com/AGWA/git-crypt](https://github.com/AGWA/git-crypt)

**Temporary security credentials**  
[https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp.html](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp.html)

**Lack of knowledge, desire and a dysfunctional culture** in the work place  
[https://blog.binarymist.net/2014/04/26/culture-in-the-work-place/](https://blog.binarymist.net/2014/04/26/culture-in-the-work-place/)

**Most of the commands are either deployment** or manual monitoring which should all be automated  
[https://github.com/binarymist/aws-docker-host](https://github.com/binarymist/aws-docker-host)

**Create a key pair using EC2**  
https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-key-pairs.html#having-ec2-cr  
eate-your-key-pair  
**Or you can provide your own**  
[https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-key-pairs.html#how-to-generate-your-own-key-and-import-it-to-aws](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-key-pairs.html#how-to-generate-your-own-key-and-import-it-to-aws)

**Every user should have their own key-pair**  
[https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-key-pairs.html](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-key-pairs.html)

**Plesant Password Server**  
[http://pleasantsolutions.com/PasswordServer/](http://pleasantsolutions.com/PasswordServer/)  
**Password Manager Pro**  
[https://www.manageengine.com/products/passwordmanagerpro/msp/features.html](https://www.manageengine.com/products/passwordmanagerpro/msp/features.html)  
**LastPass**  
[https://www.lastpass.com/teams](https://www.lastpass.com/teams)

**Even if it is in a group password manager**. As AWS have already stated  
https://docs.aws.amazon.com/IAM/latest/UserGuide/getting-started_create-admin-group.h  
tml

**There should be almost no reason** to create an access key for the root user  
[https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#lock-away-credentials](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#lock-away-credentials)

**Configure strong password policies**  
https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#configure-strong-p  
assword-policy

**Check the Secret Backends for integrations**  
[https://www.vaultproject.io/docs/secrets/index.html](https://www.vaultproject.io/docs/secrets/index.html)

**Docker secrets**  
[https://docs.docker.com/engine/swarm/secrets/](https://docs.docker.com/engine/swarm/secrets/)

**Ansible Vault**  
[https://docs.ansible.com/ansible/latest/playbooks_vault.html](https://docs.ansible.com/ansible/latest/playbooks_vault.html)

**Ansible is an Open Source**  
[https://github.com/ansible/ansible/blob/devel/docs/docsite/rst/playbooks_vault.rst](https://github.com/ansible/ansible/blob/devel/docs/docsite/rst/playbooks_vault.rst)

**AWS Key Management Service**  
[https://aws.amazon.com/kms/](https://aws.amazon.com/kms/)

**AWS has Parameter Store**  
[https://aws.amazon.com/ec2/systems-manager/parameter-store/](https://aws.amazon.com/ec2/systems-manager/parameter-store/)

**Serverless**  
[https://github.com/anaibol/awesome-serverless](https://github.com/anaibol/awesome-serverless)

**SOLID principles**  
https://en.wikipedia.org/wiki/SOLID_%28object-oriented_design%29

**Serverless** goes a long way to forcing us to write testable code**  
[https://blog.binarymist.net/2012/12/01/moving-to-tdd/](https://blog.binarymist.net/2012/12/01/moving-to-tdd/)

**Open/closed principle**  
[https://en.wikipedia.org/wiki/Open/closed_principle](https://en.wikipedia.org/wiki/Open/closed_principle)

**There are no maintenance windows or scheduled downtimes**  
[https://aws.amazon.com/lambda/faqs/#scalability](https://aws.amazon.com/lambda/faqs/#scalability)

**Permissions Model**  
[https://docs.aws.amazon.com/lambda/latest/dg/intro-permission-model.html](https://docs.aws.amazon.com/lambda/latest/dg/intro-permission-model.html)

**Snyk has a Serverless offering**  
[https://snyk.io/serverless](https://snyk.io/serverless)

**AWS Lambda function access to other AWS resources**  
[https://docs.aws.amazon.com/lambda/latest/dg/intro-permission-model.html#lambda-intro-execution-role](https://docs.aws.amazon.com/lambda/latest/dg/intro-permission-model.html#lambda-intro-execution-role)

**Create an IAM execution role of type** `AWS Service Roles`  
[https://docs.aws.amazon.com/lambda/latest/dg/with-s3-example-create-iam-role.html](https://docs.aws.amazon.com/lambda/latest/dg/with-s3-example-create-iam-role.html)

**Other AWS resources access to AWS Lambda**  
https://docs.aws.amazon.com/lambda/latest/dg/intro-permission-model.html#intro-permiss  
ion-model-access-policy

**Use**  
[https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-setup-api-key-with-console.html](https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-setup-api-key-with-console.html)  
**An API key**  
[https://serverless.com/framework/docs/providers/aws/events/apigateway/#setting-api-keys-for-your-rest-api](https://serverless.com/framework/docs/providers/aws/events/apigateway/#setting-api-keys-for-your-rest-api)

**AWS Lambda allows you to throttle the concurrent execution count**  
[https://docs.aws.amazon.com/lambda/latest/dg/concurrent-executions.html#concurrent-execution-safety-limit](https://docs.aws.amazon.com/lambda/latest/dg/concurrent-executions.html#concurrent-execution-safety-limit)

**Set Cloudwatch alarms**  
[https://docs.aws.amazon.com/lambda/latest/dg/monitoring-functions.html](https://docs.aws.amazon.com/lambda/latest/dg/monitoring-functions.html)  
**On duration and invocations**  
[https://docs.aws.amazon.com/lambda/latest/dg/monitoring-functions-metrics.html](https://docs.aws.amazon.com/lambda/latest/dg/monitoring-functions-metrics.html)

**Drive the creation of your functions** the same way you would drive any other production quality code... with unit tests (TDD)  
[https://blog.binarymist.net/2012/12/01/moving-to-tdd/](https://blog.binarymist.net/2012/12/01/moving-to-tdd/)

**You can mock, stub, pass spies in the AWS**  
[https://serverless.zone/unit-and-integration-testing-for-lambda-fc9510963003](https://serverless.zone/unit-and-integration-testing-for-lambda-fc9510963003)

**aws-sdk-mock**  
[https://www.npmjs.com/package/aws-sdk-mock](https://www.npmjs.com/package/aws-sdk-mock)  
**mock-aws**  
[https://www.npmjs.com/package/mock-aws](https://www.npmjs.com/package/mock-aws)  
**placebo**  
[https://github.com/garnaat/placebo](https://github.com/garnaat/placebo)  
**moto**  
[https://github.com/spulec/moto](https://github.com/spulec/moto)

**Centralised logging of AWS Lambda Functions**  
[https://hackernoon.com/centralised-logging-for-aws-lambda-b765b7ca9152](https://hackernoon.com/centralised-logging-for-aws-lambda-b765b7ca9152)

**AWS Elasticsearch which may or may not be stable enough**  
https://read.acloud.guru/things-you-should-know-before-using-awss-elasticsearch-service-7  
cd70c9afb4f

**Serverless**  
[https://serverless.com/framework/](https://serverless.com/framework/)  
**Along with a large collection** of awesome-serverless resources on github  
[https://github.com/JustServerless/awesome-serverless](https://github.com/JustServerless/awesome-serverless)

**Claudia.JS**  
[https://claudiajs.com/](https://claudiajs.com/)

**Zappa**  
[https://www.zappa.io/](https://www.zappa.io/)

**Software Engineering Radio** ran an excellent podcast on Terraform  
http://www.se-radio.net/2017/04/se-radio-episode-289-james-turnbull-on-declarative-progra  
mming-with-terraform/

**Continuous integration**  
[https://blog.binarymist.net/2014/02/22/automating-specification-by-example-for-net/](https://blog.binarymist.net/2014/02/22/automating-specification-by-example-for-net/)

**Security Monkey Monitors AWS and GCP accounts for policy changes**  
[https://github.com/Netflix/security_monkey/](https://github.com/Netflix/security_monkey/)

**Simian Army tools from Netflix**  
[https://github.com/Netflix/SimianArmy/wiki](https://github.com/Netflix/SimianArmy/wiki)

**Chaos Monkey**  
[https://github.com/Netflix/SimianArmy/wiki/Chaos-Monkey](https://github.com/Netflix/SimianArmy/wiki/Chaos-Monkey)  
**Janitor Monkey**  
[https://github.com/Netflix/SimianArmy/wiki/Janitor-Home](https://github.com/Netflix/SimianArmy/wiki/Janitor-Home)  
**Conformity Monkey**  
[https://github.com/Netflix/SimianArmy/wiki/Conformity-Home](https://github.com/Netflix/SimianArmy/wiki/Conformity-Home)  
**CloudSploit**  
[https://cloudsploit.com/](https://cloudsploit.com/)

**Amazon Inspector**  
[https://console.aws.amazon.com/inspector/](https://console.aws.amazon.com/inspector/)  
**Awesome AWS**  
[https://github.com/donnemartin/awesome-aws](https://github.com/donnemartin/awesome-aws)

**Tools that can break password databases**  
[https://github.com/denandz/KeeFarce](https://github.com/denandz/KeeFarce)

**Commonly known as the secret zero** problem  
[https://news.ycombinator.com/item?id=9453754](https://news.ycombinator.com/item?id=9453754)

**Tools set-up** so that they are continually auditing your infrastructure  
[https://blog.cloudsploit.com/the-importance-of-continual-auditing-in-the-cloud-8d22e0554639](https://blog.cloudsploit.com/the-importance-of-continual-auditing-in-the-cloud-8d22e0554639)

**Tunnel RDP through your SSH tunnel** as I have blogged about  
[https://blog.binarymist.net/2010/08/26/installation-of-ssh-on-64bit-windows-7-to-tunnel-rdp/](https://blog.binarymist.net/2010/08/26/installation-of-ssh-on-64bit-windows-7-to-tunnel-rdp/)

**Documentation around setting up the bastion host in AWS**  
[https://cloudacademy.com/blog/aws-bastion-host-nat-instances-vpc-peering-security/](https://cloudacademy.com/blog/aws-bastion-host-nat-instances-vpc-peering-security/)

**AWS provide some Best Practices** for security on bastion hosts  
[https://docs.aws.amazon.com/quickstart/latest/linux-bastion/architecture.html#best-practices](https://docs.aws.amazon.com/quickstart/latest/linux-bastion/architecture.html#best-practices)

**Also discuss recording the SSH sessions** that your users establish through a bastion host  
https://aws.amazon.com/blogs/security/how-to-record-ssh-sessions-established-through-a-b  
astion-host/

**Culture and techniques for bringing change** in various talks  
[https://www.slideshare.net/kimcarter75098/agile-nz2014fornonattendees-38768039](https://www.slideshare.net/kimcarter75098/agile-nz2014fornonattendees-38768039)  
**Blog posts**  
[https://blog.binarymist.net/2014/04/26/culture-in-the-work-place/#effecting-change](https://blog.binarymist.net/2014/04/26/culture-in-the-work-place/#effecting-change)

## [Web Applications](#web-applications)

**MS Application Threats and Countermeasures**  
[https://msdn.microsoft.com/en-us/library/ff648641.aspx#c02618429_008](https://msdn.microsoft.com/en-us/library/ff648641.aspx#c02618429_008)

**OWASP has the RSnake donated** seminal XSS cheat sheet  
[https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet](https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet)  
which has many tests you can use to check your vulnerability stance to XSS exploitation.

**XSS attack**  
Good resource on what XSS actually is:  
[https://www.owasp.org/index.php/XSS](https://www.owasp.org/index.php/XSS)

**Dam Vulnerable Web Application (DVWA)** from the OWASP Broken Web Applications VM  
[http://sourceforge.net/projects/owaspbwa/files/](http://sourceforge.net/projects/owaspbwa/files/)

%% Identify Risks for CSRF

**Code can be found at**  
https://github.com/OWASP/NodeGoat/blob/b475010f2de3d601eda3ad2498d9e6c729204a09/  
app/views/profile.html

**NodeGoat tutorial for CSRF**  
[https://nodegoat.herokuapp.com/tutorial/a8](https://nodegoat.herokuapp.com/tutorial/a8)

%% End Identify Risks for CSRF

%% Injection Risks

**Defects can range from** trivial to complete system compromise  
[https://www.owasp.org/index.php/Injection_Flaws](https://www.owasp.org/index.php/Injection_Flaws)

**OWASP Broken Web Applications VM**  
[http://sourceforge.net/projects/owaspbwa/files/](http://sourceforge.net/projects/owaspbwa/files/)

%% End Injection Risks
%% NoSQLi Risks

**Over 225 types of NoSQL data stores**  
[http://nosql-database.org/](http://nosql-database.org/)

**The MongoDB `$gt` comparison operator**  
[https://docs.mongodb.com/manual/reference/operator/query/gt/#op._S_gt](https://docs.mongodb.com/manual/reference/operator/query/gt/#op._S_gt)

%% End NoSQLi Risks
%% Command Injection Risks

**JavaScript `eval` function**  
[https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval)

**JavaScript `setTimeout` and `setInterval` functions**  
https://developer.mozilla.org/en-US/docs/Web/API/WindowOrWorkerGlobalScope/  
setTimeout  
https://developer.mozilla.org/en-US/docs/Web/API/WindowOrWorkerGlobalScope/  
setInterval

**JavaScript `Function` constructor**  
https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/  
Function

**NodeGoat, provides some simple examples** in the form of executable code  
https://github.com/OWASP/NodeGoat/blob/b475010f2de3d601eda3ad2498d9e6c729204a09  
/app/routes/contributions.js#L24-L26

**Tutorial with videos of exploiting Command Injection**  
[https://nodegoat.herokuapp.com/tutorial/a1](https://nodegoat.herokuapp.com/tutorial/a1)

**OWASP Top 10 A10 Underprotected APIs**  
[https://www.owasp.org/index.php/Top_10_2017-A10-Underprotected_APIs](https://www.owasp.org/index.php/Top_10_2017-A10-Underprotected_APIs)

%% End Command Injection Risks
%% XML Injection Risks

**Attempting to create invalid XML document** by injecting various XML metacharacters  
https://www.owasp.org/index.php/Testing_for_XML_Injection_(OTG-INPVAL-008)#Disco  
very

**XML External Entity (XXE) exploitation**  
https://www.owasp.org/index.php/XML\_External\_Entity\_(XXE)\_Processing

**Tag injections**  
https://www.owasp.org/index.php/Testing_for_XML_Injection_(OTG-INPVAL-008)#Tag_In  
jection

**Adam Bell also presented on the following XML Injection attack types** at the OWASP New Zealand Day conference in 2017  
https://www.owasp.org/index.php/OWASP_New_Zealand_Day_2017#tab=Presentation_Sch  
edule

**Adams slide-deck**  
[https://www.owasp.org/images/4/48/2017-04-20-OWASPNZ-XMLDangerous.pdf](https://www.owasp.org/images/4/48/2017-04-20-OWASPNZ-XMLDangerous.pdf)

%% End XML Injection Risks
%% XSLT Injection Risks

**XSLT Injection**  
[https://www.owasp.org/images/a/ae/OWASP_Switzerland_Meeting_2015-06-17_XSLT_SSRF_ENG.pdf](https://www.owasp.org/images/a/ae/OWASP_Switzerland_Meeting_2015-06-17_XSLT_SSRF_ENG.pdf)

%% End XSLT Injection Risks
%% XPath Injection Risks

**XPath has no provision for commenting out tails of expressions**  
[https://www.owasp.org/index.php/Comment_Injection_Attack#Examples](https://www.owasp.org/index.php/Comment_Injection_Attack#Examples)

**A query can access every part of the XML document**  
https://www.owasp.org/index.php/Testing_for_XPath_Injection_(OTG-INPVAL-010)#Sum  
mary

**Blind injection is a technique used in many types of injection**  
[https://www.owasp.org/index.php/Blind_XPath_Injection](https://www.owasp.org/index.php/Blind_XPath_Injection)

**OWASP XML Crawling documentation**  
[https://www.owasp.org/index.php/Blind_XPath_Injection#XML_Crawling](https://www.owasp.org/index.php/Blind_XPath_Injection#XML_Crawling)

**XPath functions and XSLT specific additions to XPath**  
[https://developer.mozilla.org/en-US/docs/Web/XPath/Functions](https://developer.mozilla.org/en-US/docs/Web/XPath/Functions)

**projects.webappsec.org**  
[http://projects.webappsec.org/w/page/13247006/XQuery%20Injection%7C](http://projects.webappsec.org/w/page/13247006/XQuery%20Injection%7C)

**XQuery also has an extension**  
[https://www.mssqltips.com/sqlservertip/2738/examples-of-using-xquery-to-update-xml-data-in-sql-server/](https://www.mssqltips.com/sqlservertip/2738/examples-of-using-xquery-to-update-xml-data-in-sql-server/)

**Called the XML Data Modification Language (DML)**  
[https://docs.microsoft.com/en-us/sql/t-sql/xml/xml-data-modification-language-xml-dml](https://docs.microsoft.com/en-us/sql/t-sql/xml/xml-data-modification-language-xml-dml)

%% End XPath Injection Risks
%% LDAP Injection Risks

**Successful LDAP injection attacks**  
[https://www.owasp.org/index.php/LDAP_Injection_Prevention_Cheat_Sheet#Introduction](https://www.owasp.org/index.php/LDAP_Injection_Prevention_Cheat_Sheet#Introduction)

**LDAP search filter metacharacters can be injected**  
https://www.owasp.org/index.php/Testing_for_LDAP_Injection_(OTG-INPVAL-006)#Sum  
mary

**Polish notation**  
[https://en.wikipedia.org/wiki/Polish_notation](https://en.wikipedia.org/wiki/Polish_notation)

**LDAP true filter**  
[https://docs.oracle.com/cd/E19476-01/821-0510/def-and-search-filter.html](https://docs.oracle.com/cd/E19476-01/821-0510/def-and-search-filter.html)

**Only the first filter is processed by the LDAP server**  
[https://www.blackhat.com/presentations/bh-europe-08/Alonso-Parada/Whitepaper/bh-eu-08-alonso-parada-WP.pdf](https://www.blackhat.com/presentations/bh-europe-08/Alonso-Parada/Whitepaper/bh-eu-08-alonso-parada-WP.pdf)

%% End LDAP Injection Risks




**The New Zealand Intelligence Service** recently told Prime Minister John Key that this was one of the 6 top threats facing New Zealand. "_Cyber attack or loss of information and data, which poses financial and reputational risks._"  

http://www.stuff.co.nz/national/politics/73704551/homegrown-threats-more-serious-says-spy-boss-rebecca-kitteridge

**Before the breach**, the company boasted about airtight data security but ironically, still proudly displays a graphic with the phrase “trusted security award” on its homepage.  
http://www.darkreading.com/operations/what-ashley-madison-can-teach-the-rest-of-  
us-about-data-security-/a/d-id/1322129

**Other notable data-store compromises were LinkedIn** with 6.5 million user accounts compromised and 95% of the users passwords cracked in days. Why so fast? Because they used simple hashing, specifically SHA-1. Details provided [here](http://securitynirvana.blogspot.co.nz/2012/06/final-word-on-linkedin-leak.html) on the findings.

**EBay with 145 million active buyers** had a small number of employee log-in credentials compromised allowing unauthorised access to eBay's corporate network.  
http://www.darkreading.com/attacks-breaches/ebay-database-hacked-with-stolen-employee-credentials-/d/d-id/1269093

**The OWASP Top 10 risks** No. 2 Broken Authentication and Session Management  
https://www.owasp.org/index.php/Top_10_2013-A2-Broken_Authentication_and_Session_  
Management

**Warning against using CBC**  
[https://github.com/bitwiseshiftleft/sjcl/wiki/Directly-Using-Ciphers](https://github.com/bitwiseshiftleft/sjcl/wiki/Directly-Using-Ciphers)

**Exemptions have been granted so that OCB** can be used in software licensed under the GNU General Public License  
[https://en.wikipedia.org/wiki/OCB_mode](https://en.wikipedia.org/wiki/OCB_mode)

**Background on OCB** from the creator  
[http://web.cs.ucdavis.edu/~rogaway/ocb/ocb-back.htm](http://web.cs.ucdavis.edu/~rogaway/ocb/ocb-back.htm)

**There are some very sobering statistics**, also detailed in "the morning paper" by Adrian Colyer, on how many defective libraries we are depending on  
https://blog.acolyer.org/2017/03/07/thou-shalt-not-depend-on-me-analysing-the-use-of-out  
dated-javascript-libraries-on-the-web/

%% Insufficient Attack Protection

**What the Insecure Direct Object References risk looks like** in the NodeGoat web application  
[https://github.com/OWASP/NodeGoat/](https://github.com/OWASP/NodeGoat/)  
Check out the tutorial  
[https://nodegoat.herokuapp.com/tutorial/a4](https://nodegoat.herokuapp.com/tutorial/a4)

%% End Insufficient Attack Protection

**the winston-syslog-posix package** was inspired by blargh  
[https://www.npmjs.com/package/winston-syslog-posix](https://www.npmjs.com/package/winston-syslog-posix)  
[http://tmont.com/blargh/2013/12/writing-to-the-syslog-with-winston](http://tmont.com/blargh/2013/12/writing-to-the-syslog-with-winston)

**There were also some other options** for those using Papertrail as their off-site syslog and aggregation PaaS:  
[http://help.papertrailapp.com/kb/configuration/configuring-centralized-logging-from-nodejs-apps/](http://help.papertrailapp.com/kb/configuration/configuring-centralized-logging-from-nodejs-apps/)

**Monit Has excellent short documentation**  
[https://mmonit.com/monit/documentation/monit.html](https://mmonit.com/monit/documentation/monit.html)

%% Statistics Graphing Countermeasures

**Statsd then aggregates the statistics** and flushes a single value for each statistic to its `backends`  
https://github.com/etsy/statsd/blob/8d5363cb109cc6363661a1d5813e0b96787c4411/exampleCo  
nfig.js#L125

**The `flushInterval`** needs to be the same as the `retentions` interval in the Carbon `/etc/carbon/storage-schemas.conf` file  
https://github.com/etsy/statsd/blob/8d5363cb109cc6363661a1d5813e0b96787c4411/exampleCo  
nfig.js#L50  
[https://graphite.readthedocs.io/en/latest/config-carbon.html#storage-schemas-conf](https://graphite.readthedocs.io/en/latest/config-carbon.html#storage-schemas-conf)

**Statistic is only being sampled 1/10th of the time**  
[https://github.com/etsy/statsd/blob/master/docs/metric_types.md#sampling](https://github.com/etsy/statsd/blob/master/docs/metric_types.md#sampling)

**Statsd does quite a lot of work with timing data**  
[https://github.com/etsy/statsd/blob/master/docs/metric_types.md#timing](https://github.com/etsy/statsd/blob/master/docs/metric_types.md#timing)

**Want to know if those changes are slowing it down**  
[https://www.digitalocean.com/community/tutorials/how-to-configure-statsd-to-collect-arbitrary-stats-for-graphite-on-ubuntu-14-04#timers](https://www.digitalocean.com/community/tutorials/how-to-configure-statsd-to-collect-arbitrary-stats-for-graphite-on-ubuntu-14-04#timers)

**Like your cars fuel gauge**  
[https://github.com/b/statsd_spec/blob/master/README.md#gauges](https://github.com/b/statsd_spec/blob/master/README.md#gauges)

**Sets allow you to send** the number of unique occurrences of events between flushes  
[https://www.digitalocean.com/community/tutorials/how-to-configure-statsd-to-collect-arbitrary-stats-for-graphite-on-ubuntu-14-04#sets](https://www.digitalocean.com/community/tutorials/how-to-configure-statsd-to-collect-arbitrary-stats-for-graphite-on-ubuntu-14-04#sets)  
[https://github.com/etsy/statsd/blob/master/docs/metric_types.md#sets](https://github.com/etsy/statsd/blob/master/docs/metric_types.md#sets)

**`exampleConfig.js`**  
https://github.com/etsy/statsd/blob/8d5363cb109cc6363661a1d5813e0b96787c4411/exampleCo  
nfig.js

**The server file must exist in the `./servers/` directory**  
[https://github.com/etsy/statsd/tree/master/servers](https://github.com/etsy/statsd/tree/master/servers)

**statsd clients**  
[https://github.com/etsy/statsd/wiki#client-implementations](https://github.com/etsy/statsd/wiki#client-implementations)

%% End Statistics Graphing Countermeasures

**Each Custom Element**  
[https://w3c.github.io/webcomponents/spec/custom/](https://w3c.github.io/webcomponents/spec/custom/)

**Has a corresponding HTML Import**  
[https://w3c.github.io/webcomponents/spec/imports/](https://w3c.github.io/webcomponents/spec/imports/)

**That provides the definition of the Custom Element**  
[https://www.polymer-project.org/1.0/docs/devguide/quick-tour](https://www.polymer-project.org/1.0/docs/devguide/quick-tour)

**We have the webcomponents.js set of polyfills** which means we can all use WebComponents  
[http://webcomponents.org/polyfills/](http://webcomponents.org/polyfills/)

**Custom Element authors can also expose Custom CSS properties** that they think consumers may want to apply values to  
[https://www.polymer-project.org/1.0/docs/devguide/styling#custom-css-properties](https://www.polymer-project.org/1.0/docs/devguide/styling#custom-css-properties)

**Custom CSS mixin**  
[https://www.polymer-project.org/1.0/docs/devguide/styling#custom-css-mixins](https://www.polymer-project.org/1.0/docs/devguide/styling#custom-css-mixins)

**This is done using the CSS @apply rule**  
[https://tabatkins.github.io/specs/css-apply-rule/](https://tabatkins.github.io/specs/css-apply-rule/)

**Polymer also has a large collection of Custom Elements** already created for you out of the box  
[https://elements.polymer-project.org/](https://elements.polymer-project.org/)

**Some of these Custom Elements are perfect for constraining** and providing validation and filtering of input types, credit card details for example  
[https://elements.polymer-project.org/browse?package=gold-elements](https://elements.polymer-project.org/browse?package=gold-elements)






**Excellent resource for dealing with user input** based on the execution contexts that it passes through  
https://www.owasp.org/index.php/XSS_%28Cross_Site_Scripting%29_Prevention_Cheat_Sheet

%% Countermeasures for CSRF

**OWASP CSRF** page  
https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)

**To enable this CSRF middleware**, simply uncomment the CSRF fix in the NodeGoat server.js file  
https://github.com/OWASP/NodeGoat/blob/b475010f2de3d601eda3ad2498d9e6c729204a09/  
server.js#L108

**Play with all this at**  
[https://nodegoat.herokuapp.com/tutorial/a8](https://nodegoat.herokuapp.com/tutorial/a8)

%% End Countermeasures for CSRF

%% Injection Countermeasures
%% End Injection Countermeasures

%% SQLi Countermeasures

**Improve performance by 20 to 30 percent**  
[https://www.ibm.com/developerworks/library/se-bindvariables/](https://www.ibm.com/developerworks/library/se-bindvariables/)

**OWASP SQLi Prevention Cheat Sheet**  
[https://www.owasp.org/index.php/SQL_Injection_Prevention_Cheat_Sheet](https://www.owasp.org/index.php/SQL_Injection_Prevention_Cheat_Sheet)

%% End SQLi Countermeasures
%% NoSQLi Countermeasures

**XML, JSON, LINQ, etc**  
[https://www.owasp.org/index.php/Testing_for_NoSQL_injection#Summary](https://www.owasp.org/index.php/Testing_for_NoSQL_injection#Summary)

**`security.javascriptEnabled`**  
https://docs.mongodb.com/manual/reference/configuration-options/#security.javascriptEna  
bled

**MongoDB attempts to address injection**  
https://docs.mongodb.com/manual/faq/fundamentals/#how-does-mongodb-address-sql-or-  
query-injection  
by using Binary JSON (BSON)  
[http://bsonspec.org/](http://bsonspec.org/)

**MongoDB docs say**  
[https://docs.mongodb.com/manual/faq/fundamentals/#javascript](https://docs.mongodb.com/manual/faq/fundamentals/#javascript)

%% End NoSQLi Countermeasures
%% Command Injection Countermeasures

**Untrusted data should never be inserted** to `eval`, `setTimeout`, `setInterval` or as the last argument to `Function`  
https://blog.binarymist.net/2012/12/19/javascript-coding-standards-and-guidelines/#JavaScr  
ipt-evalisEvil

**It is generally not good practise** to use the `Function` constructor anyway  
https://blog.binarymist.net/2013/07/06/javascript-object-creation-patterns/#object-creation-v  
ia-constructor

**Written about this on several occasions**  
[https://blog.binarymist.net/2011/08/17/function-declarations-vs-function-expressions/](https://blog.binarymist.net/2011/08/17/function-declarations-vs-function-expressions/)  
[https://blog.binarymist.net/2014/05/31/javascript-closures/#what-are-closures](https://blog.binarymist.net/2014/05/31/javascript-closures/#what-are-closures)

**Minimal countermeasure example**  
https://github.com/OWASP/NodeGoat/blob/b475010f2de3d601eda3ad2498d9e6c729204a09/ap  
p/routes/contributions.js#L30-L32

**`use strict`**  
[https://developer.mozilla.org/en/docs/Web/JavaScript/Reference/Strict_mode](https://developer.mozilla.org/en/docs/Web/JavaScript/Reference/Strict_mode)

**MDN provides details** of how it helps secure your JavaScirpt environment  
https://developer.mozilla.org/en/docs/Web/JavaScript/Reference/Strict_mode#Securing_Jav  
aScript

%% End Command Injection Countermeasures
%% XML Injection Countermeasures

**XML Schemas**  
http://www.ws-attacks.org/XML\_Injection#Attack\_mitigation\_.2F\_countermeasures

**XML External Entity (XXE) Prevention Cheat Sheet**  
https://www.owasp.org/index.php/XML\_External\_Entity\_(XXE)\_Prevention\_Cheat\_Sheet

%% End XML Injection Countermeasures
%% XSLT Injection Countermeasures

**All mitigations discussed**  
https://www.owasp.org/images/a/ae/OWASP_Switzerland_Meeting_2015-06-17_XSLT_SSR  
F_ENG.pdf

%% End XSLT Injection Countermeasures
%% XPath Injection Countermeasures

**OWASP XPath Injection Defences**  
[https://www.owasp.org/index.php/XPATH_Injection#XPath_Injection_Defenses](https://www.owasp.org/index.php/XPATH_Injection#XPath_Injection_Defenses)

%% End XPath Injection Countermeasures
%% XQuery Countermeasures
%% End XQuery Countermeasures
%% LDAP Injection Countermeasures

**For each semantic type of untrusted data**, for any characters that pass the white list validation, define filters, and sanitise all of the following validated characters  
[http://www.rlmueller.net/CharactersEscaped.htm](http://www.rlmueller.net/CharactersEscaped.htm)

%% End LDAP Injection Countermeasures
%% Captcha Countermeasures

**Hackers halfway across the world** _might know your password, but they don't know who your friends are_  
[https://m.facebook.com/story.php?story_fbid=191422450875446&id=121897834504447](https://m.facebook.com/story.php?story_fbid=191422450875446&id=121897834504447)

**helping to digitise text** for The New York Times and Google Books  
[https://en.wikipedia.org/wiki/ReCAPTCHA](https://en.wikipedia.org/wiki/ReCAPTCHA)

**Disqus tracks users activities** from hosting website to website whether you have an account, are are logged in or not.  
[http://perltricks.com/article/104/2014/7/29/Your-users-deserve-better-than-Disqus](http://perltricks.com/article/104/2014/7/29/Your-users-deserve-better-than-Disqus)

**Any information they collect** such as IP address, web browser details, installed add-ons, referring pages and exit links may be disclosed to any third party.  
[https://en.wikipedia.org/wiki/Disqus#Criticism_and_privacy_concerns](https://en.wikipedia.org/wiki/Disqus#Criticism_and_privacy_concerns)

**His (Matt Mullenweg) first attempt** was a JavaScript plugin which modified the comment form and hid fields, but within hours of launching it, spammers downloaded it, figured out how it worked, and bypassed it. This is a common pitfall for anti-spam plugins: once they get traction  
[https://en.wikipedia.org/wiki/Akismet](https://en.wikipedia.org/wiki/Akismet)


**Given the fact that many clients count on conversions to make money**, _not receiving 3.2% of those conversions could put a dent in sales.  Personally, I would rather sort through a few SPAM conversions instead of losing out on possible income._  
[https://moz.com/blog/captchas-affect-on-conversion-rates](https://moz.com/blog/captchas-affect-on-conversion-rates)

**Spam is not the user’s problem;** _it is the problem of the business that is providing the website. It is arrogant and lazy to try and push the problem onto a website’s visitors._  
[http://timkadlec.com/2011/01/death-to-captchas/](http://timkadlec.com/2011/01/death-to-captchas/)

**According to studies**, captchas just do not cut it  
[http://www.smashingmagazine.com/2011/03/in-search-of-the-perfect-captcha/](http://www.smashingmagazine.com/2011/03/in-search-of-the-perfect-captcha/)

**If you have some CSS that hides a form field** and especially if the CSS is not inline on the same page, they will usually fail at realising that the field is not supposed to be visible.  
[http://haacked.com/archive/2007/09/11/honeypot-captcha.aspx/](http://haacked.com/archive/2007/09/11/honeypot-captcha.aspx/)

**The Offensive Web Testing Framework (OWTF)** also has a [plugin](https://github.com/owtf/owtf/wiki/Listing-Plugins) for testing captchas. While you are at it. Check out the [OWTF](https://www.owasp.org/index.php/OWASP_OWTF#tab=Main). It's a very useful tool for penetration testers and developers testing their own work. Focussed on making the process of penetration testing efficient with time. The main documentation is [here](http://docs.owtf.org/en/latest/).

%% End Captcha Countermeasures



**The function used to protect stored credentials** should balance attacker and defender verification. The defender needs an acceptable response time for verification of users’ credentials during peak use. However, the time required to map `<credential> -> <protected form>` must remain beyond threats’ hardware (GPU, FPGA) and technique (dictionary-based, brute force, etc) capabilities:  
[https://www.owasp.org/index.php/Password_Storage_Cheat_Sheet#Impose_infeasible_verification_on_attacker](https://www.owasp.org/index.php/Password_Storage_Cheat_Sheet#Impose_infeasible_verification_on_attacker)

**You may read in many places** that having data-store passwords and other types of secrets in configuration files in clear text is an insecurity that must be addressed  
[https://www.owasp.org/index.php/Password_Plaintext_Storage](https://www.owasp.org/index.php/Password_Plaintext_Storage).

**There is a specific file loading order**  
[https://github.com/lorenwest/node-config/wiki/Configuration-Files](https://github.com/lorenwest/node-config/wiki/Configuration-Files)

**Custom environment variables**  
https://github.com/lorenwest/node-config/wiki/Environment-Variables#custom-environmen  
t-variables

**Use a SqlServer connection string** with `Trusted_Connection=yes`  
[https://www.owasp.org/index.php/Configuration#Secure_connection_strings](https://www.owasp.org/index.php/Configuration#Secure_connection_strings) 

**Metasploits hashdump**  
[https://www.rapid7.com/db/modules/post/windows/gather/hashdump](https://www.rapid7.com/db/modules/post/windows/gather/hashdump)

**Also discussed in my "0wn1ng The Web" presentation**  
[https://speakerdeck.com/binarymist/0wn1ng-the-web-at-www-dot-wdcnz-dot-com](https://speakerdeck.com/binarymist/0wn1ng-the-web-at-www-dot-wdcnz-dot-com)

**Encrypt sections** of a web, executable, machine-level, application-level or configuration files with Aspnet_regiis.exe:  
[SQL Authentication](https://msdn.microsoft.com/en-us/library/ff648340.aspx)  
[Windows Authentication](https://msdn.microsoft.com/en-us/library/ff647396.aspx)

**Mimikatz will force an export from the key container** to a `.pvk` file.  
Which can then be read using OpenSSL or tools from the `Mono.Security` assembly.  
[http://stackoverflow.com/questions/7332722/export-snk-from-non-exportable-key-container](http://stackoverflow.com/questions/7332722/export-snk-from-non-exportable-key-container)

**Credential Guard**  
[https://technet.microsoft.com/en-us/library/mt483740](https://technet.microsoft.com/en-us/library/mt483740) 

"**vSentry protects desktops without requiring patches or updates**_, defeating and automatically discarding all known and unknown malware, and eliminating the need for costly remediation._"   
[https://www.bromium.com/sites/default/files/Bromium-Datasheet-vSentry.pdf](https://www.bromium.com/sites/default/files/Bromium-Datasheet-vSentry.pdf)

**Every user task is isolated** into its own micro-VM  
http://security.stackexchange.com/questions/23674/how-will-microvirtualisation-change-the-security-field-if-at-all

"**vSentry empowers users** _to access whatever information they need from any network, application or website, without risk to the enterprise_"

"_Traditional security solutions rely on detection and often fail to block targeted attacks which use unknown “zero day” exploits. Bromium uses hardware enforced isolation to stop even “undetectable” attacks without disrupting the user._"

**Bromium**  
[http://www.bromium.com/sites/default/files/Bromium-Datasheet-vSentry.pdf](http://www.bromium.com/sites/default/files/Bromium-Datasheet-vSentry.pdf)

"**With Bromium micro-virtualization**_, we now have an answer: A desktop that is utterly secure and a joy to use_"

**Bromium**  
[http://www.ervik.as/virtualization-community/groups/display?categoryid=11](http://www.ervik.as/virtualization-community/groups/display?categoryid=11)

**Remind your customers** to **always use unique passwords** that are made up of alphanumeric, upper-case, lower-case and special characters  
[https://speakerdeck.com/binarymist/passwords-lol](https://speakerdeck.com/binarymist/passwords-lol) 

"**Using four AMD Radeon HD6990 graphics cards**, I am able to make about 15.5 billion guesses per second using the SHA-1 algorithm._"  
_Per Thorsheim_  
[http://securitynirvana.blogspot.co.nz/2012/06/final-word-on-linkedin-leak.html](http://securitynirvana.blogspot.co.nz/2012/06/final-word-on-linkedin-leak.html)

**scrypt**  
[http://www.tarsnap.com/scrypt.html](http://www.tarsnap.com/scrypt.html)

**bcrypt which uses the Eksblowfish cipher** which was designed specifically for bcrypt from the blowfish cipher, to be very slow to initiate thus boosting protection against dictionary attacks which were often run on custom Application-specific Integrated Circuits (ASICs) with low gate counts.  
http://security.stackexchange.com/questions/4781/do-any-security-experts-recommend-bcry  
pt-for-password-storage

**far greater memory required** for each hash, small and frequent pseudo-random memory accesses, making it harder to cache the data into faster memory.  
[http://openwall.info/wiki/john/GPU/bcrypt](http://openwall.info/wiki/john/GPU/bcrypt)

**bcrypt brute-forcing** is becoming more accessible due to easily obtainable cheap hardware.  
[http://www.extremetech.com/extreme/184828-intel-unveils-new-xeon-chip-with-integrated-fpga-touts-20x-performance-boost](http://www.extremetech.com/extreme/184828-intel-unveils-new-xeon-chip-with-integrated-fpga-touts-20x-performance-boost)  
[http://www.openwall.com/lists/announce/2013/12/03/1](http://www.openwall.com/lists/announce/2013/12/03/1)  
[http://www.openwall.com/presentations/Passwords13-Energy-Efficient-Cracking/](http://www.openwall.com/presentations/Passwords13-Energy-Efficient-Cracking/)

**Xeon Phi**  
[http://www.extremetech.com/extreme/133541-intels-64-core-champion-in-depth-on-xeon-phi](http://www.extremetech.com/extreme/133541-intels-64-core-champion-in-depth-on-xeon-phi)

**ZedBoard / Zynq 7020**  
[http://picozed.org/product/zedboard](http://picozed.org/product/zedboard)

**Haswell**  
http://www.theplatform.net/2015/06/02/intel-finishes-haswell-xeon-e5-rollout-launches-broa  
dwell-e3/

**Salsa20/8**  
[https://tools.ietf.org/html/rfc7914](https://tools.ietf.org/html/rfc7914)




**Resource Owner Password Credentials**  
[http://tools.ietf.org/html/rfc6749#section-1.3.3](http://tools.ietf.org/html/rfc6749#section-1.3.3)

**Resource Owner Password Credentials Grant**  
[http://tools.ietf.org/html/rfc6749#section-4.3](http://tools.ietf.org/html/rfc6749#section-4.3)

**Security Considerations**  
[http://tools.ietf.org/html/rfc6749#section-10.7](http://tools.ietf.org/html/rfc6749#section-10.7)

**Flows are detailed in the** OAuth 2.0  
[http://tools.ietf.org/html/rfc6749](http://tools.ietf.org/html/rfc6749)  
and  
OpenID Connect specifications  
[http://openid.net/specs/openid-connect-core-1_0.html](http://openid.net/specs/openid-connect-core-1_0.html)

**Reference for front-end, JWT for back-end** it is on the road map  
[https://github.com/IdentityServer/IdentityServer3/issues/1725](https://github.com/IdentityServer/IdentityServer3/issues/1725)

**MembershipReboot** Is a user identity management library with a similar name to the ASP.NET Membership Provider, inspired by it due to frustrations that Brock Allen (MembershipReboot creator) had from it  
[http://brockallen.com/2012/09/02/think-twice-about-using-membershipprovider-and-simplemembership/](http://brockallen.com/2012/09/02/think-twice-about-using-membershipprovider-and-simplemembership/) 

**Going down the path of** MembershipReboot  
[https://github.com/brockallen/BrockAllen.MembershipReboot](https://github.com/brockallen/BrockAllen.MembershipReboot)  
and IdentityServer3.MembershipReboot  
[https://github.com/IdentityServer/IdentityServer3.MembershipReboot](https://github.com/IdentityServer/IdentityServer3.MembershipReboot)

**Customise, out of the box**. All you need to do is add the properties you require to the already provided `CustomUser`  
https://github.com/IdentityServer/IdentityServer3.MembershipReboot/blob/master/source/  
WebHost/MR/CustomUser.cs

**Security focussed configuration**  
https://github.com/brockallen/BrockAllen.MembershipReboot/wiki/Security-Settings-Confi  
guration

**Password storage** is addressed  
[http://brockallen.com/2014/02/09/how-membershipreboot-stores-passwords-properly/](http://brockallen.com/2014/02/09/how-membershipreboot-stores-passwords-properly/)

**0 means to automatically calculate** the number based on the OWASP recommendations  
[https://www.owasp.org/index.php/Password_Storage_Cheat_Sheet](https://www.owasp.org/index.php/Password_Storage_Cheat_Sheet) for the current year

**The good, the bad and the ugly of ASP.NET Identity**  
[http://brockallen.com/2013/10/20/the-good-the-bad-and-the-ugly-of-asp-net-identity/#ugly](http://brockallen.com/2013/10/20/the-good-the-bad-and-the-ugly-of-asp-net-identity/#ugly)

**Community provided** OWIN OAuth middleware providers  
[https://github.com/RockstarLabs/OwinOAuthProviders](https://github.com/RockstarLabs/OwinOAuthProviders)

**MembershipReboot supports adding secret questions and answers** along with the ability to update user account details. Details on how this can be done is in the sample code  
[https://github.com/brockallen/BrockAllen.MembershipReboot/tree/master/samples](https://github.com/brockallen/BrockAllen.MembershipReboot/tree/master/samples)  
kindly provided by Brock Allen and documentation on their github wiki  
[https://github.com/brockallen/BrockAllen.MembershipReboot/wiki#features](https://github.com/brockallen/BrockAllen.MembershipReboot/wiki#features)

**Set the `Secure` attribute**  
[https://www.owasp.org/index.php/Session_Management_Cheat_Sheet#Secure_Attribute](https://www.owasp.org/index.php/Session_Management_Cheat_Sheet#Secure_Attribute)

**OWASP** Session Management Cheat Sheet  
[https://www.owasp.org/index.php/Session_Management_Cheat_Sheet#Cookies](https://www.owasp.org/index.php/Session_Management_Cheat_Sheet#Cookies)











**Dibbe Edwards discusses** some excellent initiatives on how they do it at IBM  
[https://soundcloud.com/owasp-podcast/dibbe-edwards-devops-and-open-source-at-ibm](https://soundcloud.com/owasp-podcast/dibbe-edwards-devops-and-open-source-at-ibm)

**There is an excellent paper by the SANS Institute** on Security Concerns in Using Open Source Software for Enterprise Requirements that is well worth a read. It confirms what the likes of IBM are doing in regards to their consumption of free and open source libraries  
http://www.sans.org/reading-room/whitepapers/awareness/security-concerns-open-source-  
software-enterprise-requirements-1305

**As a developer, you are responsible** for what you install and consume  
https://blog.liftsecurity.io/2015/01/27/a-malicious-module-on-npm#you-are-responsible-for-  
what-you-require-

**The official way** to install NodeJS. Do not do this.  
[https://github.com/nodesource/distributions](https://github.com/nodesource/distributions)

**Check to see if any package has hooks** that will run scripts  
https://blog.liftsecurity.io/2015/01/27/a-malicious-module-on-npm#inspect-the-source-befor  
e-you-npm-install-it

**Can define scripts to be run** on specific NPM hooks:  
[https://docs.npmjs.com/misc/scripts](https://docs.npmjs.com/misc/scripts)

**People often miss-type** what they want to install  
https://blog.liftsecurity.io/2015/01/27/a-malicious-module-on-npm#make-sure-you-re-instal  
ling-the-right-thing

**For NodeJS developers** Keep your eye on the nodesecurity advisories  
[https://nodesecurity.io/advisories](https://nodesecurity.io/advisories)

**There is an NPM package** that can help us with this called `precommit-hook` which installs the git pre-commit  
[https://www.npmjs.com/package/precommit-hook](https://www.npmjs.com/package/precommit-hook)

**To install RetireJS locally to your project** and run as a git precommit-hook  
[https://blog.andyet.com/2014/11/19/managing-code-changes](https://blog.andyet.com/2014/11/19/managing-code-changes)

**RequireSafe provides** "_intentful auditing as a stream of intel for bithound_"   
https://blog.liftsecurity.io/2015/02/10/introducing-requiresafe-peace-of-mind-third-party-no  
de-modules

**The Web Crypto API supported algorithms** for Chromium (as of version 46) and Mozilla (as of July 2016)  
[https://www.chromium.org/blink/webcrypto](https://www.chromium.org/blink/webcrypto)  
[https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API/Supported_algorithms](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API/Supported_algorithms)

%% Insufficient Attack Protection

**Insecure Direct Object References** was part of the OWASP Top 10 in 2013  
[https://www.owasp.org/index.php/Top_10_2013-A4-Insecure_Direct_Object_References](https://www.owasp.org/index.php/Top_10_2013-A4-Insecure_Direct_Object_References)  
which in 2017 was merged  
[https://www.owasp.org/index.php/Top_10_2017-Release_Notes](https://www.owasp.org/index.php/Top_10_2017-Release_Notes)  
into Insufficient Attack Protection  
[https://www.owasp.org/index.php/Top_10_2017-A7-Insufficient_Attack_Protection](https://www.owasp.org/index.php/Top_10_2017-A7-Insufficient_Attack_Protection)

%% End Insufficient Attack Protection

