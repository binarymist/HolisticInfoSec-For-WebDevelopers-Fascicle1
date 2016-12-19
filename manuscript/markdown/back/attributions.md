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
https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/post/windows/wmic.rb#L48

**Then create a ReverseListenerComm** to tunnel traffic through that session  
[https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/local/wmi.rb#L61](https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/local/wmi.rb#L61)




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

**Docker has many security enhancing capabilities**, but none are on by default  
http://resources.infosecinstitute.com/docker-and-enterprise-security-establishing-best-  
practices/

**These processes have indirect access to most of the Linux Kernel**  
[https://theinvisiblethings.blogspot.co.nz/2012/09/how-is-qubes-os-different-from.html](https://theinvisiblethings.blogspot.co.nz/2012/09/how-is-qubes-os-different-from.html)

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

**Cisecurity has an excellent resource** for hardening docker images  
[https://benchmarks.cisecurity.org/downloads/show-single/?file=docker12.100](https://benchmarks.cisecurity.org/downloads/show-single/?file=docker12.100) 


**An example of the NodeGoat** image  
[https://github.com/owasp/nodegoat](https://github.com/owasp/nodegoat)

**There are plenty of tools** available to help  
[http://www.debianhelp.co.uk/backuptools.htm](http://www.debianhelp.co.uk/backuptools.htm) 

**Snort can help with the Prevention** also  
https://www.ibm.com/developerworks/community/blogs/58e72888-6340-46ac-b488-d31aa4058e9c/entry/august_8_2012_12_01_pm6?lang=en

**Work through using the likes of**  
https://www.debian.org/doc/manuals/securing-debian-howto/ch-automatic-harden.en.htm  
l#s6.1  
harden  
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














## [Network](#network)


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








**If the victims SMTP server does not perform reverse lookups on the hostname**, an email `from` and `reply-to` fields can be successfully spoofed.  
[http://www.social-engineer.org/framework/se-tools/computer-based/social-engineer-toolkit-set/](http://www.social-engineer.org/framework/se-tools/computer-based/social-engineer-toolkit-set/)

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

**The New Zealand Intelligence Service** recently told Prime Minister John Key that this was one of the 6 top threats facing New Zealand. "_Cyber attack or loss of information and data, which poses financial and reputational risks._"  
http://www.stuff.co.nz/national/politics/73704551/homegrown-threats-more-serious-says-spy-boss-rebecca-kitteridge

**Before the breach**, the company boasted about airtight data security but ironically, still proudly displays a graphic with the phrase “trusted security award” on its homepage.  
http://www.darkreading.com/operations/what-ashley-madison-can-teach-the-rest-of-  
us-about-data-security-/a/d-id/1322129

**Other notable data-store compromises were LinkedIn** with 6.5 million user accounts compromised and 95% of the users passwords cracked in days. Why so fast? Because they used simple hashing, specifically SHA-1. Details provided [here](http://securitynirvana.blogspot.co.nz/2012/06/final-word-on-linkedin-leak.html) on the findings.

**EBay with 145 million active buyers** had a small number of employee log-in credentials compromised allowing unauthorised access to eBay's corporate network.  
http://www.darkreading.com/attacks-breaches/ebay-database-hacked-with-stolen-employee-credentials-/d/d-id/1269093

**The OWASP Top 10 risks** No. 2 Broken Authentication and Session Management  
[https://www.owasp.org/index.php/Top_10_2013-A2-Broken_Authentication_and_Session_Management](https://www.owasp.org/index.php/Top_10_2013-A2-Broken_Authentication_and_Session_Management)

**Warning against using CBC**  
[https://github.com/bitwiseshiftleft/sjcl/wiki/Directly-Using-Ciphers](https://github.com/bitwiseshiftleft/sjcl/wiki/Directly-Using-Ciphers)

**Exemptions have been granted so that OCB** can be used in software licensed under the GNU General Public License  
[https://en.wikipedia.org/wiki/OCB_mode](https://en.wikipedia.org/wiki/OCB_mode)

**Background on OCB** from the creator  
[http://web.cs.ucdavis.edu/~rogaway/ocb/ocb-back.htm](http://web.cs.ucdavis.edu/~rogaway/ocb/ocb-back.htm)

**the winston-syslog-posix package** was inspired by blargh  
[https://www.npmjs.com/package/winston-syslog-posix](https://www.npmjs.com/package/winston-syslog-posix)  
[http://tmont.com/blargh/2013/12/writing-to-the-syslog-with-winston](http://tmont.com/blargh/2013/12/writing-to-the-syslog-with-winston)

**There were also some other options** for those using Papertrail as their off-site syslog and aggregation PaaS:  
[http://help.papertrailapp.com/kb/configuration/configuring-centralized-logging-from-nodejs-apps/](http://help.papertrailapp.com/kb/configuration/configuring-centralized-logging-from-nodejs-apps/)

**Monit Has excellent short documentation**  
[https://mmonit.com/monit/documentation/monit.html](https://mmonit.com/monit/documentation/monit.html)

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

**The function used to protect stored credentials** should balance attacker and defender verification. The defender needs an acceptable response time for verification of users’ credentials during peak use. However, the time required to map `<credential> -> <protected form>` must remain beyond threats’ hardware (GPU, FPGA) and technique (dictionary-based, brute force, etc) capabilities:  
[https://www.owasp.org/index.php/Password_Storage_Cheat_Sheet#Impose_infeasible_verification_on_attacker](https://www.owasp.org/index.php/Password_Storage_Cheat_Sheet#Impose_infeasible_verification_on_attacker)

**You may read in many places** that having data-store passwords and other types of secrets in configuration files in clear text is an insecurity that must be addressed  
[https://www.owasp.org/index.php/Password_Plaintext_Storage](https://www.owasp.org/index.php/Password_Plaintext_Storage).

**There is a specific file loading order**  
[https://github.com/lorenwest/node-config/wiki/Configuration-Files](https://github.com/lorenwest/node-config/wiki/Configuration-Files)

**custom environment variables**  
[https://github.com/lorenwest/node-config/wiki/Environment-Variables#custom-environment-variables](https://github.com/lorenwest/node-config/wiki/Environment-Variables#custom-environment-variables)

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
[http://security.stackexchange.com/questions/4781/do-any-security-experts-recommend-bcrypt-for-password-storage](http://security.stackexchange.com/questions/4781/do-any-security-experts-recommend-bcrypt-for-password-storage)

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
[http://www.theplatform.net/2015/06/02/intel-finishes-haswell-xeon-e5-rollout-launches-broadwell-e3/](http://www.theplatform.net/2015/06/02/intel-finishes-haswell-xeon-e5-rollout-launches-broadwell-e3/)

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
[https://blog.liftsecurity.io/2015/01/27/a-malicious-module-on-npm#inspect-the-source-before-you-npm-install-it](https://blog.liftsecurity.io/2015/01/27/a-malicious-module-on-npm#inspect-the-source-before-you-npm-install-it)

**Can define scripts to be run** on specific NPM hooks:  
[https://docs.npmjs.com/misc/scripts](https://docs.npmjs.com/misc/scripts)

**People often miss-type** what they want to install  
https://blog.liftsecurity.io/2015/01/27/a-malicious-module-on-npm#make-sure-you-re-installing-the-right-thing

**For NodeJS developers** Keep your eye on the nodesecurity advisories  
[https://nodesecurity.io/advisories](https://nodesecurity.io/advisories)

**There is an NPM package** that can help us with this called `precommit-hook` which installs the git pre-commit  
[https://www.npmjs.com/package/precommit-hook](https://www.npmjs.com/package/precommit-hook)

**To install RetireJS locally to your project** and run as a git precommit-hook  
[https://blog.andyet.com/2014/11/19/managing-code-changes](https://blog.andyet.com/2014/11/19/managing-code-changes)

**RequireSafe provides** "_intentful auditing as a stream of intel for bithound_"   
https://blog.liftsecurity.io/2015/02/10/introducing-requiresafe-peace-of-mind-third-party-node-modules

**The Web Crypto API supported algorithms** for Chromium (as of version 46) and Mozilla (as of July 2016)  
[https://www.chromium.org/blink/webcrypto](https://www.chromium.org/blink/webcrypto)  
[https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API/Supported_algorithms](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API/Supported_algorithms)

