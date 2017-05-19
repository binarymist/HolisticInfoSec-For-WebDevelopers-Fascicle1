# Holistic InfoSec For Web Developers - F1 - Release Notes

## 2017-05-19

### VPS

* Added links to Interview with Docker Security Team Lead Diogo Monica on Docker Security
* Fixed typo
* Fixed ordered list sequence

### Web Applications

Ready for technical review

* Updated the OWASP Top 10 over time diagram to reflect the new 2017 list
* Added additional threat tags
* Added Sensible Security Model sections for the following:
  * Cross-Site Request Forgery (CSRF)
  * Generic Injection
  * NoSQL Injection
  * Command Injection
  * XML Injection
  * XSLT Injection
  * XPath Injection
  * XQuery Injection
  * LDAP Injection
  * Insufficient Attack Protection
  * Active Automated Prevention
* Finished SQL Injection
* Finished Cracking
* Finished WAFs
* Removed Physical Access
* Remove Console Access
* Removed Network Access
* Removed Caching of Sensitive Data

### Additional Resources

* Interview with Docker Security Team Lead Diogo Monica on Docker Security
* Injections
  * NoSQL
  * Command
  * XPath
* CSRF
* Application Intrusion Detection and Response

### Attributions

Large number of attributions added

[Diff from release 2017-05-03](https://github.com/binarymist/HolisticInfoSec-For-WebDevelopers-Fascicle1/compare/ca8e3feed499db0851c5f4af428b61051f08d5c2...a3520fb6a2f74581bdcfc2d7528b7e011aad9fc9)

## 2017-05-03

### VPS

Ready for technical review

* Threat tags finished being added
* Statistics Graphing (collectd, graphite) finished
* SSM Risks that Solution Causes finished
* SSM Costs and Trade-offs finished

### Web Applications

* Statistics Graphing (statsd, graphite) finished

### Attributions

Large number of attributions added

[Diff from release 2017-04-16](https://github.com/binarymist/HolisticInfoSec-For-WebDevelopers-Fascicle1/compare/9e9af15c3ff79b7776a3f058553173f9c8bf888b...79abd6432d1a332114452ec660ec7f580de21e5d)

## 2017-04-16

Docker Security: 51 pages added

### VPS

#### Docker Risks and Countermeasures

* Docker registries and consumption of
  * Image provenance, identification, integrity
  * copy-on-write filesystem
* Doppelganger images
* Default user root
* Hardening Docker Host, Engine and Containers
  * tools, tips, 
* Namespaces
  1. `mnt`
  2. `PID`
  3. `net`
  4. `UTS`
  5. `IPC`
  6. `user`
* Control Groups (Cgroups)
* Linux Capabilities
* Linux Security Modules (LSM)
* Secure Computing Mode (SecComp)
* Read-only Containers
* runC and Docker architecture
* Application Security
* Diagrams added:
  1. Type-2 Hypervisor vs Containers
  2. Docker architecture
  3. Linux Security Module architecture

#### Other

* PowerShell exploitation mitigations

### Web Applications

* Sobering statistics, on how many defective libraries we are depending on

### Additional Resources

* Software Engineering Radio interview with Docker Security Lead Diogo Monica
* Linux namespaces and their use in Docker
* Dockerscan
* Increasing Attacker Cost using Immutable Infrastructure
* Diogo Monica on Mutual TLS
* Diogo Monica on Orchestrating Least Privilege
* Image signing, and why it is important
* Docker security scanning (content integrity)
* The Secure Developer podcast on Understanding Container Security
* Many more

[Diff from release 2017-01-23](https://github.com/binarymist/HolisticInfoSec-For-WebDevelopers-Fascicle1/compare/9c9cdc1e5151700b45510cb4e06675f6865b7b70...fc6248fce0c550ab006565e26692f54f3f1734ec)

## 2017-01-23

Updated links to hands on hack demos on [YouTube](https://www.youtube.com/playlist?list=PLfv6teOacMIuh3VheioAXXe70IwwQySIp).

### VPS

1. Added Windows exploitation using PowerShell with Psmsf generated payload and c virus, that pulls down payload that overwrites PowerShell with reverse shell. Includes:
    * Detailed hands-on-hack
    * Tutorial video
2. Added Windows exploitation using PowerShell leveraging previous Psmsf generated payload and office document virus C/- Nishang, that pulls down payload that overwrites PowerShell with reverse shell. Includes:
    * Detailed hands-on-hack
3. Added atomic persistent exploit C/- PowerSploit, leveraging previous Psmsf generated payload and office document virus C/- Nishang, that pulls down payload that overwrites PowerShell with reverse shell. Includes:
    * Sequence diagram
    * Detailed hands-on-hack
    * Tutorial video

* Updated PsExec section
* Added Pass The Hash (PTH) section, including details around Metasploit modules and potential countermeasures:
  1. `current_user_psexec`
  2. `psexec_command`
  3. `psexec_loggedin_users`
  4. `psexec_psh`
  5. `psexec_ntdsgrab`
  6. `wmi`
* Finished FTP risks, countermeasures, alternatives and assumptions
* Added telnet risks
* Added to NIS & NFS
* Added Exim risks
* Added risks to portmap & rpcbind such as reflected & amplified DoS
* Added Using Components with Known Vulnerabilities to VPS chapter
* Added Lack of Backup risk to VPS chapter
* Added countermeasures for port mapper DoS
* Removal of boot options, thus reducing root-kit installation opportunities
* Updated Password Strategies, which KDFs are best based on the types of hardware your attackers are likely to be using

### Web Applications

* Updated details around credential hashes and how attackers obtain them.
* Added details around whitelisting npm packages with npm Enterprise
* Updated PBKDF2 details

### Additional Resources

* Bypassing PowerShell Execution Policy
* PowerSploit and Nishang resources
* Many more

[Diff from release 2016-11-04](https://github.com/binarymist/HolisticInfoSec-For-WebDevelopers-Fascicle1/compare/83f96fe53cc67cd784d68d6e4320a7d37668fd57...a623c10babd1fa6d8c60288c8076b42382d145a5)

## 2016-11-04

Updated links to hands on hack demos on [YouTube](https://www.youtube.com/playlist?list=PLfv6teOacMIuh3VheioAXXe70IwwQySIp).

### VPS

* Finished Identify Risks -> Unnecessary and Vulnerable Services -> Overly Permissive File Permissions, Ownership and Lack of Segmentation. Discussed tools useful for enumerating local Privilege Escalation and walked through how to use them
  * Detailed how Privileges are usually escalated and how
  * Created a hands-on hack to demonstrate how an attacker may perform reconnaissance, initial vulnerability scanning, then breaking into the machine, further reconnaissance, PrivEsc vulnerability searching and discovery, followed with finding a suitable exploit and executing it, through to full ownership via reverse root shell
  * Created video of attack and compromise to go with hands-on directions
* A little more work on privilege escalation Countermeasures.
* Added more details around coercing your server to produce SSH key fingerprints in a consumable manner to help mitigate MItM attacks.
* Added a little more to Partitioning on OS Installation & Lock Down the Mounting of Partitions

### Web Applications

* Update to Countermeasures -> Lack of Input Validation, Filtering and Sanitisation. Around how WebComponents can help constraining input types in terms of validation and filtering
* Update to Countermeasures -> Management of Application Secrets -> Data-store Compromise -> Which KDF to use. Discussed different types of processors for using to brute-force passwords. Discussed the best of breed KDFs and how they were designed to mitigate the specified advances in the hardware technology (CPU, GPU, FPGAs, etc)

### Additional Resources

* Added local Privilege Escalation Cheatsheet to Additional Resources
* Podcast on WebComponents
* Various links to hashing functions and KDFs
* Bcrypt brute-forcing and feasibility
* Hardware that suits brute-forcing passwords: Xeon Phi and others

## 2016-10-07

Large number of image updates due to finding that many were not up to scratch when Fascicle 0 went to print.
Swapped text images for real images.

Many large additions to the VPS chapter and fewer to the Network chapter, such as:

* The pitfalls of logging within networks and some ideas and implementations on how to overcome
* Disabling, removing and hardening the services of a VPS
* Granular OS partitioning and locking down the mounting of partitions
* Caching apt packages for all VPS
* Reviewing VPS password strategies and making the most suitable modifications to achieve enough security for you
* Disabling root logins on as many of the consoles as possible
* SSH, Symmetric and Asymmetric crypto-systems and their place in SSH
* The ciphers used in SSH, pros, cons, some history
* Hashing and its application in SSH
* How the SSH connection procedure works
* Hardening SSH
* Configuring which hosts may access your server
* SSH Key-pair authentication
* Techniques for tunnelling SSH
* Understanding enough about NFS to produce exports that will suite your environmental security concerns
* Some quick commands to provide visibility as to who is doing what and when on your servers
* VPS logging and alerting: We look at a large number of options available and the merits of them
* Managing your logs effectively, so that they will be around when you need them and not tampered with. We work through transferring them off-site in real-time. We address reliability, resilience, integrity, connectivity of the proposed solutions. Verifying that the logs being transferred are in-fact encrypted
* Proactive server monitoring, discuss goals, and the evaluation criteria for the offerings that were evaluated
* Implementation of proactive server monitoring, what works well, what does not
* Keeping your (NodeJS) applications not just running, but healthy
* We discuss the best of bread HIDS/HIPS, then go on to implement the chosen solution
* Made a start with Docker insecurities and mitigation’s
* Quick discussion around host firewalls
* Preparing DMZ and your VPS for the DMZ
* Additional Web Server preparation
* Deployment options
* Post DMZ deployment considerations
