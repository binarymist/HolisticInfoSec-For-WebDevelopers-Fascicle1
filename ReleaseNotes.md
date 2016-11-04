# Holistic InfoSec For Web Developers - F1

## 2016-11-04

Updated links to hands on hack demos on [YouTube](https://www.youtube.com/playlist?list=PLfv6teOacMIuh3VheioAXXe70IwwQySIp).

### VPS

* Finished Identify Risks -> Unnecessary and Vulnerable Services -> Overly Permissive File Permissions, Ownership and Lack of Segmentation. Discussed tools useful for enumerating local Privilege Escalation and walked through how to use them.
  * Detailed how Privileges are usually escalated and how.
  * Created a hands-on hack to demonstrate how an attacker may perform reconnaissance, initial vulnerability scanning, then breaking into the machine, further reconnaissance, PrivEsc vulnerability searching and discovery, followed with finding a suitable exploit and executing it, through to full ownership via reverse root shell.
  * Created video of attack and compromise to go with hands-on directions
* A little more work on privilege escalation Countermeasures.
* Added more details around coercing your server to produce SSH key fingerprints in a consumable manner to help mitigate MItM attacks.
* Added a little more to Partitioning on OS Installation & Lock Down the Mounting of Partitions

### Web Applications

* Update to Countermeasures -> Lack of Input Validation, Filtering and Sanitisation. Around how WebComponents can help constraining input types in terms of validation and filtering
* Update to Countermeasures -> Management of Application Secrets -> Data-store Compromise -> Which KDF to use. Discussed different types of processors for using to brute-force passwords. Discussed the best of breed KDFs and how they were designed to mitigate the specified advances in the hardware technology (CPU, GPU, FPGAs, etc).

### Additional Resources

* Added local Privilege Escalation Cheatsheet to Additional Resources
* Podcast on WebComponents
* Various links to hashing functions and KDFs
* Bcrypt brute-forcing and feasibility
* Hardware that suites brute-forcing passwords: Xeon Phi and others.

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
* Managing your logs effectively, so that they will be around when you need them and not tampered with. We work through transferring them off-site in real-time. We address reliability, resilience, integrity, connectivity of the proposed solutions. Verifying that the logs being transferred are in-fact encrypted.
* Proactive server monitoring, discuss goals, and the evaluation criteria for the offerings that were evaluated
* Implementation of proactive server monitoring, what works well, what does not
* Keeping your (NodeJS) applications not just running, but healthy
* We discuss the best of bread HIDS/HIPS, then go on to implement the chosen solution
* Made a start with Docker insecurities and mitigation’s.
* Quick discussion around host firewalls
* Preparing DMZ and your VPS for the DMZ
* Additional Web Server preparation
* Deployment options
* Post DMZ deployment considerations
