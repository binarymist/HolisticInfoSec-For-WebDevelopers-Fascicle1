# 9. Cloud {#cloud}

![10,000' view of Cloud and In-house Cloud Security](images/10000Cloud.png)

If you skipped the [VPS](#vps) chapter, just be aware that it has a lot of similarities due to the fact that in many cases your VPS may be on someone else's hardware and under their control, just as many Cloud Service Providers leverage AWS resources, which ultimately still runs on real hardware. The Cloud is an abstraction (a lie).

## 1. SSM Asset Identification

Take the results from the higher level Asset Identification in the 30,000' View chapter of [Fascicle 0](https://leanpub.com/holistic-infosec-for-web-developers). Remove any that are not applicable. Add any newly discovered.


### Productivity

Using IaaS and even more so PaaS can provide great productivity gains, but everything comes at a cost. You don't get productivity gains for free. You will be sacrificing something and usually that something is at least security. You no longer have control of your data.

Using cloud services can be a good thing especially for smaller businesses and start ups, but before the decision is made as to whether to use an external cloud provider or whether to use or create your own, there are some very important considerations to be made. We will discuss these in the Identify Risks and Countermeasures subsections.

### Competitive Advantage

If you are a start up, just be aware that the speed you have initially with a PaaS may not continue as your product moves from Proof of Concept to something that customers start to use if you decide to be more careful about customers and your own IP by bringing it in-house or entrusting it to a provider that takes security seriously rather than just saying they do. We will be investigating these options through the Identify Risks subsection.

### Control

Control of our environments

We are blindly trusting huge amounts of IP to Cloud Service Providers (CSPs). In fact, I have worked for many customers that insist on putting everything in The Cloud without much thought. Some have even said that they are not concerned with security. The problem is, they do not understand what is at risk. They may wonder why their competitor beats them to market as their progress and plans are intercepted. The best book I have read to date that reveals the problem with this blind yielding of everything is Bruce Schneier Data and Goliath. This is an eye opening canon of what we are doing and what its results are going to be.

When ever you see that word "trust", you are yielding control to the party you are trusting. When you trust an entity with your assets, you are giving them control. Are your assets their primary concern, or is it maximising their profits by using you and/or your data as their asset?

If you decide to use an external cloud provider, you need to be aware that what ever goes into The Cloud is almost completely out of your control, you may not be able to remove it once it is there, as you may not have visibility into whether or not the existing data is really removed from The Cloud.

### Data

If you deal with sensitive customer data, then you have an ethical and legal responsibility for it. If you are putting sensitive data in The Cloud then you could very well be being irresponsible with your responsibility. You may not even retain legal ownership of it.

We will keep these assets in mind as we work through the rest of this chapter.

## 2. SSM Identify Risks {#cloud-identify-risks}

Some of the thinking around the process we went through at the top level in the 30,000' View chapter of [Fascicle 0](https://leanpub.com/holistic-infosec-for-web-developers) may be worth revisiting.

### Shared Responsibility Model {#cloud-identify-risks-shared-responsibility-model}

#### CSP Responsibility

The CSP takes care of the infrastructure, not the customer specific configuration of it, and Due to the shear scale of what they are building, are able to build in good security controls, in contrast to the average system administrator, which just does not have the resources or ability to focus on security to the same degree.

Due to the share scale, the average CSP has a concentrated group of good security professionals vs a business who's core business is often not closely related to security. So CSPs do provide good security mechanisms, but the customer has to know and care enough to use them.

CSPs creating the infrastructural architecture, building the components, frameworks, hardware, platform software in most cases are taking security seriously and doing a reasonable job.

#### CSP Customer Responsibility {#cloud-identify-risks-shared-responsibility-model-csp-customer-responsibility}

CSP customers are expected to take care of their own security in terms of:

1. Their people working with the technology
2. [Application security](#web-applications), ultimately leading back to shortcomings in people: Lack of skills, experience, engagement, etc.
3. Configuring the infrastructure and/or platform components: Again leading back to people defects

but all to often the customers responsibility is neglected, which renders The Cloud no better for the customer in terms of security.

> The primary problem with The Cloud is: Customers have the misconception that someone else is taking care of all their security. That is not how the shared responsibility model works though. Yes the CSP is probably taking care of the infrastructure security, but other forms of security such as I just listed above, are even more important than before the shift to The Cloud, this is because these items are now the lowest hanging fruit for the attacker.

The following are a set of questions (verbatim) I have been asked recently, and that I hear similar versions of frequently:

* _As a software engineer, do I really care about physical network security and network logging?_
* _Surely "as a software engineer", I can just use TLS and that is the end of it?_
* _Well if the machine is compromised, then we give up on security, we aren't responsible for the network_
* _What is the difference between application security and network security? Aren't they just two aspects of the same thing?_
* _If I have implemented TLS for communication, have I fixed all of the network security problems?_

### CSP Evaluation {#cloud-identify-risks-csp-evaluation}

CSPs are constantly changing their terms and conditions, and many components and aspects of what they offer. I've compiled a set of must-answer questions to quiz your CSP with as part of your threat modelling before (or even after) you sign their service agreement.  
Most of these questions were already part of my [Cloud vs In-house talk](http://blog.binarymist.net/presentations-publications/#does-your-cloud-solution-look-like-a-mushroom) at the Saturn Architects conference. I recommend using these as a basis for identifying risks that may be important for you to consider. Then you should be well armed to come up with countermeasures and think of additional risks.

1. Do you keep a signed audit log on which users performed which actions and when, via UIs and APIs?  
   
   Both authorised and unauthorised Users are more careful about the actions they take or do not take when they know that their actions are recorded and have the potential to be watched  
   
2. There is this thing called the shared responsibility model I have heard about between CSPs and their customers. Please explain what your role and my role is in the protection of my and my customers data?  
   
   You will almost certainly not have complete control over the data you entrust to your CSP, but they will also not assume responsibility over the data you entrust to them, or how it is accessed. One example of this might be, how do you preserve secrecy on data at rest? For example, are you using the most [suitable KDF](#web-applications-countermeasures-data-store-compromise) and adjusting the number of iterations applied each year (as discussed in the [MembershipReboot](#web-applications-countermeasures-lack-of-authentication-authorisation-session-management-technology-and-design-decisions-membershipreboot) subsection of the Web Applications chapter) to the secrets stored in your data stores? The data you hand over to your CSP is no more secure than we discuss in the Management of Application Secrets subsections of the Web Applications chapter and in many cases has the potential to be less secure for the following reasons at least:  
   
   * A false assumption often encountered that somehow the data you provide is safer by default on your CSPs network
   * Your CSP can be forced by governing authorities to give up the data you entrust to them, as we discuss in the [Giving up Secrets](#cloud-identify-risks-cloud-service-provider-vs-in-house-giving-up-secrets) subsection  
   
3. Do you encrypt all communications between servers within your data centres and also your service providers?  
   
   How is your data encrypted in transit (as discussed in the Management of Application Secrets subsections of the Web Applications chapter? In reality, you have no idea what paths it will take once in your CSPs possession, and could very well be intercepted without your knowledge.  
   
   * You have little to no control over the network path that the data you provide will travel on
   * There are more parties involved in your CSPs infrastructure than on your own network  
   
4. Do you provide access to logs, if so what sort of access to what sort of logs?  
   
   Hopefully you will have easy access to any and all logs, just like you would if it was your own network. That includes hosts, routing, firewall, and any other service logs  
   
5. What is your process around terminating my contract with you and/or moving to another CSP?  
   
   No CSP is going to last forever, termination or migration is inevitable, it is just a matter of when  
   
6. Where abouts do your servers, processes and data reside physically?  
   
   As we discuss a little later in the Cloud Services Provider vs In-house subsection of Countermeasures, your data is governed by different people and jurisdictions depending on where it physically resides. CSPs have data centres in different countries and jurisdictions, each having different laws around data security


7. Who can view the data I store in the cloud?  
   
   Who has access to view this data? What checks and controls are in place to make sure that this data can not be exfiltrated?  
   
8. What is your Service Level Agreement (SLA) for uptime?  
   
   Make sure you are aware of what the uptime promises mean in terms of real time. Some CSPs will allow 99.95% uptime if you are running on a single availability zone, but closer to 100% if you run on multiple availability zones. Some CSPs do not have a SLA at all.  
   
   CSPs will often provide credits for the downtime, but these credits in many cases may not cover the losses you encounter during hot times  
   
9. Are you ISO/IEC 27001:2013 Certified? If so, what is within its scope?  
   
   If the CSP can answer this with a "everything" and prove it, they have done a lot of work to make this possible, this shows a level of commitment to something security related. Just be aware, as with any certification, it is just that, it does not prove a lot  
   
10. Do you allow your customers to carry out regular penetration testing of production and/or test environments, also allowing the network to be in-scope?  
    
    CSPs that allow penetration testing of their environments demonstrate that they embrace transparency and openness, if their networks stand up to penetration tests, then they obviously take security seriously also. Ideally this is what you are looking for. CSPs that do not permit penetration testing of their environments, are usually trying to hide the fact that either they know they have major insecurities, skill shortages in terms of security professionals, or are unaware of where their security stature lies, and not willing to have their faults demonstrated  
   
11. Do you have bug bounty programmes running, if so, what do they look like?  
    
    This is another example if the programme is run well, that the CSP is open, transparent about their security faults and willing to mitigate them as soon as possible

### [Cloud Service Provider vs In-house](https://speakerdeck.com/binarymist/does-your-cloud-solution-look-like-a-mushroom) {#cloud-identify-risks-cloud-service-provider-vs-in-house}

A question that I hear frequently is: "What is more secure, building and maintaining your own cloud, or trusting a CSP to take care of security for you?". That is a defective question, as discussed in the [Shared Responsibility Model ](#cloud-identify-risks-shared-responsibility-model) subsections. There are [some aspects](#cloud-identify-risks-shared-responsibility-model-csp-customer-responsibility) of security that the CSP has no knowledge of, and only you as the CSP customer can work security into those areas.

Going with a CSP means you are depending on their security professionals to design, build and maintain the infrastructure, frameworks, hardware and platforms. Usually the large CSPs will do a decent job of this. If you go with designing, building, and maintaining your own In-house cloud, then you will also be leveraging the skills of those that have created the cloud components you decide to use, but you will be responsible for the following along with many aspects of how these components fit together and interact with each other:

* General infrastructure
* Hardware
* Hosting
* Continuously hardening components and infrastructure
* Patching
* Network firewall routes and rules
* Network component logging
* NIDS
* Regular penetration testing
* Many other aspects covered in the VPS and Network chapters.

So in general, your engineers are going to have to be as good or better than those of the given CSP that you are comparing with in order to achieve similar levels of security at the infrastructure level.

Trust is an issue with The Cloud, you do not have control of your data or the people that create and administer the cloud environment you decide to use.

#### Skills

The smaller CSPs in many cases suffer from the same resourcing issues that many business's do in regards to having solid security skills and engagement of their workers to apply security in-house. In general, in order to benefit from the Shared Responsibility Model of the CSP, it pays to go with the larger CSPs.

#### EULA

Most CSPs will have End User License Agreements (EULA) that have the right to change at any time, do you actually read when you sign up for a cloud service?

#### Giving up Secrets {#cloud-identify-risks-cloud-service-provider-vs-in-house-giving-up-secrets}

In many cases, hosting providers can be, and in many cases are [forced](http://www.stuff.co.nz/business/industries/67546433/Spies-request-data-from-Trade-Me) by governing authorities to [give up](https://www.stuff.co.nz/business/95116991/trade-me-fields-thousands-of-requests-for-member-information) your and your customers secrets. This is a really bad place to be in and it is very common place now, you may not even know it has happened.  
The NZ Herald [covered a story](http://www.nzherald.co.nz/nz/news/article.cfm?c_id=1&objectid=11481516) in which Senior lawyers and the Privacy Commissioner have told the Herald of concerns about the practise which sees companies coerced into giving up information to the police. Instead of seeking legal order, police have asked companies to hand over information to assist with the "maintenance of the law", threatened them with prosecution if they tell the person about whom they are interested and accept data with no record keeping to show how often requests are made. The request from police carries no legal force at all yet is regularly complied with.

#### Location of Data

As touched on in the CSP Evaluation questions, in many cases CSPs are outsourcing their outsourced services to several providers deep. They do not even have visibility themselves. Often the data is hosted in other jurisdictions. Control is lost. 

#### Vendor lock-in

This does not just apply to The Cloud vs In-house, it also applies to open technologies in The Cloud vs closed/proprietary offerings.

There is a certain reliance on vendor guarantees, these are not usually an issue though, the issue is usually us not understanding fully what our part to play in the shared responsibility model is.

What happens when you need to move from your current CSP? How much do you have invested in proprietary services such as [serverless](#cloud-identify-risks-serverless) offerings? What would it cost your organisation to port to another CSPs environment? Are you getting so much benefit that it just does not matter? If you are thinking like this, then you could very well be missing many of the steps that you should be doing as your part of the shared responsibility model. We discuss these throughout this chapter. Serverless technologies really look great until you [measure](#cloud-identify-risks-serverless) the costs of [securing everything](#cloud-countermeasures-serverless). Weigh up the costs and benefits. 

#### Possible Single Points of Failure

There are plenty of single points of failure in The Cloud

* Machine instance dies
* Docker container dies
* Availability Zone goes down
* Region goes down
* Multiple Regions go down
* Account Takeover occurs

### Review Other Chapters {#cloud-identify-risks-review-other-chapters}

There is a lot in common with the topic of cloud security in the other chapters of this fascicle and Fascicle 0, that if I had not already provided coverage, I would be doing so now.

Now would be a good time to orient / reorient yourself with the related topics / concepts from the other chapters. From here on in, I will be assuming you can apply the knowledge from the other chapters to the topic of cloud security without me having to revisit large sections of it, specifically:

[Fascicle 0](https://leanpub.com/holistic-infosec-for-web-developers/)

People chapter

* Ignorance
* Morale, Productivity and Engagement Killers
* Weak Password Strategies 

[VPS](#vps) chapter

* Forfeit Control thus Security
* Weak Password Strategies
* Root Logins
* SSH
* Lack of Visibility
* Docker
* Using Components with Known Vulnerabilities
* Lack of Backup

[Network](#network) chapter

* Fortress Mentality
* Lack of Visibility
* Data Exfiltration, Infiltration

[Web Applications](#web-applications) chapter

* Most / all of it

### People

You might ask what people have to do with cloud security? A large amount of my experience working as a consulting Architect, Engineer, Security Pro for many organisations and their teams has shown me, that in the majority of security incidents, reviews, tests and redesigns, the root cause stems back to people defects, as recognised by the number one issue of the [CSP Customer Responsibility](#cloud-identify-risks-shared-responsibility-model-csp-customer-responsibility) of the Shared Responsibility Model. As people, we are our own worst enemies. We can be the weakest and also the strongest links in the security chain. The responsibility falls squarely in our own laps.

You will notice that most of the defects addressed in this chapter come down to people:

* Missing a step in a sequence (often performed manually rather than automatically)
* Lacking the required knowledge
* Lacking the required desire / engagement

### Application Security

_Todo_ Add in SER podcast

With the shift to The Cloud, AppSec has become more important than it used to be, recognised and discussed:

* Previously in this chapter by the number two issue of the [CSP Customer Responsibility](#cloud-identify-risks-shared-responsibility-model-csp-customer-responsibility) of the Shared Responsibility Model
* In the [Application Security](#vps-countermeasures-docker-application-security) subsection of Docker in the VPS chapter
* Entirely in the next chapter (Web Applications)

The reason being, that in general, as discussed in the [Shared Responsibility Model](#cloud-identify-risks-shared-responsibility-model), the dedicated security resources, focus, awareness, engagement of our major CSPs are usually greater than most organisations have access to. This pushes the target areas for the attackers further up the tree. People followed by AppSec are now usually the lowest hanging fruit for the attackers.

### Network Security {#cloud-identify-risks-network-security}

The network between the components you decide to use in The Cloud will almost certainly no longer be administered by your network administrator(s), but rather by you as a Software Engineer. That is right, networks are now [expressed as code](#cloud-identify-risks-infrastructure-and-configuration-management), and because coding is part of your responsibility as a Software Engineer, the network will more than likely be left to you to design and code, so you better have a good understanding of [Network Security](#network).

### Violations of [Least Privilege](#web-applications-countermeasures-management-of-application-secrets-least-privilege) {#cloud-identify-risks-violations-of-least-privilege}

The principle of Least Privilege is an essential aspect of defence in depth, stopping an attacker from progressing.

The attack and demise of [Code Spaces](https://cloudacademy.com/blog/how-codespaces-was-killed-by-security-issues-on-aws-the-best-practices-to-avoid-it/), is a good example of what happens when least privilege is not kept on top of. An unauthorised attacker gained access to the Code Spaces AWS console and deleted everything attached to their account. Code Spaces was no more, they could not recover.

In most organisations I work for as an architect or engineer, I see many cases of violating the principle of least privilege. We discuss this principle in many places through this entire book series. It is a concept that needs to become part of your instincts. The principle of least privilege means that no actor should be given more privileges than is necessary to do their job.

Here are some examples of violating least privilege:

In [Fascicle 0](https://leanpub.com/holistic-infosec-for-web-developers/):

* Physical chapter: If someone has access to a facility that they do not need access to in order to do their job, a cleaner for example having access to a server room, or any room where they could possibly exfill or infill anything
* People chapter: In a phishing attack, the attacker may have access to an email address to use as a from address, thus making an attack appear more legitimate, the attacker should not have access to an email address of an associate of their target, thus violating least privilege

In this fascicle:

* VPS chapter: We discussed privilege escalation. This is a direct violation of least privilege, because after escalation, they now have additional privileges
* Network chapter: We discussed [lack of segmentation](#network-identify-risks-lack-of-segmentation). I also discussed this with [Haroon Meer](https://twitter.com/haroonmeer) on the Network Security show I hosted for Software Engineering Radio. This for example could allow an attacker that managed to gain control of a network to have unhindered access to all of an organisations assets due to all being on a monolithic network segment rather than having assets on alternative network segments with firewalls between them
* Web Applications chapter: We discuss setting up data-store accounts that only have privileges to query the stored procedures necessary for a given application, thus reducing the power that any possible SQL injection attack may have to carry out arbitrary commands. [Haroon Meer](https://twitter.com/haroonmeer) also discussed this as a technique for exfiltration of data in the Network Security podcast

Hopefully you are getting the idea of what least privilege is, and subsequently how it breaks down in a cloud environment. Some examples:

* **Running services as root**: A perfect example of this is running a docker container that does not specify a non root user in its image. By just not considering the user you may run as, Docker will default to root, as discussed in the [Docker](#vps-identify-risks-docker-the-default-user-is-root) subsection of the VPS chapter
* **Configuration Settings Changed Ad Hoc**: Because there are so many features and configurations that can be easily modified, developers and administrators will modify them. For example, someone needs access right now, and we are in the middle of something else, so we quickly modify a permissions setting without realising we have just modified that permission for a group of other people as well. Because it is so easy to make ad hoc changes, they will be made
* **Machine Instance Access To Open**: Is an attacker permitted to access your machine instances from anywhere? If so, this is additional attack surface

#### Machine Instance Single User Root {#cloud-identify-risks-violations-of-least-privilege-machine-instance-single-user-root}

The [default](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/managing-users.html) on AWS EC2 instances is to have a single user (root). There is no audit trail with a bunch of developers all using the same login. When ever anything happens on any of these machine instances, it is always the fault of user `ubuntu` on an Ubuntu AMI, `ec2-user` on a RHEL AMI, or `centos` on a Centos AMI. There are so many things wrong with this approach.

#### CSP Account Single User Root {#cloud-identify-risks-violations-of-least-privilege-csp-account-single-user-root}

Sharing and even using unnecessarily the root user, as I discuss in the [Credentials and Other Secrets](#cloud-identify-risks-storage-of-secrets-credentials-and-other-secrets) subsections. In this case, the business owners lost their business.

### Storage of Secrets {#cloud-identify-risks-storage-of-secrets}

As a Consultant / contract Architect, Engineer, I see a lot of mishandling of sensitive information. The following are some examples.

#### Private Key Abuse

The following are some of the ways I see private keys mishandled.

##### SSH {#cloud-identify-risks-storage-of-secrets-private-key-abuse-ssh}

[SSH](#vps-countermeasures-disable-remove-services-harden-what-is-left-ssh) key-pair auth is no better than password auth if it is abused in the following way, in-fact it may even be worse. What I have seen some organisations do is store a single private key with no pass-phrase for all of their EC2 instances in their developer wiki. All or many developers have access to this, with the idea being that they just copy the key from the wiki to their local `~/.ssh/`. There are a number of things wrong with this. 

* Private key is not private if it is shared amongst the team
* No pass-phrase, means no second factor of authentication
* Because there is only one user (single key-pair) being used on the
VPSs, there is also no audit trail
* The weakest link is the weakest wiki password of all the developers, and we all know how weak that is likely to be, with a bit of reconnaissance, probably guessable in a few attempts without any password profiling tools. I discussed this and demonstrated a collection of password profiling tools in the "Weak Password Strategies" subsection of the People chapter of [Fascicle 0](https://leanpub.com/holistic-infosec-for-web-developers/). Once the attacker has the weakest password, then they own all of the EC2 (if on AWS) instances, or any resource that is using key-pair authentication. If the organisation is failing this badly, then they almost certainly will not have any password complexity constraints on their wiki either

Most developers will also blindly accept what they think are the server key fingerprints without verifying them, thus opening themselves up to a MItM attack, as discussed in the VPS chapter under the [SSH subsection](#vps-countermeasures-disable-remove-services-harden-what-is-left-ssh-establishing-your-ssh-servers-key-fingerprint). This very quickly moves from just a technical issue to a cultural one. People are trained to just accept that the server is who it says it is, the fact that they have to verify the fingerprint is essentially a step that gets in their way.

##### TLS {#cloud-identify-risks-storage-of-secrets-private-key-abuse-tls}

When Docker reads the instructions in the following `Dockerfile`, an image is created that copies our certificate, private key, and any other secrets you have declared, and bakes them into an additional layer, forming the resulting image. Both `COPY` and `ADD` will bake what ever you are copying or adding into an additional layer or delta, as discussed in the [Consumption from Registries](#vps-countermeasures-docker-consumption-from-registries) Docker subsection in the VPS chapter. Who ever can access this image from a public or less public registry now has access to your certificate and even worse your private key.

Anyone can see how these images were built using the likes of the following tools:

* [dockerfile-from-image](https://github.com/CenturyLinkLabs/dockerfile-from-image)
* [ImageLayers](https://imagelayers.io/)

The `ENV` command similarly bakes the `dirty little secret` value as the `mySecret` key into the image layer.

{id="dockerfile-private-key-abuse", title="Private key abuse with Dockerfile", linenos=off}
    FROM nginx

    # ...
    COPY /host-path/star.mydomain.com.cert /etc/nginx/certs/my.cert
    COPY /host-path/star.mydomain.com.key /etc/nginx/certs/my.key
    ENV mySecret="dirty little secret"
    COPY /host-path/nginx.conf /etc/nginx/nginx.conf 
    # ...

#### Credentials and Other Secrets {#cloud-identify-risks-storage-of-secrets-credentials-and-other-secrets}

Sharing accounts, especially super-user accounts on the likes of [machine instances](#cloud-identify-risks-violations-of-least-privilege-machine-instance-single-user-root) and even worse, your CSP IAM account(s), and worse still, the account [root user](#cloud-identify-risks-violations-of-least-privilege-csp-account-single-user-root). I have worked for organisations that had only the single default AWS account [root user](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html) you are given when you first sign up to AWS, shared amongst several teams of Developers and managers, on the organisations wiki, which in itself is a big security risk. Subsequently the organisation I am thinking about had one of the business owners go rogue, and change the single password and lock everyone else out.

##### Entered by People (manually)

Developers and others putting user-names and passwords in company wikis, source control, anywhere where there is a reasonably good chance that an unauthorised person will be able to view them with a little to moderate amount of persistence, as discussed above in the [SSH](#cloud-identify-risks-storage-of-secrets-private-key-abuse-ssh) section. When you have a team of Developers sharing passwords, the weakest link is usually very weak, and that is only if you are considering outsiders to be a risk, which according to the study I discussed in the [Fortress Mentality](#network-identify-risks-fortress-mentality) subsection of the network chapter would be a mistake, with about half of the security incidents being carried out from inside of an organisation.

##### Entered by Software (automatically)

What ever you use to get work done in The Cloud programmatically, you are going to need to authenticate the process at some point. I see a lot of passwords in configuration files, stored in:

* Source control
* [Dropbox](#network-identify-risks-data-exfiltration-infiltration-dropbox)
* Many other insecure mediums

This is a major insecurity.

### Serverless {#cloud-identify-risks-serverless}

Serverless is not serverless, but the idea is that as a Software Engineer, you do not think about the physical machines that your code will run on. You can also focus on small pieces of functionality without understanding all of the interactions and relationships of the code you write.

#### Third Party Services

There is a lot of implicit trust put in third party services that components of your serverless architecture consume.

#### Perimeterless

Any perimeters that you used to, or at least thought you had are gone. We discussed this in the [Fortress Mentality](#network-identify-risks-fortress-mentality) subsection of the Network chapter.

#### Functions

[Amazon](https://aws.amazon.com/serverless/) has [Lambda](https://aws.amazon.com/lambda/) which can run Java, C#, Python, Node.js.

[GCP](https://cloud.google.com/serverless/) has [Cloud Functions](https://cloud.google.com/functions/) which are JavaScript functions.

[Azure]() has [Functions](https://azure.microsoft.com/en-us/services/functions/).

The complexity alone with AWS causes a lot of Developers to just "get it working" if they are lucky, then push it to production. Of course this has the side effect that security is in most cases overlooked. With AWS Lambda, you need to first:

1. Pick your function from a huge collection
2. Pick the trigger (event) from one of the many AWS services available
3. Choosing API Gateway allows you to invoke your function from the Internet

So... What is security when it comes to the Serverless paradigm?

What changes is the target areas for the attacker, they just move closer to application security, in order of most important first, we have:

1. [Application Security](#web-applications). Functions are still just code. Now that some other areas of infrastructure have become harder to compromise, more focus is invested by attackers on application security, and as usual, this is a weak area for most developers. Also consider the huge threat surface of depending on other open source consumables, as discussed in the Web Applications chapter "[Consuming Free and Open Source](#web-applications-identify-risks-consuming-free-and-open-source)" subsection
2. Identity and Access Management (IAM) and permissions. What permissions does an attacker have to execute in any given environment, including all and any services consuming and consumed by functions 
3. API key, being a distant third

Rich Jones demonstrated what can happen if you fail at the above three points in AWS in his talk "[Gone in 60 Milliseconds](https://www.youtube.com/watch?v=YZ058hmLuv0)":

* Getting some exploit code into an S3 bucket via an injection vulnerability and passing a parameter that references the injected key value
* `/tmp` is writeable
* Persistence is possible if you keep the container warm
* Lots of other attack vectors

#### DoS of Lambda Functions

The compute executing the functions you supply are short lived. With AWS, [containers are used](https://docs.aws.amazon.com/lambda/latest/dg/lambda-introduction.html) and reused providing your function runs at least once approximately every four minutes and thirty seconds according to Rich Jones talk. So the idea of hardware DoS is less likely, but [billing DoS](https://thenewstack.io/zombie-toasters-eat-startup/) is a [real issue](https://sourcebox.be/blog/2017/08/07/serverless-a-lesson-learned-the-hard-way/).

AWS Lambda will by default allow any given function a [concurrent execution](https://docs.aws.amazon.com/lambda/latest/dg/concurrent-executions.html#concurrent-execution-safety-limit) of 1000 per region. 

### Infrastructure and Configuration Management {#cloud-identify-risks-infrastructure-and-configuration-management}

The only real glaringly obvious risks with the management of configuration and infrastructure - as code, is the management of secrets, and most of the other forms of information security. "Hu?" I hear you say. Let me try and unpack that statement. When you create and configure infrastructure as code, you are essentially combining many technical aspects: machine instances (addressed in the VPS chapter), networking (addressed in the Network chapter), The Cloud obviously, and of course your applications (addressed in the Web Applications chapter), and baking them all into code to be executed. If you create security defects as part of the configuration or infrastructure, then lock them up in code, you will have the same consistent security defects each time that code is run. Hence, why Software Engineers now need to understand so much more than they used to about security. We are now responsible for so much more than we used to be.

Now we will focus on a collection of the largest providers.

### AWS {#cloud-identify-risks-aws}

One of the resources I have found very useful to understand some of the risks along with auditing whether they exist currently, and countermeasures, including clear direction on how to apply them, is the [CIS AWS Foundations document](https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf). This is well worth following along with as you read through this chapter.

AWS is continually announcing and releasing new products, features and configuration options. The attack surface just keeps expanding. AWS does an incredible job of providing security features and options for its customers, but... just as the [AWS Shared Responsibility Model](https://aws.amazon.com/compliance/shared-responsibility-model/) states, "_security in the cloud is the responsibility of the customer_". AWS provide the security, you have to decide to use it and educate yourself on doing so. Obviously if you are reading this, you are already well down this path. If you fail to use and configure correctly what AWS has provided, your attackers will at the very minimum use your resources for evil, and you will foot the bill. Even more likely, they will attack and steal your business assets, and bring your organisation to its knees. 

#### Password-less sudo

Password-less sudo. A low privileged user can operate with root privileges. This is essentially as bad as root logins.

%% https://serverfault.com/questions/615034/disable-nopasswd-sudo-access-for-ubuntu-user-on-an-ec2-instance



%% AWS general
%%  https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf
%%  https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html
%%  https://cloudonaut.io/aws-security-primer/

%% https://appsecday.com/schedule/hacking-aws-end-to-end/

%% Kiwicon 10 talk "Hacking AWS end to end". Slide-deck here: https://github.com/dagrz/aws_pwn/blob/master/miscellanea/Kiwicon%202016%20-%20Hacking%20AWS%20End%20to%20End.pdf, along with readme and code.



[Cognito](https://aws.amazon.com/cognito/)


### GCP 

%% https://cloud.google.com/

### Heroku

%% http://stackoverflow.com/questions/9802259/why-do-people-use-heroku-when-aws-is-present-whats-distinguishing-about-heroku

### Azure

%% https://docs.microsoft.com/en-us/azure/security/azure-security-iaas



## 3. SSM Countermeasures

Revisit the Countermeasures subsection of the first chapter of [Fascicle 0](https://leanpub.com/holistic-infosec-for-web-developers).

As I briefly touch on in the [CSP Account Single User Root](#cloud-countermeasures-violations-of-least-privilege-csp-account-single-user-root) subsection, [Canarytokens](https://canarytokens.org/) are an excellent token you can drop anywhere on your infrastructure, and when an attacker opens one of these tokens, an email will be sent to a pre-defined email address with a specific message that you define. This provides early warning that someone unfamiliar with your infrastructure is running things that do not normally get run. There are quite a few different tokens available and new ones being added every so often. These tokens are very quick and also free to generate, and drop where ever you like on your infrastructure. [Haroon Meer](https://twitter.com/haroonmeer) discusses these on the Network Security show I hosted for Software Engineering Radio near the end.

### Shared Responsibiltiy Model

#### CSP Responsibility 

There is not a lot you can do about this, just be aware of what you are buying into before you do so. [AWS for example](https://aws.amazon.com/compliance/shared-responsibility-model/) states: "_Customers retain control of what security they choose to implement to protect their own content, platform, applications, systems and networks, **no differently than they would for applications in an on-site** datacenter._"

#### CSP Customer Responsibility {#cloud-countermeasures-shared-responsibility-model-csp-customer-responsibility}

If you leverage The Cloud, Make sure the following aspects of security are all at an excellent level:

1. People security: Discussed in Fascicle 0 under the People chapter
2. [Application security](#web-applications): Discussed in the Web Applications chapter. The move to application security was also [discussed](#vps-countermeasures-docker-application-security) in the VPS chapter as a response of using Docker containers
3. Configuring the infrastructure and/or platform components: Usually CSP specific, but I cover some aspects in this chapter

The following is in response to the set of frequently asked questions under the [risks subsection](#cloud-identify-risks-shared-responsibility-model-csp-customer-responsibility) of CSP Customer Responsibility:

* **(Q)**: _As a software engineer, do I really care about physical network security and network logging?_  
   
   **(A)**: In the past, many aspects of [network security](#cloud-identify-risks-network-security) were the responsibility of the Network Administrators, with the move to The Cloud, this has to large degree changed. The networks established (intentionally or not) between the components we are leveraging and creating in The Cloud are a result of Infrastructure and Configuration Management, often (and rightly so) expressed as code. Infrastructure as Code (IaC). As discussed in the [Network Security](#cloud-identify-risks-network-security) subsection, this is now the responsibility of the Software Engineer  
   
* **(Q)**: _Surely "as a software engineer", I can just use TLS and that is the end of it?_  
   
   **(A)**: TLS is one very small area of network security. Its implementation as HTTPS and the PKI model is effectively [broken](#network-identify-risks-tls-downgrade). If TLS is your only saviour, putting it bluntly, you are without hope. The [Network Chapter](#network) covers the tip of the network security ice berg, network security is a huge topic, and one that has many books written along with other resources that provide more in-depth coverage than I can provide as part of a holistic view of security for Software Engineers. Software Engineers must come to grips with the fact that they need to implement defence in depth  
   
* **(Q)**: _Well if the machine is compromised, then we give up on security, we aren't responsible for the network_  
   
   **(A)**: For this statement, please refer to the [VPS](#vps) chapter for your responsibilities as a Software Engineer in regards to "the machine". In regards to "the network", please refer to the [Network Security](#cloud-identify-risks-network-security) subsection  
   
* **(Q)**: _What is the difference between application security and network security? Aren't they just two aspects of the same thing?_  
   
   **(A)**: No, for application security, see the [Web Applications](#web-applications) chapter. For network security, see the [Network](#network) chapter. Again, as Software Engineers, you are now responsible for all aspects of information security  
   
* **(Q)**: _If I have implemented TLS for communication, have I fixed all of the network security problems?_  
   
   **(A)**: If you are still reading this, I'm pretty sure you know the answer, please share it with other Developers, Engineers as you receive the same questions

### CSP Evaluation {#cloud-countermeasures-csp-evaluation}

Once you have sprung the questions from the [CSP Evaluaton](#cloud-identify-risks-csp-evaluation) subsection in the Identify Risks subsection on your service provider and received their answers, you will be in a good position to feed these into the following subsections.


1. Do you keep a signed audit log on which users performed which actions and when, via UIs and APIs?  
   
   On AWS you can enable [CloudTrail](https://aws.amazon.com/cloudtrail/) to log all of your API calls, command line tools, SDKs, and Console interactions. This will provide a good amount of visibility around who has been accessing the AWS resources and Identities
   
2. There is this thing called the shared responsibility model I have heard about between CSPs and their customers. Please explain what your role and my role is in the protection of my and my customers data?  
   
   Make sure you are completely clear on who is responsible for which data, where and when. It is not a matter of if your data will be stolen, but more a matter of when. Know your responsibilities. As discussed in the Web Applications chapter under the [Data-store Compromise](#web-applications-identify-risks-management-of-application-secrets-data-store-compromise) subsection... Data-store Compromise is one of the 6 top threats facing New Zealand, and these types of breaches are happening daily.  
   
   Also consider data security insurance  
   
3. Do you encrypt all communications between servers within your data centres?  
   
   I have discussed in many places that we should be aiming to have all communications on any given network encrypted. This is usually not to onerous to establish on your own network, but may in some cases not be possible on a CSPs network, especially if you are using proprietary/serverless technologies. If you are using usual machine instances, then in most cases, the CSPs infrastructure is logically not really any different than an in-house network, in which case you can encrypt your own communications.  
   
   AWS also provides [Virtual Private Cloud](https://aws.amazon.com/vpc/) (VPC), which you can build your networks within, including [Serverless](https://aws.amazon.com/serverless/) technologies. This allows for segmentation and isolation.  
   
   AWS also offers four different types of [VPN connections](https://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/vpn-connections.html) to your VPC  
   
4. Do you provide access to logs, if so what sort of access to what sort of logs?  
   
   If you don't have access to logs, then you are flying blind, you have no idea what is happening around you. How much does the CSP strip out of the logs before they allow you to view them? It is really important to weigh up what you will have visibility of, what you will not have visibility of, in order to work out where you may be vulnerable. Can the CSP provide guarantees that those vulnerable areas are taken care of by them? Make sure you are comfortable with the amount of visibility you will and will not have up front, as unless you make sure blind spots are covered, then you could be unnecessarily opening yourself up to be attacked. Some of the CSPs log aggregators could be [flaky for example](https://read.acloud.guru/things-you-should-know-before-using-awss-elasticsearch-service-7cd70c9afb4f).   
   
   With the likes of machine instances and network components, you should be taking the same responsibilities as you would if you were self hosting. I addressed these in the VPS and Network chapters under the Lack of Visibility subsections.  
   
   In terms of visibility into the Cloud infrastructure, most decent CSPs provide the tooling, you just need to use it.  
   
   As mentioned in point 1 above and [Violations of Least Privilege](#web-applications-countermeasures-management-of-application-secrets-least-privilege) countermeasures, AWS provides **CloudTrail** to log API calls, Management Console actions, SDKs, CLI tools, and other AWS services. As usual, AWS has good [documentation](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html) around what sort of log events are captured, what form they take, and the plethora of [services you can integrate](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-supported-services.html) with CloudTrail. As well as viewing and analysing account activity, you can [define AWS Lambda](https://docs.aws.amazon.com/lambda/latest/dg/with-cloudtrail.html) functions to be run on the `s3:ObjectCreated:*` event that is published by S3 when CloudTrail drops its logs in an S3 bucket.  
   
   AWS **[CloudWatch](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/WhatIsCloudWatch.html)** can be used to collect and track your resource and application metrics, CloudWatch can be used to react to collected events with the likes of Lambda functions to do your bidding  
   
5. What is your process around terminating my contract with you and/or moving to another CSP?  
   
   Make sure you have an [exit and/or migration](http://blog.sysfore.com/do-you-have-your-cloud-exit-plan-ready/) strategy planned as part of entering into an agreement with your chosen CSP. Make sure you have as part of your contract with your chosen CSP:  
   
   * What the CSP is going to do to assist in terminating and/or migrating your data and services from the CSP. Consider how long it may take you to move your data at slow internet speeds if you have large amounts stored. Will you be able to use the CSPs proprietary [API based technique](http://searchcloudstorage.techtarget.com/opinion/The-need-for-a-cloud-exit-strategy-and-what-we-can-learn-from-Nirvanix) for migrating your data from the current CSP to a new CSP? When, not if your current CSP goes out of business, you may only have two weeks to move everything and set-up shop on another cloud, just like was the case with [Nirvanix](http://searchcloudstorage.techtarget.com/news/2240205813/Nirvanix-cloud-customers-face-worse-nightmares). The tighter you integrate with your current CSP and leverage their proprietary services, the more work it will be to move, but at the same time, the less you depend on your CSPs proprietary services, the [less benefit](http://www.theserverside.com/feature/Getting-out-is-harder-than-getting-in-The-importance-of-a-cloud-exit-strategy) you will be getting from them. This is why threat modelling is an essential part of discovering a strategy that works for your organisations requirements
   * How does the CSP deal with your data and services when your contract is terminated, does it lie around somewhere for some time? Ideally be certain that it is completely purged so that it is just not available on their network at all, if it remains for a duration, is it discoverable by an attacker? Will they let you test this? If not, they are probably trying to hide something. Remember, often a greater number of attacks [come from within](#network-identify-risks-fortress-mentality) the organisation than from external
   * Does the CSP have third parties that audit, test and certify the completeness of the termination/migration procedure  
   
6. Where abouts do your servers, processes and data reside physically?  
   
   Do not assume that your data in The Cloud in another country is governed by the same laws as it is in your country. Make sure you are aware of the laws that apply to your data, depending on where it is  
   
7. Who can view the data I store in the cloud?  
   
   Technically, anyone can. In the case of AWS, they will not purposely disclose your data to anyone, unless required to by law. There are a few things you need to consider here such as:  
   
   * There are many ways for an attacker to get at your data illegally, and again that does not exclude insiders, as we discuss throughout this chapter. Just as if your data was discovered in your own in-house network, if you fail to take the precautions discussed throughout this chapter, especially around least privilege, then just like the [attack on Code Spaces](#cloud-identify-risks-violations-of-least-privilege) we discussed in the Violations of Least Privilege subsection, you may be equally open to exploitation
   * In many cases you will not know if your data has been released to authorities, we discussed this in the [Giving up Secrets](#cloud-identify-risks-cloud-service-provider-vs-in-house-giving-up-secrets) countermeasures subsection
   * Defence in depth, tells us, just as we discussed in the Web Applications chapter under Data-store Compromise, that we need to [encrypt our data at rest](#web-applications-countermeasures-data-store-compromise), and in transit (as discussed in VPS, Network and Web Application chapters) at a minimum. With this taken care of, when our data does fall into the hands of those that we do not want it in, it will be of little to no use to them in its encrypted form  
     * **At rest**: For starters, do not neglect what is discussed in the Web Applications chapter around protecting sensitive information at the application level (in code that is). AWS for example provides [EC2 Instance Store Encryption](https://aws.amazon.com/blogs/security/how-to-protect-data-at-rest-with-amazon-ec2-instance-store-encryption/), which provides Disk and file system encryption, encryption for EBS volumes, S3 buckets, and RDS. AWS also provides Elastic File System [(EFS)encryption](https://aws.amazon.com/about-aws/whats-new/2017/08/amazon-efs-now-supports-encryption-of-data-at-rest/). As usual, it is your responsibility to use these offerings
     * **In transit**: Most decent CSPs will provide options for TLS, and you should also be leveraging TLS in your applications
     * **In use**: This is still an area of research, some progress is being made though. [Ben Humphreys spoke](https://2016.chcon.nz/talks.html#1245) about this at CHCon, one of the conferences I co-founded in New Zealand   
   
8. What is your Service Level Agreement (SLA) for uptime?  
   
   Count this cost before signing up to the CSP  
   
9. Are you ISO/IEC 27001:2013 Certified? If so, what is within its scope?  
   
   AWS has a list of their [compliance certificates](https://pages.awscloud.com/compliance-contact-us.html)  
   
10. Do you allow your customers to carry out regular penetration testing of production and/or test environments, also allowing the network to be in-scope?  
    
    You will not need to go through this process of requesting permission from your own company to carry out penetration testing, and if you do, there should be a lot fewer restrictions in place.  
    
    **[AWS](https://aws.amazon.com/security/penetration-testing)** allow customers to submit requests to penetration test to and from some AWS EC2 and RDS instance types that you own. All other AWS services are not permitted to be tested or tested from.  
    
    **[GCP](https://cloud.google.com/security/)** does not require penetration testers to contact them before beginning testing of their GCP hosted services, so long as they abide by the Acceptable Use Policy and the Terms of Service.  
    
    **[Heroku](https://devcenter.heroku.com/articles/pentest-instructions)** are happy for you to penetration test your applications running on their PaaS. If you are performing automated security scans, you will need to give them two business days notice before you begin testing.  
    
    **[Azure](https://blogs.msdn.microsoft.com/azuresecurity/2016/08/29/pen-testing-from-azure-virtual-machines/)** allows penetration testing of your applications and services running in Azure, you just need to fill out their form. In order to use Azure to perform penetration testing on other targets, you do not need permission providing you are not DDoS testing.   
   
11. Do you have bug bounty programmes running, if so, what do they look like?  
    
    If the CSP is of a reasonable size and is not already running bug bounties, this is a good sign that security could be taken more seriously.  
    
    **AWS** has a [bug bounty](https://hackerone.com/amazon-web-services) program.  
    
    **GCP** states that if a bug is found in the google infrastructure, the penetration tester is encouraged to submit it to their bug bounty program.  
    
    **Heroku** offer a [bug bounty](https://hackerone.com/heroku) program.  
    
    **Azure** offer a [bug bounty](https://hackerone.com/azure) program.

### [Cloud Service Provider vs In-house](https://speakerdeck.com/binarymist/does-your-cloud-solution-look-like-a-mushroom)

It depends on the CSP, and many things about your organisation. Each CSP does things differently, has strengths and weaknesses in different areas of the shared responsibility model, has different specialities, is governed by different people and jurisdictions (USA vs Sweden for example), some are less security conscious than others. The largest factor in this question is your organisation. How security conscious and capable of implementing a secure cloud environment are your workers.

You can have a more secure cloud environment than any CSP if you decide to do so and have the necessary resources to build it. If you don't decide to and/or don't have the necessary resources, then most well known CSPs will probably be doing a better job than your organisation.

Then you need to consider what you are using the given CSPs services for. If you are creating and deploying applications, then your applications will be a weaker link in the security chain, this is a very common case and one that is often overlooked. To attempt to address application security, I wrote the [Web Applications](#web-applications) chapter.

Your attackers will attack your weakest area first, in most cases this is not your CSP, but your organisations people due to lack of knowledge, passion, engagement, or a combination of them. If you have a physical premises, this can often be an easy target also. Usually application security follows closely after people security. This is why I have the Physical and People chapters in [Fascicle 0](https://leanpub.com/holistic-infosec-for-web-developers) of this book series, they are also the most commonly overlooked. The reason I added the Web Applications chapter last in this fascicle, was that I wanted to help you build a solid foundation of security in the other areas often overlooked before we addressed application security, and I also wanted it to be what sticks in your mind once you have read this fascicle.

Based on the threat modelling I hope you have done through each chapter, which was first introduced in [Fascicle 0](https://leanpub.com/holistic-infosec-for-web-developers) you should be starting to work out where cloud security rates on your list of risks to your assets. By the end of this chapter, you should have an even better idea.

#### Skills

The fate of your and your customers data is in your hands. If you have the resources to provide the necessary security then you are better off with an In-house cloud, if not, the opposite is true.  
If you go with an In-house cloud, you should have tighter control over the people creating and administering it, this is good if they have the necessary skills and experience, if not, then the opposite is true again.

#### EULA

You and any In-house cloud environment you establish is not subject to changing EULAs.

#### Giving up Secrets 

If you are using an In-house cloud and find yourself in a place where you have made it possible for your customers secrets to be read, and you are being forced by the authorities to give up secrets, you will know about it and be able to react appropriately, invoke your incident response team(s) and procedures.

#### Location of Data

If you use an In-house cloud, you decide where services & data reside.

#### Vendor lock-in

You have to weigh up the vendor benefits and possible cost savings vs how hard / costly it is to move away from them when you need to.

Many projects are locked into technology decisions / offerings, libraries, services from the design stage, and are unable to swap these at a later stage without incurring significant cost. If the offering that was chosen is proprietary, then it makes it all the more difficult to swap if and when it makes sense to do so.

Some times it can cost more up front to go with an open (non proprietary) offering because somehow the proprietary offering has streamlined the development, deployment, maintainability process, that is the whole point of proprietary offerings right? Sometimes the open offering can actually be the cheaper option, due to proprietary offerings usually incurring an additional learning or upskilling cost for the teams/people involved.

Often technology choices are chosen because they are the "new shiny", it is just what everyone else seems to be using, or there is a lot of buzz or noise around it.

**An analogy**: Do Software Developers write non-testable code because it is cheaper to write? Many/most code shops do, I discussed test driven development (TDD) in the Process and Practises chapter of [Fascicle 0](https://leanpub.com/holistic-infosec-for-web-developers/), I have [blogged](https://blog.binarymist.net/?s=tdd), [spoken and run workshops](https://blog.binarymist.net/presentations-publications/) on the topic of testability extensively. Writing non-testable code is a short sighted approach. Code is read and attempted to be modified and extended many times more than it is written up front. If you are putting all your cost savings on the initial write, and failing to consider all the times that modification will be attempted, then you are missing huge cost savings. Taking an initial hit up front to write testable code, that is code that has the properties of maintainability, extensibility defined by the [Liskov Substitution Principle](https://blog.binarymist.net/2010/10/11/lsp-dbc-and-nets-support/) will set you up so that the interface is not coupled to the implementation. If you get your thought process right up front, and make sure you can swap components (implementation) out-in at will, maintainability and extensibility are not just possible, but a pleasure to do.

**An example**: You do not make the decision up front that you are going to switch from running your JavaScript on one CSPs VM to another CSPs proprietary serverless technology in 5 years, you have no idea up front what you may switch to in 5 or 10 years time. If you choose to not be locked into a proprietary technology (AWS Lambda for example), you will be able to move that code anywhere you want trivially in the future. This is just swapping the implementation out. Just as professional Software Engineers do with code to make it testable, we should think seriously about doing the same with technology offerings. Just apply the same concept.

#### Possible Single Points of Failure

The following are some of the countermeasures to the single points of failure in The Cloud. The idea is to create redundancy on items that we can not do without:

* Load balanced instances and/or start up scripts
* Docker [restart policy](https://docs.docker.com/engine/admin/start-containers-automatically/) and/or orchestration tools
* Multiple Availability Zones
* Multiple Regions
* Multiple Accounts
* Make it hard for an attacker to succeed
  * Long complex passwords, yes the ones you can not remember and must store in a password database
  * Multi-factor authentication
  * Make sure you are collecting and storing login history in a safe place, this can be used to challenge attackers that have successfully logged in, as you will have their IP addresses and browser user agent string
  * Third party authentication
  * Lots of other techniques

### Review Other Chapters {#cloud-countermeasures-review-other-chapters}

As I mentioned in the [Identify Risks](#cloud-identify-risks-review-other-chapters) Review Other Chapters subsection, please make sure you are familiar with the related concepts discussed.

### People

Most of the countermeasures are discussed in the People chapter of [Fascicle 0](https://leanpub.com/holistic-infosec-for-web-developers/)

### Application Security

Full coverage in the [Web Applications](#web-applications) chapter.

### Network Security

Full coverage in the [Network](#network) chapter.

### Violations of [Least Privilege](#web-applications-countermeasures-management-of-application-secrets-least-privilege) {#cloud-countermeasures-violations-of-least-privilege}

When you create IAM policies, grant only the permissions required to perform the task(s) necessary for the given users. If the user needs additional permissions, then they can be added, rather than adding everything up front and potentially having to remove again at some stage. Adding as required, rather than removing as required will cause much less friction technically and socially.

**For example, [in AWS](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege)**:, you need to keep a close watch on which [permissions](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_permissions.html) are assigned to [policies](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html) that your groups and roles have attached, and subsequently which groups and roles your users are in or part of.

The sequence of how the granting of least privilege looks in AWS is as follows, other CSPs will be similar:

1. First work out which permissions a given user requires
2. Create or select an existing group or role
3. Attach policy to the group or role that has the permissions that your given user requires. You can select existing policies or create new ones
4. Add the given user to the group or role

Regularly review all of the IAM policies you are using, making sure only the required permissions (Services, Access Levels, and Resources) are available to the users and/or groups attached to the specific policies.

[Enable Multi Factor Authentication](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#enable-mfa-for-privileged-users) (MFA) on the root user, and all IAM users with console access, especially privileged users at a minimum. AWS provides the ability to mandate that users use MFA, you can do this by creating a new managed policy based on the AWS [DelegateManagementofMFA_policydocument](https://s3.amazonaws.com/awsiammedia/public/sample/DelegateManagementofMFA/DelegateManagementofMFA_policydocument_060115.txt) template, attach the new policy to a group that you have created and add users that must use MFA to that group. As usual, AWS has [documentation](https://aws.amazon.com/blogs/security/how-to-delegate-management-of-multi-factor-authentication-to-aws-iam-users/) on the process.

The [Access Advisor](https://aws.amazon.com/blogs/security/remove-unnecessary-permissions-in-your-iam-policies-by-using-service-last-accessed-data/) tab, which is visible on the IAM console details page for Users, Groups, Roles, or Policies after you select a list item, provides information about which services are accessible from any of your users, groups, or roles. This can be helpful for auditing permissions that should not be available to any of your users that are part of the group, role or policy you selected.

The [IAM Policy Simulator](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_testing-policies.html) which is accessible from the IAM console is also good for granular reporting on the permissions of your specific Users, Groups and Roles, filtered by service and actions.

[AWS Trusted Advisor](https://aws.amazon.com/premiumsupport/trustedadvisor/) should be run periodically to check for security issues. Accessible from the [Console](https://console.aws.amazon.com/trustedadvisor/), CLI and API. Trusted Advisor has a collection of core checks and recommendations which are free to use, such as security groups, specific ports unrestricted, IAM use, MFA on root user, EBS and RDS public snapshots.

* **Running services as root**: Make sure the user that a Docker container is running as is not root. Full details in [The Default User is Root](#vps-countermeasures-docker-the-default-user-is-root) Countermeasures subsection of the VPS chapter
* **Configuration Settings Changed Ad Hoc**: One option is to have solid change control in place. [AWS Config](https://aws.amazon.com/config/) can assist with this. [AWS Config](https://docs.aws.amazon.com/config/latest/developerguide/) continuously monitors and records how the AWS resources were configured and how they have changed, including how they are related to each other. This enables you to assess, audit, evaluate the configurations of your AWS resources and have notifications sent to you when Config detects that a resource is violating the conditions of any given Config rule you define, by being either created, modified or deleted.  
   
   AWS Config records IAM policies assigned to users, groups, or roles, and EC2 security groups, including port rules for any given time. Changes to your configuration settings can trigger Amazon Simple Notification Service (SNS) notifications, which you can have sent to those tasked with controlling changes to your configurations.  
   
   Your custom rules can be codified and thus source controlled. AWS calls this Compliance as Code. I discussed AWS CloudTrail briefly in item 1 of the [CSP Evaluation](#cloud-countermeasures-csp-evaluation) countermeasures subsection. AWS Config is integrated with CloudTrail which captures all API calls from AWS Config console or API, SDKs, CLI tools, and other AWS services. The information collected by CloudTrail provides insight on what request was made, from which IP address, by who, and when  
* **Machine Instance Access To Open**: Consider removing the additional attack surface of being able to access your machine instances from any source IP address

#### Machine Instance Single User Root

As part of the VPS and container builds, there should be [specific users created](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/managing-users.html) for specific jobs, every user within your organisation that needs VPS access should have their own user account on every VPS, including [SSH access](#cloud-countermeasures-storage-of-secrets-private-key-abuse-ssh) if this is required (ideally this should be automated). With Docker, I discussed how this is done in the [Dockerfile](#vps-countermeasures-docker-the-dDefault-user-is-root).

Drive a [least privilege policy](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege) around this, configuring a strong [password policy](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#configure-strong-password-policy) for your users, and implement [multi-factor authentication](https://aws.amazon.com/iam/details/mfa/) which will help with poor password selection of users. I discuss this in more depth in the [Storage of Secrets](#cloud-countermeasures-storage-of-secrets) subsection.

#### CSP Account Single User Root {#cloud-countermeasures-violations-of-least-privilege-csp-account-single-user-root}

As I discuss in the [Credentials and Other Secrets](#cloud-countermeasures-storage-of-secrets-credentials-and-other-secrets) Countermeasures subsection of this chapter, create multiple accounts with least privileges required for each, the root user should hardly ever be used. Create groups and attach restricted policies to them, then add the specific users to them.

As I discussed in the [Credentials and Other Secrets](#cloud-countermeasures-storage-of-secrets-credentials-and-other-secrets-entered-by-people-manually) countermeasures subsection, there should be almost no reason to generate key(s) for the AWS Command Line Tools for the AWS account root user, but if you do, consider setting up notifications for when they are used. As usual, AWS has plenty of [documentation](https://aws.amazon.com/blogs/security/how-to-receive-notifications-when-your-aws-accounts-root-access-keys-are-used/)
on the topic.

Another idea is to set-up monitoring and notifications on activity of your AWS account root user. AWS [documentation](https://aws.amazon.com/blogs/mt/monitor-and-notify-on-aws-account-root-user-activity/) explains how to do this.

Another great idea is to generate an AWS key [Canarytoken](https://canarytokens.org/) from canarytokens.org, and put it somewhere more obvious than your real AWS key(s). When someone uses it, you will be automatically notified. I discussed these with Haroon Meer on the Software Engineering Radio Network Security podcast.

Also consider rotating your IAM access keys to your CSP services. AWS EC2 for example provide [auto-expire, auto-renew](https://aws.amazon.com/blogs/security/how-to-rotate-access-keys-for-iam-users/) access keys by using roles.

### [Storage of Secrets](https://www.programmableweb.com/news/why-exposed-api-keys-and-sensitive-data-are-growing-cause-concern/analysis/2015/01/05) {#cloud-countermeasures-storage-of-secrets}

In this section I discuss some techniques to handle our sensitive information in a safer manner.

If you have "secrets" in source control or wikis, they are probably not secret. Remove them and change the secret (password, key, what ever it is). [Github provides guidance](https://help.github.com/articles/removing-sensitive-data-from-a-repository/) on removing sensitive data from a repository.

Also consider using [git-crypt](https://github.com/AGWA/git-crypt)

Use different access keys for each service and application requiring them.

Use [temporary security credentials](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp.html).

Rotate access keys.

#### Private Key Abuse

The following are some techniques to better handle private keys.

##### SSH {#cloud-countermeasures-storage-of-secrets-private-key-abuse-ssh}

There are many ways to harden SSH as we discussed in the [SSH](#vps-countermeasures-disable-remove-services-harden-what-is-left-ssh) subsection in the VPS chapter. Usually the issue will lie with lack of knowledge, desire and a dysfunctional [culture](https://blog.binarymist.net/2014/04/26/culture-in-the-work-place/) in the work place. You will need to address the people issues before looking at basic SSH hardening techniques.

Ideally SSH access should be reduced to a select few. Most of the work we do now by SSHing should be automated. If you have a look at all the commands in history on any of the VPSs, most of the commands are either deployment or
manual monitoring which should all be automated.

When you create an AWS EC2 instance you can create a key pair [using EC2](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-key-pairs.html#having-ec2-create-your-key-pair) or you can [provide your own](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-key-pairs.html#how-to-generate-your-own-key-and-import-it-to-aws), either way, to be able to log-in to your instance, you need to have provided EC2 with the public key of your key pair and specified it by name. 

Every user should have their [own key-pair](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-key-pairs.html), the private part should always be private, kept in the users local `~/.ssh/` directory (not the server) with permissions `600` or more restrictive, not shared on your developer wiki or anywhere else for that matter. The public part can be put on every server that the user needs access to. There is no excuse for every user not to have their own key pair, you can have up to five thousand key pairs per AWS region. AWS has [clear directions](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-key-pairs.html) on how to create additional users and provide SSH access with their own key pairs.

For generic confirming of the hosts SSH key fingerprint as you are prompted before establishing the SSH connection, follow the procedure I laid out for: [Establishing your SSH Servers Key Fingerprint](#vps-countermeasures-disable-remove-services-harden-what-is-left-ssh-establishing-your-ssh-servers-key-fingerprint) in the VPS chapter, and make it organisational policy. We should never blindly just accept key fingerprints. The key fingerprints should be stored in a relatively secure place, so that only trusted parties can modify them. What I would like to see happen, is that as part of the server creation process, the place (probably the wiki) that specifies the key fingerprints is automatically updated by something on the VPS that keeps watch of the key fingerprints. Something like [Monit](#vps-countermeasures-lack-of-visibility-proactive-monitoring-getting-started-with-monit) as discussed in the VPS chapter, would be capable of the monitoring and firing a script to do this.

To SSH to an EC2 instance, you will have to view the console output of the keys being generated. You can see this **only for the first run** of the instance when it is being created, this can be seen by first fetching:  
https://console.aws.amazon.com  
Then:

1. Click the "EC2" link
2. Click "Instances" in the left column
3. Click the instance name you want
4. Click the select button "Actions" and choose "Get System Log" (a.k.a. "Console Output")
5. In the console output, you should see the keys being generated. Record them

Then to SSH to your EC2 instance: the command to use can be seen by fetching:  
https://console.aws.amazon.com  
Then:

1. EC2
2. Instances
3. Select your instance
4. Click the Connect button for details

##### TLS {#cloud-countermeasures-storage-of-secrets-private-key-abuse-tls}

So how do we stop baking secrets into our Docker images?

The easiest way is to just not add secrets to the process of building your images. You can add them at run time in several ways. If you think back to the [Namespaces](#vps-identify-risks-docker-docker-host-engine-and-containers-namespaces) Docker subsection in the VPS chapter, we used volumes. This allows us to keep the secrets entirely out of the image and only include in the container as mounted host directories. This is how we would do it, rather than adding those secrets to the `Dockerfile`:

{id="docker-run-mitigating-private-key-abuse", title="Mitigate private key abuse via terminal", linenos=off}
    docker run -d -p 443:443 -v /host-path/star.mydomain.com.cert:/etc/nginx/certs/my.cert -v /host-path/star.mydomain.com.key:/etc/nginx/certs/my.key -e "mySecret=dirty little secret" nginx

An even easier technique is to just add your adding of secrets to the `docker-compose.yml` file, thus saving all that typing every time you want to run the container:

{id="docker-compose-mitigating-private-key-abuse", title="Mitigate private key abuse using docker-compose.yml", linenos=off}
    nginx:
        build: .
        ports:
            - "443:443"
        volumes:
            - /host-path/star.mydomain.com.key:/etc/nginx/ssl/nginx.key
            - /host-path/star.mydomain.com.cert:/etc/nginx/ssl/nginx.crt
            - /host-path/nginx.conf:/etc/nginx/nginx.conf
        env_file:
            - /host-path/secrets.env

Using the `env_file` we can hide our environment variables in the `.env` file.  
Our `Dockerfile` would now look like the following, even our config is volume mounted and will no longer reside in our image:

{id="dockerfile-no-private-key-abuse", title="Mitigate private key abuse using Dockerfile", linenos=off}
    FROM nginx

    # ...
    # ...

#### Credentials and Other Secrets {#cloud-countermeasures-storage-of-secrets-credentials-and-other-secrets}

Create multiple users with the least privileges required for each to do their job, discussed below.  
Create and enforce password policies, discussed below.

Funnily enough, with the AWS account root user story I mentioned in the [Risks](#cloud-identify-risks-storage-of-secrets-credentials-and-other-secrets) subsection, I had created a report detailing this as one of the most critical issues that needed addressing several weeks before everyone but one person lost access.

If your business is in The Cloud, the account root user is one of your most valuable assets, do not share it with anyone, and only use it when essential.

##### Entered by People (manually) {#cloud-countermeasures-storage-of-secrets-credentials-and-other-secrets-entered-by-people-manually}

**Protecting against outsiders**

The most effective alternative to storing user-names and passwords in an insecure manner is to use a group or team password manager. There are quite a few offerings available with all sorts of different attributes. The following are some of the points you will need to consider as part of your selection process:

* Cost in terms of money
* Cost in terms of set-up and maintenance
* Closed or open source. If you care about security, which you obviously do if you are looking at using a team password manager, it is important to see how secrets are handled, which rules out many. For me I need to be able to see how the code is written, which [Key Derivation Functions](#web-applications-countermeasures-data-store-compromise-which-kdf-to-use) (KDFs) and [cyphers](#web-applications-identify-risks-cryptography-on-the-client) are used. If it is of high quality, we can have more confidence that our precious sensitive pieces of information are in-fact going to be private
* Do you need a web client?
* Do you need a mobile client (iOS, Android)?
* What platforms does it need to support?
* Does it need to be able to manage secrets of multiple customers?
* Auditing of user actions? Who is accessing and changing what?
* Ability to be able to lock out users, when they leave for example?
* Multi-factor authentication
* Options: Does it have all the features you would need?
* Who is behind the offering? Are they well known for creating solid, reliable, secure solutions?

The following were my personal top three, with No. 1 being my preference, based on research I performed for one of my customers recently. All the points above were considered for a collection of about ten team password managers that I reviewed:

1. [Plesant Password Server](http://pleasantsolutions.com/PasswordServer/) (KeePass backed)
2. [Password Manager Pro](https://www.manageengine.com/products/passwordmanagerpro/msp/features.html)
3. [LastPass](https://www.lastpass.com/teams)

**Protecting against insiders as well**

The above alone is not going to stop an account take over if you are sharing the likes of the AWS account root user email and password, even if it is in a group password manager. As AWS have [already stated](https://docs.aws.amazon.com/IAM/latest/UserGuide/getting-started_create-admin-group.html), only use the root user for what is absolutely essential (remember: least privilege), this is usually just to create an Administrators group to which you attach the `AdministratorAccess` managed policy, then add any new IAM users to that group that require administrative access.

Once you have created IAM users within an Administrators group as mentioned above, these users should set-up groups to which you attach further restricted managed policies such as a group for `PowerUserAccess`, a group for `ReadOnlyAccess`, a group for `IAMFullAccess`, progressively becoming more restrictive. Use the most restrictive group possible in order to achieve specific tasks, simply assigning users to the groups you have created.

Also use multi-factor authentication.

&nbsp;

Your AWS users do not get created with access keys to use for programmatic access, do not create these unless you actually need them, and again consider least privilege, there should be almost no reason to create an [access key](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#lock-away-credentials) for the root user.

Configure [strong password policies](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#configure-strong-password-policy) for your users, make sure they are using personal password managers and know how to generate long complex passwords.

##### Entered by Software (automatically) {#cloud-countermeasures-storage-of-secrets-credentials-and-other-secrets-entered-by-software}

There are many places in software that require access to secrets, to communicate with services, APIs, datastores. configuration and infrastructure management systems have a problem of storing and accessing these secrets in a secure manner.

HashiCorp **[Vault](https://www.vaultproject.io/)**. The most fully featured of these tools, has the following attributes/features:

* [Open Source](https://github.com/hashicorp/vault) written in Go-Lang
* Deployable to any environment, including development machines
* Arbitrary key/value secrets can be stored of any type of data
* Supports cryptographic operations of the secrets
* Supports dynamic secrets, generating credentials on-demand for fine-grained security controls
* Auditing: Vault forces a mandatory lease contract with clients, which allows the rolling of keys, automatic revocation, along with multiple revocation mechanisms providing operators a break-glass for security incidents
* Non-repudiation
* Secrets protected in transit and at rest
* Not coupled to any specific configuration or infrastructure management system
* Can read secrets from configuration, infrastructure management systems and applications via its API
* Applications can query Vault for secrets to connect to services such as datastores, thus removing the need for these secrets to reside in configuration files (See the [Risks that Solution Causes](#cloud-risks-that-solution-causes-storage-of-secrets-credentials-and-other-secrets-entered-by-software) for the caveat)
* Requires multiple keys generally distributed to multiple individuals to read its encrypted secrets
* Check the [Secret Backends](https://www.vaultproject.io/docs/secrets/index.html) for integrations

**[Docker secrets](https://docs.docker.com/engine/swarm/secrets/)**

* Manages any sensitive data (including generic string or binary content up to 500 kb in size) that a [container needs at runtime](#cloud-countermeasures-storage-of-secrets-private-key-abuse-tls), but you do not want to [store in the image](#cloud-identify-risks-storage-of-secrets-private-key-abuse-tls), source control, or the host systems file-system as we did in the TLS section above
* Only available to Docker containers managed by Swarm (services). Swarm manages the secrets
* Secrets are stored in the Raft log, which is encrypted if using Docker 1.13 and higher
* Any given secret is only accessibly to services (Swarm managed container) that have been granted explicit access to the secret
* Secrets are decrypted and mounted into the container in an in-memory filesystem which defaults to `/run/secrets/<secret_name>` in Linux, `C:\ProgramData\Docker\secrets` in Windows

**[Ansible Vault](https://docs.ansible.com/ansible/latest/playbooks_vault.html)**

Ansible is an [Open Source](https://github.com/ansible/ansible/blob/devel/docs/docsite/rst/playbooks_vault.rst) configuration management tool, and has a simple secrets management feature.

* Ansible tasks and handlers can be encrypted
* Arbitrary files, including binary data can be encrypted
* From version 2.3 can encrypt single values inside YAML files
* Suggested workflow is to check the encrypted files into source control for auditing purposes

{#cloud-countermeasures-storage-of-secrets-credentials-and-other-secrets-entered-by-software-kms}
AWS **[Key Management Service](https://aws.amazon.com/kms/)** (KMS) 

* Encrypt up to 4 KB of arbitrary data (passwords, keys)
* Supports cryptographic operations of the secrets: encrypt and decrypt
* Uses Hardware Security Modules (HSM)
* Integrated with AWS CloudTrail to provide auditing of all key usage
* AWS managed service
* Create, import and rotate keys
* Usage via AWS Management Console, SDK and CLI

AWS has **[Parameter Store](https://aws.amazon.com/ec2/systems-manager/parameter-store/)**

* Centralised store on AWS to manage configuration data, plain text, or encrypted secrets via AWS KMS
* All calls to the parameter store are recorded with AWS CloudTrail, supports access controls.

Also see the [additional resources](#additional-resources-cloud-countermeasures-storage-of-secrets-credentials-and-other-secrets-entered-by-software) for other similar tools.

### [Serverless](https://github.com/anaibol/awesome-serverless) {#cloud-countermeasures-serverless}

Serverless is another form of separation of concerns / decoupling. Serverless is yet another attempt to coerce Software Developers into abiding by the Object Oriented (OO) [SOLID](https://en.wikipedia.org/wiki/SOLID_(object-oriented_design)) principles, that the vast majority of Developers never quite understood. Serverless forces the microservice way of thinking.

Serverless mandates the reactive / event driven approach that insists that our code features stand alone without the tight coupling of many services that we often seem to have. Serverless forces us to split our database's out from our business logic. Serverless goes a long way to forcing us to write [testable code](https://blog.binarymist.net/2012/12/01/moving-to-tdd/), and as I have said so many times, testable code is good code, code that is easy to maintain and extend, thus abiding by the [Open/closed principle](https://en.wikipedia.org/wiki/Open/closed_principle).

Serverless provides another step up in terms of abstraction, but at the same time allows you to focus on the code, which as a Developer, sounds great.

With AWS Lambda, you only pay when your code executes, as opposed to paying for machine instances, or with Heroku for the entire time your application is running on their compute, even if the application code is not executing. AWS Lambda and similar offerings allow granular costing, thus passing on cost savings due to many customers all using the same hardware.

AWS Lambda and similar offerings allow us to not think about machine/OS and language environment patching, compute resource capacity or scaling. You are now trusting your CSP to do these things. There are [no maintenance windows](https://aws.amazon.com/lambda/faqs/#scalability) or scheduled downtimes. Lambda is also currently free for up to one million requests per month, and does not expire after twelve months. This in itself is quite compelling to leverage the service.

#### Third Party Services

When you consume third party services (APIs, functions, etc), you are in essence outsourcing what ever you send or receive from them. How is that service handling what you pass to it or receive from it? How do you know that the service is who you think it is, are you checking its TLS certificate? Is the data in transit encrypted? Just as I discuss below under [Functions](#cloud-countermeasures-serverless-functions), you are sending and receiving from a potentially untrusted service. This all increases the attack surface.

#### Perimeterless

Not really much different to the [Fortress Mentality](#network-countermeasures-fortress-mentality) subsection discussed in the Network chapter.

#### Functions {#cloud-countermeasures-serverless-functions}

With AWS Lambda, as well as getting your application security right, you also need to fully understand the [Permissions Model](https://docs.aws.amazon.com/lambda/latest/dg/intro-permission-model.html), apply it, and protect your API gateway with a key.

1. Firstly: No matter where your code is executing, you must have a good grasp on application security, no amount of sand-boxing, Dockerising, application firewalling, or anything else will protect you from poorly written applications if they are running. In regards to help with consuming all the free and open source, review the [Consuming Free and Open Source](#web-applications-countermeasures-consuming-free-and-open-source) countermeasures subsection of the Web Applications chapter. Snyk has a [Serverless](https://snyk.io/serverless) offering also. Every function you add adds attack surface and all the risks that come with integrating with other services. Keep your inventory control tight with your functions and consumed dependencies, that is, know which packages you are consuming and which known defects they have, know how many and which functions are in production, as discussed in the [Consuming Free and Open Source](#web-applications-countermeasures-consuming-free-and-open-source). Test removing permissions and see if everything still works. If it does, your permissions were to open, reduce them
2. In regards to AWS Lambda, although it should be similar with the other large CSPs, Make sure you apply only privileges required, this way you will not be [violating the principle](#cloud-countermeasures-violations-of-least-privilege) of Least Privilege
    * AWS Lambda function [access to other AWS resources](https://docs.aws.amazon.com/lambda/latest/dg/intro-permission-model.html#lambda-intro-execution-role):
      * Create an [IAM execution role](https://docs.aws.amazon.com/lambda/latest/dg/with-s3-example-create-iam-role.html) of type `AWS Service Roles`, grant the AWS Lambda service permissions to assume your role by choosing `AWS Lambda`
      * Attach the policy to the role as discussed in step 3 under [Violations of Least Privilege](#cloud-countermeasures-violations-of-least-privilege). Make sure to tightly constrain the `Resource`'s of the chosen policy. `AWSLambdaBasicExecuteRole` if your Lambda function only needs to write logs to CloudWatch, `AWSLambdaKinesisExecutionRoleAWS` if your Lambda function also needs to access Kinesis Streams actions, `AWSLambdaDynamoDBExecutionRole` if your Lambda function needs to access DynamoDB streams actions along with CloudWatch, and `AWSLambdaVPCAccessExecutionRole` if your Lambda function needs to access AWS EC2 actions along with CloudWatch
      * When you create your Lambda function, apply your Amazon Resource Name (ARN) as the value to the `role`
      * Each function accessing a data store should use a unique user/credentials with only the permissions to do what that specific function needs to do, this honours least privilege, and also provides some level of auditing
    * Other AWS resources [access to AWS Lambda](https://docs.aws.amazon.com/lambda/latest/dg/intro-permission-model.html#intro-permission-model-access-policy):
      * Permissions are added via function policies. Make sure these are granular and specific

3. [Use](https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-setup-api-key-with-console.html) an [API key](https://serverless.com/framework/docs/providers/aws/events/apigateway/#setting-api-keys-for-your-rest-api)

#### DoS of Lambda Functions

AWS Lambda allows you to [throttle](https://docs.aws.amazon.com/lambda/latest/dg/concurrent-executions.html#concurrent-execution-safety-limit) the concurrent execution count. AWS Lambda functions being invoked asynchronously can handle bursts for approximately 15-30 minutes. Essentially if the default is not right for you, then you need to define the policy, that is set reasonable limits. Make sure you do this!

Set [Cloudwatch alarms](https://docs.aws.amazon.com/lambda/latest/dg/monitoring-functions.html) on [duration and invocations](https://docs.aws.amazon.com/lambda/latest/dg/monitoring-functions-metrics.html). These can even be sent to slack.

Drive the creation of your functions the same way you would drive any other production quality code... with unit tests ([TDD](https://blog.binarymist.net/2012/12/01/moving-to-tdd/)), that is in isolation. Follow that with integration testing of the function in a production like test environment with all the other components in place. [You can](https://serverless.zone/unit-and-integration-testing-for-lambda-fc9510963003) mock, stub, pass spies in the AWS:

* JavaScript SDK using tools such as:
  * [aws-sdk-mock](https://www.npmjs.com/package/aws-sdk-mock)
  * [mock-aws](https://www.npmjs.com/package/mock-aws)
* Python SDK (boto3) using tools such as:
  * [placebo](https://github.com/garnaat/placebo)
  * [moto](https://github.com/spulec/moto)

Set-up billing alerts.

Be careful not to create direct or indirect recursive function calls.

Use an application firewall as I discuss in the Web Application chapter under the "[Insufficient Attack Protection](#web-applications-countermeasures-insufficient-attack-protection-waf)" subsection may provide some protection if your rules are adequate.

Consider how important it is to scale compute to service requests. If it is more important to you to have a fixed price, knowing how much you are going to be charged each month, consider fixed price machine instances.

#### [Centralised logging of AWS Lambda](https://hackernoon.com/centralised-logging-for-aws-lambda-b765b7ca9152) Functions

You should also be sending your logs to an aggregator and not in your execution time. What ever your function writes to stdout is captured by Lambda and sent to Cloudwatch Logs asynchronously, that means consumers of the function will not take a latency hit and you will not take a cost hit. Cloudwatch Logs can then be streamed to AWS Elasticsearch which may or may not be [stable enough](https://read.acloud.guru/things-you-should-know-before-using-awss-elasticsearch-service-7cd70c9afb4f) for you. Other than that, there are not that many good options on AWS yet, beside sending to Lambda which of course could also end up costing you compute and being another DoS vector. 

#### Frameworks

The following are supposed to make the exercise of deploying your functions to the cloud easier:

**[Serverless](https://serverless.com/framework/)** along with a large collection of [awesome-serverless](https://github.com/JustServerless/awesome-serverless) resources on github.

The Serverless framework currently has the following provider APIs:

* AWS
* Microsoft Azure
* IBM OpenWhisk
* GCP
* Kuberless

**[Claudia.JS](https://claudiajs.com/)**: Specific to AWS and only covers Node.js. Authored by Gojko Adzic, which if you have been in the industry as a Software Engineer for long, this fact alone may be enough to sell it.

**[Zappa](https://www.zappa.io/)**: Specific to AWS and only covers Python.


### Infrastructure and Configuration Management

Storing infrastructure and configuration as code is an effective measure for many mundane tasks that people may still be doing that are prone to human error. This means we can sequence specific processes, debug them, source control them, and achieve repeatable processes that are far less likely to have security defects in them, providing those that are writing the automation are sufficiently skilled and knowledgeable on the security topics involved. This also has the positive side-effect of speeding processes up.

When an artefact is deployed, how do you know that it will perform the same in production that it did in development? That is what a staging environment is for. A staging environment will never be exactly the same as production unless your infrastructure is codified, this is another place where containers can help, Using containers, you can test the new software anywhere and it will run the same, providing its environment is the same and in the case of
containers the environment is the image, and that is what you ship. The container goes from the developers machine once tested, to the staging environment then to production. The staging environment in this case is less important than it used to be, and is just responsible for testing your infrastructure, which should all be built from source controlled infrastructure as code, so it is guaranteed repeatable.

1. Pick off repetitious, booring, prone to human error and easily automatable tasks that your team(s) have been doing. Script and source control them
    * **Configuration management**: One of the grass root types of tooling options required here is a configuration management tool. I have found Ansible to be excellent. If you use Docker containers, most of the configuration management is already taken care of in the [`Dockerfile`](#vps-countermeasures-docker-the-dDefault-user-is-root). The [`docker-compose.yml`](#nodegoat-docker-compose.yml) file, orchestration platforms and tooling take us to "infrastructure as code"
    * **Infrastructure management** :Terraform is one of the tools that can act as a simple version control for cloud infrastructure. One of my co-hosts (lead host Robert Blumen) on Software Engineering Radio ran an excellent [podcast on Terraform](http://www.se-radio.net/2017/04/se-radio-episode-289-james-turnbull-on-declarative-programming-with-terraform/)
    * Ultimately we want to get to the place where we can have an entire front-end and back-end (if Web) deployment automated. There are many things this depends on. A deployment must come from a specific source branch that is production ready. A production ready branch is that way because another branch leading into it has passed all the quality checks mentioned in the Agile Development and Practises subsection of the Process and Practises chapter of [Fascicle 0](https://leanpub.com/holistic-infosec-for-web-developers/), plus others such as [continuous integration](https://blog.binarymist.net/2014/02/22/automating-specification-by-example-for-net/)
2. Once a few of the above tasks are done, start stringing them together in pipelines
3. Schedule execution of any/all of the above

### AWS

As mentioned in the [risks subsection](#cloud-identify-risks-aws) for AWS, the [CIS AWS Foundations document](https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf) is well worth following along with.

#### Password-less sudo

Add password to the default user.

We have covered the people aspects along with exploitation techniques of Weak Password Strategies in the People chapter of [Fascicle 0](https://leanpub.com/holistic-infosec-for-web-developers/)

We have covered the technical aspects of password strategies in the [Review Password Strategies](#vps-countermeasures-disable-remove-services-harden-what-is-left-review-password-strategies) subsection of the VPS chapter


%% AWS general (security enhancing services and features)
%%  https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf
%%  https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html
%%  https://cloudonaut.io/aws-security-primer/





#### Additional Tooling {#cloud-countermeasures-aws-additional-tooling} 



* [Security Monkey](https://github.com/Netflix/security_monkey/): Monitors AWS and GCP accounts for policy changes, and alerts on insecure configurations, conceptually similar to AWS Config, as discussed in the [Violations of Least Privilege](#cloud-countermeasures-violations-of-least-privilege) countermeasures subsection. Security Monkey is free and open source. Although not strictly security related, the [Simian Army](https://github.com/Netflix/SimianArmy/wiki) tools from Netflix are also well worth mentioning if you are serious about doing things the right way in AWS. They include:
  * [Chaos Monkey](https://github.com/Netflix/SimianArmy/wiki/Chaos-Monkey)
  * [Janitor Monkey](https://github.com/Netflix/SimianArmy/wiki/Janitor-Home)
  * [Conformity Monkey](https://github.com/Netflix/SimianArmy/wiki/Conformity-Home)
* [CloudSploit](https://cloudsploit.com/): Aims to solve the problem of missconfigured AWS accounts. Background scanning through hundreds of resources, settings, and activity logs looking for potential issues. Their blog also has some good resources on it. Scan reports include in-depth remediation steps. Has a free and paid hosted tiers. Auto scanning scheduling for the paid plans. Is open source on [github](https://github.com/cloudsploit/scans)
* [Amazon Inspector](https://console.aws.amazon.com/inspector/): At this time only targets EC2 instances. Inspector agent needs to be installed on all target EC2 instances
* [Awesome AWS](https://github.com/donnemartin/awesome-aws) has many useful resources


### GCP 



#### Additional Tooling {#cloud-countermeasures-gcp-additional-tooling} 



* [Security Monkey](https://github.com/Netflix/security_monkey/): As discussed in the AWS countermeasures [Additional Tooling](#cloud-countermeasures-aws-additional-tooling) subsection

### Heroku

### Azure



## 4. SSM Risks that Solution Causes

_Todo_

### CSP Evaluation {#cloud-risks-that-the-solution-causes-csp-evaluation}

1. 
2. 
3. 
4. There are also a collection of items that need to be addressed in the Logging subsection of the [CIS AWS Foundations document](https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf)

### Violations of Least Privilege




* **Running services as root**: Removing permissions, once a service has been running as root, may make something stop working
* **Configuration Settings Changed Ad Hoc**: Because features, and settings will be changed on an ad hoc basis, and change control just like security is often seen as an annoyance, if it can be bypassed, it will be, and those changes will be forgotten.  
   
   AWS as many other CSPs provide many great tools to help us harden our configuration and infrastructure. If we decide not to take [our part](#cloud-countermeasures-shared-responsibility-model-csp-customer-responsibility) of the shared responsibility model seriously, then it is just time before we are compromised
* **Machine Instance Access To Open**: You may think that having the source IP address that people can administer your machine instances from locked down to a single IP address will make it difficult for workers outside of a single office to connect to your machine instances




### Storage of Secrets

#### Credentials and Other Secrets

##### Entered by People (manually)

%% Discuss how KeePass can be broken

##### Entered by Software (automatically) {#cloud-risks-that-solution-causes-storage-of-secrets-credentials-and-other-secrets-entered-by-software}

In order for an application or service to access the secrets provided by one of these tools, it must also be able to authenticate itself, which means we have replaced the secrets in the configuration file with another secret to access that initial secret, thus making the whole strategy not that much more secure, unless you are relying on obscurity. This is commonly known as the [secret zero](https://news.ycombinator.com/item?id=9453754) problem.

### Serverless

Many of the gains that attract people to the serverless paradigm are imbalanced by the extra complexities required to understand in order to secure the integration of the components. There is a real danger that Developers fail to understand and implement all the security countermeasures required to get them to a similar security stand point that they enjoyed having their components less distributed and running in long lived processes.

#### Frameworks

These frameworks may lead the Developer to think that the framework does everything for them, it does not, so using a framework is just another thing to learn.


#### Functions

API keys are great, but not so great when they reside in untrusted territory, which in the case of the web, is any time your users need access to your API, so anyone permitted to become a user has permission to send requests to your API.

Do not depend on client side API keys for security, this is a very thin layer of defence. You can not protect API keys sent to a client over the internet. Yes, we have TLS, but that will not stop an end user masquerading as someone else.

Also consider anything you put in source control even if not public, already compromised. Your source control is only as strong as the weakest password of any given team member at best. You have also got build pipelines that are often leaking, along with other leaky mediums such as people.

AWS as the largest CSP is a primary target for attackers.

## 5. SSM Costs and Trade-offs

_Todo_

### Violations of Least Privilege


* **Running services as root**: Always start with the minimum permissions possible and add if necessary, it is far easier to add than to remove
* **Configuration Settings Changed Ad Hoc**: Remember detection works where prevention fails, that means in this case, where your change control fails, because it is decided not to use it, you need something to detect changes and notify someone that cares. For this, there are also other options specifically designed for this. For a collection of such tooling, review the [Tooling](#cloud-countermeasures-aws-additional-tooling) sections.  
   
   You need to have these tools set-up so that they are [continually auditing](https://blog.cloudsploit.com/the-importance-of-continual-auditing-in-the-cloud-8d22e0554639) your infrastructure and notifying the person(s) responsible and/or that care about the issues, rather than having people continually manually reviewing settings, permissions and so forth
* **Machine Instance Access To Open**: Set-up a bastion host and lock the source IP address down to the public facing IP address of your bastion host required to access your machine instances. I discussed locking the source IP address down in the [Hardening SSH](#vps-countermeasures-disable-remove-services-harden-what-is-left-ssh-hardening-ssh) subsection of the VPS chapter.  
   
   Your bastion host will be hardened as discussed throughout the VPS chapter. All authorised workers can VPN to the bastion host and SSH from there, or just SSH tunnel from where ever they are on the planet through the bastion host via port forward and to any given machine instances.  
   
   If you have Windows boxes you need to reach, you can tunnel RDP through your SSH tunnel as I have [blogged about](https://blog.binarymist.net/2010/08/26/installation-of-ssh-on-64bit-windows-7-to-tunnel-rdp/).  
   
   A second option with SSH (using the `-A` option) is to, rather than tunneling, hop from the bastion host to your machine instances by forwarding the private key, which does provide the risk that someone could gain access to your forwarded SSH agent connection, thus being able to use your private key while you have an SSH connection established. `ssh-add -c` can provide some protection with this.  
   
   If you do decide to use the `-A` option, then you are essentially considering your bastion host as a trusted machine. I commented on the `-A` option in the [Tunneling SSH](#vps-countermeasures-disable-remove-services-harden-what-is-left-ssh-tunneling-ssh) subsection of the VPS chapter. There is plenty of good [documentation](https://cloudacademy.com/blog/aws-bastion-host-nat-instances-vpc-peering-security/) around setting up the bastion host in AWS. AWS provide some [Best Practices](https://docs.aws.amazon.com/quickstart/latest/linux-bastion/architecture.html#best-practices) for security on bastion hosts, and also [discuss](https://aws.amazon.com/blogs/security/how-to-record-ssh-sessions-established-through-a-bastion-host/) recording the SSH sessions that your users establish through a bastion host for auditing purposes

### Storage of Secrets

#### Credentials and Other Secrets

##### Entered by People (manually)



##### Entered by Software (automatically)

All of security is a deception. By embracing defence in depth, we make it harder to break into systems, which just means it takes longer and someone has to think a little harder. There is no secure system. You decide how much it is worth investing to slow your attackers down. If your attacker is 100% determined and well resourced, they will own you eventually no matter what you do.