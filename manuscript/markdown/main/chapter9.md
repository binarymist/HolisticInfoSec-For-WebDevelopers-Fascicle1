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

We are blindly trusting huge amounts of IP to CSPs. In fact, I have worked for many customers that insist on putting everything in The Cloud without much thought. Some have even said that they are not concerned with security. The problem is, they do not understand what is at risk. They may wonder why their competitor beats them to market as their progress and plans are intercepted. The best book I have read to date that reveals the problem with this blind yielding of everything is Bruce Schneier Data and Goliath. This is an eye opening canon of what we are doing and what its results are going to be.

When ever you see that word "trust", you are yielding control to the party you are trusting. When you trust an entity with your assets, you are giving them control. Are your assets their primary concern, or is it maximising their profits by using you and/or your data as their asset?

If you decide to use an external cloud provider, you need to be aware that what ever goes into The Cloud is almost completely out of your control, you may not be able to remove it once it is there, as you may not have visibility into whether or not the existing data is really removed from The Cloud.

### Data

If you deal with sensitive customer data, then you have an ethical and legal responsibility for it. If you are putting sensitive data in The Cloud then you could very well be being irresponsible with your responsibility. You may not even retain legal ownership of it.









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
2. [Application Security](#web-applications), ultimately leading back to shortcomings in people: Lack of skills, experience, engagement, etc
3. Configuring the Infrastructure and/or platform components: Again leading back to people defects

but all to often the customers responsibility is neglected, which renders The Cloud no better for the customer in terms of security.

> The primary problem with The Cloud is: Customers have the misconception that someone else is taking care of all their security. That is not how the shared security model works though. Yes the CSP is probably taking care of the infrastructure security, but other forms of security such as I just listed above, are even more important than before the shift to The Cloud, this is because these items are now the lowest hanging fruit for the attacker.

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
   
   No CSP is going to last forever, termination or migration is inevitible, it is just a matter of when.  
   
6. Where abouts do your servers, processes and data reside physically?  
   
   As we discuss a little later in the Cloud Services Provider vs In-house subsection of Countermeasures, your data is governed by different people and jurisdictions depending on where it physically resides. CSPs have data centres in different countries and jurisdictions, each having different laws around data security.


7. Who can view the data I store in the cloud?  
   
   Who has access to view this data? What checks and controls are in place to make sure that this data can not be exfiltrated?  
   
8. What is your Service Level Agreement (SLA) for uptime?  
   
   Make sure you are aware of what the uptime promises mean in terms of real time. Some CSPs will allow 99.95% uptime if you are running on a single availability zone, but closer to 100% if you run on multiple availability zones.  
   
   CSPs will often provide credits for the downtime, but these credits in many cases may not cover the losses you encounter during hot times  
   
9. Are you ISO/IEC 27001:2013 Certified? If so, what is within its scope?  
   
   If the CSP can answer this with a "everything" and prove it, they have done a lot of work to make this possible, this shows a level of commitment to something security related. Just be aware, as with any certification, it is just that, it does not prove a lot  
   
10. Do you allow your customers to carry out regular penetration testing of production and/or test environments, also allowing the network to be in-scope?  
    
    CSPs that allow penetration testing of their environments demonstrate that they embrace transparency and openness, if their networks stand up to penetration tests, then obviously take security seriously also. Ideally this is what you are looking for. CSPs that do not permit penetration testing of their environments, are usually trying to hide the fact that either they know they have major insecurities, skill shortages in terms of security professionals, or are unaware of where their security stature lies, and not willing to have their faults demonstrated  
   
11. Do you have bug bounty programmes running, if so, what do they look like?  
    
    This is another example if the programme is run well, that the CSP is open, transparent about their security faults and willing to mitigate them as soon as possible





Now we will focus on a collection of the largest providers.

#### AWS

%%    Kiwicon 10 talk "Hacking AWS end to end". Slide-deck here: https://github.com/dagrz/aws_pwn/blob/master/miscellanea/Kiwicon%202016%20-%20Hacking%20AWS%20End%20to%20End.pdf, along with readme and code.

##### Password-less sudo

Password-less sudo. A low privileged user can operate with root privileges. This is essentially as bad as root logins.

%% https://serverfault.com/questions/615034/disable-nopasswd-sudo-access-for-ubuntu-user-on-an-ec2-instance





#### Google 

%% https://cloud.google.com/

#### Heroku

%% http://stackoverflow.com/questions/9802259/why-do-people-use-heroku-when-aws-is-present-whats-distinguishing-about-heroku

#### Azure

%% https://docs.microsoft.com/en-us/azure/security/azure-security-iaas

#### Etc.







### [Cloud Service Provider vs In-house](https://speakerdeck.com/binarymist/does-your-cloud-solution-look-like-a-mushroom) {#cloud-identify-risks-cloud-service-provider-vs-in-house}

A question that I hear frequently is: "What is more secure, building and maintaining your own cloud, or trusting a CSP to take care of security for you?". That is a defective question, as discussed in the [Shared Responsibility Model ](#cloud-identify-risks-shared-responsibility-model) subsections. There are [some aspects](#cloud-identify-risks-shared-responsibility-model-csp-customer-responsibility) of security that the CSP has no knowledge of, and only you as the CSP customer can work security into those areas.

Going with a CSP means you are depending on their security professionals to design, build and maintain the infrastructure, frameworks, hardware and platforms. Usually the large CSPs will do a decent job of this. If you go with designing, building, and maintaining your own in-house cloud, then you will also be leveraging the skills of those that have created the cloud components you decide to use, but you will be responsible for the following along with many aspects of how these components fit together and interact with each other:

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

The smaller CSPs in many cases suffer from the same resourcing issues that many business's do in regards to having solid security skills and engagement of their workers to apply security in-house. In general, in order to benefit from the Shared Responsibility Model of the CSP, it pays to go with one of the larger CSPs.

#### EULA

Most CSPs will have End User License Agreements (EULA) that have the right to change at any time, do you actually read when you sign up for a cloud service?

#### Giving up Secrets {#cloud-identify-risks-cloud-service-provider-vs-in-house-giving-up-secrets}

In many cases, hosting providers can be, and in many cases are [forced](http://www.stuff.co.nz/business/industries/67546433/Spies-request-data-from-Trade-Me) by governing authorities to [give up](https://www.stuff.co.nz/business/95116991/trade-me-fields-thousands-of-requests-for-member-information) your and your customers secrets. This is a really bad place to be in and it is very common place now, you may not even know it has happened.  
The NZ Herald [covered a story](http://www.nzherald.co.nz/nz/news/article.cfm?c_id=1&objectid=11481516) in which Senior lawyers and the Privacy Commissioner have told the Herald of concerns about the practise which sees companies coerced into giving up information to the police. Instead of seeking legal order, police have asked companies to hand over information to assist with the "maintenance of the law", threatened them with prosecution if they tell the person about whom they are interested and accept data with no record keeping to show how often requests are made. The request from police carries no legal force at all yet is regularly complied with.

#### Location of Data

As touched on in the CSP Evaluation questions, in many cases CSPs are outsourcing their outsourced services to several providers deep. They do not even have visibility themselves. Often the data is hosted in other jurisdictions. Control is lost. 

#### Vendor lock-in

_Todo_ vvv.

Reliance on vendor guarantees

#### Possible Single Points of Failure

_Todo_ vvv.

Single points of failure  
Loss of availability zone







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

* Missing a step in a sequence (often performed manually)
* Lacking the required knowledge
* Lacking the required desire / engagement

### Application Security

_Todo_ Add in SER podcast

With the shift to The Cloud, AppSec has become more important than it used to be, recognised and discussed:

* Previously in this chapter by the number two issue of the [CSP Customer Responsibility](#cloud-identify-risks-shared-responsibility-model-csp-customer-responsibility) of the Shared Responsibility Model
* In the [Application Security](#vps-countermeasures-docker-application-security) subsection of Docker in the VPS chapter
* Entirely in the next chapter (Web Applications)

The reason being, that in general, as discussed in the [Shared Responsibility Model](#cloud-identify-risks-shared-responsibility-model), the dedicated security resources, focus, awareness, engagement of our major CSPs are usually greater than most organisations have access to. This pushes the target areas for the attackers further up the tree. People followed by AppSec are now usually the lowest hanging fruit for the attackers.

### Network Security

The network between the components you decide to use in The Cloud will almost certainly no longer be administered by your network administrator(s), but rather by you as a Software Engineer. That is right, networks are now [expressed as code](#infrastructure-and-configuration-management), and because coding is part of your responsibility as a Software Engineer, the network will more than likely be left to you to design and code, so you better have a good understanding of [Network Security](#network).

### Single User Root

The default on AWS EC2 instances is to have a single user (root). There is no audit trail with a bunch of developers all using the same login. When ever anything happens on any of these machine instances, it's always the fault of user `ubuntu`. There are so many things wrong with this approach.

%% Todo: verify this is the default



### Violations of [Least Privilege](#web-applications-countermeasures-management-of-application-secrets-least-privilege)

In most organisations I work for as an architect or engineer, I see many cases of violating the principle of least privilege. 

### Storage of Secrets

#### Private Key Abuse

[SSH](#vps-countermeasures-disable-remove-services-harden-what-is-left-ssh) key-pair auth is no better than password auth if it is abused in the following way, in-fact it may even be worse. What I have seen some organisations do is store a single private key with no pass-phrase for all of their EC2 instances in their developer wiki. All or many developers have access to this. There are a number of things wrong with this. 

* Private key is not private if it is shared amongst the team
* No pass-phrase, means no second factor of authentication
* Because there is only one user (single key-pair) being used on the
VPSs, there is also no audit trail
* The weakest link is the weakest wiki password of all the developers, and we all know how weak that is likely to be, with a bit of reconnaissance, probably guessable in a few attempts without any password profiling tools. I discussed this and demonstrated a collection of password profiling tools in the "Weak Password Strategies" subsection of the People chapter of [Fascicle 0](https://leanpub.com/holistic-infosec-for-web-developers/). Once the attacker has the weakest password, then they own all of the EC2 instances, or any resource that is using key-pair authentication. If the organisation is failing this badly, then they almost certainly will not have any password complexity constraints on their wiki either

Most developers will also blindly accept what they think are the server key fingerprints without verifying them, thus opening themselves up to a MItM attack, as discussed in the VPS chapter under the [SSH subsection](#vps-countermeasures-disable-remove-services-harden-what-is-left-ssh-establishing-your-ssh-servers-key-fingerprint). This very quickly moves from just a technical issue to a cultural one. People are trained to just accept that the server is who it says it is, the fact that they have to verify the fingerprint is essentially a step that gets in their way.

#### Credentials

Sharing accounts, especially super-user

Doesn't take much from here to have your accounts hijacked


### Serverless

%% Serverless https://serverless.com/
%%    AWS Lambda
%%       https://aws.amazon.com/lambda/
%%       http://www.alldaydevops.com/blog/taking-lambda-to-the-max
%%    Google CloudFunctions https://cloud.google.com/functions/
%%    Azure Functions https://azure.microsoft.com/en-us/services/functions/
%% What is to stop DoS attacks and costing the renter megabucks?
%% https://devops.com/5-common-misconceptions-serverless-technology/

%% https://thenewstack.io/security-serverless-gets-better-gets-worse/

### Infrastructure and Configuration Management {#infrastructure-and-configuration-management}

%% Discuss Infrastsructure as Code (IaC) with the likes of Terraform
%%    Quite a bit of thought gone into this in the SER review of James Turnbull, show #289: https://groups.google.com/forum/?hl=en#!topic/seradio/5OTTZMIUAns
%%    Also discussed testing your IaC with the likes of Test Kitchen.
%%    Also discussed Puppet, and the lower level configuration management tools like Ansible, which I've documented for Mobidiction.

## 3. SSM Countermeasures

Revisit the Countermeasures subsection of the first chapter of [Fascicle 0](https://leanpub.com/holistic-infosec-for-web-developers).

### Shared Responsibiltiy Model

_Todo_

#### CSP Responsibility

_Todo_

#### CSP Customer Responsibility

If you leverage The Cloud, Make sure the following aspects of security are all at an excellent level:

1. People Security: Discussed in Fascicle 0 under the People chapter
2. [Application Security](#web-applications): Discussed in the Web Applications chapter. The move to application security was also [discussed](#vps-countermeasures-docker-application-security) in the VPS chapter as a response of using Docker containers
3. Configuring the Infrastructure and/or platform components: Usually CSP specific, but I cover some aspects in this chapter

### CSP Evaluation

Once you have sprung the questions from the [CSP Evaluaton](#cloud-identify-risks-csp-evaluation) subsection in the Identify Risks subsection on your service provider and received their answers, you will be in a good position to feed these into the following subsections.


1. Do you keep a signed audit log on which users performed which actions and when, via UIs and APIs?  
   
   _Todo_ What offerings are available: https://aws.amazon.com/cloudtrail/
   
2. There is this thing called the shared responsibility model I have heard about between CSPs and their customers. Please explain what your role and my role is in the protection of my and my customers data?  
   
   _Todo_
   
3. Do you encrypt all communications between servers within your data centres?  
   
   I've discussed in many places that we should be aiming to have all communications on any given network encrypted. This is usually not to onerous to establish on your own network, but if it does not already exist on the CSPs network that you are evaluating, you will probably not be able to do anything about it, and once an attacker has access to the internal network, they can listen to the conversations happening. You can provide encryption between the services you offer and your customers because the Internet is open, but this is not usually the case with CSPs, so if they do not encrypt all internal traffic you could very well be at risk. This is part of the CSPs shared security model that they may or not provide  
   
4. Do you provide access to logs, if so what sort of access to what sort of logs?  
   
   If you don't have access to logs, then you are flying blind, you have no idea what is happening around you. How much does the CSP strip out of the logs before they allow you to view them? It is really important to weigh up what you will have visibility of, what you will not have visibility of, in order to work out where you may be vulnerable. Can the CSP provide guarantees that those vulnerable areas are taken care of by them? Make sure you are comfortable with the amount of visibility you will and will not have up front, as unless you make sure blind spots are covered, then you could be unnecessarily opening yourself up to be attacked  
   
5. What is your process around terminating my contract with you and/or moving to another CSP?  
   
   Make sure you have an exit and/or migration strategy planned as part of entering into an agreement with your chosen CSP. Make sure you have as part of your contract with your chosen CSP:  
   
   * What the CSP is going to do to assist in terminating and/or migrating your data and services from the CSP
   * How does the CSP deal with your data and services when your contract is terminated, does it lie around somewhere for some time? Ideally be certain that it is completely purged so that it is just not available on their network at all, if it remains for a duration, is it discoverable by an attacker? Will they let you test this? If not, they are probably trying to hide something
   * Does the CSP have third parties that audit, test and certify the completeness of the termination/migration procedure  
   
6. Where abouts do your servers, processes and data reside physically?  
   
   Do not assume that your data in The Cloud in another country is governed by the same laws as it is in your country. Make sure you are aware of the laws that apply to your data, depending on where it is.

7. Who can view the data I store in the cloud?  
   
   _Todo_
   
8. What is your Service Level Agreement (SLA) for uptime?  
   
   Count this cost before signing up to the CSP  
   
9. Are you ISO/IEC 27001:2013 Certified? If so, what is within its scope?  
   
   _Todo_
   
10. Do you allow your customers to carry out regular penetration testing of production and/or test environments, also allowing the network to be in-scope?  
    
    You will not need to go through this process of requesting permission from your own company to carry out penetration testing, and if you do, there should be a lot fewer restrictions in place  
   
11. Do you have bug bounty programmes running, if so, what do they look like?  
    
    If the CSP is of a reasonable size and is not already running bug bounties, this is a good sign that security could be taken more seriously.






#### AWS

%% AWS: CIS Benchmark


##### Password-less sudo

Add password to the default user.

We have covered the people aspects along with exploitation techniques of Weak Password Strategies in the People chapter of [Fascicle 0](https://leanpub.com/holistic-infosec-for-web-developers/)

We have covered the technical aspects of password strategies in the [Review Password Strategies](#vps-countermeasures-disable-remove-services-harden-what-is-left-review-password-strategies) subsection of the VPS chapter


#### Google 

#### Heroku

#### Azure

#### Etc.



### [Cloud Service Provider vs In-house](https://speakerdeck.com/binarymist/does-your-cloud-solution-look-like-a-mushroom)

It depends on the CSP, and many things about your organisation. Each CSP does things differently, has strengths and weaknesses in different areas of the shared security model, has different specialities, is governed by different people and jurisdictions (USA vs Sweden for example), some are less security conscious than others. The largest factor in this question is your organisation. How security conscious and capable of implementing a secure cloud environment are your workers.

You can have a more secure cloud environment than any CSP if you decide to do so and have the necessary resources to build it. If you don't decide to and/or don't have the necessary resources, then most well known CSPs will probably be doing a better job than your organisation.

Then you need to consider what you are using the given CSPs services for. If you are creating and deploying applications, then your applications will be a weaker link in the security chain, this is a very common case and one that is often overlooked. To attempt to address application security, I wrote the [Web Applications](#web-applications) chapter.

Your attackers will attack your weakest area first, in most cases this is not your CSP, but your organisations people due to lack of knowledge, passion, engagement, or a combination of them. If you have a physical premises, this can often be an easy target also. Usually application security follows closely after people security. This is why I have the Physical and People chapters in [Fascicle 0](https://leanpub.com/holistic-infosec-for-web-developers) of this book series, they are also the most commonly overlooked. The reason I added the Web Applications chapter last in this fascicle, was that I wanted to help you build a solid foundation of security in the other areas often overlooked before we addressed application security, and I also wanted it to be what sticks in your mind once you have read this fascicle.

Based on the threat modelling I hope you have done through each chapter, which was first introduced in [Fascicle 0](https://leanpub.com/holistic-infosec-for-web-developers) you should be starting to work out where cloud security rates on your list of risks to your assets. By the end of this chapter, you should have an even better idea.

#### Skills

The fate of your and your customers data is in your hands. If you have the resources to provide the necessary security then you are better off with an in-house cloud, if not, the opposite is true.  
If you go with an in-house cloud, you should have tighter control over the people creating and administering it, this is good if they have the necessary skills and experience, if not, then the opposite is true again.

#### EULA

You and any in-house cloud environment you establish is not subject to changing EULAs.

#### Giving up Secrets 

If you are using an in-house cloud and find yourself in a place where you have made it possible for your customers secrets to be read, and you are being forced by the authorities to give up secrets, you will know about it and be able to react appropriately, invoke your incident response team(s) and procedures.

#### Location of Data

If you use an in-house cloud, you decide where services & data reside.

#### Vendor lock-in

Vendor guarantees: Verify how water tight these are
Single points of failure, create reduncancy in services that we simply can not do without  
Multiple availability zones  
Consider vendor agnostic


#### Possible Single Points of Failure









### Review Other Chapters {#cloud-countermeasures-review-other-chapters}

As I mentioned in the [Identify Risks](#cloud-identify-risks-review-other-chapters) Review Other Chapters subsection, please make sure you are familiar with the related concepts discussed.

### People



### Application Security

_Todo_

### Network Security

_Todo_

### Single User Root

_Todo_ more research required here vvv.

As part of the VPS and container builds, there should be [specific users created](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/managing-users.html) for specific jobs, every user within your organisation that needs VPS access should have their own user account on every VPS (this all needs to be automated). With Docker, I discussed how this is done in the [Dockerfile](#vps-countermeasures-docker-the-dDefault-user-is-root).

Research and document the options we have for AWS IAM segregation, and drive a least provilage policy around this, implement [multi-factor authentication](https://aws.amazon.com/iam/details/mfa/) which will help with poor password selection of users.

### Violations of [Least Privilege](#web-applications-countermeasures-management-of-application-secrets-least-privilege)

### Storage of Secrets

%% Cover password vaults such as for Terraform and Ansible vaults, storing secrets with docker containers as I discussed on PB redmine wiki
%%   https://www.vaultproject.io/docs/secrets/aws/index.html
%%   https://www.vaultproject.io/docs/auth/aws.html

#### Private Key Abuse



There are many ways to harden SSH as we discussed in the [SSH](#vps-countermeasures-disable-remove-services-harden-what-is-left-ssh) subsection in the VPS chapter. Usually the issue will lie with lack of knowledge, desire and a dysfunctional [culture](https://blog.binarymist.net/2014/04/26/culture-in-the-work-place/) in the work place. You will need to address the people issues before looking at basic SSH hardening techniques.

Ideally SSH access should be reduced to a select few. Most of the work we do now by SSHing should be automated. If you have a look at all the commands in history on any of the VPSs, most of the commands are either deployment or
manual monitoring which should all be automated.

Every user should have their [own key-pair](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-key-pairs.html), the private part should always be private, not shared on your developer wiki or anywhere else for that matter. The public part can be put on every server that the user needs access to.

_Todo_ more research required here ^^^ vvv find a better way.

Follow the procedure I laid out for [Establishing your SSH Servers Key Fingerprint](#vps-countermeasures-disable-remove-services-harden-what-is-left-ssh-establishing-your-ssh-servers-key-fingerprint) in the VPS chapter, and make it organisational policy. We should never blindly just accept key fingerprints. The key fingerprints should be stored in a relatively secure place, so that only trusted parties can modify them. What I'd like to see happen, is that as part of the server creation process, the place (probably the wiki) that specifies the key fingerprints is automatically updated by something on the VPS that keeps watch of the key fingerprints. Something like Monit would be capable of the monitoring and firing a script to do this.

#### Credentials

_Todo_ vvv.


Create multiple accounts with least privileges required for each user  
Create and enforce password policies


Password managers

### Serverless

### Infrastructure and Configuration Management

Storing infrastructure and configuration as code is an effective measure for many mundane tasks that people may still be doing that are prone to human error. This means we can sequence specific processes, debug them, source control them, and achieve repeatable processes that are far less likely to have security defects in them, providing those that are writing the automation are sufficiently skilled and knowledgeable on the security topics involved. This also has the positive side-effect of speeding processes up.

When an artefact is deployed, how do you know that it will perform the same in production that it did in development? That is what a staging environment is for. A staging environment will never be exactly the same as production unless your infrastructure is codified, this is another place where containers can help, Using containers, you can test the new software anywhere and it will run the same, providing its environment is the same and in the case of
containers the environment is the image, and that is what you ship. The container goes from the developers machine once tested, to the staging environment then to production. The staging environment in this case is less important that it used to be, and is just responsible for testing your infrastructure, which should all be built from source controlled infrastructure as code, so it is guaranteed repeatable.

_Todo_ Discuss some of the other orchestration options below vvv.

1. Pick off repetitious, booring, prone to human error and easily automatable tasks that your team(s) have been doing. Script and source control them
    * **Configuration management**: One of the grass root types of tooling options required here is a configuration management tool. I have found Ansible to be excellent. If you use Docker containers, most of the configuration management is already taken care of in the [`Dockerfile`](#vps-countermeasures-docker-the-dDefault-user-is-root). The [`docker-compose.yml`](#nodegoat-docker-compose.yml) file, orchestration platforms and tooling take us to "infrastructure as code"
    * **Infrastructure management** :Terraform is one of the tools that can act as a simple version control for cloud infrastructure. One of my co-hosts (lead host Robert Blumen) on Software Engineering Radio ran an excellent [podcast on Terraform](http://www.se-radio.net/2017/04/se-radio-episode-289-james-turnbull-on-declarative-programming-with-terraform/)
    * Ultimately we want to get to the place where we can have an entire front-end and back-end (if Web) deployment automated. There are many things this depends on. A deployment must come from a specific source branch that is production ready. A production ready branch is that way because another branch leading into it has passed all the quality checks mentioned in the Agile Development and Practises subsection of the Process and Practises chapter of [Fascicle 0](https://leanpub.com/holistic-infosec-for-web-developers/), plus others such as [continuous integration](https://blog.binarymist.net/2014/02/22/automating-specification-by-example-for-net/)
2. Once a few of the above tasks are done, start stringing them together in pipelines
3. Schedule execution of any/all of the above




## 4. SSM Risks that Solution Causes

_Todo_

## 5. SSM Costs and Trade-offs

_Todo_

