# Additional Resources {#additional-resources}

## [VPS](#vps)

[**Details**](https://community.rapid7.com/community/metasploit/blog/2013/03/09/psexec-demystified) on the Metasploit PSExec module.

[**Distributed Computing Environment / Remote Procedure Call**](https://en.wikipedia.org/wiki/DCE/RPC).

## [Network](#network)

## [Cloud](#cloud)

## [Web Applications](#web-applications)

**OWASP canonical XSS resource**  
https://www.owasp.org/index.php/Cross-site_Scripting_%28XSS%29

**Hashcat rules based** attack  
[http://hashcat.net/wiki/doku.php?id=rule_based_attack](http://hashcat.net/wiki/doku.php?id=rule_based_attack)

**Details that helped setup NodeJS logging**:  
[https://gist.github.com/rtgibbons/7354879](https://gist.github.com/rtgibbons/7354879)  
[https://thejsf.wordpress.com/2015/01/18/node-js-logging-with-winston/](https://thejsf.wordpress.com/2015/01/18/node-js-logging-with-winston/)

**Application logging to syslog server** on another machine:  
[http://unix.stackexchange.com/questions/67250/where-does-rsyslog-keep-facility-local0](http://unix.stackexchange.com/questions/67250/where-does-rsyslog-keep-facility-local0)  
[http://wiki.rsyslog.com/index.php/Very_simple_config_--_starting_point_for_modifications](http://wiki.rsyslog.com/index.php/Very_simple_config_--_starting_point_for_modifications)

**Or the new style configuration**:  
[http://www.rsyslog.com/doc/v8-stable/configuration/modules/imudp.html](http://www.rsyslog.com/doc/v8-stable/configuration/modules/imudp.html)

**Syslog compatible protocol severities**:  
[https://wiki.gentoo.org/wiki/Rsyslog#Severity](https://wiki.gentoo.org/wiki/Rsyslog#Severity)

**Monit is an excellent tool** for the dark cockpit approach:  
[http://blog.binarymist.net/2015/06/27/keeping-your-nodejs-web-app-running-on-production-linux/#monit](http://blog.binarymist.net/2015/06/27/keeping-your-nodejs-web-app-running-on-production-linux/#monit)

**Experience with Monit**:  
[http://blog.binarymist.net/2015/06/27/keeping-your-nodejs-web-app-running-on-production-linux/#getting-started-with-monit](http://blog.binarymist.net/2015/06/27/keeping-your-nodejs-web-app-running-on-production-linux/#getting-started-with-monit)

**statsd source code**:  
[https://github.com/etsy/statsd/](https://github.com/etsy/statsd/)

**One of the ways we can generate statistics for our statsd daemon** is by using one of the many language specific statsd clients  
[https://github.com/etsy/statsd/wiki#client-implementations](https://github.com/etsy/statsd/wiki#client-implementations)

**First statsd spec for metric types**:  
[https://github.com/b/statsd_spec/blob/master/README.md](https://github.com/b/statsd_spec/blob/master/README.md)  
**Current, or at least more recent statsd spec** for metric types:  
[https://github.com/etsy/statsd/blob/master/docs/metric_types.md](https://github.com/etsy/statsd/blob/master/docs/metric_types.md)

**I would recommend NSubstitute** instead if you were looking for a mocking framework for .NET.  
[http://blog.binarymist.net/2013/12/14/evaluation-of-net-mocking-libraries/](http://blog.binarymist.net/2013/12/14/evaluation-of-net-mocking-libraries/)

**Information on how jQuery plugins plugin**  
[https://learn.jquery.com/plugins/](https://learn.jquery.com/plugins/)

**jQuery Validation** documentation  
[http://jqueryvalidation.org/documentation/](http://jqueryvalidation.org/documentation/)

[http://jqueryvalidation.org/validate](http://jqueryvalidation.org/validate)

[http://jqueryvalidation.org/jQuery.validator.addMethod](http://jqueryvalidation.org/jQuery.validator.addMethod)

[http://jqueryvalidation.org/rules](http://jqueryvalidation.org/rules)

**express-form**  
[https://github.com/freewil/express-form](https://github.com/freewil/express-form)

**Recording and testing user time expenditure**

[http://www.smashingmagazine.com/2011/03/in-search-of-the-perfect-captcha/#recording-user-time-expenditure](http://www.smashingmagazine.com/2011/03/in-search-of-the-perfect-captcha/#recording-user-time-expenditure)

[http://stackoverflow.com/questions/8472/practical-non-image-based-captcha-approaches](http://stackoverflow.com/questions/8472/practical-non-image-based-captcha-approaches)

**Blowfish cipher**  
https://en.wikipedia.org/wiki/Blowfish_%28cipher%29

**PBKDF2**  
[https://en.wikipedia.org/wiki/PBKDF2](https://en.wikipedia.org/wiki/PBKDF2)

**Key Derivation Function**  
[https://en.wikipedia.org/wiki/Key_derivation_function](https://en.wikipedia.org/wiki/Key_derivation_function) (KDF)

**bcrypt**  
[https://en.wikipedia.org/wiki/Bcrypt](https://en.wikipedia.org/wiki/Bcrypt)

**Cryptographic hash function**  
[https://en.wikipedia.org/wiki/Cryptographic_hash_function](https://en.wikipedia.org/wiki/Cryptographic_hash_function): MD5, SHA1, SHA2, etc

**Key stretching**  
[https://en.wikipedia.org/wiki/Key_stretching](https://en.wikipedia.org/wiki/Key_stretching)

**scrypt**  
[https://en.wikipedia.org/wiki/Scrypt](https://en.wikipedia.org/wiki/Scrypt)

**bcrypt brute-forcing** becoming feasible with well ordered rainbow tables  
[http://www.openwall.com/presentations/Passwords13-Energy-Efficient-Cracking/Passwords13-Energy-Efficient-Cracking.pdf](http://www.openwall.com/presentations/Passwords13-Energy-Efficient-Cracking/Passwords13-Energy-Efficient-Cracking.pdf)  
[https://www.usenix.org/system/files/conference/woot14/woot14-malvoni.pdf](https://www.usenix.org/system/files/conference/woot14/woot14-malvoni.pdf)


**Password Cracking Strategy**  
[http://null-byte.wonderhowto.com/how-to/hack-like-pro-crack-passwords-part-2-cracking-strategy-0156491/](http://null-byte.wonderhowto.com/how-to/hack-like-pro-crack-passwords-part-2-cracking-strategy-0156491/)

**Securing Sessions** via cookie attributes  
[https://www.owasp.org/index.php/HttpOnly](https://www.owasp.org/index.php/HttpOnly)

**Justin Searls talk** on consuming all the open source  
[http://blog.testdouble.com/posts/2014-12-02-the-social-coding-contract.html](http://blog.testdouble.com/posts/2014-12-02-the-social-coding-contract.html)

**Effecting Change**  
[http://blog.binarymist.net/2013/06/22/ideas-for-more-effective-meetings-and-presentations/](http://blog.binarymist.net/2013/06/22/ideas-for-more-effective-meetings-and-presentations/)



**Application Intrusion Detection and Response**

**Appsensor home**  
[http://appsensor.org/](http://appsensor.org/)

**Sample Appsensor applications**  
[https://github.com/jtmelton/appsensor/tree/master/sample-apps](https://github.com/jtmelton/appsensor/tree/master/sample-apps)

**Slide deck** from John Melton (AppSensor project lead)  
[http://www.slideshare.net/jtmelton/appsensor-near-real-time-event-detection-and-response](http://www.slideshare.net/jtmelton/appsensor-near-real-time-event-detection-and-response)

**Good podcast on OWASP 24/7 soundcloud**  
[https://soundcloud.com/owasp-podcast/john-melton-and-the-owasp-appsensor-project](https://soundcloud.com/owasp-podcast/john-melton-and-the-owasp-appsensor-project)
