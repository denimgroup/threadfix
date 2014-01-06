ThreadFix is a software vulnerability aggregation and management system that reduces the time it takes to fix software vulnerabilities. ThreadFix imports the results from dynamic, static and manual testing to provide a centralized view of software security defects across development teams and applications. The system allows companies to correlate testing results and streamline software remediation efforts by simplifying feeds to software issue trackers. By auto generating application firewall rules, this tool allows organizations to continue remediation work uninterrupted. ThreadFix empowers managers with
vulnerability trending reports that show progress over time, giving them justification for their efforts.

ThreadFix is licensed under the Mozilla Public License (MPL) version 2.0.

The main GitHub site for ThreadFix can be found here:

https://github.com/denimgroup/threadfix/

The Google Group for ThreadFix can be found here:

https://groups.google.com/forum/#!forum/threadfix

Instructions on setting up a development environment can be found here:

https://code.google.com/p/threadfix/wiki/EnvironmentSetup

Further documentation can be found online here:

https://code.google.com/p/threadfix/w/list

Submit bugs to the GitHub issue tracker:

https://github.com/denimgroup/threadfix/issues

ThreadFix is a platform with a number of components. Each subdirectory should have its own pom.xml files to support Maven builds. The major components in the repository include:

* **threadfix-cli-endpoints** - Command-line utility to calculate the attack surface of an application and print it to standard output. This relies on the Hybrid Analysis Mapping (HAM) capabilities in the threadfix-ham/ component.
* **theadfix-cli** - Command-line client for ThreadFix. This allows for scripting and automation of the ThreadFix platform.
* **threadfix-extras** - Experimental tools and ThreadFix proof-of-concept projects.
* **threadfix-ham** - Hybrid Analysis Mapping (HAM) technology used in ThreadFix that performs lightweight static analysis of application source code to calculate attack surfaces and map application attack surface endpoints to source code locations.
* **threadfix-ide-plugin** - IDE plugins for Eclipse and IntelliJ that pulls vulnerability data from ThreadFix and highlights these vulnerabilities in application source code.
* **threadfix-main** - Main ThreadFix server application. This is a Java-based Spring/Hibernate web application with associated web services. Other components of the ThreadFix platform call into the ThreadFix server.
* **threadfix-scanagent** - External scan agent that can run automated application security scans on behalf of a ThreadFix server.
* **threadfix-scanner-plugin** - Scanner plugins that can connect to a ThreadFix server and import an application's attack surface to improve the thoroughness of dynamic scanning. Also allows for exporting scan results directly into ThreadFix (rather than saving files and uploading them.)
* **threadfix-update** - Update scripts to upgrade the ThreadFix server database between versions.
