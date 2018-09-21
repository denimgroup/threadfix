# ThreadFix Command Line Tool
## Introduction ##
ThreadFix is a software vulnerability aggregation and management system that helps organizations aggregate vulnerability data, generate virtual patches, and interact with software defect tracking systems.
The ThreadFix core is a Java/Spring/Hibernate web application. This web application exposes a REST-based interface to support automation and customization. This project is a set of Java-based wrappers to that REST API providing a command-line wrapper to the REST API.

## Building ##
From the current (threadfix-cli/) directory, run Maven with:

> mvn clean compile assembly:single

This will create a single JAR file with all dependencies rolled in called:

> threadfix-cli-2.0-jar-with-dependencies.jar

## Usage ##
Full documentation for the ThreadFix command-line interface can be found online: [https://github.com/denimgroup/threadfix/wiki/Command-Line-Interface](https://github.com/denimgroup/threadfix/wiki/Command-Line-Interface)

Before using the ThreadFix command-line client you have to set the URL and API key that the client will use. This can be done by executing:

> java -jar threadfix-cli-2.0-jar-with-dependencies.jar --set key {apiKey}
> 
>  java -jar threadfix-cli-2.0-jar-with-dependencies.jar --set url {url}

Please note that the ThreadFix URL should be the base of the ThreadFix installation - for example http://localhost:8080/threadfix/ (the "rest/" component of the API URLs will be added by the command-line client).
From there, additional calls to "java -jar threadfix-cli-2.0-jar-with-dependencies.jar " can be used to create applications, upload scan files and so on. Running:
>java -jar threadfix-cli-2.0-jar-with-dependencies.jar

will result in a list of command line options and parameters. Please consult the full ThreadFix command-line documentation for more information.
## References ##

* The main documentation for the ThreadFix command-line client can be found here [https://github.com/denimgroup/threadfix/wiki/Command-Line-Interface](https://github.com/denimgroup/threadfix/wiki/Command-Line-Interface)
* Documentation for the ThreadFix REST interface that the command-line client calls in to can be found here [https://github.com/denimgroup/threadfix/wiki/Command-Line-Interfacehttps://github.com/denimgroup/threadfix/wiki/Threadfix-REST-Interface](https://github.com/denimgroup/threadfix/wiki/Command-Line-Interfacehttps://github.com/denimgroup/threadfix/wiki/Threadfix-REST-Interface)