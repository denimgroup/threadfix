# Introduction #
ThreadFix scan agents can be used to automate the process of scanning applications and feeding the results of this scanning into ThreadFix.

# Supported Scanners #

Scanners currently supported by the ThreadFix Scan Agent include:

* OWASP ZAP
* IBM Rational AppScan
* Acunetix WVS

# How the Scan Agent Works #

The scan agent communicates with the ThreadFix server to retrieve scanning tasks and to upload the results of scanning tasks performed on the scan agent. This sequence of events roughly looks like:

 * Scan agent starts up and reads its configuration from scanagent.properties
 * Scan agent calls to the ThreadFix server, sends information about the scan agent OS as well as the various scanners configured for the particular scan agent.
 * The ThreadFix server checks its scan task queue to see if there are any tasks that area  match for the OS and available scanners the scan agent has presented.
 * If there is an available task, the ThreadFix server marks it as being in progress and checks to see if the application has stored configuration data for the scanner. The scan task is returned to the scan agent and if there is stored configuration for that application for the target scanner then that configuration data is bundled with the response and sent back to the scan agent.
 * The scan agent receives the scan task and the optional scan configuration data and kicks of the scanning progress.
 * Along the way the scan agent can report status updates back to the ThreadFix server. What gets reported back is handled on a scanner-by-scanner basis.
 * When the scan task is complete, the scan agent bundles up the results and submits them back to the ThreadFix server.
 * The ThreadFix server processes the results and marks the scan queue task complete
 * The scan agent will then request a new task from the ThreadFix server

This process repeats either indefinitely (for a typical production scenario) or for a set number of tasks (for debugging or other specialized scenarios).

# Architecture #

The ThreadFix scan agent system consists of:

 * A single ThreadFix server
 * One or more scan agents, each capable of running one or more scanners

Scan agents communicate with the ThreadFix server via its REST API. The ThreadFix server does not initiate communications with scan agents. Scan agents authenticate themselves to the ThreadFix server via an API key which can be shared between scan agents if needed. Scan agents are designed to be transient - they can be added to or removed from the configuration without having to notify the ThreadFix server.

ThreadFix and scan agents can be deployed in a number of configurations:

 * ThreadFix server running on a VM that also runs a scan agent with one or more scanners. This may be suitable for smaller configurations where the memory and processor load from the scanning activities will not interfere with the performance of the ThreadFix server.
 * ThreadFix server running on one host with one or more independent scan agents running on one or more separate host servers. This configuration will support larger-scale scanning environments with more complicated scans and a larger number of applications.
 * ThreadFix server running on one host with an arbitrary number of scan agents running on multiple virtual servers that are provisioned and de-provisioned on an as-needed basis. This configuration can support even larger numbers of applications and can be dynamically scaled up or down based on the scanning load at any given time.

# Building the ThreadFix Scan Agent #

TODO

# Installation and Configuration #

## Installation ##

The scan agent can be installed anywhere on the filesystem

## Configuration ##

Configuration for ThreadFix scan agents is handled in the scanagent.properties properties file. The ThreadFix scan agent distribution should come with an example scanagent.properties file that has extensive documentation for the various configuration settings that can be defined in the scanagent.properties files. This file consists of several major sections :

 * Main Configuration - This section contains information about the ThreadFix server configuration - its URL and the API key to be used to communicate with the server. It also contains a list of the available scanners for the scan agent in the scanagent.scanners property with the contents of the property being a comma-separated list of the scanners available on the scan agent.
 * Scanner-Specific Configurations - These sections provide scanner-specific configurations for the different scanners available from a given scan agent. These configurations must define the com.denimgroup.threadfix.scanagent.AbstractScanAgent subclass that contains the code for the scan agent in the [scanner_name].className property.  In addition, most scanners require the scan agent to know the location of the executable to run.

## Feedback and Questions ##

If you have questions or feedback on ThreadFix, please reach out via:

 * [ThreadFix Google Group](https://groups.google.com/forum/?fromgroups#!forum/threadfix) - For general discussion about ThreadFix and questions/comments about scripting ThreadFix and interactions with different tools.
 * [GitHub Issue Tracker](https://github.com/denimgroup/threadfix/issues) - For bugs or features requests for ThreadFix scan agents or the ThreadFix server and API.

# References #

* [ThreadFix Documentation Wiki](https://code.google.com/p/threadfix/wiki/)
