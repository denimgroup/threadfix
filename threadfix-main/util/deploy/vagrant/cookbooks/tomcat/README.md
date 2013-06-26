Description
===========

Installs and configures Tomcat version 6, Java servlet engine and webserver.

Requirements
============

Platform:

* Debian, Ubuntu (OpenJDK, Oracle)
* CentOS 6+, Red Hat 6+, Fedora (OpenJDK, Oracle)

The following Opscode cookbooks are dependencies:

* java

Attributes
==========

* `node["tomcat"]["port"]` - The network port used by Tomcat's HTTP connector, default `8080`.
* `node["tomcat"]["ssl_port"]` - The network port used by Tomcat's SSL HTTP connector, default `8443`.
* `node["tomcat"]["ajp_port"]` - The network port used by Tomcat's AJP connector, default `8009`.
* `node["tomcat"]["java_options"]` - Extra options to pass to the JVM, default `-Xmx128M -Djava.awt.headless=true`.
* `node["tomcat"]["use_security_manager"]` - Run Tomcat under the Java Security Manager, default `false`.

Usage
=====

Simply include the recipe where you want Tomcat installed.

Due to the ways that some system init scripts call the configuration,
you may wish to set the java options to include `JAVA_OPTS`. As an
example for a java app server role:

    name "java-app-server"
    run_list("recipe[tomcat]")
    override_attributes(
      'tomcat' => {
        'java_options' => "${JAVA_OPTS} -Xmx128M -Djava.awt.headless=true"
      }
    )

License and Author
==================

Author:: Seth Chisamore (<schisamo@opscode.com>)

Copyright:: 2010-2012, Opscode, Inc

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
