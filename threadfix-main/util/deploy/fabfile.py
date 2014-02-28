from __future__ import with_statement
from fabric.api import *
from fabric.contrib.console import confirm

env.hosts = ['localhost']
#env.password = 'password'
env.user = 'denimgroup'

local_working_folder_loc = '/var/lib/jenkins/workspace/ThreadFix_Regression' #where fabfile is running from
server_base_loc = '/var/lib/tomcat7/webapps' #where to deploy to

# creates the WAR file from the source code
@task
@runs_once
def build_war(profile):
    print("profile is %s" % profile)
    with lcd('%s' % local_working_folder_loc):
        res = local('mvn help:active-profiles clean install -DskipTests -P %s' % profile)
    if res.failed and confirm('Maven failed to build the WAR file. Abort recommended. Abort?'):
        abort('Aborting because Maven failed.')

# moves the WAR file to the remote server, updates the database and restarts tomcat 
@task
@runs_once
def deploy_war():
    sudo('service tomcat7 stop')   #stop tomcat
    with settings(warn_only=True):
        sudo('rm -rf %s/threadfix' % (server_base_loc))
    sudo('mv %s/threadfix-main/target/threadfix-2.0M2-SNAPSHOT.war %s/threadfix.war' % (local_working_folder_loc, server_base_loc))
    sudo('service tomcat7 start')  #start tomcat

@task(default=True)
def deploy(profile):

    env.profile = profile

    build_war(profile)
    deploy_war()

