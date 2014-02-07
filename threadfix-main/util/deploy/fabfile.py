from __future__ import with_statement
from fabric.api import *
from fabric.contrib.console import confirm
import datetime, re

env.hosts = ['localhost']
#env.password = 'password'
env.user = 'denimgroup'

local_working_folder_loc = '/var/lib/jenkins/workspace/ThreadFix_Regression' #where fabfile is running from
server_base_loc = '/var/lib/tomcat7/webapps' #where to deploy to

#path to .deploy files
local_path = 'threadfix-main/src/main/resources'
now = datetime.datetime.now()

# removes the old version of the source code locally
@task
@runs_once
def remove_old_code():
    local("rm -rf threadfix")

# gets the new version of the source code locally
@task
@runs_once
def clone_code():
    with settings(warn_only=True):
        result = local('git clone %s' % source_code_loc)
    if result.failed and confirm('Source code could not be found. Abort recommended. Abort?'):
        abort('Aborting because source code not found.')

# exchanges the debug versions for the deploy versions
@task
@runs_once
def exchange_files():
    with settings(warn_only = True):
        res1 = local('mv %s/%s/log4j.xml.deploy %s/%s/log4j.xml' % (local_working_folder_loc, local_path, local_working_folder_loc, local_path))
        #res2 = local('sed "s/hibernate.hbm2ddl.auto=update/hibernate.hbm2ddl.auto=create/g" %s/%s/jdbc.properties.mysql -i' % (local_working_folder_loc, local_path))
        res3 = local('mv %s/%s/jdbc.properties.mysql %s/%s/jdbc.properties' % (local_working_folder_loc, local_path, local_working_folder_loc, local_path))
        res4 = local('mv %s/%s/applicationContext-scheduling.xml.deploy %s/%s/applicationContext-scheduling.xml' % (local_working_folder_loc, local_path, local_working_folder_loc, local_path))
    res = res1 and res3 and res4
    if res.failed and confirm('Deploy files were not found. Abort recommended. Abort?'):
        abort('Aborting because deploy files not found.')

# creates the WAR file from the source code
@task
@runs_once
def build_war(profile, qaprofile):
    with lcd('%s' % local_working_folder_loc):
        res = local('mvn install -DskipTests -P %s,%s' % profile, qaprofile)
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

# verifies the login page
@task
def verify_site():
    with settings(warn_only = True):
        str = local('curl -I https://localhost:443/threadfix/login.jsp')
    testing = re.match('HTTP/1.1 200', str)
    if testing:
        print("Successful launch verified using HTTP response.")
    else:
        print('WARNING: The HTTP response was not successful.')

@task
def slow_deploy():
    if confirm('Ready to delete old source code locally?'):
        remove_old_code()
        if confirm('Ready to obtain new source code?'):
            clone_code()
            if confirm('Ready to exchange debug files for deploy files?'):
                exchange_files()
                if confirm('Ready to build the WAR file?'):
                    build_war()
                    if confirm('Ready to deploy to the remote server(s)? (This will take a few minutes)'):
                        deploy_war()
                        if confirm('Ready to verify the login page?'):
                            verify_site()

@task(default=True)
def deploy(profile, qaprofile):

    env.profile = profile
    env.qaprofile = qaprofile

    #exchange_files()
    build_war(profile, qaprofile)
    deploy_war()
    #verify_site()
