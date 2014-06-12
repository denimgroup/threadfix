from __future__ import with_statement
from fabric.api import *
from fabric.contrib.console import confirm
import os

env.hosts = ['localhost']
#env.password = 'password'
env.user = 'denimgroup'

local_working_folder_loc = os.getcwd() #where fabfile is running from
server_base_loc = '/var/lib/tomcat7/webapps' #where to deploy to

# moves the WAR file to the remote server, updates the database and restarts tomcat 
@task
@runs_once
def deploy_war():
    sudo('service tomcat7 stop')   #stop tomcat
    with settings(warn_only=True):
        sudo('rm -rf %s/threadfix' % (server_base_loc))
    sudo('mv %s/threadfix-main/target/threadfix-2.1-SNAPSHOT.war %s/threadfix.war' % (local_working_folder_loc, server_base_loc))
    sudo('service tomcat7 start')  #start tomcat

# moves the WAR file to the remote server, updates the database and restarts tomcat
@task
@runs_once
def reset_hsql():
    with settings(warn_only=True):
        sudo('rm -rf /var/lib/tomcat7/database')
    sudo('cp -r /var/lib/tomcat7/backup_database /var/lib/tomcat7/database')
    sudo('chown tomcat7:tomcat7 /var/lib/tomcat7/database')

@task(default=True)
def deploy():
    reset_hsql()
    deploy_war()

