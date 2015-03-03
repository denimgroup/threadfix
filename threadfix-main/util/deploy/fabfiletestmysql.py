from __future__ import with_statement
from fabric.api import *
from fabric.contrib.console import confirm
import os
from urlparse import urlparse
from ftplib import FTP

from fabric.api import env

local_working_folder_loc = os.getcwd() #where fabfile is running from
server_base_loc = '/var/lib/tomcat7/webapps' #where to deploy to


# moves the WAR file to the remote server, updates the database and restarts tomcat
@task(default=True)
@runs_once
def deploy_war():
    local('scp -i ~/.ssh/id_rsa %s/threadfix-main/target/*.war %s@%s:threadfix.war' % (local_working_folder_loc, env.user, env.host))
    run('w')
    sudo('service tomcat7 stop')   #stop tomcat
    with settings(warn_only=True):
        sudo('rm -rf %s/threadfix' % (server_base_loc))
        sudo('rm -rf %s/threadfix.war' % (server_base_loc))
    sudo('cp ~/threadfix.war %s/threadfix.war' % (server_base_loc))
    sudo('service tomcat7 start')  #start tomcat