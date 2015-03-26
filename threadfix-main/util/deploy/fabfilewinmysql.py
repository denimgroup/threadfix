from __future__ import with_statement
from fabric.api import *
from fabric.contrib.console import confirm
import os
from urlparse import urlparse
from ftplib import FTP

from fabric.api import env

local_working_folder_loc = os.getcwd() #where fabfile is running from
server_base_loc = "/c/Program\ Files/Apache\ Software\ Foundation/Tomcat\ 7.0" #where to deploy to

env.shell = 'C:/\"Program Files (x86)\"/Git/bin/bash.exe -l -c'

# moves the WAR file to the remote server, updates the database and restarts tomcat
@task(default=True)
@runs_once
def deploy_war():
    local('scp -i ~/.ssh/id_rsa %s/threadfix-main/target/*.war %s@%s:threadfix.war' % (local_working_folder_loc, env.user, env.host))
    run('%s/bin/Tomcat7.exe stop' % (server_base_loc))   #stop tomcat
    with settings(warn_only=True):
        run('rm -rf %s/webapps/threadfix' % (server_base_loc))
        run('rm -rf %s/webapps/threadfix.war' % (server_base_loc))
    run('cp /c/Program\ Files/nsoftware/PowerShell\ Server\ V6/sftproot/threadfix.war %s/webapps/threadfix.war' % (server_base_loc))
    run('%s/bin/Tomcat7.exe  start' % (server_base_loc))  #start tomcat