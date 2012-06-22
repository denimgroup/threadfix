from __future__ import with_statement
from fabric.api import *
from fabric.contrib.console import confirm
import datetime, re

env.hosts = ['host IP']
env.user = 'username'
env.password = 'password'
source_code_loc='https://code.google.com/p/threadfix'
local_working_folder_loc = '/path/to/local/folder' #where fabfile is running from
server_base_loc = '/path/to/server/base' #where to deploy to
local_path = '/threadfix/src/main/resources' #path to .deploy files
now = datetime.datetime.now()

@task #removes the old version of the source code locally
def remove():
    local("rm -rf threadfix")

@task #gets the new version of the source code locally
def code():
    with settings(warn_only=True):
        result = local('git clone %s' % source_code_loc)
    if result.failed and confirm('Source code could not be found. Abort recommended. Abort?'):
        abort('Aborting because source code not found.')

@task #exchanges the debug versions for the deploy versions
def exchange():
    with settings(warn_only = True):
        res1 = local('mv %s%s/log4j.xml.deploy %s%s/log4j.xml' % (local_working_folder_loc, local_path, local_working_folder_loc, local_path))
        res2 = local('mv %s%s/jdbc.properties.deploy %s%s/jdbc.properties' % (local_working_folder_loc, local_path, local_working_folder_loc, local_path))
        res3 = local('mv %s%s/applicationContext-scheduling.xml.deploy %s%s/applicationContext-scheduling.xml' % (local_working_folder_loc, local_path, local_working_folder_loc, local_path))
    res = res1 and res2 and res3
    if res.failed and confirm('Deploy files were not found. Abort recommended. Abort?'):
        abort('Aborting because deploy files not found.')

@task #creates the WAR file from the source code
def mav():
    with lcd('%s/threadfix' % local_working_folder_loc):
        res = local('mvn package')
    if res.failed and confirm('Maven failed to build the WAR file. Abort recommended. Abort?'):
        abort('Aborting because Maven failed.')

@task #moves the WAR file to the remote server, updates the database and restarts tomcat 
def remote():
    folder_name = now.year*100000000 + now.month*1000000 + now.day*10000 + now.hour*100 + now.minute
    server_target_loc = server_base_loc + '/' +  str(folder_name)
    with cd(server_base_loc):
        run('mkdir %s' % str(folder_name))
    put('%s/threadfix/target/threadfix-0.0.1-SNAPSHOT.war' % local_working_folder_loc, server_target_loc)
    with cd(server_target_loc):        
        run('unzip -q threadfix-0.0.1-SNAPSHOT.war -d threadfix') #unzip the WAR file
    run('sudo service tomcat6 stop')   #stop tomcat
    run('mv -f %s/threadfix/WEB-INF/classes/threadfix-backup.script /var/lib/tomcat6/database/threadfix.script' % server_target_loc)
    run('rm -f /var/lib/tomcat6/database/threadfix.log') 
    run('sudo ln -fs %s/threadfix /var/lib/tomcat6/webapps' % server_target_loc) #update symlink in webapps
    run('sudo service tomcat6 start')  #start tomcat

@task #verifies the login page
def ver():
    time.sleep(2)
    with settings(warn_only = True):
        str = run('curl -I http://servername:8080/threadfix/login.jsp')
    testing = re.match('HTTP/1.1 200', str)
    if testing:
        print("Successful launch verified using HTTP response.")
    else:
        print('WARNING: The HTTP response was not 200. Startup was probably not successful.')

@task(default=True)
def deploy():
    remove()
    code()
    exchange()
    mav()
    remote()
    ver()

@task
def slow_deploy():
    if confirm('Ready to delete old source code locally?'):
        remove()
        if confirm('Ready to obtain new source code?'):
            code()
            if confirm('Ready to exchange debug files for deploy files?'):
                exchange()
                if confirm('Ready to build the WAR file?'):
                    mav()
                    if confirm('Ready to deploy to the remote server(s)? (This will take a few minutes)'):
                        remote()
                        if confirm('Ready to verify the login page?'):
                            ver()
