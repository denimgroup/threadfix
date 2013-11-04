from __future__ import with_statement
from fabric.api import *
from fabric.contrib.console import confirm
import datetime, re

source_code_loc='https://code.google.com/p/threadfix'
local_working_folder_loc = '/home/vagrant/threadfix_1_2_vm_upgrade' #where fabfile is running from
server_base_loc = '/home/vagrant/artifacts' #where to deploy to
local_path = 'threadfix/threadfix-main/src/main/resources' #path to .deploy files
mysql_user = 'threadfix'
mysql_password = 'passwordpassword'
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
        result = local('git clone %s -b 1.2final' % source_code_loc)
        with lcd("threadfix"):
            result2 = local('git checkout tags/1.2final-tag')
    if (result.failed or result2.failed) and confirm('Source code could not be found. Abort recommended. Abort?'):
        abort('Aborting because source code not found.')

# exchanges the debug versions for the deploy versions
@task
@runs_once
def exchange_files():
    with settings(warn_only = True):
        res1 = local('mv %s/%s/log4j.xml.deploy %s/%s/log4j.xml' % (local_working_folder_loc, local_path, local_working_folder_loc, local_path))
        res2 = local('mv %s/%s/jdbc.properties.mysql %s/%s/jdbc.properties' % (local_working_folder_loc, local_path, local_working_folder_loc, local_path))
        res3 = local('mv %s/%s/applicationContext-scheduling.xml.deploy %s/%s/applicationContext-scheduling.xml' % (local_working_folder_loc, local_path, local_working_folder_loc, local_path))
    res = res1 and res2 and res3
    if res.failed and confirm('Deploy files were not found. Abort recommended. Abort?'):
        abort('Aborting because deploy files not found.')

# Updates the Java version from 6 to 7
@task
@runs_once
def install_java_7():
    local('sudo apt-get update && sudo apt-get upgrade')
    local('sudo service tomcat7 stop')
    local('sudo apt-get install openjdk-7-jdk -y && sudo update-java-alternatives -s java-1.7.0-openjdk-i386')
    local('sudo touch /usr/share/tomcat7/bin/setenv.sh && sudo chown $(whoami) /usr/share/tomcat7/bin/setenv.sh && sudo echo "\nJAVA_HOME=/usr/lib/jvm/java-7-openjdk-i386/" >> /usr/share/tomcat7/bin/setenv.sh')
    local('sudo chown tomcat7:tomcat7 /usr/share/tomcat7/bin/setenv.sh')
    local("sudo sed -i 's/#JAVA_HOME=\/usr\/lib\/jvm\/openjdk-6-jdk/JAVA_HOME=\/usr\/lib\/jvm\/java-7-openjdk-i386/g' /etc/default/tomcat7")
    local("sudo sed -i 's/\/usr\/lib\/jvm\/java-6-openjdk/\/usr\/lib\/jvm\/java-7-openjdk-i386/g' /etc/init.d/tomcat7")

# creates the WAR file from the source code
@task
@runs_once
def build_war():
    with lcd('%s/threadfix/threadfix-main' % local_working_folder_loc):
        res = local('mvn package -DskipTests -P mysql')
    if res.failed and confirm('Maven failed to build the WAR file. Abort recommended. Abort?'):
        abort('Aborting because Maven failed.')

# Updates the database to contain new mappings
@task
def update_database():
    print('About to back up database and run updates.')
    folder_name = now.year*100000000 + now.month*1000000 + now.day*10000 + now.hour*100 + now.minute
    local('mysqldump -u %s -p%s threadfix > threadfixdump%s.sql' % (mysql_user, mysql_password, folder_name))
    local('java -jar dbupdate.jar //localhost:3306/threadfix %s %s' % (mysql_user, mysql_password))

# moves the WAR file to the remote server, updates the database and restarts tomcat 
@task
def deploy_war():
    folder_name = now.year*100000000 + now.month*1000000 + now.day*10000 + now.hour*100 + now.minute
    server_target_loc = server_base_loc + '/' +  str(folder_name)
    with settings(warn_only=True):
        local('sudo mkdir %s %s' % (server_base_loc,server_target_loc))
    local('sudo mv %s/threadfix/threadfix-main/target/threadfix-0.0.1-SNAPSHOT.war %s' % (local_working_folder_loc, server_target_loc))
    with cd(server_target_loc):        
        local('sudo unzip -q %s/threadfix-0.0.1-SNAPSHOT.war -d %s/threadfix' % (server_target_loc, server_target_loc)) #unzip the WAR file
        local('sudo chown tomcat7 %s/threadfix' % (server_target_loc))
    local('sudo service tomcat7 stop')   #stop tomcat
    local('sudo cp /var/lib/tomcat7/webapps/threadfix/WEB-INF/classes/jdbc.properties %s/threadfix/WEB-INF/classes/jdbc.properties' % (server_target_loc))
    local('sudo ln -fs %s/threadfix /var/lib/tomcat7/webapps' % server_target_loc) #update symlink in webapps
    local('sudo cp %s/threadfix/threadfix-main/src/main/java/ESAPI.properties %s/threadfix/WEB-INF/classes/ESAPI.properties' % (local_working_folder_loc, server_target_loc))
	# We need to move the mysql / deploy config files to replace the development ones
    #local('sudo mv /var/lib/tomcat7/webapps/threadfix/WEB-INF/classes/jdbc.properties.mysql /var/lib/tomcat7/webapps/threadfix/WEB-INF/classes/jdbc.properties') 
    #local('sudo mv /var/lib/tomcat7/webapps/threadfix/WEB-INF/classes/applicationContext-scheduling.xml.deploy /var/lib/tomcat7/webapps/threadfix/WEB-INF/classes/applicationContext-scheduling.xml') 
    #local('sudo mv /var/lib/tomcat7/webapps/threadfix/WEB-INF/classes/log4j.xml.deploy /var/lib/tomcat7/webapps/threadfix/WEB-INF/classes/log4j.xml') 
    
@task
def change_owners() :
    # This directory must be writable so that reports work
    local('sudo mkdir /var/lib/tomcat7/webapps/threadfix/jasper/images')
    # Tomcat must own these directories so that logs, scans, and report images are writable
    local('sudo chown tomcat7 /var/lib/tomcat7') 
    local('sudo chown tomcat7 /var/lib/tomcat7/webapps/threadfix/jasper/images') 
    local('sudo service tomcat7 start')  #start tomcat
    
# verifies the login page
@task
def verify_site():
    with settings(warn_only = True):
        str = local('curl -k -I https://localhost:443/threadfix/login.jsp')
    testing = re.match('HTTP/1.1 200', str)
    if testing:
        print("Successful launch verified using HTTP response.")
    else:
        print('WARNING: The HTTP response was not successful.')

@task(default=True)
def deploy_new_war():
    remove_old_code()
    clone_code()
    exchange_files()
    install_java_7()
    build_war()
    update_database()
    deploy_war()
    change_owners()
    verify_site()
