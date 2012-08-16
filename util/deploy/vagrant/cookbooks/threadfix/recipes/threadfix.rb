##//////////////////////////////////////////////////////////////////////
##
##     Copyright (c) 2009-2012 Denim Group, Ltd.
##
##     The contents of this file are subject to the Mozilla Public License
##     Version 1.1 (the "License"); you may not use this file except in
##     compliance with the License. You may obtain a copy of the License at
##     http://www.mozilla.org/MPL/
##
##     Software distributed under the License is distributed on an "AS IS"
##     basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
##     License for the specific language governing rights and limitations
##     under the License.
##
##     The Original Code is Vulnerability Manager.
##
##     The Initial Developer of the Original Code is Denim Group, Ltd.
##     Portions created by Denim Group, Ltd. are Copyright (C)
##     Denim Group, Ltd. All Rights Reserved.
##
##     Contributor(s): Denim Group, Ltd.
##
##//////////////////////////////////////////////////////////////////////

# custom.rb
# Ubuntu 12.04
# Denim Group 2012

# The scripts included with this project are not intended to be generic.

execute "apt-get update" do
  command "apt-get update"
end

execute "apt-get upgrade" do
  command "apt-get -y upgrade"
end

client_package = package "unzip" 
client_package.run_action(:install)

fabric_package = package "fabric" 
fabric_package.run_action(:install)

curl_package = package "curl" 
curl_package.run_action(:install)

git_package = package "git" 
git_package.run_action(:install)

maven_package = package "maven" do
  notifies :run, "execute[apt-get update]", :immediately
  notifies :run, "execute[apt-get upgrade]", :immediately
end

template "/home/vagrant/fabfile.py" do
  source "fabfile.py.erb"
  owner "root"
  group "root"
  mode "0744"
end

template "/reset-database.sh" do
  source "reset-database.sh.erb"
  owner "root"
  group "root"
  mode "0744"
end

script "run fabric" do
  interpreter "bash"
  user "root"
  cwd "/home/vagrant"
  code <<-EOH
    sudo fab deploy
  EOH
end

script "deploy WAR" do
  interpreter "bash"
  user "root"
  cwd "/home/vagrant"
  code <<-EOH
    sudo fab deploy_war
    sudo service tomcat6 start
	sudo sleep 5;
  EOH
end

script "verify WAR" do
  interpreter "bash"
  user "root"
  cwd "/home/vagrant"
  code <<-EOH
	sudo fab verify_site
  EOH
end

script "import_db" do
  interpreter "bash"
  user "root"
  cwd "/vagrant"
  code <<-EOH
    echo "use threadfix;" > /tmp/db.sql
	cat /tmp/db.sql /var/lib/tomcat6/webapps/threadfix/WEB-INF/classes/import-mysql.sql | /usr/bin/mysql -u threadfix -ptfpassword
  EOH
end
