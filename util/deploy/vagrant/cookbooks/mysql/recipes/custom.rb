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

# I'm not trying for a generic solution, I'm trying for a working 12.04 Ubuntu.

script "install mysql" do
  interpreter "bash"
  user "root"
  cwd "/home/vagrant"
  code <<-EOH
    export DEBIAN_FRONTEND=noninteractive
    sudo debconf-set-selections <<< 'mysql-server-5.1 mysql-server/root_password password test'
    sudo debconf-set-selections <<< 'mysql-server-5.1 mysql-server/root_password_again password test'
    sudo apt-get install mysql-server -y
    sudo apt-get install mysql-client -y
  EOH
end

execute "assign-root-password" do
  command "/usr/bin/mysqladmin -u root password test"
  action :run
  only_if "/usr/bin/mysql -u root -e 'show databases;'"
end

grants_path = value_for_platform(
  "default" => "/etc/mysql/grants.sql"
)

begin
  t = resources(:template => "/etc/mysql/grants.sql")
rescue
  Chef::Log.warn("Could not find previously defined grants.sql resource")
  t = template "/etc/mysql/grants.sql" do
    path grants_path
    source "grants.sql.erb"
    owner "root"
    group "root"
    mode "0600"
    action :create
  end
end

execute "mysql-install-privileges" do
  command "sudo bash -c \"/usr/bin/mysql -u root -ptest < #{grants_path}\""
  action :nothing
  subscribes :run, resources(:template => "/etc/mysql/grants.sql"), :immediately
end

r = gem_package "ruby-mysql" 

r.run_action(:install)