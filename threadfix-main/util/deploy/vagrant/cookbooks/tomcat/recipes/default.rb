#
# Cookbook Name:: tomcat
# Recipe:: default
#
# Copyright 2010, Opscode, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

include_recipe "java"

package "tomcat7" do
  action :install
end

service "tomcat" do
  service_name "tomcat7"
  case node["platform"]
  when "centos","redhat","fedora"
    supports :restart => true, :status => true
  when "debian","ubuntu"
    supports :restart => true, :reload => true, :status => true
  end
  action [:enable, :start]
end

=begin

case node["platform"]
when "centos","redhat","fedora"
  template "/etc/sysconfig/tomcat7" do
    source "sysconfig_tomcat7.erb"
    owner "root"
    group "root"
    mode "0644"
    notifies :restart, resources(:service => "tomcat")
  end
else  
  template "/etc/default/tomcat7" do
    source "default_tomcat7.erb"
    owner "root"
    group "root"
    mode "0644"
    notifies :restart, resources(:service => "tomcat")
  end
end
=end

template "/etc/tomcat7/server.xml" do
  source "server.xml.erb"
  owner "root"
  group "root"
  mode "0644"
  notifies :restart, resources(:service => "tomcat")
end

=begin
template "/var/lib/tomcat7/conf/context.xml" do
  source "context.xml.erb"
  owner "root"
  group "root"
  mode "0644"
  notifies :restart, resources(:service => "tomcat")
end

# This template ensures that we always run with the tomcat security manager
template "/etc/init.d/tomcat7" do
  source "tomcat7.erb"
  owner "root"
  group "root"
  mode "0755"
  action :create
  notifies :restart, resources(:service => "tomcat")
end
=end

#This template increases the memory limit for tomcat
template "/usr/share/tomcat7/bin/setenv.sh" do
  source "setenv.sh.erb"
  owner "root"
  group "root"
  mode "0755"
  notifies :restart, resources(:service => "tomcat")
end


