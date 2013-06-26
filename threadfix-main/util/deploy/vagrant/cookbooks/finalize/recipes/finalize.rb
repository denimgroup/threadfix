##//////////////////////////////////////////////////////////////////////
##
##     Copyright (c) 2009-2013 Denim Group, Ltd.
##
##     The contents of this file are subject to the Mozilla Public License
##     Version 2.0 (the "License"); you may not use this file except in
##     compliance with the License. You may obtain a copy of the License at
##     http://www.mozilla.org/MPL/
##
##     Software distributed under the License is distributed on an "AS IS"
##     basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
##     License for the specific language governing rights and limitations
##     under the License.
##
##     The Original Code is ThreadFix.
##
##     The Initial Developer of the Original Code is Denim Group, Ltd.
##     Portions created by Denim Group, Ltd. are Copyright (C)
##     Denim Group, Ltd. All Rights Reserved.
##
##     Contributor(s): Denim Group, Ltd.
##
##//////////////////////////////////////////////////////////////////////

# finalize.rb
# Ubuntu 12.04
# Denim Group 2012

# Once everything is configured, let's remove artifacts that aren't necessary in the final version.

execute "apt-get update" do
  command "apt-get update"
  action :run
end

execute "apt-get upgrade" do
	command "apt-get -y upgrade"
	action :run
end

package "make" do
  action :remove
end

package "gcc" do
  action :remove
end

script "Remove Vagrant user" do
  interpreter "bash"
  user "root"
  cwd "/"
  code <<-EOH
    sudo chown -R tfuser:tfuser /home/vagrant/
    sudo ln -s /home/vagrant /home/tfuser
  EOH
end



