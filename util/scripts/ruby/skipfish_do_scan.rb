##############################################################################
##
##     Copyright (c) 2009-2011 Denim Group, Ltd.
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
##############################################################################
# This is just a very simple piped process.
# It needs its own file so it can be run from outside Cygwin inside a Cygwin pipe.
# Skipfish is only piped at all so that it can feed the newline character to skip the wait.
IO.popen("cd /scanners/skipfish-1.92b; #{ARGV[0]}", mode="w+") do |pipe|
	pipe.puts "\n"
	pipe.flush
	pipe.close
end
