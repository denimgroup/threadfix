////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2013 Denim Group, Ltd.
//
//     The contents of this file are subject to the Mozilla Public License
//     Version 2.0 (the "License"); you may not use this file except in
//     compliance with the License. You may obtain a copy of the License at
//     http://www.mozilla.org/MPL/
//
//     Software distributed under the License is distributed on an "AS IS"
//     basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//     License for the specific language governing rights and limitations
//     under the License.
//
//     The Original Code is ThreadFix.
//
//     The Initial Developer of the Original Code is Denim Group, Ltd.
//     Portions created by Denim Group, Ltd. are Copyright (C)
//     Denim Group, Ltd. All Rights Reserved.
//
//     Contributor(s): Denim Group, Ltd.
//
////////////////////////////////////////////////////////////////////////
package com.denimgroup.threadfix.plugin.scanner;

import com.denimgroup.threadfix.data.dao.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.context.support.SpringBeanAutowiringSupport;

/**
 * This class allows us to use autowired beans.
 */
public class DaoHolder extends SpringBeanAutowiringSupport {
	@Autowired
	public ChannelVulnerabilityDao channelVulnerabilityDao;
	@Autowired
	public ChannelSeverityDao channelSeverityDao;
	@Autowired
	public ChannelTypeDao channelTypeDao;
	@Autowired
	public GenericVulnerabilityDao genericVulnerabilityDao;
	@Autowired
	public ApplicationDao applicationDao;
	@Autowired
	public ApplicationChannelDao applicationChannelDao;
    @Autowired
    public GenericSeverityDao genericSeverityDao;
}
