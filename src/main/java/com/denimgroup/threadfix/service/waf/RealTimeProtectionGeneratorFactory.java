////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2011 Denim Group, Ltd.
//
//     The contents of this file are subject to the Mozilla Public License
//     Version 1.1 (the "License"); you may not use this file except in
//     compliance with the License. You may obtain a copy of the License at
//     http://www.mozilla.org/MPL/
//
//     Software distributed under the License is distributed on an "AS IS"
//     basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//     License for the specific language governing rights and limitations
//     under the License.
//
//     The Original Code is Vulnerability Manager.
//
//     The Initial Developer of the Original Code is Denim Group, Ltd.
//     Portions created by Denim Group, Ltd. are Copyright (C)
//     Denim Group, Ltd. All Rights Reserved.
//
//     Contributor(s): Denim Group, Ltd.
//
////////////////////////////////////////////////////////////////////////
package com.denimgroup.threadfix.service.waf;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.denimgroup.threadfix.data.dao.WafRuleDao;
import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.WafType;

/**
 * @author bbeverly
 * 
 */
public class RealTimeProtectionGeneratorFactory {

	private WafRuleDao wafRuleDao;
	
	private final Log log = LogFactory.getLog(RealTimeProtectionGeneratorFactory.class);

	public RealTimeProtectionGeneratorFactory(WafRuleDao wafRuleDao) {
		this.wafRuleDao = wafRuleDao;
	}
	
	/**
	 * Returns an RealTimeProtectionGenerator implementation based on the
	 * application's waf name.
	 * 
	 * @param
	 * @return
	 */
	public RealTimeProtectionGenerator getTracker(Application app) {
		if (app == null || app.getWaf() == null || app.getWaf().getWafType() == null
				|| app.getWaf().getWafType().getName() == null) {
			return null;
		}

		String wafName = app.getWaf().getWafType().getName();

		return getTracker(wafName);
	}

	/**
	 * @param wafName
	 * @return
	 */
	public RealTimeProtectionGenerator getTracker(String wafName) {
		if (wafName == null || wafName.trim().equals(""))
			return null;

		if (wafName.equals(WafType.MOD_SECURITY)) {
			return new ModSecurityWafGenerator(wafRuleDao);
		} else if (wafName.equals(WafType.SNORT)) {
			return new SnortGenerator(wafRuleDao);
		} else if (wafName.equals(WafType.BIG_IP_ASM)) {
			return new BigIPASMGenerator(wafRuleDao);
		} else {
			log.warn("Invalid WAF type name '"
					+ wafName
					+ "'  Unable to find suitable RealTimeProtectionGenerator implementation class.  Returning null");
			return null;
		}
	}
}
