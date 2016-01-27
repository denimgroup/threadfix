////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2016 Denim Group, Ltd.
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
package com.denimgroup.threadfix.data.dao;

import java.util.List;

import com.denimgroup.threadfix.data.entities.Vulnerability;
import com.denimgroup.threadfix.data.entities.Waf;
import com.denimgroup.threadfix.data.entities.WafRule;
import com.denimgroup.threadfix.data.entities.WafRuleDirective;

/**
 * Basic DAO class for the WafRule entity.
 * 
 * @author mcollins
 */
public interface WafRuleDao extends GenericObjectDao<WafRule> {

	/**
	 * @param name
	 * @return
	 */
	WafRule retrieveByRule(String rule);

	/**
	 * @param vuln
	 * @param waf
	 * @return
	 */
	WafRule retrieveByVulnerabilityAndWafAndDirective(Vulnerability vuln, Waf waf, WafRuleDirective directive);

	/**
	 * 
	 * @param waf
	 * @param lastWafRuleDirective
	 * @return
	 */
	List<WafRule> retrieveByWafAndDirective(Waf waf,
			WafRuleDirective lastWafRuleDirective);

	/**
	 * @param nativeId
	 * @return
	 */
	WafRule retrieveByWafAndNativeId(String wafId, String nativeId);

	/**
	 * @param rule
	 */
	void delete(WafRule rule);

}
