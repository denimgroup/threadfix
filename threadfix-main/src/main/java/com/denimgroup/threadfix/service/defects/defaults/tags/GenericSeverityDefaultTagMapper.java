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

package com.denimgroup.threadfix.service.defects.defaults.tags;

import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.GenericSeverity;
import com.denimgroup.threadfix.data.entities.Vulnerability;
import com.denimgroup.threadfix.service.GenericSeverityService;
import com.denimgroup.threadfix.service.defects.defaults.AbstractDefaultTagMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;

import static com.denimgroup.threadfix.CollectionUtils.list;

@Component
public class GenericSeverityDefaultTagMapper extends AbstractDefaultTagMapper {

	@Autowired
	private GenericSeverityService genericSeverityService;

	@Override
	public String getValueAssociated(List<Vulnerability> vulnerabilities) {
		List<Finding> firstVulnFindings = vulnerabilities.get(0).getFindings();
		if (firstVulnFindings != null){
			return firstVulnFindings.get(0).getChannelSeverity().getSeverityMap().getGenericSeverity().getName();
		}
		else return null;
	}

	@Override
	public boolean isSupportingValueMapping() {
		return true;
	}

	@Override
	public List<String> getValueMappingKeys() {
		List<GenericSeverity> genericSeverities = genericSeverityService.loadAll();
		List<String> keys = list();
		for (GenericSeverity genericSeverity : genericSeverities){
			keys.add(genericSeverity.getName());
		}
		return keys;
	}
}
