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

package com.denimgroup.threadfix.service;

import java.util.List;
import com.denimgroup.threadfix.data.entities.DefaultTag;
import com.denimgroup.threadfix.data.entities.Vulnerability;

public interface DefaultTagMappingService extends GenericNamedObjectService<DefaultTag> {

	public String evaluateTagValueForVulns(DefaultTag tag, List<Vulnerability> vulnerabilities);

	/**
	 * This function is meant to be compliant with the protocol for listing the available tags 
	 * and return a map that can just be integrated in larger object before serialization
	 * 
	 */
	public List<Object> getTagsWithValueMappingFields();

	public List<String> getTagKeysOrNull(String tagName);

	String evaluateTagValueForVulnsFromPattern(String dynamicPattern, List<Vulnerability> vulnerabilities);
}
