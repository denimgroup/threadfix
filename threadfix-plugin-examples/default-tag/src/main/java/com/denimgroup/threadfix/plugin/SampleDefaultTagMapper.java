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

package com.denimgroup.threadfix.plugin;

/**
 * getValueAssociated(vulns) is the most important, it's the one that will associate the tag with a value under
 * depending on the vulnerabilities to be submitted.
 *
 * If you want your tag to support value mapping you'll have to implement the other functions as well, otherwise you
 * can ignore them and leave them.
 */
import java.util.List;

import org.springframework.stereotype.Component;

import com.denimgroup.threadfix.data.entities.Vulnerability;
import com.denimgroup.threadfix.service.defects.defaults.AbstractDefaultTagMapper;

@Component
public class SampleDefaultTagMapper extends AbstractDefaultTagMapper {

	/*
	 * given a list of vulnerabilities (the ones selected for defect submission) return the value
	 * you want to see appear in the field when this default tag was used for
	 */
	@Override
	public String getValueAssociated(List<Vulnerability> vulnerabilities) {
		//this example returns a string appended to the vulnerabilities ids
		String value = "The ids of the submitted vulns are:";
		for (Vulnerability vulnerability : vulnerabilities){
			value += " " + vulnerability.getId().toString();
		}
		return value;
	}

	/*
	 * this method specifies if the tag is supporting value mapping
	 * if you return true, you'll have to implement the next method to provide a set of keys for mapping
	 */
	@Override
	public boolean isSupportingValueMapping() {
		return false;
	}

	/*
	 * If you know the set of value that getValueAssociated(vulns) can return, and you have an interest in mapping that result
	 * to selectors' values, then you have to return true for isSupportingValueMapping(), and implement this function
	 * to return the set of values of interest that can be returned by getValueAssociated(vulns)
	 */
	@Override
	public List<String> getValueMappingKeys() {
		return null;
	}
	/*
	 * Example of predefined values:
	 * List<String> keys = list("value1", "value2", "value3")
	 * return keys;
	 *
	 * Note that this way of doing allows to retrieve the set of key from database if these are defined in some other way
	 */

}

