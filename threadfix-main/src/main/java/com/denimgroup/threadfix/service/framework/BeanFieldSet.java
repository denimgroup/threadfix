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
package com.denimgroup.threadfix.service.framework;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class BeanFieldSet {

	private Map<String, BeanField> fieldMap = new HashMap<>();
	private Set<BeanField> fieldSet = null;
	
	public BeanFieldSet(Set<BeanField> fields) {
		fieldSet = fields;
		for (BeanField field : fields) {
			fieldMap.put(field.getParameterKey(), field);
		}
	}
	
	public BeanField getField(String parameterName) {
		return fieldMap.get(parameterName);
	}
	
	public boolean contains(BeanField field) {
		return fieldSet.contains(field);
	}
	
	public void addAll(BeanFieldSet beanFieldSet) {
		this.fieldSet.addAll(beanFieldSet.fieldSet);
		for (BeanField field : beanFieldSet.fieldSet) {
			fieldMap.put(field.getParameterKey(), field);
		}
	}
}
