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

public class BeanField {
	
	public BeanField(String fieldType, String methodName) {
		if (fieldType == null) {
			this.fieldType = "empty";
		} else {
			this.fieldType = fieldType;
		}
		
		if (methodName == null) {
			this.parameterKey = "empty";
		} else {
			this.parameterKey = getParameterKey(methodName);
		}
	}
	
	private String getParameterKey(String methodCall) {
		String propertyName = methodCall;
		
		if (methodCall.startsWith("get")) {
			// transform from bean accessor to parameter name
			propertyName = methodCall.substring(3);
			propertyName = propertyName.substring(0,1).toLowerCase() + propertyName.substring(1);
		}
		
		return propertyName;
	}

	private final String fieldType, parameterKey;

	public String getType() {
		return fieldType;
	}

	public String getParameterKey() {
		return parameterKey;
	}
	
	public boolean isPrimitiveType() {
		return "Integer".equals(fieldType) || "String".equals(fieldType) || "int".equals(fieldType);
	}
	
	@Override
	public String toString() {
		return parameterKey + ":" + fieldType;
	}
	
	@Override
	public int hashCode() {
		return fieldType.hashCode() * 37 + parameterKey.hashCode();
	}
	
	@Override
	public boolean equals(Object object) {
		return object != null && object.hashCode() == hashCode();
	}
}
