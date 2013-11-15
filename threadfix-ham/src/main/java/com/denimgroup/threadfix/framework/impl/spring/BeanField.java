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
package com.denimgroup.threadfix.framework.impl.spring;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

class BeanField {
	
	public BeanField(@NotNull String fieldType, @NotNull String methodName) {
		this.fieldType = fieldType;
        this.parameterKey = getParameterKey(methodName);
	}
	
	@NotNull
    private String getParameterKey(@NotNull String methodCall) {
		String propertyName = methodCall;
		
		if (methodCall.startsWith("get")) {
			// transform from bean accessor to parameter name
			propertyName = methodCall.substring(3);
			propertyName = propertyName.substring(0,1).toLowerCase() + propertyName.substring(1);
		}
		
		return propertyName;
	}

	@NotNull
    private final String fieldType, parameterKey;

	@NotNull
    public String getType() {
		return fieldType;
	}

	@NotNull
    public String getParameterKey() {
		return parameterKey;
	}
	
	public boolean isPrimitiveType() {
		return "Integer".equals(fieldType) || "String".equals(fieldType) || "int".equals(fieldType);
	}
	
	@NotNull
    @Override
	public String toString() {
		return parameterKey + ":" + fieldType;
	}
	
	@Override
	public int hashCode() {
		return fieldType.hashCode() * 37 + parameterKey.hashCode();
	}
	
	@Override
	public boolean equals(@Nullable Object object) {
		return object instanceof BeanField && object.hashCode() == hashCode();
	}
}
