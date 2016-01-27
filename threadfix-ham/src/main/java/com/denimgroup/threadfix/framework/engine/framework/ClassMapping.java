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
package com.denimgroup.threadfix.framework.engine.framework;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class ClassMapping {

	@Nonnull
    private final String servletName, classWithPackage;

    @Nullable
    private final String contextConfigLocation, contextClass;
	
	private static final String CLASSPATH_START = "classpath:";
	
	public ClassMapping(@Nonnull String servletName, @Nonnull String classWithPackage,
                        @Nullable String contextConfigLocation,
                        @Nullable String contextClass) {

        this.contextClass = contextClass;
		this.servletName = servletName.trim();
		this.classWithPackage = classWithPackage.trim();

		if (contextConfigLocation != null && contextConfigLocation.startsWith(CLASSPATH_START)) {
			this.contextConfigLocation = contextConfigLocation.substring(CLASSPATH_START.length());
		} else {
			this.contextConfigLocation = contextConfigLocation;
		}
	}
	
	@Nonnull
    public String getServletName() {
		return servletName;
	}
	
	@Nonnull
    public String getClassWithPackage() {
		return classWithPackage;
	}
	
	@Nullable
    public String getContextConfigLocation() {
		return contextConfigLocation;
	}

    @Nullable
    public String getContextClass() {
        return contextClass;
    }
	
	@Nonnull
    @Override
	public String toString() {
		return getServletName() + " -> " + getClassWithPackage();
	}
	
}
