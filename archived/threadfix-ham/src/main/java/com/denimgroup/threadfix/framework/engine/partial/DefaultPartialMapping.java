////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2015 Denim Group, Ltd.
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

package com.denimgroup.threadfix.framework.engine.partial;

import com.denimgroup.threadfix.data.enums.FrameworkType;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class DefaultPartialMapping implements PartialMapping {
	
	@Nullable
    private final String staticPath, dynamicPath, frameworkGuess;
	
	public DefaultPartialMapping(@Nullable String staticPath, @Nullable String dynamicPath, @Nullable String frameworkGuess) {
		this.staticPath = staticPath;
		this.dynamicPath = dynamicPath;
		this.frameworkGuess = frameworkGuess;
	}
	
	public DefaultPartialMapping(@Nullable String staticPath, @Nullable String dynamicPath) {
		this.staticPath = staticPath;
		this.dynamicPath = dynamicPath;
		this.frameworkGuess = null;
	}

	@Override
    @Nullable
	public String getStaticPath() {
		return staticPath;
	}

	@Override
    @Nullable
	public String getDynamicPath() {
		return dynamicPath;
	}

	@Nonnull
    @Override
	public FrameworkType guessFrameworkType() {
		return FrameworkType.getFrameworkType(frameworkGuess);
	}

	@Nonnull
    @Override
	public String toString() {
		return staticPath + " <--> " + dynamicPath;
	}
	
}
