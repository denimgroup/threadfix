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
package com.denimgroup.threadfix.framework.impl.jsp;

import java.util.Set;

import com.denimgroup.threadfix.framework.engine.AbstractEndpoint;

public class JSPEndpoint extends AbstractEndpoint {
	
	private final String dynamicPath, staticPath;
	private final Set<String> parameters, methods;
	
	public JSPEndpoint(String staticPath, String dynamicPath,
			Set<String> parameters, Set<String> methods) {
		this.methods = methods;
		this.staticPath = staticPath;
		this.dynamicPath = dynamicPath;
		this.parameters = parameters;
	}

	@Override
	public Set<String> getParameters() {
		return parameters;
	}
	
	@Override
	public String getUrlPath() {
		return dynamicPath;
	}

	@Override
	public Set<String> getHttpMethods() {
		return methods;
	}

	@Override
	public boolean matchesLineNumber(int lineNumber) {
		return true; // JSPs aren't controller-based, so the whole page is the endpoint
	}

	@Override
	public String getFilePath() {
		return staticPath;
	}

	@Override
	public int getStartingLineNumber() {
		return -1; // JSPs aren't controller-based, so the whole page is the endpoint
	}

}
