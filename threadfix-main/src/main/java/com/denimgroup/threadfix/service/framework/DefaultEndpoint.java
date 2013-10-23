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

import java.util.Set;

public class DefaultEndpoint implements Endpoint {
	
	private final String method, path;
	private final Set<String> parameters;
	
	public DefaultEndpoint(String path, Set<String> parameters, String method) {
		this.method = method;
		this.path = path;
		this.parameters = parameters;
	}
	
	@Override
	public Set<String> getParameters() {
		return parameters;
	}
	
	private String getParametersString() {
		StringBuilder builder = new StringBuilder("[");
		if (parameters != null) {
			for (String param : parameters) {
				builder.append(param).append(" ");
			}
		}
		if (builder.length() > 1) {
			builder.deleteCharAt(builder.length() - 1);
		}
		
		return builder.append("]").toString();
	}

	@Override
	public String getPath() {
		return path;
	}

	@Override
	public String getMethod() {
		return method;
	}

	// TODO decide whether to escape the parameters or leave them like this
	@Override
	public String getCSVLine() {
		return method + "," + path + "," + getParametersString();
	}
	
	@Override
	public String toString() {
		return getCSVLine();
	}

}
