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
package com.denimgroup.threadfix.framework.impl.struts.model;

import java.util.List;
import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.CollectionUtils.map;

/**
 * Created by sgerick on 11/12/2014.
 */

public class StrutsAction {
	private String name;
	private String method;
	private String actClass;
	private Map<String, String> params;
	private List<StrutsResult> results;

	public StrutsAction() { }

	public StrutsAction(String name, String method, String actClass) {
		this.name = name;
		this.method = method;
		this.actClass = actClass;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getMethod() {
		return method;
	}

	public void setMethod(String method) {
		this.method = method;
	}

	public String getActClass() {
		return actClass;
	}

	public void setActClass(String actClass) {
		this.actClass = actClass;
	}

	public Map<String, String> getParams() {
		return params;
	}

	public void setParams(Map<String, String> params) {
		this.params = params;
	}

	public void addParam(String name, String value) {
		if (params == null)
			params = map();
		params.put(name, value);
	}

	public List<StrutsResult> getResults() {
		return results;
	}

	public void setResults(List<StrutsResult> results) {
		this.results = results;
	}

	public void addResult(StrutsResult result) {
		if (results == null)
			results = list();
		results.add(result);
	}

	@Override
	public String toString() {
		if (name==null && method==null && actClass==null)
			return "null";
		StringBuilder sb = new StringBuilder("<action");
		if (name != null) {
			sb.append(" name=\"");
			sb.append( name );
			sb.append("\"");
		}
		if (method != null) {
			sb.append(" method=\"");
			sb.append( method );
			sb.append("\"");
		}
		if (actClass != null) {
			sb.append(" class=\"");
			sb.append( actClass );
			sb.append("\"");
		}
		sb.append(">");
		return sb.toString();
	}
}
