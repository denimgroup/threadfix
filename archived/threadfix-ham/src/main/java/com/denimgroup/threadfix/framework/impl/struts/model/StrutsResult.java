////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2014 Denim Group, Ltd.
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

import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.map;

/**
 * Created by sgerick on 11/12/2014.
 */
public class StrutsResult {
	private String name;
	private String type;
	private String value;

	public StrutsResult() {	}

	public StrutsResult(String name, String type, String value) {
		this.name = name;
		this.type = type;
		this.value = value;
	}

	private Map params;

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getType() {
		return type;
	}

	public void setType(String type) {
		this.type = type;
	}

	public String getValue() {
		return value;
	}

	public void setValue(String value) {
		this.value = value;
	}

	public Map getParams() {
		return params;
	}

	public void setParams(Map params) {
		this.params = params;
	}

	public void addParam(String name, String value) {
		if (params == null)
			params = map();
		params.put(name, value);
	}

	@Override
	public String toString() {
		if (name==null && type==null && value==null)
			return "null";
		StringBuilder sb = new StringBuilder("<result");
		if (name != null) {
			sb.append(" name=\"");
			sb.append( name );
			sb.append("\"");
		}
		if (type != null) {
			sb.append(" type=\"");
			sb.append( type );
			sb.append("\"");
		}
		if (value != null) {
			sb.append(">");
			sb.append( value );
			sb.append("</result");
		}
		sb.append(">");
		return sb.toString();
	}

}
