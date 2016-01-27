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

import static com.denimgroup.threadfix.CollectionUtils.list;

/**
 * Created by sgerick on 11/12/2014.
 */
public class StrutsPackage {
	private String name;
	private String namespace;
	private String pkgExtends;
	private List<StrutsAction> actions;

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getNamespace() {
		return namespace;
	}

	public void setNamespace(String namespace) {
		this.namespace = namespace;
	}

	public String getPkgExtends() {
		return pkgExtends;
	}

	public void setPkgExtends(String pkgExtends) {
		this.pkgExtends = pkgExtends;
	}

	public List<StrutsAction> getActions() {
		return actions;
	}

	public void setActions(List<StrutsAction> actions) {
		this.actions = actions;
	}

	public void addAction(StrutsAction action) {
		if (actions == null)
			actions = list();
		actions.add(action);
	}

	@Override
	public String toString() {
		if (name==null && namespace==null && pkgExtends==null)
			return "null";
		StringBuilder sb = new StringBuilder("<package");
		if (name != null) {
			sb.append(" name=\"");
			sb.append( name );
			sb.append("\"");
		}
		if (namespace != null) {
			sb.append(" namespace=\"");
			sb.append( namespace );
			sb.append("\"");
		}
		if (pkgExtends != null) {
			sb.append(" extends=\"");
			sb.append( pkgExtends );
			sb.append("\"");
		}
		sb.append(">");
		return sb.toString();
	}
}
