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

package com.denimgroup.threadfix.data.enums;

public enum TagEnum {
	PCI("PCI","{\"tags\":[],\"severities\":{\"critical\":true,\"high\":true,\"medium\":true,\"low\":true,\"info\":true},\"daysOldModifier\":\"LastYear\",\"filterType\":{\"isComplianceFilter\":true}}"),
	HIPAA("HIPAA","{\"tags\":[],\"severities\":{\"critical\":true,\"high\":true,\"medium\":true,\"low\":false,\"info\":false},\"daysOldModifier\":\"LastYear\",\"filterType\":{\"isComplianceFilter\":true}}");

	private String name, defaultFilter;

    public String getName() {
        return name;
    }

    public String getDefaultFilter() {
        return defaultFilter;
    }

    TagEnum(String name, String defaultFilter) {
        this.name = name;
		this.defaultFilter = defaultFilter;
	}

}
