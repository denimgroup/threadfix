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
package com.denimgroup.threadfix.framework.enums;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

public enum SourceCodeAccessLevel {
	NONE("None"), DETECT("Detect"), PARTIAL("Partial"), FULL("Full");
	
	SourceCodeAccessLevel(String displayName) {
		this.displayName = displayName;
	}
	
	private String displayName;
	public String getDisplayName() { return displayName; }
	
	@NotNull
    public static SourceCodeAccessLevel getSourceCodeAccessLevel(@Nullable String input) {
		SourceCodeAccessLevel returnAccessLevel = DETECT; // default access level
		
		if (input != null) {
			for (SourceCodeAccessLevel sourceCodeAccessLevel : values()) {
				if (sourceCodeAccessLevel.toString().equals(input)) {
					returnAccessLevel = sourceCodeAccessLevel;
					break;
				}
			}
		}
		
		return returnAccessLevel;
	}
}