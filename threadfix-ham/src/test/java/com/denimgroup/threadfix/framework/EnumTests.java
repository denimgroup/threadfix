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
package com.denimgroup.threadfix.framework;

import com.denimgroup.threadfix.data.enums.FrameworkType;
import com.denimgroup.threadfix.data.enums.InformationSourceType;
import com.denimgroup.threadfix.data.enums.SourceCodeAccessLevel;
import org.junit.Test;

import javax.annotation.Nonnull;

import static org.junit.Assert.assertTrue;

public class EnumTests {
	
	@Nonnull
    private String upperAndUnderscore(@Nonnull String input) {
		return input.toUpperCase().replace(' ', '_');
	}

	@Test
	public void testFrameworkType() {
		for (FrameworkType frameworkType : FrameworkType.values()) {
            String lookupString = frameworkType == FrameworkType.DOT_NET_MVC ?
                "DOT_NET_MVC":
                upperAndUnderscore(frameworkType.getDisplayName());

			assertTrue("Enum lookup is broken for " + frameworkType,
                    FrameworkType.getFrameworkType(lookupString) == frameworkType);
		}
	}
	
	@Test
	public void testSourceCodeAccessLevel() {
		for (SourceCodeAccessLevel sourceCodeAccessLevel : SourceCodeAccessLevel.values()) {
			assertTrue("Enum lookup is broken", SourceCodeAccessLevel.getSourceCodeAccessLevel(upperAndUnderscore(sourceCodeAccessLevel.getDisplayName())) == sourceCodeAccessLevel);
		}
	}
	
	@Test
	public void testInformationSourceType() {
		assertTrue("There were other than 3 values for InformationSourceType", InformationSourceType.values().length == 3);
	}
	
}
