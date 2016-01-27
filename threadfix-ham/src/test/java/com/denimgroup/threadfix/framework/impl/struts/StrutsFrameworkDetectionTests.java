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

package com.denimgroup.threadfix.framework.impl.struts;

import com.denimgroup.threadfix.data.enums.FrameworkType;
import com.denimgroup.threadfix.framework.TestConstants;
import com.denimgroup.threadfix.framework.engine.framework.FrameworkCalculator;
import org.junit.Test;

import java.io.File;

import static org.junit.Assert.assertTrue;

public class StrutsFrameworkDetectionTests {

	@Test
	public void strutsTest() {
		FrameworkType type = FrameworkCalculator.getType( TestConstants.ROLLER_SOURCE_LOCATION );
		assertTrue("Didn't find STRUTS, found " + type + ".", type == FrameworkType.STRUTS);
	}

	@Test
	public void bodgeitTest() {
		FrameworkType type = FrameworkCalculator.getType(new File(TestConstants.BODGEIT_SOURCE_LOCATION));
		assertTrue("Didn't find JSP, found " + type + ".", type == FrameworkType.JSP);
	}
	
	@Test
	public void wavsepTest() {
		FrameworkType type = FrameworkCalculator.getType(new File(TestConstants.WAVSEP_SOURCE_LOCATION));
		assertTrue("Didn't find JSP, found " + type + ".", type == FrameworkType.JSP);
	}

	@Test
	public void basicDotNetTest() {
		FrameworkType type = FrameworkCalculator.getType(new File(TestConstants.DOT_NET_SAMPLE));
		assertTrue("Didn't find DOT_NET_MVC, found " + type + ".", type == FrameworkType.DOT_NET_MVC);
	}

	@Test
	public void basicWebFormsTest() {
		FrameworkType type = FrameworkCalculator.getType(new File(TestConstants.WEB_FORMS_SAMPLE));
		assertTrue("Didn't find DOT_NET_WEB_FORMS, found " + type + ".", type == FrameworkType.DOT_NET_WEB_FORMS);
	}

}
