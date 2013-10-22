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

import static org.junit.Assert.*;

import java.io.File;

import org.junit.Test;

public class DispatcherServletParserTests {
	
	@Test
	public void testPetClinic() {
		assertTrue("The dispatcher servlet parser found false when it should have found true.",
				DispatcherServletParser.usesSpringMvcAnnotations(
				new File(TestConstants.MVC_DISPATCHER_1)));
	}
	
	@Test
	public void testNonMVC() {
		assertTrue("The dispatcher servlet parser found true when it should have found false.",
				!DispatcherServletParser.usesSpringMvcAnnotations(
						new File(TestConstants.MVC_DISPATCHER_2)));
	}
	
	@Test
	public void testNonExistentFile() {
		assertTrue("The dispatcher servlet parser found true when it should have found false.",
				!DispatcherServletParser.usesSpringMvcAnnotations(
						new File(TestConstants.FAKE_FILE)));
	}
	
	@Test
	public void testNullInput() {
		assertTrue("The dispatcher servlet parser found true when it should have found false.",
				!DispatcherServletParser.usesSpringMvcAnnotations(null));
	}
}
