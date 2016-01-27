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

import com.denimgroup.threadfix.framework.ResourceManager;
import org.junit.Test;

import java.util.*;

/**
 * Created by sgerick on 11/12/2014.
 */
public class StrutsPropertiesParserTests {

	@Test
	public void testStrutsPropertiesFile() {

		Properties strutsProperties
				= StrutsPropertiesParser.getStrutsProperties( ResourceManager.getStrutsFile("struts.properties") );

		assert strutsProperties != null;
		assert strutsProperties.getProperty("struts.action.extension").equals("rol");
		assert strutsProperties.getProperty("struts.action.extension","default").equals("rol");
		assert strutsProperties.getProperty("strutsActionExtension") == null;
		assert strutsProperties.getProperty("strutsActionExtension","default").equals("default");

	}

}
