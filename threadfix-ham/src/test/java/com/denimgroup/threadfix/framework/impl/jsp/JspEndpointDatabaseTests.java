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
package com.denimgroup.threadfix.framework.impl.jsp;

import static org.junit.Assert.assertTrue;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.junit.Test;

import com.denimgroup.threadfix.framework.TestConstants;
import com.denimgroup.threadfix.framework.engine.full.Endpoint;
import com.denimgroup.threadfix.framework.engine.full.EndpointDatabase;
import com.denimgroup.threadfix.framework.engine.full.EndpointDatabaseFactory;
import com.denimgroup.threadfix.framework.engine.full.EndpointQuery;
import com.denimgroup.threadfix.framework.engine.full.EndpointQueryBuilder;
import com.denimgroup.threadfix.framework.engine.partial.DefaultPartialMapping;
import com.denimgroup.threadfix.framework.engine.partial.PartialMapping;
import com.denimgroup.threadfix.framework.enums.FrameworkType;
import com.denimgroup.threadfix.framework.enums.InformationSourceType;

public class JspEndpointDatabaseTests {

	@Nullable
    private EndpointDatabase getBodgeItDatabase() {
		File file = new File(TestConstants.BODGEIT_SOURCE_LOCATION);
		
		List<PartialMapping> partialMappings = new ArrayList<>();
		
		for (String page : pages) {
			partialMappings.add(new DefaultPartialMapping(null, dynamicRoot + page));
		}
		
		EndpointDatabase db = EndpointDatabaseFactory.getDatabase(file, partialMappings);
		
		assertTrue(db.getFrameworkType() == FrameworkType.JSP);
		
		return db;
	}
	
	@Test
	public void testBodgeItDynamicToStaticPathQueries() {
		
		EndpointDatabase db = getBodgeItDatabase();
		
		for (String page : pages) {
			
			String dynamicPage = dynamicRoot + page;
			String staticPage  = staticRoot + page;
			
			String result = getStaticPath(db, dynamicPage);
			assertTrue("Input: " + dynamicPage + ", expected " + staticPage + " but got " + result, staticPage.equals(result));
		}
	}
	
	@NotNull
    String dynamicRoot = "/bodgeit/", staticRoot = "/root/";
	
	@NotNull
    String[] pages = {
		"about.jsp",
		"admin.jsp",
		"advanced.jsp",
		"basket.jsp",
		"contact.jsp",
		"footer.jsp",
		"header.jsp",
		"home.jsp",
		"init.jsp",
		"login.jsp",
		"logout.jsp",
		"password.jsp",
		"product.jsp",
		"register.jsp",
		"score.jsp",
		"search.jsp",
	};
	
	@NotNull
    private String getStaticPath(@NotNull EndpointDatabase db, String dynamicPath) {
		EndpointQuery query = EndpointQueryBuilder.start()
				.setInformationSourceType(InformationSourceType.DYNAMIC)
				.setDynamicPath(dynamicPath)
				.generateQuery();
		
		Endpoint endpoint = db.findBestMatch(query);
		
		if (endpoint == null) {
			return "null result";
		} else {
			return endpoint.getFilePath();
		}
	}
	
}
