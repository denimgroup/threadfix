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
package com.denimgroup.threadfix.framework.impl.struts;

import com.denimgroup.threadfix.data.enums.FrameworkType;
import com.denimgroup.threadfix.data.interfaces.Endpoint;
import com.denimgroup.threadfix.framework.engine.cleaner.DefaultPathCleaner;
import com.denimgroup.threadfix.framework.engine.full.EndpointDatabase;
import com.denimgroup.threadfix.framework.engine.full.EndpointDatabaseFactory;
import com.denimgroup.threadfix.framework.engine.full.EndpointQuery;
import com.denimgroup.threadfix.framework.engine.full.EndpointQueryBuilder;
import org.junit.Test;

import java.io.File;

import static org.junit.Assert.assertTrue;

public class StrutsEndpointMappingsTests {
	
//	@Test
//	public void printEndpoints() {
//		File file = new File(TestConstants.PETCLINIC_SOURCE_LOCATION);
//		SpringControllerMappings mappings = new SpringControllerMappings(file);
//
//		for (Endpoint endpoint: mappings.generateEndpoints()) {
//			System.out.println(endpoint);
//		}
//	}
	
	@Test
	public void testRoller() {
        File rootFile = new File("C:/SourceCode/roller-weblogger-5.1.1-source/app/src");
        StrutsEndpointMappings mappings = new StrutsEndpointMappings(rootFile);

        EndpointDatabase database = EndpointDatabaseFactory.getDatabase(
                mappings,
                FrameworkType.STRUTS,
                new DefaultPathCleaner("",""));

        test(database, "/main/java/org/apache/roller/weblogger/ui/struts2/core/Register.java",
                "/roller-ui/register!*.rol", "POST",
                "servletRequest", "activationStatus", "bean", "activationCode", "authMethod");

        test(database, "/main/java/org/apache/roller/weblogger/ui/struts2/admin/UserEdit.java",
                "/roller-ui/admin/modifyUser!*.rol", "POST", "bean", "authMethod");

        test(database, "/main/java/org/apache/roller/weblogger/ui/struts2/editor/MediaFileAdd.java",
                "/roller-ui/authoring/overlay/mediaFileAdd!*.rol", "POST", "bean", "directoryName", "directory");

        test(database, "/main/java/org/apache/roller/weblogger/ui/struts2/editor/MediaFileImageChooser.java",
                "/roller-ui/authoring/overlay/mediaFileImageChooser!*.rol", "POST",
                "currentDirectory", "directoryId", "directoryName");

        test(database, "/main/java/org/apache/roller/weblogger/ui/struts2/editor/ThemeEdit.java",
                "/roller-ui/authoring/themeEdit!*.rol", "POST", "themeId", "themeType", "selectedThemeId");

        test(database, "/main/java/org/apache/roller/weblogger/ui/struts2/editor/Comments.java",
                "/roller-ui/authoring/comments!*.rol", "POST",
                "pager", "lastComment", "bulkDeleteCount", "bean", "queryEntry", "firstComment");

    }

    private void test(EndpointDatabase database, String fileName, String url, String method, String... parameters) {

        EndpointQuery endpointQuery = EndpointQueryBuilder.start().setDynamicPath(url).generateQuery();

        Endpoint bestMatch = database.findBestMatch(endpointQuery);

        assert bestMatch != null : "No match found for url " + url;

        assert bestMatch.getFilePath().equals(fileName) :
                "Endpoint didn't match fileName " + fileName + ", got " + bestMatch.getFilePath() + " instead.";

        assert bestMatch.getHttpMethods().contains(method) :
                "Endpoint didn't have HTTP method " + method + ", had " + bestMatch.getHttpMethods();

        for (String parameter : parameters) {
            assert bestMatch.getParameters().contains(parameter) : "Parameters didn't contain " + parameter;
        }

    }

}
