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
import com.denimgroup.threadfix.data.enums.SourceCodeAccessLevel;
import com.denimgroup.threadfix.framework.TestConstants;
import com.denimgroup.threadfix.framework.engine.CodePoint;
import com.denimgroup.threadfix.framework.engine.DefaultCodePoint;
import com.denimgroup.threadfix.framework.engine.ProjectConfig;
import com.denimgroup.threadfix.framework.engine.full.EndpointQuery;
import com.denimgroup.threadfix.framework.engine.full.EndpointQueryBuilder;
import com.denimgroup.threadfix.framework.engine.parameter.ParameterParser;
import com.denimgroup.threadfix.framework.engine.parameter.ParameterParserFactory;
import com.denimgroup.threadfix.framework.impl.spring.SpringDataFlowParser;
import org.junit.Test;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.io.File;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertTrue;

public class StrutsParameterParsingTests {
	
	@Nonnull
    static ProjectConfig
		defaultConfig = new ProjectConfig(FrameworkType.STRUTS, SourceCodeAccessLevel.FULL,
			new File(TestConstants.ROLLER_SOURCE_LOCATION), null);

    static {
        assert new File(TestConstants.ROLLER_SOURCE_LOCATION).exists() :
                "Roller source didn't exist: " + TestConstants.ROLLER_SOURCE_LOCATION;
    }
	
	// These are immutable so it's ok to use the same one for all the tests
	@Nonnull
    static StrutsDataFlowParser parser = new StrutsDataFlowParser(defaultConfig);
	@Nullable
    static ParameterParser factoryParser = ParameterParserFactory.getParameterParser(defaultConfig);
	
	@Nonnull
    static ParameterParser[] allParsers = {
		factoryParser,
		parser };

	@Test
	public void testBeanUserName() {

		for (ParameterParser parser : allParsers) {
			// These are from the Roller Fortify results
			List<? extends CodePoint> basicModelElements = Arrays.asList(
				new DefaultCodePoint("app/src/main/java/org/apache/roller/weblogger/ui/struts2/core/Register.java",422,
						"public void setBean(ProfileBean bean) {"),
				new DefaultCodePoint("app/src/main/java/org/apache/roller/weblogger/ui/struts2/core/Register.java", 423,
						"this.bean = bean;"),
				new DefaultCodePoint("app/src/main/java/org/apache/roller/weblogger/ui/struts2/core/Register.java", 419,
						"return bean;"),
				new DefaultCodePoint("app/src/main/java/org/apache/roller/weblogger/ui/struts2/core/Register.java", 192,
						"ud.setUserName(getBean().getUserName());"),
				new DefaultCodePoint("app/src/main/java/org/apache/roller/weblogger/pojos/User.java", 90,
						"return this.userName;"),
				new DefaultCodePoint("app/src/main/java/org/apache/roller/weblogger/ui/struts2/ajax/UserDataServlet.java", 111,
						"response.getWriter().print(user.getUserName());")
			);

			EndpointQuery finding = EndpointQueryBuilder.start()
					.setCodePoints(basicModelElements)
					.generateQuery();

			String result = parser.parse(finding);
			assertTrue("Parameter was " + result + " instead of bean.userName", "bean.userName".equals(result));
//			System.out.println("result = " + result);
		}
	}

	@Test
	public void testScreenName() {

		for (ParameterParser parser : allParsers) {
			List<? extends CodePoint> basicModelElements = Arrays.asList(
					new DefaultCodePoint("app/src/main/java/org/apache/roller/weblogger/pojos/User.java",147,
							"public void setScreenName( String screenName ) {"),
					new DefaultCodePoint("app/src/main/java/org/apache/roller/weblogger/pojos/User.java", 148,
							"this.screenName = screenName;"),
					new DefaultCodePoint("app/src/main/java/org/apache/roller/weblogger/pojos/User.java", 144,
							"return this.screenName;"),
					new DefaultCodePoint("app/src/main/java/org/apache/roller/weblogger/ui/struts2/ajax/UserDataServlet.java", 117,
							"response.getWriter().println(user.getScreenName());")
			);

			EndpointQuery finding = EndpointQueryBuilder.start()
					.setCodePoints(basicModelElements)
					.generateQuery();

			String result = parser.parse(finding);
			assertTrue("Parameter was " + result + " instead of screenName ", "screenName".equals(result));
//			System.out.println("result = " + result);
		}
	}

	@Test
	public void testGroupPlanetDescription() {

		for (ParameterParser parser : allParsers) {
			List<? extends CodePoint> basicModelElements = Arrays.asList(
					new DefaultCodePoint("app/src/main/java/org/apache/roller/weblogger/planet/ui/PlanetSubscriptions.java", 223,
							"public void setGroup(PlanetGroup group) {"),
					new DefaultCodePoint("app/src/main/java/org/apache/roller/weblogger/planet/ui/PlanetSubscriptions.java", 224,
							"this.group = group;"),
					new DefaultCodePoint("app/src/main/java/org/apache/roller/weblogger/planet/ui/PlanetSubscriptions.java", 220,
							"return group;"),
					new DefaultCodePoint("app/src/main/java/org/apache/roller/weblogger/planet/ui/PlanetSubscriptions.java", 100,
							"dummy = group.getPlanet();"),
					new DefaultCodePoint("app/src/main/java/org/apache/roller/planet/pojos/PlanetGroup.java", 127,
							"return planet;"),
					new DefaultCodePoint("app/src/main/java/org/apache/roller/planet/business/jpa/JPAPlanetManagerImpl.java", 200,
							"dummy.setParameter(1, planet.getDescription());")

			);

			EndpointQuery finding = EndpointQueryBuilder.start()
					.setCodePoints(basicModelElements)
					.generateQuery();

			String result = parser.parse(finding);
			assertTrue("Parameter was " + result + " instead of group.planet.description ", "group.planet.description".equals(result));
//			System.out.println("result = " + result);
		}
	}

    @Test(expected= NullPointerException.class)
    public void testNullConstructorArg() {
        parser.parse(null);
    }
}
