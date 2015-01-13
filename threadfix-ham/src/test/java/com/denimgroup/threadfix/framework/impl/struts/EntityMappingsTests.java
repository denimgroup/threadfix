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

import com.denimgroup.threadfix.framework.TestConstants;
import com.denimgroup.threadfix.framework.impl.model.ModelField;
import com.denimgroup.threadfix.framework.impl.model.ModelFieldSet;
import com.denimgroup.threadfix.framework.util.java.EntityMappings;
import org.junit.Test;

import java.io.File;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class EntityMappingsTests {

	@Test
	public void testUserFields() {
		File file = new File( TestConstants.ROLLER_SOURCE_LOCATION );

		EntityMappings mappings = new EntityMappings(file);
		
		ModelFieldSet userFields = mappings.getPossibleParametersForModelType("User");

		assertNotNull(userFields);
		assertEquals(userFields.getFieldSet().size(), 12);

		assertTrue(userFields.getField("id").getType().equals("String"));
		assertTrue(userFields.getField("userName").getType().equals("String"));
		assertTrue(userFields.getField("password").getType().equals("String"));
		assertTrue(userFields.getField("openIdUrl").getType().equals("String"));
		assertTrue(userFields.getField("screenName").getType().equals("String"));
		assertTrue(userFields.getField("fullName").getType().equals("String"));
		assertTrue(userFields.getField("emailAddress").getType().equals("String"));
		assertTrue(userFields.getField("dateCreated").getType().equals("Date"));
		assertTrue(userFields.getField("locale").getType().equals("String"));
		assertTrue(userFields.getField("timeZone").getType().equals("String"));
		assertTrue(userFields.getField("enabled").getType().equals("Boolean"));
		assertTrue(userFields.getField("activationCode").getType().equals("String"));

	}

	@Test
	public void testConfigModel() {
		File file = new File( TestConstants.ROLLER_SOURCE_LOCATION );

		EntityMappings mappings = new EntityMappings(file);

		ModelFieldSet configModel = mappings.getPossibleParametersForModelType("ConfigModel");

		assertNotNull(configModel);
		assertEquals(configModel.getFieldSet().size(), 21);

		assertEquals("String", configModel.getField("modelName").getType() );
		assertEquals("String", configModel.getField("siteName").getType() );
		assertEquals("String", configModel.getField("siteShortName").getType() );
		assertEquals("String", configModel.getField("siteDescription").getType() );
		assertEquals("String", configModel.getField("siteEmail").getType() );
		assertEquals("boolean", configModel.getField("registrationEnabled").getType() );
		assertEquals("String", configModel.getField("registrationURL").getType() );
		assertEquals("boolean", configModel.getField("feedHistoryEnabled").getType() );
		assertEquals("int", configModel.getField("feedSize").getType() );
		assertEquals("int", configModel.getField("feedMaxSize").getType() );
		assertEquals("boolean", configModel.getField("feedStyle").getType() );
		assertEquals("boolean", configModel.getField("commentHtmlAllowed").getType() );
		assertEquals("boolean", configModel.getField("commentAutoFormat").getType() );
		assertEquals("boolean", configModel.getField("commentEscapeHtml").getType() );
		assertEquals("boolean", configModel.getField("commentEmailNotify").getType() );
		assertEquals("boolean", configModel.getField("trackbacksEnabled").getType() );
		assertEquals("String", configModel.getField("rollerVersion").getType() );
		assertEquals("String", configModel.getField("rollerBuildTimestamp").getType() );
		assertEquals("String", configModel.getField("rollerBuildUser").getType() );
		assertEquals("String", configModel.getField("defaultAnalyticsTrackingCode").getType() );
		assertEquals("boolean", configModel.getField("analyticsOverrideAllowed").getType());

	}

	@Test
	public void testMediaFile() {
		File file = new File( TestConstants.ROLLER_SOURCE_LOCATION );

		EntityMappings mappings = new EntityMappings(file);

		ModelFieldSet mediaFile = mappings.getPossibleParametersForModelType("MediaFile");
		assertNotNull(mediaFile);

		assertEquals("String", mediaFile.getField("id").getType() );
		assertEquals("String", mediaFile.getField("name").getType() );
		assertEquals("String", mediaFile.getField("description").getType() );
		assertEquals("String", mediaFile.getField("copyrightText").getType() );
		assertEquals("long", mediaFile.getField("length").getType() );
		assertEquals("Timestamp", mediaFile.getField("dateUploaded").getType() );
		assertEquals("long", mediaFile.getField("lastModified").getType() );
		assertEquals("Timestamp", mediaFile.getField("lastUpdated").getType() );
		assertEquals("Set", mediaFile.getField("addedTags").getType() );
		assertEquals("Set", mediaFile.getField("removedTags").getType() );
		assertEquals("String", mediaFile.getField("tagsAsString").getType() );
		assertEquals("String", mediaFile.getField("contentType").getType() );
		assertEquals("String", mediaFile.getField("path").getType() );
		assertEquals("InputStream", mediaFile.getField("inputStream").getType() );
		assertEquals("String", mediaFile.getField("permalink").getType() );
		assertEquals("String", mediaFile.getField("thumbnailURL").getType() );
		assertEquals("String", mediaFile.getField("creatorUserName").getType() );
		assertEquals("String", mediaFile.getField("originalPath").getType() );
		assertEquals("int", mediaFile.getField("width").getType() );
		assertEquals("int", mediaFile.getField("height").getType() );
		assertEquals("InputStream", mediaFile.getField("thumbnailInputStream").getType() );
		assertEquals("int", mediaFile.getField("thumbnailHeight").getType() );
		assertEquals("int", mediaFile.getField("thumbnailWidth").getType() );

		assertEquals("String", mediaFile.getField("directory.id").getType() );
		assertEquals("String", mediaFile.getField("directory.description").getType() );
		assertEquals("String", mediaFile.getField("directory.name").getType() );
		assertEquals("String", mediaFile.getField("directory.weblog.id").getType() );
		assertEquals("String", mediaFile.getField("directory.weblog.name").getType() );
		assertEquals("Boolean", mediaFile.getField("directory.weblog.active").getType() );
		assertEquals("Boolean", mediaFile.getField("directory.weblog.allowComments").getType() );
		assertEquals("long", mediaFile.getField("directory.weblog.commentCount").getType() );
		assertEquals("boolean", mediaFile.getField("directory.weblog.commentModerationRequired").getType() );
		assertEquals("Date", mediaFile.getField("directory.weblog.dateCreated").getType() );
		assertEquals("Boolean", mediaFile.getField("directory.weblog.defaultAllowComments").getType() );
		assertEquals("int", mediaFile.getField("directory.weblog.defaultCommentDays").getType() );
		assertEquals("Boolean", mediaFile.getField("directory.weblog.emailComments").getType() );
		assertEquals("Boolean", mediaFile.getField("directory.weblog.enableBloggerApi").getType() );
		assertEquals("long", mediaFile.getField("directory.weblog.entryCount").getType() );
		assertEquals("int", mediaFile.getField("directory.weblog.entryDisplayCount").getType() );
		assertEquals("String", mediaFile.getField("directory.weblog.id").getType() );
		assertEquals("Date", mediaFile.getField("directory.weblog.lastModified").getType() );
		assertEquals("Boolean", mediaFile.getField("directory.weblog.moderateComments").getType() );
		assertEquals("int", mediaFile.getField("directory.weblog.todaysHits").getType() );
		assertEquals("Boolean", mediaFile.getField("directory.weblog.visible").getType() );
		assertEquals("String", mediaFile.getField("directory.weblog.bookmarkFolder.id").getType() );
		assertEquals("String", mediaFile.getField("directory.weblog.weblogEntry.id").getType() );
		assertEquals("String", mediaFile.getField("directory.weblog.weblogEntry.category.id").getType() );
		assertEquals("String", mediaFile.getField("directory.weblog.weblogEntry.creator.id").getType() );

	}
	@Test
	public void testMediaFileBean() {
		File file = new File(TestConstants.ROLLER_SOURCE_LOCATION);

		EntityMappings mappings = new EntityMappings(file);

		ModelFieldSet mediaFileBean = mappings.getPossibleParametersForModelType("MediaFileBean");

		assertNotNull(mediaFileBean);
		assertEquals(mediaFileBean.getFieldSet().size(), 13);

		assertEquals("String", mediaFileBean.getField("name").getType() );
		assertEquals("String", mediaFileBean.getField("description").getType() );
		assertEquals("String", mediaFileBean.getField("copyrightText").getType() );
		assertEquals("String", mediaFileBean.getField("tagsAsString").getType() );
		assertEquals("String", mediaFileBean.getField("directoryId").getType() );
		assertEquals("String", mediaFileBean.getField("id").getType() );
		assertEquals("String", mediaFileBean.getField("permalink").getType() );
		assertEquals("String", mediaFileBean.getField("thumbnailURL").getType() );
		assertEquals("int", mediaFileBean.getField("width").getType() );
		assertEquals("int", mediaFileBean.getField("height").getType() );
		assertEquals("long", mediaFileBean.getField("length").getType() );
		assertEquals("String", mediaFileBean.getField("contentType").getType() );
		assertEquals("String", mediaFileBean.getField("originalPath").getType());

	}

}
