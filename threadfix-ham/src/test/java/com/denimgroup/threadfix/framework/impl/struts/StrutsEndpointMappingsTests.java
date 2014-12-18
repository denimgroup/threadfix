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
import com.denimgroup.threadfix.framework.TestConstants;
import com.denimgroup.threadfix.framework.engine.cleaner.DefaultPathCleaner;
import com.denimgroup.threadfix.framework.engine.full.EndpointDatabase;
import com.denimgroup.threadfix.framework.engine.full.EndpointDatabaseFactory;
import com.denimgroup.threadfix.framework.engine.full.EndpointQuery;
import com.denimgroup.threadfix.framework.engine.full.EndpointQueryBuilder;
import org.junit.Test;

import java.io.File;


public class StrutsEndpointMappingsTests {

    private String[][] TEST_DATA = {
            {"/app/src/main/java/org/apache/roller/weblogger/ui/struts2/core/Setup.java",
                    "/roller-ui/setup.rol", "POST",
                    "aggregated", "frontpageBlog", "userCount", "blogCount"},
            {"/app/src/main/java/org/apache/roller/weblogger/ui/struts2/core/Login.java",
                    "/roller-ui/login.rol", "POST",
                    "error", "authMethod"},
            {"/app/src/main/java/org/apache/roller/weblogger/ui/struts2/core/Register.java",
                    "/roller-ui/register!*.rol", "POST",
                    "servletRequest", "activationStatus", "bean", "activationCode", "authMethod"},
            {"/app/src/main/java/org/apache/roller/weblogger/ui/struts2/core/Profile.java",
                    "/roller-ui/profile!*.rol", "POST",
                    "bean", "authMethod"},
            {"/app/src/main/java/org/apache/roller/weblogger/ui/struts2/core/OAuthKeys.java",
                    "/roller-ui/oauthKeys!*.rol", "POST",
                    "userConsumer", "accessTokenURL", "requestTokenURL", "siteWideConsumer", "authorizationURL"},
            {"/app/src/main/java/org/apache/roller/weblogger/ui/struts2/core/OAuthAuthorize.java",
                    "/roller-ui/oauthAuthorize!*.rol", "POST",
                    "token", "callback", "appDesc", "userName"},
            {"/app/src/main/java/org/apache/roller/weblogger/ui/struts2/core/CreateWeblog.java",
                    "/roller-ui/createWeblog!*.rol", "POST",
                    "bean", "themes"},
            {"/app/src/main/java/org/apache/roller/weblogger/ui/struts2/core/MainMenu.java",
                    "/roller-ui/menu!*.rol", "POST",
                    "websiteId", "inviteId"},
            {"/app/src/main/java/org/apache/roller/weblogger/ui/struts2/core/Install.java",
                    "/roller-ui/install/install.rol", "POST",
                    "databaseName", "rootCauseStackTrace", "prop", "databaseProductName", "rootCauseException"},
            {"/app/src/main/java/org/apache/roller/weblogger/ui/struts2/admin/GlobalConfig.java",
                    "/roller-ui/admin/globalConfig!*.rol", "POST",
                    "globalConfigDef"},
            {"/app/src/main/java/org/apache/roller/weblogger/ui/struts2/admin/UserAdmin.java",
                    "/roller-ui/admin/userAdmin.rol", "POST",
                    "authMethod"},
            {"/app/src/main/java/org/apache/roller/weblogger/ui/struts2/admin/UserEdit.java",
                    "/roller-ui/admin/createUser!*.rol", "POST",
                    "bean", "authMethod"},
            {"/app/src/main/java/org/apache/roller/weblogger/ui/struts2/admin/UserEdit.java",
                    "/roller-ui/admin/modifyUser!*.rol", "POST",
                    "bean", "authMethod"},
            {"/app/src/main/java/org/apache/roller/weblogger/ui/struts2/admin/GlobalCommentManagement.java",
                    "/roller-ui/admin/globalCommentManagement!*.rol", "POST",
                    "pager", "lastComment", "bean", "bulkDeleteCount", "firstComment"},
            {"/app/src/main/java/org/apache/roller/weblogger/ui/struts2/admin/PingTargets.java",
                    "/roller-ui/admin/commonPingTargets!*.rol", "POST",
                    "pingTargetId", "pingTarget"},
            {"/app/src/main/java/org/apache/roller/weblogger/ui/struts2/admin/PingTargetEdit.java",
                    "/roller-ui/admin/commonPingTargetAdd!*.rol", "POST",
                    "bean"},
            {"/app/src/main/java/org/apache/roller/weblogger/ui/struts2/admin/PingTargetEdit.java",
                    "/roller-ui/admin/commonPingTargetEdit!*.rol", "POST",
                    "bean"},
            {"/app/src/main/java/org/apache/roller/weblogger/ui/struts2/admin/CacheInfo.java",
                    "/roller-ui/admin/cacheInfo!*.rol", "POST",
                    "cache", "stats"},
            {"/app/src/main/java/org/apache/roller/weblogger/planet/ui/PlanetConfig.java",
                    "/roller-ui/admin/planetConfig!*.rol", "POST",
                    "globalConfigDef", "parameters"},
            {"/app/src/main/java/org/apache/roller/weblogger/planet/ui/PlanetSubscriptions.java",
                    "/roller-ui/admin/planetSubscriptions!*.rol", "POST",
                    "subUrl", "groupHandle", "group"},
            {"/app/src/main/java/org/apache/roller/weblogger/planet/ui/PlanetGroups.java",
                    "/roller-ui/admin/planetGroups!*.rol", "POST",
                    "group", "bean"},
            {"/app/src/main/java/org/apache/roller/weblogger/ui/struts2/editor/MediaFileAdd.java",
                    "/roller-ui/authoring/mediaFileAdd!*.rol", "POST",
                    "bean", "directoryName", "directory"},
            {"/app/src/main/java/org/apache/roller/weblogger/ui/struts2/editor/MediaFileEdit.java",
                    "/roller-ui/authoring/mediaFileEdit!*.rol", "POST",
                    "uploadedFile", "bean", "uploadedFileName", "uploadedFileContentType", "directory"},
            {"/app/src/main/java/org/apache/roller/weblogger/ui/struts2/editor/MediaFileEdit.java",
                    "/roller-ui/authoring/mediaFileAddExternalInclude!*.rol", "POST",
                    "uploadedFile", "bean", "uploadedFileName", "uploadedFileContentType", "directory"},
            {"/app/src/main/java/org/apache/roller/weblogger/ui/struts2/editor/MediaFileView.java",
                    "/roller-ui/authoring/mediaFileView!*.rol", "POST",
                    "newDirectoryPath", "currentDirectory", "newDirectoryName", "viewDirectoryId", "directoryId",
                    "pager", "directoryName", "bean", "sortBy"},
            {"/app/src/main/java/org/apache/roller/weblogger/ui/struts2/editor/MediaFileImageDim.java",
                    "/roller-ui/authoring/mediaFileImageDim!*.rol", "POST",
                    "bean"},
            {"/app/src/main/java/org/apache/roller/weblogger/ui/struts2/editor/EntryAddWithMediaFile.java",
                    "/roller-ui/authoring/entryAddWithMediaFile!*.rol", "POST",
                    "bean", "selectedImage", "weblog"},
            {"/app/src/main/java/org/apache/roller/weblogger/ui/struts2/editor/EntryEdit.java",
                    "/roller-ui/authoring/entryAdd!*.rol", "POST",
                    "bean", "previewURL", "editor", "trackbackUrl", "entry", "jsonAutocompleteUrl"},
            {"/app/src/main/java/org/apache/roller/weblogger/ui/struts2/editor/EntryEdit.java",
                    "/roller-ui/authoring/entryEdit!*.rol", "POST",
                    "bean", "previewURL", "editor", "trackbackUrl", "entry", "jsonAutocompleteUrl"},
            {"/app/src/main/java/org/apache/roller/weblogger/ui/struts2/editor/EntryRemove.java",
                    "/roller-ui/authoring/entryRemove!*.rol", "POST",
                    "removeId", "removeEntry"},
            {"/app/src/main/java/org/apache/roller/weblogger/ui/struts2/editor/EntryRemove.java",
                    "/roller-ui/authoring/entryRemoveViaList!*.rol", "POST",
                    "removeId", "removeEntry"},
            {"/app/src/main/java/org/apache/roller/weblogger/ui/struts2/editor/Entries.java",
                    "/roller-ui/authoring/entries.rol", "POST",
                    "pager", "bean", "lastEntry", "firstEntry"},
            {"/app/src/main/java/org/apache/roller/weblogger/ui/struts2/editor/Comments.java",
                    "/roller-ui/authoring/comments!*.rol", "POST",
                    "pager", "lastComment", "bulkDeleteCount", "bean", "queryEntry", "firstComment"},
            {"/app/src/main/java/org/apache/roller/weblogger/ui/struts2/editor/CategoryEdit.java",
                    "/roller-ui/authoring/categoryAdd!*.rol", "POST",
                    "bean"},
            {"/app/src/main/java/org/apache/roller/weblogger/ui/struts2/editor/CategoryEdit.java",
                    "/roller-ui/authoring/categoryEdit!*.rol", "POST",
                    "bean"},
            {"/app/src/main/java/org/apache/roller/weblogger/ui/struts2/editor/CategoryRemove.java",
                    "/roller-ui/authoring/categoryRemove!*.rol", "POST",
                    "targetCategoryId", "removeId", "category"},
            {"/app/src/main/java/org/apache/roller/weblogger/ui/struts2/editor/Bookmarks.java",
                    "/roller-ui/authoring/bookmarks!*.rol", "POST",
                    "folder", "targetFolderId", "viewFolderId", "folderId"},
            {"/app/src/main/java/org/apache/roller/weblogger/ui/struts2/editor/BookmarkEdit.java",
                    "/roller-ui/authoring/bookmarkAdd!*.rol", "POST",
                    "bookmark", "bean", "folderId"},
            {"/app/src/main/java/org/apache/roller/weblogger/ui/struts2/editor/BookmarkEdit.java",
                    "/roller-ui/authoring/bookmarkEdit!*.rol", "POST",
                    "bookmark", "bean", "folderId"},
            {"/app/src/main/java/org/apache/roller/weblogger/ui/struts2/editor/BookmarksImport.java",
                    "/roller-ui/authoring/bookmarksImport!*.rol", "POST",
                    "opmlFile", "opmlFileContentType", "opmlFileFileName"},
            {"/app/src/main/java/org/apache/roller/weblogger/ui/struts2/editor/FolderEdit.java",
                    "/roller-ui/authoring/folderAdd!*.rol", "POST",
                    "bean", "folderId"},
            {"/app/src/main/java/org/apache/roller/weblogger/ui/struts2/editor/FolderEdit.java",
                    "/roller-ui/authoring/folderEdit!*.rol", "POST",
                    "bean", "folderId"},
            {"/app/src/main/java/org/apache/roller/weblogger/ui/struts2/editor/WeblogConfig.java",
                    "/roller-ui/authoring/weblogConfig!*.rol", "POST",
                    "pluginsList", "editorsList", "weblogCategories", "bean"},
            {"/app/src/main/java/org/apache/roller/weblogger/ui/struts2/editor/ThemeEdit.java",
                    "/roller-ui/authoring/themeEdit!*.rol", "POST",
                    "themeId", "themeType", "selectedThemeId"},
            {"/app/src/main/java/org/apache/roller/weblogger/ui/struts2/editor/StylesheetEdit.java",
                    "/roller-ui/authoring/stylesheetEdit!*.rol", "POST",
                    "contentsMobile", "contentsStandard", "template"},
            {"/app/src/main/java/org/apache/roller/weblogger/ui/struts2/editor/Templates.java",
                    "/roller-ui/authoring/templates!*.rol", "POST",
                    "newTmplName", "newTmplAction"},
            {"/app/src/main/java/org/apache/roller/weblogger/ui/struts2/editor/TemplateEdit.java",
                    "/roller-ui/authoring/templateEdit!*.rol", "POST",
                    "template", "bean"},
            {"/app/src/main/java/org/apache/roller/weblogger/ui/struts2/editor/TemplateRemove.java",
                    "/roller-ui/authoring/templateRemove!*.rol", "POST",
                    "template", "removeId"},
            {"/app/src/main/java/org/apache/roller/weblogger/ui/struts2/editor/TemplatesRemove.java",
                    "/roller-ui/authoring/templatesRemove!*.rol", "POST",
                    "ids"},
            {"/app/src/main/java/org/apache/roller/weblogger/ui/struts2/editor/Members.java",
                    "/roller-ui/authoring/members!*.rol", "POST",
                    "parameter", "parameters"},
            {"/app/src/main/java/org/apache/roller/weblogger/ui/struts2/editor/MembersInvite.java",
                    "/roller-ui/authoring/invite!*.rol", "POST",
                    "permissionString", "userName"},
            {"/app/src/main/java/org/apache/roller/weblogger/ui/struts2/editor/Pings.java",
                    "/roller-ui/authoring/pings!*.rol", "POST",
                    "pingStatus", "pingTargetId", "pingTarget"},
            {"/app/src/main/java/org/apache/roller/weblogger/ui/struts2/editor/MediaFileAdd.java",
                    "/roller-ui/authoring/overlay/mediaFileAdd!*.rol", "POST",
                    "bean", "directoryName", "directory"},
            {"/app/src/main/java/org/apache/roller/weblogger/ui/struts2/editor/MediaFileImageChooser.java",
                    "/roller-ui/authoring/overlay/mediaFileImageChooser!*.rol", "POST",
                    "currentDirectory", "directoryId", "directoryName"}
    };

    @Test
    public void testRoller() {
        File rootFile = new File(TestConstants.ROLLER_SOURCE_LOCATION);
        StrutsEndpointMappings mappings = new StrutsEndpointMappings(rootFile);

        EndpointDatabase database = EndpointDatabaseFactory.getDatabase(
                mappings,
                FrameworkType.STRUTS,
                new DefaultPathCleaner("", ""));

        test(database);
    }

    @Test
    public void testRollerFrameworkType() {
        File rootFile = new File(TestConstants.ROLLER_SOURCE_LOCATION);
        StrutsEndpointMappings mappings = new StrutsEndpointMappings(rootFile);

        // test with EndpointDatabaseFactory finding the FrameworkType
        EndpointDatabase database = EndpointDatabaseFactory.getDatabase(rootFile);

        test(database);
    }


    private void test(EndpointDatabase edb) {
        for (String[] endpointTest : TEST_DATA) {
            String testFileName = endpointTest[0];
            String testUrl = endpointTest[1];
            String testMethod = endpointTest[2];
            String[] testParams = null;
            if (endpointTest.length > 3) {
                testParams = new String[endpointTest.length - 3];
                for (int i = 0; i < testParams.length; i++) {
                    testParams[i] = endpointTest[i + 3];
                }
            }
            test(edb, testFileName, testUrl, testMethod, testParams);
        }
    }

    private void test(EndpointDatabase database, String fileName, String url, String method, String[] parameters) {

        EndpointQuery endpointQuery = EndpointQueryBuilder.start().setDynamicPath(url).generateQuery();

        Endpoint bestMatch = database.findBestMatch(endpointQuery);

        assert bestMatch != null : "No match found for url " + url;

        assert bestMatch.getFilePath().equals(fileName) :
                "Endpoint didn't match fileName " + fileName + ", got " + bestMatch.getFilePath() + " instead.";

        assert bestMatch.getHttpMethods().contains(method) :
                "Endpoint didn't have HTTP method " + method + ", had " + bestMatch.getHttpMethods();

        if (parameters != null) {
            for (String parameter : parameters) {
                assert bestMatch.getParameters().contains(parameter) : "Parameters didn't contain " + parameter;
            }
        }
    }

}
