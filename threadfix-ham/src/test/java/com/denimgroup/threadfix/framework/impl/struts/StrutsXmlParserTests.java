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

import com.denimgroup.threadfix.framework.ResourceManager;
import com.denimgroup.threadfix.framework.impl.struts.model.StrutsAction;
import com.denimgroup.threadfix.framework.impl.struts.model.StrutsPackage;
import com.denimgroup.threadfix.framework.impl.struts.model.StrutsResult;
import org.junit.Test;

import java.util.*;

import static com.denimgroup.threadfix.CollectionUtils.list;

/**
 * Created by sgerick on 11/12/2014.
 */
public class StrutsXmlParserTests {

	@Test
	public void testBasicStrutsXmlFile() {
		String[][] PACKAGE_VALUES = {
				// name, namespace, extends
				{"weblogger", "/roller-ui", "struts-default"},
				{"weblogger-install", "/roller-ui/install", "weblogger"},
				{"weblogger-admin", "/roller-ui/admin", "weblogger"},
				{"weblogger-authoring", "/roller-ui/authoring", "weblogger"},
				{"weblogger-authoring-overlay", "/roller-ui/authoring/overlay", "weblogger-authoring"}
		};

		String[][] ROLLER_ACTIONS = {  //  11 Actions
				// name, class, method
				{"home", null, null},
				{"login-redirect", null, null},
				{"logout", null, null},
				{"setup", "org.apache.roller.weblogger.ui.struts2.core.Setup", null},
				{"login", "org.apache.roller.weblogger.ui.struts2.core.Login", null},
				{"register!*", "org.apache.roller.weblogger.ui.struts2.core.Register", "{1}"},
				{"profile!*", "org.apache.roller.weblogger.ui.struts2.core.Profile", "{1}"},
				{"oauthKeys!*", "org.apache.roller.weblogger.ui.struts2.core.OAuthKeys", "{1}"},
				{"oauthAuthorize!*", "org.apache.roller.weblogger.ui.struts2.core.OAuthAuthorize", "{1}"},
				{"createWeblog!*", "org.apache.roller.weblogger.ui.struts2.core.CreateWeblog", "{1}"},
				{"menu!*", "org.apache.roller.weblogger.ui.struts2.core.MainMenu", "{1}"}
		};

		String[][] ROLLER_INSTALL_ACTIONS = {    //  1 Actions
				// name, class, method
				new String[]{"install", "org.apache.roller.weblogger.ui.struts2.core.Install", null}
		};

		String[][] ROLLER_ADMIN_ACTIONS = {    //  12 Actions
				// name, class, method
				{"globalConfig!*", "org.apache.roller.weblogger.ui.struts2.admin.GlobalConfig", "{1}"},
				{"userAdmin", "org.apache.roller.weblogger.ui.struts2.admin.UserAdmin", null},
				{"createUser!*", "org.apache.roller.weblogger.ui.struts2.admin.UserEdit", "{1}"},
				{"modifyUser!*", "org.apache.roller.weblogger.ui.struts2.admin.UserEdit", "{1}"},
				{"globalCommentManagement!*", "org.apache.roller.weblogger.ui.struts2.admin.GlobalCommentManagement", "{1}"},
				{"commonPingTargets!*", "org.apache.roller.weblogger.ui.struts2.admin.PingTargets", "{1}"},
				{"commonPingTargetAdd!*", "org.apache.roller.weblogger.ui.struts2.admin.PingTargetEdit", "{1}"},
				{"commonPingTargetEdit!*", "org.apache.roller.weblogger.ui.struts2.admin.PingTargetEdit", "{1}"},
				{"cacheInfo!*", "org.apache.roller.weblogger.ui.struts2.admin.CacheInfo", "{1}"},
				{"planetConfig!*", "org.apache.roller.weblogger.planet.ui.PlanetConfig", "{1}"},
				{"planetSubscriptions!*", "org.apache.roller.weblogger.planet.ui.PlanetSubscriptions", "{1}"},
				{"planetGroups!*", "org.apache.roller.weblogger.planet.ui.PlanetGroups", "{1}"}
		};

		String[][] ROLLER_AUTHORING_ACTIONS = {    //  35 Actions
				// name, class, method
				{"mediaFileAdd!*", "org.apache.roller.weblogger.ui.struts2.editor.MediaFileAdd", "{1}"},
				{"mediaFileEdit!*", "org.apache.roller.weblogger.ui.struts2.editor.MediaFileEdit", "{1}"},
				{"mediaFileAddExternalInclude!*", "org.apache.roller.weblogger.ui.struts2.editor.MediaFileEdit", "{1}"},
				{"mediaFileView!*", "org.apache.roller.weblogger.ui.struts2.editor.MediaFileView", "{1}"},
				{"mediaFileImageDim!*", "org.apache.roller.weblogger.ui.struts2.editor.MediaFileImageDim", "{1}"},
				{"entryAddWithMediaFile!*", "org.apache.roller.weblogger.ui.struts2.editor.EntryAddWithMediaFile", "{1}"},
				{"entryAdd!*", "org.apache.roller.weblogger.ui.struts2.editor.EntryEdit", "{1}"},
				{"entryEdit!*", "org.apache.roller.weblogger.ui.struts2.editor.EntryEdit", "{1}"},
				{"entryRemove!*", "org.apache.roller.weblogger.ui.struts2.editor.EntryRemove", "{1}"},
				{"entryRemoveViaList!*", "org.apache.roller.weblogger.ui.struts2.editor.EntryRemove", "{1}"},
				{"entries", "org.apache.roller.weblogger.ui.struts2.editor.Entries", null},
				{"comments!*", "org.apache.roller.weblogger.ui.struts2.editor.Comments", "{1}"},
				{"categories!*", "org.apache.roller.weblogger.ui.struts2.editor.Categories", "{1}"},
				{"categoryAdd!*", "org.apache.roller.weblogger.ui.struts2.editor.CategoryEdit", "{1}"},
				{"categoryEdit!*", "org.apache.roller.weblogger.ui.struts2.editor.CategoryEdit", "{1}"},
				{"categoryRemove!*", "org.apache.roller.weblogger.ui.struts2.editor.CategoryRemove", "{1}"},
				{"bookmarks!*", "org.apache.roller.weblogger.ui.struts2.editor.Bookmarks", "{1}"},
				{"bookmarkAdd!*", "org.apache.roller.weblogger.ui.struts2.editor.BookmarkEdit", "{1}"},
				{"bookmarkEdit!*", "org.apache.roller.weblogger.ui.struts2.editor.BookmarkEdit", "{1}"},
				{"bookmarksImport!*", "org.apache.roller.weblogger.ui.struts2.editor.BookmarksImport", "{1}"},
				{"folderAdd!*", "org.apache.roller.weblogger.ui.struts2.editor.FolderEdit", "{1}"},
				{"folderEdit!*", "org.apache.roller.weblogger.ui.struts2.editor.FolderEdit", "{1}"},
				{"weblogConfig!*", "org.apache.roller.weblogger.ui.struts2.editor.WeblogConfig", "{1}"},
				{"weblogRemove!*", "org.apache.roller.weblogger.ui.struts2.editor.WeblogRemove", "{1}"},
				{"themeEdit!*", "org.apache.roller.weblogger.ui.struts2.editor.ThemeEdit", "{1}"},
				{"stylesheetEdit!*", "org.apache.roller.weblogger.ui.struts2.editor.StylesheetEdit", "{1}"},
				{"templates!*", "org.apache.roller.weblogger.ui.struts2.editor.Templates", "{1}"},
				{"templateEdit!*", "org.apache.roller.weblogger.ui.struts2.editor.TemplateEdit", "{1}"},
				{"templateRemove!*", "org.apache.roller.weblogger.ui.struts2.editor.TemplateRemove", "{1}"},
				{"templatesRemove!*", "org.apache.roller.weblogger.ui.struts2.editor.TemplatesRemove", "{1}"},
				{"members!*", "org.apache.roller.weblogger.ui.struts2.editor.Members", "{1}"},
				{"invite!*", "org.apache.roller.weblogger.ui.struts2.editor.MembersInvite", "{1}"},
				{"memberResign!*", "org.apache.roller.weblogger.ui.struts2.editor.MemberResign", "{1}"},
				{"pings!*", "org.apache.roller.weblogger.ui.struts2.editor.Pings", "{1}"},
				{"maintenance!*", "org.apache.roller.weblogger.ui.struts2.editor.Maintenance", "{1}"}
		};

		String[][] ROLLER_AUTHORING_OVERLAY_ACTIONS = {    //  2 Actions
				// name, class, method
				{"mediaFileAdd!*", "org.apache.roller.weblogger.ui.struts2.editor.MediaFileAdd", "{1}"},
				{"mediaFileImageChooser!*", "org.apache.roller.weblogger.ui.struts2.editor.MediaFileImageChooser", "{1}"}
		};


		List<StrutsPackage> strutsPackages
				= StrutsXmlParser.parse( ResourceManager.getStrutsFile("struts.xml") );

		assert strutsPackages != null;

		// assert parserResult.getAction("login-redirect").containsResult("/roller-ui/login-redirect.jsp");

		assert strutsPackages.size() == PACKAGE_VALUES.length :
				"Expected " + PACKAGE_VALUES.length + " packages. Got " + strutsPackages.size();

		List<String[][]> action_values = list();
		action_values.add(ROLLER_ACTIONS);
		action_values.add(ROLLER_INSTALL_ACTIONS);
		action_values.add(ROLLER_ADMIN_ACTIONS);
		action_values.add(ROLLER_AUTHORING_ACTIONS);
		action_values.add(ROLLER_AUTHORING_OVERLAY_ACTIONS);

		for (int i=0; i < PACKAGE_VALUES.length; i++) {
			testPackageValues(strutsPackages.get(i), PACKAGE_VALUES[i][0], PACKAGE_VALUES[i][1], PACKAGE_VALUES[i][2]);
			testPackageActions(strutsPackages.get(i), action_values.get(i));
		}
	}

	private void testPackageValues(StrutsPackage p, String name, String namespace, String pkgExtends) {
		assert p != null;
		assert p.getName().equals( name ) : "Wrong name in pkg " + p + ": expected " + name + ", got " + p.getName();
		assert p.getNamespace().equals( namespace ) : "Wrong namespace in pkg " + p + ": expected " + namespace + ", got " + p.getNamespace();
		assert p.getPkgExtends().equals( pkgExtends ) : "Wrong extends in pkg " + p + ": expected " + pkgExtends + ", got " + p.getPkgExtends();
	}

	private void testPackageActions(StrutsPackage p, String[][] packageActions) {
		// check number of actions
		assert p.getActions().size() == packageActions.length : "Expected " + packageActions.length + " actions in " + p
				+ ", got " + p.getActions().size();
		// check action values
		for (int i=0; i < packageActions.length; i++) {
			testActionValues(p.getActions().get(i), packageActions[i][0], packageActions[i][1], packageActions[i][2]);
		}
		if ("weblogger-admin".equals(p.getName())) {
			testActionResults( p.getActions() );
		}
	}

	private void testActionValues(StrutsAction a, String name, String actClass, String method) {
		assert a != null;
		assert name.equals(a.getName()) : "Wrong name in action " + a + ": expected " + name + ", got " + a.getName();
		if (actClass == null)
			assert a.getActClass() == null : "Wrong class in action " + a + ": expected null, got " + a.getActClass();
		else
			assert actClass.equals( a.getActClass() ) : "Wrong class in action " + a + ": expected " + actClass + ", got " + a.getActClass();
		if (method == null)
			assert a.getMethod() == null : "Wrong method in action " + a + ": expected null, got " + a.getMethod();
		else
			assert method.equals( a.getMethod() ) : "Wrong method in action " + a + ": expected " + method + ", got " +a.getMethod();
	}

	private void testActionResults(List<StrutsAction> actions) {
		for (int i=0; i < actions.size(); i++) {

			StrutsAction action = actions.get(i);

			List<StrutsResult> results = action.getResults();
			Map params = action.getParams();
			switch (i) {
				case 0:
					assert params == null : "Expected null params in " + action + ", got " + params;

					assert results.size() == 1 : "Expected 1 result in " + action + ", got " + results.size();
					assert results.get(0).getName().equals("success") : "Wrong name in " + results.get(0) + ", expected: success";
					assert results.get(0).getType().equals("tiles") : "Wrong type in " + results.get(0) + ", expected: tiles";
					assert results.get(0).getValue().equals(".GlobalConfig") : "Wrong value in " + results.get(0) + ", expected: .GlobalConfig";
					assert results.get(0).getParams() == null : "Expected null params in " + results.get(0) + ", got " + results.get(0).getParams();
					break;
				case 1:
					assert params == null : "Expected null params in " + action + ", got " + params;

					assert results.size() == 3 : "Expected 3 results in " + action + ", got " + results.size();
					assert results.get(0).getName().equals("success") : "Wrong name in " + results.get(0) + ", expected: success";
					assert results.get(0).getType().equals("tiles") : "Wrong type in " + results.get(0) + ", expected: tiles";
					assert results.get(0).getValue().equals(".UserAdmin") : "Wrong value in " + results.get(0) + ", expected: .UserAdmin";
					assert results.get(0).getParams() == null : "Expected null params in " + results.get(0) + ", got " + results.get(0).getParams();

					assert results.get(1).getName().equals("error") : "Wrong name in " + results.get(1) + ", expected: error";
					assert results.get(1).getType().equals("tiles") : "Wrong type in " + results.get(1) + ", expected: tiles";
					assert results.get(1).getValue().equals(".UserAdmin") : "Wrong value in " + results.get(1) + ", expected: .UserAdmin";
					assert results.get(1).getParams() == null : "Expected null params in " + results.get(1) + ", got " + results.get(1).getParams();

					assert results.get(2).getName().equals("input") : "Wrong name in " + results.get(2) + ", expected: input";
					assert results.get(2).getType().equals("tiles") : "Wrong type in " + results.get(2) + ", expected: tiles";
					assert results.get(2).getValue().equals(".UserAdmin") : "Wrong value in " + results.get(2) + ", expected: .UserAdmin";
					assert results.get(2).getParams() == null : "Expected null params in " + results.get(2) + ", got " + results.get(2).getParams();

					break;
				case 2:
					Map<String, String> testParams = new HashMap<String, String>(2);
					testParams.put("actionName", "createUser");
					testParams.put("pageTitle", "userAdmin.title.createNewUser");
					assert params.equals(testParams) : "Wrong params in " + action + action.getParams() + ", expected: " + testParams;

					assert results.size() == 2 : "Expected 2 results in " + action + ", got " + results.size();
					assert results.get(0).getName().equals("input") : "Wrong name in " + results.get(0) + ", expected: input";
					assert results.get(0).getType().equals("tiles") : "Wrong type in " + results.get(0) + ", expected: tiles";
					assert results.get(0).getValue().equals(".UserEdit") : "Wrong value in " + results.get(0) + ", expected: .UserEdit";
					assert results.get(0).getParams() == null : "Expected null params in " + results.get(0) + ", got " + params;

					assert results.get(1).getName().equals("success") : "Wrong name in " + results.get(1) + ", expected: success";
					assert results.get(1).getType().equals("redirectAction") : "Wrong type in " + results.get(1) + ", expected: redirectAction";
					assert results.get(1).getValue() == null : "Wrong value in " + results.get(1) + ", expected: null";
					Map resultParam = results.get(1).getParams();
					Map<String, String> testResultParams = new HashMap<String, String>(2);
					testResultParams.put("actionName", "modifyUser!firstSave");
					testResultParams.put("bean.id", "${bean.id}");
					assert resultParam.equals(testResultParams) : "Wrong params in " + results.get(1) + ", expected: " + testResultParams;

					break;
				case 3:
					testParams = new HashMap<String, String>(2);
					testParams.put("actionName", "modifyUser");
					testParams.put("pageTitle", "userAdmin.title.editUser");
					assert params.equals(testParams) : "Wrong params in " + action + action.getParams() + ", expected: " + testParams;

					assert results.size() == 3 : "Expected 3 results in " + action + ", got " + results.size();
					assert results.get(0).getName().equals("input") : "Wrong name in " + results.get(0) + ", expected: input";
					assert results.get(0).getType().equals("tiles") : "Wrong type in " + results.get(0) + ", expected: tiles";
					assert results.get(0).getValue().equals(".UserEdit") : "Wrong value in " + results.get(0) + ", expected: .UserEdit";
					assert results.get(0).getParams() == null : "Expected null params in " + results.get(0) + ", got " + params;

					assert results.get(1).getName().equals("error") : "Wrong name in " + results.get(1) + ", expected: error";
					assert results.get(1).getType().equals("chain") : "Wrong type in " + results.get(1) + ", expected: chain";
					assert results.get(1).getValue().equals("userAdmin") : "Wrong value in " + results.get(1) + ", expected: userAdmin";
					assert results.get(1).getParams() == null : "Expected null params in " + results.get(1) + ", got " + params;

					assert results.get(2).getName().equals("cancel") : "Wrong name in " + results.get(2) + ", expected: cancel";
					assert results.get(2).getType().equals("redirectAction") : "Wrong type in " + results.get(2) + ", expected: redirectAction";
					assert results.get(2).getValue() == null;
					resultParam = results.get(2).getParams();
					testResultParams = new HashMap<String, String>(1);
					testResultParams.put("actionName", "userAdmin");
					assert resultParam.equals(testResultParams) : "Wrong params in " + results.get(2) + ", expected: " + testResultParams;

					break;
				case 4:
					assert params == null : "Expected null params in " + action + ", got " + params;

					assert results.size() == 1 : "Expected 1 result in " + action + ", got " + results.size();
					assert results.get(0).getName().equals("list") : "Wrong name in " + results.get(0) + ", expected: list";
					assert results.get(0).getType().equals("tiles") : "Wrong type in " + results.get(0) + ", expected: tiles";
					assert results.get(0).getValue().equals(".GlobalCommentManagement") : "Wrong value in " + results.get(0) + ", expected: .GlobalCommentManagement";
					assert results.get(0).getParams() == null : "Expected null params in " + results.get(0) + ", got " + results.get(0).getParams();

					break;
				case 5:
					assert params == null : "Expected null params in " + action + action.getParams() + ", got " + params;

					assert results.size() == 2 : "Expected 2 results in " + action + ", got " + results.size();
					assert results.get(0).getName().equals("list") : "Wrong name in " + results.get(0) + ", expected: list";
					assert results.get(0).getType().equals("tiles") : "Wrong type in " + results.get(0) + ", expected: tiles";
					assert results.get(0).getValue().equals(".PingTargets") : "Wrong value in " + results.get(0) + ", expected: .PingTargets";
					assert results.get(0).getParams() == null : "Expected null params in " + results.get(0) + ", got " + results.get(0).getParams();

					assert results.get(1).getName().equals("confirm") : "Wrong name in " + results.get(1) + ", expected: confirm";
					assert results.get(1).getType().equals("tiles") : "Wrong type in " + results.get(1) + ", expected: tiles";
					assert results.get(1).getValue().equals(".PingTargetConfirm") : "Wrong value in " + results.get(1) + ", expected: .PingTargetConfirm";
					assert results.get(1).getParams() == null : "Expected null params in " + results.get(1) + ", got " + results.get(1).getParams();

					break;
				case 6:
					testParams = new HashMap<String, String>(2);
					testParams.put("actionName", "commonPingTargetAdd");
					testParams.put("pageTitle", "pingTarget.addTarget");
					assert params.equals(testParams) : "Wrong params in " + action + action.getParams() + ", expected: " + testParams;

					assert results.size() == 2 : "Expected 2 results in " + action + ", got " + results.size();
					assert results.get(0).getName().equals("input") : "Wrong name in " + results.get(0) + ", expected: input";
					assert results.get(0).getType().equals("tiles") : "Wrong type in " + results.get(0) + ", expected: tiles";
					assert results.get(0).getValue().equals(".PingTargetEdit") : "Wrong value in " + results.get(0) + ", expected: .PingTargetEdit";
					assert results.get(0).getParams() == null : "Expected null params in " + results.get(0) + ", got " + params;

					assert results.get(1).getName().equals("success") : "Wrong name in " + results.get(1) + ", expected: success";
					assert results.get(1).getType().equals("chain") : "Wrong type in " + results.get(1) + ", expected: chain";
					assert results.get(1).getValue().equals("commonPingTargets") : "Wrong value in " + results.get(1) + ", expected: commonPingTargets";
					assert results.get(1).getParams() == null : "Expected null params in " + results.get(1) + ", got " + params;

					break;
				case 7:
					testParams = new HashMap<String, String>(2);
					testParams.put("actionName", "commonPingTargetEdit");
					testParams.put("pageTitle", "pingTarget.editTarget");
					assert params.equals(testParams) : "Wrong params in " + action + action.getParams() + ", expected: " + testParams;

					assert results.size() == 3 : "Expected 3 results in " + action + ", got " + results.size();
					assert results.get(0).getName().equals("input") : "Wrong name in " + results.get(0) + ", expected: input";
					assert results.get(0).getType().equals("tiles") : "Wrong type in " + results.get(0) + ", expected: tiles";
					assert results.get(0).getValue().equals(".PingTargetEdit") : "Wrong value in " + results.get(0) + ", expected: .PingTargetEdit";
					assert results.get(0).getParams() == null : "Expected null params in " + results.get(0) + ", got " + params;

					assert results.get(1).getName().equals("success") : "Wrong name in " + results.get(1) + ", expected: success";
					assert results.get(1).getType().equals("chain") : "Wrong type in " + results.get(1) + ", expected: chain";
					assert results.get(1).getValue().equals("commonPingTargets") : "Wrong value in " + results.get(1) + ", expected: commonPingTargets";
					assert results.get(1).getParams() == null : "Expected null params in " + results.get(1) + ", got " + params;

					assert results.get(2).getName().equals("error") : "Wrong name in " + results.get(2) + ", expected: error";
					assert results.get(2).getType().equals("chain") : "Wrong type in " + results.get(2) + ", expected: chain";
					assert results.get(2).getValue().equals("commonPingTargets") : "Wrong value in " + results.get(2) + ", expected: commonPingTargets";
					assert results.get(2).getParams() == null : "Expected null params in " + results.get(2) + ", got " + params;

					break;
				case 8:
					assert params == null : "Expected null params in " + action + ", got " + params;

					assert results.size() == 1 : "Expected 1 result in " + action + ", got " + results.size();
					assert results.get(0).getName().equals("success") : "Wrong name in " + results.get(0) + ", expected: success";
					assert results.get(0).getType().equals("tiles") : "Wrong type in " + results.get(0) + ", expected: tiles";
					assert results.get(0).getValue().equals(".CacheInfo") : "Wrong value in " + results.get(0) + ", expected: .CacheInfo";
					assert results.get(0).getParams() == null : "Expected null params in " + results.get(0) + ", got " + results.get(0).getParams();

					break;
				case 9:
					assert params == null : "Expected null params in " + action + ", got " + params;

					assert results.size() == 1 : "Expected 1 result in " + action + ", got " + results.size();
					assert results.get(0).getName().equals("input") : "Wrong name in " + results.get(0) + ", expected: input";
					assert results.get(0).getType().equals("tiles") : "Wrong type in " + results.get(0) + ", expected: tiles";
					assert results.get(0).getValue().equals(".PlanetConfig") : "Wrong value in " + results.get(0) + ", expected: .PlanetConfig";
					assert results.get(0).getParams() == null : "Expected null params in " + results.get(0) + ", got " + results.get(0).getParams();

					break;
				case 10:
					assert params == null : "Expected null params in " + action + ", got " + params;

					assert results.size() == 1 : "Expected 1 result in " + action + ", got " + results.size();
					assert results.get(0).getName().equals("list") : "Wrong name in " + results.get(0) + ", expected: list";
					assert results.get(0).getType().equals("tiles") : "Wrong type in " + results.get(0) + ", expected: tiles";
					assert results.get(0).getValue().equals(".PlanetSubscriptions") : "Wrong value in " + results.get(0) + ", expected: .PlanetSubscriptions";
					assert results.get(0).getParams() == null : "Expected null params in " + results.get(0) + ", got " + results.get(0).getParams();

					break;
				case 11:
					assert params == null : "Expected null params in " + action + ", got " + params;

					assert results.size() == 1 : "Expected 1 result in " + action + ", got " + results.size();
					assert results.get(0).getName().equals("list") : "Wrong name in " + results.get(0) + ", expected: list";
					assert results.get(0).getType().equals("tiles") : "Wrong type in " + results.get(0) + ", expected: tiles";
					assert results.get(0).getValue().equals(".PlanetGroups") : "Wrong value in " + results.get(0) + ", expected: .PlanetGroups";
					assert results.get(0).getParams() == null : "Expected null params in " + results.get(0) + ", got " + results.get(0).getParams();

					break;
				default:
					assert i<11 : "Expected only 12 Action in the \"weblogger-admin\" package, got " + i;
			}
		}
	}

}
