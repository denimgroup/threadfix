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
package com.denimgroup.threadfix.plugin.eclipse.action;

import java.util.Set;

import org.eclipse.jface.action.IAction;
import org.eclipse.jface.viewers.ISelection;
import org.eclipse.jface.window.Window;
import org.eclipse.ui.IWorkbenchWindow;
import org.eclipse.ui.IWorkbenchWindowActionDelegate;

import com.denimgroup.threadfix.plugin.eclipse.dialog.ApplicationDialog;
import com.denimgroup.threadfix.plugin.eclipse.dialog.ConfigDialog;
import com.denimgroup.threadfix.plugin.eclipse.rest.ApplicationsMap;
import com.denimgroup.threadfix.plugin.eclipse.rest.ThreadFixService;
import com.denimgroup.threadfix.plugin.eclipse.util.EclipsePropertiesManager;

public class ConfigureAction implements IWorkbenchWindowActionDelegate {
	private IWorkbenchWindow window;

	/**
	 * The constructor.
	 */
	public ConfigureAction() {
	}

	/**
	 * The action has been activated. The argument of the method represents the
	 * 'real' action sitting in the workbench UI.
	 * 
	 * @see IWorkbenchWindowActionDelegate#run
	 */
	@Override
	public void run(IAction action) {
		boolean cancelled = false;
		// Get endpoint info
		ConfigDialog dialog = new ConfigDialog(window.getShell(),false);

		dialog.create();

		if (dialog.open() == Window.OK) {
			EclipsePropertiesManager.saveThreadFixInfo(dialog.getUrl(), dialog.getApiKey());
			System.out.println("Saved ThreadFix information successfully.");
			
			// Get application info
			ApplicationsMap threadFixApplicationMap = ThreadFixService.getApplications();
			while (threadFixApplicationMap.getTeams().isEmpty()){
				dialog = new ConfigDialog(window.getShell(), true);

				dialog.create();
				if (dialog.open() == Window.OK) {
					EclipsePropertiesManager.saveThreadFixInfo(dialog.getUrl(), dialog.getApiKey());
					System.out.println("Saved ThreadFix information successfully.");
					threadFixApplicationMap = ThreadFixService.getApplications();
				} else {
					System.out.println("Cancel was pressed.");
					cancelled = true;
					break;
				}
			}
			if (!cancelled) {
				Set<String> configuredApps = EclipsePropertiesManager.getConfiguredApplications();
				
				ApplicationDialog appDialog = new ApplicationDialog(window.getShell(),
						threadFixApplicationMap, configuredApps);
				
				appDialog.create();
				
				if (appDialog.open() == Window.OK) {
					EclipsePropertiesManager.saveApplicationInfo(appDialog.getAppIds());
					System.out.println("Saved successfully.");
				} else {
					System.out.println("Cancel was pressed.");
				}
			}
				
		} else {
			System.out.println("Cancel was pressed instead ");
		}
	}

	/**
	 * Selection in the workbench has been changed. We can change the state of
	 * the 'real' action here if we want, but this can only happen after the
	 * delegate has been created.
	 * 
	 * @see IWorkbenchWindowActionDelegate#selectionChanged
	 */
	@Override
	public void selectionChanged(IAction action, ISelection selection) {
	}

	/**
	 * We can use this method to dispose of any system resources we previously
	 * allocated.
	 * 
	 * @see IWorkbenchWindowActionDelegate#dispose
	 */
	@Override
	public void dispose() {
	}

	/**
	 * We will cache window object in order to be able to provide parent shell
	 * for the message dialog.
	 * 
	 * @see IWorkbenchWindowActionDelegate#init
	 */
	@Override
	public void init(IWorkbenchWindow window) {
		this.window = window;
	}
}
