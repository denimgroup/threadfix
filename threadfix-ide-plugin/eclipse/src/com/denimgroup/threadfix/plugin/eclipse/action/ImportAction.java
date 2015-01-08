////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2015 Denim Group, Ltd.
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

import java.util.List;
import java.util.Map;
import java.util.Set;

import org.eclipse.core.resources.IFile;
import org.eclipse.jface.action.IAction;
import org.eclipse.jface.dialogs.MessageDialog;
import org.eclipse.jface.viewers.ISelection;
import org.eclipse.jface.window.Window;
import org.eclipse.ui.IWorkbenchWindow;
import org.eclipse.ui.IWorkbenchWindowActionDelegate;

import com.denimgroup.threadfix.data.entities.VulnerabilityMarker;
import com.denimgroup.threadfix.plugin.eclipse.dialog.ConfigDialog;
import com.denimgroup.threadfix.plugin.eclipse.rest.ApplicationsMap;
import com.denimgroup.threadfix.plugin.eclipse.rest.ThreadFixService;
import com.denimgroup.threadfix.plugin.eclipse.rest.VulnerabilityMarkerService;
import com.denimgroup.threadfix.plugin.eclipse.util.EclipsePropertiesManager;
import com.denimgroup.threadfix.plugin.eclipse.util.VulnerabilityMarkerUtils;
import com.denimgroup.threadfix.plugin.eclipse.util.WorkspaceUtils;
import com.denimgroup.threadfix.plugin.eclipse.views.VulnerabilitiesView;

/**
 * Our sample action implements workbench action delegate.
 * The action proxy will be created by the workbench and
 * shown in the UI. When the user tries to use the action,
 * this delegate will be created and execution will be
 * delegated to it.
 * @see IWorkbenchWindowActionDelegate
 */
public class ImportAction implements IWorkbenchWindowActionDelegate {
	private IWorkbenchWindow window;

	/**
	 * The action has been activated. The argument of the
	 * method represents the 'real' action sitting
	 * in the workbench UI.
	 * @see IWorkbenchWindowActionDelegate#run
	 */
	@Override
	public void run(IAction action) {
		boolean cancelled = false;
		ConfigDialog dialog = new ConfigDialog(window.getShell(), false);

		dialog.create();

		if (dialog.open() == Window.OK) {
			EclipsePropertiesManager.saveThreadFixInfo(dialog.getUrl(), dialog.getApiKey());
			ApplicationsMap threadFixApplicationMap = ThreadFixService.getApplications();
			
			while (threadFixApplicationMap.getTeams().isEmpty()) {
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
			
			if(!cancelled){
				MessageDialog.openInformation(
						window.getShell(), "ThreadFix Vulnerability Import", "Importing ThreadFix Vulnerabilities.");
				List<VulnerabilityMarker> vulnerabilityMarkers =
						VulnerabilityMarkerService.getMarkers();
				
				Map<String, Set<IFile>> files = WorkspaceUtils.getFileMap();
				
				VulnerabilityMarkerUtils.clearAllMarkers();
				
				VulnerabilityMarkerUtils.addMarkersToFiles(vulnerabilityMarkers, files);
				
				VulnerabilitiesView.showView();
			}
		}
	}
	
	/**
	 * We will cache window object in order to
	 * be able to provide parent shell for the message dialog.
	 * @see IWorkbenchWindowActionDelegate#init
	 */
	@Override
	public void init(IWorkbenchWindow window) {
		this.window = window;
	}

	@Override
	public void selectionChanged(IAction arg0, ISelection arg1) {}

	@Override
	public void dispose() {}
	
}