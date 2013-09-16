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
package com.denimgroup.threadfix.plugin.eclipse;

import java.util.List;
import java.util.Map;
import java.util.Set;

import org.eclipse.core.resources.IFile;
import org.eclipse.core.runtime.CoreException;
import org.eclipse.jface.action.IAction;
import org.eclipse.jface.dialogs.MessageDialog;
import org.eclipse.jface.viewers.ISelection;
import org.eclipse.ui.IWorkbenchWindow;
import org.eclipse.ui.IWorkbenchWindowActionDelegate;
import org.eclipse.ui.PartInitException;

import com.denimgroup.threadfix.plugin.eclipse.util.SettingsUtils;
import com.denimgroup.threadfix.plugin.eclipse.util.VulnerabilityMarker;
import com.denimgroup.threadfix.plugin.eclipse.util.VulnerabilityMarkerService;
import com.denimgroup.threadfix.plugin.eclipse.util.WorkspaceUtils;

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
	 * The constructor.
	 */
	public ImportAction() {
	}

	/**
	 * The action has been activated. The argument of the
	 * method represents the 'real' action sitting
	 * in the workbench UI.
	 * @see IWorkbenchWindowActionDelegate#run
	 */
	@Override
	public void run(IAction action) {
		MessageDialog.openInformation(
			window.getShell(), "Helloworld", "I'm opening up yo stuff.");
		
		// TODO make this a dialog so users can put their own endpoint info and key in here.
		List<VulnerabilityMarker> vulnerabilityMarkers =
				VulnerabilityMarkerService.getMarkers(SettingsUtils.getApiKey(), SettingsUtils.getUrl(), "2");
		
		Map<String, Set<IFile>> files = WorkspaceUtils.getFileMap();
		
		addMarkersToFiles(vulnerabilityMarkers, files);
	}
	
	private void addMarkersToFiles(
			List<VulnerabilityMarker> vulnerabilityMarkers,
			Map<String, Set<IFile>> files) {
		
		for (VulnerabilityMarker marker : vulnerabilityMarkers) {
			if (marker.getShortClassName() != null && files.get(marker.getShortClassName()) != null) {
				// TODO a better package comparison
				for (IFile file : files.get(marker.getShortClassName())) {
					add(file, marker);
				}
			}
		}
		
	}
	
	private void add(IFile file, VulnerabilityMarker marker) {
		try {
			if (file != null) {
				WorkspaceUtils.createMarker(file, marker);
			}
		} catch (PartInitException e) {
			e.printStackTrace();
		} catch (CoreException e) {
			e.printStackTrace();
		}
	}
	
	/**
	 * Selection in the workbench has been changed. We
	 * can change the state of the 'real' action here
	 * if we want, but this can only happen after
	 * the delegate has been created.
	 * @see IWorkbenchWindowActionDelegate#selectionChanged
	 */
	@Override
	public void selectionChanged(IAction action, ISelection selection) {
	}

	/**
	 * We can use this method to dispose of any system
	 * resources we previously allocated.
	 * @see IWorkbenchWindowActionDelegate#dispose
	 */
	@Override
	public void dispose() {
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
}