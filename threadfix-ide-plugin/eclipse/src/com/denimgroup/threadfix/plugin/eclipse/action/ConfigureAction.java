package com.denimgroup.threadfix.plugin.eclipse.action;

import java.util.Map;
import java.util.Set;

import org.eclipse.jface.action.IAction;
import org.eclipse.jface.viewers.ISelection;
import org.eclipse.jface.window.Window;
import org.eclipse.ui.IWorkbenchWindow;
import org.eclipse.ui.IWorkbenchWindowActionDelegate;

import com.denimgroup.threadfix.plugin.eclipse.dialog.ApplicationDialog;
import com.denimgroup.threadfix.plugin.eclipse.dialog.ConfigDialog;
import com.denimgroup.threadfix.plugin.eclipse.rest.ThreadFixService;
import com.denimgroup.threadfix.plugin.eclipse.util.SettingsUtils;

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
		
		// Get endpoint info
		ConfigDialog dialog = new ConfigDialog(window.getShell(),
				SettingsUtils.getApiKey(), SettingsUtils.getUrl());

		dialog.create();

		if (dialog.open() == Window.OK) {
			SettingsUtils.saveThreadFixInfo(dialog.getUrl(), dialog.getApiKey());
			System.out.println("Saved ThreadFix information successfully.");
			
			// Get application info
			Map<String, String> threadFixApplicationMap = ThreadFixService.getApplications();
			Set<String> configuredApps = SettingsUtils.getConfiguredApplications();
			
			ApplicationDialog appDialog = new ApplicationDialog(window.getShell(),
					threadFixApplicationMap, configuredApps);
			
			appDialog.create();
			
			if (appDialog.open() == Window.OK) {
				SettingsUtils.saveApplicationInfo(appDialog.getAppIds());
				System.out.println("Saved successfully.");
			} else {
				System.out.println("Cancel was pressed.");
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
