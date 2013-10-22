package com.denimgroup.threadfix.plugin.eclipse.dialog;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import org.eclipse.jface.dialogs.TitleAreaDialog;
import org.eclipse.swt.SWT;
import org.eclipse.swt.layout.GridData;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.widgets.Button;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.widgets.Control;
import org.eclipse.swt.widgets.Shell;

public class ApplicationDialog extends TitleAreaDialog {
	
	private List<Button> buttons = new ArrayList<Button>();

	private Set<String> appIds = null;

	private final Map<String, String> appIdMap;
	private final Set<String> alreadyChecked;

	public ApplicationDialog(Shell parentShell, Map<String, String> appIdMap,
			Set<String> alreadyChecked) {
		super(parentShell);
		this.appIdMap = appIdMap;
		this.alreadyChecked = alreadyChecked;
	}

	@Override
	public void create() {
		super.create();
		setTitle("Pick Applications");
	}

	@Override
	protected Control createDialogArea(Composite parent) {
		Composite area = (Composite) super.createDialogArea(parent);
		Composite container = new Composite(area, SWT.NONE);
		container.setLayoutData(new GridData(GridData.FILL_BOTH));
		GridLayout layout = new GridLayout(1, false);
		container.setLayoutData(new GridData(SWT.FILL, SWT.FILL, true, true));
		container.setLayout(layout);

		createApplicationSelection(container);

		return area;
	}

	private void createApplicationSelection(Composite container) {
		for (String appIdentifier : new TreeSet<String>(appIdMap.keySet())) {
			Button button = new Button(container, SWT.CHECK);
			button.setText(appIdentifier);
			if (alreadyChecked.contains(appIdMap.get(appIdentifier))) {
				button.setSelection(true);
			}
			buttons.add(button);
		}
	}

	@Override
	protected boolean isResizable() {
		return true;
	}

	// We need to save the values of the Text fields into Strings because the UI
	// gets disposed and the Text fields are not accessible any more.
	private void saveInput() {
		appIds = getAppIdsFromButtons();
	}
	
	private Set<String> getAppIdsFromButtons() {
		Set<String> returnSet = new HashSet<String>();
	
		for (Button button : buttons) {
			if (button.getSelection()) {
				returnSet.add(appIdMap.get(button.getText()));
			}
		}
	
		return returnSet;
	}

	@Override
	protected void okPressed() {
		saveInput();
		super.okPressed();
	}
	
	public Set<String> getAppIds() {
		return appIds;
	}
}
