package com.denimgroup.threadfix.plugin.eclipse.dialog;

import org.eclipse.jface.dialogs.TitleAreaDialog;
import org.eclipse.swt.SWT;
import org.eclipse.swt.layout.GridData;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.widgets.Control;
import org.eclipse.swt.widgets.Label;
import org.eclipse.swt.widgets.Shell;
import org.eclipse.swt.widgets.Text;

public class ConfigDialog extends TitleAreaDialog {
	private Text urlTextInput;
	private Text apiKeyTextInput;
	
	private String url;
	private String apiKey;
	private boolean invalid;

	private final String initialUrl, initialApiKey;

	public ConfigDialog(Shell parentShell, String initialApiKey,
			String initialUrl,boolean invalid) {
		super(parentShell);
		this.initialApiKey = initialApiKey;
		this.initialUrl = initialUrl;
		this.invalid = invalid;
	}

	@Override
	public void create() {
		super.create();
		if(invalid){
			setTitle("ThreadFix Configuration: Incorrect Credentials");
		}else{
			setTitle("ThreadFix Configuration");
		}
	}

	@Override
	protected Control createDialogArea(Composite parent) {
		Composite area = (Composite) super.createDialogArea(parent);
		Composite container = new Composite(area, SWT.NONE);
		container.setLayoutData(new GridData(GridData.FILL_BOTH));
		GridLayout layout = new GridLayout(2, false);
		container.setLayoutData(new GridData(SWT.FILL, SWT.FILL, true, true));
		container.setLayout(layout);

		createUrlText(container);
		createApiKeyText(container);

		return area;
	}

	private void createUrlText(Composite container) {
		Label lbtFirstName = new Label(container, SWT.NONE);
		lbtFirstName.setText("ThreadFix Endpoint URL");

		GridData dataFirstName = new GridData();
		dataFirstName.grabExcessHorizontalSpace = true;
		dataFirstName.horizontalAlignment = GridData.FILL;
		urlTextInput = new Text(container, SWT.BORDER);
		urlTextInput.setLayoutData(dataFirstName);
		urlTextInput.setText(initialUrl);

	}

	private void createApiKeyText(Composite container) {
		Label lbtLastName = new Label(container, SWT.NONE);
		lbtLastName.setText("API Key");

		GridData dataLastName = new GridData();
		dataLastName.grabExcessHorizontalSpace = true;
		dataLastName.horizontalAlignment = GridData.FILL;
		apiKeyTextInput = new Text(container, SWT.BORDER);
		apiKeyTextInput.setLayoutData(dataLastName);
		apiKeyTextInput.setText(initialApiKey);
	}

	@Override
	protected boolean isResizable() {
		return true;
	}

	// We need to save the values of the Text fields into Strings because the UI
	// gets disposed and the Text fields are not accessible any more.
	private void saveInput() {
		url = urlTextInput.getText();
		apiKey = apiKeyTextInput.getText();
	}
	
	@Override
	protected void okPressed() {
		saveInput();
		super.okPressed();
	}

	public String getUrl() {
		return url;
	}

	public String getApiKey() {
		return apiKey;
	}
}
