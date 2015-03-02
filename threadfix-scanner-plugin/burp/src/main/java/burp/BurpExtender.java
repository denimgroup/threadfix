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

package burp;

import burp.custombutton.ExportButton;
import burp.custombutton.LocalEndpointsButton;
import burp.custombutton.RemoteEndpointsButton;
import burp.extention.BurpPropertiesManager;
import burp.extention.RestUtils;
import com.denimgroup.threadfix.data.entities.Application;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.awt.event.*;
import java.util.HashMap;
import java.util.Map;

/**
 * Created with IntelliJ IDEA.
 * User: stran
 * Date: 12/30/13
 * Time: 2:28 PM
 * To change this template use File | Settings | File Templates.
 */
public class BurpExtender implements IBurpExtender, ITab
{
    private BurpPropertiesManager burpPropertiesManager;
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private JTabbedPane tabbedPane;
    private JTextField urlField;
    private JTextField keyField;
    private JLabel apiErrorLabel;
    private Map<String, String> applicationMap = new HashMap<>();
    private JComboBox applicationComboBox;
    private JTextField sourceFolderField;
    private JTextField targetUrlField;

    //
    // implement IBurpExtender
    //

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks)
    {
        // keep a reference to our callbacks object
        this.callbacks = callbacks;

        burpPropertiesManager = BurpPropertiesManager.generateBurpPropertiesManager(callbacks);

        // obtain an extension helpers object
        helpers = callbacks.getHelpers();

        // set our extension name
        callbacks.setExtensionName("ThreadFix plugin");

        // create UI
        SwingUtilities.invokeLater(new Runnable()
        {
            @Override
            public void run()
            {
                tabbedPane = new JTabbedPane();

                JPanel mainPanel = buildMainPanel();
                JScrollPane mainScrollPane = new JScrollPane(mainPanel);
                tabbedPane.addTab("Main", mainScrollPane);

                JPanel optionsPanel = buildOptionsPanel();
                JScrollPane optionsScrollPane = new JScrollPane(optionsPanel);
                tabbedPane.addTab("Options", optionsScrollPane);

                // customize our UI components
                callbacks.customizeUiComponent(tabbedPane);

                // add the custom tab to Burp's UI
                callbacks.addSuiteTab(BurpExtender.this);
            }
        });
    }

    private JPanel buildMainPanel() {
        JPanel mainPanel = new JPanel();

        JButton localEndpointsButton = new LocalEndpointsButton(getUiComponent(), callbacks);
        callbacks.customizeUiComponent(localEndpointsButton);

        JButton remoteEndpointsButton = new RemoteEndpointsButton(getUiComponent(), callbacks);
        callbacks.customizeUiComponent(remoteEndpointsButton);

        JButton exportButton = new ExportButton(getUiComponent(), callbacks);
        callbacks.customizeUiComponent(exportButton);

        localEndpointsButton.setLocation(10, 10);
        localEndpointsButton.setSize(300, 30);
        remoteEndpointsButton.setLocation(10, 50);
        remoteEndpointsButton.setSize(300, 30);
        exportButton.setLocation(10, 90);
        exportButton.setSize(300, 30);
        mainPanel.setLayout(null);
        mainPanel.add(localEndpointsButton);
        mainPanel.add(remoteEndpointsButton);
        mainPanel.add(exportButton);

        return mainPanel;
    }

    private JPanel buildOptionsPanel() {
        final JPanel optionsPanel = new JPanel();
        optionsPanel.addHierarchyListener(new HierarchyListener() {
            @Override
            public void hierarchyChanged(HierarchyEvent e) {
                boolean tabIsShowing = optionsPanel.isShowing();
                if (tabIsShowing) {
                    loadOptionsProperties();
                } else {
                    burpPropertiesManager.saveProperties();
                }
            }
        });
        optionsPanel.setLayout(new GridBagLayout());
        Insets optionsPanelInsets = new Insets(10, 10, 10, 10);
        int yPosition = 0;

        JPanel parametersPanel = buildParametersPanel();
        GridBagConstraints parametersPanelConstraints = new GridBagConstraints();
        parametersPanelConstraints.gridx = 0;
        parametersPanelConstraints.gridy = yPosition++;
        parametersPanelConstraints.ipadx = 5;
        parametersPanelConstraints.ipady = 5;
        parametersPanelConstraints.insets = optionsPanelInsets;
        parametersPanelConstraints.anchor = GridBagConstraints.NORTHWEST;
        optionsPanel.add(parametersPanel, parametersPanelConstraints);

        JSeparator parametersPanelSeparator = new JSeparator(JSeparator.HORIZONTAL);
        callbacks.customizeUiComponent(parametersPanelSeparator);
        GridBagConstraints parametersPanelSeparatorConstraints = new GridBagConstraints();
        parametersPanelSeparatorConstraints.gridx = 0;
        parametersPanelSeparatorConstraints.gridy = yPosition++;
        parametersPanelSeparatorConstraints.insets = optionsPanelInsets;
        parametersPanelSeparatorConstraints.fill = GridBagConstraints.HORIZONTAL;
        parametersPanelSeparatorConstraints.anchor = GridBagConstraints.NORTH;
        optionsPanel.add(parametersPanelSeparator, parametersPanelSeparatorConstraints);

        JPanel sourcePanel = buildSourcePanel();
        GridBagConstraints sourcePanelConstraints = new GridBagConstraints();
        sourcePanelConstraints.gridx = 0;
        sourcePanelConstraints.gridy = yPosition++;
        sourcePanelConstraints.ipadx = 5;
        sourcePanelConstraints.ipady = 5;
        sourcePanelConstraints.insets = optionsPanelInsets;
        sourcePanelConstraints.anchor = GridBagConstraints.NORTHWEST;
        optionsPanel.add(sourcePanel, sourcePanelConstraints);

        JSeparator sourcePanelSeparator = new JSeparator(JSeparator.HORIZONTAL);
        callbacks.customizeUiComponent(sourcePanelSeparator);
        GridBagConstraints sourcePanelSeparatorConstraints = new GridBagConstraints();
        sourcePanelSeparatorConstraints.gridx = 0;
        sourcePanelSeparatorConstraints.gridy = yPosition++;
        sourcePanelSeparatorConstraints.insets = optionsPanelInsets;
        sourcePanelSeparatorConstraints.fill = GridBagConstraints.HORIZONTAL;
        sourcePanelSeparatorConstraints.anchor = GridBagConstraints.NORTH;
        optionsPanel.add(sourcePanelSeparator, sourcePanelSeparatorConstraints);

        JPanel targetPanel = buildTargetPanel();
        GridBagConstraints targetPanelConstraints = new GridBagConstraints();
        targetPanelConstraints.gridx = 0;
        targetPanelConstraints.gridy = yPosition++;
        targetPanelConstraints.ipadx = 5;
        targetPanelConstraints.ipady = 5;
        targetPanelConstraints.insets = optionsPanelInsets;
        targetPanelConstraints.weightx = 1.0;
        targetPanelConstraints.weighty = 1.0;
        targetPanelConstraints.anchor = GridBagConstraints.NORTHWEST;
        optionsPanel.add(targetPanel, targetPanelConstraints);

        loadOptionsProperties();

        return optionsPanel;
    }

    private JPanel buildParametersPanel() {
        JPanel parametersPanel = new JPanel();
        parametersPanel.setLayout(new GridBagLayout());
        int yPosition = 0;

        Runnable applicationComboBoxRunnable = new Runnable() {
            @Override
            public void run() {
                updateApplicationComboBox(applicationMap, apiErrorLabel, applicationComboBox);
            }
        };
        ActionListener applicationComboBoxActionListener = new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String applicationName = (String) applicationComboBox.getSelectedItem();
                String applicationId = applicationMap.get(applicationName);
                burpPropertiesManager.setPropertyValue(BurpPropertiesManager.APP_ID_KEY, applicationId);
            }
        };

        final JLabel parametersPanelTitle = addPanelTitleToGridBagLayout("ThreadFix Server", parametersPanel, yPosition++);
        final JLabel parametersPanelDescription = addPanelDescriptionToGridBagLayout("These settings let you connect to a ThreadFix server and choose an Application.", parametersPanel, yPosition++);
        urlField = addTextFieldToGridBagLayout("ThreadFix Server URL:", parametersPanel, yPosition++, BurpPropertiesManager.THREADFIX_URL_KEY, applicationComboBoxRunnable);
        keyField = addTextFieldToGridBagLayout("API Key:", parametersPanel, yPosition++, BurpPropertiesManager.API_KEY_KEY, applicationComboBoxRunnable);

        final JButton applicationComboBoxRefreshButton = new JButton("Refresh application list");
        applicationComboBoxRefreshButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {
                updateApplicationComboBox(applicationMap, apiErrorLabel, applicationComboBox);
            }
        });
        applicationComboBox = addComboBoxToGridBagLayout("Pick an Application", parametersPanel, yPosition++, applicationComboBoxActionListener, applicationComboBoxRefreshButton);
        apiErrorLabel = addErrorMessageToGridBagLayout(parametersPanel, yPosition++);

        return parametersPanel;
    }

    private JPanel buildSourcePanel() {
        final JPanel sourcePanel = new JPanel();
        sourcePanel.setLayout(new GridBagLayout());
        int yPosition = 0;

        final JLabel sourcePanelTitle = addPanelTitleToGridBagLayout("Local Source Code", sourcePanel, yPosition++);
        final JLabel sourcePanelDescription = addPanelDescriptionToGridBagLayout("This setting lets you configure the location of your source code.", sourcePanel, yPosition++);

        final JButton sourceFolderBrowseButton = new JButton("Select folder ...");
        sourceFolderBrowseButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {
                JFileChooser chooser = new JFileChooser();
                String currentDirectory = sourceFolderField.getText();
                if ((currentDirectory == null) || (currentDirectory.trim().equals(""))) {
                    currentDirectory = System.getProperty("user.home");
                }
                chooser.setCurrentDirectory(new java.io.File(currentDirectory));
                chooser.setDialogTitle("Please select the folder containing the source code");
                chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
                chooser.setAcceptAllFileFilterUsed(false);
                if (chooser.showOpenDialog(sourcePanel) == JFileChooser.APPROVE_OPTION) {
                    sourceFolderField.setText(chooser.getSelectedFile().getAbsolutePath());
                }
            }
        });
        sourceFolderField = addTextFieldToGridBagLayout("Location of source code folder:", sourcePanel, yPosition++, BurpPropertiesManager.SOURCE_FOLDER_KEY, sourceFolderBrowseButton);

        return sourcePanel;
    }

    private JPanel buildTargetPanel() {
        final JPanel targetPanel = new JPanel();
        targetPanel.setLayout(new GridBagLayout());
        int yPosition = 0;

        final JLabel targetPanelTitle = addPanelTitleToGridBagLayout("Target URL", targetPanel, yPosition++);
        targetUrlField = addTextFieldToGridBagLayout("Please enter the target URL:", targetPanel, yPosition++, BurpPropertiesManager.TARGET_URL_KEY);

        return targetPanel;
    }

    //
    // implement ITab
    //

    @Override
    public String getTabCaption()
    {
        return "ThreadFix";
    }

    @Override
    public Component getUiComponent()
    {
        return tabbedPane;
    }

    private class ThreadFixPropertyFieldListener implements DocumentListener, FocusListener {
        private JTextField jTextField;
        private String propertyName;
        private Runnable runnable;

        private String lastValue = null;

        public ThreadFixPropertyFieldListener(JTextField jTextField, String propertyName) {
            this(jTextField, propertyName, null);
        }

        public ThreadFixPropertyFieldListener(JTextField jTextField, String propertyName, Runnable runnable) {
            this.jTextField = jTextField;
            this.propertyName = propertyName;
            this.runnable = runnable;
        }

        protected void update() {
            burpPropertiesManager.setPropertyValue(propertyName, jTextField.getText().trim());
            if (runnable != null) {
                runnable.run();
            }
        }

        @Override
        public void insertUpdate(DocumentEvent e) {
            update();
        }

        @Override
        public void removeUpdate(DocumentEvent e) {
            update();
        }

        @Override
        public void changedUpdate(DocumentEvent e) {
            update();
        }

        @Override
        public void focusGained(FocusEvent e) {
            System.out.println("focusGained -- " + jTextField.getText());
            lastValue = jTextField.getText().trim();
        }

        @Override
        public void focusLost(FocusEvent e) {
            System.out.println("focusLost -- " + jTextField.getText());
            String currentValue = jTextField.getText().trim();
            if (!currentValue.equals(lastValue)) {
                update();
            }
        }
    }

    private void loadOptionsProperties() {
        urlField.setText(burpPropertiesManager.getUrl());
        keyField.setText(burpPropertiesManager.getKey());
        updateApplicationComboBox(applicationMap, apiErrorLabel, applicationComboBox);
        sourceFolderField.setText(burpPropertiesManager.getSourceFolder());
        targetUrlField.setText(burpPropertiesManager.getTargetUrl());
    }

    private void updateApplicationComboBox(Map<String, String> applicationMap, JLabel apiErrorLabel, JComboBox applicationComboBox) {
        applicationComboBox.setEnabled(false);
        ActionListener[] applicationComboBoxActionListeners = applicationComboBox.getActionListeners();
        for (ActionListener applicationComboBoxActionListener : applicationComboBoxActionListeners) {
            applicationComboBox.removeActionListener(applicationComboBoxActionListener);
        }

        updateApplicationMapData(applicationMap);
        Object[] possibilities = applicationMap.keySet().toArray();

        boolean failedToConnect = false;
        String failureMessage = "";
        if (possibilities.length != 0 && possibilities[0].toString().startsWith("Authentication failed")) {
            failedToConnect = true;
            failureMessage = possibilities[0].toString();
        }
        else if (possibilities.length == 0) {
            failedToConnect = true;
            failureMessage = "Failed while trying to get a list of applications from ThreadFix.";
        }

        String currentAppId = burpPropertiesManager.getAppId();
        applicationComboBox.removeAllItems();
        if (failedToConnect) {
            apiErrorLabel.setText(failureMessage);
        } else {
            apiErrorLabel.setText("");
            for (Object possibility : possibilities) {
                applicationComboBox.addItem(possibility);
            }
            String currentAppName = applicationMap.get(currentAppId);
            for (String appName : applicationMap.keySet()) {
                if(applicationMap.get(appName).equals(currentAppId)) {
                    currentAppName = appName;
                    break;
                }
            }
            applicationComboBox.setSelectedItem(currentAppName);
        }
        for (ActionListener applicationComboBoxActionListener : applicationComboBoxActionListeners) {
            applicationComboBox.addActionListener(applicationComboBoxActionListener);
        }
        applicationComboBox.setEnabled(!failedToConnect);
    }

    private void updateApplicationMapData(Map<String, String> applicationMap) {
        Application.Info[] infos;
        try {
            infos = RestUtils.getApplications();
        } catch (Exception e) {
            infos = new Application.Info[0];
        }
        applicationMap.clear();
        for (Application.Info info : infos) {
            applicationMap.put(info.getOrganizationName() + "/" + info.getApplicationName(),
                    info.getApplicationId());
        }
    }

    private JLabel addPanelTitleToGridBagLayout(String titleText, Container gridBagContainer, int yPosition) {
        final JLabel panelTitle = new JLabel(titleText, JLabel.LEFT);
        panelTitle.setForeground(new Color(236, 136, 0));
        Font font = panelTitle.getFont();
        panelTitle.setFont(new Font(font.getFontName(), font.getStyle(), font.getSize() + 4));
        panelTitle.setHorizontalAlignment(SwingConstants.LEFT);
        callbacks.customizeUiComponent(panelTitle);
        GridBagConstraints gridBagConstraints = new GridBagConstraints();
        gridBagConstraints.gridwidth = 3;
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = yPosition;
        gridBagConstraints.ipadx = 5;
        gridBagConstraints.ipady = 5;
        gridBagConstraints.fill = GridBagConstraints.HORIZONTAL;
        gridBagConstraints.anchor = GridBagConstraints.NORTH;
        gridBagContainer.add(panelTitle, gridBagConstraints);
        return panelTitle;
    }

    private JLabel addPanelDescriptionToGridBagLayout(String descriptionText, Container gridBagContainer, int yPosition) {
        final JLabel panelDescription = new JLabel(descriptionText);
        panelDescription.setHorizontalAlignment(SwingConstants.LEFT);
        callbacks.customizeUiComponent(panelDescription);
        GridBagConstraints gridBagConstraints = new GridBagConstraints();
        gridBagConstraints.gridwidth = 3;
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = yPosition;
        gridBagConstraints.ipadx = 5;
        gridBagConstraints.ipady = 5;
        gridBagConstraints.fill = GridBagConstraints.HORIZONTAL;
        gridBagConstraints.anchor = GridBagConstraints.WEST;
        gridBagContainer.add(panelDescription, gridBagConstraints);
        return panelDescription;
    }

    private JLabel addErrorMessageToGridBagLayout(Container gridBagContainer, int yPosition) {
        final JLabel errorMessage = new JLabel("");
        errorMessage.setForeground(new Color(255, 0, 0));
        errorMessage.setHorizontalAlignment(SwingConstants.LEFT);
        callbacks.customizeUiComponent(errorMessage);
        GridBagConstraints gridBagConstraints = new GridBagConstraints();
        gridBagConstraints.gridwidth = 3;
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = yPosition;
        gridBagConstraints.ipadx = 5;
        gridBagConstraints.ipady = 10;
        gridBagConstraints.fill = GridBagConstraints.HORIZONTAL;
        gridBagConstraints.anchor = GridBagConstraints.WEST;
        gridBagContainer.add(errorMessage, gridBagConstraints);
        return errorMessage;
    }

    private JTextField addTextFieldToGridBagLayout(String labelText, Container gridBagContainer, int yPosition, String propertyKey) {
        return addTextFieldToGridBagLayout(labelText, gridBagContainer, yPosition, propertyKey, null, null);
    }

    private JTextField addTextFieldToGridBagLayout(String labelText, Container gridBagContainer, int yPosition, String propertyKey, Runnable threadFixPropertyFieldListenerRunnable) {
        return addTextFieldToGridBagLayout(labelText, gridBagContainer, yPosition, propertyKey, threadFixPropertyFieldListenerRunnable, null);
    }

    private JTextField addTextFieldToGridBagLayout(String labelText, Container gridBagContainer, int yPosition, String propertyKey, JButton button) {
        return addTextFieldToGridBagLayout(labelText, gridBagContainer, yPosition, propertyKey, null, button);
    }

    private JTextField addTextFieldToGridBagLayout(String labelText, Container gridBagContainer, int yPosition, String propertyKey, Runnable threadFixPropertyFieldListenerRunnable, JButton button) {
        JLabel textFieldLabel = new JLabel(labelText);
        callbacks.customizeUiComponent(textFieldLabel);
        textFieldLabel.setHorizontalAlignment(SwingConstants.LEFT);
        GridBagConstraints gridBagConstraints = new GridBagConstraints();
        gridBagConstraints.gridwidth = 1;
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = yPosition;
        gridBagConstraints.ipadx = 5;
        gridBagConstraints.ipady = 5;
        gridBagConstraints.fill = GridBagConstraints.BOTH;
        gridBagContainer.add(textFieldLabel, gridBagConstraints);

        JTextField textField = new JTextField(40);
        callbacks.customizeUiComponent(textField);
        textField.addFocusListener(new ThreadFixPropertyFieldListener(textField, propertyKey, threadFixPropertyFieldListenerRunnable));
        gridBagConstraints = new GridBagConstraints();
        if (button == null) {
            gridBagConstraints.gridwidth = 2;
        } else {
            gridBagConstraints.gridwidth = 1;
        }
        gridBagConstraints.gridx = 2;
        gridBagConstraints.gridy = yPosition;
        gridBagConstraints.ipadx = 5;
        gridBagConstraints.ipady = 5;
        gridBagConstraints.fill = GridBagConstraints.HORIZONTAL;
        gridBagConstraints.anchor = GridBagConstraints.NORTH;
        gridBagContainer.add(textField, gridBagConstraints);

        if (button != null) {
            callbacks.customizeUiComponent(button);
            gridBagConstraints = new GridBagConstraints();
            gridBagConstraints.gridwidth = 1;
            gridBagConstraints.gridx = 3;
            gridBagConstraints.gridy = yPosition;
            gridBagConstraints.ipadx = 5;
            gridBagConstraints.ipady = 5;
            gridBagConstraints.fill = GridBagConstraints.NONE;
            gridBagConstraints.anchor = GridBagConstraints.NORTHEAST;
            gridBagContainer.add(button, gridBagConstraints);
        }

        return textField;
    }

    private JComboBox addComboBoxToGridBagLayout(String labelText, Container gridBagContainer, int yPosition, ActionListener actionListener) {
        return addComboBoxToGridBagLayout(labelText, gridBagContainer, yPosition, actionListener, null);
    }

    private JComboBox addComboBoxToGridBagLayout(String labelText, Container gridBagContainer, int yPosition, ActionListener actionListener, JButton button) {
        JLabel textFieldLabel = new JLabel(labelText);
        callbacks.customizeUiComponent(textFieldLabel);
        textFieldLabel.setHorizontalAlignment(SwingConstants.LEFT);
        GridBagConstraints gridBagConstraints = new GridBagConstraints();
        gridBagConstraints.gridwidth = 1;
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = yPosition;
        gridBagConstraints.ipadx = 5;
        gridBagConstraints.ipady = 5;
        gridBagConstraints.fill = GridBagConstraints.BOTH;
        gridBagContainer.add(textFieldLabel, gridBagConstraints);

        JComboBox comboBox = new JComboBox();
        comboBox.setEnabled(false);
        callbacks.customizeUiComponent(comboBox);
        gridBagConstraints = new GridBagConstraints();
        if (button == null) {
            gridBagConstraints.gridwidth = 2;
        } else {
            gridBagConstraints.gridwidth = 1;
        }
        gridBagConstraints.gridx = 2;
        gridBagConstraints.gridy = yPosition;
        gridBagConstraints.ipadx = 5;
        gridBagConstraints.ipady = 5;
        gridBagConstraints.fill = GridBagConstraints.HORIZONTAL;
        gridBagConstraints.anchor = GridBagConstraints.NORTH;
        gridBagContainer.add(comboBox, gridBagConstraints);

        if (button != null) {
            callbacks.customizeUiComponent(button);
            gridBagConstraints = new GridBagConstraints();
            gridBagConstraints.gridwidth = 1;
            gridBagConstraints.gridx = 3;
            gridBagConstraints.gridy = yPosition;
            gridBagConstraints.ipadx = 5;
            gridBagConstraints.ipady = 5;
            gridBagConstraints.fill = GridBagConstraints.NONE;
            gridBagConstraints.anchor = GridBagConstraints.NORTHEAST;
            gridBagContainer.add(button, gridBagConstraints);
        }

        comboBox.addActionListener(actionListener);

        return comboBox;
    }
}
