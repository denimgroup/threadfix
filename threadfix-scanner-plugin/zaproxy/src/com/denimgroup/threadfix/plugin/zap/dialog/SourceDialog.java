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

package com.denimgroup.threadfix.plugin.zap.dialog;

import org.apache.log4j.Logger;
import org.parosproxy.paros.extension.ViewDelegate;
import org.zaproxy.zap.extension.threadfix.ZapPropertiesManager;

import javax.swing.*;
import java.awt.*;

public class SourceDialog {

    private static final String
            PASSWORD_PLACEHOLDER = "PASSWORD";

    private static final Logger logger = Logger.getLogger(SourceDialog.class);

    public static boolean show(ViewDelegate view) {
        logger.info("Attempting to show dialog.");
        JTextField repositoryUrlField = new JTextField(40);
        repositoryUrlField.setText(ZapPropertiesManager.INSTANCE.getRepositoryUrl());
        JTextField repositoryBranchField = new JTextField(40);
        repositoryBranchField.setText(ZapPropertiesManager.INSTANCE.getRepositoryBranch());
        JTextField repositoryUserNameField = new JTextField(40);
        repositoryUserNameField.setText(ZapPropertiesManager.INSTANCE.getRepositoryUserName());
        JPasswordField repositoryPasswordField = new JPasswordField(40);
        char[] repositoryPassword = ZapPropertiesManager.INSTANCE.getRepositoryPassword();
        if (repositoryPassword == null) {
            repositoryPasswordField.setText("");
        } else {
            repositoryPasswordField.setText(PASSWORD_PLACEHOLDER);
        }
        JTextField repositoryFolderField = new JTextField(40);
        repositoryFolderField.setText(ZapPropertiesManager.INSTANCE.getRepositoryFolder());

        GridBagLayout experimentLayout = new GridBagLayout();
        GridBagConstraints labelConstraints = new GridBagConstraints();
        labelConstraints.gridwidth = 1;
        labelConstraints.gridx = 0;
        labelConstraints.gridy = 0;
        labelConstraints.fill = GridBagConstraints.HORIZONTAL;
        GridBagConstraints textBoxConstraints = new GridBagConstraints();
        textBoxConstraints.gridwidth = 4;
        textBoxConstraints.gridx = 1;
        textBoxConstraints.gridy = 0;
        textBoxConstraints.fill = GridBagConstraints.HORIZONTAL;

        JPanel myPanel = new JPanel();
        myPanel.setLayout(experimentLayout);

        myPanel.add(new JLabel("Source Code URL"), labelConstraints);
        myPanel.add(repositoryUrlField, textBoxConstraints);

        labelConstraints.gridy++;
        textBoxConstraints.gridy++;

        myPanel.add(new JLabel("Source Code Revision"), labelConstraints);
        myPanel.add(repositoryBranchField, textBoxConstraints);

        labelConstraints.gridy++;
        textBoxConstraints.gridy++;

        myPanel.add(new JLabel("Source Code User Name"), labelConstraints);
        myPanel.add(repositoryUserNameField, textBoxConstraints);

        labelConstraints.gridy++;
        textBoxConstraints.gridy++;

        myPanel.add(new JLabel("Source Code Password"), labelConstraints);
        myPanel.add(repositoryPasswordField, textBoxConstraints);

        labelConstraints.gridy++;
        textBoxConstraints.gridy++;

        myPanel.add(new JLabel("Source Code Folder"), labelConstraints);
        myPanel.add(repositoryFolderField, textBoxConstraints);

        String attempt = SourceDialog.class.getProtectionDomain().getCodeSource().getLocation().getFile() + "/dg-icon.png";

        logger.info("Trying " + attempt);

        ImageIcon icon = new ImageIcon(attempt);

        int result = JOptionPane.showConfirmDialog(view.getMainFrame(),
                myPanel,
                "Please enter the appropriate information for accessing the source code",
                JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.INFORMATION_MESSAGE,
                icon);
        if (result == JOptionPane.OK_OPTION) {
            ZapPropertiesManager.setRepositoryInformation(repositoryUrlField.getText(), repositoryBranchField.getText(), repositoryUserNameField.getText(), repositoryFolderField.getText());
            repositoryPassword = repositoryPasswordField.getPassword();
            logger.info("Password Field: " + repositoryPassword);
            if ((repositoryPassword.length > 0) && !(repositoryPassword.equals(PASSWORD_PLACEHOLDER.toCharArray()))) {
                ZapPropertiesManager.setRepositoryPassword(repositoryPassword);
            }
            logger.info("Got properties and saved.");
            return true;
        } else {
            logger.info("Cancel pressed.");
            return false;
        }
    }

}
