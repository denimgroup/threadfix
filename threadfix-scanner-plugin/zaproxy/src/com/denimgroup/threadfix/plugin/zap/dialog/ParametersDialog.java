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

package com.denimgroup.threadfix.plugin.zap.dialog;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;

import javax.swing.ImageIcon;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTextField;

import org.apache.log4j.Logger;
import org.parosproxy.paros.extension.ViewDelegate;
import org.zaproxy.zap.extension.threadfix.ZapPropertiesManager;

public class ParametersDialog {

    private static final Logger logger = Logger.getLogger(ParametersDialog.class);

    public static boolean show(ViewDelegate view) {
        logger.info("Attempting to show dialog.");
        JTextField urlField = new JTextField(40);
        urlField.setText(ZapPropertiesManager.INSTANCE.getUrl());
        JTextField keyField = new JTextField(40);
        keyField.setText(ZapPropertiesManager.INSTANCE.getKey());

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
        myPanel.add(new JLabel("URL"), labelConstraints);
        myPanel.add(urlField, textBoxConstraints);

        labelConstraints.gridy = 1;
        textBoxConstraints.gridy = 1;

        myPanel.add(new JLabel("API Key"), labelConstraints);
        myPanel.add(keyField, textBoxConstraints);

        String attempt = ParametersDialog.class.getProtectionDomain().getCodeSource().getLocation().getFile() + "/dg-icon.png";

        logger.info("Trying " + attempt);

        ImageIcon icon = new ImageIcon(attempt);

        int result = JOptionPane.showConfirmDialog(view.getMainFrame(),
                myPanel,
                "Please enter the ThreadFix URL and API Key values",
                JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.INFORMATION_MESSAGE,
                icon);
        if (result == JOptionPane.OK_OPTION) {
            ZapPropertiesManager.setKeyAndUrl(keyField.getText(), urlField.getText());
            logger.info("Got properties and saved.");
            return true;
        } else {
            logger.info("Cancel pressed.");
            return false;
        }
    }

}
