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

package burp.dialog;

import burp.extention.BurpPropertiesManager;

import javax.swing.*;
import java.awt.*;

public class UrlDialog {

    public static String show(Component view) {
        BurpPropertiesManager burpPropertiesManager = BurpPropertiesManager.getBurpPropertiesManager();
        String targetUrl = burpPropertiesManager.getTargetUrl();
        if ((targetUrl != null) && !targetUrl.trim().isEmpty()) {
            return targetUrl;
        }

        JTextField urlField = new JTextField(40);
        urlField.setText("http://");

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

        String attempt = UrlDialog.class.getProtectionDomain().getCodeSource().getLocation().getFile() + "/dg-icon.png";

        ImageIcon icon = new ImageIcon(attempt);

        int result = JOptionPane.showConfirmDialog(view,
                myPanel,
                "Please enter the target URL",
                JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.INFORMATION_MESSAGE,
                icon);
        if (result == JOptionPane.OK_OPTION) {
            String url = urlField.getText();
            if (url != null && !url.isEmpty())
                burpPropertiesManager.setTargetUrl(url);
            return url;
        } else {
            return null;
        }
    }

}
