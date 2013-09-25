package org.zaproxy.zap.extension.threadfix;

import org.apache.log4j.Logger;
import org.parosproxy.paros.extension.ViewDelegate;
import org.parosproxy.paros.model.Model;

import javax.swing.*;
import java.io.File;

/**
 * Created with IntelliJ IDEA.
 * User: mcollins
 * Date: 9/24/13
 * Time: 1:20 PM
 * To change this template use File | Settings | File Templates.
 */
public class ImportAction extends JMenuItem {

    private static final Logger logger = Logger.getLogger(ThreadFixExtension.class);

    public ImportAction(final ViewDelegate view, final Model model) {
        logger.info("Initializing ThreadFix scan export menu item");
        setText("Export Scan to ThreadFix");

        addActionListener(new java.awt.event.ActionListener() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {

                logger.info("About to show dialog.");

                ParametersDialog.show(view);

                logger.info("Got settings. About to show Application selection.");

                ApplicationDialog.show(view);

                logger.info("Got application id, about to generate XML and use REST call.");

                File file = ReportGenerator.generateXml(view, model);

                logger.info("File = " + file);
                logger.info("full path = " + file.getAbsoluteFile());

                logger.info("About to try to upload.");
                int responseCode = RestUtils.uploadScan(file);
                if (responseCode == 0) {
                    view.showWarningDialog("The response code was 0, indicating that the ThreadFix server " +
                            "was unreachable. Make sure that the server is running and not blocked by the ZAP " +
                            "local proxy.");
                } else if (responseCode == -2) {
                    view.showWarningDialog("The parameters were not saved correctly.");
                } else if (responseCode != 200) {
                    view.showWarningDialog("Scan upload failed: the HTTP response code was " + responseCode +
                            " and not 200.");
                } else {
                    view.showMessageDialog("The scan was uploaded to ThreadFix successfully.");
                }
            }
        });
    }

}
