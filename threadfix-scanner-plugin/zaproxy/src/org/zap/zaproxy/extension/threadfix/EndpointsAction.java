package org.zaproxy.zap.extension.threadfix;

import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.log4j.Logger;
import org.parosproxy.paros.extension.ViewDelegate;
import org.parosproxy.paros.model.Model;
import org.zaproxy.zap.spider.Spider;

import javax.swing.*;

/**
 * Created with IntelliJ IDEA.
 * User: mcollins
 * Date: 9/24/13
 * Time: 1:20 PM
 * To change this template use File | Settings | File Templates.
 */
public class EndpointsAction extends JMenuItem {

    private static final Logger logger = Logger.getLogger(ThreadFixExtension.class);

    public EndpointsAction(final ViewDelegate view, final Model model, Spider spider) {
        logger.info("Initializing ThreadFix endpoint menu item");
        setText("Import Endpoints from ThreadFix");
        this.spider = spider;

        addActionListener(new java.awt.event.ActionListener() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {

                logger.info("About to show dialog.");

                ParametersDialog.show(view);

                logger.info("Got settings. About to show Application selection.");

                ApplicationDialog.show(view);

                logger.info("Got application id, about to generate XML and use REST call.");

                String csv = RestUtils.getEndpoints();

                logger.info(csv);

                String url = UrlDialog.show(view);

                for (String line : csv.split("\n")) {
                    String path = line.split(",")[1];
                    addURI(url + path);
                }

                int responseCode = 200;

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

    private final Spider spider;

    private void addURI(String uri) {

        try {
            logger.info("Attempting to add " + uri);

            spider.start();
            //spider.

            spider.addSeed(new URI(uri, false));
        } catch (URIException e) {
            logger.warn(e.getMessage(), e);
        }
    }

}
