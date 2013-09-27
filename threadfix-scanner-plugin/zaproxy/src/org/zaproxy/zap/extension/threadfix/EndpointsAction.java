package org.zaproxy.zap.extension.threadfix;

import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.log4j.Logger;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ViewDelegate;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.zap.extension.ascan.ExtensionActiveScan;
import org.zaproxy.zap.extension.spider.ExtensionSpider;
import org.zaproxy.zap.spider.Spider;

import javax.swing.*;
import java.net.URL;
import java.sql.SQLException;

/**
 * Created with IntelliJ IDEA.
 * User: mcollins
 * Date: 9/24/13
 * Time: 1:20 PM
 * To change this template use File | Settings | File Templates.
 */
public class EndpointsAction extends JMenuItem {

    private static final Logger logger = Logger.getLogger(ThreadFixExtension.class);

    private Model model;

    public EndpointsAction(final ViewDelegate view, final Model model, Spider spider) {
        logger.info("Initializing ThreadFix endpoint menu item");
        setText("Import Endpoints from ThreadFix");
        this.spider = spider;
        this.model = model;
        this.extensionSpider = (ExtensionSpider) Control.getSingleton().getExtensionLoader().getExtension(ExtensionSpider.NAME);

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

                try {
                    logger.info("URL = " + url);
                    URI uri = new URI(url.toString(), true);
                    logger.info("URI = " + uri);

                    HttpMessage msg = new HttpMessage(uri);
                    logger.info("Message = " + msg);

                    msg.setHistoryRef(new HistoryReference(model.getSession(), HistoryReference.TYPE_SPIDER, msg));

                    SiteNode node = Model.getSingleton().getSession().getSiteTree().addPath(msg.getHistoryRef());

                    if (node == null) {
                        logger.info("Node was null.");
                    } else {
                        logger.info("Node was " + node);
                        extensionSpider.startScan(node);
                        ExtensionActiveScan extActiveScan = (ExtensionActiveScan) Control.getSingleton().getExtensionLoader().getExtension(ExtensionActiveScan.NAME);
                        extActiveScan.startScan(node);
                    }

                } catch (HttpMalformedHeaderException e1) {
                    logger.info("Malformed header.", e1);
                } catch (URIException e1) {
                    logger.info("URIException", e1);
                } catch (SQLException e1) {
                    logger.info("SQLException", e1);
                }

                try {
                    logger.info("About to start extension spider. spider = " + extensionSpider);
                    SiteNode startNode = Model.getSingleton().getSession().getSiteTree().findNode(new URI(url.toString(), false));
                    // accessNode(new URL(url));

                    logger.info("Node = " + startNode);
                    extensionSpider.startScan(startNode);

//                } catch (MalformedURLException e1) {
//                    logger.info("MalformedURLException", e1);
                } catch (URIException e1) {
                    logger.info("URIException", e1);
                }

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

    private final ExtensionSpider extensionSpider;

    private void addURI(String url) {

        try {
            logger.info("URL = " + url);
            URI uri = new URI(url.toString(), true);
            logger.info("URI = " + uri);

            HttpMessage msg = new HttpMessage(uri);
            logger.info("Message = " + msg);

            msg.setHistoryRef(new HistoryReference(model.getSession(), HistoryReference.TYPE_SPIDER, msg));

            SiteNode node = Model.getSingleton().getSession().getSiteTree().addPath(msg.getHistoryRef());

            if (node == null) {
                logger.info("Node was null.");
            } else {
                logger.info("Node was " + node);
                extensionSpider.startScan(node);
            }

        } catch (HttpMalformedHeaderException e1) {
            logger.info("Malformed header.", e1);
        } catch (URIException e1) {
            logger.info("URIException", e1);
        } catch (SQLException e1) {
            logger.info("SQLException", e1);
        }

        try {
            logger.info("About to start extension spider. spider = " + extensionSpider);
            SiteNode startNode = Model.getSingleton().getSession().getSiteTree().findNode(new URI(url.toString(), false));
            // accessNode(new URL(url));

            logger.info("Node = " + startNode);
            extensionSpider.startScan(startNode);

//                } catch (MalformedURLException e1) {
//                    logger.info("MalformedURLException", e1);
        } catch (URIException e1) {
            logger.info("URIException", e1);
        }
    }

    private SiteNode accessNode(URL url) {
        SiteNode startNode = null;
        // Request the URL
        try {
            HttpMessage msg = new HttpMessage(new URI(url.toString(), true));
            getHttpSender().sendAndReceive(msg,true);

            if (msg.getResponseHeader().getStatusCode() != HttpStatusCode.OK) {
                return null;
            }

            if (msg.getResponseHeader().isEmpty()) {
                return null;
            }

            ExtensionHistory extHistory = ((ExtensionHistory)Control.getSingleton().getExtensionLoader().getExtension(ExtensionHistory.NAME));
            extHistory.addHistory(msg, HistoryReference.TYPE_MANUAL);

            Model.getSingleton().getSession().getSiteTree().addPath(msg.getHistoryRef());

            for (int i=0; i < 10; i++) {
                startNode = Model.getSingleton().getSession().getSiteTree().findNode(new URI(url.toString(), false));
                if (startNode != null) {
                    break;
                }
                try {
                    Thread.sleep(200);
                } catch (InterruptedException e) {
                    // Ignore
                }
            }
        } catch (Exception e1) {
            return null;
        }
        return startNode;
    }

    private HttpSender httpSender;

    private HttpSender getHttpSender() {
        if (httpSender == null) {
            httpSender = new HttpSender(Model.getSingleton().getOptionsParam().getConnectionParam(), true,
                    HttpSender.MANUAL_REQUEST_INITIATOR);
        }
        return httpSender;
    }

}
