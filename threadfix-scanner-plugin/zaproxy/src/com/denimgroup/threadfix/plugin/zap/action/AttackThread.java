/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2012 The ZAP development team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.denimgroup.threadfix.plugin.zap.action;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;

import org.apache.commons.httpclient.URI;
import org.apache.log4j.Logger;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.zap.extension.ascan.ExtensionActiveScan;
import org.zaproxy.zap.extension.spider.ExtensionSpider;

public class AttackThread extends Thread {
    public enum Progress { NOT_STARTED, SPIDER, ASCAN, FAILED, COMPLETE, STOPPED }

    private EndpointsAction extension;
    private URL url;
    private HttpSender httpSender = null;
    private boolean stopAttack = false;

    private List<String> nodes = null;

    private static final Logger logger = Logger.getLogger(AttackThread.class);

    public AttackThread(EndpointsAction ext) {
        this.extension = ext;
    }

    public void setURL(URL url) {
        this.url = url;
    }

    public void setNodes(List<String> nodes) {
        this.nodes = nodes;
    }

    @Override
    public void run() {
        stopAttack = false;
        try {
            SiteNode startNode = null;
            String urlString = url.toString();

            logger.info("Starting at url : " + urlString);

            if (startNode == null) {
                startNode = this.accessNode(this.url);
            }

            if (startNode == null) {
                logger.debug("Failed to access URL " + urlString);
                extension.notifyProgress(Progress.FAILED);
                return;
            }
            if (stopAttack) {
                logger.debug("Attack stopped manually");
                extension.notifyProgress(Progress.STOPPED);
                return;
            }

            spider(startNode);
            
            ExtensionActiveScan extAscan = (ExtensionActiveScan) Control.getSingleton().getExtensionLoader().getExtension(ExtensionActiveScan.NAME);
            if (extAscan == null) {
                logger.error("No active scanner");
                extension.notifyProgress(Progress.FAILED);
                return;
            } else {
                extension.notifyProgress(Progress.ASCAN);
                extAscan.onHttpRequestSend(startNode.getHistoryReference().getHttpMessage());
            }

        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            extension.notifyProgress(Progress.FAILED);
        }
    }

    private void spider(SiteNode startNode) throws InterruptedException, MalformedURLException {
        logger.info("About to grab spider.");
        ExtensionSpider extSpider = (ExtensionSpider) Control.getSingleton().getExtensionLoader().getExtension(ExtensionSpider.NAME);
        logger.info("Starting spider.");

        if (extSpider == null) {
            logger.error("No spider");
            extension.notifyProgress(Progress.FAILED);
            return;
        } else if (startNode == null) {
            logger.error("start node was null");
            extension.notifyProgress(Progress.FAILED);
            return;
        } else {
            logger.info("Starting spider.");
            extension.notifyProgress(Progress.SPIDER);
            startNode.setAllowsChildren(true);
            for (String node : nodes) {
                logger.info("About to call accessNode.");
                SiteNode childNode = accessNode(new URL(url + node));
                logger.info("got out of accessNode.");
                if (childNode != null) {
                    logger.info("Child node != null, child node is " + childNode);
                    //childNode.setParent(startNode);
                    //startNode.add(childNode);
                } else {
                    logger.info("child node was null.");
                }
                //extSpider.startScanNode(childNode);
            }
            logger.info("about to start the extension. node = " + startNode);
            logger.info("child count = " + startNode.getChildCount());
            extSpider.startScanNode(startNode);
            logger.info("Started the extension.");
        }

        // Give some time to the spider to finish to setup and start itself.
        sleep(1500);

        try {
            // Wait for the spider to complete
            while (extSpider.isScanning(startNode, true)) {
                sleep (500);
                if (this.stopAttack) {
                    extSpider.stopScan(startNode);
                    break;
                }
            }
        } catch (InterruptedException e) {
            // Ignore
        }
        if (stopAttack) {
            logger.debug("Attack stopped manually");
            extension.notifyProgress(Progress.STOPPED);
            return;
        }

        // Pause before the spider seems to help
        sleep(2000);

        if (stopAttack) {
            logger.debug("Attack stopped manually");
            extension.notifyProgress(Progress.STOPPED);
            return;
        }
    }

    private SiteNode accessNode(URL url) {
        logger.info("Trying to find a node for " + url);

        SiteNode startNode = null;
        // Request the URL
        try {
            HttpMessage msg = new HttpMessage(new URI(url.toString(), true));
            getHttpSender().sendAndReceive(msg, true);

            if (msg.getResponseHeader().getStatusCode() != HttpStatusCode.OK) {
                extension.notifyProgress(Progress.FAILED);
                logger.info("response header was " + msg.getResponseHeader().getStatusCode());
                return null;
            }

            if (msg.getResponseHeader().isEmpty()) {
                logger.info("Reponse header was empty.");
                return null;
            }

            ExtensionHistory extHistory = (ExtensionHistory)Control.getSingleton().getExtensionLoader().getExtension(ExtensionHistory.NAME);
            extHistory.addHistory(msg, HistoryReference.TYPE_MANUAL);

            Model.getSingleton().getSession().getSiteTree().addPath(msg.getHistoryRef());

            for (int i=0; i < 10; i++) {
                startNode = Model.getSingleton().getSession().getSiteTree().findNode(new URI(url.toString(), false));
                if (startNode != null) {
                    break;
                }
                try {
                    sleep (200);
                } catch (InterruptedException e) {
                    // Ignore
                }
            }
        } catch (Exception e1) {
            logger.info(e1.getMessage(), e1);
            return null;
        }

        logger.warn("returning " + startNode);
        return startNode;
    }

    private HttpSender getHttpSender() {
        if (httpSender == null) {
            httpSender = new HttpSender(Model.getSingleton().getOptionsParam().getConnectionParam(), true,
                    HttpSender.MANUAL_REQUEST_INITIATOR);
        }
        return httpSender;
    }

    public void stopAttack() {
        this.stopAttack = true;
    }

}