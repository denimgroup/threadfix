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

package com.denimgroup.threadfix.plugin.zap.action;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.extension.ViewDelegate;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.SiteMap;
import org.parosproxy.paros.model.SiteNode;
import org.zaproxy.zap.extension.XmlReporterExtension;
import org.zaproxy.zap.utils.XMLStringUtil;
import org.zaproxy.zap.view.ScanPanel;

import java.io.File;

/**
 * Created by mac on 9/23/13.
 */
public class ReportGenerator {

    private static Logger logger = Logger.getLogger(ReportGenerator.class);

    private ReportGenerator(){}

    private static File generate(String fileName, Model model, String xslFile) throws Exception {
        StringBuilder sb = new StringBuilder(500);
        generate(sb, model);
        return org.parosproxy.paros.extension.report.ReportGenerator.stringToHtml(sb.toString(), xslFile, fileName);
    }

    private static void generate(StringBuilder report, Model model) throws Exception {
        report.append("<?xml version=\"1.0\"?>");
        report.append("<OWASPZAPReport version=\"")
                .append(Constant.PROGRAM_VERSION)
                .append("\" generated=\"")
                .append(org.parosproxy.paros.extension.report.ReportGenerator.getCurrentDateTimeString())
                .append("\">\r\n");
        siteXML(report);
        report.append("</OWASPZAPReport>");
    }

    private static void siteXML(StringBuilder report) {
        SiteMap siteMap = Model.getSingleton().getSession().getSiteTree();
        SiteNode root = (SiteNode) siteMap.getRoot();
        int siteNumber = root.getChildCount();
        for (int i = 0; i < siteNumber; i++) {
            SiteNode site = (SiteNode) root.getChildAt(i);
            String siteName = ScanPanel.cleanSiteName(site, true);
            String[] hostAndPort = siteName.split(":");
            boolean isSSL = (site.getNodeName().startsWith("https"));
            String siteStart = "<site name=\"" + XMLStringUtil.escapeControlChrs(site.getNodeName()) + "\"" +
                    " host=\"" + XMLStringUtil.escapeControlChrs(hostAndPort[0])+ "\""+
                    " port=\"" + XMLStringUtil.escapeControlChrs(hostAndPort[1])+ "\""+
                    " ssl=\"" + String.valueOf(isSSL) + "\"" +
                    ">";
            StringBuilder extensionsXML = getExtensionsXML(site);
            String siteEnd = "</site>";
            report.append(siteStart);
            report.append(extensionsXML);
            report.append(siteEnd);
        }
    }

    private static StringBuilder getExtensionsXML(SiteNode site) {
        StringBuilder extensionXml = new StringBuilder();
        ExtensionLoader loader = Control.getSingleton().getExtensionLoader();
        int extensionCount = loader.getExtensionCount();
        for(int i=0; i<extensionCount; i++) {
            Extension extension = loader.getExtension(i);
            if(extension instanceof XmlReporterExtension) {
                extensionXml.append(((XmlReporterExtension)extension).getXml(site));
            }
        }
        return extensionXml;
    }

    public static File generateXml(ViewDelegate view, Model model) {

        File report = null;

        // ZAP: Allow scan report file name to be specified
        try {

            File file = new File("threadfix.xml");

            report = generate(file.getAbsolutePath(), model, "xml/report.xml.xsl");

        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            view.showWarningDialog(Constant.messages.getString("report.unexpected.warning"));
        }

        return report;
    }
}
