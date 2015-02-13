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
package com.denimgroup.threadfix.webapp.controller;

import com.denimgroup.threadfix.logging.SanitizedLogger;
import org.apache.commons.io.IOUtils;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;

@Controller
@RequestMapping("/configuration/download")
public class ToolsDownloadController {

	private final SanitizedLogger log = new SanitizedLogger(ToolsDownloadController.class);

    private final static String JAR_DOWNLOAD_DIR = "/WEB-INF/classes/downloads/";

    private final static String TF_CLI_JAR = "tfcli.jar";
    private final static String TF_SCAN_IMPORTER_JAR = "threadfix-cli-importers.jar";
    private final static String TF_ENDPOINT_JAR = "endpoints.jar";
    private final static String TF_DATA_MIGRATION_JAR = "threadfix-data-migration.jar";
    private final static String TF_BURP_JAR = "threadfix-release-2-burp.jar";
    private final static String TF_ZAP = "threadfix-release-2.zap";
    private final static String TF_SONAR_JAR = "sonar-threadfix-plugin.jar";
    private final static String CSV2SSVL_JAR = "csv2ssvl.jar";


    public ToolsDownloadController(){}
	
	@RequestMapping(method = RequestMethod.GET)
	public String index() {

		return "config/download/index";
	}

    @RequestMapping(value="/tfcli")
    public String doDownloadTFcli(HttpServletRequest request, HttpServletResponse response) {
        String destination = null;
        try {
            doDownload(request, response, TF_CLI_JAR);
        } catch (Exception e) {
            destination = "config/download/index";
        }
        return destination;
    }

    @RequestMapping(value="/tfscancli")
    public String doDownloadTFscancli(HttpServletRequest request, HttpServletResponse response) {
        String destination = null;
        try {
            doDownload(request, response, TF_SCAN_IMPORTER_JAR);
        } catch (Exception e) {
            destination = "config/download/index";
        }
        return destination;
    }

    @RequestMapping(value="/tfendpoint")
    public String doDownloadTFendcli(HttpServletRequest request, HttpServletResponse response) {
        String destination = null;
        try {
            doDownload(request, response, TF_ENDPOINT_JAR);
        } catch (Exception e) {
            destination = "config/download/index";
        }
        return destination;
    }

    @RequestMapping(value="/tfdatamigration")
    public String doDownloadTFdatamigration(HttpServletRequest request, HttpServletResponse response) {
        String destination = null;
        try {
            doDownload(request, response, TF_DATA_MIGRATION_JAR);
        } catch (Exception e) {
            destination = "config/download/index";
        }
        return destination;
    }

    @RequestMapping(value="/burp")
    public String doDownloadBurp(HttpServletRequest request, HttpServletResponse response) {
        String destination = null;
        try {
            doDownload(request, response, TF_BURP_JAR);
        } catch (Exception e) {
            destination = "config/download/index";
        }
        return destination;
    }

    @RequestMapping(value="/zap")
    public String doDownloadZap(HttpServletRequest request, HttpServletResponse response) {
        String destination = null;
        try {
            doDownload(request, response, TF_ZAP);
        } catch (Exception e) {
            destination = "config/download/index";
        }
        return destination;
    }

    @RequestMapping(value="/sonar")
    public String doDownloadSonar(HttpServletRequest request, HttpServletResponse response) {
        String destination = null;
        try {
            doDownload(request, response, TF_SONAR_JAR);
        } catch (Exception e) {
            destination = "config/download/index";
        }
        return destination;
    }

    @RequestMapping(value="/csv2ssvl")
    public String doDownloadCsv2ssvl(HttpServletRequest request, HttpServletResponse response) {
        String destination = null;
        try {
            doDownload(request, response, CSV2SSVL_JAR);
        } catch (Exception e) {
            destination = "config/download/index";
        }
        return destination;
    }


    private void doDownload(HttpServletRequest request, HttpServletResponse response, String jarName) throws IOException {

        String jarResource = JAR_DOWNLOAD_DIR + jarName;

        InputStream in = request.getServletContext().getResourceAsStream(jarResource);
        if (in == null) {
            log.error("JAR File not found for download: " + jarResource);
            throw new FileNotFoundException("JAR File not found for download: " + jarResource);
        }

        ServletOutputStream out = response.getOutputStream();
        int jarSize = request.getServletContext().getResource(jarResource).openConnection().getContentLength();

        if (jarName.endsWith(".jar"))
            response.setContentType("application/java-archive");
        else
            response.setContentType("application/octet-stream");;
        response.setContentLength(jarSize);
        response.addHeader("Content-Disposition", "attachment; filename=\"" + jarName + "\"");

        IOUtils.copy(in, out);
        in.close();
        out.flush();
        out.close();
    }


}
