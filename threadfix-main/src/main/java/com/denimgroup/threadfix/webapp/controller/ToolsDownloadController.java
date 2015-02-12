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
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

@Controller
@RequestMapping("/configuration/download")
public class ToolsDownloadController {

	private final SanitizedLogger log = new SanitizedLogger(ToolsDownloadController.class);
    private final static String CSV2SSVL_JAR = "CSV2SSVL-1.0-SNAPSHOT-jar-with-dependencies.jar";
    private final static String TF_CLI_JAR = "threadfix-cli-2.0-jar-with-dependencies.jar";
    private final static String TF_SCAN_IMPORTER_JAR = "threadfix-cli-importers-2.2-SNAPSHOT.jar";
    private final static String TF_HAM_CLI_JAR = "threadfix-ham-2.2-SNAPSHOT.jar";
    private final static String TF_DATA_MIGRATION_JAR = "threadfix-data-migration-2.2-SNAPSHOT.jar";

	public ToolsDownloadController(){}
	
	@RequestMapping(method = RequestMethod.GET)
	public String index() {

		return "config/download/index";
	}

    @RequestMapping(value="/csv2ssvl")
    public void doDownloadCsv2ssvl(HttpServletRequest request, HttpServletResponse response) {
        doDownload(request, response, CSV2SSVL_JAR);
    }

    @RequestMapping(value="/tfcli")
    public String doDownloadTFcli(HttpServletRequest request, HttpServletResponse response) {
        doDownload(request, response, TF_CLI_JAR);
        return "config/download/index";
    }

    @RequestMapping(value="/tfscancli")
    public void doDownloadTFscancli(HttpServletRequest request, HttpServletResponse response) {
        doDownload(request, response, TF_SCAN_IMPORTER_JAR);
    }

    @RequestMapping(value="/tfhamcli")
    public String doDownloadTFhamcli(HttpServletRequest request, HttpServletResponse response) {
        doDownload(request, response, TF_HAM_CLI_JAR);
        return "config/download/index";
    }

    @RequestMapping(value="/tfdatamigration")
    public String doDownloadTFdatamigration(HttpServletRequest request, HttpServletResponse response) {
        doDownload(request, response, TF_DATA_MIGRATION_JAR);
        return "config/download/index";
    }

    private void doDownload(HttpServletRequest request, HttpServletResponse response, String jarName) {

        String jarResource = "/WEB-INF/download/" + jarName;

        InputStream in = request.getServletContext().getResourceAsStream(jarResource);
        if (in == null) {
            log.error("JAR File not found for download: " + jarResource);
            return;
        }

        ServletOutputStream out;

        try {
            out = response.getOutputStream();
            int jarSize = request.getServletContext().getResource(jarResource).openConnection().getContentLength();

            response.setContentType("application/java-archive");
            response.setContentLength(jarSize);

            response.addHeader("Content-Disposition", "attachment; filename=\"" + jarName + "\"");

            IOUtils.copy(in, out);
            in.close();
            out.flush();
            out.close();
        } catch (IOException e) {
            log.error("IOException writing JAR File to client: " + jarName, e);
        }

    }


}
