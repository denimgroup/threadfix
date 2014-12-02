////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2014 Denim Group, Ltd.
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

package com.denimgroup.threadfix.webapp.filter;

import com.denimgroup.threadfix.logging.SanitizedLogger;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.io.InputStream;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.Random;
import java.util.jar.Attributes;
import java.util.jar.Manifest;

/**
 * Created by zabdisubhan on 9/8/14.
 */

@Component
public class CacheBustFilter extends GenericFilterBean {

    private final SanitizedLogger log = new SanitizedLogger(CacheBustFilter.class);
    private String gitCommit = null;
    private String buildNumber = null;
    private Date buildDate = null;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;

        // If there was a build number defined in the war, then use it for the cache buster.
        req.setAttribute("gitCommit", gitCommit);
        req.setAttribute("buildNumber", (buildNumber != null) ? buildNumber : "2.2-SNAPSHOT" + "-" + gitCommit);
        req.setAttribute("buildDate", (buildDate != null) ? buildDate : Calendar.getInstance().getTime());

        chain.doFilter(request, response);
    }

    @Override
    public void initFilterBean() throws ServletException {
        try {
            InputStream is =
                getServletContext().getResourceAsStream("/META-INF/MANIFEST.MF");
            if (is == null) {
                log.warn("/META-INF/MANIFEST.MF not found.");
            } else {
                Manifest mf = new Manifest();
                mf.read(is);
                Attributes attrs = mf.getMainAttributes();
                String version = attrs.getValue("Implementation-Version");
                String date = attrs.getValue("Implementation-Build-Date");
                gitCommit = attrs.getValue("Implementation-Build");

                gitCommit = (gitCommit != null) ? gitCommit : String.valueOf(new Random().nextInt(10000000));

                if (version != null && gitCommit != null){
                    buildNumber = version + "-" + gitCommit;
                    log.info("Application version set to: " + buildNumber);
                }

                if(date != null) {
                    SimpleDateFormat dt = new SimpleDateFormat("yyyy-MM-dd hh:mm:ss");
                    try {
                        buildDate = dt.parse(date);
                    } catch (ParseException e) {
                        log.debug("Exception thrown parsing build date from MANIFEST.mf file.");
                    }
                }

            }
        } catch (IOException e) {
            log.error("I/O Exception reading manifest: " + e.getMessage());
        }
    }
}
