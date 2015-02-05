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

package com.denimgroup.threadfix.service;

import com.denimgroup.threadfix.data.entities.Report;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.io.InputStream;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.List;
import java.util.jar.Attributes;
import java.util.jar.Manifest;

import static com.denimgroup.threadfix.CollectionUtils.list;

/**
 * @author zabdisubhan
 */
@Service
public class CacheBustServiceImpl implements CacheBustService {

    private final SanitizedLogger log = new SanitizedLogger(CacheBustServiceImpl.class);

    public String filteredAsset(HttpServletRequest request, String relUrl) {

        String gitCommit = null;
        String buildNumber = null;
        String version = "2.2-SNAPSHOT";

        try {
            InputStream is =
                request.getServletContext().getResourceAsStream("/META-INF/MANIFEST.MF");
            if (is == null) {
                log.warn("/META-INF/MANIFEST.MF not found.");
                return null;
            } else {
                Manifest mf = new Manifest();
                mf.read(is);
                Attributes attrs = mf.getMainAttributes();

                if (attrs.getValue("Implementation-Version") != null) {
                    version = attrs.getValue("Implementation-Version");
                }

                if (attrs.getValue("Implementation-Build") != null) {
                    gitCommit = attrs.getValue("Implementation-Build");
                }

                // build fake git commit # for dev env
                SimpleDateFormat dt = new SimpleDateFormat("yyyyMMddhh");
                gitCommit = (gitCommit != null) ? gitCommit : dt.format(Calendar.getInstance().getTime());

                buildNumber = version + "-" + gitCommit;
            }

        } catch (IOException e) {
            log.error("I/O Exception reading manifest: " + e.getMessage());
        }

        return request.getContextPath() + "/v/" + buildNumber + relUrl;
    }


    @Override
    public List<String> uncachedJsPaths(HttpServletRequest request, List<Report> reports) {

        List<String> uncachedJs = list();

        for (Report report : reports) {

            String jsFilePath = report.getJsFilePath();

            if(jsFilePath != null && !jsFilePath.isEmpty()){
                String filteredJsPath = filteredAsset(request, jsFilePath);
                uncachedJs.add(filteredJsPath);
            }
        }

        return uncachedJs;

    }
}
