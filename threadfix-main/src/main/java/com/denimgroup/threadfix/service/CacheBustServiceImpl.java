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
import java.util.List;

import static com.denimgroup.threadfix.CollectionUtils.list;

/**
 * @author zabdisubhan
 */
@Service
public class CacheBustServiceImpl implements CacheBustService {

    private final SanitizedLogger log = new SanitizedLogger(CacheBustServiceImpl.class);

    public String notCachedAsset(HttpServletRequest request, String relUrl) {

        String buildNumber = (String) request.getAttribute("buildNumber");
        return request.getContextPath() + "/v/" + buildNumber + relUrl;
    }

    @Override
    public List<String> notCachedJsPaths(HttpServletRequest request, List<Report> reports) {

        List<String> notCachedJs = list();

        if (reports == null || reports.isEmpty()) {
            throw new IllegalStateException("Unable to load any reports. ThreadFix needs the default reports.");
        }

        for (Report report : reports) {

            if (report == null) {
                throw new IllegalStateException("Got a null report.");
            }

            String jsFilePath = report.getJsFilePath();

            if(jsFilePath != null && !jsFilePath.isEmpty()){
                String filteredJsPath = notCachedAsset(request, jsFilePath);
                if (!notCachedJs.contains(filteredJsPath))
                    notCachedJs.add(filteredJsPath);
            }
        }

        return notCachedJs;

    }
}
