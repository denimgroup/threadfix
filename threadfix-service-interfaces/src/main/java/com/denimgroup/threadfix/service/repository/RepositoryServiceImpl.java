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

package com.denimgroup.threadfix.service.repository;

import com.denimgroup.threadfix.DiskUtils;
import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.RepositoryService;
import org.springframework.stereotype.Service;

import java.io.File;

/**
 * @author zabdisubhan
 */

@Service
public abstract class RepositoryServiceImpl implements RepositoryService {

    private static final SanitizedLogger log = new SanitizedLogger(RepositoryServiceImpl.class);

    protected static final String baseDirectory = "scratch/";

    @Override
    public File getWorkTree(Application application) {
        File applicationDirectory = DiskUtils.getScratchFile(baseDirectory + application.getId());

        if (application.getRepositoryUrl() != null && !application.getRepositoryUrl().trim().isEmpty()) {
            File repo = cloneRepoToDirectory(application, applicationDirectory);

            if (repo != null && repo.exists()) {
                return repo;
            } else {
                return applicationDirectory;
            }
        } else if (application.getRepositoryFolder() != null && !application.getRepositoryFolder().trim().isEmpty()) {
            File file = new File(application.getRepositoryFolder().trim());
            if (!file.exists() || !file.isDirectory()) {
                return applicationDirectory;
            } else {
                return file;
            }
        }

        return applicationDirectory;
    }
}
