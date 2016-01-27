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
package com.denimgroup.threadfix.service.repository;

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.SourceCodeRepoType;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.RepositoryService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.annotation.Nonnull;

/**
 * @author zabdisubhan
 */
@Component
public class RepositoryServiceFactoryImpl implements RepositoryServiceFactory {

    private static final SanitizedLogger LOG = new SanitizedLogger(RepositoryServiceFactory.class);

    @Autowired
    private GitServiceImpl gitServiceImpl;
    @Autowired
    private SvnServiceImpl svnServiceImpl;

    @Override
    public RepositoryService getRepositoryService(@Nonnull Application application) {

        LOG.info("Determining proper RepositoryService implementation for application " + application.getName() + " and new scan.");
        return getRepositoryService(application.getRepositoryType());
    }

    @Override
    public RepositoryService getRepositoryService(@Nonnull String repoName) {

        RepositoryService repositoryService = null;

        SourceCodeRepoType repoType = SourceCodeRepoType.getType(repoName);
        if (repoType == SourceCodeRepoType.GIT) {
            LOG.info("Source code is being stored in Git. Returning GitServiceImpl.");
            repositoryService = gitServiceImpl;
        } else if (repoType == SourceCodeRepoType.SVN) {
            LOG.info("Source code is being stored in SVN. Returning SvnServiceImpl.");
            repositoryService = svnServiceImpl;
        }

        return repositoryService;
    }

}
