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

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.ApplicationService;
import com.denimgroup.threadfix.service.SvnService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.tmatesoft.svn.core.SVNException;
import org.tmatesoft.svn.core.SVNNodeKind;
import org.tmatesoft.svn.core.SVNURL;
import org.tmatesoft.svn.core.auth.ISVNAuthenticationManager;
import org.tmatesoft.svn.core.internal.io.dav.DAVRepositoryFactory;
import org.tmatesoft.svn.core.internal.io.fs.FSRepositoryFactory;
import org.tmatesoft.svn.core.internal.io.svn.SVNRepositoryFactoryImpl;
import org.tmatesoft.svn.core.io.SVNRepository;
import org.tmatesoft.svn.core.io.SVNRepositoryFactory;
import org.tmatesoft.svn.core.wc.SVNWCUtil;

/**
 * @author zabdisubhan
 */

@Service
public class SvnServiceImpl implements SvnService {

    protected final SanitizedLogger log = new SanitizedLogger(SvnServiceImpl.class);

    @Autowired
    private ApplicationService applicationService;

    @Override
    public boolean testSvnConfiguration(Application application) throws SVNException {

        setupLibrary();

        SVNURL svnurl = SVNURL.parseURIEncoded(application.getRepositoryUrl());
        SVNRepository svnRepository = SVNRepositoryFactory.create(svnurl);

        if (application.getRepositoryUserName() != null && application.getRepositoryPassword() != null) {
            ISVNAuthenticationManager authManager = SVNWCUtil.createDefaultAuthenticationManager(
                    application.getRepositoryUserName(), application.getRepositoryPassword());
            svnRepository.setAuthenticationManager(authManager);
        }

        SVNNodeKind nodeKind = svnRepository.checkPath("", -1);

        // If node at repoUrl is anything besides a directory, return false
        if (nodeKind == SVNNodeKind.NONE) {
            log.error("There is no entry at '" + application.getRepositoryUrl() + "'.");
            return false;
        } else if (nodeKind == SVNNodeKind.FILE) {
            log.error("The entry at '" + application.getRepositoryUrl() + "' is a file while a directory was expected.");
            return false;
        } else if (nodeKind == SVNNodeKind.UNKNOWN) {
            log.error("The entry at '" + application.getRepositoryUrl() + "' is unknown while a directory was expected.");
            return false;
        }

        return true;
    }

    private static void setupLibrary() {
        /*
         * For using over http:// and https://
         */
        DAVRepositoryFactory.setup();
        /*
         * For using over svn:// and svn+xxx://
         */
        SVNRepositoryFactoryImpl.setup();

        /*
         * For using over file:///
         */
        FSRepositoryFactory.setup();
    }
}
