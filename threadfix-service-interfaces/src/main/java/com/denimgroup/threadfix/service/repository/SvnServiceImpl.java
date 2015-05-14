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
import com.denimgroup.threadfix.data.entities.ExceptionLog;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.ApplicationService;
import com.denimgroup.threadfix.service.ExceptionLogService;
import com.denimgroup.threadfix.service.RepositoryService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.validation.BindingResult;
import org.tmatesoft.svn.core.SVNDepth;
import org.tmatesoft.svn.core.SVNException;
import org.tmatesoft.svn.core.SVNNodeKind;
import org.tmatesoft.svn.core.SVNURL;
import org.tmatesoft.svn.core.auth.ISVNAuthenticationManager;
import org.tmatesoft.svn.core.internal.io.dav.DAVRepositoryFactory;
import org.tmatesoft.svn.core.internal.io.fs.FSRepositoryFactory;
import org.tmatesoft.svn.core.internal.io.svn.SVNRepositoryFactoryImpl;
import org.tmatesoft.svn.core.io.SVNRepository;
import org.tmatesoft.svn.core.io.SVNRepositoryFactory;
import org.tmatesoft.svn.core.wc.SVNClientManager;
import org.tmatesoft.svn.core.wc.SVNRevision;
import org.tmatesoft.svn.core.wc.SVNUpdateClient;
import org.tmatesoft.svn.core.wc.SVNWCUtil;

import java.io.File;

/**
 * @author zabdisubhan
 */

@Service
public class SvnServiceImpl extends RepositoryServiceImpl implements RepositoryService {

    protected final SanitizedLogger log = new SanitizedLogger(RepositoryServiceImpl.class);

    @Autowired private ApplicationService applicationService;
    @Autowired private ExceptionLogService exceptionLogService;

    @Override
    public boolean testConfiguration(Application application) throws SVNException {

        applicationService.decryptRepositoryCredentials(application);

        setupLibrary();

        SVNURL svnurl = SVNURL.parseURIEncoded(application.getSvnRepositoryUrl());
        SVNRepository svnRepository = SVNRepositoryFactory.create(svnurl);

        if (application.getRepositoryUserName() != null && application.getRepositoryPassword() != null) {
            ISVNAuthenticationManager authManager = SVNWCUtil.createDefaultAuthenticationManager(
                    application.getRepositoryUserName(), application.getRepositoryPassword());
            svnRepository.setAuthenticationManager(authManager);
        }

        SVNNodeKind nodeKind = svnRepository.checkPath("", -1);

        // If node at repoUrl is anything besides a directory, return false
        if (nodeKind == SVNNodeKind.NONE) {
            log.error("There is no entry at '" + application.getSvnRepositoryUrl() + "'.");
            return false;
        } else if (nodeKind == SVNNodeKind.FILE) {
            log.error("The entry at '" + application.getSvnRepositoryUrl() + "' is a file while a directory was expected.");
            return false;
        } else if (nodeKind == SVNNodeKind.UNKNOWN) {
            log.error("The entry at '" + application.getSvnRepositoryUrl() + "' is unknown while a directory was expected.");
            return false;
        }

        return true;
    }

    @Override
    public void handleException(Exception e, Application application, BindingResult result) {

        if (e instanceof SVNException) {
            if (e.getMessage().contains("Authentication required for")) {
                result.rejectValue("repositoryUrl", null, null, "Authorization failed.");
            }

            log.info("Got an error from the SVN server, logging to database (visible under View Error Messages)");
            exceptionLogService.storeExceptionLog(new ExceptionLog(e));
        } else {
            log.info("Got an error, logging to database (visible under View Error Messages)");
            exceptionLogService.storeExceptionLog(new ExceptionLog(e));
        }
    }

    @Override
    public File cloneRepoToDirectory(Application application, File dirLocation) {

        if (!dirLocation.exists()) {
            if (dirLocation.mkdir()) {
                log.info("Created directory location at: " + dirLocation);
            } else {
                log.error("Failed to create directory at: " + dirLocation);
                return null;
            }
        }
        try {
            SVNURL svnurl = SVNURL.parseURIEncoded(application.getSvnRepositoryUrl());
            SVNRepository svnRepository = SVNRepositoryFactory.create(svnurl);
            SVNRevision svnRevision = SVNRevision.HEAD;

            applicationService.decryptRepositoryCredentials(application);

            if (application.getRepositoryUserName() != null && application.getRepositoryPassword() != null) {
                ISVNAuthenticationManager authManager = SVNWCUtil.createDefaultAuthenticationManager(
                        application.getRepositoryUserName(), application.getRepositoryPassword());
                svnRepository.setAuthenticationManager(authManager);
            }

            if (application.getRepositoryRevision() != null && !application.getRepositoryRevision().isEmpty()) {
                try {
                    Long svnRevisionNum = Long.parseLong(application.getRepositoryRevision());
                    if (svnRevisionNum > 0)
                        svnRevision = SVNRevision.create(svnRevisionNum);
                } catch (NumberFormatException e) {
                    log.error("Revision value provided was not a valid number.");
                }
            }

            log.info("Attempting to clone application from repository.");
            long revision = checkout(svnurl, svnRepository, svnRevision, dirLocation);
            if (revision > 0) {
                log.info("Application was successfully cloned from repository.");
            } else {
                log.error("Failed to clone application from repository.");
            }
        } catch (SVNException e) {
            log.error("Failed to clone application from repository.", e);
        }

        return dirLocation;
    }

    private long checkout(SVNURL svnurl, SVNRepository svnRepository, SVNRevision svnRevision, File destPath) throws SVNException {

        SVNClientManager clientManager = SVNClientManager.newInstance(null,
                svnRepository.getAuthenticationManager());
        SVNUpdateClient updateClient = clientManager.getUpdateClient();
        updateClient.setIgnoreExternals(false);

        /*
         * returns the number of the revision at which the working copy is
         */
        return updateClient.doCheckout(svnurl, destPath, svnRevision, svnRevision,
                SVNDepth.getInfinityOrEmptyDepth(true), false);
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
