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
import com.denimgroup.threadfix.service.ApplicationService;
import com.denimgroup.threadfix.service.GitService;
import org.eclipse.jgit.api.*;
import org.eclipse.jgit.api.errors.*;
import org.eclipse.jgit.internal.storage.file.FileRepository;
import org.eclipse.jgit.lib.Repository;
import org.eclipse.jgit.transport.CredentialsProvider;
import org.eclipse.jgit.transport.RefSpec;
import org.eclipse.jgit.transport.UsernamePasswordCredentialsProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.IOException;

@Service
public class GitServiceImpl extends RepositoryServiceImpl implements GitService {

    private static final SanitizedLogger LOG = new SanitizedLogger(GitServiceImpl.class);

    @Autowired private ApplicationService applicationService;

    @Override
    public boolean testConfiguration(Application application) throws GitAPIException {
        InitCommand initCommand = new InitCommand();
        File applicationDirectory = DiskUtils.getScratchFile(baseDirectory + application.getId() + "-test");
        initCommand.setDirectory(applicationDirectory);

        Git otherGit = initCommand.call();

        otherGit.getRepository().getConfig().setString("remote", "origin", "url", application.getRepositoryUrl());

        String targetRefSpec =
                application.getRepositoryBranch() == null ?
                        "fakebranch" :
                        application.getRepositoryBranch();

        FetchCommand fetchCommand = otherGit.fetch()
                .setCredentialsProvider(getUnencryptedApplicationCredentials(application))
                .setDryRun(true)
                .setRefSpecs(new RefSpec(targetRefSpec))
                .setRemote("origin");

        fetchCommand.call();

        return true;
    }

    @Override
	public File cloneRepoToDirectory(Application application, File dirLocation) {

		if (dirLocation.exists()) {
			try {
				File gitDirectoryFile = new File(dirLocation.getAbsolutePath() + File.separator + ".git");
				if (!gitDirectoryFile.exists()) {
                    Git newRepo = clone(application, dirLocation);
                    if (newRepo != null)
                        return newRepo.getRepository().getWorkTree();
				} else {
                    Repository localRepo = new FileRepository(gitDirectoryFile);
                    Git git = new Git(localRepo);
//                    // Fetch repository if user asked for new revision/branch
//                    if (application.getRepositoryBranch() != null
//                            && !application.equals(application.getRepositoryDBBranch())) {
//                        application.setRepositoryDBBranch(application.getRepositoryBranch());
//                            git = fetch(application, git);
//                    }
					return git.getRepository().getWorkTree();
				}
			} catch (JGitInternalException e) {
				LOG.error("Exception", e);
			} catch (IOException e) {
				LOG.error("Exception", e);
			}
		} else {
			try {
                LOG.info("Attempting to clone application from repository.");
                Git result = clone(application, dirLocation);
				if (result != null) {
                    LOG.info("Application was successfully cloned from repository.");
					return result.getRepository().getWorkTree();
				}
                LOG.error("Failed to clone application from repository.");
			} catch (JGitInternalException e) {
				e.printStackTrace();
                LOG.error("Failed to clone application from repository.", e);
			}
		}
		return null;
	}

    private Git clone(Application application, File dirLocation) {
        Git git = null;
        try {
            CloneCommand clone = Git.cloneRepository();
            clone.setURI(application.getRepositoryUrl())
                    .setDirectory(dirLocation);

            clone.setCredentialsProvider(getApplicationCredentials(application));

            if (application.getRepositoryBranch() != null) {
                application.setRepositoryDBBranch(application.getRepositoryBranch());
                clone.call()
                        .checkout()
                        .setCreateBranch(true)
                        .setName(application.getRepositoryBranch())
                        .setUpstreamMode(CreateBranchCommand.SetupUpstreamMode.TRACK)
                        .setStartPoint(application.getRepositoryBranch()).call();
            } else {
                git = clone.call();
            }
        } catch (WrongRepositoryStateException  e) {
            e.printStackTrace();
        } catch (InvalidConfigurationException  e) {
            e.printStackTrace();
        } catch (DetachedHeadException          e) {
            e.printStackTrace();
        } catch (InvalidRemoteException         e) {
            e.printStackTrace();
        } catch (CanceledException              e) {
            e.printStackTrace();
        } catch (RefNotFoundException           e) {
            e.printStackTrace();
        } catch (NoHeadException                e) {
            e.printStackTrace();
        } catch (RefAlreadyExistsException      e) {
            e.printStackTrace();
        } catch (CheckoutConflictException      e) {
            e.printStackTrace();
        } catch (InvalidRefNameException        e) {
            e.printStackTrace();
        } catch (TransportException             e) {
            e.printStackTrace();
        } catch (GitAPIException                e) {
            e.printStackTrace();
        }

        return git;
    }

    private UsernamePasswordCredentialsProvider getApplicationCredentials(Application application) {
        if (application.getRepositoryEncryptedUserName() != null
                && application.getRepositoryEncryptedPassword() != null) {
            applicationService.decryptRepositoryCredentials(application);
            return new UsernamePasswordCredentialsProvider(application.getRepositoryUserName(),
                    application.getRepositoryPassword());
        }
        return null;
    }

    private CredentialsProvider getUnencryptedApplicationCredentials(Application application) {
        if (application.getRepositoryUserName() != null
                && application.getRepositoryPassword() != null) {
            return new UsernamePasswordCredentialsProvider(application.getRepositoryUserName(),
                    application.getRepositoryPassword());
        }

        return null;
    }

}
