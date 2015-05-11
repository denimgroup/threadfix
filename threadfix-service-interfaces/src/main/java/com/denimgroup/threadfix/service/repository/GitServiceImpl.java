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
import org.eclipse.jgit.api.*;
import org.eclipse.jgit.api.errors.*;
import org.eclipse.jgit.internal.storage.file.FileRepository;
import org.eclipse.jgit.lib.Repository;
import org.eclipse.jgit.transport.CredentialsProvider;
import org.eclipse.jgit.transport.RefSpec;
import org.eclipse.jgit.transport.UsernamePasswordCredentialsProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.validation.BindingResult;

import java.io.File;
import java.io.IOException;

@Service
public class GitServiceImpl extends RepositoryServiceImpl implements RepositoryService {

    private static final SanitizedLogger log = new SanitizedLogger(GitServiceImpl.class);

    @Autowired private ApplicationService applicationService;
    @Autowired private ExceptionLogService exceptionLogService;

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
    public void handleException(Exception e, Application application, BindingResult result) {
        if (e instanceof GitAPIException || e instanceof JGitInternalException) {

            boolean shouldLog = true;

            if (e instanceof JGitInternalException) {
                result.rejectValue("repositoryUrl", null, null, "Unable to connect to this URL.");
            }

            if (e.getMessage().contains("not authorized")) {
                result.rejectValue("repositoryUrl", null, null, "Authorization failed.");
            }

            if (application.getRepositoryBranch() != null) {
                String missingBranchError = "Remote does not have " + application.getRepositoryBranch() + " available for fetch";
                if (e.getMessage().contains(missingBranchError)) {
                    result.rejectValue("repositoryUrl", null, null, "Supplied branch wasn't found.");
                }
            } else if (e.getMessage().contains("Remote does not have fakebranch available for fetch")) {
                // this is expected behavior, let's not return an error.
                shouldLog = false;
            } else {
                result.rejectValue("repositoryUrl", null, null, "Unable to clone repository");
            }

            if (shouldLog) {
                log.info("Got an error from the Git server, logging to database (visible under View Error Messages)");
                exceptionLogService.storeExceptionLog(new ExceptionLog(e));
            }
        } else {
            log.info("Got an error, logging to database (visible under View Error Messages)");
            exceptionLogService.storeExceptionLog(new ExceptionLog(e));
        }
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
				log.error("Exception", e);
			} catch (IOException e) {
				log.error("Exception", e);
			}
		} else {
			try {
                log.info("Attempting to clone application from repository.");
                Git result = clone(application, dirLocation);
				if (result != null) {
                    log.info("Application was successfully cloned from repository.");
					return result.getRepository().getWorkTree();
				}
                log.error("Failed to clone application from repository.");
			} catch (JGitInternalException e) {
				e.printStackTrace();
                log.error("Failed to clone application from repository.", e);
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
