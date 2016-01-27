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
import org.eclipse.jgit.lib.Constants;
import org.eclipse.jgit.lib.Ref;
import org.eclipse.jgit.lib.Repository;
import org.eclipse.jgit.transport.CredentialsProvider;
import org.eclipse.jgit.transport.RefSpec;
import org.eclipse.jgit.transport.UsernamePasswordCredentialsProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.validation.BindingResult;

import java.io.File;
import java.io.IOException;
import java.util.List;

@Service
public class GitServiceImpl extends RepositoryServiceImpl implements RepositoryService {

    private static final SanitizedLogger log = new SanitizedLogger(GitServiceImpl.class);
    private static final String EXCEPTION_MESSAGE = "Failed to clone application from repository";

    @Autowired private ApplicationService applicationService;
    @Autowired private ExceptionLogService exceptionLogService;

    @Override
    public boolean testConfiguration(Application application) throws GitAPIException {
        return testConfiguration(application, application.getRepositoryUrl(), application.getRepositoryBranch());
    }

    @Override
    public boolean testConfiguration(Application application, String repo, String branch) throws GitAPIException {
        InitCommand initCommand = new InitCommand();
        File applicationDirectory = DiskUtils.getScratchFile(baseDirectory + application.getId() + "-test");
        initCommand.setDirectory(applicationDirectory);

        Git otherGit = initCommand.call();

        otherGit.getRepository().getConfig().setString("remote", "origin", "url", repo);

        String targetRefSpec =
                branch == null || branch.isEmpty()  ?
                        Constants.R_HEADS + "*:refs/remotes/origin/*" :
                        Constants.R_HEADS + branch;

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
                log.info("Got an error from the Git server, logging to database (visible under Error Messages)");
                exceptionLogService.storeExceptionLog(new ExceptionLog(e));
            }
        } else {
            log.info("Got an error, logging to database (visible under Error Messages)");
            exceptionLogService.storeExceptionLog(new ExceptionLog(e));
        }
    }

    @Override
	public File cloneRepoToDirectory(Application application, File dirLocation) {

        if (dirLocation.exists()) {
            File gitDirectoryFile = new File(dirLocation.getAbsolutePath() + File.separator + ".git");

            try {
				if (!gitDirectoryFile.exists()) {
                    Git newRepo = clone(application, dirLocation);
                    if (newRepo != null)
                        return newRepo.getRepository().getWorkTree();
				} else {
                    Repository localRepo = new FileRepository(gitDirectoryFile);
                    Git git = new Git(localRepo);


                    if (application.getRepositoryRevision() != null && !application.getRepositoryRevision().isEmpty()) {
                        //remote checkout
                        git.checkout()
                                .setCreateBranch(true)
                                .setStartPoint(application.getRepositoryRevision())
                                .setName(application.getRepositoryRevision())
                                .call();
                    } else {

                        List<Ref> refs = git.branchList().setListMode(ListBranchCommand.ListMode.ALL).call();

                        String repoBranch = (application.getRepositoryBranch() != null &&
                                !application.getRepositoryBranch().isEmpty()) ? application.getRepositoryBranch() : "master";

                        boolean localCheckout = false;

                        for (Ref ref : refs) {
                            String refName = ref.getName();
                            if (refName.contains(repoBranch) && !refName.contains(Constants.R_REMOTES)) {
                                localCheckout = true;
                            }
                        }

                        String HEAD = localRepo.getFullBranch();

                        if (HEAD.contains(repoBranch)) {
                            git.pull()
                                    .setRemote("origin")
                                    .setRemoteBranchName(repoBranch)
                                    .setCredentialsProvider(getApplicationCredentials(application))
                                    .call();
                        } else {
                            if (localCheckout) {
                                //local checkout
                                git.checkout()
                                        .setName(application.getRepositoryBranch())
                                        .call();
                                git.pull()
                                        .setRemote("origin")
                                        .setRemoteBranchName(repoBranch)
                                        .setCredentialsProvider(getApplicationCredentials(application))
                                        .call();
                            } else {
                                //remote checkout
                                git.checkout()
                                        .setCreateBranch(true)
                                        .setName(repoBranch)
                                        .setUpstreamMode(CreateBranchCommand.SetupUpstreamMode.SET_UPSTREAM)
                                        .setStartPoint("origin/" + repoBranch)
                                        .call();
                            }
                        }
                    }

					return git.getRepository().getWorkTree();
				}
			} catch (JGitInternalException          e) {
				log.error(EXCEPTION_MESSAGE, e);
			} catch (IOException                    e) {
				log.error(EXCEPTION_MESSAGE, e);
			} catch (WrongRepositoryStateException  e) {
                log.error(EXCEPTION_MESSAGE, e);
            } catch (InvalidConfigurationException  e) {
                log.error(EXCEPTION_MESSAGE, e);
            } catch (DetachedHeadException          e) {
                log.error(EXCEPTION_MESSAGE, e);
            } catch (InvalidRemoteException         e) {
                log.error(EXCEPTION_MESSAGE, e);
            } catch (CanceledException              e) {
                log.error(EXCEPTION_MESSAGE, e);
            } catch (RefNotFoundException           e) {
                log.error(EXCEPTION_MESSAGE, e);
            } catch (NoHeadException                e) {
                log.error(EXCEPTION_MESSAGE, e);
            } catch (RefAlreadyExistsException      e) {
                log.error(EXCEPTION_MESSAGE, e);
            } catch (CheckoutConflictException      e) {
                log.error(EXCEPTION_MESSAGE, e);
            } catch (InvalidRefNameException        e) {
                log.error(EXCEPTION_MESSAGE, e);
            } catch (TransportException             e) {
                log.error(EXCEPTION_MESSAGE, e);
            } catch (GitAPIException                e) {
                log.error(EXCEPTION_MESSAGE, e);
            }
		} else {
			try {
                log.info("Attempting to clone application from repository.");
                Git result = clone(application, dirLocation);
				if (result != null) {
                    log.info("Application was successfully cloned from repository.");
					return result.getRepository().getWorkTree();
				}
                log.error(EXCEPTION_MESSAGE);
			} catch (JGitInternalException e) {
                log.error(EXCEPTION_MESSAGE, e);
			}
		}
		return null;
	}

    private Git clone(Application application, File dirLocation) {
        Git git = null;
        try {
            CloneCommand clone = Git.cloneRepository();

            clone.setURI(application.getRepositoryUrl())
                    .setDirectory(dirLocation)
                    .setCredentialsProvider(getApplicationCredentials(application));

            if (application.getRepositoryBranch() != null
                    && !application.getRepositoryBranch().isEmpty()) {
                clone.setBranch(application.getRepositoryBranch());
            }

            // clone git repo
            git = clone.call();

            // checkout specific revision
            if (application.getRepositoryRevision() != null
                    && !application.getRepositoryRevision().isEmpty()) {
                git.checkout()
                        .setCreateBranch(true)
                        .setStartPoint(application.getRepositoryRevision())
                        .setName(application.getRepositoryRevision())
                        .call();
            }

        } catch (WrongRepositoryStateException  e) {
            log.error(EXCEPTION_MESSAGE, e);
        } catch (InvalidConfigurationException  e) {
            log.error(EXCEPTION_MESSAGE, e);
        } catch (DetachedHeadException          e) {
            log.error(EXCEPTION_MESSAGE, e);
        } catch (InvalidRemoteException         e) {
            log.error(EXCEPTION_MESSAGE, e);
        } catch (CanceledException              e) {
            log.error(EXCEPTION_MESSAGE, e);
        } catch (RefNotFoundException           e) {
            log.error(EXCEPTION_MESSAGE, e);
        } catch (NoHeadException                e) {
            log.error(EXCEPTION_MESSAGE, e);
        } catch (RefAlreadyExistsException      e) {
            log.error(EXCEPTION_MESSAGE, e);
        } catch (CheckoutConflictException      e) {
            log.error(EXCEPTION_MESSAGE, e);
        } catch (InvalidRefNameException        e) {
            log.error(EXCEPTION_MESSAGE, e);
        } catch (TransportException             e) {
            log.error(EXCEPTION_MESSAGE, e);
        } catch (GitAPIException                e) {
            log.error(EXCEPTION_MESSAGE, e);
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
