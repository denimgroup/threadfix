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
package com.denimgroup.threadfix.service.repository;

import java.io.File;
import java.io.IOException;

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.framework.engine.ProjectConfig;
import org.codehaus.jackson.annotate.JsonIgnore;
import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.api.errors.CanceledException;
import org.eclipse.jgit.api.errors.DetachedHeadException;
import org.eclipse.jgit.api.errors.GitAPIException;
import org.eclipse.jgit.api.errors.InvalidConfigurationException;
import org.eclipse.jgit.api.errors.InvalidRemoteException;
import org.eclipse.jgit.api.errors.JGitInternalException;
import org.eclipse.jgit.api.errors.NoHeadException;
import org.eclipse.jgit.api.errors.RefNotFoundException;
import org.eclipse.jgit.api.errors.TransportException;
import org.eclipse.jgit.api.errors.WrongRepositoryStateException;
import org.eclipse.jgit.errors.NoWorkTreeException;
import org.eclipse.jgit.lib.Repository;
import org.eclipse.jgit.storage.file.FileRepository;
import org.eclipse.jgit.storage.file.FileRepositoryBuilder;

import javax.persistence.Transient;

public class GitService {
	
	private GitService() {
		// intentionally inaccessible
	}
	
	public static void main(String[] args) throws NoWorkTreeException, IOException {
		File test = new File("C:\\test\\scratch\\13\\.git");
		
		new FileRepositoryBuilder().setGitDir(test).build().getWorkTree();
		
//		new FileRepository(test).getWorkTree();
	}
	
	// Cursory testing indicates that this works.
	public static Repository cloneGitTreeToDirectory(String gitUrl, File fileLocation) {
		
		if (fileLocation.exists()) {
			try {
				
				File gitDirectoryFile = new File(fileLocation.getAbsolutePath() + File.separator + ".git");
				
				if (!gitDirectoryFile.exists()) {
					
					Git newRepo = Git.cloneRepository()
						.setURI(gitUrl)
						.setDirectory(fileLocation)
						.call();
					
					return newRepo.getRepository();
				} else {
					// for now let's not try to pull
					Repository localRepo = new FileRepository(gitDirectoryFile);
					Git git = new Git(localRepo);
					
//					if (localRepo.getRepositoryState() == RepositoryState.SAFE) {
//						git.pull().call();
//					}
					return git.getRepository();
				}
			} catch (IOException e) {
				e.printStackTrace();
			} catch (WrongRepositoryStateException e) {
				e.printStackTrace();
			} catch (InvalidConfigurationException e) {
				e.printStackTrace();
			} catch (DetachedHeadException e) {
				e.printStackTrace();
			} catch (InvalidRemoteException e) {
				e.printStackTrace();
			} catch (CanceledException e) {
				e.printStackTrace();
			} catch (RefNotFoundException e) {
				e.printStackTrace();
			} catch (NoHeadException e) {
				e.printStackTrace();
			} catch (TransportException e) {
				e.printStackTrace();
			} catch (GitAPIException e) {
				e.printStackTrace();
			} catch (JGitInternalException e) {
				e.printStackTrace();
			}
		} else {
			try {
				Git result = Git.cloneRepository()
					.setURI(gitUrl)
					.setDirectory(fileLocation)
					.call();
				
				if (result != null) {
					return result.getRepository();
				}
			} catch (GitAPIException e) {
				e.printStackTrace();
			} catch (JGitInternalException e) {
				e.printStackTrace();
			}
		}

		return null;
	}

    // TODO move this somewhere central
    private static final String baseDirectory = "scratch/";

    // TODO move to some sort of repository manager instead of tying to the Git implementation.
    public static File getWorkTree(Application application) {

        File applicationDirectory = new File(baseDirectory + application.getId());

        if (application.getRepositoryUrl() != null && !application.getRepositoryUrl().trim().isEmpty()) {
            Repository repo = GitService.cloneGitTreeToDirectory(application.getRepositoryUrl(), applicationDirectory);

            if (repo != null && repo.getWorkTree() != null && repo.getWorkTree().exists()) {
                return repo.getWorkTree();
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
