package com.denimgroup.threadfix.service.repository;

import java.io.File;
import java.io.IOException;

import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.api.errors.CanceledException;
import org.eclipse.jgit.api.errors.DetachedHeadException;
import org.eclipse.jgit.api.errors.GitAPIException;
import org.eclipse.jgit.api.errors.InvalidConfigurationException;
import org.eclipse.jgit.api.errors.InvalidRemoteException;
import org.eclipse.jgit.api.errors.NoHeadException;
import org.eclipse.jgit.api.errors.RefNotFoundException;
import org.eclipse.jgit.api.errors.TransportException;
import org.eclipse.jgit.api.errors.WrongRepositoryStateException;
import org.eclipse.jgit.errors.NoWorkTreeException;
import org.eclipse.jgit.lib.Repository;
import org.eclipse.jgit.storage.file.FileRepository;
import org.eclipse.jgit.storage.file.FileRepositoryBuilder;

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
			}
		}

		return null;
	}
	
}
