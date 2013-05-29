package com.denimgroup.threadfix.service.repository;

import java.io.File;

import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.api.errors.GitAPIException;
import org.eclipse.jgit.lib.Repository;

public class GitService {
	
	private GitService() {
		// intentionally inaccessible
	}
	
	// Cursory testing indicates that this works.
	public static Repository cloneGitTreeToDirectory(String gitUrl, File fileLocation) {
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
		
		return null;
	}
	
}
