package com.denimgroup.threadfix.service.scans;

import java.io.File;
import java.net.URL;

public enum WebApplication {
	WAVSEP("wavsep", "http://satgit2.denimgroup.com/sbir/wavsep.git"), 
	BODGEIT("bodgeit", null), 
	PETCLINIC("petclinic", null);
	
	WebApplication(String name, String url) { 
		this.name = name; 
		this.url = url;
	}
	
	private String name, url;
	
	public String getName() { 
		return name; 
	}
	
	public String getUrl() {
		return url;
	}
	
	public File getMergeCsvFile() {
		return getResource("/SBIR/" + name + "-merge.csv");
	}
	
	public String getFPRPath() {
		return getResource("/SBIR/" + name + ".fpr").getAbsolutePath();
	}
	
	public String getAppscanXMLPath() {
		return getResource("/SBIR/" + name + ".xml").getAbsolutePath();
	}
	
	public File getResource(String path) {
		URL url = this.getClass().getResource(path);
		return new File(url.getFile());
	}
}
