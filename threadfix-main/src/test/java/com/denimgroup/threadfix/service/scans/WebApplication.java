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

package com.denimgroup.threadfix.service.scans;

import java.io.File;
import java.net.URL;

public enum WebApplication {
	
	WAVSEP("wavsep", "http://satgit2.denimgroup.com/sbir/wavsep.git"), 
	BODGEIT("bodgeit", "http://satgit2.denimgroup.com/sbir/bodgeit.git"), 
	PETCLINIC("petclinic", "http://satgit2.denimgroup.com/sbir/petclinic.git");
	
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
