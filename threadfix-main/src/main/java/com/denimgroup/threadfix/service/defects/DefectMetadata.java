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

package com.denimgroup.threadfix.service.defects;

import com.denimgroup.threadfix.logging.SanitizedLogger;

/**
 * @author bbeverly
 * 
 */
public class DefectMetadata {
	
	protected final SanitizedLogger log = new SanitizedLogger(this.getClass());

	private String description;
	private String preamble;
	private String component;
	private String version;
	private String severity;
	private String priority;
	private String status;

	/**
	 * @param description
	 * @param preamble
	 */
	public DefectMetadata(String description, String preamble, String component, String version,
			String severity, String priority, String status) {
		if (description == null) {
			log.warn("Description should never be null");
		}

		this.description = description;
		this.preamble = preamble;
		this.component = component;
		this.version = version;
		this.severity = severity;
		this.priority = priority;
		this.status = status;
	}

	/**
	 * @return
	 */
	public String getDescription() {
		return description;
	}

	/**
	 * @return
	 */
	public String getPreamble() {
		if (this.preamble != null) {
			return this.preamble;
		} else {
			return "";
		}
	}

	public String getComponent() {
		return component;
	}

	public String getVersion() {
		return version;
	}

	public String getSeverity() {
		return severity;
	}
	
	public String getStatus() {
		return status;
	}
	
	public String getPriority() {
		return priority;
	}
}
