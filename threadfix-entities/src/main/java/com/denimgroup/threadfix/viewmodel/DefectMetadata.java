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

package com.denimgroup.threadfix.viewmodel;

import com.denimgroup.threadfix.logging.SanitizedLogger;

import java.util.Map;

/**
 * @author bbeverly
 * 
 */
public class DefectMetadata {
	
	protected static final SanitizedLogger log = new SanitizedLogger(DefectMetadata.class);

	private String description, preamble, component, version, severity, priority, status, fullDescription;

    private Map<String, Object> fieldsMap;

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

    public DefectMetadata(String description, String preamble, String component, String version,
                          String severity, String priority, String status, Map<String, Object> fieldsMap) {
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
        this.fieldsMap = fieldsMap;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getPreamble() {
        return preamble == null ? "" : preamble;
    }

    public void setPreamble(String preamble) {
        this.preamble = preamble;
    }

    public String getComponent() {
        return component;
    }

    public void setComponent(String component) {
        this.component = component;
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public String getPriority() {
        return priority;
    }

    public void setPriority(String priority) {
        this.priority = priority;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public Map<String, Object> getFieldsMap() {
        return fieldsMap;
    }

    public void setFieldsMap(Map<String, Object> fieldsMap) {
        this.fieldsMap = fieldsMap;
    }

    /**
     * @return the full generated description for the defect including vulnerability IDs and information
     */
    public String getFullDescription() {
        return fullDescription;
    }

    public void setFullDescription(String fullDescription) {
        this.fullDescription = fullDescription;
    }
}
