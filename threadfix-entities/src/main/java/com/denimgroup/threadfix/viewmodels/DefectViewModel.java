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
package com.denimgroup.threadfix.viewmodels;

import org.codehaus.jackson.map.ObjectMapper;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class DefectViewModel {

	private String id; //Used for merging defect
	private String summary;
	private String preamble;
	private String selectedComponent;
	private String version;
	private String severity;
	private String priority;
	private String status;
    private Boolean additionalScannerInfo;
    private Map<String, Object> fieldsMap;
    private String fieldsMapStr;
		
	public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
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

	private List<Integer> vulnerabilityIds;

	public String getSummary() {
		return summary;
	}

	public void setSummary(String summary) {
		this.summary = summary;
	}

	public String getPreamble() {
		return preamble;
	}

	public void setPreamble(String preamble) {
		this.preamble = preamble;
	}

	public String getSelectedComponent() {
		return selectedComponent;
	}

	public void setSelectedComponent(String selectedComponent) {
		this.selectedComponent = selectedComponent;
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

	public List<Integer> getVulnerabilityIds() {
		return vulnerabilityIds;
	}

	public void setVulnerabilityIds(List<Integer> vulnerabilityIds) {
		this.vulnerabilityIds = vulnerabilityIds;
	}

    public Map getFieldsMap() {
		if (fieldsMapStr == null) {
			return null;
		}

        try {
            return new ObjectMapper().readValue(fieldsMapStr, HashMap.class);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    public void setFieldsMap(Map<String, Object> fieldsMap) {
        this.fieldsMap = fieldsMap;
    }

    public String getFieldsMapStr() {
        return fieldsMapStr;
    }

    public void setFieldsMapStr(String fieldsMapStr) {
        this.fieldsMapStr = fieldsMapStr;
    }

    public Boolean getAdditionalScannerInfo(){
        return additionalScannerInfo;
    }

    public void setAdditionalScannerInfo(Boolean additionalScannerInfo) {
        this.additionalScannerInfo = additionalScannerInfo;
    }
}
