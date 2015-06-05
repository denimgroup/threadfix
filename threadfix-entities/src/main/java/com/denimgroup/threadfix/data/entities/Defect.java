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
package com.denimgroup.threadfix.data.entities;

import com.denimgroup.threadfix.views.AllViews;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonView;
import org.hibernate.annotations.Index;

import javax.persistence.*;
import javax.validation.constraints.Size;
import java.util.List;
import java.util.Set;

import static com.denimgroup.threadfix.CollectionUtils.set;

@Entity
@Table(name = "Defect")
public class Defect extends AuditableEntity {

    private static final long serialVersionUID = -3912326857875561633L;

    public static final int STATUS_LENGTH = 255;
    public static final int URL_LENGTH    = 255;

    // TODO make this smarter
    public final static Set<String> OPEN_CODES   = set("Active", "Open", "New", "CONFIRMED", "IN_PROGRESS", "Reopen", "Future", "In Progress", "Accepted");
    public final static Set<String> CLOSED_CODES = set("Closed", "Resolved", "RESOLVED", "VERIFIED", "Fixed", "Done");

    public enum TrackerType {
        BUGZILLA, JIRA
    }

    private String nativeId;

    private Application         application;
    private List<Vulnerability> vulnerabilities;

    @Size(max = STATUS_LENGTH, message = "{errors.maxlength} " + STATUS_LENGTH + ".")
    private String status;

    @Size(max = URL_LENGTH, message = "{errors.maxlength} " + URL_LENGTH + ".")
    private String defectURL;

    /**
     * Stores the ID used by the defect tracking system.
     *
     * @return
     */
    @Column(length = 50, nullable = false)
    @JsonView({AllViews.TableRow.class, AllViews.VulnSearch.class, AllViews.VulnerabilityDetail.class})
    public String getNativeId() {
        return nativeId;
    }

    public void setNativeId(String nativeId) {
        this.nativeId = nativeId;
    }

    @Column(length = 255, nullable = false)
    @JsonView({AllViews.TableRow.class, AllViews.VulnSearch.class, AllViews.VulnerabilityDetail.class})
    @Index(name="status")
    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        if (status != null) {
            if (status.length() > STATUS_LENGTH) {
                this.status = status.substring(0, STATUS_LENGTH - 2);
            } else {
                this.status = status;
            }
        }
    }

    @Column(length = 255)
    @JsonView({AllViews.TableRow.class, AllViews.VulnSearch.class, AllViews.VulnerabilityDetail.class})
    public String getDefectURL() {
        return defectURL;
    }

    public void setDefectURL(String defectURL) {
        if (defectURL != null && defectURL.length() > STATUS_LENGTH) {
            this.defectURL = defectURL.substring(0, STATUS_LENGTH - 2);
        } else {
            this.defectURL = defectURL;
        }
    }

    @ManyToOne
    @JoinColumn(name = "applicationId")
    @JsonIgnore
	public Application getApplication() {
		return application;
	}

	public void setApplication(Application application) {
		this.application = application;
	}

	@OneToMany(mappedBy = "defect")
    @JsonIgnore
    public List<Vulnerability> getVulnerabilities() {
		return vulnerabilities;
	}

	public void setVulnerabilities(List<Vulnerability> vulnerabilities) {
		this.vulnerabilities = vulnerabilities;
	}

    @Transient
    @JsonView({AllViews.TableRow.class, AllViews.VulnSearch.class, AllViews.VulnerabilityDetail.class})
    private boolean isOpened() {
        if (CLOSED_CODES.contains(status)) return false;
        else return true;
    }

}
