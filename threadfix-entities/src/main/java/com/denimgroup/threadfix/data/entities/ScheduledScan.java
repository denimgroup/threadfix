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

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonView;
import org.hibernate.validator.constraints.URL;

import javax.persistence.*;
import javax.validation.constraints.Size;

@Entity
@Table(name="ScheduledScan")
public class ScheduledScan extends ScheduledJob {

    private static final long serialVersionUID = 3165699013829091108L;

	private Application application;
    private String scanner;
    private Document scanConfig;
    private String targetUrl;

	@ManyToOne
	@JoinColumn(name = "applicationId")
	@JsonIgnore
	public Application getApplication() {
		return this.application;
    }
	
	public void setApplication(Application application) {
		this.application = application;
	}

    @Column(nullable=false)
    @JsonView(Object.class)
    public String getScanner() {
        return scanner;
    }

    public void setScanner(String scanner) {
        this.scanner = scanner;
    }

    @ManyToOne
    @JsonView(Object.class)
    public Document getScanConfig() {
        return scanConfig;
    }

    public void setScanConfig(Document scanConfig) {
        this.scanConfig = scanConfig;
    }

    @URL(message = "{errors.url}")
    @Size(min = 0, max = 255, message = "{errors.maxlength} " + 255 + ".")
    @JsonView(Object.class)
    public String getTargetUrl() {
        return (targetUrl == null || targetUrl.isEmpty()) && getApplication() != null ? getApplication().getUrl() : targetUrl;
    }

    public void setTargetUrl(String targetUrl) {
        this.targetUrl = targetUrl;
    }
}
