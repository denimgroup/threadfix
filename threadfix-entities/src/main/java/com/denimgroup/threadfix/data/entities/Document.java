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
package com.denimgroup.threadfix.data.entities;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonView;

import javax.persistence.*;
import javax.validation.constraints.Size;
import java.sql.Blob;
import java.util.Date;

@Entity
@Table(name = "Document")
public class Document extends AuditableEntity {

	private static final long serialVersionUID = -4412241568719564078L;
	public static final int MAX_LENGTH_NAME = 256;
	@Size(max = MAX_LENGTH_NAME, message = "{errors.maxlength} 256.")
	private String name;
	
	private Vulnerability vulnerability;
	
	private Application application;
	
	@Size(max = 10, message = "{errors.maxlength} 10.")
	private String type;
	
	@Size(max = 255, message = "{errors.maxlength} 255.")
	private String contentType;
	
	private Blob file;

	@Column(length = 50, nullable = false)
    @JsonView(Object.class)
    public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

    @Transient
    @JsonView(Object.class)
    public Date getUploadedDate() {
        return super.getCreatedDate();
    }

    @ManyToOne
	@JoinColumn(name = "vulnerabilityId")
	@JsonIgnore
	public Vulnerability getVulnerability() {
		return vulnerability;
	}

	public void setVulnerability(Vulnerability vulnerability) {
		this.vulnerability = vulnerability;
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

	@Column(length = 10, nullable = true)
    @JsonView(Object.class)
    public String getType() {
		return type;
	}

	public void setType(String type) {
		this.type = type;
	}

	@Column(length = 255)
    @JsonView(Object.class)
    public String getContentType() {
		return contentType;
	}

	public void setContentType(String contentType) {
		this.contentType = contentType;
	}

    @JsonIgnore
	public Blob getFile() {
		return file;
	}

	public void setFile(Blob file) {
		this.file = file;
	}

}
