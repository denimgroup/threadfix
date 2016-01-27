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

import com.denimgroup.threadfix.views.AllViews;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonView;
import org.hibernate.validator.constraints.NotEmpty;

import javax.persistence.*;
import javax.validation.constraints.Size;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Entity
@Table(name = "ApplicationCriticality")
public class ApplicationCriticality extends BaseEntity {

	private static final long serialVersionUID = 8187838774235832281L;
	
	public static final String LOW = "Low";
	public static final String MEDIUM = "Medium";
	public static final String HIGH = "High";
	public static final String CRITICAL = "Critical";
	
	public static final Map<String, Integer> NUMERIC_MAP = new HashMap<String, Integer>();
	static {
		NUMERIC_MAP.put(LOW, 0);
		NUMERIC_MAP.put(MEDIUM, 1);
		NUMERIC_MAP.put(HIGH, 2);
		NUMERIC_MAP.put(CRITICAL, 3);
	}

	@NotEmpty(message = "{errors.required}")
	@Size(max = 50, message = "{errors.maxlength}")
    @JsonView({ AllViews.TableRow.class, AllViews.FormInfo.class})
    private String name;

	private List<Application> applications;

    @JsonView(Object.class)
	@Column(length = 50, nullable = false)
	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	@OneToMany(mappedBy = "applicationCriticality", cascade = CascadeType.ALL)
	@JsonIgnore
	public List<Application> getApplications() {
		return applications;
	}

	public void setApplications(List<Application> applications) {
		this.applications = applications;
	}
}
