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
package com.denimgroup.threadfix.data.entities;

import com.denimgroup.threadfix.views.AllViews;
import org.codehaus.jackson.annotate.JsonIgnore;
import org.codehaus.jackson.annotate.JsonProperty;
import org.codehaus.jackson.map.annotate.JsonView;
import org.hibernate.validator.constraints.NotEmpty;

import javax.persistence.*;
import javax.validation.constraints.Size;
import java.util.ArrayList;
import java.util.List;

import static com.denimgroup.threadfix.CollectionUtils.list;

@Entity
@Table(name = "Waf")
public class Waf extends AuditableEntity {

	private static final long serialVersionUID = 2937339816996157154L;

	public static final int NAME_LENGTH = 50;
	
	@NotEmpty(message = "{errors.required}")
	@Size(max = NAME_LENGTH, message = "{errors.maxlength} " + NAME_LENGTH + ".")
	private String name;
	private WafType wafType;
	private Integer currentId;
	private WafRuleDirective lastWafRuleDirective;

	private List<Application> applicationList;
	private List<WafRule> wafRuleList;
	
	boolean canDelete = false;

	@Column(length = NAME_LENGTH, nullable = false)
    @JsonView(Object.class) // This means it will be included in all ObjectWriters with Views.
	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}
	
	@Column
	public Integer getCurrentId() {
		return currentId;
	}

	public void setCurrentId(Integer currentId) {
		this.currentId = currentId;
	}

	@ManyToOne
	@JoinColumn(name = "wafTypeId")
	public WafType getWafType() {
		return wafType;
	}

	public void setWafType(WafType wafType) {
		this.wafType = wafType;
	}

    @Transient
    @JsonView(AllViews.RestView2_1.class)
    private String getWafTypeName() {
        return getWafType() == null ? null : getWafType().getName();
    }

	@ManyToOne
	@JoinColumn(name = "wafRuleDirectiveId")
	public WafRuleDirective getLastWafRuleDirective() {
		return lastWafRuleDirective;
	}

	public void setLastWafRuleDirective(WafRuleDirective lastWafRuleDirective) {
		this.lastWafRuleDirective = lastWafRuleDirective;
	}

	@OneToMany(mappedBy = "waf")
    @JsonIgnore
	public List<Application> getApplications() {
        return applicationList;
	}

    @JsonView(AllViews.RestViewWaf2_1.class)
    @Transient
    @JsonProperty("applications")
    public List<Application> getActiveApplications() {
        List<Application> list = list();

        if (applicationList != null) {
            for (Application application : applicationList) {
                if (application.isActive()) {
                    list.add(application);
                }
            }
        }

        return list;
    }

	public void setApplications(List<Application> applicationList) {
		this.applicationList = applicationList;
	}

	@OneToMany(mappedBy = "waf")
	public List<WafRule> getWafRules() {
		return wafRuleList;
	}

	public void setWafRules(List<WafRule> wafRuleList) {
		this.wafRuleList = wafRuleList;
	}
	
	@Transient
	public boolean getCanDelete() {
		boolean hasActiveApplication = false;
		if (getApplications() != null) {
			for (Application application : getApplications()) {
				if (application.isActive()) {
					hasActiveApplication = true;
					break;
				}
			}
		}
		return !hasActiveApplication;
	}

    public void addWafRules(List<WafRule> wafRuleList) {
        if (getWafRules()==null)
            setWafRules(new ArrayList<WafRule>());
        for (WafRule rule: wafRuleList) {
            if (!getWafRules().contains(rule))
                getWafRules().add(rule);
        }
    }

}
