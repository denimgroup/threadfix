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
import java.util.List;

@Entity
@Table(name = "WafRuleDirective")
public class WafRuleDirective extends BaseEntity {

	private static final long serialVersionUID = 4853103123698810781L;

	@NotEmpty(message = "{errors.required}")
	@Size(max = 256, message = "{errors.maxlength}")
	private String directive;
	
	private WafType wafType;
	private List<WafRule> wafRules;
	
	@Column(length = 256)
    @JsonView(AllViews.TableRow.class)
	public String getDirective() {
		return directive;
	}

	public void setDirective(String directive) {
		this.directive = directive;
	}

	@ManyToOne
	@JoinColumn(name = "wafTypeId")
	@JsonIgnore
	public WafType getWafType() {
		return wafType;
	}

	public void setWafType(WafType wafType) {
		this.wafType = wafType;
	}
	
	@OneToMany(mappedBy = "wafRuleDirective", cascade = CascadeType.ALL)
	@JsonIgnore
	public List<WafRule> getWafRules() {
		return wafRules;
	}

	public void setWafRules(List<WafRule> wafRules) {
		this.wafRules = wafRules;
	}
}
