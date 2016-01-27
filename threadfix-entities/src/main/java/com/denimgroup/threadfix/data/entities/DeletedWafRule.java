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

import org.hibernate.validator.constraints.NotEmpty;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Table;
import javax.validation.constraints.Size;

@Entity
@Table(name = "DeletedWafRule")
public class DeletedWafRule extends BaseEntity {

	private static final long serialVersionUID = 968480666516980702L;

	public DeletedWafRule(WafRule wafRule) {
		if (wafRule != null) {
			setId(wafRule.getId());
			setRule(wafRule.getRule());
			setPath(wafRule.getPath());
			setParameter(wafRule.getParameter());
			setVulnerabilityDesc(wafRule.getVulnerabilityDesc());
			setNativeId(wafRule.getNativeId());
			
			if (wafRule.getWaf() != null){
				setWafId(wafRule.getWaf().getId());
			}

			if (wafRule.getVulnerability() != null) {
				setVulnerabilityId(wafRule.getVulnerability().getId());
			}
		}
	}

	@NotEmpty(message = "{errors.required}")
	@Size(max = WafRule.PATH_LENGTH, message = "{errors.maxlength} " + WafRule.PATH_LENGTH + ".")
	private String rule;
	
	@Size(max = WafRule.PARAMETER_LENGTH, message = "{errors.maxlength} " + WafRule.PARAMETER_LENGTH + ".")
	private String parameter;
	
	@Size(max = WafRule.PATH_LENGTH, message = "{errors.maxlength} " + WafRule.PATH_LENGTH + ".")
	private String path;
	
	@Size(max = 25, message = "{errors.maxlength} 25.")
	private String nativeId;
	private Integer wafId;
	private Integer vulnerabilityId;
	
	@Size(max = 1024, message = "{errors.maxlength} 1024")
	private String vulnerabilityDesc;

	@Column(length = WafRule.RULE_LENGTH)
	public String getRule() {
		return rule;
	}

	public void setRule(String rule) {
		this.rule = rule;
	}
	
	@Column(length = WafRule.PATH_LENGTH)
	public String getPath() {
		return path;
	}

	public void setPath(String path) {
		this.path = path;
	}
	
	@Column(length = WafRule.PARAMETER_LENGTH)
	public String getParameter() {
		return parameter;
	}

	public void setParameter(String parameter) {
		this.parameter = parameter;
	}

	@Column(length = 1024)
	public String getVulnerabilityDesc() {
		return vulnerabilityDesc;
	}

	public void setVulnerabilityDesc(String vulnerabilityDesc) {
		this.vulnerabilityDesc = vulnerabilityDesc;
	}

	@Column(length = 25)
	public String getNativeId() {
		return nativeId;
	}

	public void setNativeId(String nativeId) {
		this.nativeId = nativeId;
	}

	@Column
	public Integer getWafId() {
		return wafId;
	}

	public void setWafId(Integer wafId) {
		this.wafId = wafId;
	}

	@Column
	public Integer getVulnerabilityId() {
		return vulnerabilityId;
	}

	public void setVulnerabilityId(Integer vulnerabilityId) {
		this.vulnerabilityId = vulnerabilityId;
	}
}
