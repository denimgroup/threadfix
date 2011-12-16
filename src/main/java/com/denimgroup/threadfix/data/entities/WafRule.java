////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2011 Denim Group, Ltd.
//
//     The contents of this file are subject to the Mozilla Public License
//     Version 1.1 (the "License"); you may not use this file except in
//     compliance with the License. You may obtain a copy of the License at
//     http://www.mozilla.org/MPL/
//
//     Software distributed under the License is distributed on an "AS IS"
//     basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//     License for the specific language governing rights and limitations
//     under the License.
//
//     The Original Code is Vulnerability Manager.
//
//     The Initial Developer of the Original Code is Denim Group, Ltd.
//     Portions created by Denim Group, Ltd. are Copyright (C)
//     Denim Group, Ltd. All Rights Reserved.
//
//     Contributor(s): Denim Group, Ltd.
//
////////////////////////////////////////////////////////////////////////
package com.denimgroup.threadfix.data.entities;

import java.util.List;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.OneToMany;
import javax.persistence.Table;
import javax.validation.constraints.Size;

import org.hibernate.validator.constraints.NotEmpty;

@Entity
@Table(name = "WafRule")
public class WafRule extends BaseEntity {

	private static final long serialVersionUID = 1723103296983210781L;

	@NotEmpty(message = "{errors.required}")
	@Size(max = 1024, message = "{errors.maxlength} 1024.")
	private String rule;
	
	@Size(max = 25, message = "{errors.maxlength} 25.")
	private String nativeId;
	private Waf waf;
	private Vulnerability vulnerability;
	
	@Size(max = 1024, message = "{errors.maxlength} 1024")
	private String vulnerabilityDesc;
	private WafRuleDirective wafRuleDirective;
	
	private List<SecurityEvent> securityEvents;

	@Column(length = 1024)
	public String getRule() {
		return rule;
	}

	public void setRule(String rule) {
		this.rule = rule;
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

	@ManyToOne
	@JoinColumn(name = "wafId")
	public Waf getWaf() {
		return waf;
	}

	public void setWaf(Waf waf) {
		this.waf = waf;
	}

	@ManyToOne
	@JoinColumn(name = "vulnerabilityId")
	public Vulnerability getVulnerability() {
		return vulnerability;
	}

	public void setVulnerability(Vulnerability vulnerability) {
		this.vulnerability = vulnerability;
	}

	@OneToMany(mappedBy = "wafRule")
	public List<SecurityEvent> getSecurityEvents() {
		return securityEvents;
	}

	public void setSecurityEvents(List<SecurityEvent> securityEvents) {
		this.securityEvents = securityEvents;
	}
	
	@ManyToOne
	@JoinColumn(name = "wafRuleDirectiveId")
	public WafRuleDirective getWafRuleDirective() {
		return wafRuleDirective;
	}

	public void setWafRuleDirective(WafRuleDirective wafRuleDirective) {
		this.wafRuleDirective = wafRuleDirective;
	}
}
