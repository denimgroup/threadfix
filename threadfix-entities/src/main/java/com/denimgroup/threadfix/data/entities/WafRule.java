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
import org.hibernate.validator.constraints.NotEmpty;

import javax.persistence.*;
import javax.validation.constraints.Size;
import java.util.List;

@Entity
@Table(name = "WafRule")
public class WafRule extends AuditableEntity {

	private static final long serialVersionUID = 1723103296983210781L;
	
	public static final int PARAMETER_LENGTH = 1024;
	public static final int PATH_LENGTH = 1024;
	public static final int RULE_LENGTH = 10000;

	@NotEmpty(message = "{errors.required}")
	@Size(max = RULE_LENGTH, message = "{errors.maxlength} " + RULE_LENGTH + ".")
	private String rule;
	
	@Size(max = PARAMETER_LENGTH, message = "{errors.maxlength} " + PARAMETER_LENGTH + ".")
	private String parameter;
	
	@Size(max = PATH_LENGTH, message = "{errors.maxlength} " + PATH_LENGTH + ".")
	private String path;
	
	// This field is used to remove rules that are handled specially 
	// from inclusion with the normal rules. Right now just used by BIG-IP
	// to prevent CSRF rules from going into the URL section.
	private boolean isNormalRule = true;
	
	@Size(max = 25, message = "{errors.maxlength} 25.")
	private String nativeId;
	private Waf waf;
	private Vulnerability vulnerability;
	
	@Size(max = 1024, message = "{errors.maxlength} 1024")
	private String vulnerabilityDesc;
	private WafRuleDirective wafRuleDirective;
	
	private List<SecurityEvent> securityEvents;

	@Column(length = RULE_LENGTH)
	public String getRule() {
		return rule;
	}

	public void setRule(String rule) {
		this.rule = rule;
	}
	
	@Column(length = PATH_LENGTH)
	public String getPath() {
		return path;
	}

	public void setPath(String path) {
		this.path = path;
	}
	
	@Column(length = PARAMETER_LENGTH)
	public String getParameter() {
		return parameter;
	}

	public void setParameter(String parameter) {
		this.parameter = parameter;
	}
	
	// TODO switch to independent rule
	@Column(nullable = false)
	public boolean getIsNormalRule() {
		return isNormalRule;
	}

	public void setIsNormalRule(boolean isNormalRule) {
		this.isNormalRule = isNormalRule;
	}

	@Column(length = 1024)
	public String getVulnerabilityDesc() {
		return vulnerabilityDesc;
	}

	public void setVulnerabilityDesc(String vulnerabilityDesc) {
		this.vulnerabilityDesc = vulnerabilityDesc;
	}

	@Column(length = 25)
	@JsonView(AllViews.TableRow.class)
	public String getNativeId() {
		return nativeId;
	}

	public void setNativeId(String nativeId) {
		this.nativeId = nativeId;
	}

	@ManyToOne
	@JoinColumn(name = "wafId")
	@JsonIgnore
	public Waf getWaf() {
		return waf;
	}

	public void setWaf(Waf waf) {
		this.waf = waf;
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

	@OneToMany(mappedBy = "wafRule")
	@JsonIgnore
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

    @Transient
	@JsonView(AllViews.TableRow.class)
	public int getSecurityEventsCount() {
        if (securityEvents != null)
            return securityEvents.size();

        return 0;
    }
}
