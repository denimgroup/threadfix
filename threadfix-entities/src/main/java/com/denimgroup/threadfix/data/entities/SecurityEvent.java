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

import javax.persistence.*;
import javax.validation.constraints.Size;
import java.util.Calendar;

@Entity
@Table(name = "SecurityEvent")
public class SecurityEvent extends BaseEntity {

	private static final long serialVersionUID = -5489815525873130309L;

	private WafRule wafRule;
	private Integer backupWafRuleId = null;
	
	@Size(max = 1024, message = "{errors.maxlength}")
	private String logText;
	private Calendar importTime;
	
	@Size(max = 250, message = "{errors.maxlength}")
	private String attackType;
	
	@Size(max = 50, message = "{errors.maxlength}")
	private String nativeId;
	
	@Size(max = 50, message = "{errors.maxlength}")
	private String attackerIP;

	@ManyToOne
	@JoinColumn(name = "wafRuleId")
	@JsonIgnore
	public WafRule getWafRule() {
		return wafRule;
	}

	public void setWafRule(WafRule wafRule) {
		this.wafRule = wafRule;
	}

	@Column(length = 1024)
	public String getLogText() {
		return logText;
	}

	public void setLogText(String logText) {
		this.logText = logText;
	}

	@Temporal(TemporalType.TIMESTAMP)
	public Calendar getImportTime() {
		return importTime;
	}

	public void setImportTime(Calendar importTime) {
		this.importTime = importTime;
	}

	@Column(length = 250)
	public String getAttackType() {
		return attackType;
	}

	public void setAttackType(String attackType) {
		this.attackType = attackType;
	}
	
	@Column(length = 50)
	public String getNativeId() {
		return nativeId;
	}

	public void setNativeId(String nativeId) {
		this.nativeId = nativeId;
	}
	
	@Column(length = 50)
	public String getAttackerIP() {
		return attackerIP;
	}

	public void setAttackerIP(String attackerIP) {
		this.attackerIP = attackerIP;
	}

	public void backUpWafRule() {
		if (getWafRule() != null) {
			setBackupWafRuleId(getWafRule().getId());
			setWafRule(null);
		}
	}

	@Column(nullable=true)
	public Integer getBackupWafRuleId() {
		return backupWafRuleId;
	}

	public void setBackupWafRuleId(Integer backupWafRuleId) {
		this.backupWafRuleId = backupWafRuleId;
	}
}
