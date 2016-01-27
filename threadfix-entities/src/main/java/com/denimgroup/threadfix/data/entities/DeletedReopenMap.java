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

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Table;

@Entity
@Table(name="DeletedReopenMap")
public class DeletedReopenMap extends AuditableEntity {

	private static final long serialVersionUID = -5721116440103821972L;

	private Integer vulnerabilityId, scanId;

	public DeletedReopenMap(ScanReopenVulnerabilityMap map) {
		if (map != null && map.getScan() != null && map.getVulnerability() != null) {
			setScanId(map.getScan().getId());
			setVulnerabilityId(map.getVulnerability().getId());
			setId(map.getId());
		}
	}

	@Column
	public Integer getScanId() {
		return scanId;
	}

	public void setScanId(Integer scanId) {
		this.scanId = scanId;
	}

	@Column
	public Integer getVulnerabilityId() {
		return vulnerabilityId;
	}

	public void setVulnerabilityId(Integer vulnerabilityId) {
		this.vulnerabilityId = vulnerabilityId;
	}

}
