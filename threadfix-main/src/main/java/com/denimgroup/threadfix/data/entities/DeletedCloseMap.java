package com.denimgroup.threadfix.data.entities;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Table;

@Entity
@Table(name = "DeletedCloseMap")
public class DeletedCloseMap extends AuditableEntity {

	private static final long serialVersionUID = 2820320205974503498L;

	private Integer scanId, vulnerabilityId;

	public DeletedCloseMap(ScanCloseVulnerabilityMap map) {
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
