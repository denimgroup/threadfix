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
