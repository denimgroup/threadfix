package com.denimgroup.threadfix.data.entities;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Table;

@Entity
@Table(name = "DeletedRepeatFindingMap")
public class DeletedRepeatFindingMap extends AuditableEntity {
	
	private static final long serialVersionUID = -6516192744544931178L;

	private Integer findingId, scanId;
	
	public DeletedRepeatFindingMap(ScanRepeatFindingMap map) {
		if (map != null && map.getScan() != null && map.getFinding() != null) {
			setScanId(map.getScan().getId());
			setFindingId(map.getFinding().getId());
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
	public Integer getFindingId() {
		return findingId;
	}

	public void setFindingId(Integer findingId) {
		this.findingId = findingId;
	}

}
