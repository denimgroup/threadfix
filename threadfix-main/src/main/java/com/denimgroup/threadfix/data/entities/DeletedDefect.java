package com.denimgroup.threadfix.data.entities;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Table;
import javax.validation.constraints.Size;

@Entity
@Table(name = "DeletedDefect")
public class DeletedDefect extends BaseEntity {
	
	private static final long serialVersionUID = 5923185785519317995L;

	public DeletedDefect(Defect defect) {
		if (defect != null) {
			setNativeId(defect.getNativeId());
			setId(defect.getId());
			setStatus(defect.getStatus());
			setDefectURL(defect.getDefectURL());
			if (defect.getApplication() != null) {
				setApplicationId(defect.getApplication().getId());
			}
		}
	}
	
	private String nativeId;
	private Integer applicationId;
	
	@Size(max = Defect.STATUS_LENGTH, message = "{errors.maxlength} " + Defect.STATUS_LENGTH + ".")
	private String status;
	
	@Size(max = Defect.URL_LENGTH, message = "{errors.maxlength} " + Defect.URL_LENGTH + ".")
	private String defectURL;

	/**
	 * Stores the ID used by the defect tracking system.
	 * 
	 * @return
	 */
	@Column(length = 50, nullable = false)
	public String getNativeId() {
		return nativeId;
	}

	public void setNativeId(String nativeId) {
		this.nativeId = nativeId;
	}
	
	@Column(length = 255, nullable = false)
	public String getStatus() {
		return status;
	}

	public void setStatus(String status) {
		this.status = status;
	}
	
	@Column(length = 255)
	public String getDefectURL() {
		return defectURL;
	}

	public void setDefectURL(String defectURL) {
		this.defectURL = defectURL;
	}

	@Column
	public Integer getApplicationId() {
		return applicationId;
	}

	public void setApplicationId(Integer applicationId) {
		this.applicationId = applicationId;
	}

}
