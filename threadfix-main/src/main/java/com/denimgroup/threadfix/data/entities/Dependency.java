package com.denimgroup.threadfix.data.entities;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Table;
import javax.validation.constraints.Size;

@Entity
@Table(name = "Dependency")
public class Dependency extends AuditableEntity {

	/**
	 * 
	 */
	private static final long serialVersionUID = 3647499545381978852L;
	
	@Size(max = 20, message = "{errors.maxlength} 20.")
	private String cve;

	@Column(length = 20)
	public String getCve() {
		return cve;
	}

	public void setCve(String cve) {
		this.cve = cve;
	}

}
