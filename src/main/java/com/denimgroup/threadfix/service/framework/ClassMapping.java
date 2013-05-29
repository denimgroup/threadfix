package com.denimgroup.threadfix.service.framework;

public class ClassMapping {

	private String servletName, classWithPackage;
	
	public ClassMapping(String servletName, String classWithPackage) {
		if (servletName == null) {
			throw new IllegalArgumentException("Servlet Name cannot be null.");
		}
		
		if (classWithPackage == null) {
			throw new IllegalArgumentException("Class cannot be null.");
		}
		
		this.servletName = servletName.trim();
		this.classWithPackage = classWithPackage.trim();
	}
	
	public String getServletName() {
		return servletName;
	}
	
	public String getClassWithPackage() {
		return classWithPackage;
	}
	
	@Override
	public String toString() {
		return getServletName() + " -> " + getClassWithPackage();
	}
	
}
