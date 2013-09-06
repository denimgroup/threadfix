package com.denimgroup.threadfix.webapp.controller;

public class TableSortBean {
	
	int page, sort, field;
	String descriptionFilter, severityFilter, locationFilter, parameterFilter;
	private String cweFilter;
	boolean open, falsePositive, hidden;

	public boolean isHidden() {
		return hidden;
	}
	public void setHidden(boolean hidden) {
		this.hidden = hidden;
	}
	public boolean isOpen() {
		return open;
	}
	public void setOpen(boolean open) {
		this.open = open;
	}
	public boolean isFalsePositive() {
		return falsePositive;
	}
	public void setFalsePositive(boolean falsePositive) {
		this.falsePositive = falsePositive;
	}
	public String getDescriptionFilter() {
		return descriptionFilter;
	}
	public void setDescriptionFilter(String descriptionFilter) {
		this.descriptionFilter = descriptionFilter;
	}
	public int getPage() {
		return page;
	}
	public void setPage(int page) {
		this.page = page;
	}
	public int getSort() {
		return sort;
	}
	public void setSort(int sort) {
		this.sort = sort;
	}
	public int getField() {
		return field;
	}
	public void setField(int field) {
		this.field = field;
	}
	public String getSeverityFilter() {
		return severityFilter;
	}
	public void setSeverityFilter(String severityFilter) {
		this.severityFilter = severityFilter;
	}
	public String getLocationFilter() {
		return locationFilter;
	}
	public void setLocationFilter(String locationFilter) {
		this.locationFilter = locationFilter;
	}
	public String getParameterFilter() {
		return parameterFilter;
	}
	public void setParameterFilter(String parameterFilter) {
		this.parameterFilter = parameterFilter;
	}
	public String getCweFilter() {
		return cweFilter;
	}
	public void setCweFilter(String cweFilter) {
		this.cweFilter = cweFilter;
	}
	
	// This is currently used to decide whether or not the vulnerabilities should be put into groups or not.
	public boolean isDefaultBean() {
		return field == 0 && descriptionFilter.isEmpty() && locationFilter.isEmpty() &&
				parameterFilter.isEmpty() && severityFilter.isEmpty() && sort == 0;
	}
}
