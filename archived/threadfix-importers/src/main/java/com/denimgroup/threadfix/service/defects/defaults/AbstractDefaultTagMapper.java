package com.denimgroup.threadfix.service.defects.defaults;

import java.util.List;

import com.denimgroup.threadfix.data.entities.Vulnerability;

/**
 * The Interface the tag mappers have to implement to return relevant
 * values when updating or retrieving default fields using tags for Defect submission
 *
 */
public abstract class AbstractDefaultTagMapper {

	public abstract String getValueAssociated(List<Vulnerability> vulnerabilities);

	public abstract boolean isSupportingValueMapping();

	public abstract List<String> getValueMappingKeys();

}