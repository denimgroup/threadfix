package com.denimgroup.threadfix.service.defects.defaults.tags;

import java.util.List;

import org.springframework.stereotype.Component;

import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Vulnerability;
import com.denimgroup.threadfix.service.defects.defaults.AbstractDefaultTagMapper;

@Component
public class GenericNameDefaultTagMapper extends AbstractDefaultTagMapper {

	@Override
	public String getValueAssociated(List<Vulnerability> vulnerabilities) {
		List<Finding> firstVulnFindings = vulnerabilities.get(0).getFindings();
		if (firstVulnFindings != null){
			return firstVulnFindings.get(0).getChannelVulnerability().getGenericVulnerability().getName();
		}
		else return null;
	}

	@Override
	public boolean isSupportingValueMapping() {
		return false;
	}

	@Override
	public List<String> getValueMappingKeys() {
		return null;
	}

}
