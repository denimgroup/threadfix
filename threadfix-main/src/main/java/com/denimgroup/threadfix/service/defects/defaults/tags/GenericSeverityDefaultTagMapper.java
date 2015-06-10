package com.denimgroup.threadfix.service.defects.defaults.tags;

import java.util.List;

import static com.denimgroup.threadfix.CollectionUtils.list;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.GenericSeverity;
import com.denimgroup.threadfix.data.entities.Vulnerability;
import com.denimgroup.threadfix.service.GenericSeverityService;
import com.denimgroup.threadfix.service.defects.defaults.AbstractDefaultTagMapper;

@Component
public class GenericSeverityDefaultTagMapper extends AbstractDefaultTagMapper {

	@Autowired
	private GenericSeverityService genericSeverityService;

	@Override
	public String getValueAssociated(List<Vulnerability> vulnerabilities) {
		List<Finding> firstVulnFindings = vulnerabilities.get(0).getFindings();
		if (firstVulnFindings != null){
			return firstVulnFindings.get(0).getChannelSeverity().getSeverityMap().getGenericSeverity().getName();
		}
		else return null;
	}

	@Override
	public boolean isSupportingValueMapping() {
		return true;
	}

	@Override
	public List<String> getValueMappingKeys() {
		List<GenericSeverity> genericSeverities = genericSeverityService.loadAll();
		List<String> keys = list();
		for (GenericSeverity genericSeverity : genericSeverities){
			keys.add(genericSeverity.getName());
		}
		return keys;
	}
}
