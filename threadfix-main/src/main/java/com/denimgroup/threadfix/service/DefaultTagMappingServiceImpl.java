package com.denimgroup.threadfix.service;

import java.util.List;
import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.map;
import static com.denimgroup.threadfix.CollectionUtils.list;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.denimgroup.threadfix.data.dao.DefaultTagDao;
import com.denimgroup.threadfix.data.dao.GenericNamedObjectDao;
import com.denimgroup.threadfix.data.entities.DefaultTag;
import com.denimgroup.threadfix.data.entities.Vulnerability;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.defects.defaults.AbstractDefaultTagMapper;
import com.denimgroup.threadfix.service.defects.defaults.DefaultTagMapperFactory;

@Service
public class DefaultTagMappingServiceImpl extends AbstractNamedObjectService<DefaultTag> implements DefaultTagMappingService {

	private static final SanitizedLogger LOG = new SanitizedLogger(DefaultTagMappingServiceImpl.class);

	@Autowired
	private DefaultTagDao defaultTagDao;
	@Autowired
	private DefaultTagMapperFactory defaultTagMapperFactory;

	@Override
	public String evaluateTagValueForVulns(DefaultTag tag, List<Vulnerability> vulnerabilities) {
		AbstractDefaultTagMapper tagMapper = defaultTagMapperFactory.getTagMapperFromDefaultTag(tag);
		return tagMapper.getValueAssociated(vulnerabilities);
	}

	@Override
	public List<Object> getTagsWithValueMappingFields() {
		List<Object> tagsWithValueMappingFields = list();
		List<DefaultTag> defaultTags = defaultTagDao.retrieveAll();

		for (DefaultTag tag : defaultTags) {
			Map<String,Object> tagWithFields = map("name", (Object) tag.getName());
			AbstractDefaultTagMapper tagMapper = defaultTagMapperFactory.getTagMapperFromDefaultTag(tag);
			if(tagMapper.isSupportingValueMapping()){
				tagWithFields.put("valueMapping", true);
				tagWithFields.put("valueMappingFields", tagMapper.getValueMappingKeys());
			}
			else {
				tagWithFields.put("valueMapping", false);
			}
			tagsWithValueMappingFields.add(tagWithFields);
		}
		return tagsWithValueMappingFields;
	}

	@Override
	public List<String> getTagKeysOrNull(String tagName){ //for the moment we assume that tagName is verified before calling this function
		DefaultTag tag = defaultTagDao.retrieveByName(tagName);
		if (tag == null) return null;

		AbstractDefaultTagMapper tagMapper = defaultTagMapperFactory.getTagMapperFromDefaultTag(tag);
		LOG.debug("tagMapper loaded");
		if (tagMapper.isSupportingValueMapping()){
			return tagMapper.getValueMappingKeys();
		}
		else {
			return null;
		}
	}

	@Override
	public GenericNamedObjectDao<DefaultTag> getDao() {
		return defaultTagDao;
	}
}
