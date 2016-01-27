////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2016 Denim Group, Ltd.
//
//     The contents of this file are subject to the Mozilla Public License
//     Version 2.0 (the "License"); you may not use this file except in
//     compliance with the License. You may obtain a copy of the License at
//     http://www.mozilla.org/MPL/
//
//     Software distributed under the License is distributed on an "AS IS"
//     basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//     License for the specific language governing rights and limitations
//     under the License.
//
//     The Original Code is ThreadFix.
//
//     The Initial Developer of the Original Code is Denim Group, Ltd.
//     Portions created by Denim Group, Ltd. are Copyright (C)
//     Denim Group, Ltd. All Rights Reserved.
//
//     Contributor(s): Denim Group, Ltd.
//
////////////////////////////////////////////////////////////////////////
package com.denimgroup.threadfix.framework.impl.struts;

import com.denimgroup.threadfix.framework.engine.CodePoint;
import com.denimgroup.threadfix.framework.engine.ProjectConfig;
import com.denimgroup.threadfix.framework.engine.full.EndpointQuery;
import com.denimgroup.threadfix.framework.engine.parameter.ParameterParser;
import com.denimgroup.threadfix.framework.impl.model.ModelField;
import com.denimgroup.threadfix.framework.util.RegexUtils;
import com.denimgroup.threadfix.framework.util.java.EntityMappings;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.List;
import java.util.regex.Pattern;

import static com.denimgroup.threadfix.CollectionUtils.list;

public class StrutsDataFlowParser implements ParameterParser {

	// So we only compile these patterns once
	public static final Pattern
		ENTITY_PAREN_PATTERN 	= Pattern.compile("\\(([^)]+)\\)");

	@Nonnull
    private final EntityMappings mappings;

	public StrutsDataFlowParser(@Nonnull ProjectConfig projectConfig) {
		EntityMappings mappings = null;
		if (projectConfig.getRootFile() != null) {
			mappings = new EntityMappings(projectConfig.getRootFile());
		}
		this.mappings = mappings;
	}
	@Override
	public String parse(@Nonnull EndpointQuery query) {
		String parameter = null;
		
		if (query.getCodePoints() != null && !query.getCodePoints().isEmpty()) {
			List<String> lines = getLines(query.getCodePoints());
			parameter = attemptModelParsingWithMappings(lines);
		}
		
		if (parameter == null) {
			parameter = query.getParameter();
		}
		
		return parameter;
	}
	
	@Nonnull
    private List<String> getLines(@Nonnull List<CodePoint> codePoints) {
		List<String> returnList = list();
		
		for (CodePoint element : codePoints) {
			if (element != null && element.getLineText() != null) {
				returnList.add(element.getLineText());
			}
		}
		
		return returnList;
	}

	@Nullable
    private String attemptModelParsingWithMappings(@Nonnull List<String> lines) {
		String result = null;

		if (!lines.isEmpty()) {
			String modelObject = getModelObject(lines.get(0));
			String initialType = getModelObjectType(lines.get(0));

			if (modelObject != null && initialType != null) {

				ModelField beanField = new ModelField(initialType, modelObject);

				List<ModelField> fieldChain = list(beanField);

				for (String elementText : lines) {
					if (elementText != null) {
						List<ModelField> beanFields = getParameterWithEntityData(elementText,
								fieldChain.get(fieldChain.size() - 1));

						if (beanFields.size() > 1) {
							beanFields.remove(0);
							fieldChain.addAll(beanFields);
							beanField = fieldChain.get(fieldChain.size() - 1);
						}

						if (beanField.isPrimitiveType()) {
                            break;
                        }
                    }
                }

                result = buildStringFromFieldChain(fieldChain);
            }
		}
		
		return result;
	}
	
	@Nonnull
    private String buildStringFromFieldChain(@Nonnull List<ModelField> fieldChain) {
		StringBuilder parameterChainBuilder = new StringBuilder();
		
		if (fieldChain.size() > 0) {
			for (ModelField field : fieldChain) {
				parameterChainBuilder.append(field.getParameterKey()).append('.');
			}
			parameterChainBuilder.setLength(parameterChainBuilder.length() - 1);
		}
		
		return parameterChainBuilder.toString();
	}

    @Nullable
	private String getModelObject(String elementText) {
		return getParameterFromString(elementText, false);
	}

	@Nullable
	private String getModelObjectType(String elementText) {
		return getParameterFromString(elementText, true);
	}

	private String getParameterFromString(String elementText, boolean type) {
		// if type is true, return ObjectType, else return objectName;
		String string = null;
		String paramString = RegexUtils.getRegexResult(elementText, ENTITY_PAREN_PATTERN);
		if (paramString == null)
			return null;
		paramString = paramString.trim();
		if (!paramString.matches("\\w+\\s+\\w+"))
			return null;
//		String[] params = paramString.split(",");
//		if (params.length < 1)
//			return null;
//		String[] model = params[0].trim().split("\\s+");
		String[] model = paramString.split("\\s+");
		if (model.length == 2)
			if (type)
				string = model[0];
			else
				string = model[1];
		return string;
	}

    @Nonnull
	private List<ModelField> getParameterWithEntityData(String line, @Nonnull ModelField beanField) {
		String methodCall = RegexUtils.getRegexResult(line, getPatternForString(beanField.getParameterKey()));

		List<ModelField> returnField = list();

		if (mappings != null && methodCall != null) {
			returnField = mappings.getFieldsFromMethodCalls(methodCall, beanField);
		}
		
		return returnField;
	}

    // public for testing
    // TODO write more rigorous unit tests and shake out corner cases
    public static Pattern getPatternForString(String entity) {
        if (entity != null) {
            String regexGetSection = entity.length() > 1 ?
                    "(?:" + entity.substring(1) + "|" + entity.substring(1) + "\\(\\))((?:\\.get[^\\.;]+))" :
                    entity + "((?:\\.get[^\\.;]+))";
            return Pattern.compile(regexGetSection);
        } else {
            return null;
        }
    }

}
