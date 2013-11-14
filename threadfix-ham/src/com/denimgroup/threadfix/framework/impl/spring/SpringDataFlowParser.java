////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2013 Denim Group, Ltd.
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
package com.denimgroup.threadfix.framework.impl.spring;

import com.denimgroup.threadfix.framework.engine.CodePoint;
import com.denimgroup.threadfix.framework.engine.ProjectConfig;
import com.denimgroup.threadfix.framework.engine.full.EndpointQuery;
import com.denimgroup.threadfix.framework.engine.parameter.ParameterParser;
import com.denimgroup.threadfix.framework.util.RegexUtils;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

public class SpringDataFlowParser implements ParameterParser {
	
	// So we only compile these patterns once
	private static final Pattern
		ENTITY_TYPE_PATTERN      = Pattern.compile("([a-zA-Z0-9_]+) [^ ]+, ?BindingResult"),
		ENTITY_OBJECT_PATTERN    = Pattern.compile("([a-zA-Z0-9_]+), ?BindingResult"),
		PATH_VARIABLE_WITH_PARAM = Pattern.compile("@PathVariable\\(\"([a-zA-Z0-9]+)\"\\)"),
		PATH_VARIABLE_NO_PARAM   = Pattern.compile("@PathVariable [^ ]+ ([^,\\)]+)"),
		REQUEST_PARAM_WITH_PARAM = Pattern.compile("@RequestParam\\(\"([a-zA-Z0-9]+)\"\\)"),
		REQUEST_PARAM_NO_PARAM   = Pattern.compile("@RequestParam [^ ]+ ([^,\\)]+)");
	
	@Nullable
    private final SpringEntityMappings mappings;
	
	public SpringDataFlowParser(@NotNull ProjectConfig projectConfig) {
		SpringEntityMappings mappings = null;
		if (projectConfig.getRootFile() != null) {
			mappings = new SpringEntityMappings(projectConfig.getRootFile());
		}
		this.mappings = mappings;
	}
	
	/**
	 * Examines the data flow to try to find Spring parameters.
	 * 
	 * This method takes advantage of a few assumptions:
	 * 	1. The flow will follow only one parameter.
	 *  2. The first element in the flow will be the Spring controller method call
	 * 
	 *  TODO handle owner.pet.name and similar cases
	 * 
	 */
	@Override
	public String parse(@NotNull EndpointQuery query) {
		
		String parameter = null;
		
		if (query.getCodePoints() != null &&
				!query.getCodePoints().isEmpty()) {
			
			List<String> lines = getLines(query.getCodePoints());
			
			if (mappings == null || mappings.isEmpty()) {
				parameter = attemptModelParsingNoMappings(lines);
			} else {
				parameter = attemptModelParsingWithMappings(lines);
			}
			if (parameter == null || parameter.isEmpty()) {
				parameter = attemptPathVariableParsing(lines);
			}
		}
		
		if (parameter == null) {
			parameter = query.getParameter();
		}
		
		return parameter;
	}
	
	@NotNull
    private List<String> getLines(@NotNull List<CodePoint> codePoints) {
		List<String> returnList = new ArrayList<>(codePoints.size());
		
		for (CodePoint element : codePoints) {
			if (element != null && element.getLineText() != null) {
				returnList.add(element.getLineText());
			}
		}
		
		return returnList;
	}

	// TODO move to a system that supports more than one variable
	@Nullable
    private String attemptPathVariableParsing(@Nullable List<String> lines) {
		
		String parameter = null;
		
		if (lines != null && !lines.isEmpty()) {
			String elementText = lines.get(0);
		
			// try for @PathVariable("ownerId") int ownerId
			parameter = RegexUtils.getRegexResult(elementText, PATH_VARIABLE_WITH_PARAM);
			
			if (parameter == null) {
				// try for @PathVariable String ownerName
				parameter = RegexUtils.getRegexResult(elementText, PATH_VARIABLE_NO_PARAM);
			}
			
			if (parameter == null) {
				// try for @RequestParam("ownerName") String ownerName
				parameter = RegexUtils.getRegexResult(elementText, REQUEST_PARAM_WITH_PARAM);
			}
			
			if (parameter == null) {
				// try for @RequestParam String ownerName
				parameter = RegexUtils.getRegexResult(elementText, REQUEST_PARAM_NO_PARAM);
			}
		}
		
		return parameter;
	}

	@Nullable
    private String attemptModelParsingNoMappings(@Nullable List<String> lines) {
		
		String parameter = null;
		
		if (lines != null && !lines.isEmpty()) {
			String modelObject = getModelObject(lines.get(0));
			
			if (modelObject != null) {
				for (String elementText : lines) {
					if (elementText != null) {
						parameter = getParameter(elementText, modelObject);
						
						if (parameter != null) {
							break;
						}
					}
				}
			}
		}
		
		return parameter;
	}
	
	@Nullable
    private String attemptModelParsingWithMappings(@NotNull List<String> lines) {
		String result = null;
		
		if (!lines.isEmpty()) {
			String modelObject = getModelObject(lines.get(0));
			String initialType = getModelObjectType(lines.get(0));

            if (modelObject != null && initialType != null) {
			
                BeanField beanField = new BeanField(initialType, modelObject);

                List<BeanField> fieldChain = new ArrayList<>(Arrays.asList(beanField));
					
                for (String elementText : lines) {
                    if (elementText != null) {
                        List<BeanField> beanFields = getParameterWithEntityData(elementText,
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
	
	@NotNull
    private String buildStringFromFieldChain(@NotNull List<BeanField> fieldChain) {
		StringBuilder parameterChainBuilder = new StringBuilder();
		
		if (fieldChain.size() > 1) {
			fieldChain.remove(0);
			for (BeanField field : fieldChain) {
				parameterChainBuilder.append(field.getParameterKey()).append('.');
			}
			parameterChainBuilder.setLength(parameterChainBuilder.length() - 1);
		}
		
		return parameterChainBuilder.toString();
	}

    @Nullable
	private String getModelObject(String elementText) {
		return RegexUtils.getRegexResult(elementText, ENTITY_OBJECT_PATTERN);
	}

    @Nullable
	private String getModelObjectType(String elementText) {
		return RegexUtils.getRegexResult(elementText, ENTITY_TYPE_PATTERN);
	}

    @NotNull
	private List<BeanField> getParameterWithEntityData(String line, @NotNull BeanField beanField) {
		List<String> methodCalls = RegexUtils.getRegexResults(line,
				Pattern.compile(beanField.getParameterKey() + "(\\.get[^\\(]+\\(\\))+"));
		
		List<BeanField> returnField = new ArrayList<>();
		
		if (mappings != null && methodCalls != null && !methodCalls.isEmpty()) {
			returnField = mappings.getFieldsFromMethodCalls(methodCalls.get(0), beanField);
		}
		
		return returnField;
	}

	@Nullable
    private String getParameter(String line, @NotNull String modelObject) {
		String methodCall = RegexUtils.getRegexResult(line, "(" + modelObject + "\\.[a-zA-Z0-9]+)");
		
		String parameterName = null;
		
		if (methodCall != null) {
			parameterName = getParameterFromBeanAccessor(modelObject, methodCall);
		}
		
		return parameterName;
	}

	@Nullable
    private String getParameterFromBeanAccessor(@NotNull String modelObject,
			@NotNull String methodCall) {
		
		String propertyName = null;
		
		if (methodCall.startsWith(modelObject + ".get")) {
			propertyName = methodCall.substring(modelObject.length() + 4);
			propertyName = propertyName.substring(0,1).toLowerCase() + propertyName.substring(1);
		}
		
		return propertyName;
	}
	
}
