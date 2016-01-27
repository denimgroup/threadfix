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
package com.denimgroup.threadfix.framework.impl.spring;

import com.denimgroup.threadfix.framework.engine.CodePoint;
import com.denimgroup.threadfix.framework.engine.ProjectConfig;
import com.denimgroup.threadfix.framework.engine.full.EndpointQuery;
import com.denimgroup.threadfix.framework.engine.parameter.ParameterParser;
import com.denimgroup.threadfix.framework.impl.model.ModelField;
import com.denimgroup.threadfix.framework.util.RegexUtils;
import com.denimgroup.threadfix.framework.util.java.EntityMappings;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.CollectionUtils.map;

public class SpringDataFlowParser implements ParameterParser {
	
	// So we only compile these patterns once
	public static final Pattern
		ENTITY_TYPE_PATTERN      = Pattern.compile("([a-zA-Z0-9_]+) [^ ]+, ?BindingResult"),
		ENTITY_OBJECT_PATTERN    = Pattern.compile("([a-zA-Z0-9_]+), ?BindingResult"),
		PATH_VARIABLE_WITH_PARAM = Pattern.compile("@PathVariable\\(\"([a-zA-Z0-9]+)\"\\)"),
		PATH_VARIABLE_NO_PARAM   = Pattern.compile("@PathVariable\\W+\\w+\\W+([^,\\)]+)"),
		REQUEST_PARAM_WITH_PARAM = Pattern.compile("@RequestParam\\(\"([a-zA-Z0-9]+)\"\\)"),
		REQUEST_PARAM_NO_PARAM   = Pattern.compile("@RequestParam\\W+\\w+\\W+([^,\\)]+)");
	
	@Nullable
    private final EntityMappings mappings;
	
	public SpringDataFlowParser(@Nonnull ProjectConfig projectConfig) {
		EntityMappings mappings = null;
		if (projectConfig.getRootFile() != null) {
			mappings = new EntityMappings(projectConfig.getRootFile());
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
	public String parse(@Nonnull EndpointQuery query) {
		
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

	// TODO move to a system that supports more than one variable
	@Nullable
    private String attemptPathVariableParsing(@Nullable List<String> lines) {

        List<String> parameters;

		String parameter = null;
		
		if (lines != null && !lines.isEmpty()) {
			String elementText = lines.get(0);

			// try for @PathVariable("ownerId") int ownerId
            parameters = RegexUtils.getRegexResults(elementText, PATH_VARIABLE_WITH_PARAM);

			if (parameters.isEmpty()) {
				// try for @PathVariable String ownerName
                parameters = RegexUtils.getRegexResults(elementText, PATH_VARIABLE_NO_PARAM);
			}

			if (parameters.isEmpty()) {
				// try for @RequestParam("ownerName") String ownerName
                parameters = RegexUtils.getRegexResults(elementText, REQUEST_PARAM_WITH_PARAM);
			}

			if (parameters.isEmpty()) {
				// try for @RequestParam String ownerName
                parameters = RegexUtils.getRegexResults(elementText, REQUEST_PARAM_NO_PARAM);
			}

            if (parameters.size() == 1) {
                parameter = parameters.get(0);
            } else if (parameters.size() > 1) {
                parameter = scoreParameters(parameters, lines);
            }
		}

		return parameter;
	}

    private String scoreParameters(List<String> parameters, List<String> lines) {

        Map<String, Integer> map = map();

        for (String parameter : parameters) {
            map.put(parameter, 0);
        }

        for (String line : lines) {
            for (String parameter : parameters) {
                if (line.contains(parameter)) {
                    map.put(parameter, map.get(parameter) + 1);
                }
            }
        }

        String winningParameter = null;

        for (Map.Entry<String, Integer> stringIntegerEntry : map.entrySet()) {
            if (winningParameter == null || stringIntegerEntry.getValue() > map.get(winningParameter)) {
                winningParameter = stringIntegerEntry.getKey();
            }
        }

        return winningParameter;
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
		
		if (fieldChain.size() > 1) {
			fieldChain.remove(0);
			for (ModelField field : fieldChain) {
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

	@Nullable
    private String getParameter(String line, @Nonnull String modelObject) {
		String methodCall = RegexUtils.getRegexResult(line, "(" + modelObject + "\\.[a-zA-Z0-9]+)");
		
		String parameterName = null;

		if (methodCall != null) {
			parameterName = getParameterFromBeanAccessor(modelObject, methodCall);
		}
		
		return parameterName;
	}

	@Nullable
    private String getParameterFromBeanAccessor(@Nonnull String modelObject,
			@Nonnull String methodCall) {
		
		String propertyName = null;
		
		if (methodCall.startsWith(modelObject + ".get")) {
			propertyName = methodCall.substring(modelObject.length() + 4);
			propertyName = propertyName.substring(0,1).toLowerCase() + propertyName.substring(1);
		}
		
		return propertyName;
	}
	
}
