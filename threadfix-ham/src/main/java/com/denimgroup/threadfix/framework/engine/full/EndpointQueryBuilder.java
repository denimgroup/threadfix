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

package com.denimgroup.threadfix.framework.engine.full;

import java.util.List;

import com.denimgroup.threadfix.data.enums.InformationSourceType;
import com.denimgroup.threadfix.framework.engine.CodePoint;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class EndpointQueryBuilder {
	
	@Nullable
    private String dynamicPath, staticPath, parameter, httpMethod;

    @Nullable
    private List<? extends CodePoint> codePoints;

    @Nullable
    private InformationSourceType informationSourceType;
	
	private EndpointQueryBuilder() {}
	
	@Nonnull
    public static EndpointQueryBuilder start() {
		return new EndpointQueryBuilder();
	}
	
	@Nonnull
    public EndpointQueryBuilder setDynamicPath(@Nullable String dynamicPath) {
		this.dynamicPath = dynamicPath;
		return this;
	}

	@Nonnull
    public EndpointQueryBuilder setStaticPath(@Nullable String staticPath) {
		this.staticPath = staticPath;
		return this;
	}

	@Nonnull
    public EndpointQueryBuilder setParameter(@Nullable String parameter) {
		this.parameter = parameter;
		
		if (parameter == null) {
			this.parameter = "null";
		}
		
		return this;
	}

	@Nonnull
    public EndpointQueryBuilder setHttpMethod(@Nullable String httpMethod) {
		this.httpMethod = httpMethod;
		return this;
	}

	@Nonnull
    public EndpointQueryBuilder setCodePoints(@Nullable List<? extends CodePoint> basicModelElements) {
		this.codePoints = basicModelElements;
		return this;
	}

	@Nonnull
    public EndpointQueryBuilder setInformationSourceType(
            @Nonnull InformationSourceType informationSourceType) {
		this.informationSourceType = informationSourceType;
		return this;
	}

	@Nonnull
    public EndpointQuery generateQuery() {
		return new DefaultEndpointQuery(dynamicPath, staticPath, parameter,
				httpMethod, codePoints, informationSourceType);
	}

	private static class DefaultEndpointQuery implements EndpointQuery {

        @Nullable
		private final String dynamicPath, staticPath, parameter, httpMethod;

		@Nullable
        private final List<CodePoint> codePoints;

        @Nullable
		private final InformationSourceType informationSourceType;

		@SuppressWarnings("unchecked")
		public DefaultEndpointQuery(@Nullable String dynamicPath, @Nullable String staticPath,
                                    @Nullable String parameter, @Nullable String httpMethod,
                                    @Nullable List<? extends CodePoint> codePoints,
                                    @Nullable InformationSourceType informationSourceType) {
			this.dynamicPath = dynamicPath;
			this.staticPath = staticPath;
			this.parameter = parameter;
			this.httpMethod = httpMethod;
			this.codePoints = (List<CodePoint>) codePoints;
			this.informationSourceType = informationSourceType;
		}

		@Override
        @Nullable
		public String getDynamicPath() {
			return dynamicPath;
		}

		@Override
        @Nullable
		public String getStaticPath() {
			return staticPath;
		}

		@Override
        @Nullable
		public String getParameter() {
			return parameter;
		}

		@Override
        @Nullable
		public String getHttpMethod() {
			return httpMethod;
		}

		@Override
        @Nullable
		public List<CodePoint> getCodePoints() {
			return codePoints;
		}

		@Override
        @Nullable
		public InformationSourceType getInformationSourceType() {
			return informationSourceType;
		}
		
		@Nonnull
        @Override
		public String toString() {
			StringBuilder builder = new StringBuilder();
			
			if (dynamicPath != null) {
				builder.append("dynamic path = ").append(dynamicPath).append(",");
			}
			
			if (staticPath != null) {
				builder.append("static path = ").append(staticPath).append(",");
			}
			
			if (parameter != null) {
				builder.append("parameter = ").append(parameter).append(",");
			}
			
			if (httpMethod != null) {
				builder.append("httpMethod = ").append(httpMethod).append(",");
			}
			
			if (informationSourceType != null) {
				builder.append("information type = ").append(informationSourceType).append(",");
			}
			
			if (codePoints != null) {
				builder.append("codePoints size = ").append(codePoints.size()).append(",");
			}
			
			if (builder.length() > 1) {
				builder.deleteCharAt(builder.length() - 1);
			}
			
			return builder.toString();
		}
		
	}
	
}
