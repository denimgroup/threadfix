package com.denimgroup.threadfix.framework.engine.full;

import java.util.List;

import com.denimgroup.threadfix.framework.engine.CodePoint;
import com.denimgroup.threadfix.framework.enums.InformationSourceType;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

public class EndpointQueryBuilder {
	
	@Nullable
    private String dynamicPath, staticPath, parameter, httpMethod;

    @Nullable
    private List<? extends CodePoint> codePoints;

    @Nullable
    private InformationSourceType informationSourceType;
	
	private EndpointQueryBuilder() {}
	
	@NotNull
    public static EndpointQueryBuilder start() {
		return new EndpointQueryBuilder();
	}
	
	@NotNull
    public EndpointQueryBuilder setDynamicPath(@Nullable String dynamicPath) {
		this.dynamicPath = dynamicPath;
		return this;
	}

	@NotNull
    public EndpointQueryBuilder setStaticPath(@Nullable String staticPath) {
		this.staticPath = staticPath;
		return this;
	}

	@NotNull
    public EndpointQueryBuilder setParameter(@Nullable String parameter) {
		this.parameter = parameter;
		
		if (parameter == null) {
			this.parameter = "null";
		}
		
		return this;
	}

	@NotNull
    public EndpointQueryBuilder setHttpMethod(@Nullable String httpMethod) {
		this.httpMethod = httpMethod;
		return this;
	}

	@NotNull
    public EndpointQueryBuilder setCodePoints(@Nullable List<? extends CodePoint> basicModelElements) {
		this.codePoints = basicModelElements;
		return this;
	}

	@NotNull
    public EndpointQueryBuilder setInformationSourceType(
            @NotNull InformationSourceType informationSourceType) {
		this.informationSourceType = informationSourceType;
		return this;
	}

	@NotNull
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
		
		@NotNull
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
