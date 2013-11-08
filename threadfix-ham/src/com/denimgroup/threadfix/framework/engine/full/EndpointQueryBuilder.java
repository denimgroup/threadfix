package com.denimgroup.threadfix.framework.engine.full;

import java.util.List;

import com.denimgroup.threadfix.framework.engine.CodePoint;
import com.denimgroup.threadfix.framework.enums.InformationSourceType;

public class EndpointQueryBuilder {
	
	private String dynamicPath, staticPath, parameter, httpMethod;
	private List<? extends CodePoint> codePoints;
	private InformationSourceType informationSourceType;
	
	private EndpointQueryBuilder() {}
	
	public static EndpointQueryBuilder start() {
		return new EndpointQueryBuilder();
	}
	
	public EndpointQueryBuilder setDynamicPath(String dynamicPath) {
		this.dynamicPath = dynamicPath;
		return this;
	}

	public EndpointQueryBuilder setStaticPath(String staticPath) {
		this.staticPath = staticPath;
		return this;
	}

	public EndpointQueryBuilder setParameter(String parameter) {
		this.parameter = parameter;
		return this;
	}

	public EndpointQueryBuilder setHttpMethod(String httpMethod) {
		this.httpMethod = httpMethod;
		return this;
	}

	public EndpointQueryBuilder setCodePoints(List<? extends CodePoint> basicModelElements) {
		this.codePoints = basicModelElements;
		return this;
	}

	public EndpointQueryBuilder setInformationSourceType(
			InformationSourceType informationSourceType) {
		this.informationSourceType = informationSourceType;
		return this;
	}

	public EndpointQuery generateQuery() {
		return new DefaultEndpointQuery(dynamicPath, staticPath, parameter,
				httpMethod, codePoints, informationSourceType);
	}

	private static class DefaultEndpointQuery implements EndpointQuery {
		
		private final String dynamicPath, staticPath, parameter, httpMethod;
		private final List<CodePoint> codePoints;
		private final InformationSourceType informationSourceType;

		@SuppressWarnings("unchecked")
		public DefaultEndpointQuery(String dynamicPath, String staticPath,
				String parameter, String httpMethod,
				List<? extends CodePoint> codePoints,
				InformationSourceType informationSourceType) {
			this.dynamicPath = dynamicPath;
			this.staticPath = staticPath;
			this.parameter = parameter;
			this.httpMethod = httpMethod;
			this.codePoints = (List<CodePoint>) codePoints;
			this.informationSourceType = informationSourceType;
		}

		@Override
		public String getDynamicPath() {
			return dynamicPath;
		}

		@Override
		public String getStaticPath() {
			return staticPath;
		}

		@Override
		public String getParameter() {
			return parameter;
		}

		@Override
		public String getHttpMethod() {
			return httpMethod;
		}

		@Override
		public List<CodePoint> getCodePoints() {
			return codePoints;
		}

		@Override
		public InformationSourceType getInformationSourceType() {
			return informationSourceType;
		}
		
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
