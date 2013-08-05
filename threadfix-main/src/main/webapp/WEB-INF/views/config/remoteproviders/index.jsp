<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Remote Providers</title>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/remote_providers_page.js"></script>
</head>

<body>
	<form:form modelAttribute="error" name="formErrors">
		<form:errors cssClass="errors" />
	</form:form>

	<h2>Remote Providers</h2>

	<c:if test="${ not empty successMessage }">
		<div class="alert alert-success">
			<button class="close" data-dismiss="alert" type="button">×</button>
			<c:out value="${ successMessage }"/>
		</div>
	</c:if>
	
	<%@ include file="/WEB-INF/views/errorMessage.jsp"%>
	
	<div id="helpText">
		Remote Providers are links to services which
		import vulnerability data into ThreadFix.
	</div>
	
	<div id="headerDiv">
		<%@ include file="/WEB-INF/views/config/remoteproviders/typesTable.jsp" %>
	</div>
	
	<c:set var="appsPresent" value="false"/>
	
	<c:forEach var="remoteProvider" items="${ remoteProviders }" varStatus="outerStatus">
		<c:if test="${ not empty remoteProvider.filteredApplications }">
			<c:set var="appsPresent" value="true"/>
			<spring:url value="/configuration/remoteproviders/{id}/clearConfiguration" htmlEscape="true" var="clearConfigUrl">
				<spring:param name="id" value="${ remoteProvider.id }"/>
			</spring:url>
			<form:form action="${ fn:escapeXml(clearConfigUrl) }">
				<h2 style="padding-top:15px"><c:out value="${ remoteProvider.name }"/> 
					Applications 
					<spring:url value="/configuration/remoteproviders/{id}/update" htmlEscape="true" var="updateUrl">
						<spring:param name="id" value="${ remoteProvider.id }"/>
					</spring:url>
					<a class="btn header-button" id="updateApps${ outerStatus.count }" style="font-size:60%;padding-left:10px;padding-right:8px;" href="${ fn:escapeXml(updateUrl) }">Update Applications</a>
					
					<c:if test="${ remoteProvider.hasConfiguredApplications }">
						<spring:url value="/configuration/remoteproviders/{id}/importAll" htmlEscape="true" var="importAllUrl">
							<spring:param name="id" value="${ remoteProvider.id }"/>
						</spring:url>
						<a class="btn header-button" id="updateApps${ outerStatus.count }" 
								style="font-size:60%;padding-left:10px;padding-right:8px;" 
								href="${ fn:escapeXml(importAllUrl) }">
							Import All Scans
						</a>
					</c:if>
					
					<c:if test="${ canManageRemoteProviders }">
						<button id="clearConfig${ outerStatus.count }" onclick="return confirm('Are you sure? This will clear your credentials and delete the apps in the table below.')" class="btn btn-primary" type="submit">Clear Configuration</button>
					</c:if>
				</h2>
			</form:form>
			<spring:url value="" var="emptyUrl"></spring:url>	
			<table class="table table-striped">
				<thead>
					<tr>
						<th class="long first">Name / ID</th>
						<th class="medium">Team</th>
						<th>Application</th>
						<c:if test="${ canManageRemoteProviders }">
							<th class="medium">Edit</th>
						</c:if>
						<th class="medium last">Import Scan</th>
					</tr>
				</thead>
				<tbody>
					<c:forEach var="remoteProviderApplication" items="${ remoteProvider.filteredApplications }" varStatus="innerStatus">
						<tr class="bodyRow">
							<td id="provider${ outerStatus.count }appid${ innerStatus.count }">
								<c:out value="${ remoteProviderApplication.nativeId }"/>
							</td>
							<td id="provider${ outerStatus.count }tfteamname${ innerStatus.count }">
								<c:if test="${ not empty remoteProviderApplication.application }">
									<spring:url value="/organizations/{teamId}" htmlEscape="true" var="teamUrl">
										<spring:param name="teamId" value="${ remoteProviderApplication.application.organization.id }"/>
									</spring:url>
									<a href="${ fn:escapeXml(teamUrl) }">
										<c:out value="${ remoteProviderApplication.application.organization.name }"/>
									</a>
								</c:if>
							</td>
							<td id="provider${ outerStatus.count }tfappname${ innerStatus.count }">
								<c:if test="${ not empty remoteProviderApplication.application }">
									<spring:url value="/organizations/{teamId}/applications/{appId}" htmlEscape="true" var="applicationUrl">
										<spring:param name="teamId" value="${ remoteProviderApplication.application.organization.id }"/>
										<spring:param name="appId" value="${ remoteProviderApplication.application.id }"/>
									</spring:url>
									<a href="${ fn:escapeXml(applicationUrl) }">
										<c:out value="${ remoteProviderApplication.application.name }"/>
									</a>
								</c:if>
							</td>
							<c:if test="${ canManageRemoteProviders }">
								<td>
									<spring:url value="/configuration/remoteproviders/{providerId}/apps/{appId}/edit" htmlEscape="true" var="editAppUrl">
										<spring:param name="providerId" value="${ remoteProvider.id }"/>
										<spring:param name="appId" value="${ remoteProviderApplication.id }"/>
									</spring:url>
									<a id="provider${ outerStatus.count }updateMapping${ innerStatus.count }" href="#remoteProviderApplicationMappingModal${ remoteProviderApplication.id }" role="button" class="btn" data-toggle="modal">Edit Mapping</a>
									<div id="remoteProviderApplicationMappingModal${ remoteProviderApplication.id }" class="modal hide fade" tabindex="-1"
											role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
										<%@ include file="/WEB-INF/views/config/remoteproviders/editMapping.jsp" %>
									</div>
								</td>
							</c:if>
							<td>
								<c:if test="${ not empty remoteProviderApplication.application }">
									<spring:url value="/configuration/remoteproviders/{providerId}/apps/{appId}/import" htmlEscape="true" var="editAppUrl">
										<spring:param name="providerId" value="${ remoteProvider.id }"/>
										<spring:param name="appId" value="${ remoteProviderApplication.id }"/>
									</spring:url>
									<a class="btn" id="provider${ outerStatus.count }import${ innerStatus.count }"href="${ fn:escapeXml(editAppUrl) }">Import</a>
								</c:if>
							</td>
						</tr>
					</c:forEach>
				</tbody>
			</table>
		</c:if>
	</c:forEach>
</body>
