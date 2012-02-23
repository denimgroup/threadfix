<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Remote Providers</title>
</head>

<body>
	<form:form modelAttribute="error" name="formErrors">
		<form:errors cssClass="errors" />
	</form:form>

	<h2>Remote Providers</h2>
	
	<div id="helpText">
		Remote Providers are links to services which
		import vulnerability data into ThreadFix.
	</div>

	<table class="formattedTable">
		<thead>
			<tr>
				<th class="medium first">Name</th>
				<th class="medium">User name</th>
				<th class="medium last">Configure</th>
			</tr>
		</thead>
		<tbody id="remoteProvidersTableBody">
		<c:if test="${ empty remoteProviders }">
			<tr class="bodyRow">
				<td colspan="5" style="text-align:center;"> No providers found.</td>
			</tr>
		</c:if>
		<c:forEach var="provider" items="${ remoteProviders }">
			<tr class="bodyRow">
				<td>
					<c:out value="${ provider.name }" />
				</td>
				<td>
					<c:if test="${ not empty provider.username }">
						<c:out value="${ provider.username }" />
					</c:if>
				</td>
				<td>
					<spring:url value="/configuration/remoteproviders/{id}/configure" htmlEscape="true" var="configUrl">
						<spring:param name="id" value="${ provider.id }"/>
					</spring:url>
					<a href="${ fn:escapeXml(configUrl) }">Configure</a>
				</td>
			</tr>
		</c:forEach>
		</tbody>
	</table>
	
	<c:forEach var="provider" items="${ remoteProviders }">
		<c:if test="${ not empty provider.remoteProviderApplications }">
			<spring:url value="/configuration/remoteproviders/{id}/update" htmlEscape="true" var="updateUrl">
				<spring:param name="id" value="${ provider.id }"/>
			</spring:url>
			<h2 style="padding-top:15px"><c:out value="${ provider.name }"/> 
				Applications 
				<a style="font-size:60%;padding-left:10px;" href="${ fn:escapeXml(updateUrl) }">Update Apps</a>
			</h2>
			<spring:url value="" var="emptyUrl"></spring:url>	
			<table class="formattedTable">
				<thead>
					<tr>
						<th class="long first">Name / ID</th>
						<th class="medium">Team</th>
						<th>Application</th>
						<th class="medium">Edit</th>
						<th class="medium last">Import Scan</th>
					</tr>
				</thead>
				<tbody>
					<c:forEach var="application" items="${ provider.remoteProviderApplications }">
						<tr class="bodyRow">
							<td><c:out value="${ application.nativeId }"/></td>
							<td>
								<c:if test="${ not empty application.application }">
									<c:out value="${ application.application.organization.name }"/>
								</c:if>
							</td>
							<td>
								<c:if test="${ not empty application.application }">
									<c:out value="${ application.application.name }"/>
								</c:if>
							</td>
							<td>
								<spring:url value="/configuration/remoteproviders/{providerId}/apps/{appId}/edit" htmlEscape="true" var="editAppUrl">
									<spring:param name="providerId" value="${ provider.id }"/>
									<spring:param name="appId" value="${ application.id }"/>
								</spring:url>
								<a href="${ fn:escapeXml(editAppUrl) }">Edit Mapping</a>
							</td>
							<td>
								<c:if test="${ not empty application.application }">
									<spring:url value="/configuration/remoteproviders/{providerId}/apps/{appId}/import" htmlEscape="true" var="editAppUrl">
										<spring:param name="providerId" value="${ provider.id }"/>
										<spring:param name="appId" value="${ application.id }"/>
									</spring:url>
									<a href="${ fn:escapeXml(editAppUrl) }">Import</a>
								</c:if>
							</td>
						</tr>
					</c:forEach>
				</tbody>
			</table>
		</c:if>
	</c:forEach>
</body>