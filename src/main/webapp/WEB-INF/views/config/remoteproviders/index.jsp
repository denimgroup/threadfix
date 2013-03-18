<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Remote Providers</title>
</head>

<body>
	<form:form modelAttribute="error" name="formErrors">
		<form:errors cssClass="errors" />
	</form:form>

	<h2>Remote Providers</h2>
	
	<spring:url value="/configuration" var="configUrl"/>
	<div style="padding-bottom:8px" >
		<a id="topBackLink" href="${ fn:escapeXml(configUrl) }">Back to Configuration Index</a>
	</div>
	<c:if test="${ not empty message }">
		<center class="errors" ><c:out value="${ message }"/></center>
	</c:if>
	
	<div id="helpText">
		Remote Providers are links to services which
		import vulnerability data into ThreadFix.
	</div>
	
	<c:if test="${ canManageRemoteProviders }">
		<table class="table auto table-striped">
			<thead>
				<tr>
					<th class="medium first">Name</th>
					<th class="medium">User name</th>
					<c:if test="${ not canManageRemoteProviders }">
						<th class="medium last">API Key</th>
					</c:if>
					<c:if test="${ canManageRemoteProviders }">
						<th class="medium">API Key</th>
						<th class="medium last">Configure</th>
					</c:if>
				</tr>
			</thead>
			<tbody id="remoteProvidersTableBody">
			<c:if test="${ empty remoteProviders }">
				<tr class="bodyRow">
					<td colspan="4" style="text-align:center;"> No providers found.</td>
				</tr>
			</c:if>
			<c:forEach var="provider" items="${ remoteProviders }" varStatus="status">
				<tr class="bodyRow">
					<td id="name${status.count }">
						<c:out value="${ provider.name }" />
					</td>
					<td id="username${status.count }">
						<c:if test="${ not empty provider.username }">
							<c:out value="${ provider.username }" />
						</c:if>
					</td>
					<td id="apiKey${status.count }">
						<c:if test="${ not empty provider.apiKey }">
							<c:out value="${ provider.apiKey }" />
						</c:if>
					</td>
					<c:if test="${ canManageRemoteProviders }">
					<td>
						<spring:url value="/configuration/remoteproviders/{id}/configure" htmlEscape="true" var="configUrl">
							<spring:param name="id" value="${ provider.id }"/>
						</spring:url>
						<a id="configure${status.count }" href="${ fn:escapeXml(configUrl) }">Configure</a>
					</td>
					</c:if>
				</tr>
			</c:forEach>
			</tbody>
		</table>
	</c:if>
	
	<c:set var="appsPresent" value="false"/>
	
	<c:forEach var="provider" items="${ remoteProviders }" varStatus="outerStatus">
		<c:if test="${ not empty provider.filteredApplications }">
			<c:set var="appsPresent" value="true"/>
			<spring:url value="/configuration/remoteproviders/{id}/clearConfiguration" htmlEscape="true" var="clearConfigUrl">
				<spring:param name="id" value="${ provider.id }"/>
			</spring:url>
			<form:form action="${ fn:escapeXml(clearConfigUrl) }">
				<h2 style="padding-top:15px"><c:out value="${ provider.name }"/> 
					Applications 
					<spring:url value="/configuration/remoteproviders/{id}/update" htmlEscape="true" var="updateUrl">
						<spring:param name="id" value="${ provider.id }"/>
					</spring:url>
					<a id="updateApps${ outerStatus.count }" style="font-size:60%;padding-left:10px;padding-right:8px;" href="${ fn:escapeXml(updateUrl) }">Update Apps</a>
					<c:if test="${ canManageRemoteProviders }">
						<button id="clearConfig${ outerStatus.count }" onclick="return confirm('Are you sure? This will clear your credentials and delete the apps in the table below.')" class="btn btn-primary" type="submit">Clear <c:out value="${ provider.name }"/> Configuration</button>
					</c:if>
				</h2>
			</form:form>
			<spring:url value="" var="emptyUrl"></spring:url>	
			<table class="table auto table-striped">
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
					<c:forEach var="application" items="${ provider.filteredApplications }" varStatus="innerStatus">
						<tr class="bodyRow">
							<td id="provider${ outerStatus.count }appid${ innerStatus.count }"><c:out value="${ application.nativeId }"/></td>
							<td id="provider${ outerStatus.count }tfteamname${ innerStatus.count }">
								<c:if test="${ not empty application.application }">
									<c:out value="${ application.application.organization.name }"/>
								</c:if>
							</td>
							<td id="provider${ outerStatus.count }tfappname${ innerStatus.count }">
								<c:if test="${ not empty application.application }">
									<c:out value="${ application.application.name }"/>
								</c:if>
							</td>
							<c:if test="${ canManageRemoteProviders }">
								<td>
									<spring:url value="/configuration/remoteproviders/{providerId}/apps/{appId}/edit" htmlEscape="true" var="editAppUrl">
										<spring:param name="providerId" value="${ provider.id }"/>
										<spring:param name="appId" value="${ application.id }"/>
									</spring:url>
									<a id="provider${ outerStatus.count }updateMapping${ innerStatus.count }" href="${ fn:escapeXml(editAppUrl) }">Edit Mapping</a>
								</td>
							</c:if>
							<td>
								<c:if test="${ not empty application.application }">
									<spring:url value="/configuration/remoteproviders/{providerId}/apps/{appId}/import" htmlEscape="true" var="editAppUrl">
										<spring:param name="providerId" value="${ provider.id }"/>
										<spring:param name="appId" value="${ application.id }"/>
									</spring:url>
									<a  id="provider${ outerStatus.count }import${ innerStatus.count }"href="${ fn:escapeXml(editAppUrl) }">Import</a>
								</c:if>
							</td>
						</tr>
					</c:forEach>
				</tbody>
			</table>
		</c:if>
	</c:forEach>
	<c:if test="${ appsPresent }">
		<div style="padding-top:8px" >
			<a id="bottomBackLink" href="${ fn:escapeXml(configUrl) }">Back to Configuration Index</a>
		</div>
	</c:if>
</body>
