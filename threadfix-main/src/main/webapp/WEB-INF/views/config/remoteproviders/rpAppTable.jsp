<%@ include file="/common/taglibs.jsp"%>

	<div id="errorDiv"></div>
 	<spring:url value="/login.jsp" var="loginUrl"/>
	
	<spring:url value="/configuration/remoteproviders/{id}/table" var="tableUrl">
		<spring:param name="id" value="${ remoteProvider.id }"/>
	</spring:url>
	
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

		<c:if test="${ numPages > 1 }">
			<div class="pagination">
			<ul style="vertical-align:middle">
			<c:if test="${ page > 4 }">
				<li>
					<a href="javascript:refillElement('#toReplace${ remoteProvider.id }', '${tableUrl}', 1, '<c:out value="${ loginUrl }"/>')">First</a>
				</li>
			</c:if>
		
			<c:if test="${ page >= 4 }">
				<li>
					<a href="javascript:refillElement('#toReplace${ remoteProvider.id }', '${tableUrl}', ${ page - 3 }, '<c:out value="${ loginUrl }"/>')"><c:out value="${ page - 3 }"/></a>
				</li>
			</c:if>
		
			<c:if test="${ page >= 3 }">
				<li>
					<a href="javascript:refillElement('#toReplace${ remoteProvider.id }', '${tableUrl}', ${ page - 2 }, '<c:out value="${ loginUrl }"/>')"><c:out value="${ page - 2 }"/></a>
				</li>
			</c:if>
			
			<c:if test="${ page >= 2 }">
				<li>
					<a href="javascript:refillElement('#toReplace${ remoteProvider.id }', '${tableUrl}', ${ page - 1 }, '<c:out value="${ loginUrl }"/>')"><c:out value="${ page - 1 }"/></a>
				</li>
			</c:if>
			
			<li class="active"><a href="#"><c:out value="${ page }"/></a></li>
		
			<c:if test="${ page <= numPages}">
				<li>
					<a href="javascript:refillElement('#toReplace${ remoteProvider.id }', '${tableUrl}', ${ page + 1 }, '<c:out value="${ loginUrl }"/>')"><c:out value="${ page + 1 }"/></a>
				</li>
			</c:if>
			
			<c:if test="${ page <= numPages - 1 }">
				<li>
					<a href="javascript:refillElement('#toReplace${ remoteProvider.id }', '${tableUrl}', ${ page + 2 }, '<c:out value="${ loginUrl }"/>')"><c:out value="${ page + 2 }"/></a>
				</li>
			</c:if>
			
			<c:if test="${ page <= numPages - 2 }">
				<li>
					<a href="javascript:refillElement('#toReplace${ remoteProvider.id }', '${tableUrl}', ${ page + 3 }, '<c:out value="${ loginUrl }"/>')"><c:out value="${ page + 3 }"/></a>
				</li>
			</c:if>
			
			<c:if test="${ page < numPages - 2 }">
				<li>
					<a href="javascript:refillElement('#toReplace${ remoteProvider.id }', '${tableUrl}', ${ numPages + 1 }, '<c:out value="${ loginUrl }"/>')">Last (<c:out value="${ numPages + 1}"/>)</a>
				</li>
			</c:if>
			</ul>
		
			<input class="refillElementOnEnter" type="text" id="pageInput" />
			<a href="javascript:refillElementDropDownPage('#toReplace${ remoteProvider.id }', '${ tableUrl }', '<c:out value="${ loginUrl }"/>')">Go to page</a>
		</div>
	
	</c:if>
			
			<table class="table table-striped" style="table-layout:fixed;">
				<thead>
					<tr>
						<th class="medium first">Name / ID</th>
						<th class="medium">Team</th>
						<th class="medium">Application</th>
						<c:if test="${ canManageRemoteProviders }">
							<th class="medium">Edit</th>
						</c:if>
						<th class="medium last">Import Scan</th>
					</tr>
				</thead>
				<tbody>
				
					<c:forEach var="remoteProviderApplication" items="${ remoteProvider.filteredApplications }" varStatus="innerStatus">
						<tr>
							<td id="provider${ remoteProvider.id }appid${ innerStatus.count }">
								<c:out value="${ remoteProviderApplication.nativeId }"/>
							</td>
							<td id="provider${ remoteProvider.id }tfteamname${ innerStatus.count }">
								<c:if test="${ not empty remoteProviderApplication.application }">
									<spring:url value="/organizations/{teamId}" htmlEscape="true" var="teamUrl">
										<spring:param name="teamId" value="${ remoteProviderApplication.application.organization.id }"/>
									</spring:url>
									<div style="word-wrap: break-word;max-width:170px;text-align:left;"><a href="${ fn:escapeXml(teamUrl) }">
										<c:out value="${ remoteProviderApplication.application.organization.name }"/>
									</a></div>
								</c:if>
							</td>
							<td id="provider${ remoteProvider.id }tfappname${ innerStatus.count }">
								<c:if test="${ not empty remoteProviderApplication.application }">
									<spring:url value="/organizations/{teamId}/applications/{appId}" htmlEscape="true" var="applicationUrl">
										<spring:param name="teamId" value="${ remoteProviderApplication.application.organization.id }"/>
										<spring:param name="appId" value="${ remoteProviderApplication.application.id }"/>
									</spring:url>
									<div style="word-wrap: break-word;max-width:170px;text-align:left;"><a href="${ fn:escapeXml(applicationUrl) }">
										<c:out value="${ remoteProviderApplication.application.name }"/>
									</a></div>
								</c:if>
							</td>
							<c:if test="${ canManageRemoteProviders }">
								<td>
									<spring:url value="/configuration/remoteproviders/{providerId}/apps/{appId}/edit" htmlEscape="true" var="editAppUrl">
										<spring:param name="providerId" value="${ remoteProvider.id }"/>
										<spring:param name="appId" value="${ remoteProviderApplication.id }"/>
									</spring:url>
									<a id="provider${ remoteProvider.id }updateMapping${ innerStatus.count }" href="#remoteProviderApplicationMappingModal${ remoteProviderApplication.id }" role="button" class="btn" data-toggle="modal">Edit Mapping</a>
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
									<a class="btn" id="provider${ remoteProvider.id }import${ innerStatus.count }"href="${ fn:escapeXml(editAppUrl) }">Import</a>
								</c:if>
							</td>
						</tr>
					</c:forEach>
				</tbody>
			</table>
		</c:if>
