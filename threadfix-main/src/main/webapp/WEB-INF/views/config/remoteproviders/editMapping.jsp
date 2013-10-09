<%@ include file="/common/taglibs.jsp"%>

<spring:url value="/configuration/remoteproviders/{typeId}/apps/{appId}/edit" var="saveUrl">
	<spring:param name="typeId" value="${ remoteProviderApplication.remoteProviderType.id }"/>
	<spring:param name="appId" value="${ remoteProviderApplication.id }"/>
</spring:url>
<spring:url value="/configuration/remoteproviders/{typeId}/apps/{rpAppId}/delete/{appId}" var="deleteUrl">
	<spring:param name="typeId" value="${ remoteProviderApplication.remoteProviderType.id }"/>
	<spring:param name="rpAppId" value="${ remoteProviderApplication.id }"/>
	<spring:param name="appId" value="${ remoteProviderApplication.application.id }"/>
</spring:url>

<div class="modal-header">
	<h4 id="myModalLabel">Edit Mapping for <c:out value="${ remoteProviderApplication.nativeId }"/>
		<c:if test="${ not empty remoteProviderApplication.application.id}"> 
			<span class="delete-span">
				<a class="btn btn-danger header-button deleteLink" 
						id="deleteLink${ remoteProviderApplication.id }" 
						href="#"
						data-error-div="remoteProviderApplicationMappingModal${ remoteProviderApplication.id }"
						data-url="${ fn:escapeXml(deleteUrl) }"
						onclick="return confirm('Are you sure you want to delete the mapping?')">
					Delete
				</a>
			</span>
		</c:if>	
	</h4>
</div>

<form:form id="remoteProviderApplicationForm${ remoteProviderApplication.id }" modelAttribute="remoteProviderApplication" action="${ fn:escapeXml(saveUrl) }">

	<div class="modal-body">
		<%@ include file="/WEB-INF/views/errorMessage.jsp"%>
		<table style="border-spacing:10" class="dataTable">
			<tbody>
				<tr>
					<td class="no-color">Team</td>
					<td class="no-color">
						<form:select path="application.organization.id" id="orgSelect${ remoteProvider.id }-${ innerStatus.count }"
								class="selectFiller"
								data-select-target="appSelect${ remoteProvider.id }-${ innerStatus.count }"
								data-selected-value="${ remoteProviderApplication.application.id }">
							<c:set var="optionsBase" value="[{\"id\":\"do-not-use\", \"name\":\"\"}"/>
							<option value="-1">Pick a Team</option>
							<c:forEach var="organization" items="${ organizationList }">
								<c:if test="${ organization.active and not empty organization.applications}">
									<c:set var="options" value="${ optionsBase }"/>
									<c:set var="quote" value="\""/>
									<c:forEach var="application" items="${ organization.activeApplications}">
										<c:set var="options" value="${options},{${ quote }id${ quote }:${ quote }${ application.id }${ quote }, ${ quote }name${ quote }:${ quote }${ application.name }${ quote }}"/>
									</c:forEach>
									<c:set var="options" value="${options}]"/>
									
										<option value="${ organization.id }" data-select-items="<c:out value="${ options }"/>"
										<c:if test="${ organization.id == remoteProviderApplication.application.organization.id }">
											selected=selected
										</c:if>
									>
										<c:out value="${ organization.name }"/>
									</option>
								</c:if>
							</c:forEach>
						</form:select>
					</td>
					<td class="no-color" style="padding-left:5px">
						<form:errors path="application.organization.id" cssClass="errors" />
					</td>
				</tr>
				<tr>
					<td class="no-color" style="padding-right:10px">Application</td>
					<td class="no-color">
						<form:select path="application.id" id="appSelect${ remoteProvider.id }-${ innerStatus.count }">
							<option value="-1"></option>
							
						</form:select>
					</td>
					<td class="no-color" style="padding-left:5px">
						<form:errors path="application.id" cssClass="errors" />
					</td>
				</tr>
			</tbody>
		</table>
	</div>
	<div class="modal-footer">
		<button class="btn" data-dismiss="modal" aria-hidden="true">Close</button>
		<a id="submitRemoteProviderFormButton" class="modalSubmit btn btn-primary" data-success-div="headerDiv">
			Update Application</a>
	</div>
</form:form>
