<%@ include file="/common/taglibs.jsp"%>
<spring:url value="/organizations/{orgId}" var="orgUrl">
	<spring:param name="orgId" value="${ application.organization.id }"/>
</spring:url>
<ul class="breadcrumb">
    <li><a href="<spring:url value="/"/>">Applications Index</a> <span class="divider">/</span></li>
    <li><a href="${ fn:escapeXml(orgUrl) }">Team: <c:out value="${ application.organization.name }"/></a> <span class="divider">/</span></li>
    <li class="active">Application: <c:out value="${ application.name }"/></li>
</ul>
<div>
<h2 style="padding-bottom:5px;line-height:1">

	<span id="nameText" style="padding-top:5px;"><c:out value="${ application.name }"/></span>
<c:if test="${ not empty canManageApplications }">
	<div id="btnDiv1" class="btn-group">
		<button id="actionButton1" class="btn dropdown-toggle" data-toggle="dropdown" type="button">Action <span class="caret"></span></button>
			<ul class="dropdown-menu">		
				<c:if test="${canManageApplications }">
					<li><a id="editApplicationModalButton" href="#editApplicationModal" data-toggle="modal">Edit / Delete</a></li>
					
				</c:if>
				<c:if test="${canManageApplications }">
					<spring:url value="/organizations/{orgId}/applications/{appId}/filters" var="vulnFiltersUrl">
						<spring:param name="orgId" value="${ application.organization.id }"/>
						<spring:param name="appId" value="${ application.id }"/>
					</spring:url>
					<li><a id="editVulnerabilityFiltersButton" href="<c:out value="${ vulnFiltersUrl }"/>" data-toggle="modal">Edit Vulnerability Filters</a></li>
				</c:if>
				<c:if test="${!canManageApplications }">
					<li><a id="viewApplicationModalButton" href="#viewApplicationModal" data-toggle="modal">Details	</a></li>
				</c:if>
				<c:if test="${ canManageUsers && enterprise}">				
					<li><a id="userListModelButton" href="#usersModal" data-toggle="modal">View Permissible Users</a></li>
				</c:if>
				<c:if test="${ canUploadScans }">
					<li><a id="uploadScanModalLink" href="#uploadScan${ application.id }" data-toggle="modal">Upload Scan</a></li>
					<li><a id="addManualFindingModalLink" href="#addManualFindingModal" data-toggle="modal">Add Manual Finding</a></li>
					<c:if test="${ not empty application.defectTracker }">
						<spring:url value="/organizations/{orgId}/applications/{appId}/defects/update" var="updateDefectUrl">
							<spring:param name="orgId" value="${ application.organization.id }"/>
							<spring:param name="appId" value="${ application.id }"/>
						</spring:url>
						<li><a id="updateDefectsLink" href="${ fn:escapeXml(updateDefectUrl) }">
							Update Defect Status
						</a></li>
					</c:if>
				</c:if>					
			</ul>
	</div>
</c:if>

</h2>
</div>
<%@ include file="/WEB-INF/views/applications/modals/uploadScanModal.jsp" %>
<%@ include file="/WEB-INF/views/applications/modals/manualFindingModal.jsp" %>
<%@ include file="/WEB-INF/views/applications/modals/scanParametersModal.jsp" %>

<div id="editApplicationModal" class="modal hide fade" tabindex="-1"
	role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
	<div id="editAppFormDiv">
		<%@ include file="/WEB-INF/views/applications/forms/editApplicationForm.jsp" %>
	</div>
</div> 
<div id="viewApplicationModal" class="modal hide fade" tabindex="-1"
	role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
	<div id="viewAppFormDiv">
		<%@ include file="/WEB-INF/views/applications/forms/viewApplicationForm.jsp" %>
	</div>
</div>
<div id="usersModal" class="modal hide fade" tabindex="-1"
		role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
		<div id="editFormDiv">
			<%@ include file="/WEB-INF/views/config/users/permissibleUsers.jsp" %>
		</div>
</div>
<%@ include file="/WEB-INF/views/successMessage.jspf" %>

<%@ include file="/WEB-INF/views/errorMessage.jsp"%>
