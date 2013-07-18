<%@ include file="/common/taglibs.jsp"%>

<ul class="breadcrumb">
    <li><a href="<spring:url value="/"/>">Applications Index</a> <span class="divider">/</span></li>
    <li><a href="${ fn:escapeXml(orgUrl) }">Team: <c:out value="${ application.organization.name }"/></a> <span class="divider">/</span></li>
    <li class="active">Application: <c:out value="${ application.name }"/></li>
</ul>

<h2 style="padding-bottom:5px;">
	<span id="nameText" style="max-width:400px; display:inline-block" class="ellipsis"><c:out value="${ application.name }"/></span>
	<a class="btn header-button" id="editApplicationModalButton" href="#editApplicationModal" 
			role="button" data-toggle="modal">
		Edit / Delete
	</a>
	
	<c:if test="${ canUploadScans }">
		<span style="float:right">
			<a id="uploadScanModalLink" href="#uploadScan${ application.id }" role="button" class="btn header-button" data-toggle="modal">Upload Scan</a>
			<a id="addManualFindingModalLink" href="#addManualFindingModal" role="button" class="btn header-button" data-toggle="modal">Add Manual Finding</a>
			
			<c:if test="${ not empty application.defectTracker }">
				<spring:url value="/organizations/{orgId}/applications/{appId}/defects/update" var="updateDefectUrl">
					<spring:param name="orgId" value="${ application.organization.id }"/>
					<spring:param name="appId" value="${ application.id }"/>
				</spring:url>
				<a id="updateDefectsLink" href="${ fn:escapeXml(updateDefectUrl) }" role="button" 
						class="btn header-button">
					Update Defect Status
				</a>
			</c:if>
		</span>
	</c:if>
</h2>

<%@ include file="/WEB-INF/views/applications/modals/uploadScanModal.jsp" %>
<%@ include file="/WEB-INF/views/applications/modals/manualFindingModal.jsp" %>

<div id="editApplicationModal" class="modal hide fade" tabindex="-1"
	role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
	<div id="editAppFormDiv">
		<%@ include file="/WEB-INF/views/applications/forms/editApplicationForm.jsp" %>
	</div>
</div> 

<%@ include file="/WEB-INF/views/successMessage.jspf" %>

<%@ include file="/WEB-INF/views/errorMessage.jsp"%>
