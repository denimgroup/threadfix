<%@ include file="/common/taglibs.jsp"%>

<ul class="breadcrumb">
    <li><a href="<spring:url value="/"/>">Teams</a> <span class="divider">/</span></li>
    <li><a href="${ fn:escapeXml(orgUrl) }"><c:out value="${ application.organization.name }"/></a> <span class="divider">/</span></li>
    <li class="active"><c:out value="${ application.name }"/></li>
</ul>

<h2 style="padding-bottom:5px;">
	
	<span id="nameText"><c:out value="${ application.name }"/></span>
	<a class="btn header-button" id="showDetailsLink" href="#" data-toggle="collapse" data-target="#appInfoDiv">
		Show More
	</a>
	
	<c:if test="${ canUploadScans }">
		<span style="float:right">
			<a id="uploadScanModalLink" href="#uploadScan${ application.id }" role="button" class="btn header-button" data-toggle="modal">Upload Scan</a>
			<a id="addManualFindingModalLink" href="#addManualFindingModal" role="button" class="btn header-button" data-toggle="modal">Add Manual Finding</a>
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
