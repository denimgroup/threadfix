<%@ include file="/common/taglibs.jsp"%>

	<c:if test="${ canManageApplications }">
		<div style="margin-top:10px;margin-bottom:7px;">
			<a id="uploadDocModalLink${ application.id }" href="#uploadDoc${ application.id }" role="button" class="btn" data-toggle="modal">Upload</a>
			<%@ include file="/WEB-INF/views/applications/modals/uploadDocModal.jsp" %>
		</div>	
	</c:if>
	
<table class="table table-striped">
	<thead>
		<tr>
			<th class="first">File Name</th>
			<th>Type</th>
			<th>Upload Date</th>
			<th class="centered">Download</th>
			<c:if test="${ canManageApplications }">
				<th class="centered last">Delete</th>
			</c:if>
			<th></th>
		</tr>
	</thead>
	<tbody id="wafTableBody">
	<c:if test="${ empty application.documents }">
		<tr class="bodyRow">
			<td colspan="5" style="text-align:center;">No documents found.</td>
		</tr>
	</c:if>
	<c:forEach var="document" items="${ application.documents }" varStatus="status">
		<tr class="bodyRow">
			<td id="docName${ status.count }"><c:out value="${ document.name }"/></td>
			<td id="type${ status.count }" ><c:out value="${ document.type }"/></td>
			<td id="uploadDate${ status.count }" >
				<fmt:formatDate value="${ document.createdDate }" type="both" dateStyle="short" timeStyle="short"/>
			</td>
			<td class="centered">
				<spring:url value="/organizations/{orgId}/applications/{appId}/documents/{docId}/download" var="downloadUrl">
					<spring:param name="orgId" value="${ document.application.organization.id }"/>
					<spring:param name="appId" value="${ document.application.id }"/>
					<spring:param name="docId" value="${ document.id }"/>
				</spring:url>
                <a class="btn docDownload" data-download-form="downloadForm${ document.id }">Download</a>
				<form id="downloadForm${ document.id }" method="POST" action="${ fn:escapeXml(downloadUrl) }"></form>
			</td>			
			<c:if test="${ canManageApplications }">
			<td class="centered">
				<spring:url value="/organizations/{orgId}/applications/{appId}/documents/{docId}/delete" var="deleteUrl">
					<spring:param name="orgId" value="${ document.application.organization.id }"/>
					<spring:param name="appId" value="${ document.application.id }"/>
					<spring:param name="docId" value="${ document.id }"/>
				</spring:url>
                <a class="btn btn-danger docDelete" data-delete-form="deleteForm${ document.id }">Delete</a>
				<form id="deleteForm${ document.id }" method="POST" action="${ fn:escapeXml(deleteUrl) }"></form>				
			</td>
			</c:if>
			<td>
				<spring:url value="/organizations/{orgId}/applications/{appId}/documents/{docId}/view" var="viewUrl">
					<spring:param name="orgId" value="${ document.application.organization.id }"/>
					<spring:param name="appId" value="${ document.application.id }"/>
					<spring:param name="docId" value="${ document.id }"/>
				</spring:url>
				<a href="<c:out value="${ viewUrl }"/>" target="_blank">View Document</a>
			</td>
		</tr>
	</c:forEach>
	</tbody>
</table>
