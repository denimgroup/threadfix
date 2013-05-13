<%@ include file="/common/taglibs.jsp"%>

<spring:url value="/organizations/{orgId}/applications/{applicationId}/vulnerabilities/{vulnerabilityId}/addComment" var="commentUrl">
	<spring:param name="orgId" value="${ application.organization.id }" />
	<spring:param name="applicationId" value="${ application.id }" />
	<spring:param name="vulnerabilityId" value="${ vulnerability.id }" />
</spring:url>
<form id="addCommentForm${ vulnerability.id }" method="post" action="${ fn:escapeXml(commentUrl) }">
	<div class="modal-body">
		<span class="errors"><c:out value="${ commentError }"/></span><br>
		<span style="display:none" id="lengthError${ vulnerability.id }" class="errors">Maximum length is 200 characters.</span><br>
		Comment:
		<textarea style="margin:10px;width: 497px; height: 215px;" 
			class="textbox clear-after-submit" 
			id="commentInputBox"
			data-max-length="200"
			data-error="lengthError${ vulnerability.id }"
			name="comments"></textarea>
	</div>
	<div class="modal-footer">
		<button id="closeCommentForm${ vulnerability.id }" class="btn" data-dismiss="modal" aria-hidden="true">Close</button>
		<button class="modalSubmit btn btn-primary" data-success-div="commentDiv${ vulnerability.id }" 
				id="addCommentButton${ vulnerability.id }" type="button">Add Comment</button>
	</div>
</form>
