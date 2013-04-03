<%@ include file="/common/taglibs.jsp"%>

<spring:url value="/organizations/{orgId}/applications/{applicationId}/vulnerabilities/{vulnerabilityId}/addComment" var="commentUrl">
	<spring:param name="orgId" value="${ application.organization.id }" />
	<spring:param name="applicationId" value="${ application.id }" />
	<spring:param name="vulnerabilityId" value="${ vulnerability.id }" />
</spring:url>
<form id="addCommentForm${ vulnerability.id }" method="post" action="${ fn:escapeXml(commentUrl) }">
	<div class="modal-body">
		<span class="errors"><c:out value="${ commentError }"/></span><br>
		Comment:
		<textarea style="margin:10px;width: 497px; height: 215px;" class="textbox focus" id="commentInputBox" name="comments"></textarea>
	</div>
	<div class="modal-footer">
		<button id="closeCommentForm${ vulnerability.id }" class="btn" data-dismiss="modal" aria-hidden="true">Close</button>
		<button class="btn btn-primary" onclick="javascript:submitAjaxModal('${ fn:escapeXml(commentUrl) }', '#addCommentForm${ vulnerability.id }', '#commentFormDiv${ vulnerability.id }', '#commentDiv${ vulnerability.id }', '#commentModal${ vulnerability.id }');return false;" id="addCommentButton${ vulnerability.id }" type="button">Add Comment</button>
	</div>
</form>
<script>
$("#addCommentForm<c:out value='vulnerability.id'/>").keypress(function(e){
    if (e.which == 13){
        $("#addCommentButton<c:out value='vulnerability.id'/>").click();
    }
});
</script>
