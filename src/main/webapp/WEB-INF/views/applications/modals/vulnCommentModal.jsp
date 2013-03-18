<%@ include file="/common/taglibs.jsp"%>

<a href="#commentModal${ vulnerability.id }" role="button" class="btn form-bottom" data-toggle="modal">Add Comment</a>
<div id="commentModal${ vulnerability.id }" class="modal hide fade" tabindex="-1"
	role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
	<div class="modal-header">
		<button type="button" class="close" data-dismiss="modal"
			aria-hidden="true">X</button>
		<h4 id="myModalLabel">Add Comment</h4>
	</div>
	<div id="commentFormDiv${ vulnerability.id }">
		<%@ include file="/WEB-INF/views/applications/forms/vulnCommentForm.jsp" %>
	</div>
</div>