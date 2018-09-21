<%@ include file="/common/taglibs.jsp"%>

<a href="#commentModal${ vulnerability.id }" role="button" class="btn margin-bottom" data-toggle="modal">Add Comment</a>
<div id="commentModal${ vulnerability.id }" class="modal hide fade" tabindex="-1"
     role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
    <div id="commentFormDiv${ vulnerability.id }">
        <%@ include file="/WEB-INF/views/applications/forms/vulnCommentForm.jsp" %>
    </div>
</div>