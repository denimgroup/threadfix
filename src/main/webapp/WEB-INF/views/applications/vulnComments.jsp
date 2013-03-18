<%@ include file="/common/taglibs.jsp"%>

<h4>Comments</h4>
					
<c:if test="${ not empty vulnerability.vulnerabilityComments }">
	<table class="table table-striped">
		<thead>
			<tr>
				<th class="first"></th>
				<th>User</th>
				<th>Date</th>
				<th class="last">Comment</th>
			<tr>
		</thead>
		<tbody>
			<c:forEach var="comment" items="${ vulnerability.vulnerabilityComments }" varStatus="status">
				<tr class="bodyRow">
					<td id="commentNum${ status.count }"><c:out value="${ status.count }" /></td>
					<td id="commentUser${ status.count }"><c:out value="${ comment.user.name }" /></td>
					<td id="commentDate${ status.count }"><fmt:formatDate value="${ comment.time }"
							pattern="hh:mm:ss MM/dd/yyyy" /></td>
					<td id="commentText${ status.count }"><c:out value="${ comment.comment }" /></td>
				</tr>
			</c:forEach>
		</tbody>
	</table>
</c:if>
<%@include file="/WEB-INF/views/applications/modals/vulnCommentModal.jsp"%>