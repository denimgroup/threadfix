<%@ include file="/common/taglibs.jsp"%>

<table class="table">
	<thead>
		<tr>
			<th class="first"></th>
			<th>User</th>
			<th>Date</th>
			<th class="last">Comment</th>
		<tr>
	</thead>
	<tbody>
		<c:if test="${ empty vulnerability.vulnerabilityComments }">
			<tr class="bodyRow">
				<td colspan="4" style="text-align:center;">No comments found.</td>
			</tr>
		</c:if>
	
		<c:forEach var="comment" items="${ vulnerability.vulnerabilityComments }" varStatus="status">
			<tr class="bodyRow left-align">
				<td id="commentNum${ status.count }"><c:out value="${ status.count }" /></td>
				<td id="commentUser${ status.count }"><c:out value="${ comment.user.name }" /></td>
				<td id="commentDate${ status.count }"><fmt:formatDate value="${ comment.time }"
						pattern="hh:mm:ss MM/dd/yyyy" /></td>
				<td id="commentText${ status.count }">
					<div class="vuln-comment-word-wrap">
						<c:out value="${ comment.comment }" />
					</div>
				</td>
			</tr>
		</c:forEach>
	</tbody>
</table>

