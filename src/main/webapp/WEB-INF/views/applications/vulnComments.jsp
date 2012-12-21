<%@ include file="/common/taglibs.jsp"%>

<body>
	<h3>Comments</h3>

	<c:if test="${ not empty comments }">
		<table class="formattedTable">
			<thead>
				<tr>
					<th class="first"></th>
					<th>User</th>
					<th>Date</th>
					<th class="last">Comment</th>
				<tr>
			</thead>
			<tbody>
				<c:forEach var="comment" items="${comments}" varStatus="status">
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
	
	<spring:url value="../../../applications/{applicationId}/vulnerabilities/{vulnerabilityId}/addComment" var="commentUrl">
		<spring:param name="applicationId" value="${ vulnerability.application.id }" />
		<spring:param name="vulnerabilityId" value="${ vulnerability.id }" />
	</spring:url>
	<form id="addCommentForm" method="post" action="${ fn:escapeXml(commentUrl) }">
		<textarea style="margin-top:10px" id="commentInputBox" name="comments"></textarea> <span class="errors"><c:out value="${ commentError }"/></span> <br/>
		<input onclick="javascript:addComment('${ fn:escapeXml(commentUrl) }');return false;" style="margin-top:8px" id="addCommentButton" type="button" value="Add Comment" />
	</form>
</body>