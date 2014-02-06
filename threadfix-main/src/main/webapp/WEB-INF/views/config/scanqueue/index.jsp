<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Scan Agent Tasks</title>
    <script type="text/javascript" src="<%=request.getContextPath()%>/scripts/scan_page.js"></script>
</head>

<body>
	<h2>Scan Agent Tasks</h2>

    <c:if test="${ not empty successMessage }">
        <div class="alert alert-success">
            <button class="close" data-dismiss="alert" type="button">x</button>
            <c:out value="${ successMessage }"/>
        </div>
    </c:if>

    <%@ include file="/WEB-INF/views/errorMessage.jsp"%>

	<div id="helpText">
		The scan queue is a list of scans ThreadFix has been asked to coordinate.<br/>
	</div>
	
	<div id="tableDiv">
		<table class="table">
			<thead>
				<tr>
					<th>ID</th>
					<th>Application</th>
					<th>Status</th>
					<th>Scanner</th>
					<th>Created Time</th>
					<th>Start Time</th>
					<th>End Time</th>
                    <security:authorize ifAnyGranted="ROLE_CAN_MANAGE_APPLICATIONS">
                        <th class="centered last"></th>
                    </security:authorize>
				</tr>
			</thead>
			<tbody>
				<c:forEach items="${scanQueueTaskList}" var="scanQueueTask"> 
					<tr>
						<td>
							<spring:url value="/configuration/scanqueue/{scanQueueTaskId}/detail" var="detailUrl">
								<spring:param name="scanQueueTaskId" value="${ scanQueueTask.id }" />
							</spring:url>
							<a href='<c:out value="${detailUrl}" />'><c:out value="${scanQueueTask.id}" />
							</a>
						</td>
						<td id="application${ status.count }">
							<spring:url	value="/organizations/{teamId}/applications/{appId}" var="appUrl">
								<spring:param name="teamId"	value="${ scanQueueTask.application.organization.id }" />
								<spring:param name="appId" value="${ scanQueueTask.application.id }" />
							</spring:url> 
							<div style="word-wrap: break-word;max-width:130px;text-align:left;"> <a href="<c:out value="${ appUrl }"/>"> 
								<c:out	value="${ scanQueueTask.application.name }" />
							</a></div>
						</td>						
						<td><c:out value="${scanQueueTask.showStatusString()}" /></td>
						<td><c:out value="${scanQueueTask.scanner}" /></td>
						<td><fmt:formatDate value="${ scanQueueTask.createTime }" type="both" dateStyle="short" timeStyle="short" /></td>
						<td><fmt:formatDate value="${ scanQueueTask.startTime }" type="both" dateStyle="short" timeStyle="short" /></td>
						<td><fmt:formatDate value="${ scanQueueTask.endTime }" type="both" dateStyle="short" timeStyle="short" /></td>
                        <security:authorize ifAnyGranted="ROLE_CAN_MANAGE_APPLICATIONS">
                            <td class="centered">
                                <spring:url value="/configuration/scanqueue/scanQueueTask/{taskId}/delete" var="deleteUrl">
                                    <spring:param name="taskId" value="${ scanQueueTask.id }"/>
                                </spring:url>
                                <a class="btn btn-danger scanQueueDelete" data-delete-form="deleteForm${ scanQueueTask.id }">Delete</a>
                                <form id="deleteForm${ scanQueueTask.id }" method="POST" action="${ fn:escapeXml(deleteUrl) }"></form>
                            </td>
                        </security:authorize>
                    </tr>
				
				</c:forEach>
			</tbody>

		</table>
	</div>
	
	<br/>
	
</body>
