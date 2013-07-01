<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Scan Queue</title>
</head>

<body>
	<h2>Scan Queue</h2>
	
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
				</tr>
			</thead>
			<tbody>
				<c:forEach items="${scanQueueTaskList}" var="scanQueueTask"> 
					<tr>
						<td><c:out value="${scanQueueTask.id}" /></td> 
						<td><c:out value="${scanQueueTask.application.name}" /></td>
						<td><c:out value="${scanQueueTask.status}" /></td>
						<td><c:out value="${scanQueueTask.scanner}" /></td>
						<td><fmt:formatDate value="${ scanQueueTask.createTime }" type="both" dateStyle="short" timeStyle="short" /></td>
						<td><fmt:formatDate value="${ scanQueueTask.startTime }" type="both" dateStyle="short" timeStyle="short" /></td>
						<td><fmt:formatDate value="${ scanQueueTask.endTime }" type="both" dateStyle="short" timeStyle="short" /></td>					
					</tr>
				
				</c:forEach>
			</tbody>

		</table>
	</div>
	
	<br/>
	
</body>
