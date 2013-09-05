<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Scan Queue Item</title>
</head>

<body>
	<h2>Scan Queue Item</h2>
	
	<div id="helpText">
		This shows detail about a specific queued scan.<br/>
	</div>
	
	<div id="tableDiv">
	
	Task ID: <c:out value="${scanQueueTask.id}" />
	
		<table class="table">
			<thead>
				<tr>
					<th>Timestamp</th>
					<th>Message</th>
				</tr>
			</thead>
			<tbody>
				<c:forEach items="${scanQueueTask.scanStatuses}" var="scanStatus"> 
					<tr>
						<td><fmt:formatDate value="${ scanStatus.timestamp }" type="both" dateStyle="short" timeStyle="short" /></td>
						<td><pre><c:out value="${scanStatus.message}" /></pre></td>					
					</tr>
				</c:forEach>
			</tbody>

		</table>
	</div>
	
	<br/>
	
</body>
