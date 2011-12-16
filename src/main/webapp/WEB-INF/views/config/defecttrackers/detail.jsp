<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Defect Tracker Details</title>
</head>

<body id="config">
	<h2>Defect Tracker Details</h2>
	
	<table class="dataTable">
		<tbody>
			<tr>
				<td class="label">Name:</td>
				<td id="nameText" class="inputValue"><c:out value="${ defectTracker.name }"/></td>
			</tr>
			<tr>
				<td class="label">URL:</td>
				<td id="urlText" class="inputValue"><c:out value="${ defectTracker.url }"/></td>
			</tr>
			<tr>
				<td class="label">Type:</td>
				<td id="typeText" class="inputValue"><c:out value="${ defectTracker.defectTrackerType.name }"/></td>
			</tr>
		</tbody>
	</table>
	<br />
	<spring:url value="{defectTrackerId}/edit" var="editUrl">
		<spring:param name="defectTrackerId" value="${ defectTracker.id }"/>
	</spring:url>
	<a id="editLink" href="${ fn:escapeXml(editUrl) }">Edit</a> | 
	<spring:url value="{defectTrackerId}/delete" var="deleteUrl">
		<spring:param name="defectTrackerId" value="${ defectTracker.id }"/>
	</spring:url>
	<a id="deleteButton" onclick="return confirm('If you delete this Tracker, all the associated Defects will also be deleted. Are you sure?')" href="${ fn:escapeXml(deleteUrl) }">Delete</a> | 
	<a id="backToListLink" href="<spring:url value="/configuration/defecttrackers" />">Back to List</a>
	<br />
</body>