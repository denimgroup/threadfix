<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Defect Tracker Details</title>
</head>

<body id="config">
	<h2>Defect Tracker Details</h2>
	
	<c:if test="${ empty defectTracker.applications }">
		<div id="helpText">
			Now that you have set up a Defect Tracker, the next step is to attach it to an application.<br/>
			To do that, go to an Add Application or Edit Application page and complete the form there.
		</div>
	</c:if>
	
	<table class="dataTable">
		<tbody>
			<tr>
				<td>Name:</td>
				<td ng-non-bindable id="nameText" class="inputValue"><c:out value="${ defectTracker.name }"/></td>
			</tr>
			<tr>
				<td>URL:</td>
				<td ng-non-bindable id="urlText" class="inputValue"><c:out value="${ defectTracker.url }"/></td>
			</tr>
			<tr>
				<td>Type:</td>
				<td ng-non-bindable id="typeText" class="inputValue"><c:out value="${ defectTracker.defectTrackerType.name }"/></td>
			</tr>
		</tbody>
	</table>
	<br />
	<c:if test="${ canManageDefectTrackers }">
		<spring:url value="{defectTrackerId}/edit" var="editUrl">
			<spring:param name="defectTrackerId" value="${ defectTracker.id }"/>
		</spring:url>
		<a id="editLink" href="${ fn:escapeXml(editUrl) }">Edit</a> | 
		<spring:url value="{defectTrackerId}/delete" var="deleteUrl">
			<spring:param name="defectTrackerId" value="${ defectTracker.id }"/>
		</spring:url>
		<a id="deleteButton" onclick="return confirm('If you delete this Tracker, all the associated Defects will also be deleted. Are you sure?')" href="${ fn:escapeXml(deleteUrl) }">Delete</a> | 
	</c:if>
	<a id="backToListLink" href="<spring:url value="/configuration/defecttrackers" />">Back to Defect Tracker Index</a>
	<br />
</body>