<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Defect Trackers</title>
</head>

<body id="config">
	<h2>Defect Trackers</h2>
	
	<table class="formattedTable">
		<thead>
			<tr>
			    <th class="medium first">Name</th>
				<th class="long">URL</th>
				<th class="medium last">Type</th>
			</tr>
		</thead>
		<tbody id="defectTrackerTableBody">
		<c:if test="${ empty defectTrackerList }">
			<tr class="bodyRow">
				<td colspan="3" style="text-align:center;">No Defect Trackers found.</td>
			</tr>
		</c:if>
		<c:forEach var="defectTracker" items="${ defectTrackerList }">
			<tr class="bodyRow">
			    <td>
			    	<spring:url value="/configuration/defecttrackers/{defectTrackerId}" var="dtUrl">
						<spring:param name="defectTrackerId" value="${ defectTracker.id }" />
					</spring:url>
					<a href="${ fn:escapeXml(dtUrl) }">
			            <c:out value="${ defectTracker.name }"/>
			        </a> 
			    </td>
				<td>
					<c:out value="${ defectTracker.url }"/>
				</td>
				<td>
					<c:out value="${ defectTracker.defectTrackerType.name }"/>
				</td>
			</tr>
		</c:forEach>
			<tr class="footer">
				<td class="first">
					<a id="addDefectTrackerLink" href="<spring:url value="/configuration/defecttrackers/new" />">Add Defect Tracker</a>
				</td>
				<td class="pagination" style="text-align:right"></td>
			</tr>
		</tbody>
	</table>
</body>