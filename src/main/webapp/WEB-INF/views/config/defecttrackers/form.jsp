<%@ include file="/common/taglibs.jsp"%>

<head>
	<title><c:if test="${ defectTracker.new }">New </c:if>Defect Tracker</title>
</head>

<body id="config">
	<h2><c:if test="${ defectTracker.new }">New </c:if>Defect Tracker</h2>
	
<spring:url value="" var="emptyUrl"></spring:url>	
<form:form modelAttribute="defectTracker" method="post" action="${ fn:escapeXml(emptyUrl) }">
	<table class="dataTable">
		<tbody>
			    <tr>
					<td class="label">Name:</td>
					<td class="inputValue">
						<form:input id="nameInput" path="name" cssClass="focus" size="50" maxlength="50"/>
					</td>
					<td style="padding-left: 5px">
						<form:errors path="name" cssClass="errors" />
					</td>
				</tr>
				<tr>
					<td class="label">URL:</td>
					<td class="inputValue">
						<form:input id="urlInput" path="url" cssClass="focus" size="50" maxlength="255"/>
					</td>
					<td style="padding-left: 5px">
						<form:errors path="url" cssClass="errors" />
					</td>
				</tr>
				<tr>	
					<td class="label">Type:</td>
					<td class="inputValue">
						<form:select id="defectTrackerTypeSelect" path="defectTrackerType.id">
							<form:options items="${ defectTrackerTypeList }" itemValue="id" itemLabel="name" />
						</form:select>
					</td>
					<td style="padding-left: 5px">
						<form:errors path="defectTrackerType.id" cssClass="errors" />
					</td>
				</tr>
			</tbody>
	</table>
	<br/>
<c:choose>
<c:when test="${ defectTracker.new }">
	<input id="addDefectTrackerButton" type="submit" value="Add Defect Tracker" />
	<spring:url value="/configuration/defecttrackers" var="dtUrl" />
</c:when>
<c:otherwise>
	<input id="updateDefectTrackerButton" type="submit" onclick="return confirm('If you are editing the URL, make sure that the Threadfix Defects have the correct IDs. If you are editing the type, all associated Defects will be deleted.')" value="Update Defect Tracker" />
	<spring:url value="/configuration/defecttrackers/{defectTrackerId}" var="dtUrl">
		<spring:param name="defectTrackerId" value="${ defectTracker.id }" />
	</spring:url>
</c:otherwise>
</c:choose>
	<span style="padding-left: 10px"><a id="cancelLink" href="${ fn:escapeXml(dtUrl) }">Cancel</a></span>
</form:form>
</body>