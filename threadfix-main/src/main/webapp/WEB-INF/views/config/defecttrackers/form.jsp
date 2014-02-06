<%@ include file="/common/taglibs.jsp"%>

<head>
	<title><c:if test="${ defectTracker['new'] }">New </c:if>Defect Tracker</title>
	<script>
	function displayWarning(){
		var displayUrl = (typeof(initialUrl) !== 'undefined') && (initialUrl !== $('#urlInput').val()); 
		var displayType = (typeof(initialTrackerTypeId) !== 'undefined') && initialTrackerTypeId !== $('#defectTrackerTypeSelect').val(); 
		var message = ''; 
		if (displayUrl) {
			message = message + 'The URL has changed, make sure that the Threadfix Defects have the correct IDs in the new location.';
		}
		if (displayUrl && displayType) {
			message = message + '\n\n';
		}
		if (displayType) {
			message = message + 'The type has changed, all associated Defects will be deleted.';
		}	
		if (displayUrl || displayType) {
			return confirm(message);
		}
		return true;
	}
	</script>
</head>

<body id="config">
	<h2><c:if test="${ defectTracker['new'] }">New </c:if>Defect Tracker</h2>
	
	<div id="helpText">
		To set up the Defect Tracker, enter the RPC endpoint address of your tracker instance.
	</div>
	
<spring:url value="" var="emptyUrl"/>
<form:form modelAttribute="defectTracker" method="post" action="${ fn:escapeXml(emptyUrl) }">
	<table class="dataTable">
		<tbody>
			    <tr>
					<td>Name:</td>
					<td class="inputValue">
						<form:input id="nameInput${status.count}" path="name" cssClass="focus" size="50" maxlength="50"/>
					</td>
					<td style="padding-left: 5px">
						<form:errors path="name" cssClass="errors" />
					</td>
				</tr>
				<tr>
					<td>URL:</td>
					<td class="inputValue">
						<c:if test="${ not empty defectTracker.url }">
							<script>
								var initialUrl = '<c:out value="${ defectTracker.url }"/>';
							</script>
						</c:if>
						<form:input id="urlInput" path="url" cssClass="focus" size="50" maxlength="255"/>
					</td>
					<td style="padding-left: 5px">
						<form:errors path="url" cssClass="errors" />
						<c:if test="${ showKeytoolLink }">
							<span class="errors">Instructions for importing a self-signed certificate can be found</span> <a target="_blank" href="http://code.google.com/p/threadfix/wiki/ImportingSelfSignedCertificates">here</a>.
						</c:if>
					</td>
				</tr>
				<tr>	
					<td>Type:</td>
					<td class="inputValue">
						<c:if test="${ not empty defectTracker.defectTrackerType.id }">
							<script>
								var initialTrackerTypeId = '<c:out value="${ defectTracker.defectTrackerType.id }"/>';
							</script>
						</c:if>
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
<c:when test="${ defectTracker['new'] }">
	<input id="addDefectTrackerButton" type="submit" value="Add Defect Tracker" />
	<spring:url value="/configuration/defecttrackers" var="dtUrl" />
	<span style="padding-left: 10px"><a id="cancelLink" href="${ fn:escapeXml(dtUrl) }">Back to Defect Tracker Index</a></span>
</c:when>
<c:otherwise>

	<input id="updateDefectTrackerButton" type="submit" onclick="return displayWarning()" value="Update Defect Tracker" />
	<spring:url value="/configuration/defecttrackers/{defectTrackerId}" var="dtUrl">
		<spring:param name="defectTrackerId" value="${ defectTracker.id }" />
	</spring:url>
	<span style="padding-left: 10px"><a id="cancelLink" href="${ fn:escapeXml(dtUrl) }">Back to Defect Tracker <c:out value="${ defectTracker.name }"/></a></span>
</c:otherwise>
</c:choose>
	
</form:form>
</body>