<%@ include file="/common/taglibs.jsp"%>

<head>
	<title ng-non-bindable><c:out value="${ application.name }"/> Scheduled Scan Configuration</title>
</head>

<body id="apps">
	<h2 ng-non-bindable><c:out value="${ application.name }"/> Scheduled Scan Configuration</h2>
	
<c:if test="${ not empty message }">
	<center class="errors" ng-non-bindable><c:out value="${ message }"/></center>
	<c:if test="${ not empty type }">
		<center class="errors">This error could be caused by trying to upload a scan in an incorrect format.</center>
		<center class="errors" ng-non-bindable>The last scan was uploaded to the channel <c:out value="${ type.name }"/></center>
		<center class="errors" ng-non-bindable><c:out value="${ type.exportInfo }"/></center>
	</c:if>
</c:if>

	<div id="helpText">
		This page is used to configure scheduled scans.
	</div>

<spring:url value="" var="uploadUrl"></spring:url>
<form:form method="post" action="${ fn:escapeXml(uploadUrl) }" enctype="multipart/form-data">
	<form:errors path="*" cssClass="errors" />
	<table class="dataTable">
		<tbody>
			<tr>
				<td class="label">Channel:</td>
				<td class="inputValue">
					<select id="channelSelect" name="channelId">
						<c:forEach var="channel" items="${ application.uploadableChannels }">
							<option ng-non-bindable onclick="display(<c:out value="${ channel.id }"/>)" value="${ channel.id }"><c:out value="${ channel.channelType.name }"/></option>
						</c:forEach>
					</select>
					<c:forEach var="channel" items="${ application.uploadableChannels }">
						<c:if test="${ not empty channel.channelType.exportInfo }">
							<span style="padding-left: 8px; display: none;" id="info${ channel.id }">
								<a ng-non-bindable href="javascript:alert('<c:out value='${ channel.channelType.exportInfo }'/>');">Which file format do I need?</a>
							</span>
						</c:if>
					</c:forEach>
					<c:if test="${ not empty application.uploadableChannels }">
						<script>display(<c:out value="${ application.uploadableChannels[0].id}"/>);</script>
					</c:if>
				</td>
			</tr>
			<tr>
				<td class="label">Scan Configuration File:</td>
				<td class="inputValue">
					<input id="fileInput" type="file" name="file" size="50" />
				</td>
			</tr>
		</tbody>
	</table>
	<br />
	<input id="uploadScanButton" type="submit" value="Upload Scan Configuration" />
	<spring:url value="/organizations/{orgId}/applications/{appId}" var="appUrl">
		<spring:param name="orgId" value="${ application.organization.id }" />
		<spring:param name="appId" value="${ application.id }" />
	</spring:url>
	<span style="padding-left: 10px"><a id="cancelLink" href="${ fn:escapeXml(appUrl) }" ng-non-bindable>Back to Application <c:out value="${ application.name }"/></a></span>
</form:form>

</body>