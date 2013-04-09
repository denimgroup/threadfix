<%@ include file="/common/taglibs.jsp"%>

<head>
	<title><c:out value="${ application.name }"/> Scan Upload</title>
	<script>
		var lastId = 0;
		function display(currentId) {
			$("#info" + currentId).css('display','');
			$("#info" + lastId).css('display','none');
			lastId = currentId;
		}
	</script>
</head>

<body id="apps">
	<h2><c:out value="${ application.name }"/> Scan Upload</h2>
	
<c:if test="${ not empty message }">
	<div class="alert">
		<button class="close" data-dismiss="alert" type="button">×</button>
		<c:out value="${ message }"/>
	</div>
	<c:if test="${ not empty type }">
		<br>This error could be caused by trying to upload a scan in an incorrect format.
		<br>The last scan was uploaded to the channel <c:out value="${ type.name }"/>
		<br><c:out value="${ type.exportInfo }"/>
	</c:if>
</c:if>

	<div id="helpText">
		This page is used to upload scans from application scanner tools into your ThreadFix application.
	</div>

	<spring:url value="upload" var="uploadUrl"></spring:url>
	<form:form method="post" action="${ fn:escapeXml(uploadUrl) }" enctype="multipart/form-data">
		<form:errors path="*" cssClass="errors" />
		<table class="dataTable">
			<tbody>
				<tr>
					<td>Scanner Type:</td>
					<td class="inputValue">
						<select id="channelSelect" name="channelId">
						<option onclick="display(-1)" value="-1">Auto-detect</option>
							<c:forEach var="channel" items="${ channelTypes }">
								<option onclick="display(<c:out value="${ channel.id }"/>)" value="${ channel.id }"><c:out value="${ channel.name }"/></option>
							</c:forEach>
						</select>
						<c:forEach var="channel" items="${ channelTypes }">
							<c:if test="${ not empty channel.exportInfo }">
								<span style="padding-left: 8px; display: none;" id="info${ channel.id }">
									<a href="javascript:alert('<c:out value='${ channel.exportInfo }'/>');">Which file format do I need?</a>
								</span>
							</c:if>
						</c:forEach>
					</td>
				</tr>
				<tr>
					<td>File:</td>
					<td class="inputValue">
						<input id="fileInput" type="file" name="file" size="50" />
					</td>
				</tr>
			</tbody>
		</table>
		<br />
		<input id="uploadScanButton" type="submit" value="Upload Scan" />
		<spring:url value="/organizations/{orgId}/applications/{appId}" var="appUrl">
			<spring:param name="orgId" value="${ application.organization.id }" />
			<spring:param name="appId" value="${ application.id }" />
		</spring:url>
		<span style="padding-left: 10px"><a id="cancelLink" href="${ fn:escapeXml(appUrl) }">Back to Application <c:out value="${ application.name }"/></a></span>
	</form:form>
</body>