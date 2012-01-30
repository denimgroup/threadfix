<%@ include file="/common/taglibs.jsp"%>

<head>
	<title><c:out value="${ application.name }"/> Scan Upload</title>
</head>

<body id="apps">
	<h2><c:out value="${ application.name }"/> Scan Upload</h2>
	
<c:if test="${ not empty message }">
	<center class="errors" ><c:out value="${ message }"/></center>
</c:if>

	<div id="helpText">
		This page is used to upload scans from application scanner tools into your ThreadFix application.
	</div>

<c:choose>
	<c:when test="${ empty application.channelList }">
	<table class="dataTable">
		<tbody>
			<tr>
				<td class="label">Channel:</td>
				<td>
					<spring:url value="/organizations/{orgId}/applications/{appId}/addChannel" var="addChannelUrl">
						<spring:param name="orgId" value="${ application.organization.id }" />
						<spring:param name="appId" value="${ application.id }" />
					</spring:url>
					<span style="padding-left: 10px"><a href="${ fn:escapeXml(addChannelUrl) }">Add Channel</a></span>
				</td>
			</tr>
		</tbody>
	</table>
	</c:when>
	<c:otherwise>
	
	<spring:url value="upload" var="uploadUrl"></spring:url>
	<form:form method="post" action="${ fn:escapeXml(uploadUrl) }" enctype="multipart/form-data">
		<form:errors path="*" cssClass="errors" />
		<table class="dataTable">
			<tbody>
				<tr>
					<td class="label">Channel:</td>
					<td class="inputValue">
						<select id="channelSelect" name="channelId">
							<c:forEach var="channel" items="${ application.uploadableChannels }">
								<option value="${ channel.id }"><c:out value="${ channel.channelType.name }"/></option>
							</c:forEach>
						</select>
					</td>
				</tr>
				<tr>
					<td class="label">File:</td>
					<td class="inputValue">
						<input id="fileInput" type="file" name="file" size="50" />
					</td>
				</tr>
			</tbody>
		</table>
		<br />
		<input id="uploadScanButton" type="submit" value="Upload Scan" />
		<spring:url value="/organizations/{orgId}/applications/{appId}/addChannel" var="addChannelUrl">
			<spring:param name="orgId" value="${ application.organization.id }" />
			<spring:param name="appId" value="${ application.id }" />
		</spring:url>
		<span style="padding-left: 10px"><a id="addAnotherChannelLink" href="${ fn:escapeXml(addChannelUrl) }">Add Another Channel</a></span>
		<spring:url value="/organizations/{orgId}/applications/{appId}" var="appUrl">
			<spring:param name="orgId" value="${ application.organization.id }" />
			<spring:param name="appId" value="${ application.id }" />
		</spring:url>
		<span style="padding-left: 10px"><a id="cancelLink" href="${ fn:escapeXml(appUrl) }">Back to Application <c:out value="${ application.name }"/></a></span>
	</form:form>
	</c:otherwise>
</c:choose>
</body>