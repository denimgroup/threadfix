<%@ include file="/common/taglibs.jsp"%>

<head>
	<title><c:out value="${ application.name }"/> New Channel</title>
</head>

<body id="apps">
	<h2><c:out value="${ application.name }"/> New Channel</h2>

<spring:url value="/organizations/{orgId}/applications/{appId}/addChannel" var="submitUrl">
	<spring:param name="orgId" value="${ application.organization.id }" />
	<spring:param name="appId" value="${ application.id }" />
</spring:url>

<form:form modelAttribute="applicationChannel" method="post" action="${fn:escapeXml(submitUrl)}">
<table class="dataTable">
	<tbody>
		<tr>
			<td class="label">Channel Type:</td>
			<td class="inputValue">
				<form:select id="channelTypeSelect" path="channelType.id">
					<form:options items="${ channelTypeList }" itemValue="id" itemLabel="name" />
				</form:select>
			</td>
			<td style="padding-left: 5px">
				<form:errors path="channelType.id" cssClass="errors" />
			</td>
		</tr>
	</tbody>
</table>
<br/>
<input id="addChannelButton" type="submit" value="Add Channel" />
<spring:url value="/organizations/{orgId}/applications/{appId}" var="appUrl">
	<spring:param name="orgId" value="${ application.organization.id }" />
	<spring:param name="appId" value="${ application.id }" />
</spring:url>
<span style="padding-left: 10px"><a id="cancelButton" href="${ fn:escapeXml(appUrl) }">Cancel</a></span>
</form:form>
</body>