<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>New Channel</title>
</head>

<body id="config">
	<h2>New Channel</h2>


<c:if test="${ (empty channelTypeList) or (empty applicationList) }">
	There was not enough data to add Application Channels.
</c:if>
<c:if test="${ (not empty channelTypeList) and (not empty applicationList) }">
<spring:url value="" var="emptyUrl"></spring:url>	
<form:form modelAttribute="applicationChannel" method="post" action="${fn:escapeXml(emptyUrl) }">
	<table class="dataTable">
		<tbody>
			<tr>
				<td class="label">Channel Type:</td>
				<td class="inputValue">
					<form:select path="channelType.id">
						<form:options items="${ channelTypeList }" itemValue="id" itemLabel="name" />
					</form:select>
				</td>
				<td style="padding-left: 5px">
					<form:errors path="channelType.id" cssClass="errors" />
				</td>
			</tr>
			<tr>
				<td class="label">Application:</td>
				<td class="inputValue">
					<form:select path="application.id">
						<form:options items="${ applicationList }" itemValue="id" itemLabel="name" />
					</form:select>
				</td>
				<td style="padding-left: 5px">
					<form:errors path="application.id" cssClass="errors" />
				</td>
			</tr>
		</tbody>
	</table>
	<br/>
	<input type="submit" value="Add Channel" />
	<span style="padding-left: 10px">
		<a href="<spring:url value="/configuration/channels" />">Cancel</a>
	</span>
</form:form>
</c:if>
</body>