<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>API Key</title>
</head>

<body>
	<h2>API Key</h2>
	
	<spring:url value="" var="emptyUrl"></spring:url>	
	<form:form modelAttribute="apiKey" method="post" action="${fn:escapeXml(emptyUrl) }">
		<table class="dataTable">
			<tbody>
				<tr>
					<td class="label">Note:</td>
					<td class="inputValue">
						<form:input path="note" cssClass="focus" size="70" maxlength="255" value="${ note }" />
					</td>
					<td style="padding-left:5px">
						<form:errors path="note" cssClass="errors" />
					</td>
				</tr>
			</tbody>
		</table>
		<br/>
		<input type="submit" value="Update API Key" />
		<span style="padding-left: 10px"><a href="<spring:url value="/configuration/keys"/>">Back to API Key</a></span>
	</form:form>
</body>