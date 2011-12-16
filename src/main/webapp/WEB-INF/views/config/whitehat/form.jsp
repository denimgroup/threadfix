<%@ include file="/common/taglibs.jsp"%>

<head>
    <title>Add WhiteHat Account</title>
    
    <script type="text/javascript" src="<%=request.getContextPath()%>/scripts/whitehat-key-check.js"></script>
</head>

<body id="config">
	<h2>WhiteHat Sentinel</h2>
	
<spring:url value="" var="emptyUrl"></spring:url>
<form:form modelAttribute="channelType" autocomplete="off" method="post" action="${ fn:escapeXml(emptyUrl) }">
	<table class="dataTable">
		<tbody>
			<tr>
				<td> API Key: </td>
				<td class="inputValue">
					<form:input id="apikey" path="apiKey" cssClass="focus" size="50" maxlength="255" />
					<spring:url value="/configuration/whitehat/jsoncheck" var="jsonUrl"/>
					<a href="${ fn:escapeXml(jsonUrl) }" id="jsonLink">Test Key</a>
				</td>
				<td>
					<span id="results"><form:errors path="apiKey" cssClass="errors" /></span>
				</td>
			</tr>
		</tbody>
	</table>
	<br/>
	
	<input type="submit" value="Submit" />
	<span style="padding-left: 10px">
	<c:if test="${ cancelToConfigPage }">
		<a href="<spring:url value="/configuration" />">Cancel</a>
	</c:if>
	<c:if test="${ not cancelToConfigPage }">
		<a href="<spring:url value="/configuration/whitehat" />">Cancel</a>
	</c:if>
	</span>
	
	</form:form>
</body>