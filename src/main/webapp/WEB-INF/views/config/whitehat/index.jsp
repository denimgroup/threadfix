<%@ include file="/common/taglibs.jsp"%>

<head>
    <title>WhiteHat Sentinel</title>
    
    <script type="text/javascript" src="<%=request.getContextPath()%>/scripts/whitehat-key-check.js"></script>
</head>

<body id="config">
	<h2>WhiteHat Sentinel</h2>
	
	<div id="helpText">
		This Sentinel API Key is used to pull scan results from the Sentinel Web Services.<br/>
		If you are having problems, make sure that your API Key is correct and that your application URLs correspond to the WhiteHat Sentinel URLs.
	</div>
	
	<table class="dataTable">
		<tbody>
			<tr>
				<td> API Key: </td>
				<td class="inputValue" id="apikey"><c:out value="${ channelType.apiKey}"/></td>
			</tr>
		</tbody>
	</table>
	<br/>
		
	<spring:url value="/configuration/whitehat/change" var="changeUrl"/>
	<a href="${ fn:escapeXml(changeUrl) }">Edit API Key</a> |
	<spring:url value="/configuration/whitehat/jsoncheck" var="jsonUrl"/>
	<a href="${ fn:escapeXml(jsonUrl) }" id="jsonLink">Test Key</a>	
	<br/>
	<div id="results"></div>
	
	
			
</body>
