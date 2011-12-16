<%@ include file="/common/taglibs.jsp"%>

<head>
    <title>WhiteHat Sentinel</title>
    
    <script type="text/javascript" src="<%=request.getContextPath()%>/scripts/whitehat-key-check.js"></script>
</head>

<body id="config">
	<h2>WhiteHat Sentinel</h2>
	
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
