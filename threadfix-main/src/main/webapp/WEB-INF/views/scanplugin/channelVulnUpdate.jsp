<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Scanner Plugin</title>
</head>

<body id="wafs">
	<h2>Channel Vulnerability Update Results</h2>
	
	<%@ include file="/WEB-INF/views/successMessage.jspf" %>
	<%@ include file="/WEB-INF/views/errorMessage.jsp"%>

<table class="table table-striped">
	<thead>
		<tr>
			<th class="long first">Channel Type</th>
			<th class="centered last">Number updated</th>
		</tr>
	</thead>
	<tbody id="wafTableBody">
	<c:if test="${ empty resultList }">
		<tr class="bodyRow">
			<td colspan="5" style="text-align:center;">No Channel Vulnerabilities updated.</td>
		</tr>
	</c:if>
	<c:forEach var="result" items="${ resultList }" varStatus="status">
		<tr class="bodyRow">
			<td class="details" id="name${ status.count }">
				<c:out value="${ result[0] }"/>
			</td>
			<td class="centered" id="numUpdated${ status.count }">
				<c:out value="${ result[1] }"/>
			</td>
		</tr>
	</c:forEach>
	</tbody>
</table>
</body>
