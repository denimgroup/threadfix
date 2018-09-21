<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>WAF Events</title>
</head>

<body id="wafs">
	<h2>WAF Events</h2>
	
	<table class="table table-striped">
		<thead>
			<tr>
				<th class="long first">Native ID</th>
				<th class="medium">Vulnerability</th>
				<th class="medium">Attack Type</th>
				<th class="long">Log Text</th>
				<th class="medium last">Time</th>
			</tr>
		</thead>
		<tbody>
		<c:if test="${ empty eventList }">
			<tr class="bodyRow">
				<td colspan="5" style="text-align:center;">No events found.</td>
			</tr>
		</c:if>
		<c:forEach var="event" items="${ eventList }">
			<tr class="bodyRow" ng-non-bindable>
				<td class="details">
					<c:out value="${ waf.wafRule.nativeId }"/> 
				</td>
				<td><c:out value="${ waf.wafRule.vulnerability.genericVulnerability.name }"/></td>
				<td><c:out value="${ waf.attackType }"/></td>
				<td><c:out value="${ waf.logText }"/></td>
				<td><c:out value="${ waf.importTime }"/></td>
			</tr>
		</c:forEach>
			<tr class="footer">
				<td colspan="5" class="last pagination" style="text-align:right"></td>
			</tr>
		</tbody>
	</table>
	
	<br />
	<a href="<spring:url value="/wafs"/>">Continue</a>
</body>