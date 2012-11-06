<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>WAFs</title>
</head>

<body id="wafs">
	<h2>WAFs</h2>
	
	<div id="helpText" style="width:630px;">
		A ThreadFix WAF is used to generate rules for a WAF or IDS/IPS program that is used to filter web traffic.
	</div>
	
	<table class="formattedTable">
		<thead>
			<tr>
				<th class="long first">Name</th>
				<th class="medium last">Type</th>
			</tr>
		</thead>
		<tbody id="wafTableBody">
		<c:if test="${ empty wafList }">
			<tr class="bodyRow">
				<td colspan="2" style="text-align:center;">No WAFs found.</td>
			</tr>
		</c:if>
		<c:forEach var="waf" items="${ wafList }">
			<tr class="bodyRow">
				<td class="details">
					<spring:url value="/wafs/{wafId}" var="wafUrl">
						<spring:param name="wafId" value="${ waf.id }" />
					</spring:url>
					<a href="${ fn:escapeXml(wafUrl) }">
						<c:out value="${ waf.name }"/>
					</a>
				</td>
				<td><c:out value="${ waf.wafType.name }"/></td>
			</tr>
		</c:forEach>
		</tbody>
	</table>
	<c:if test="${ canManageWafs }">
		<div style="padding-top:10px" id="link">
			<a id="addWafLink" href="<spring:url value="/wafs/new" />">Add WAF</a>
		</div>
	</c:if>
</body>