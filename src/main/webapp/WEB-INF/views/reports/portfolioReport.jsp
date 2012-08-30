<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Scanner Comparison By Vulnerability</title>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/confirm.js"></script>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/sortable_us.js"></script>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/tablefilter2.js"></script> 
	<style type="text/css">
		input { width:100% }
	</style>
</head>

<body>
	<h2>Portfolio Report</h2>
	
	<table class="dataTable">
		<tbody>
			<tr>
				<td class="label">Number of Applications:</td>
				<td class="inputValue"><c:out value="${ totalApps }"/></td>
			</tr>
			<tr>
				<td class="label">Number of Scans:</td>
				<td class="inputValue"><c:out value="${ totalScans }"/></td>
			</tr>
		</tbody>
	</table>
	
	<h3>Application Breakdown by Latest Scan</h3>
	
	<table class="formattedTable">
		<thead>
			<tr>
				<th class="first"></th>
				<th>1 Month</th>
				<th>2 Months</th>
				<th>3 Months</th>
				<th>6 Months</th>
				<th>9 Months</th>
				<th>12 Months</th>
				<th>12+ Months</th>
				<th>Never</th>
				<th class="last">Totals</th>
			</tr>
		</thead>
		<tbody>
			<c:forEach var="row" items="${appsByCriticality}">
			<tr class="bodyRow">
				<c:forEach var="cell" items="${ row }">
					<td><c:out value="${ cell }"/></td>
				</c:forEach>
			</tr>
		</c:forEach>
		</tbody>
	</table>
	
	<h3>Portfolio Scan Statistics</h3>
	
	<table class="formattedTable">
		<thead>
			<tr>
				<th class="first"></th>
				<th class="medium">Criticality</th>
				<th class="short"># Scans</th>
				<th class="medium last">Most Recent Scan</th>
			</tr>
		</thead>
		<tbody>
		<c:forEach var="row" items="${ tableContents }">
			<tr class="bodyRow">
				<c:if test="${ empty row }">
					<td colspan="4"></td>
				</c:if>
				<c:if test="${ not empty row }">
					<c:forEach var="cell" items="${ row }">
						<td><c:out value="${ cell }"/></td>
					</c:forEach>
				</c:if>
			</tr>
		</c:forEach>
		</tbody>
		<tfoot>
			<tr class="footer">
				<td colspan="10" class="pagination" style="text-align:right"></td>
			</tr>
		</tfoot>
	</table>
</body>