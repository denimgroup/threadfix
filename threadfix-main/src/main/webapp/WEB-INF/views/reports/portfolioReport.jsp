<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Scanner Comparison By Vulnerability</title>
	<cbs:cachebustscript src="/scripts/confirm.js"/>
	<cbs:cachebustscript src="/scripts/sortable_us.js"/>
	<cbs:cachebustscript src="/scripts/tablefilter2.js"/> 
	<style type="text/css">
		input { width:100% }
	</style>
</head>

<body>
	<h2>Portfolio Report</h2>
	
	<table class="dataTable">
		<tbody>
			<tr>
				<td>Team:</td>
				<td class="inputValue"><c:out value="${ teamName }"/></td>
			</tr>
			<tr>
				<td>Number of Applications:</td>
				<td class="inputValue"><c:out value="${ totalApps }"/></td>
			</tr>
			<tr>
				<td>Number of Scans:</td>
				<td class="inputValue"><c:out value="${ totalScans }"/></td>
			</tr>
		</tbody>
	</table>
	
	<h3>Application Breakdown by Latest Scan</h3>
	
	<table class="table table-striped">
		<thead>
			<tr>
				<th class="short first"></th>
				<th class="short">1 Month</th>
				<th class="short">2 Months</th>
				<th class="short">3 Months</th>
				<th class="short">6 Months</th>
				<th class="short">9 Months</th>
				<th class="short">12 Months</th>
				<th class="short">12+ Months</th>
				<th class="short">Never</th>
				<th class="short last" >Totals</th>
			</tr>
		</thead>
		<tbody>
			<c:forEach var="row" items="${appsByCriticality}" varStatus="outerStatus">
				<c:if test="${ outerStatus.count == 5 }">
					<tr class="bodyRow" style="background-color: #E2E4FF; font-weight: bold;"/>
				</c:if>
				<c:if test="${ outerStatus.count != 5 }">
					<tr class="bodyRow">
				</c:if>
				<c:forEach var="cell" items="${ row }" varStatus="status">
					<c:choose> 
						<c:when test="${ status.count == 8 and not cell.equals('0') }">
							<td style="background:orange;font-weight:bold;"><c:out value="${ cell }"/></td>
						</c:when>
						<c:when test="${ status.count == 9 and not cell.equals('0')}">
							<td style="background:red;font-weight:bold;"><c:out value="${ cell }"/></td>
						</c:when>
						<c:when test="${ status.count == 10 }">
							<td style="background-color: #E2E4FF; font-weight: bold;"><c:out value="${ cell }"/></td>
						</c:when>
						<c:otherwise>
							<td><c:out value="${ cell }"/></td>
						</c:otherwise> 
					</c:choose>  
				</c:forEach>
			</tr>
		</c:forEach>
		</tbody>
	</table>
	
	<h3>Portfolio Scan Statistics</h3>
	
	<table class="table table-striped">
		<thead>
			<tr>
				<th class="first"></th>
				<th class="medium">Criticality</th>
				<th class="short"># Scans</th>
				<th class="medium last">Most Recent Scan</th>
			</tr>
		</thead>
		<tbody>
		<c:forEach var="row" items="${ tableContents }" varStatus="outerStatus">
			<tr class="bodyRow">
				<c:if test="${ empty row }">
					<td colspan="4"></td>
				</c:if>
				<c:if test="${ not empty row }">
					<c:forEach var="cell" items="${ row }" varStatus="status">
						<c:choose> 
							<c:when test="${status.count == 4 and cell.equals('Never')}" > 
								<td style="background:red;font-weight:bold;"><c:out value="${ cell }"/></td>
							</c:when> 
							<c:when test="${status.count == 4 and old[outerStatus.count - 1] }" > 
								<td style="background:orange;font-weight:bold;"><c:out value="${ cell }"/> days ago</td>
							</c:when> 
							<c:when test="${status.count == 4}" > 
								<td><c:out value="${ cell }"/> days ago</td>
							</c:when> 
						 	<c:otherwise> 
								<td><c:out value="${ cell }"/></td>
							</c:otherwise> 
						</c:choose>  
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