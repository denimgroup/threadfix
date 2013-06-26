<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Scan History</title>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/remote-pagination.js"></script>
</head>

<body id="scans">
	<h2>Scans</h2>
	
	<div id="helpText">
		This page lists all of the scans that have been uploaded to ThreadFix.
	</div>
		
	<spring:url value="/scans/table" var="tableUrl" />
	<spring:url value="/login.jsp" var="loginUrl" />
	<div id="toReplace" class="refreshOnLoad" data-source-url="<c:out value="${ tableUrl }"/>" 
			data-login-url="<c:out value="${ loginUrl }"/>">
		<table class="table">
			<thead>
				<tr>
					<th style="width: 120px" class="long">Scan Date</th>
					<th style="text-align: left">Application</th>
					<th style="text-align: left" class="first">Team</th>
					<th>Scanner</th>
					<th>Total Vulns</th>
					<th>Critical</th>
					<th>High</th>
					<th>Medium</th>
					<th>Low</th>
					<th></th>
				</tr>
			</thead>
			<tbody id="wafTableBody">
				<tr class="bodyRow">
					<td colspan="10" style="text-align: center;">Loading Scans.</td>
				</tr>
			</tbody>
		</table>
	</div>
</body>