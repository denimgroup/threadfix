<%@ include file="/common/taglibs.jsp"%>

<head>
<title>Scan History</title>
<script type="text/javascript"
	src="<%=request.getContextPath()%>/scripts/remote-pagination.js"></script>
<spring:url value="/scans/table" var="tableUrl" />
<spring:url value="/login.jsp" var="loginUrl" />
<script type="text/javascript">
	window.onload = function() {
		refillElementSort('#toReplace', '<c:out value="${ tableUrl }"/>', 1,
				null, '<c:out value="${ loginUrl }"/>');
	};
</script>

</head>

<body id="scans">
	<h2>Scan History</h2>
	<div id="helpText">This page lists all of the scans that have
		been uploaded to ThreadFix.</div>
	<div id="toReplace">
		<table class="table">
			<thead>
				<tr>
					<th style="text-align: left" class="first">Team</th>
					<th style="text-align: left">Application</th>
					<th>Defect Tracker</th>
					<th>Scanner</th>
					<th>Scan Type</th>
					<th style="width: 120px" class="long">Scan Date</th>
					<th>Total Vulns</th>
					<th>Critical</th>
					<th>Major</th>
					<th>Minor</th>
					<th class="last">Trivial</th>
				</tr>
			</thead>
			<tbody id="wafTableBody">
				<tr class="bodyRow">
					<td colspan="11" style="text-align: center;">Loading Scans.</td>
				</tr>
			</tbody>
		</table>
	</div>
</body>