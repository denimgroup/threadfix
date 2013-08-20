<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Vulnerability Filters</title>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/vulnerability_filters.js"></script>
</head>

<body>
	<h2>Vulnerability Filters</h2>
	
	<div id="helpText">
		ThreadFix Vulnerability Filters are used to sort data.<br/>
	</div>
	
	<div id="tableDiv">
		<%@ include file="/WEB-INF/views/filters/table.jsp" %>
	</div>
</body>
