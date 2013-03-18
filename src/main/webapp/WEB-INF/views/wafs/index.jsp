<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>WAFs</title>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/ajax_replace.js"></script>
</head>

<body id="wafs">
	<h2>WAFs</h2>
	
	<div id="helpText" style="width:630px;">
		A ThreadFix WAF is used to generate rules for a WAF or IDS/IPS program that is used to filter web traffic.
	</div>
	
	<div id="appWafDiv">
		<%@ include file="/WEB-INF/views/wafs/wafsTable.jsp" %>
	</div>
</body>
