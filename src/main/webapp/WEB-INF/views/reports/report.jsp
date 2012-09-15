<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Report</title>
	<script>window.onload=function(){$('p').each(function(index) { $(this).css('line-height','1.5');});};</script>
</head>

<body id="reports">
	<h2>Report</h2>
	
	${jasperReport}
</body>
