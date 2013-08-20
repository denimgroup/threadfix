<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Vulnerability Filters</title>
</head>

<body>
	<h2>Vulnerability Filters</h2>
	
	<div id="helpText">
		ThreadFix Vulnerability Filters are used to sort data as it comes into ThreadFix.<br/>
	</div>
	
	<div id="tableDiv">
		<%@ include file="/WEB-INF/views/filters/table.jsp" %>
	</div>
	
	<br/>
	
	<div id="newFilterModalDiv" class="modal hide fade" tabindex="-1"
		role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
		<div class="modal-header">
			<h4 id="myModalLabel">New Vulnerability Filter</h4>
		</div>
		<div id="formDiv">
			<%@ include file="/WEB-INF/views/filters/newForm.jsp" %>
		</div>
	</div>
</body>
