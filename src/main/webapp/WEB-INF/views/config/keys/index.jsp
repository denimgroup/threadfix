<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>API Keys</title>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/ajax_replace.js"></script>
</head>

<body>
	<h2>API Keys</h2>
	
	<div id="helpText">
		ThreadFix API Keys are used to access the REST interface.<br/>
	</div>
	
	<div id="tableDiv">
		<%@ include file="/WEB-INF/views/config/keys/keyTable.jsp" %>
	</div>
	
	<br/>
	
	<div id="newKeyModalDiv" class="modal hide fade" tabindex="-1"
		role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
		<div class="modal-header">
			<h4 id="myModalLabel">New API Key</h4>
		</div>
		<div id="formDiv">
			<%@ include file="/WEB-INF/views/config/keys/newForm.jsp" %>
		</div>
	</div>
</body>
