<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Home</title>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/bootstrap.min.js" media="screen"></script>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/remote-pagination.js"></script>
	<script>
	function submitAjaxModal(url, formId, formDiv, successDiv, modalName, collapsible) {
		$.ajax({
			type : "POST",
			url : url,
			data : $(formId).serializeArray(),
			contentType : "application/x-www-form-urlencoded",
			dataType : "text",
			success : function(text) {
				
				if ($.trim(text).slice(0,22) === "<body id=\"formErrors\">") {
					$(formDiv).html(text);
				} else if ($.trim(text).slice(0,17) === "<body id=\"table\">") {
					$(modalName).on('hidden', function () {
						$(successDiv).html(text);
						$(collapsible).collapse('show');
				    });
				    $(modalName).modal('hide');
				} else {
					try {
						var json = JSON.parse(text);
						alert(json.error);
					} catch (e) {
						history.go(0);
					}
				}
			},
			error : function (xhr, ajaxOptions, thrownError){
				history.go(0);
		    }
		});
	}
	function reloadTable(address) {
		$.ajax({
			type : "GET",
			url : address,
			success : function(text) {
				$("#teamTable").html(text);
			},
			error : function (xhr, ajaxOptions, thrownError){
				history.go(0);
		    }
		});
	}
	</script>

</head>

<body id="apps">
	<h2>Teams</h2>
	<img src="<%=request.getContextPath()%>/images/ThreadFix_72.jpg">
	<img src="<%=request.getContextPath()%>/images/ThreadFix_72.jpg">

	<br>
	<a href="#myTeamModal" role="button" class="btn" data-toggle="modal" style="margin-bottom:8px;margin-top:10px;">Add Team</a>
	<div id="myTeamModal" class="modal hide fade" tabindex="-1"
		role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
		<div id="formDiv">
		<div class="modal-header">
			<button type="button" class="close" data-dismiss="modal"
				aria-hidden="true">X</button>
			<h4 id="myModalLabel">New Team</h3>
		</div>
		<spring:url value="/organizations/modalAdd" var="saveUrl"/>
		<form:form style="margin-bottom:0px;" id="organizationForm" modelAttribute="organization" method="post" autocomplete="off" action="${fn:escapeXml(saveUrl)}">
		<div class="modal-body">
			Name <form:input style="margin-bottom:0px;margin-left:5px;" id="nameInput" path="name" cssClass="focus" size="50" maxlength="60" />
				<form:errors path="name" cssClass="errors" />
		</div>
		<div class="modal-footer">
			<button class="btn" data-dismiss="modal" aria-hidden="true">Close</button>
			<a id="submitTeamModal" class="btn btn-primary" onclick="javascript:submitAjaxModal('<c:out value="${saveUrl }"/>','#organizationForm', '#formDiv', '#teamTable', '#myTeamModal','');return false;">Add Team</a>
		</div>
		</form:form>
		</div>
	</div>
	
	<div id="teamTable">
		
	</div>
	<spring:url value="/organizations/teamTable" var="tableUrl"/>
	<script>reloadTable("<c:out value="${tableUrl}"/>");</script>
	
</body>
