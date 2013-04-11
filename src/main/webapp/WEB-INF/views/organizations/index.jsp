<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Home</title>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/remote-pagination.js"></script>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/ajax_replace.js"></script>
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
				    $(".clear-after-submit").val('');
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
	<h2>Teams Index</h2>

	<div id="teamTable">
		<a id="addTeamModalButton" href="#myTeamModal" role="button" class="btn" data-toggle="modal" style="margin-bottom:8px;margin-top:10px;">Add Team</a>
	</div>
	
	<spring:url value="/organizations/teamTable" var="tableUrl"/>
	<script>reloadTable("<c:out value="${tableUrl}"/>");</script>
	
	<div id="myTeamModal" class="modal hide fade" tabindex="-1"
		role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
		<div id="formDiv">
			<%@ include file="/WEB-INF/views/organizations/newTeamForm.jsp" %>
		</div>
	</div>
</body>
