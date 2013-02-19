function confirmRoles() {
	return $("#roleSelect").children("option").filter(":selected").text() !== "User" || 
		confirm("You are switching roles from Administrator to User and will be logged out after this change.");
}

function toggleRoles() {
	if (! $("#hasGlobalGroupAccessCheckbox").is(':checked')){
		$("#roleSelect").attr("disabled","disabled");
	} else {
		$("#roleSelect").removeAttr("disabled","");
	}
}

function togglePassword() {
	if ($("#isLdapUserCheckbox").is(':checked')){
		$("#passwordConfirmInput").attr("disabled","disabled");
		$("#passwordInput").attr("disabled","disabled");
	} else {
		$("#passwordConfirmInput").removeAttr("disabled","");
		$("#passwordInput").removeAttr("disabled","");
	}
}

function toggleAppSelect() {
	if ($("#allAppsCheckbox").is(':checked')){
		$("#appSelect :input").attr("disabled","disabled");
		$("#roleSelectTeam").removeAttr("disabled","");
	} else {
		$("#appSelect :input").removeAttr("disabled","");
		$("#roleSelectTeam").attr("disabled","disabled");
	}
}

function submitModal(url) {
	$.ajax({
		type : "POST",
		url : url,
		data : $("#newAccessControlMapForm").serializeArray(),
		contentType : "application/x-www-form-urlencoded",
		dataType : "text",
		success : function(text) {
			
			if ($.trim(text).slice(0,6) === "<body>") {
				$('#myModal').on('hidden', function () {
					$("#permsTableDiv").html(text);
			    });
			    $("#myModal").modal('hide');
			    setTimeout(function() {
					$("#orgSelect").val('');
					$("#roleSelectTeam").val('');
					$("#orgSelect").change();
					if (! $("#allAppsCheckbox").is(':checked')) {
						$("#allAppsCheckbox").click();
					}
					toggleAppSelect();
				}, 1000);
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

function submitFormAndReload(address) {
	$.ajax({
		type : "POST",
		url : address,
		data : "",
		contentType : "application/x-www-form-urlencoded",
		dataType : "text",
		success : function(text) {
			$("#permsTableDiv").html(text);
		},
		error : function (xhr, ajaxOptions, thrownError){
			history.go(0);
	    }
	});
}

