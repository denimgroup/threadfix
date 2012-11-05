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
			
			if (text.trim().slice(0,6) === "<head>") {
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
					alert("The JSON was not parsed correctly.");
				}
			}
		},
		error : function (xhr, ajaxOptions, thrownError){
			alert("AJAX failed.");
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
			alert("AJAX failed.");
	    }
	});
}

