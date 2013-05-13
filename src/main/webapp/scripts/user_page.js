function confirmRoles(id) {
	return $("#roleSelect" + id).children("option").filter(":selected").text() !== "User" || 
		confirm("You are switching roles from Administrator to User and will be logged out after this change.");
}

function toggleRoles(id) {
	if (! $("#hasGlobalGroupAccessCheckbox" + id).is(':checked')){
		$("#roleSelect" + id).attr("disabled","disabled");
	} else {
		$("#roleSelect" + id).removeAttr("disabled","");
	}
}

var addPasswordHandlers = function() {
	
	$(".ldapCheckbox").each(function(){
		if ($(this).attr("data-value") === "true") {
			$(this).attr("checked", "checked");
		}
	});
	
	$(".ldapCheckbox").each(function(){
		if ($(this).is(':checked')){
			$("." + $(this).attr("data-target-class")).attr("disabled","disabled");
		} else {
			$("." + $(this).attr("data-target-class")).removeAttr("disabled","");
		}
	});
	
	$(".ldapCheckbox").on("click", function(){
		if ($(this).is(':checked')){
			$("." + $(this).attr("data-target-class")).attr("disabled","disabled");
		} else {
			$("." + $(this).attr("data-target-class")).removeAttr("disabled","");
		}
	});
};

addToDocumentReadyFunctions(addPasswordHandlers);

function toggleAppSelect(id) {
	if ($("#allAppsCheckbox" + id).is(':checked')){
		$("#appSelect" + id + " :input").attr("disabled","disabled");
		$("#roleSelectTeam" + id).removeAttr("disabled","");
	} else {
		$("#appSelect" + id + " :input").removeAttr("disabled","");
		$("#roleSelectTeam" + id).attr("disabled","disabled");
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
			
			if ($.trim(text).slice(0,5) === "<body") {
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

