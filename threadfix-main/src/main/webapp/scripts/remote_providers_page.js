var addRefreshHandlers = function() {
	$(".deleteLink").on("click", function() {
		var errorDiv = "#" + $(this).attr("data-error-div");
		
		$.ajax({
			type : "GET",
			url : $(this).attr("data-url"),
			dataType : "text",
			success : function(text) {
				if ($.trim(text).slice(0,22) === "<body id=\"formErrors\">") {
					$(errorDiv).html(text);
					for (var i = 0; i < modalRefreshFunctions.length; i++) {
						modalRefreshFunctions[i]();
					}
				} else {
					try {
						var json = $.parseJSON($.trim(text));
						if (json.isJSONRedirect) {
							window.location.href = json.redirectURL;
						}
					} catch (e) {
						history.go(0);
					}
				}
				
				
			},
			error : function (xhr, ajaxOptions, thrownError){
				
		    }
		});
	});
};

addToModalRefreshFunctions(addRefreshHandlers);
addToDocumentReadyFunctions(addRefreshHandlers);