function addComment(url) {
	
	$.ajax({
		type : "POST",
		url : url,
		data : $("#addCommentForm").serializeArray(),
		contentType : "application/x-www-form-urlencoded",
		dataType : "text",
		success : function(text) {
			if (text.trim().slice(0,6) === "<body>") {
			    $("#commentDiv").html(text);
			}
		},
		error : function (xhr, ajaxOptions, thrownError){
			alert('error');
			history.go(0);
	    }
	});
	
	return false;
}
