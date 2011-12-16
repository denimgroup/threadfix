function deletePopup(url, deleteType) {
	var newUrl = url;
	var type = deleteType;
	
	jQuery("#dialog").dialog("destroy");
	jQuery("#deleteType").html(type);
	jQuery("#delete-dialog").css("display", "block");
	
	jQuery("#delete-dialog").dialog({
		resizable: false,
		height:120,
		width: 400,
		modal: true,
		buttons: {
			Ok: function() {
				jQuery("#deleteType").html('');
				jQuery(this).dialog('close');
				window.location.replace(newUrl);
			},
			Cancel: function() {
				jQuery("#deleteType").html('');
				jQuery(this).dialog('close');
			}
		}
	});
}