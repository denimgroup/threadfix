function toggleHelp() {
	if ($("#helpText").css('display') === 'none') {
		$("#helpText").css('display','inline-block');
	} else {
		$("#helpText").css('display','none');
	}
}

function toggleUserMenu() {
	$("#configurationHeader").dropdown('toggle');
}
