var edited = false;
    
function toggle(classToToggle) {
	if ($("." + classToToggle).css('display') === 'none') {
		$("." + classToToggle).css('display', '');
	} else {
		$("." + classToToggle).css('display', 'none');
	}
}

function markEdited() {
	edited = true;
}

function confirmExit() {
	return !edited || confirm('The page has unsaved changes. Are you sure you want to exit?');
}

window.onload = function()
{
	$('.toFix').each(function() { $(this).css('width',($(this).width())); });
};

