function confirmAppDelete(deleteUrl){
	if(confirm("Are you sure you want to delete the application?")){
		document.location = deleteUrl;
	}
}

function confirmOrgDelete(deleteUrl){
	if(confirm("Are you sure you want to delete the organization?")){
		document.location = deleteUrl;
	}
}