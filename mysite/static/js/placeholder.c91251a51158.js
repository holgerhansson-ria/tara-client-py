function addNumber(p_id) {
	var n = document.getElementById(p_id).innerHTML;
    document.getElementById(p_id).innerHTML = n+1;
}

function rmvNumber(p_id) {
	var n = document.getElementById(p_id).innerHTML;
    document.getElementById(p_id).innerHTML = n-1;
}