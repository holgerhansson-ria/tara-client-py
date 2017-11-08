document.addEventListener('DOMContentLoaded', function() {
   	var initialFormInputs = document.getElementsByClassName("form-control");
	var i; 	
	for (i = 0; i < initialFormInputs.length; i++) {
		var rmvbtn = "rmvbtn-"+initialFormInputs[i].id;
		if (initialFormInputs[i].value === "removed") {
			var disabled = document.createAttribute("disabled"); 
    		initialFormInputs[i].setAttributeNode(disabled);
    		document.getElementById(rmvbtn).classList.remove("glyphicon-remove");
			document.getElementById(rmvbtn).classList.add("glyphicon-plus"); 
    	} 
	}	
}, false);

function rmvParam(id, placeholder) {
	var rmvbtn = "rmvbtn-"+id
	if ( document.getElementById(rmvbtn).classList.contains('glyphicon-remove') ) {
		document.getElementById(id).value = "removed";
		var att = document.createAttribute("disabled");  
		document.getElementById(id).setAttributeNode(att); 
		document.getElementById(rmvbtn).classList.remove("glyphicon-remove");
		document.getElementById(rmvbtn).classList.add("glyphicon-plus");  	
	}
	else {
		document.getElementById(id).value = placeholder;
		document.getElementById(id).removeAttribute("disabled"); 
		document.getElementById(rmvbtn).classList.remove("glyphicon-plus");
		document.getElementById(rmvbtn).classList.add("glyphicon-remove");  
	}
}

function enableInput() {
	var formInputs = document.getElementsByClassName("form-control");
	var i;
	for (i = 0; i < formInputs.length; i++) {
    		formInputs[i].removeAttribute("disabled");
	}		
}
