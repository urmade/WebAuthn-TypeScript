//The functions declared here have absolutely nothing to do with the WebAuthn specification. They are just provided for a smoother UI experience in the demo!

function checkCompleteness() {
	if (
		document.getElementById("uname").value != "" &&
		document.getElementById("fname").value != ""
	)
		document.getElementById("btn").removeAttribute("disabled");
	else
		document.getElementById("btn").setAttribute("disabled", "true");
}

function togglePlatform(id) {
	if (id == "platform") {
		document.getElementById("platform").classList.add("active");
		document.getElementById("cross-platform").classList.remove("active");
		platform = "platform";
	}
	else {
		document.getElementById("platform").classList.remove("active");
		document.getElementById("cross-platform").classList.add("active");
		platform = "cross-platform";
	}
}

function loadLogin() {
	document.getElementById("btn").innerHTML = "All set! Login is loading...";
	document.getElementById("btn").style.backgroundColor = "green";
	window.setTimeout(() => {
		let form = document.getElementsByClassName("form")[0];
		form.innerHTML = '<button id="login" onclick="startLogin()">Log in</button>';

	}, 1500)
}

function BtnLoadUI() {
	document.getElementsByTagName("button")[0].innerHTML = '<div class="lds-ellipsis"><div></div><div></div><div></div><div></div></div>';
	document.getElementsByTagName("button")[0].setAttribute("disabled", "true");
}

function verifyLogin() {
	let btn = document.getElementById("login");
	btn.innerHTML = "Congratulations! You are now logged in, without any password!";
	btn.style.backgroundColor = "green";
}