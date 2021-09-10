addEventListener("fetch", (event) => {
	let randValues = crypto.getRandomValues(new Uint8Array(252));
	let time = Date.now();
	event.respondWith(
		handleRequest(event.request, randValues, time).catch(
			(err) => new Response(err.stack, { status: 500 })
		)
	);
});

const totpSecret = (typeof TOTP_SECRET !== 'undefined') ? TOTP_SECRET : "";

function cryptoRandom(genArray) {
	let tmpArray = [];

	genArray.forEach(function (ele, index) {
		tmpArray[index] = ele.toString();
		if (ele.toString().length < 3) {
			if (((index === 0) && (Math.random() < 0.1)) || (Math.random() < 0.5)) {
				tmpArray[index] = ("0" + ele);
			}
		}
	});

	return Number("0." + tmpArray.join(""));
}

async function getOtp(secret, time) {
	let arrayToHex = arr =>
		arr.reduce((str, byte) => str + byte.toString(16).padStart(2, "0"), "");

	let base32ToHex = function (src) {
		let bits = "";
		const charlist = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
		let hex = "";
		for (let i = 0; i < src.length; i++) {
			let val = charlist.indexOf(src.charAt(i).toUpperCase());
			bits += padLeft(val.toString(2), 5, '0');
		}
		for (let i = 0; i + 4 <= bits.length; i += 4) {
			let chunk = bits.substr(i, 4);
			hex = hex + parseInt(chunk, 2).toString(16);
		}
		return hex;
	};

	let decToHex = float =>
		((float < 15.5 ? "0" : "") + Math.round(float).toString(16));

	let hexToArray = str =>
		new Uint8Array(str.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));

	let hexToDec = str =>
		parseInt(str, 16);

	let padLeft = function (src, l, p) {
		if (l + 1 >= src.length) {
			src = Array(l + 1 - src.length).join(p) + src;
		}
		return src;
	};

	const epoch = Math.round(time / 1000.0);
	const counter = padLeft(decToHex(Math.floor(epoch / 30)), 16, "0");
	const keyObj = await crypto.subtle.importKey(
		"raw",
		hexToArray(base32ToHex(secret)),
		{ name: "HMAC", hash: { name: "SHA-1" } },
		false,
		["sign"]
	);
	const hmac = arrayToHex(new Uint8Array(await crypto.subtle.sign("HMAC", keyObj, hexToArray(counter))));
	const offset = hexToDec(hmac.substring(hmac.length - 1));
	const otp = (hexToDec(hmac.substr(offset * 2, 8)) & hexToDec("7fffffff")) + "";
	return (otp).substr(otp.length - 6, 6);
}

async function handleRequest(request, randValues, time) {
	// Nonce generation must occur prior to defining response bodies.
	const imageNonce = nonceGenerator(randValues, 1);
	const manifestNonce = nonceGenerator(randValues, 2);
	const scriptNonce = nonceGenerator(randValues, 3);
	const styleNonce = nonceGenerator(randValues, 4);

	const errorBody = `<!DOCTYPE html>
<html lang="en-GB">

<head>
	<meta name="viewport" content="initial-scale=1.0, width=device-width">

	<title>${randomTitle()}</title>

	<link rel="icon" nonce="${imageNonce}"
		href="data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0idXRmLTgiPz4NCjwhRE9DVFlQRSBzdmcgUFVCTElDICItLy9XM0MvL0RURCBTVkcgMS4xLy9FTiIgImh0dHA6Ly93d3cudzMub3JnL0dyYXBoaWNzL1NWRy8xLjEvRFREL3N2ZzExLmR0ZCIgWw0KCTwhRU5USVRZIG5zX2V4dGVuZCAiaHR0cDovL25zLmFkb2JlLmNvbS9FeHRlbnNpYmlsaXR5LzEuMC8iPg0KCTwhRU5USVRZIG5zX2FpICJodHRwOi8vbnMuYWRvYmUuY29tL0Fkb2JlSWxsdXN0cmF0b3IvMTAuMC8iPg0KCTwhRU5USVRZIG5zX2dyYXBocyAiaHR0cDovL25zLmFkb2JlLmNvbS9HcmFwaHMvMS4wLyI+DQoJPCFFTlRJVFkgbnNfdmFycyAiaHR0cDovL25zLmFkb2JlLmNvbS9WYXJpYWJsZXMvMS4wLyI+DQoJPCFFTlRJVFkgbnNfaW1yZXAgImh0dHA6Ly9ucy5hZG9iZS5jb20vSW1hZ2VSZXBsYWNlbWVudC8xLjAvIj4NCgk8IUVOVElUWSBuc19zZncgImh0dHA6Ly9ucy5hZG9iZS5jb20vU2F2ZUZvcldlYi8xLjAvIj4NCgk8IUVOVElUWSBuc19jdXN0b20gImh0dHA6Ly9ucy5hZG9iZS5jb20vR2VuZXJpY0N1c3RvbU5hbWVzcGFjZS8xLjAvIj4NCgk8IUVOVElUWSBuc19hZG9iZV94cGF0aCAiaHR0cDovL25zLmFkb2JlLmNvbS9YUGF0aC8xLjAvIj4NCgk8IUVOVElUWSBzdDAgImZpbGwtcnVsZTpldmVub2RkO2NsaXAtcnVsZTpldmVub2RkO2ZpbGw6I0FFRUEwMDsiPg0KCTwhRU5USVRZIHN0MSAiZmlsbDojQzZGRjAwOyI+DQoJPCFFTlRJVFkgc3QzICJmaWxsOiNBRUVBMDA7Ij4NCl0+DQo8c3ZnIHZlcnNpb249IjEuMSIgaWQ9IkxheWVyXzEiIHhtbG5zOng9IiZuc19leHRlbmQ7IiB4bWxuczppPSImbnNfYWk7IiB4bWxuczpncmFwaD0iJm5zX2dyYXBoczsiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyIgeG1sbnM6eGxpbms9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkveGxpbmsiIHg9IjBweCIgeT0iMHB4IiB2aWV3Qm94PSIwIDAgMzg0IDM4NCIgc3R5bGU9ImVuYWJsZS1iYWNrZ3JvdW5kOm5ldyAwIDAgMzg0IDM4NDsiIHhtbDpzcGFjZT0icHJlc2VydmUiPg0KCTxzdHlsZSB0eXBlPSJ0ZXh0L2NzcyI+DQoJCS5zdDJ7ZmlsbDojRjRGN0RBO30NCgkJQG1lZGlhIChwcmVmZXJzLWNvbG9yLXNjaGVtZTogZGFyaykgew0KCQkJLnN0MntmaWxsOiMyMDIxMTA7fQ0KCQl9DQoJPC9zdHlsZT4NCgk8bWV0YWRhdGE+DQoJCTxzZncgeG1sbnM9IiZuc19zZnc7Ij4NCgkJCTxzbGljZXM+PC9zbGljZXM+DQoJCQk8c2xpY2VTb3VyY2VCb3VuZHMgYm90dG9tTGVmdE9yaWdpbj0idHJ1ZSIgaGVpZ2h0PSIzNjgiIHdpZHRoPSI3NzIiIHg9IjgiIHk9Ii0zNzYiPjwvc2xpY2VTb3VyY2VCb3VuZHM+DQoJCTwvc2Z3Pg0KCTwvbWV0YWRhdGE+DQoJPHBhdGggaWQ9IlJvdW5kZWRfUmVjdGFuZ2xlXzFfY29weSIgc3R5bGU9IiZzdDA7IiBkPSJNMTg0LjU0MywxMy4yNzFoMTM2LjQ3MWMyNy40NDMsMCw0OS43MTYsMjIuMjczLDQ5LjcxNiw0OS43MTZ2MTM2LjQ3MQ0KCWMwLDk0LjYxLTc2LjY2MiwxNzEuMjcyLTE3MS4yNzIsMTcxLjI3MmgtMTQuOTE1Yy05NC42MSwwLTE3MS4yNzItNzYuNjYyLTE3MS4yNzItMTcxLjI3MnYtMTQuOTE1DQoJQzEzLjI3MSw4OS45MzMsODkuOTMzLDEzLjI3MSwxODQuNTQzLDEzLjI3MXogTTE4NC41NDMsMTMuMjcxaDE0LjkxNWM5NC42MSwwLDE3MS4yNzIsNzYuNjYyLDE3MS4yNzIsMTcxLjI3MnYxNC45MTUNCgljMCw5NC42MS03Ni42NjIsMTcxLjI3Mi0xNzEuMjcyLDE3MS4yNzJINjIuOTg3Yy0yNy40NDMsMC00OS43MTYtMjIuMjczLTQ5LjcxNi00OS43MTZsMCwwVjE4NC41NDMNCglDMTMuMjcxLDg5LjkzMyw4OS45MzMsMTMuMjcxLDE4NC41NDMsMTMuMjcxeiIgLz4NCgk8Y2lyY2xlIHN0eWxlPSImc3QxOyIgY3g9IjE5MiIgY3k9IjE5MiIgcj0iMTg0IiAvPg0KCTxjaXJjbGUgY2xhc3M9InN0MiIgY3g9IjE5MiIgY3k9IjE5MiIgcj0iMTU3LjE2NyIgLz4NCgk8Zz4NCgkJPGc+DQoJCQk8cGF0aCBzdHlsZT0iJnN0MzsiIGQ9Ik0xNDAuODgyLDI2Mi4zMThjLTEuNjAyLDAtMy0wLjU1OS00LjItMS42ODFjLTEuMi0xLjExNy0xLjgtMi41NTctMS44LTQuMzE5di0xOC43MjENCgkJCWMwLTEuNzU4LDAuMzYtMy4yNzcsMS4wOC00LjU2YzAuNzItMS4yNzgsMS42MzktMi40NzksMi43Ni0zLjZsNTYuMTYtNjAuOTZoLTUxLjg0Yy0xLjc2MiwwLTMuMjQtMC41NTktNC40NC0xLjY4DQoJCQljLTEuMi0xLjExOC0xLjgtMi41NTgtMS44LTQuMzJ2LTE4Ljk2YzAtMS43NTksMC42LTMuMTk5LDEuOC00LjMyYzEuMi0xLjExNywyLjY3OC0xLjY4LDQuNDQtMS42OGg5Ni40OA0KCQkJYzEuNTk4LDAsMywwLjU2Miw0LjIsMS42OGMxLjIsMS4xMjIsMS44LDIuNTYyLDEuOCw0LjMydjIwLjRjMCwxLjQ0LTAuMzIyLDIuNzIyLTAuOTYsMy44NGMtMC42NDEsMS4xMjEtMS40NCwyLjI0My0yLjQsMy4zNg0KCQkJbC01NC43Miw2MC4yNGg1Ni44OGMxLjc1OSwwLDMuMTk5LDAuNTYyLDQuMzIsMS42OGMxLjExOCwxLjEyMSwxLjY4LDIuNTYyLDEuNjgsNC4zMnYxOC45NmMwLDEuNzYzLTAuNTYyLDMuMjAyLTEuNjgsNC4zMTkNCgkJCWMtMS4xMjEsMS4xMjItMi41NjEsMS42ODEtNC4zMiwxLjY4MUgxNDAuODgyeiIgLz4NCgkJPC9nPg0KCTwvZz4NCjwvc3ZnPg0K">

	<link rel="manifest" nonce="${manifestNonce}" href="data:application/json;base64,ew0KCSJuYW1lIjogIlF1aWNrbmFtZSIsDQoJImRlc2NyaXB0aW9uIjogIk5vdCB5b3VyIGF2ZXJhZ2UgbGluayBzaG9ydG5lci4iLA0KCSJpY29ucyI6IFsNCgkJew0KCQkJInNyYyI6ICJodHRwczovL3F1aWNrbmEubWUvYXdudmJnIiwNCgkJCSJzaXplcyI6ICIxOTJ4MTkyIiwNCgkJCSJ0eXBlIjogImltYWdlL3N2Zyt4bWwiDQoJCX0sDQoJCXsNCgkJCSJzcmMiOiAiaHR0cHM6Ly9xdWlja25hLm1lL2F3bnZiZyIsDQoJCQkic2l6ZXMiOiAiNTEyeDUxMiIsDQoJCQkidHlwZSI6ICJpbWFnZS9zdmcreG1sIg0KCQl9DQoJXSwNCgkic3RhcnRfdXJsIjogImh0dHBzOi8vcXVpY2tuYS5tZSIsDQoJImRpc3BsYXkiOiAic3RhbmRhbG9uZSIsDQoJInByZWZlcl9yZWxhdGVkX2FwcGxpY2F0aW9ucyI6IGZhbHNlDQp9DQo=">

	<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css"
		integrity="sha384-EVSTQN3/azprG1Anm3QDgpJLIm9Nao0Yz1ztcQTwFspd3yD65VohhpuuCOmLASjC" crossorigin="anonymous"
		rel="stylesheet" nonce="${styleNonce}">

	<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/js/bootstrap.bundle.min.js"
		integrity="sha384-MrcW6ZMFYlzcLA8Nl+NtUVF0sA7MsXsP1UyJoMp4YLEuNSfAP+JcXn/tWtIaxVXM"
		crossorigin="anonymous" nonce="${scriptNonce}"></script>

	<script nonce="${scriptNonce}">
		const divInstall = document.getElementById("installContainer");
		const butInstall = document.getElementById("butInstall");

		if ('serviceWorker' in navigator) {
  			navigator.serviceWorker.register("c2VydmljZS13b3JrZXI");
		}
	</script>

	<style nonce="${styleNonce}">
		@import url("https://fonts.googleapis.com/css2?family=Google+Sans:wght@500&display=swap");

		*,
		body {
			text-rendering: optimizeLegibility;

			-moz-osx-font-smoothing: grayscale;
			-webkit-font-smoothing: antialiased;
		}

		body,
		html {
			background-color: #FFFFFF;
			height: 100%;
			overflow: hidden;
		}
		@media (prefers-color-scheme: dark) {
			body,
			html {
				background-color: #111111;
			}
		}

		@keyframes glitch-anim {
			0% {
				clip: rect(1px, 9999px, 8px, 0);
				transform: skew(0.45deg);
			}
			5% {
				clip: rect(40px, 9999px, 24px, 0);
				transform: skew(0.2deg);
			}
			10% {
				clip: rect(19px, 9999px, 29px, 0);
				transform: skew(0.53deg);
			}
			15% {
				clip: rect(22px, 9999px, 39px, 0);
				transform: skew(0.61deg);
			}
			20% {
				clip: rect(59px, 9999px, 93px, 0);
				transform: skew(0.52deg);
			}
			25% {
				clip: rect(47px, 9999px, 5px, 0);
				transform: skew(0.52deg);
			}
			30% {
				clip: rect(88px, 9999px, 101px, 0);
				transform: skew(0.45deg);
			}
			35% {
				clip: rect(76px, 9999px, 124px, 0);
				transform: skew(0.37deg);
			}
			40% {
				clip: rect(91px, 9999px, 100px, 0);
				transform: skew(0.46deg);
			}
			45% {
				clip: rect(30px, 9999px, 32px, 0);
				transform: skew(0.77deg);
			}
			50% {
				clip: rect(68px, 9999px, 116px, 0);
				transform: skew(0.43deg);
			}
			55% {
				clip: rect(25px, 9999px, 32px, 0);
				transform: skew(0.58deg);
			}
			60% {
				clip: rect(16px, 9999px, 73px, 0);
				transform: skew(0.47deg);
			}
			65% {
				clip: rect(98px, 9999px, 41px, 0);
				transform: skew(0.35deg);
			}
			70% {
				clip: rect(75px, 9999px, 93px, 0);
				transform: skew(0.74deg);
			}
			75% {
				clip: rect(74px, 9999px, 56px, 0);
				transform: skew(0.3deg);
			}
			80% {
				clip: rect(79px, 9999px, 30px, 0);
				transform: skew(0.5deg);
			}
			85% {
				clip: rect(8px, 9999px, 20px, 0);
				transform: skew(0.53deg);
			}
			90% {
				clip: rect(32px, 9999px, 11px, 0);
				transform: skew(0.54deg);
			}
			95% {
				clip: rect(41px, 9999px, 4px, 0);
				transform: skew(0.31deg);
			}
			100% {
				clip: rect(25px, 9999px, 122px, 0);
				transform: skew(0.02deg);
			}
		}

		.fancy {
			color: #71AC26;
		}

		.form-check-label {
			margin: auto 50px auto 50px !important;
		}

		.form-content h3 {
			color: #111111;
			font-size: 28px;
			font-weight: 600;
			margin-bottom: 5px;
			text-align: left;
		}
		@media (prefers-color-scheme: dark) {
			.form-content h3 {
				color: #FFFFFF;
			}
		}

		.form-content h3.form-title {
			margin-bottom: 30px;
		}

		.form-content input[type=email],
		.form-content input[type=password],
		.form-content input[type=text],
		.form-content select {
			background-color: #EFEFEF;
			border: 0;
			border-radius: 6px;
			font-size: 15px;
			font-weight: 300;
			margin-top: 16px;
			outline: 0;
			padding: 9px 20px;
			text-align: center;
			transition: all 0.3s ease;
			width: 100%;

			-webkit-transition: all 0.3s ease;
		}
		@media (prefers-color-scheme: dark) {
			.form-content input[type=email],
			.form-content input[type=password],
			.form-content input[type=text],
			.form-content select {
				background-color: #212121;
			}
		}

		.form-content input,
		.form-content input:focus {
			color: #111111;
		}
		@media (prefers-color-scheme: dark) {
			.form-content input,
			.form-content input:focus {
				color: #FFFFFF;
			}
		}

		.form-content input::placeholder {
			color: #434343;
		}
		@media (prefers-color-scheme: dark) {
			.form-content input::placeholder {
				color: #CDCDCD;
			}
		}

		.form-content p {
			color: #111111;
			font-size: 17px;
			font-weight: 300;
			line-height: 20px;
			margin-bottom: 30px;
			text-align: left;
		}
		@media (prefers-color-scheme: dark) {
			.form-content p {
				color: #FFFFFF;
			}
		}

		.form-content textarea {
			border: 0;
			border-radius: 6px;
			font-size: 15px;
			font-weight: 300;
			height: 120px;
			margin-bottom: 14px;
			outline: none;
			padding: 8px 20px;
			position: static !important;
			resize: none;
			text-align: left;
			transition: none;
			width: 100%;

			-webkit-transition: none;
		}

		.form-content textarea:hover,
		.form-content textarea:focus {
			border: 0;
		}

		.form-content .form-holder {
			align-items: center;
			display: -moz-box;
			display: -ms-flexbox;
			display: -webkit-box;
			display: -webkit-flex;
			justify-content: center;
			display: flex;
			padding: 60px;
			position: relative;
			text-align: center;

			-webkit-align-items: center;
			-webkit-justify-content: center;
		}

		.form-content .form-items {
			display: inline-block;
			min-width: 540px;
			padding: 40px;
			text-align: left;
			transition: all 0.4s ease;
			width: 100%;

			-webkit-transition: all 0.4s ease;
		}

		.form-content label,
		.was-validated .form-check-input:invalid~.form-check-label,
		.was-validated .form-check-input:valid~.form-check-label {
			color: #111111;
		}
		@media (prefers-color-scheme: dark) {
			.form-content label,
			.was-validated .form-check-input:invalid~.form-check-label,
			.was-validated .form-check-input:valid~.form-check-label {
				color: #FFFFFF;
			}
		}

		.form-control {
			margin: 14px auto 0 auto !important;
		}
		@media all and (orientation: portrait) {
			.form-control {
				width: 80% !important;
			}
		}

		.form-holder {
			align-items: center;
			display: flex;
			flex-direction: column;
			justify-content: center;
			min-height: 100vh;
			text-align: center;
		}

		.glitch {
			position: relative;
		}

		.glitch::after {
			content: attr(data-text);
			inset: 0 auto auto 0;
			position: absolute;
			width: 100%;
			animation: glitch-anim 2s infinite ease-out alternate-reverse;
			left: -2px;
			text-shadow: -2px 0 #8E53D9, 2px 2px #71AC26;
		}
		@media (prefers-reduced-motion) {
			.glitch::after {
				content: none;
				animation: none;
			}
		}

		.glitch::before {
			content: attr(data-text);
			inset: 0 auto auto 0;
			position: absolute;
			width: 100%;
			animation: glitch-anim 5s infinite ease-in alternate-reverse;
			clip-path: polygon(44px, 450px, 56px, 0);
			left: 2px;
			text-shadow: -2px 0 #111111;
		}
		@media (prefers-color-scheme: dark) {
			.glitch::before {
				text-shadow: -2px 0 #FFFFFF;
			}
		}
		@media (prefers-reduced-motion) {
			.glitch::before {
				content: none;
				animation: none;
			}
		}

		.headline {
			font-family: 'Google Sans', sans-serif !important;
			font-weight: 500 !important;
			margin-left: 50px !important;
			margin-right: 50px !important;
		}
	</style>
</head>

<body>
	<div class="form-body">
		<div class="row">
			<div class="form-holder">
				<div class="form-content">
					<div class="form-items">
						<h3 class="text-center mx-auto headline glitch" data-text="This is not the page you were looking for">This is not the page you were looking for<span class="fancy">.</span></h3>
						<h3 class="text-center mx-auto headline glitch" data-text=":'(">:'(</h3>
					</div>
				</div>
			</div>
		</div>
	</div>
</body>

</html>`
	const formBody = `<!DOCTYPE html>
<html lang="en-GB">

<head>
	<meta name="viewport" content="initial-scale=1.0, width=device-width">

	<title>Quickname Link Shortener</title>

	<link rel="icon" nonce="${imageNonce}"
		href="data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0idXRmLTgiPz4NCjwhRE9DVFlQRSBzdmcgUFVCTElDICItLy9XM0MvL0RURCBTVkcgMS4xLy9FTiIgImh0dHA6Ly93d3cudzMub3JnL0dyYXBoaWNzL1NWRy8xLjEvRFREL3N2ZzExLmR0ZCIgWw0KCTwhRU5USVRZIG5zX2V4dGVuZCAiaHR0cDovL25zLmFkb2JlLmNvbS9FeHRlbnNpYmlsaXR5LzEuMC8iPg0KCTwhRU5USVRZIG5zX2FpICJodHRwOi8vbnMuYWRvYmUuY29tL0Fkb2JlSWxsdXN0cmF0b3IvMTAuMC8iPg0KCTwhRU5USVRZIG5zX2dyYXBocyAiaHR0cDovL25zLmFkb2JlLmNvbS9HcmFwaHMvMS4wLyI+DQoJPCFFTlRJVFkgbnNfdmFycyAiaHR0cDovL25zLmFkb2JlLmNvbS9WYXJpYWJsZXMvMS4wLyI+DQoJPCFFTlRJVFkgbnNfaW1yZXAgImh0dHA6Ly9ucy5hZG9iZS5jb20vSW1hZ2VSZXBsYWNlbWVudC8xLjAvIj4NCgk8IUVOVElUWSBuc19zZncgImh0dHA6Ly9ucy5hZG9iZS5jb20vU2F2ZUZvcldlYi8xLjAvIj4NCgk8IUVOVElUWSBuc19jdXN0b20gImh0dHA6Ly9ucy5hZG9iZS5jb20vR2VuZXJpY0N1c3RvbU5hbWVzcGFjZS8xLjAvIj4NCgk8IUVOVElUWSBuc19hZG9iZV94cGF0aCAiaHR0cDovL25zLmFkb2JlLmNvbS9YUGF0aC8xLjAvIj4NCgk8IUVOVElUWSBzdDAgImZpbGwtcnVsZTpldmVub2RkO2NsaXAtcnVsZTpldmVub2RkO2ZpbGw6I0FFRUEwMDsiPg0KCTwhRU5USVRZIHN0MSAiZmlsbDojQzZGRjAwOyI+DQoJPCFFTlRJVFkgc3QzICJmaWxsOiNBRUVBMDA7Ij4NCl0+DQo8c3ZnIHZlcnNpb249IjEuMSIgaWQ9IkxheWVyXzEiIHhtbG5zOng9IiZuc19leHRlbmQ7IiB4bWxuczppPSImbnNfYWk7IiB4bWxuczpncmFwaD0iJm5zX2dyYXBoczsiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyIgeG1sbnM6eGxpbms9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkveGxpbmsiIHg9IjBweCIgeT0iMHB4IiB2aWV3Qm94PSIwIDAgMzg0IDM4NCIgc3R5bGU9ImVuYWJsZS1iYWNrZ3JvdW5kOm5ldyAwIDAgMzg0IDM4NDsiIHhtbDpzcGFjZT0icHJlc2VydmUiPg0KCTxzdHlsZSB0eXBlPSJ0ZXh0L2NzcyI+DQoJCS5zdDJ7ZmlsbDojRjRGN0RBO30NCgkJQG1lZGlhIChwcmVmZXJzLWNvbG9yLXNjaGVtZTogZGFyaykgew0KCQkJLnN0MntmaWxsOiMyMDIxMTA7fQ0KCQl9DQoJPC9zdHlsZT4NCgk8bWV0YWRhdGE+DQoJCTxzZncgeG1sbnM9IiZuc19zZnc7Ij4NCgkJCTxzbGljZXM+PC9zbGljZXM+DQoJCQk8c2xpY2VTb3VyY2VCb3VuZHMgYm90dG9tTGVmdE9yaWdpbj0idHJ1ZSIgaGVpZ2h0PSIzNjgiIHdpZHRoPSI3NzIiIHg9IjgiIHk9Ii0zNzYiPjwvc2xpY2VTb3VyY2VCb3VuZHM+DQoJCTwvc2Z3Pg0KCTwvbWV0YWRhdGE+DQoJPHBhdGggaWQ9IlJvdW5kZWRfUmVjdGFuZ2xlXzFfY29weSIgc3R5bGU9IiZzdDA7IiBkPSJNMTg0LjU0MywxMy4yNzFoMTM2LjQ3MWMyNy40NDMsMCw0OS43MTYsMjIuMjczLDQ5LjcxNiw0OS43MTZ2MTM2LjQ3MQ0KCWMwLDk0LjYxLTc2LjY2MiwxNzEuMjcyLTE3MS4yNzIsMTcxLjI3MmgtMTQuOTE1Yy05NC42MSwwLTE3MS4yNzItNzYuNjYyLTE3MS4yNzItMTcxLjI3MnYtMTQuOTE1DQoJQzEzLjI3MSw4OS45MzMsODkuOTMzLDEzLjI3MSwxODQuNTQzLDEzLjI3MXogTTE4NC41NDMsMTMuMjcxaDE0LjkxNWM5NC42MSwwLDE3MS4yNzIsNzYuNjYyLDE3MS4yNzIsMTcxLjI3MnYxNC45MTUNCgljMCw5NC42MS03Ni42NjIsMTcxLjI3Mi0xNzEuMjcyLDE3MS4yNzJINjIuOTg3Yy0yNy40NDMsMC00OS43MTYtMjIuMjczLTQ5LjcxNi00OS43MTZsMCwwVjE4NC41NDMNCglDMTMuMjcxLDg5LjkzMyw4OS45MzMsMTMuMjcxLDE4NC41NDMsMTMuMjcxeiIgLz4NCgk8Y2lyY2xlIHN0eWxlPSImc3QxOyIgY3g9IjE5MiIgY3k9IjE5MiIgcj0iMTg0IiAvPg0KCTxjaXJjbGUgY2xhc3M9InN0MiIgY3g9IjE5MiIgY3k9IjE5MiIgcj0iMTU3LjE2NyIgLz4NCgk8Zz4NCgkJPGc+DQoJCQk8cGF0aCBzdHlsZT0iJnN0MzsiIGQ9Ik0xNDAuODgyLDI2Mi4zMThjLTEuNjAyLDAtMy0wLjU1OS00LjItMS42ODFjLTEuMi0xLjExNy0xLjgtMi41NTctMS44LTQuMzE5di0xOC43MjENCgkJCWMwLTEuNzU4LDAuMzYtMy4yNzcsMS4wOC00LjU2YzAuNzItMS4yNzgsMS42MzktMi40NzksMi43Ni0zLjZsNTYuMTYtNjAuOTZoLTUxLjg0Yy0xLjc2MiwwLTMuMjQtMC41NTktNC40NC0xLjY4DQoJCQljLTEuMi0xLjExOC0xLjgtMi41NTgtMS44LTQuMzJ2LTE4Ljk2YzAtMS43NTksMC42LTMuMTk5LDEuOC00LjMyYzEuMi0xLjExNywyLjY3OC0xLjY4LDQuNDQtMS42OGg5Ni40OA0KCQkJYzEuNTk4LDAsMywwLjU2Miw0LjIsMS42OGMxLjIsMS4xMjIsMS44LDIuNTYyLDEuOCw0LjMydjIwLjRjMCwxLjQ0LTAuMzIyLDIuNzIyLTAuOTYsMy44NGMtMC42NDEsMS4xMjEtMS40NCwyLjI0My0yLjQsMy4zNg0KCQkJbC01NC43Miw2MC4yNGg1Ni44OGMxLjc1OSwwLDMuMTk5LDAuNTYyLDQuMzIsMS42OGMxLjExOCwxLjEyMSwxLjY4LDIuNTYyLDEuNjgsNC4zMnYxOC45NmMwLDEuNzYzLTAuNTYyLDMuMjAyLTEuNjgsNC4zMTkNCgkJCWMtMS4xMjEsMS4xMjItMi41NjEsMS42ODEtNC4zMiwxLjY4MUgxNDAuODgyeiIgLz4NCgkJPC9nPg0KCTwvZz4NCjwvc3ZnPg0K">

	<link rel="manifest" nonce="${manifestNonce}" href="data:application/json;base64,ew0KCSJuYW1lIjogIlF1aWNrbmFtZSIsDQoJImRlc2NyaXB0aW9uIjogIk5vdCB5b3VyIGF2ZXJhZ2UgbGluayBzaG9ydG5lci4iLA0KCSJpY29ucyI6IFsNCgkJew0KCQkJInNyYyI6ICJodHRwczovL3F1aWNrbmEubWUvYXdudmJnIiwNCgkJCSJzaXplcyI6ICIxOTJ4MTkyIiwNCgkJCSJ0eXBlIjogImltYWdlL3N2Zyt4bWwiDQoJCX0sDQoJCXsNCgkJCSJzcmMiOiAiaHR0cHM6Ly9xdWlja25hLm1lL2F3bnZiZyIsDQoJCQkic2l6ZXMiOiAiNTEyeDUxMiIsDQoJCQkidHlwZSI6ICJpbWFnZS9zdmcreG1sIg0KCQl9DQoJXSwNCgkic3RhcnRfdXJsIjogImh0dHBzOi8vcXVpY2tuYS5tZSIsDQoJImRpc3BsYXkiOiAic3RhbmRhbG9uZSIsDQoJInByZWZlcl9yZWxhdGVkX2FwcGxpY2F0aW9ucyI6IGZhbHNlDQp9DQo=">

	<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css"
		integrity="sha384-EVSTQN3/azprG1Anm3QDgpJLIm9Nao0Yz1ztcQTwFspd3yD65VohhpuuCOmLASjC" crossorigin="anonymous"
		rel="stylesheet" nonce="${styleNonce}">

	<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/js/bootstrap.bundle.min.js"
		integrity="sha384-MrcW6ZMFYlzcLA8Nl+NtUVF0sA7MsXsP1UyJoMp4YLEuNSfAP+JcXn/tWtIaxVXM"
		crossorigin="anonymous" nonce="${scriptNonce}"></script>

	<script nonce="${scriptNonce}">
		const divInstall = document.getElementById("installContainer");
		const butInstall = document.getElementById("butInstall");

		if ('serviceWorker' in navigator) {
  			navigator.serviceWorker.register("c2VydmljZS13b3JrZXI");
		}
	</script>

	<style nonce="${styleNonce}">
		@import url("https://fonts.googleapis.com/css2?family=Google+Sans:wght@500&display=swap");
		@import url("https://fonts.googleapis.com/css2?family=Google+Sans+Text:wght@400&display=swap");

		*,
		body {
			font-family: 'Google Sans Text', sans-serif;
			font-weight: 400;
			text-rendering: optimizeLegibility;

			-moz-osx-font-smoothing: grayscale;
			-webkit-font-smoothing: antialiased;
		}

		a {
			text-decoration: none;
		}

		a:active {
			color: #F44336;
		}

		a:link {
			color: #2196F3;
		}

		a:visited {
			color: #673AB7;
		}

		body,
		html {
			background-color: #FFFFFF;
			height: 100%;
			overflow: hidden;
		}
		@media (prefers-color-scheme: dark) {
			body,
			html {
				background-color: #111111;
			}
		}

		.btn-primary {
			color: #71AC26;
			background-color: #D5EFB5;
			border: 0px;
			box-shadow: none;
			font-size: 0.9rem;
			outline: none;
		}

		.btn-primary:hover,
		.btn-primary:focus,
		.btn-primary:active {
			background-color: #B6E37E;
			border: none !important;
			box-shadow: none;
			outline: none !important;
		}

		.fancy {
			color: #71AC26;
		}

		.form-check-label {
			margin: auto 50px auto 50px !important;
		}

		.form-content h3 {
			color: #111111;
			font-size: 28px;
			font-weight: 600;
			margin-bottom: 5px;
			text-align: left;
		}
		@media (prefers-color-scheme: dark) {
			.form-content h3 {
				color: #FFFFFF;
			}
		}

		.form-content h3.form-title {
			margin-bottom: 30px;
		}

		.form-content input[type=email],
		.form-content input[type=password],
		.form-content input[type=text],
		.form-content select {
			background-color: #EFEFEF;
			border: 0;
			border-radius: 6px;
			font-size: 15px;
			font-weight: 300;
			margin-top: 16px;
			outline: 0;
			padding: 9px 20px;
			text-align: center;
			transition: all 0.3s ease;
			width: 100%;

			-webkit-transition: all 0.3s ease;
		}
		@media (prefers-color-scheme: dark) {
			.form-content input[type=email],
			.form-content input[type=password],
			.form-content input[type=text],
			.form-content select {
				background-color: #212121;
			}
		}

		.form-content input,
		.form-content input:focus {
			color: #111111;
		}
		@media (prefers-color-scheme: dark) {
			.form-content input,
			.form-content input:focus {
				color: #FFFFFF;
			}
		}

		.form-content input::placeholder {
			color: #434343;
		}
		@media (prefers-color-scheme: dark) {
			.form-content input::placeholder {
				color: #CDCDCD;
			}
		}

		.form-content p {
			color: #111111;
			font-size: 17px;
			font-weight: 300;
			line-height: 20px;
			margin-bottom: 30px;
			text-align: left;
		}
		@media (prefers-color-scheme: dark) {
			.form-content p {
				color: #FFFFFF;
			}
		}

		.form-content textarea {
			border: 0;
			border-radius: 6px;
			font-size: 15px;
			font-weight: 300;
			height: 120px;
			margin-bottom: 14px;
			outline: none;
			padding: 8px 20px;
			position: static !important;
			resize: none;
			text-align: left;
			transition: none;
			width: 100%;

			-webkit-transition: none;
		}

		.form-content textarea:hover,
		.form-content textarea:focus {
			border: 0;
		}

		.form-content .form-holder {
			align-items: center;
			display: -moz-box;
			display: -ms-flexbox;
			display: -webkit-box;
			display: -webkit-flex;
			justify-content: center;
			display: flex;
			padding: 60px;
			position: relative;
			text-align: center;

			-webkit-align-items: center;
			-webkit-justify-content: center;
		}

		.form-content .form-items {
			display: inline-block;
			min-width: 540px;
			padding: 40px;
			text-align: left;
			transition: all 0.4s ease;
			width: 100%;

			-webkit-transition: all 0.4s ease;
		}

		.form-content label,
		.was-validated .form-check-input:invalid~.form-check-label,
		.was-validated .form-check-input:valid~.form-check-label {
			color: #111111;
		}
		@media (prefers-color-scheme: dark) {
			.form-content label,
			.was-validated .form-check-input:invalid~.form-check-label,
			.was-validated .form-check-input:valid~.form-check-label {
				color: #FFFFFF;
			}
		}

		.form-control {
			margin: 14px auto 0 auto !important;
		}
		@media all and (orientation: portrait) {
			.form-control {
				width: 80% !important;
			}
		}

		.form-holder {
			align-items: center;
			display: flex;
			flex-direction: column;
			justify-content: center;
			min-height: 100vh;
			text-align: center;
		}

		.headline {
			font-family: 'Google Sans', sans-serif !important;
			font-weight: 500 !important;
		}

		.mv-up {
			margin-top: -9px !important;
			margin-bottom: 8px !important;
		}
	</style>
</head>

<body>
	<div class="form-body">
		<div class="row">
			<div class="form-holder">
				<div class="form-content">
					<div class="form-items">
						<h3 class="text-center mx-auto headline">Quickna<span class="fancy">.</span>me</h3>
						<p class="text-center mx-auto headline"><s>Not</s> your average link shortener.</p>
						<div class="col-md-12">
							<input class="form-control" type="text" id="url" placeholder="URL" required>
						</div>
						<div class="col-md-12">
							<input class="form-control" type="text" id="alias" placeholder="Alias (Optional)">
						</div>
						<div class="col-md-12">
							<input class="form-control" type="text" id="totp" placeholder="TOTP (Optional)">
						</div>
						<div class="form-button mt-4 text-center mx-auto ">
							<!--sse-->
							<button id="submit" class="btn btn-primary">Shorten</button>
							<script nonce="${scriptNonce}">
								function isLsAvail() {
									const testContent = "dreamIsACheater";
									try {
										localStorage.setItem(test, testContent);
										localStorage.removeItem(test);
										return true;
									} catch(e) {
										return false;
									}
								}

								function submitRequest() {
									if (isLsAvail() === true) {
										while (localStorage.getItem(requestPending) === true) {
											document.getElementById("status").innerText = "Please wait for the previous request before submitting a new one."
											continue;
										}
										localStorage.setItem(requestPending, true);
									}
									document.getElementById("status").innerText = "Shrinking the URL..."
									const object = {
										origin: document.getElementById("url").value,
										alias: document.getElementById("alias").value,
										totp: document.getElementById("totp").value
									}
									fetch('/', {
										method: "POST",
										body: JSON.stringify(object),
										headers: {
											'Content-Type': 'application/json'
										}
									})
										.then(data => data.text())
										.then(data => {
											document.getElementById("status").innerHTML = data;
										})
										.then(data => {
											const linkElement = document.getElementById("redirLink");
											if (linkElement) {
												navigator.clipboard.writeText(linkElement.href);
											}
											if (isLsAvail() === true) {
												localStorage.setItem(requestPending, false);
											}
										});
								}

								function wrapperEnterKeySubmit(event) {
									if (event.key === 'Enter') {
										submitRequest();
									}
								}

								document.getElementById("url").addEventListener("keypress", wrapperEnterKeySubmit);
								document.getElementById("alias").addEventListener("keypress", wrapperEnterKeySubmit);
								document.getElementById("totp").addEventListener("keypress", wrapperEnterKeySubmit);
								document.getElementById("submit").addEventListener("click", submitRequest);
							</script>
							<!--/sse-->
						</div>
						<div class=" col-md-12 mt-5 text-center mx-auto">
							<label class="form-check-label" id="status"></label>
						</div>
					</div>
				</div>
			</div>
		</div>
	</div>
</body>

</html>`
	const icon = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd" [
	<!ENTITY ns_extend "http://ns.adobe.com/Extensibility/1.0/">
	<!ENTITY ns_ai "http://ns.adobe.com/AdobeIllustrator/10.0/">
	<!ENTITY ns_graphs "http://ns.adobe.com/Graphs/1.0/">
	<!ENTITY ns_vars "http://ns.adobe.com/Variables/1.0/">
	<!ENTITY ns_imrep "http://ns.adobe.com/ImageReplacement/1.0/">
	<!ENTITY ns_sfw "http://ns.adobe.com/SaveForWeb/1.0/">
	<!ENTITY ns_custom "http://ns.adobe.com/GenericCustomNamespace/1.0/">
	<!ENTITY ns_adobe_xpath "http://ns.adobe.com/XPath/1.0/">
	<!ENTITY st0 "fill-rule:evenodd;clip-rule:evenodd;fill:#AEEA00;">
	<!ENTITY st1 "fill:#C6FF00;">
	<!ENTITY st3 "fill:#AEEA00;">
]>
<svg version="1.1" id="Layer_1" xmlns:x="&ns_extend;" xmlns:i="&ns_ai;" xmlns:graph="&ns_graphs;" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" x="0px" y="0px" viewBox="0 0 384 384" style="enable-background:new 0 0 384 384;" xml:space="preserve">
	<style type="text/css">
		.st2{fill:#F4F7DA;}
		@media (prefers-color-scheme: dark) {
			.st2{fill:#202110;}
		}
	</style>
	<metadata>
		<sfw xmlns="&ns_sfw;">
			<slices></slices>
			<sliceSourceBounds bottomLeftOrigin="true" height="368" width="772" x="8" y="-376"></sliceSourceBounds>
		</sfw>
	</metadata>
	<path id="Rounded_Rectangle_1_copy" style="&st0;" d="M184.543,13.271h136.471c27.443,0,49.716,22.273,49.716,49.716v136.471
	c0,94.61-76.662,171.272-171.272,171.272h-14.915c-94.61,0-171.272-76.662-171.272-171.272v-14.915
	C13.271,89.933,89.933,13.271,184.543,13.271z M184.543,13.271h14.915c94.61,0,171.272,76.662,171.272,171.272v14.915
	c0,94.61-76.662,171.272-171.272,171.272H62.987c-27.443,0-49.716-22.273-49.716-49.716l0,0V184.543
	C13.271,89.933,89.933,13.271,184.543,13.271z" />
	<circle style="&st1;" cx="192" cy="192" r="184" />
	<circle class="st2" cx="192" cy="192" r="157.167" />
	<g>
		<g>
			<path style="&st3;" d="M140.882,262.318c-1.602,0-3-0.559-4.2-1.681c-1.2-1.117-1.8-2.557-1.8-4.319v-18.721
			c0-1.758,0.36-3.277,1.08-4.56c0.72-1.278,1.639-2.479,2.76-3.6l56.16-60.96h-51.84c-1.762,0-3.24-0.559-4.44-1.68
			c-1.2-1.118-1.8-2.558-1.8-4.32v-18.96c0-1.759,0.6-3.199,1.8-4.32c1.2-1.117,2.678-1.68,4.44-1.68h96.48
			c1.598,0,3,0.562,4.2,1.68c1.2,1.122,1.8,2.562,1.8,4.32v20.4c0,1.44-0.322,2.722-0.96,3.84c-0.641,1.121-1.44,2.243-2.4,3.36
			l-54.72,60.24h56.88c1.759,0,3.199,0.562,4.32,1.68c1.118,1.121,1.68,2.562,1.68,4.32v18.96c0,1.763-0.562,3.202-1.68,4.319
			c-1.121,1.122-2.561,1.681-4.32,1.681H140.882z" />
		</g>
	</g>
</svg>`
	const serviceWorker = `const CACHE_NAME = 'offline';
const OFFLINE_URL = '/';

self.addEventListener('install', function (event) {
	console.log('[ServiceWorker] Install');

	event.waitUntil((async () => {
		const cache = await caches.open(CACHE_NAME);
		// Setting {cache: 'reload'} in the new request will ensure that the response
		// isn't fulfilled from the HTTP cache; i.e., it will be from the network.
		await cache.add(new Request(OFFLINE_URL, { cache: 'reload' }));
	})());

	self.skipWaiting();
});

self.addEventListener('activate', (event) => {
	console.log('[ServiceWorker] Activate');
	event.waitUntil((async () => {
		// Disable navigation preload if it's supported.
		if ('navigationPreload' in self.registration) {
			await self.registration.navigationPreload.disable();
		}
	})());

	// Tell the active service worker to take control of the page immediately.
	self.clients.claim();
});

self.addEventListener('fetch', function (event) {
	if (event.request.mode === 'navigate') {
		event.respondWith((async () => {
			try {
				const preloadResponse = await event.preloadResponse;
				if (preloadResponse) {
					return preloadResponse;
				}

				const networkResponse = await fetch(event.request);
				return networkResponse;
			} catch (error) {
				console.log('[Service Worker] Fetch failed; returning offline page instead.', error);

				const cache = await caches.open(CACHE_NAME);
				const cachedResponse = await cache.match(OFFLINE_URL);
				return cachedResponse;
			}
		})());
	}
});`

	if (request.method === "GET") {
		let pathname = request.url.replace(/https:\/\/.+?\//g, "");
		pathname = pathname.replace(/http:\/\/.+?\//g, "");
		pathname = pathname.toLowerCase();

		if (pathname != "") {
			// TODO: Clean up the code for the reserved aliases.
			if (pathname == "awnvbg") {
				return new Response(icon, { headers: { "content-type": "image/svg+xml" } });
			} else if (pathname == "c2vydmljzs13b3jrzxi") {
				return new Response(serviceWorker, { headers: { "content-type": "application/javascript" } });
			}

			let redirectTo = await KV_STORE.get(pathname);
			if (redirectTo !== null) {
				return Response.redirect(redirectTo, 301);
			}
			else {
				return new Response(errorBody, {
					headers: {
						"content-type": "text/html",
						"content-security-policy": `default-src 'none';  base-uri 'self'; connect-src 'self' https://cloudflareinsights.com; form-action 'self'; font-src https://fonts.gstatic.com; frame-ancestors https://dash.cloudflare.com; img-src data: 'nonce-${imageNonce}' 'self'; manifest-src data: 'nonce-${manifestNonce}'; navigate-to 'self'; prefetch-src https://cdn.jsdelivr.net https://fonts.googleapis.com https://fonts.gstatic.com 'self'; script-src 'strict-dynamic' 'nonce-${scriptNonce}' 'unsafe-inline'; style-src https: 'strict-dynamic' 'nonce-${styleNonce}' 'unsafe-inline'; worker-src 'self'`,
						"referrer": "strict-origin",
						"strict-transport-security": "max-age=15768000",
						"x-content-type-options": "nosniff",
						"x-frame-options": "DENY",
						"x-xss-protection": "1; mode=block"
					},
					status: 404
				});
			}
		}
		else {
			return new Response(formBody, {
				headers: {
					"content-type": "text/html",
					"content-security-policy": `default-src 'none'; base-uri 'self'; connect-src 'self' https://cloudflareinsights.com; form-action 'self'; font-src https://fonts.gstatic.com; frame-ancestors https://dash.cloudflare.com; img-src data: 'nonce-${imageNonce}' 'self'; manifest-src data: 'nonce-${manifestNonce}'; navigate-to 'self'; prefetch-src https://cdn.jsdelivr.net https://fonts.googleapis.com https://fonts.gstatic.com 'self'; script-src 'strict-dynamic' 'nonce-${scriptNonce}' 'unsafe-inline' https://ajax.cloudflare.com https://static.cloudflareinsights.com; style-src https: 'strict-dynamic' 'nonce-${styleNonce}' 'unsafe-inline'; worker-src 'self'`,
					"referrer": "strict-origin",
					"strict-transport-security": "max-age=15768000",
					"x-content-type-options": "nosniff",
					"x-frame-options": "DENY",
					"x-xss-protection": "1; mode=block"
				},
			});
		}
	}

	if (request.method === "POST") {
		const jsonData = JSON.parse(JSON.stringify(await request.json()));
		let aliasPath = jsonData.alias;
		let clientTotp = jsonData.totp;
		let originUrl = jsonData.origin;
		let serverTotp = await getOtp(totpSecret, time);

		let doesAliasExist = function (existingValue) {
			if (existingValue === null) {
				return false;
			} else {
				return true;
			}
		}

		// Remove spaces from the OTP as some authenticator apps add them in.
		clientTotp = clientTotp.replace(/\s+/g, "");

		// Handle the OTP verification first as it is time constrainted
		if (clientTotp !== "") {
			if (Number(clientTotp) !== Number(serverTotp)) {
				return new Response(`The OTP you have entered was incorrect.`);
			}
		}

		// Verify the alias path next, as the originUrl isn't useful if this is borked.
		if (aliasPath == "") {
			let count = 0
			aliasPath = await randomPath();
			while (doesAliasExist(await KV_STORE.get(aliasPath)) === true) {
				if (count > 4) {
					return new Response("Random alias generation failed. Please try again later.");
				}
				aliasPath = await randomPath();
				count += 1
			}
		} else {
			aliasPath = aliasPath.toLowerCase()
			const regexMatch = new RegExp("^[a-z0-9\\-]+$")
			if (!regexMatch.test(aliasPath)) {
				return new Response("The alias path you've entered is invalid. It is limited to alphanumeric characters and hyphens.");
			}
		}

		// Finally, verify the URL.
		if (!await verifyUrl(originUrl)) {
			// This is what browsers do, don't blame me.
			originUrl = "http://" + originUrl
			if (!await verifyUrl(originUrl)) {
				return new Response("The URL you have entered is invalid.");
			}
		}
		if ((originUrl.startsWith("http://quickna.me")) || (originUrl.startsWith("https://quickna.me"))) {
			return new Response("Nice try, but that won't work.");
		}

		// TODO: Clean up the code for the reserved aliases.
		if ((aliasPath === "awnvbg") || (aliasPath === "c2VydmljZS13b3JrZXI")) {
			return new Response("This alias entered is reserved, please try again.");

			// If everything checks out, push the value to the key store.
		} else if (doesAliasExist(await KV_STORE.get(aliasPath)) === false) {
			let timeLimit = "";
			// We already verify the OTP above, so just check if we've used one.
			if ((clientTotp !== "") && (totpSecret !== "")) {
				await KV_STORE.put(aliasPath, originUrl);
			} else {
				await KV_STORE.put(aliasPath, originUrl, { expirationTtl: 604800 });
				timeLimit = "for seven days "
			}
			return new Response(`Your shortened URL has been generated and is available ${timeLimit}at <a id="redirLink" href="https://quickna.me/${aliasPath}">https://quickna.me/${aliasPath}</a>.`);
		} else {
			return new Response("The alias entered is already in use, please try again.");
		}
	}
}

function nonceGenerator(randValues, set) {
	// This may look weird, but it secures the nonce by having a better distribution of characters.
	const charset = "+/0123456789+/+/ABCDEFGHIJKLMNOPQRSTUVWXYZ+/+/0123456789+/+/abcdefghijklmnopqrstuvwxyz+/+/0123456789+/";
	let nonce = "";

	for (let i = 0; i < 9; i++) {
		nonce += charset.charAt(Math.floor(cryptoRandom(randValues.slice(((((i + 1) * set) - 1) * 7), (((i + 1) * set) * 7))) * charset.length));
	}
	const ecc = ((nonce || '').match(RegExp(/[1-9]/g)) || []).length;
	return (nonce + ecc);
}

function randomTitle() {
	const emojiList = ["😄", "😃", "😀", "😊", "😉", "😍", "😘", "😚", "😗", "😙", "😜", "😝", "😛", "😳", "😁", "😔", "😌", "😒", "😞", "😣", "😢", "😂", "😭", "😪", "😥", "😰", "😅", "😓", "😩", "😫", "😨", "😱", "😠", "😡", "😤", "😖", "😆", "😋", "😷", "😎", "😴", "😵", "😲", "😟", "😦", "😧", "😈", "👿", "😮", "😬", "😐", "😕", "😯", "😶", "😇", "😏", "😑", "👲", "👳", "👮", "👷", "💂", "👶", "👦", "👧", "👨", "👩", "👴", "👵", "👱", "👼", "👸", "😺", "😸", "😻", "😽", "😼", "🙀", "😿", "😹", "😾", "👹", "👺", "🙈", "🙉", "🙊", "💀", "👽", "💩", "🔥", "✨", "🌟", "💫", "💥", "💢", "💦", "💧", "💤", "💨", "👂", "👀", "👃", "👅", "👄", "👍", "👎", "👌", "👊", "✊", "✌", "👋", "✋", "👐", "👆", "👇", "👉", "👈", "🙌", "🙏", "☝", "👏", "💪", "🚶", "🏃", "💃", "👫", "👪", "👬", "👭", "💏", "💑", "👯", "🙆", "🙅", "💁", "🙋", "💆", "💇", "💅", "👰", "🙎", "🙍", "🙇", "🎩", "👑", "👒", "👟", "👞", "👡", "👠", "👢", "👕", "👔", "👚", "👗", "🎽", "👖", "👘", "👙", "💼", "👜", "👝", "👛", "👓", "🎀", "🌂", "💄", "💛", "💙", "💜", "💚", "❤", "💔", "💗", "💓", "💕", "💖", "💞", "💘", "💌", "💋", "💍", "💎", "👤", "👥", "💬", "👣", "💭", "🐶", "🐺", "🐱", "🐭", "🐹", "🐰", "🐸", "🐯", "🐨", "🐻", "🐷", "🐽", "🐮", "🐗", "🐵", "🐒", "🐴", "🐑", "🐘", "🐼", "🐧", "🐦", "🐤", "🐥", "🐣", "🐔", "🐍", "🐢", "🐛", "🐝", "🐜", "🐞", "🐌", "🐙", "🐚", "🐠", "🐟", "🐬", "🐳", "🐋", "🐄", "🐏", "🐀", "🐃", "🐅", "🐇", "🐉", "🐎", "🐐", "🐓", "🐕", "🐖", "🐁", "🐂", "🐲", "🐡", "🐊", "🐫", "🐪", "🐆", "🐈", "🐩", "🐾", "💐", "🌸", "🌷", "🍀", "🌹", "🌻", "🌺", "🍁", "🍃", "🍂", "🌿", "🌾", "🍄", "🌵", "🌴", "🌲", "🌳", "🌰", "🌱", "🌼", "🌐", "🌞", "🌝", "🌚", "🌑", "🌒", "🌓", "🌔", "🌕", "🌖", "🌗", "🌘", "🌜", "🌛", "🌙", "🌍", "🌎", "🌏", "🌋", "🌌", "🌠", "⭐", "☀", "⛅", "☁", "⚡", "☔", "❄", "⛄", "🌀", "🌁", "🌈", "🌊", "🎍", "💝", "🎎", "🎒", "🎓", "🎏", "🎆", "🎇", "🎐", "🎑", "🎃", "👻", "🎅", "🎄", "🎁", "🎋", "🎉", "🎊", "🎈", "🎌", "🔮", "🎥", "📷", "📹", "📼", "💿", "📀", "💽", "💾", "💻", "📱", "☎", "📞", "📟", "📠", "📡", "📺", "📻", "🔊", "🔉", "🔈", "🔇", "🔔", "🔕", "📢", "📣", "⏳", "⌛", "⏰", "⌚", "🔓", "🔒", "🔏", "🔐", "🔑", "🔎", "💡", "🔦", "🔆", "🔅", "🔌", "🔋", "🔍", "🛁", "🛀", "🚿", "🚽", "🔧", "🔩", "🔨", "🚪", "🚬", "💣", "🔫", "🔪", "💊", "💉", "💰", "💴", "💵", "💷", "💶", "💳", "💸", "📲", "📧", "📥", "📤", "✉", "📩", "📨", "📯", "📫", "📪", "📬", "📭", "📮", "📦", "📝", "📄", "📃", "📑", "📊", "📈", "📉", "📜", "📋", "📅", "📆", "📇", "📁", "📂", "✂", "📌", "📎", "📏", "📐", "📕", "📗", "📘", "📙", "📓", "📔", "📒", "📚", "📖", "🔖", "📛", "🔬", "🔭", "📰", "🎨", "🎬", "🎤", "🎧", "🎼", "🎵", "🎶", "🎹", "🎻", "🎺", "🎷", "🎸", "👾", "🎮", "🃏", "🎴", "🀄", "🎲", "🎯", "🏈", "🏀", "⚽", "⚾", "🎾", "🎱", "🏉", "🎳", "⛳", "🚵", "🚴", "🏁", "🏇", "🏆", "🎿", "🏂", "🏊", "🏄", "🎣", "☕", "🍵", "🍶", "🍼", "🍺", "🍻", "🍸", "🍹", "🍷", "🍴", "🍕", "🍔", "🍟", "🍗", "🍖", "🍝", "🍛", "🍤", "🍱", "🍣", "🍥", "🍙", "🍘", "🍚", "🍜", "🍲", "🍢", "🍡", "🍳", "🍞", "🍩", "🍮", "🍦", "🍨", "🍧", "🎂", "🍰", "🍪", "🍫", "🍬", "🍭", "🍯", "🍎", "🍏", "🍊", "🍋", "🍒", "🍇", "🍉", "🍓", "🍑", "🍈", "🍌", "🍐", "🍍", "🍠", "🍆", "🍅", "🌽", "🏠", "🏡", "🏫", "🏢", "🏣", "🏥", "🏦", "🏪", "🏩", "🏨", "💒", "⛪", "🏬", "🏤", "🌇", "🌆", "🏯", "🏰", "⛺", "🏭", "🗼", "🗾", "🗻", "🌄", "🌅", "🌃", "🗽", "🌉", "🎠", "🎡", "⛲", "🎢", "🚢", "⛵", "🚤", "🚣", "⚓", "🚀", "💺", "🚁", "🚂", "🚊", "🚉", "🚞", "🚆", "🚄", "🚅", "🚈", "🚇", "🚝", "🚋", "🚃", "🚎", "🚌", "🚍", "🚙", "🚘", "🚗", "🚕", "🚖", "🚛", "🚚", "🚨", "🚓", "🚔", "🚒", "🚑", "🚐", "🚲", "🚡", "🚟", "🚠", "🚜", "💈", "🚏", "🎫", "🚦", "🚥", "🚧", "🔰", "⛽", "🏮", "🎰", "♨", "🗿", "🎪", "🎭", "📍", "🚩"];
	let randomEmoji = function () {
		return emojiList[Math.floor(Math.random() * emojiList.length)];
	}
	return (randomEmoji() + randomEmoji() + randomEmoji());
}

async function randomPath() {
	const wordList = ["aahs", "abba", "abet", "abos", "abys", "acer", "acid", "acta", "adds", "adry", "aery", "afro", "agee", "agha", "agly", "ague", "ahoy", "aids", "aine", "airt", "ajar", "akee", "alan", "alay", "alco", "ales", "alga", "alky", "alme", "aloo", "alto", "amah", "ames", "amin", "ammo", "amyl", "ands", "anil", "anno", "anow", "anti", "aper", "apos", "apts", "arba", "arcs", "areg", "arfs", "aril", "arms", "arpa", "arty", "asar", "asks", "atma", "atop", "auks", "aunt", "avas", "avid", "awdl", "awfy", "awny", "axed", "axis", "ayes", "azan", "baas", "baby", "bade", "baft", "bahu", "bake", "ball", "bams", "bang", "bant", "bard", "barm", "base", "bast", "batt", "bawd", "baye", "beak", "beat", "beds", "beep", "bego", "bels", "bene", "bent", "berm", "beth", "bhai", "bias", "bide", "bier", "bigs", "bill", "bing", "biog", "birl", "bish", "bito", "blab", "blah", "blay", "blet", "blip", "blog", "blue", "boar", "bobs", "body", "bogs", "boil", "boks", "boll", "bomb", "bong", "book", "boor", "bora", "borm", "bosh", "bote", "bouk", "bowr", "boyg", "brad", "bran", "bray", "bren", "brie", "brin", "brod", "brow", "brux", "bubs", "budi", "bufo", "buik", "bull", "buna", "bunn", "bura", "burk", "burr", "busk", "bute", "byde", "byrl", "cabs", "cadi", "cage", "cain", "calk", "calp", "camo", "cang", "cany", "capi", "card", "carn", "cart", "cask", "cauf", "caup", "cawk", "ceca", "ceil", "cens", "cere", "cete", "cham", "chas", "chay", "chez", "chid", "chis", "choc", "chou", "chum", "cide", "cill", "cirl", "cits", "clag", "clat", "cleg", "clit", "clop", "cloy", "coat", "coca", "code", "coft", "coil", "coke", "cole", "coly", "comm", "cone", "conn", "cook", "coos", "copy", "cork", "cory", "cost", "cots", "cove", "cows", "coys", "crag", "craw", "crem", "crim", "crog", "crue", "cubs", "cuff", "cull", "cups", "curf", "curs", "cusp", "cwms", "cyst", "dabs", "dado", "daft", "dahs", "dali", "damn", "dank", "darb", "dark", "data", "daud", "dawd", "dawt", "deaf", "deaw", "deck", "deem", "dees", "defo", "degu", "deke", "dell", "deme", "deni", "dere", "derv", "deva", "dexy", "dhol", "dice", "didy", "dies", "digs", "dime", "ding", "dint", "dire", "disa", "diss", "ditt", "divi", "dixy", "doat", "doco", "doek", "doff", "dohs", "doll", "doms", "dong", "dool", "doos", "dopy", "dorm", "dort", "doss", "dots", "doum", "dout", "dowf", "dows", "doze", "drad", "drat", "dreg", "drib", "drub", "dsos", "duar", "duck", "dued", "duff", "duke", "duma", "dung", "duos", "dure", "dush", "dwam", "dyes", "dzos", "eard", "ease", "eats", "ebbs", "ecco", "ecod", "eddo", "edhs", "eely", "efts", "eggs", "egos", "eild", "eked", "elds", "ells", "elts", "emic", "emmy", "emyd", "enew", "enuf", "eorl", "epos", "erev", "eric", "eros", "eses", "esse", "etch", "etic", "eugh", "even", "evil", "ewes", "exec", "exon", "eyed", "eyne", "eyry", "face", "fads", "fahs", "fair", "falx", "fang", "fard", "faro", "fast", "faur", "fave", "faze", "feck", "feel", "feet", "feis", "fems", "fent", "fern", "fete", "feus", "fiat", "fido", "fife", "fiky", "film", "fine", "fins", "firm", "fish", "fitt", "flab", "flan", "flax", "flee", "fley", "flir", "floc", "flor", "flue", "foam", "foes", "foid", "folk", "font", "fops", "fore", "foss", "fous", "fozy", "frap", "fray", "frig", "froe", "frow", "fuds", "fugu", "fums", "funk", "furs", "fuss", "fuzz", "fyrd", "gadi", "gaes", "gags", "gait", "gale", "gamb", "gamy", "gant", "gaps", "gari", "gasp", "gats", "gaup", "gawd", "gean", "geds", "gees", "gels", "gene", "geos", "gert", "geum", "gibe", "gien", "gigs", "gilt", "ginn", "gird", "girr", "gite", "gjus", "glee", "gley", "glim", "glop", "glum", "gnaw", "goaf", "gobi", "gods", "goey", "gold", "gone", "good", "gool", "goos", "gorm", "goss", "govs", "gowl", "grad", "grav", "grew", "grig", "gris", "grot", "grue", "gubs", "guff", "gule", "guls", "gung", "gurl", "gush", "guys", "gyms", "gyri", "haaf", "hade", "haem", "haff", "haha", "hain", "haka", "half", "halt", "hang", "haps", "hark", "haro", "hask", "hate", "hauf", "hawk", "haze", "heap", "hech", "heft", "heir", "helm", "hemp", "hent", "herd", "hern", "hesp", "hets", "hick", "high", "hili", "hind", "hioi", "hish", "hits", "hoar", "hobs", "hoer", "hogs", "hoka", "hole", "hols", "home", "hone", "hood", "hoop", "hops", "horn", "host", "hour", "howf", "hoya", "hued", "huge", "huia", "hule", "humf", "hunh", "hups", "husk", "hwan", "hyes", "hymn", "hyte", "iced", "icky", "idem", "idol", "iggs", "ikon", "ilka", "imam", "imps", "ingo", "inky", "inti", "ired", "irks", "isle", "itas", "iwis", "jabs", "jaga", "jake", "jane", "jark", "jasp", "jauk", "jaxy", "jean", "jeel", "jeez", "jell", "jete", "jiao", "jiff", "jimp", "jinx", "jivy", "joco", "john", "jole", "jomo", "josh", "jouk", "joys", "judo", "jugs", "jump", "jure", "juts", "kaas", "kadi", "kago", "kaif", "kain", "kaks", "kame", "kang", "kapa", "karn", "kati", "kaws", "kbar", "keds", "keen", "kegs", "kelp", "keno", "keps", "kern", "keta", "kewl", "khat", "khud", "kief", "kifs", "kiln", "kina", "kink", "kipp", "kirs", "kite", "kiwi", "knap", "knit", "knub", "koap", "koel", "kois", "kolo", "kook", "kore", "koss", "kris", "kueh", "kuku", "kuri", "kutu", "kyar", "kyle", "kyte", "lack", "lads", "lahs", "lain", "laky", "lame", "land", "lant", "lare", "lars", "last", "lats", "lava", "lawn", "lazo", "leak", "leap", "lech", "leer", "legs", "leke", "lend", "lent", "lerp", "leud", "levy", "liar", "lich", "lied", "lies", "ligs", "lilt", "lime", "limy", "link", "lint", "lipe", "lire", "lisp", "lits", "loaf", "lobi", "loch", "lode", "logo", "loin", "loma", "loof", "loop", "lope", "lorn", "loss", "loth", "loud", "lous", "lown", "loys", "luck", "lues", "luit", "luma", "lune", "luny", "lush", "lutz", "lyam", "lyms", "lyre", "maas", "mack", "maes", "mags", "mail", "make", "mala", "malm", "mams", "mang", "many", "mard", "marl", "mary", "mask", "mate", "maty", "maut", "maws", "mays", "meal", "meds", "mees", "megs", "mell", "memo", "meng", "meou", "meri", "mese", "mete", "meve", "mezz", "mice", "mics", "miff", "mihi", "milf", "mils", "mind", "mink", "miny", "mirk", "miry", "mist", "mixt", "moai", "mobe", "mock", "mods", "mogs", "mojo", "mola", "mols", "momi", "monk", "mood", "moon", "moot", "mora", "mort", "moss", "moti", "moue", "mowa", "moya", "mozo", "muds", "muil", "mumm", "mung", "muon", "murl", "musk", "mute", "muzz", "myna", "naam", "nabs", "naff", "naik", "name", "nane", "naos", "narc", "nary", "nays", "neap", "neck", "neep", "neks", "neon", "nesh", "nets", "neve", "next", "nick", "nied", "niff", "nimb", "nips", "nite", "noah", "nodi", "nogg", "nole", "nome", "nong", "noon", "nork", "nosy", "noul", "nout", "nows", "nubs", "null", "nurl", "nyas", "oaks", "oast", "obas", "obis", "obos", "octa", "odds", "odor", "offs", "ogle", "ohms", "oink", "okeh", "olde", "oleo", "olla", "omen", "once", "only", "onus", "oohs", "oops", "ooze", "oped", "opts", "orbs", "ordo", "orfs", "orts", "oses", "ouch", "oulk", "oups", "outs", "oven", "ower", "owns", "oxen", "oxim", "paal", "pack", "pacy", "pahs", "pain", "pall", "paly", "pang", "pape", "pare", "pars", "pass", "pats", "paul", "pawk", "pays", "pean", "peba", "peds", "peen", "pegh", "peke", "pell", "pene", "pent", "pere", "pern", "peso", "pfft", "phis", "phos", "pian", "pick", "pies", "pike", "pili", "pimp", "pink", "pion", "pipi", "pirn", "piso", "pity", "plan", "plea", "plex", "plop", "plue", "poas", "poem", "pogy", "pole", "pols", "pomo", "pone", "pont", "pooh", "poor", "pops", "port", "poss", "pots", "pour", "poxy", "prao", "pree", "prey", "proa", "prog", "pros", "psis", "puce", "puer", "puha", "puke", "pule", "pulp", "puma", "pung", "puny", "pure", "purs", "putt", "pyat", "pyin", "pyro", "qins", "quai", "quey", "quip", "quop", "rach", "rads", "rage", "ragu", "raik", "rait", "raku", "rams", "rani", "raps", "rase", "rata", "rats", "ravs", "rays", "reak", "reap", "recs", "reds", "reel", "reft", "reif", "reke", "renk", "reos", "resh", "revs", "rhus", "riba", "rick", "riel", "rifs", "rile", "rims", "rine", "riot", "ript", "rite", "riva", "road", "robe", "rocs", "roes", "roke", "rolf", "roms", "ronz", "room", "root", "rort", "rosy", "rotl", "roul", "roux", "rube", "rucs", "rued", "ruga", "rule", "rums", "runs", "rusa", "rust", "ryas", "rynd", "sabe", "sade", "safe", "sago", "said", "sair", "sale", "salt", "sams", "sank", "sard", "sash", "saul", "sawn", "scab", "scan", "scog", "scry", "scum", "scye", "sear", "seco", "seek", "seep", "segs", "seir", "sele", "seme", "sene", "sept", "serk", "sesh", "sett", "sexy", "shah", "shaw", "shes", "shin", "shmo", "shoo", "shri", "shwa", "sice", "sida", "sies", "sijo", "sile", "silt", "sims", "sinh", "sips", "siss", "sits", "sjoe", "skaw", "skeo", "skew", "skio", "skol", "skyf", "slag", "slaw", "slee", "slim", "sloe", "slow", "slum", "smew", "smug", "snag", "sneb", "snig", "snod", "snub", "soap", "soca", "sods", "soho", "soke", "soli", "some", "song", "soom", "soph", "sord", "sort", "souk", "sour", "sowf", "sowp", "spae", "spar", "spay", "spek", "spie", "spin", "spot", "spug", "stab", "stat", "stem", "stew", "stir", "stot", "stum", "subs", "suds", "suet", "suid", "sulk", "sums", "sunk", "sups", "sure", "swab", "swan", "swee", "swiz", "swum", "syen", "sync", "syph", "tabu", "taco", "tael", "tahr", "tais", "taki", "talc", "tall", "tana", "tank", "tape", "tare", "tars", "tass", "tatt", "tava", "tawt", "tead", "tear", "tecs", "teek", "teer", "tegg", "teil", "tele", "teme", "tene", "terf", "tete", "text", "that", "then", "thin", "thon", "thud", "tiar", "tics", "tied", "tift", "tike", "till", "tina", "tink", "tipi", "tirl", "titi", "toad", "tocs", "toed", "toft", "togs", "toke", "tole", "tomb", "tone", "tony", "toon", "topi", "torc", "toro", "tory", "toss", "touk", "town", "toyo", "tram", "tree", "tret", "trie", "trio", "tron", "troy", "tryp", "tuba", "tufa", "tuis", "tuna", "tuns", "turk", "tusk", "twae", "twee", "twos", "tyer", "tyke", "type", "tyre", "udal", "ufos", "ulan", "ulus", "umph", "umus", "unce", "undo", "unto", "upgo", "urao", "urdy", "uric", "urus", "uses", "utus", "vacs", "vags", "vale", "vang", "vare", "vase", "vaus", "veal", "vega", "vein", "vell", "vera", "vert", "vets", "vias", "vide", "vies", "vild", "vina", "vint", "virl", "vite", "vizy", "voes", "vole", "vors", "vrot", "vugh", "waac", "wade", "wady", "wage", "wail", "wait", "wald", "wall", "wane", "wany", "ward", "warn", "wary", "wast", "wauk", "wavy", "waws", "weal", "weds", "weem", "wees", "weil", "welk", "wemb", "wens", "wero", "wets", "wham", "when", "whid", "whio", "whiz", "whot", "wice", "wiel", "wild", "wilt", "wine", "wino", "wire", "wisp", "with", "wock", "woke", "womb", "wood", "woos", "wore", "wort", "wowf", "writ", "wuss", "wynd", "xray", "yack", "yags", "yale", "yapp", "yark", "yaud", "yawp", "ybet", "year", "yede", "yelk", "yelt", "yerk", "yett", "ygoe", "yins", "yirk", "ylke", "yock", "yoga", "yoks", "yond", "yoop", "youk", "yowl", "yuca", "yuga", "yuks", "yunx", "yuzu", "zany", "zati", "zeds", "zels", "zest", "ziff", "zimb", "zins", "zits", "zoea", "zone", "zoos", "zulu", "zyme"];
	let randomWord = function () {
		return wordList[Math.floor(Math.random() * wordList.length)];
	}
	return (randomWord() + "-" + randomWord());
}

async function verifyUrl(url) {
	const regex = new RegExp("^(?:(?:(?:https?):)\\/\\/)(?:\\S+(?::\\S*)?@)?(?:(?!(?:10|127)(?:\\.\\d{1,3}){3})(?!(?:169\\.254|192\\.168)(?:\\.\\d{1,3}){2})(?!172\\.(?:1[6-9]|2\\d|3[0-1])(?:\\.\\d{1,3}){2})(?:[1-9]\\d?|1\\d\\d|2[01]\\d|22[0-3])(?:\\.(?:1?\\d{1,2}|2[0-4]\\d|25[0-5])){2}(?:\\.(?:[1-9]\\d?|1\\d\\d|2[0-4]\\d|25[0-4]))|\\[(((([0-9a-eA-E][0-9a-fA-F]{0,3})|([fF]([0-9a-cfA-CF][0-9a-fA-F]{0,2})?)|([fF][eE]([0-7c-fC-F][0-9a-fA-F]?)?)):)([0-9a-fA-F]{1,4}:){6,6}[0-9a-fA-F]{1,4}|((([0-9a-eA-E][0-9a-fA-F]{0,3})|([fF]([0-9a-cfA-CF][0-9a-fA-F]{0,2})?)|([fF][eE]([0-7c-fC-F][0-9a-fA-F]?)?)):)([0-9a-fA-F]{1,4}:){0,6}:|((([0-9a-eA-E][0-9a-fA-F]{0,3})|([fF]([0-9a-cfA-CF][0-9a-fA-F]{0,2})?)|([fF][eE]([0-7c-fC-F][0-9a-fA-F]?)?)):)([0-9a-fA-F]{1,4}:){0,5}:[0-9a-fA-F]{1,4}|((([0-9a-eA-E][0-9a-fA-F]{0,3})|([fF]([0-9a-cfA-CF][0-9a-fA-F]{0,2})?)|([fF][eE]([0-7c-fC-F][0-9a-fA-F]?)?)):)([0-9a-fA-F]{1,4}:){0,4}(:[0-9a-fA-F]{1,4}){1,2}|((([0-9a-eA-E][0-9a-fA-F]{0,3})|([fF]([0-9a-cfA-CF][0-9a-fA-F]{0,2})?)|([fF][eE]([0-7c-fC-F][0-9a-fA-F]?)?)):)([0-9a-fA-F]{1,4}:){0,3}(:[0-9a-fA-F]{1,4}){1,3}|((([0-9a-eA-E][0-9a-fA-F]{0,3})|([fF]([0-9a-cfA-CF][0-9a-fA-F]{0,2})?)|([fF][eE]([0-7c-fC-F][0-9a-fA-F]?)?)):)([0-9a-fA-F]{1,4}:){0,2}(:[0-9a-fA-F]{1,4}){1,4}|((([0-9a-eA-E][0-9a-fA-F]{0,3})|([fF]([0-9a-cfA-CF][0-9a-fA-F]{0,2})?)|([fF][eE]([0-7c-fC-F][0-9a-fA-F]?)?)):)([0-9a-fA-F]{1,4}:)?(:[0-9a-fA-F]{1,4}){1,5}|((([0-9a-eA-E][0-9a-fA-F]{0,3})|([fF]([0-9a-cfA-CF][0-9a-fA-F]{0,2})?)|([fF][eE]([0-7c-fC-F][0-9a-fA-F]?)?)):)((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]).){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]).){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))\\]|(?:xn--[a-z0-9\\-]{1,59}|(?:(?:[a-z\\u00a1-\\uffff0-9]-*){0,62}[a-z\\u00a1-\\uffff0-9]{1,63}))(?:\\.(?:xn--[a-z0-9\\-]{1,59}|(?:[a-z\\u00a1-\\uffff0-9]-*){0,62}[a-z\\u00a1-\\uffff0-9]{1,63}))*(?:\\.(?:xn--[a-z0-9\\-]{1,59}|(?:[a-z\\u00a1-\\uffff]{2,63})))\\.?)(?::\\d{2,5})?(?:[/?#]\\S*)?$", "i")
	return regex.test(url);
}
