cloudflared tunnel --url http://localhost:8080 2>&1 |
ForEach-Object {

$_

if ($_ -match 'https://[a-zA-Z0-9\-]+\.trycloudflare\.com') {

    $url = $matches[0]

    Invoke-WebRequest `
      -Uri "https://hypers.com.bd/hyper/update.php?key=HYP3R&tunnel=$url" `
      -UseBasicParsing

    Write-Host "Updated tunnel: $url"
}

}