param([string]$OutPath)
$hash = git rev-parse --short=8 HEAD 2>$null
if (-not $hash) { $hash = '00000000' }
$tag = git describe --abbrev=0 --tags 2>$null
if (-not $tag) { $tag = 'Unknown' }
$parts = $tag.Substring(1).Split('.')
$major = if ($parts[0] -match '^\d+$') { $parts[0] } else { 0 }
$minor = if ($parts[1] -match '^\d+$') { $parts[1] } else { 0 }
$patch = if ($parts[2] -match '^\d+$') { $parts[2] } else { 0 }
$ver = "$major,0,$minor,$patch"
$q = [char]34
@'
#define FILE_VERSION_STR "__HASH__"
#define PRODUCT_VERSION_STR "__TAG__"
#define FILEVER __VER__
#define PRODVER __VER__
'@ -replace '__HASH__', $hash -replace '__TAG__', $tag -replace '__VER__', $ver | Set-Content -Path $OutPath -Encoding ASCII
