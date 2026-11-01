# Builds the shipped Graystone branding assets from the source art in icon/.
#   icon/graystone-appicon.png -> build/appicon.png (256px)
#                              -> build/windows/icon.ico (16/32/48/256px) - the
#                                 exe/taskbar icon; Wails v2 has no Windows-side
#                                 icon option, so this resource is the only one
#                              -> frontend/public/graystone-icon.png (320px) -
#                                 the favicon
#                              -> frontend/public/graystone-about.png (512px) -
#                                 the About screen's artwork
# The About screen used to take a second master, icon/graystone-logo.png, because
# that PNG carried the product name. It is gone: every surface now shows the stone
# and writes "Graystone" as real text, so the name can be selected and searched,
# the README banner matches the app, and the exe does not carry a 2.7 MB picture
# of letters. That master had no alpha channel either - its "transparent"
# background was a painted grey checkerboard, which showed through on every theme.
# The appicon master is transparent-background (32bpp ARGB); every derived size
# keeps its alpha channel, so the art sits on the app's own theme instead of a
# white card.
# Nothing here draws the logo any more - replace the PNG in icon/ and re-run this
# script and every surface picks the new art up. The files under frontend/public
# are build products, not second masters: editing them instead of icon/ means the
# next run overwrites the change.
Add-Type -AssemblyName System.Drawing

$root = Split-Path -Parent $PSScriptRoot

function Get-ResizedPng([string]$sourcePath, [int]$size) {
    $img = [System.Drawing.Image]::FromFile($sourcePath)
    try {
        if ($img.Width -ne $img.Height) {
            throw "$sourcePath must be square (got $($img.Width)x$($img.Height))"
        }
        $bmp = New-Object System.Drawing.Bitmap($size, $size)
        $g = [System.Drawing.Graphics]::FromImage($bmp)
        # The art is 1254px; without a high quality filter the 16px icon layer
        # turns to mud, which is the whole point of the .ico.
        $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
        $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
        $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
        $g.DrawImage($img, [System.Drawing.Rectangle]::new(0, 0, $size, $size))
        $g.Dispose()
        return $bmp
    } finally {
        $img.Dispose()
    }
}

function Save-PngBytes($bmp) {
    $ms = New-Object System.IO.MemoryStream
    $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
    return $ms.ToArray()
}

function New-Ico([byte[]]$png256, [byte[]]$png48, [byte[]]$png32, [byte[]]$png16) {
    $images = @($png16, $png32, $png48, $png256)
    $sizes  = @(16, 32, 48, 256)
    $ms = New-Object System.IO.MemoryStream
    $bw = New-Object System.IO.BinaryWriter($ms)
    $bw.Write([uint16]0)          # reserved
    $bw.Write([uint16]1)          # type = icon
    $bw.Write([uint16]$images.Count)
    $offset = 6 + (16 * $images.Count)
    for ($i = 0; $i -lt $images.Count; $i++) {
        $w = if ($sizes[$i] -ge 256) { 0 } else { $sizes[$i] }
        $h = if ($sizes[$i] -ge 256) { 0 } else { $sizes[$i] }
        $bw.Write([byte]$w); $bw.Write([byte]$h)
        $bw.Write([byte]0); $bw.Write([byte]0)      # colors, reserved
        $bw.Write([uint16]1)                         # planes
        $bw.Write([uint16]32)                        # bit count
        $bw.Write([uint32]$images[$i].Length)        # bytes in resource
        $bw.Write([uint32]$offset)                   # image offset
        $offset += $images[$i].Length
    }
    foreach ($img in $images) { $bw.Write($img) }
    $bw.Flush()
    return $ms.ToArray()
}

New-Item -ItemType Directory -Force -Path (Join-Path $root "build\windows") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $root "frontend\public") | Out-Null

$appicon = Join-Path $root "icon\graystone-appicon.png"
if (-not (Test-Path $appicon)) { throw "missing source art: $appicon" }

# Application icon: one square master resized to every size the .ico carries.
$b256 = Get-ResizedPng $appicon 256
$b48  = Get-ResizedPng $appicon 48
$b32  = Get-ResizedPng $appicon 32
$b16  = Get-ResizedPng $appicon 16

$png256 = Save-PngBytes $b256
$b256.Save((Join-Path $root "build\appicon.png"), [System.Drawing.Imaging.ImageFormat]::Png)

$ico = New-Ico $png256 (Save-PngBytes $b48) (Save-PngBytes $b32) (Save-PngBytes $b16)
[System.IO.File]::WriteAllBytes((Join-Path $root "build\windows\icon.ico"), $ico)

# The favicon: the stone on its own, which survives being drawn at 16px.
$appIconWeb = Get-ResizedPng $appicon 320
$appIconWeb.Save((Join-Path $root "frontend\public\graystone-icon.png"), [System.Drawing.Imaging.ImageFormat]::Png)

# The About-screen artwork: the same stone, big enough to stay crisp where the
# page draws it on a scaled display.
$about = Get-ResizedPng $appicon 512
$about.Save((Join-Path $root "frontend\public\graystone-about.png"), [System.Drawing.Imaging.ImageFormat]::Png)

foreach ($b in @($b256, $b48, $b32, $b16, $appIconWeb, $about)) { $b.Dispose() }
Write-Output "branding written: build/appicon.png, build/windows/icon.ico ($($ico.Length) bytes), frontend/public/graystone-icon.png, frontend/public/graystone-about.png"
