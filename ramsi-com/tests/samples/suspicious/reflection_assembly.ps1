$bytes = [IO.File]::ReadAllBytes("lib.bin")
[Reflection.Assembly]::Load($bytes)
