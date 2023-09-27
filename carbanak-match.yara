rule detect_carbanak
{
	meta:
		author = "skiddie"
		date = "25/08/2023"
		description = "find carbanak source code, builder or exe"
	strings:
		$x1 = "сорцы" # source
		$x2 = "билдер" # builder 
		$x3 = "BlackEnergy2" # BlackEnergy PrivEsc-er
		$x4 = "UACBypass" # uac bypass library/script
		$x5 = "копируем начало апи функции" # comment from hook.cpp (always called)
		$x6 = "O:\botep\bin\Release\builder_gui.pdb" # string from builder.exe 
		$y1 = "bot"
		$y2 = "proxy"
	condition:
	   (any of x*) and ($y1 and $y2)
}
