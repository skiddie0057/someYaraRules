rule python_executable
{
	meta:
		author = "skiddie"
		date = "21/08/2023"
		description = "find python files"
	strings:
		$str1 = "PyInstaller"
	condition:
	   uint16(0) == 0x5A4D and $str1
}
