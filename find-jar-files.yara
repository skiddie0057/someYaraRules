rule java_jar
{
	meta:
		author = "skiddie"
		date = "21/08/2023"
		description = "find java jar, pk header and 'class' word"
	strings:
		$head = "PK"
		$str1 = ".class"
	condition:
	   ($head at 0) and $str1
}
