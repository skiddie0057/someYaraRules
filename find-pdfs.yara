rule detect_pdf
{
	meta:
		author = "skiddie"
		date = "20/09/2023"
		description = "find pdfs in your malware dataset - for origami"
	strings:
		$x1 = "%PDF" // magic number 
	condition:
	   $x1 at 0
}
