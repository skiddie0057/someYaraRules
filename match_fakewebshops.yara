rule match_fakewebshops_v1
{
	meta:
		author = "skiddie0057"
		date = "2023/09/09"
		description = "matches me some webshops' strings"
	strings:
		$str1 = "Službu za Korisnike"
		$str2 = "Outlet"
		$str3 = "bof "
		$str4 = "$.noConflict()"
		$str5 = " breadcrumb"
		$str6 = "eof "
		$str7 = "Popust" 
		$str8 = "==== CURRENCIES ==="
		$a = "shopping_cart.html"

	condition:
	   4 of ($str*) and $a
}
