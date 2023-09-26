rule match_fakewebshops_v1
{
	meta:
		author = "skiddie0057"
		date = "2023/09/09"
		description = "matches me some webshops' strings"
	strings:
		$str1 = "Službu za Korisnike"
		$str2 = "shopping_cart.html"
		$str3 = "bof  breadcrumb"
		$str4 = "$.noConflict()"
		$a = "Outlet"
		$b = "Popust" 
	condition:
	   3 of ($str*) and $a and $b
}
