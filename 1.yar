rule Conti_V3 {
	meta:
	  	description = "YARA rule for Conti Ransomware v2 and v3"
		author = "@cPeterr & 4B4DB4B3"
    		date = "2020-12-15 - 2021"
    		rule_version = "v3"
    		malware_type = "ransomware"
    		malware_family = "Ransom:W32/Conti"
		tlp = "white"
	strings:
		$str1 = "polzarutu1982@protonmail.com"
		$str2 = "http://m232fdxbfmbrcehbrj5iayknxnggf6niqfj6x4iedrgtab4qupzjlaid.onion"
    		$str3 = "expand 32-byte k"
		$string_decryption = { 8a 07 8d 7f 01 0f b6 c0 b9 ?? 00 00 00 2b c8 6b c1 ?? 99 f7 fe 8d 42 7f 99 f7 fe 88 57 ff }
    		$uni_keycodes = { c6 45 e9 3f c6 45 ea 13 c6 45 eb 3c c6 45 ec 69 c6 45 ed 3c c6 45 ee 1b c6 45 ef 23 c6 45 f0 69 c6 45 f1 6f c6 45 f2 27 c6 45 f3 71 c6 45 f4 71 c6 45 f5 03 }
    		$compare_size = { ?? ?? 00 00 50 00 }
	condition:
		all of ($str*) or $string_decryption and $compare_size or $uni_keycodes
}