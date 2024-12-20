
rule Comprehensive_Ransom_Message {
    meta:
        description = "Detects ransom messages across various ransomware families"
    strings:
        $ransom1 = "YOUR FILES HAVE BEEN ENCRYPTED" ascii nocase
        $ransom2 = "All important files have been encrypted" ascii nocase
        $ransom3 = "contact us for decryption" ascii nocase
        $ransom4 = "decrypt your files by paying ransom" ascii nocase
        $ransom5 = "Send BTC to this address to decrypt" ascii nocase
        $ransom6 = "Payment is required to recover files" ascii nocase
        $ransom7 = "Follow instructions to unlock files" ascii nocase
        $ransom8 = "For decryption, contact us at" ascii nocase
        $ransom9 = "Payment portal for file recovery" ascii nocase
        $ransom10 = "Follow instructions to unlock" ascii nocase
    condition:
        any of them
}


rule Extended_Ransomware_Email_Contact {
    meta:
        description = "Detects ransom-related email addresses with enhanced regex pattern"
    strings:
        $support_email = /support[a-zA-Z0-9._%+-]*@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/ nocase
        $help_email = /help[a-zA-Z0-9._%+-]*@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/ nocase
        $decrypt_email = /decrypt[a-zA-Z0-9._%+-]*@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/ nocase
        $restore_email = /restore[a-zA-Z0-9._%+-]*@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/ nocase
        $unlock_email = /unlock[a-zA-Z0-9._%+-]*@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/ nocase
    condition:
        any of them
}


rule Ransomware_File_Names_Extensions {
    meta:
        description = "Detects common ransomware filenames and temporary files used during encryption"
    strings:
        $file1 = "decryptor.exe" ascii
        $file2 = "key.dat" ascii
        $file3 = "readme.txt" ascii
        $file4 = "instructions.html" ascii
        $file5 = "decrypt_instructions.txt" ascii
        $file6 = "how_to_unlock.html" ascii
        $file7 = "help_restore.html" ascii
        $temp_file = /(.tmp|_temp|~lock)/ ascii
    condition:
        any of them
}


rule Broad_Crypto_API {
    meta:
        description = "Detects cryptographic APIs and encryption libraries in ransomware executables"
    strings:
        $crypto1 = "CryptEncrypt" ascii nocase
        $crypto2 = "CryptAcquireContext" ascii nocase
        $crypto3 = "CryptGenRandom" ascii nocase
        $crypto4 = "CryptImportKey" ascii nocase
        $crypto5 = "BCryptEncrypt" ascii nocase
        $crypto6 = "RSAEncrypt" ascii nocase
        $crypto7 = "AES256Encrypt" ascii nocase
        $lib1 = "libeay32.dll" ascii nocase
        $lib2 = "advapi32.dll" ascii nocase
        $lib3 = "bcrypt.dll" ascii nocase
    condition:
        any of them
}


rule Ransomware_Obfuscation_Detection {
    meta:
        description = "Detects obfuscation techniques in ransomware, including PowerShell commands"
    strings:
        $obf1 = "[Convert]::FromBase64String" ascii nocase
        $obf2 = "IEX([System.Text.Encoding]" ascii nocase
        $obf3 = "cmd /c powershell -enc" ascii nocase
        $obf4 = "New-Object IO.StreamReader" ascii nocase
        $obf5 = "Invoke-Expression" ascii nocase
        $obf6 = "ShellExecuteA" ascii nocase
    condition:
        any of them
}


rule Bitcoin_Address_Detection {
    meta:
        description = "Detects Bitcoin wallet addresses in ransomware executables"
    strings:
        $btc = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/
    condition:
        $btc
}


rule Expanded_Known_Ransomware_Names {
    meta:
        description = "Detects mentions of known ransomware families"
    strings:
        $name1 = "WannaCry" ascii nocase
        $name2 = "Locky" ascii nocase
        $name3 = "Ryuk" ascii nocase
        $name4 = "CryptoLocker" ascii nocase
        $name5 = "Cerber" ascii nocase
        $name6 = "GandCrab" ascii nocase
        $name7 = "Maze" ascii nocase
        $name8 = "Sodinokibi" ascii nocase
        $name9 = "Conti" ascii nocase
        $name10 = "DarkSide" ascii nocase
    condition:
        any of them
}


rule Enhanced_Mutex_Registry_Detection {
    meta:
        description = "Detects mutexes and registry entries often created by ransomware"
    strings:
        $mutex1 = "Global\\MsWinZonesCacheCounterMutexA" ascii
        $mutex2 = "Global\\MicrosoftWindowsSecurity" ascii
        $mutex3 = "Global\\WannaCryTaskMutex" ascii
        $reg1 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii
        $reg2 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii
        $reg3 = "HKEY_LOCAL_MACHINE\\Software\\WannaCry" ascii
        $reg4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\Folder" ascii
    condition:
        any of them
}


rule Ransomware_C2_Indicators {
    meta:
        description = "Detects C2 indicators, such as URLs and IP addresses, in ransomware executables"
    strings:
        $url1 = "http://" ascii nocase
        $url2 = "https://" ascii nocase
        $url3 = "ftp://" ascii nocase
        $url4 = "smb://" ascii nocase
        $ip1 = "192.168." ascii
        $ip2 = "10.0." ascii
        $cnc1 = "/cnc" ascii nocase
        $cnc2 = "/command-and-control" ascii nocase
    condition:
        any of them
}


rule SuspiciousSystemCalls
{
    meta:
        description = "Detects suspicious system calls often associated with malware"
        reference = "https://yara.readthedocs.io/ (YARA documentation)"
        version = "1.0"

    strings:
        $create_process = { 57 89 E5 B8 4A 56 7F }   // Pattern for CreateProcess
        $open_process = { 8B FF 55 8B EC 83 }        // Pattern for OpenProcess
        $write_process = { 6A 02 8B 44 24 08 }       // Pattern for WriteProcessMemory
        $read_process = { 8B FF 55 8B EC 83 }        // Pattern for ReadProcessMemory
        $create_file = { 8B FF 55 8B EC 56 }         // Pattern for CreateFile
        $open_file = { 8B FF 55 8B EC 83 }           // Pattern for OpenFile

    condition:
        any of ($create_process, $open_process, $write_process, $read_process, $create_file, $open_file)
}


/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/
rule Ransom_CryptXXX_Dropper
{
    /*
      Regla para detectar el dropper de Ransom.CryptXXX con MD5 d01fd2bb8c6296d51be297978af8b3a1
    */
    meta:
        description = "Regla para detectar RANSOM.CRYPTXXX"
        author      = "CCN-CERT"
        version     = "1.0"
        ref = "https://www.ccn-cert.cni.es/seguridad-al-dia/comunicados-ccn-cert/4002-publicado-el-informe-del-codigo-danino-ransom-cryptxxx.html"
    strings:
        $a = { 50 65 31 57 58 43 46 76 59 62 48 6F 35 }
        $b = { 43 00 3A 00 5C 00 42 00 49 00 45 00 52 00 5C 00 51 00 6D 00 6B 00 4E 00 52 00 4C 00 46 00 00 }
    condition:
        all of them
}

rule Ransom_CryptXXX_Real
{
    /*
      Regla para detectar el codigo Ransom.CryptXXX fuera del dropper con MD5 ae06248ab3c02e1c2ca9d53b9a155199
    */
    meta:
        description = "Regla para detectar Ransom.CryptXXX original"
        author      = "CCN-CERT"
        version     = "1.0"
        ref = "https://www.ccn-cert.cni.es/seguridad-al-dia/comunicados-ccn-cert/4002-publicado-el-informe-del-codigo-danino-ransom-cryptxxx.html"
    strings:
        $a = { 52 59 47 40 4A 41 59 5D 52 00 00 00 FF FF FF FF }
		$b = { 06 00 00 00 52 59 47 40 40 5A 00 00 FF FF FF FF }
		$c = { 0A 00 00 00 52 5C 4B 4D 57 4D 42 4B 5C 52 00 00 }
		$d = { FF FF FF FF 0A 00 00 00 52 5D 57 5D 5A 4B 43 70 }
		$e = { 3F 52 00 00 FF FF FF FF 06 00 00 00 52 4C 41 41 }
		$f = { 5A 52 00 00 FF FF FF FF 0A 00 00 00 52 5C 4B 4D }
		$g = { 41 58 4B 5C 57 52 00 00 FF FF FF FF 0E 00 00 00 }
		$h = { 52 2A 5C 4B 4D 57 4D 42 4B 20 4C 47 40 52 00 00 }
		$i = { FF FF FF FF 0A 00 00 00 52 5E 4B 5C 48 42 41 49 }
		$j = { 5D 52 00 00 FF FF FF FF 05 00 00 00 52 4B 48 47 }
		$k = { 52 00 00 00 FF FF FF FF 0C 00 00 00 52 4D 41 40 }
		$l = { 48 47 49 20 43 5D 47 52 00 00 00 00 FF FF FF FF }
		$m = { 0A 00 00 00 52 5E 5C 41 49 5C 4F 70 3F 52 00 00 }
		$n = { FF FF FF FF 0A 00 00 00 52 5E 5C 41 49 5C 4F 70 }
		$o = { 3C 52 00 00 FF FF FF FF 08 00 00 00 52 49 41 41 }
		$p = { 49 42 4B 52 00 00 00 00 FF FF FF FF 06 00 00 00 }
		$q = { 52 5A 4B 43 5E 52 00 00 FF FF FF FF 08 00 00 00 }
		$v = { 52 48 3A 4C 4D 70 3F 52 00 00 00 00 FF FF FF FF }
		$w = { 0A 00 00 00 52 4F 42 42 5B 5D 4B 70 3F 52 00 00 }
		$x = { FF FF FF FF 0A 00 00 00 52 5E 5C 41 49 5C 4F 70 }
		$y = { 3F 52 00 00 FF FF FF FF 0A 00 00 00 52 5E 5C 41 }
		$z = { 49 5C 4F 70 3C 52 00 00 FF FF FF FF 09 00 00 00 }
		$aa = { 52 4F 5E 5E 4A 4F 5A 4F 52 00 00 00 FF FF FF FF }
		$ab = { 0A 00 00 00 52 5E 5C 41 49 5C 4F 70 3D 52 00 00 }
		$ac = { FF FF FF FF 08 00 00 00 52 5E 5B 4C 42 47 4D 52 }
		
    condition:
        all of them
}

rule legion_777
{
    meta:
        author = "Daxda (https://github.com/Daxda)"
        date = "2016/6/6"
        description = "Detects an UPX-unpacked .777 ransomware binary."
        ref = "https://github.com/Daxda/malware-analysis/tree/master/malware_samples/legion"
        category = "Ransomware"
        sample = "SHA256: 14d22359e76cf63bf17268cad24bac03663c8b2b8028b869f5cec10fe3f75548"

    strings:
        $s1 = "http://tuginsaat.com/wp-content/themes/twentythirteen/stats.php"
        $s2 = "read_this_file.txt" wide // Ransom note filename.
        $s3 = "seven_legion@india.com" // Part of the format string used to rename files.
        $s4 = {46 4f 52 20 44 45 43 52 59 50 54 20 46 49 4c 45 53 0d 0a 53 45 4e 44 20 4f
               4e 45 20 46 49 4c 45 20 49 4e 20 45 2d 4d 41 49 4c 0d 0a 73 65 76 65 6e 5f
               6c 65 67 69 6f 6e 40 69 6e 64 69 61 2e 63 6f 6d } // Ransom note content.
        $s5 = "%s._%02i-%02i-%02i-%02i-%02i-%02i_$%s$.777" // Renaming format string.

    condition:
        4 of ($s*)
}


/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
rule Ransom_Alpha
{
meta:
description = "Regla para detectar Ransom.Alpha (posibles falsos positivos)"
author = "CCN-CERT"
version = "1.0"
strings:
$a = { 52 00 65 00 61 00 64 00 20 00 4D 00 65 00 20 00 28 00 48 00 6F 00 77 00 20 00 44 00 65 00 63 }
condition:
$a
}

rule Ransom_Alfa
{
meta:
description = "Regla para detectar W32/Filecoder.Alfa (Posibles falsos positivos)"
author = "CCN-CERT"
version = "1.0"
strings:
$a = { 8B 0C 97 81 E1 FF FF 00 00 81 F9 19 04 00 00 74 0F 81 F9 } 
$b = { 22 04 00 00 74 07 42 3B D0 7C E2 EB 02 }
condition:
all of them
}


/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule cerber3{
meta:
  author = "pekeinfo"
  date = "2016-09-09"
  description = "Cerber3 "
strings:
  $a = {00 6A 00 68 80 00 00 00 6A 03 6A 00 6A 03 6A  01 8B 85}
  $b = {68 3B DB 00 00 ?? ?? ?? ?? 00 ?? FF 15}
  
condition:
  1 of them 
}


rule cerber4{
meta:
        author = "pekeinfo"
        date = "2016-09-09"
        description = "Cerber4"
strings:
        $a = {8B 0D ?? ?? 43 00 51 8B 15 ?? ?? 43 00 52 E8 C9 04 00 00 83 C4 08 89 45 FC A1 ?? ?? 43 00 3B 05 ?? ?? 43 00 72 02}

condition:
        1 of them 
}


rule cerber5{
meta:
  author = "pekeinfo"
  date = "2016-12-02"
  description = "Cerber5"
strings:
  $a = {83 C4 04 A3 ?? ?? ?? 00 C7 45 ?? ?? ?? ?? 00 8B ?? ?? C6 0? 56 8B ?? ?? 5? 68 ?? ?? 4? 00 FF 15 ?? ?? 4? 00 50 FF 15 ?? ?? 4? 00 A3 ?? ?? 4? 00 68 1D 10 00 00 E8 ?? ?? FF FF 83 C4 04 ?? ?? ??}
  
condition:
  1 of them 
}


rule cerber5b{
meta:
  author = "pekeinfo"
  date = "2016-12-20"
  description = "Cerber5b"
strings:
  $a={8B ?? ?8 ?? 4? 00 83 E? 02 89 ?? ?8 ?? 4? 00 68 ?C ?9 4? 00 [0-6] ?? ?? ?? ?? ?? ?8 ?? 4? 00 5? FF 15 ?? ?9 4? 00 89 45 ?4 83 7D ?4 00 75 02 EB 12 8B ?? ?0 83 C? 06 89 ?? ?0 B? DD 03 00 00 85}  
condition:
  $a
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
rule ransom_comodosec_mrcr1 {

        meta:
                author = " J from THL <j@techhelplist.com>"
                date = "2017/01"
                reference = "https://virustotal.com/en/file/75c82fd18fcf8a51bc1b32a89852d90978fa5e7a55281f42b0a1de98d14644fa/analysis/"
                version = 1
                maltype = "Ransomware"
                filetype = "memory"

        strings:
                $text01 = "WebKitFormBoundary"
                $text02 = "Start NetworkScan"
                $text03 = "Start DriveScan"
                $text04 = "Start CryptFiles"
                $text05 = "cmd /c vssadmin delete shadows /all /quiet"
                $text06 = "isAutorun:"
                $text07 = "isNetworkScan:"
                $text08 = "isUserDataLast:"
                $text09 = "isCryptFileNames:"
                $text10 = "isChangeFileExts:"
                $text11 = "isPowerOffWindows:"
                $text12 = "GatePath:"
                $text13 = "GatePort:"
                $text14 = "DefaultCryptKey:"
                $text15 = "UserAgent:"
                $text16 = "Mozilla_"
                $text17 = "On Error Resume Next"
                $text18 = "Content-Disposition: form-data; name=\"uid\""
                $text19 = "Content-Disposition: form-data; name=\"uname\""
                $text20 = "Content-Disposition: form-data; name=\"cname\""
                $regx21 = /\|[0-9a-z]{2,5}\|\|[0-9a-z]{2,5}\|\|[0-9a-z]{2,5}\|\|[0-9a-z]{2,5}\|/


    condition:
        10 of them
}
rule Ransom : Crypren{
    meta:
        weight = 1
        Author = "@pekeinfo"
        reference = "https://github.com/pekeinfo/DecryptCrypren"
    strings: 
        $a = "won't be able to recover your files anymore.</p>"
        $b = {6A 03 68 ?? ?? ?? ?? B9 74 F1 AE 00 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 98 3A 00 00 FF D6 6A 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ??}
        $c = "Please restart your computer and wait for instructions for decrypting your files"
    condition:
        any of them
}
rule cryptonar_ransomware {

   meta:
   
      description = "Rule to detect CryptoNar Ransomware"
      author = "Marc Rivero | @seifreed"
      reference = "https://www.bleepingcomputer.com/news/security/cryptonar-ransomware-discovered-and-quickly-decrypted/"
      
   strings:
   
      $s1 = "C:\\narnar\\CryptoNar\\CryptoNarDecryptor\\obj\\Debug\\CryptoNar.pdb" fullword ascii
      $s2 = "CryptoNarDecryptor.exe" fullword wide
      $s3 = "server will eliminate the key after 72 hours since its generation (since the moment your computer was infected). Once this has " fullword ascii
      $s4 = "Do not delete this file, else the decryption process will be broken" fullword wide
      $s5 = "key you received, and wait until the decryption process is done." fullword ascii
      $s6 = "In order to receive your decryption key, you will have to pay $200 in bitcoins to this bitcoin address: [bitcoin address]" fullword ascii
      $s7 = "Decryption process failed" fullword wide
      $s8 = "CryptoNarDecryptor.KeyValidationWindow.resources" fullword ascii
      $s9 = "Important note: Removing CryptoNar will not restore access to your encrypted files." fullword ascii
      $s10 = "johnsmith987654@tutanota.com" fullword wide
      $s11 = "Decryption process will start soon" fullword wide
      $s12 = "CryptoNarDecryptor.DecryptionProgressBarForm.resources" fullword ascii
      $s13 = "DecryptionProcessProgressBar" fullword wide
      $s14 = "CryptoNarDecryptor.Properties.Resources.resources" fullword ascii
      
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB) and all of them 
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule CryptoLocker_set1
{
meta:
	author = "Christiaan Beek, Christiaan_Beek@McAfee.com"
	date = "2014-04-13"
	description = "Detection of Cryptolocker Samples"
	
strings:
	$string0 = "static"
	$string1 = " kscdS"
	$string2 = "Romantic"
	$string3 = "CompanyName" wide
	$string4 = "ProductVersion" wide
	$string5 = "9%9R9f9q9"
	$string6 = "IDR_VERSION1" wide
	$string7 = "  </trustInfo>"
	$string8 = "LookFor" wide
	$string9 = ":n;t;y;"
	$string10 = "        <requestedExecutionLevel level"
	$string11 = "VS_VERSION_INFO" wide
	$string12 = "2.0.1.0" wide
	$string13 = "<assembly xmlns"
	$string14 = "  <trustInfo xmlns"
	$string15 = "srtWd@@"
	$string16 = "515]5z5"
	$string17 = "C:\\lZbvnoVe.exe" wide
condition:
	12 of ($string*)
}

rule CryptoLocker_rule2
{
meta:
	author = "Christiaan Beek, Christiaan_Beek@McAfee.com"
	date = "2014-04-14"
	description = "Detection of CryptoLocker Variants"
strings:
	$string0 = "2.0.1.7" wide
	$string1 = "    <security>"
	$string2 = "Romantic"
	$string3 = "ProductVersion" wide
	$string4 = "9%9R9f9q9"
	$string5 = "IDR_VERSION1" wide
	$string6 = "button"
	$string7 = "    </security>"
	$string8 = "VFileInfo" wide
	$string9 = "LookFor" wide
	$string10 = "      </requestedPrivileges>"
	$string11 = " uiAccess"
	$string12 = "  <trustInfo xmlns"
	$string13 = "last.inf"
	$string14 = " manifestVersion"
	$string15 = "FFFF04E3" wide
	$string16 = "3,31363H3P3m3u3z3"
condition:
	12 of ($string*)
}

rule SVG_LoadURL {
	meta:
		description = "Detects a tiny SVG file that loads an URL (as seen in CryptoWall malware infections)"
		author = "Florian Roth"
		reference = "http://goo.gl/psjCCc"
		date = "2015-05-24"
		hash1 = "ac8ef9df208f624be9c7e7804de55318"
		hash2 = "3b9e67a38569ebe8202ac90ad60c52e0"
		hash3 = "7e2be5cc785ef7711282cea8980b9fee"
		hash4 = "4e2c6f6b3907ec882596024e55c2b58b"
		score = 50
	strings:
		$s1 = "</svg>" nocase
		$s2 = "<script>" nocase
		$s3 = "location.href='http" nocase
	condition:
		all of ($s*) and filesize < 600
}
rule BackdoorFCKG: CTB_Locker_Ransomware
{
meta:
author = "ISG"
date = "2015-01-20"
reference = "https://blogs.mcafee.com/mcafee-labs/rise-backdoor-fckq-ctb-locker"
description = "CTB_Locker"

strings:
$string0 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
$stringl = "RNDBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" 
$string2 = "keme132.DLL" 
$string3 = "klospad.pdb" 
condition:
3 of them 
}
//more info at reversecodes.wordpress.com
rule DMALocker : ransom
{
    meta:
    Description = "Deteccion del ransomware DMA Locker desde la version 1.0 a la 4.0"
    ref = "https://blog.malwarebytes.org/threat-analysis/2016/02/dma-locker-a-new-ransomware-but-no-reason-to-panic/"
    Author = "SadFud"
    Date = "30/05/2016"
    
    strings:
    $uno = { 41 42 43 58 59 5a 31 31 }
	  $dos = { 21 44 4d 41 4c 4f 43 4b }
	  $tres = { 21 44 4d 41 4c 4f 43 4b 33 2e 30 }
	  $cuatro = { 21 44 4d 41 4c 4f 43 4b 34 2e 30 }
    
    condition:
    any of them
    
}

//More at reversecodes.wordpress.com
rule DMALocker4 : ransom {

    meta:
    Description = "Deteccion del ransomware DMA Locker version 4.0"
    ref = "https://blog.malwarebytes.org/threat-analysis/2016/02/dma-locker-a-new-ransomware-but-no-reason-to-panic/"
    Author = "SadFud"
    Date = "30/05/2016"
	Hash = "e3106005a0c026fc969b46c83ce9aeaee720df1bb17794768c6c9615f083d5d1"
    
    strings:
    $clave = { 21 44 4d 41 4c 4f 43 4b 34 2e 30 }
    
    condition:
    $clave 
    
}

rule DoublePulsarXor_Petya
{
 meta:
   description = "Rule to hit on the XORed DoublePulsar shellcode"
   author = "Patrick Jones"
   company = "Booz Allen Hamilton"
   reference1 ="https://www.boozallen.com/s/insight/publication/the-petya-ransomware-outbreak.html"
   reference2 = "https://www.boozallen.com/content/dam/boozallen_site/sig/pdf/white-paper/rollup-of-booz-allen-petya-research.pdf"
   date = "2017-06-28"
   hash = "027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745"
   hash = "64b0b58a2c030c77fdb2b537b2fcc4af432bc55ffb36599a31d418c7c69e94b1"
 strings:
   $DoublePulsarXor_Petya = { FD 0C 8C 5C B8 C4 24 C5 CC CC CC 0E E8 CC 24 6B CC CC CC 0F 24 CD CC CC CC 27 5C 97 75 BA CD CC CC C3 FE }
 condition:
   $DoublePulsarXor_Petya
}

rule DoublePulsarDllInjection_Petya
{
 meta:
  description = "Rule to hit on the XORed DoublePulsar DLL injection shellcode"
  author = "Patrick Jones"
  company = "Booz Allen Hamilton"
  reference1 ="https://www.boozallen.com/s/insight/publication/the-petya-ransomware-outbreak.html"
  reference2 = "https://www.boozallen.com/content/dam/boozallen_site/sig/pdf/white-paper/rollup-of-booz-allen-petya-research.pdf"
  date = "2017-06-28"
  hash = "027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745"
  hash = "64b0b58a2c030c77fdb2b537b2fcc4af432bc55ffb36599a31d418c7c69e94b1" 
 strings:
   $DoublePulsarDllInjection_Petya = { 45 20 8D 93 8D 92 8D 91 8D 90 92 93 91 97 0F 9F 9E 9D 99 84 45 29 84 4D 20 CC CD CC CC 9B 84 45 03 84 45 14 84 45 49 CC 33 33 33 24 77 CC CC CC 84 45 49 C4 33 33 33 24 84 CD CC CC 84 45 49 DC 33 33 33 84 47 49 CC 33 33 33 84 47 41 }
 condition:
   $DoublePulsarDllInjection_Petya
} 

rule Erebus: ransom
{
	meta:
		description = "Erebus Ransomware"
		author = "Joan Soriano / @joanbtl"
		date = "2017-06-23"
		version = "1.0"
		MD5 = "27d857e12b9be5d43f935b8cc86eaabf"
		SHA256 = "0b7996bca486575be15e68dba7cbd802b1e5f90436ba23f802da66292c8a055f"
		ref1 = "http://blog.trendmicro.com/trendlabs-security-intelligence/erebus-resurfaces-as-linux-ransomware/"
	strings:
		$a = "/{5f58d6f0-bb9c-46e2-a4da-8ebc746f24a5}//log.log"
		$b = "EREBUS IS BEST."
	condition:
		all of them
}

rule crime_ransomware_windows_GPGQwerty: crime_ransomware_windows_GPGQwerty

{

meta:

author = "McAfee Labs"

description = "Detect GPGQwerty ransomware"

reference = "https://securingtomorrow.mcafee.com/mcafee-labs/ransomware-takes-open-source-path-encrypts-gnu-privacy-guard/"

strings:

$a = "gpg.exe –recipient qwerty  -o"

$b = "%s%s.%d.qwerty"

$c = "del /Q /F /S %s$recycle.bin"

$d = "cryz1@protonmail.com"

condition:

all of them

}

/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule GoldenEye_Ransomware_XLS {
   meta:
      description = "GoldenEye XLS with Macro - file Schneider-Bewerbung.xls"
      author = "Florian Roth"
      reference = "https://goo.gl/jp2SkT"
      date = "2016-12-06"
      hash1 = "2320d4232ee80cc90bacd768ba52374a21d0773c39895b88cdcaa7782e16c441"
   strings:
      $x1 = "fso.GetTempName();tmp_path = tmp_path.replace('.tmp', '.exe')" fullword ascii
      $x2 = "var shell = new ActiveXObject('WScript.Shell');shell.run(t'" fullword ascii
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 4000KB and 1 of them )
}

rule GoldenEyeRansomware_Dropper_MalformedZoomit {
   meta:
      description = "Auto-generated rule - file b5ef16922e2c76b09edd71471dd837e89811c5e658406a8495c1364d0d9dc690"
      author = "Florian Roth"
      reference = "https://goo.gl/jp2SkT"
      date = "2016-12-06"
      hash1 = "b5ef16922e2c76b09edd71471dd837e89811c5e658406a8495c1364d0d9dc690"
   strings:
      $s1 = "ZoomIt - Sysinternals: www.sysinternals.com" fullword ascii
      $n1 = "Mark Russinovich" wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 800KB and $s1 and not $n1 )
}

/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-02-17
	Identifier: Locky
*/

rule Locky_Ransomware : ransom {
	meta:
		description = "Detects Locky Ransomware (matches also on Win32/Kuluoz)"
		author = "Florian Roth (with the help of binar.ly)"
		reference = "https://goo.gl/qScSrE"
		date = "2016-02-17"
		hash = "5e945c1d27c9ad77a2b63ae10af46aee7d29a6a43605a9bfbf35cebbcff184d8"
	strings:
		$o1 = { 45 b8 99 f7 f9 0f af 45 b8 89 45 b8 } // address=0x4144a7
		$o2 = { 2b 0a 0f af 4d f8 89 4d f8 c7 45 } // address=0x413863
	condition:
		all of ($o*)
}

rule Locky_Ransomware_2: ransom {
meta:
    description = "Regla para detectar RANSOM.LOCKY"
    author = "CCN-CERT"
    version = "1.0"
strings:
    $a1 = { 2E 00 6C 00 6F 00 63 00 6B 00 79 00 00 }
    $a2 = { 00 5F 00 4C 00 6F 00 63 00 6B 00 79 00 }
    $a3 = { 5F 00 72 00 65 00 63 00 6F 00 76 00 65 }
    $a4 = { 00 72 00 5F 00 69 00 6E 00 73 00 74 00 }
    $a5 = { 72 00 75 00 63 00 74 00 69 00 6F 00 6E }
    $a6 = { 00 73 00 2E 00 74 00 78 00 74 00 00 }
    $a7 = { 53 6F 66 74 77 61 72 65 5C 4C 6F 63 6B 79 00 }
condition:
    all of them
}

/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule MS17_010_WanaCry_worm {
	meta:
		description = "Worm exploiting MS17-010 and dropping WannaCry Ransomware"
		author = "Felipe Molina (@felmoltor)"
		reference = "https://www.exploit-db.com/exploits/41987/"
		date = "2017/05/12"
	strings:
		$ms17010_str1="PC NETWORK PROGRAM 1.0"
		$ms17010_str2="LANMAN1.0"
		$ms17010_str3="Windows for Workgroups 3.1a"
		$ms17010_str4="__TREEID__PLACEHOLDER__"
		$ms17010_str5="__USERID__PLACEHOLDER__"
		$wannacry_payload_substr1 = "h6agLCqPqVyXi2VSQ8O6Yb9ijBX54j"
		$wannacry_payload_substr2 = "h54WfF9cGigWFEx92bzmOd0UOaZlM"
		$wannacry_payload_substr3 = "tpGFEoLOU6+5I78Toh/nHs/RAP"

	condition:
		all of them
}

/*
Four YARA rules to check for payloads on systems. Thanks to sinkholing, encyrption may not occur, BUT you may still have binaries lying around.
If you get a match for "WannaDecryptor" and not for Wanna_Sample, then you may have a variant!
 
Check out http://yara.readthedocs.io on how to write and add a rule as below and index your
rule by the sample hashes.  Add, share, rinse and repeat!
*/
 
rule WannaDecryptor: WannaDecryptor
{
        meta:
                description = "Detection for common strings of WannaDecryptor"
 
        strings:
                $id1 = "taskdl.exe"
                $id2 = "taskse.exe"
                $id3 = "r.wnry"
                $id4 = "s.wnry"
                $id5 = "t.wnry"
                $id6 = "u.wnry"
                $id7 = "msg/m_"
 
        condition:
                3 of them
}

rule Wanna_Sample_84c82835a5d21bbcf75a61706d8ab549: Wanna_Sample_84c82835a5d21bbcf75a61706d8ab549
{
        meta:
                description = "Specific sample match for WannaCryptor"
                MD5 = "84c82835a5d21bbcf75a61706d8ab549"
                SHA1 = "5ff465afaabcbf0150d1a3ab2c2e74f3a4426467"
                SHA256 = "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"
                INFO = "Looks for 'taskdl' and 'taskse' at known offsets"
 
        strings:
                $taskdl = { 00 74 61 73 6b 64 6c }
                $taskse = { 00 74 61 73 6b 73 65 }
 
        condition:
                $taskdl at 3419456 and $taskse at 3422953
}

rule Wanna_Sample_4da1f312a214c07143abeeafb695d904: Wanna_Sample_4da1f312a214c07143abeeafb695d904
{
        meta:
                description = "Specific sample match for WannaCryptor"
                MD5 = "4da1f312a214c07143abeeafb695d904"
                SHA1 = "b629f072c9241fd2451f1cbca2290197e72a8f5e"
                SHA256 = "aee20f9188a5c3954623583c6b0e6623ec90d5cd3fdec4e1001646e27664002c"
                INFO = "Looks for offsets of r.wry and s.wry instances"
 
        strings:
                $rwnry = { 72 2e 77 72 79 }
                $swnry = { 73 2e 77 72 79 }
 
        condition:
                $rwnry at 88195 and $swnry at 88656 and $rwnry at 4495639
}
rule NHS_Strain_Wanna: NHS_Strain_Wanna
{
        meta:
                description = "Detection for worm-strain bundle of Wcry, DOublePulsar"
                MD5 = "db349b97c37d22f5ea1d1841e3c89eb4"
                SHA1 = "e889544aff85ffaf8b0d0da705105dee7c97fe26"
                SHA256 = "24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c"
                INFO = "Looks for specific offsets of c.wnry and t.wnry strings"
 
        strings:
                $cwnry = { 63 2e 77 6e 72 79 }
                $twnry = { 74 2e 77 6e 72 79 }
 
        condition:
                $cwnry at 262324 and $twnry at 267672 and $cwnry at 284970
}
rule ransom_telefonica : TELEF
{
  meta:
    author = "Jaume Martin <@Xumeiquer>"
    description = "Ransmoware Telefonica"
    date = "2017-05-13"
    reference = "http://www.elmundo.es/tecnologia/2017/05/12/59158a8ce5fdea194f8b4616.html"
    md5 = "7f7ccaa16fb15eb1c7399d422f8363e8"
    sha256 = "2584e1521065e45ec3c17767c065429038fc6291c091097ea8b22c8a502c41dd"
  strings:
    $a = "RegCreateKeyW" wide ascii nocase
    $b = "cmd.exe /c"
    $c = "115p7UMMngoj1pMvkpHijcRdfJNXj6LrLn" ascii
    $d = "12t9YDPgwueZ9NyMgw519p7AA8isjr6SMw" ascii
    $e = "13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94" ascii
    $f = "tasksche.exe"
  condition:
    uint16(0) == 0x5A4D and $a and for all of ($b, $c, $d, $e, $f) : (@ > @a)
}

rule Wanna_Cry_Ransomware_Generic {
       meta:
              description = "Detects WannaCry Ransomware on Disk and in Virtual Page"
              author = "US-CERT Code Analysis Team"
              reference = "not set"                                        
              date = "2017/05/12"
       hash0 = "4DA1F312A214C07143ABEEAFB695D904"
       strings:
              $s0 = {410044004D0049004E0024}
              $s1 = "WannaDecryptor"
              $s2 = "WANNACRY"
              $s3 = "Microsoft Enhanced RSA and AES Cryptographic"
              $s4 = "PKS"
              $s5 = "StartTask"
              $s6 = "wcry@123"
              $s7 = {2F6600002F72}
              $s8 = "unzip 0.15 Copyrigh"
              $s9 = "Global\\WINDOWS_TASKOSHT_MUTEX"        
              $s10 = "Global\\WINDOWS_TASKCST_MUTEX"   
             $s11 = {7461736B736368652E657865000000005461736B5374617274000000742E776E7279000069636163}
             $s12 = {6C73202E202F6772616E742045766572796F6E653A46202F54202F43202F5100617474726962202B68}
             $s13 = "WNcry@2ol7"
             $s14 = "wcry@123"
             $s15 = "Global\\MsWinZonesCacheCounterMutexA"
       condition:
              $s0 and $s1 and $s2 and $s3 or $s4 and $s5 and $s6 and $s7 or $s8 and $s9 and $s10 or $s11 and $s12 or $s13 or $s14 or $s15
}
rule WannaCry_Ransomware {
   meta:
      description = "Detects WannaCry Ransomware"
      author = "Florian Roth (with the help of binar.ly)"
      reference = "https://goo.gl/HG2j5T"
      date = "2017-05-12"
      hash1 = "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"
   strings:
      $x1 = "icacls . /grant Everyone:F /T /C /Q" fullword ascii
      $x2 = "taskdl.exe" fullword ascii
      $x3 = "tasksche.exe" fullword ascii
      $x4 = "Global\\MsWinZonesCacheCounterMutexA" fullword ascii
      $x5 = "WNcry@2ol7" fullword ascii
      $x6 = "www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" ascii
      $x7 = "mssecsvc.exe" fullword ascii
      $x8 = "C:\\%s\\qeriuwjhrf" fullword ascii
      $x9 = "icacls . /grant Everyone:F /T /C /Q" fullword ascii

      $s1 = "C:\\%s\\%s" fullword ascii
      $s2 = "<!-- Windows 10 --> " fullword ascii
      $s3 = "cmd.exe /c \"%s\"" fullword ascii
      $s4 = "msg/m_portuguese.wnry" fullword ascii
      $s5 = "\\\\192.168.56.20\\IPC$" fullword wide
      $s6 = "\\\\172.16.99.5\\IPC$" fullword wide

      $op1 = { 10 ac 72 0d 3d ff ff 1f ac 77 06 b8 01 00 00 00 }
      $op2 = { 44 24 64 8a c6 44 24 65 0e c6 44 24 66 80 c6 44 }
      $op3 = { 18 df 6c 24 14 dc 64 24 2c dc 6c 24 5c dc 15 88 }
      $op4 = { 09 ff 76 30 50 ff 56 2c 59 59 47 3b 7e 0c 7c }
      $op5 = { c1 ea 1d c1 ee 1e 83 e2 01 83 e6 01 8d 14 56 }
      $op6 = { 8d 48 ff f7 d1 8d 44 10 ff 23 f1 23 c1 }
   condition:
      uint16(0) == 0x5a4d and filesize < 10000KB and ( 1 of ($x*) and 1 of ($s*) or 3 of ($op*) )
}

rule WannaCry_Ransomware_Gen {
   meta:
      description = "Detects WannaCry Ransomware"
      author = "Florian Roth (based on rule by US CERT)"
      reference = "https://www.us-cert.gov/ncas/alerts/TA17-132A"
      date = "2017-05-12"
      hash1 = "9fe91d542952e145f2244572f314632d93eb1e8657621087b2ca7f7df2b0cb05"
      hash2 = "8e5b5841a3fe81cade259ce2a678ccb4451725bba71f6662d0cc1f08148da8df"
      hash3 = "4384bf4530fb2e35449a8e01c7e0ad94e3a25811ba94f7847c1e6612bbb45359"
   strings:
      $s1 = "__TREEID__PLACEHOLDER__" fullword ascii
      $s2 = "__USERID__PLACEHOLDER__" fullword ascii
      $s3 = "Windows for Workgroups 3.1a" fullword ascii
      $s4 = "PC NETWORK PROGRAM 1.0" fullword ascii
      $s5 = "LANMAN1.0" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and all of them
}

rule WannCry_m_vbs {
   meta:
      description = "Detects WannaCry Ransomware VBS"
      author = "Florian Roth"
      reference = "https://goo.gl/HG2j5T"
      date = "2017-05-12"
      hash1 = "51432d3196d9b78bdc9867a77d601caffd4adaa66dcac944a5ba0b3112bbea3b"
   strings:
      $x1 = ".TargetPath = \"C:\\@" ascii
      $x2 = ".CreateShortcut(\"C:\\@" ascii
      $s3 = " = WScript.CreateObject(\"WScript.Shell\")" ascii
   condition:
      ( uint16(0) == 0x4553 and filesize < 1KB and all of them )
}

rule WannCry_BAT {
   meta:
      description = "Detects WannaCry Ransomware BATCH File"
      author = "Florian Roth"
      reference = "https://goo.gl/HG2j5T"
      date = "2017-05-12"
      hash1 = "f01b7f52e3cb64f01ddc248eb6ae871775ef7cb4297eba5d230d0345af9a5077"
   strings:
      $s1 = "@.exe\">> m.vbs" ascii
      $s2 = "cscript.exe //nologo m.vbs" fullword ascii
      $s3 = "echo SET ow = WScript.CreateObject(\"WScript.Shell\")> " ascii
      $s4 = "echo om.Save>> m.vbs" fullword ascii
   condition:
      ( uint16(0) == 0x6540 and filesize < 1KB and 1 of them )
}

rule WannaCry_RansomNote {
   meta:
      description = "Detects WannaCry Ransomware Note"
      author = "Florian Roth"
      reference = "https://goo.gl/HG2j5T"
      date = "2017-05-12"
      hash1 = "4a25d98c121bb3bd5b54e0b6a5348f7b09966bffeec30776e5a731813f05d49e"
   strings:
      $s1 = "A:  Don't worry about decryption." fullword ascii
      $s2 = "Q:  What's wrong with my files?" fullword ascii
   condition:
      ( uint16(0) == 0x3a51 and filesize < 2KB and all of them )
}

/* Kaspersky Rule */

rule lazaruswannacry {
   meta:
      description = "Rule based on shared code between Feb 2017 Wannacry sample and Lazarus backdoor from Feb 2015 discovered by Neel Mehta"
      date = "2017-05-15"
      reference = "https://twitter.com/neelmehta/status/864164081116225536"
      author = "Costin G. Raiu, Kaspersky Lab"
      version = "1.0"
      hash = "9c7c7149387a1c79679a87dd1ba755bc"
      hash = "ac21c8ad899727137c4b94458d7aa8d8"
   strings:
      $a1 = { 51 53 55 8B 6C 24 10 56 57 6A 20 8B 45 00 8D 75 04 24 01 0C 01 46 89 45 00 C6 46 FF 03 C6 06 01 46 56 E8 }
      $a2 = { 03 00 04 00 05 00 06 00 08 00 09 00 0A 00 0D 00 10 00 11 00 12 00 13 00 14 00 15 00 16 00 2F 00 30 00 31 00 32 00 33 00 34 00 35 00 36 00 37 00 38 00 39 00 3C 00 3D 00 3E 00 3F 00 40 00 41 00 44 00 45 00 46 00 62 00 63 00 64 00 66 00 67 00 68 00 69 00 6A 00 6B 00 84 00 87 00 88 00 96 00 FF 00 01 C0 02 C0 03 C0 04 C0 05 C0 06 C0 07 C0 08 C0 09 C0 0A C0 0B C0 0C C0 0D C0 0E C0 0F C0 10 C0 11 C0 12 C0 13 C0 14 C0 23 C0 24 C0 27 C0 2B C0 2C C0 FF FE }
   condition:
      uint16(0) == 0x5A4D and filesize < 15000000 and all of them
}

/* Cylance Rule */

 import "pe"
 
 rule WannaCry_Ransomware_Dropper
 {
 meta:
	description = "WannaCry Ransomware Dropper"
 	reference = "https://www.cylance.com/en_us/blog/threat-spotlight-inside-the-wannacry-attack.html"
 	date = "2017-05-12"

strings:
	$s1 = "cmd.exe /c \"%s\"" fullword ascii
 	$s2 = "tasksche.exe" fullword ascii
 	$s3 = "icacls . /grant Everyone:F /T /C /Q" fullword ascii
 	$s4 = "Global\\MsWinZonesCacheCounterMutexA" fullword ascii
 
 condition:
 	uint16(0) == 0x5a4d and filesize < 4MB and all of them
}

rule WannaCry_SMB_Exploit
{
 meta:
 	description = "WannaCry SMB Exploit"
 	reference = "https://www.cylance.com/en_us/blog/threat-spotlight-inside-the-wannacry-attack.html"
 	date = "2017-05-12"
 
 strings:
 	$s1 = { 53 4D 42 72 00 00 00 00 18 53 C0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 FF FE 00 00 40 00 00 62 00 02 50 43 20 4E 45 54 57 4F 52 4B 20 50 52 4F 47 52 41 4D 20 31 2E 30 00 02 4C 41 4E 4D 41 4E 31 2E 30 00 02 57 69 6E 64 6F 77 73 20 66 6F 72 20 57 6F 72 6B 67 72 6F 75 70 73 20 33 2E 31 61 00 02 4C 4D 31 2E 32 58 30 30 32 00 02 4C 41 4E 4D 41 4E 32 2E 31 00 02 4E 54 20 4C 4D 20 30 2E 31 32 00 00 00 00 00 00 00 88 FF 53 4D 42 73 00 00 00 00 18 07 C0 }
 
 condition:
 	uint16(0) == 0x5a4d and filesize < 4MB and all of them and pe.imports("ws2_32.dll", "connect") and pe.imports("ws2_32.dll", "send") and pe.imports("ws2_32.dll", "recv") and pe.imports("ws2_32.dll", "socket") and pe.imports("ws2_32.dll", "closesocket")
 }
 
 rule wannacry_static_ransom : wannacry_static_ransom {

meta:

description = "Detects WannaCryptor spreaded during 2017-May-12th campaign and variants"

author = "Blueliv"

reference = "https://blueliv.com/research/wannacrypt-malware-analysis/"

date = "2017-05-15"

strings:

$mutex01 = "Global\\MsWinZonesCacheCounterMutexA" ascii

$lang01 = "m_bulgarian.wnr" ascii

$lang02 = "m_vietnamese.wnry" ascii

$startarg01 = "StartTask" ascii

$startarg02 = "TaskStart" ascii

$startarg03 = "StartSchedule" ascii

$wcry01 = "WanaCrypt0r" ascii wide

$wcry02 = "WANACRY" ascii

$wcry03 = "WANNACRY" ascii

$wcry04 = "WNCRYT" ascii wide

$forig01 = ".wnry\x00" ascii

$fvar01 = ".wry\x00" ascii

condition:

($mutex01 or any of ($lang*)) and ( $forig01 or all of ($fvar*) ) and any of ($wcry*) and any of ($startarg*)

}

rule wannacry_memory_ransom : wannacry_memory_ransom {

meta:

description = "Detects WannaCryptor spreaded during 2017-May-12th campaign and variants in memory"

author = "Blueliv"

reference = "https://blueliv.com/research/wannacrypt-malware-analysis/"

date = "2017-05-15"

strings:

$s01 = "%08X.eky"

$s02 = "%08X.pky"

$s03 = "%08X.res"

$s04 = "%08X.dky"

$s05 = "@WanaDecryptor@.exe"

condition:

all of them

}

rule worm_ms17_010 : worm_ms17_010 {

meta:

description = "Detects Worm used during 2017-May-12th WannaCry campaign, which is based on ETERNALBLUE"

author = "Blueliv"

reference = "https://blueliv.com/research/wannacrypt-malware-analysis/"

date = "2017-05-15"

strings:

$s01 = "__TREEID__PLACEHOLDER__" ascii

$s02 = "__USERID__PLACEHOLDER__@" ascii

$s03 = "SMB3"

$s05 = "SMBu"

$s06 = "SMBs"

$s07 = "SMBr"

$s08 = "%s -m security" ascii

$s09 = "%d.%d.%d.%d"

$payloadwin2000_2195 =

"\x57\x00\x69\x00\x6e\x00\x64\x00\x6f\x00\x77\x00\x73\x00\x20\x00\x32\x00\x30\x00\x30\x00\x30\x00\x20\x00\x32\x00\x31\x00\x39\x00\x35\x00\x00\x00"

$payload2000_50 =

"\x57\x00\x69\x00\x6e\x00\x64\x00\x6f\x00\x77\x00\x73\x00\x20\x00\x32\x00\x30\x00\x30\x00\x30\x00\x20\x00\x35\x00\x2e\x00\x30\x00\x00\x00"

condition:

all of them

}

rule Maze
{
meta:
	description = "Identifies Maze ransomware in memory or unpacked."
	author = "@bartblaze"
	date = "2019-11"
	tlp = "White"

strings:	
	$ = "Enc: %s" ascii wide
	$ = "Encrypting whole system" ascii wide
	$ = "Encrypting specified folder in --path parameter..." ascii wide
	$ = "!Finished in %d ms!" ascii wide
	$ = "--logging" ascii wide
	$ = "--nomutex" ascii wide
	$ = "--noshares" ascii wide
	$ = "--path" ascii wide
	$ = "Logging enabled | Maze" ascii wide
	$ = "NO SHARES | " ascii wide
	$ = "NO MUTEX | " ascii wide
	$ = "Encrypting:" ascii wide
	$ = "You need to buy decryptor in order to restore the files." ascii wide
	$ = "Dear %s, your files have been encrypted by RSA-2048 and ChaCha algorithms" ascii wide
	$ = "%s! Alert! %s! Alert! Dear %s Your files have been encrypted by %s! Attention! %s" ascii wide
	$ = "DECRYPT-FILES.txt" ascii wide fullword

condition:
	5 of them
}

rule ransomware_PetrWrap 
{
meta:
	copyright= "Kaspersky Lab"
	description = "Rule to detect PetrWrap ransomware samples"
    reference = "https://securelist.com/schroedingers-petya/78870/"
	last_modified = "2017-06-27"
	author = "Kaspersky Lab"
	hash = "71B6A493388E7D0B40C83CE903BC6B04"
	version = "1.0"
strings:
	$a1 = "MIIBCgKCAQEAxP/VqKc0yLe9JhVqFMQGwUITO6WpXWnKSNQAYT0O65Cr8PjIQInTeHkXEjfO2n2JmURWV/uHB0ZrlQ/wcYJBwLhQ9EqJ3iDqmN19Oo7NtyEUmbYmopcqYLIBZzQ2ZTK0A2DtX4GRKxEEFLCy7vP12EYOPXknVy/mf0JFWixz29QiTf5oLu15wVLONCuEibGaNNpgqCXsPwfITDbDDmdrRIiUEUw6o3pt5pNOskfOJbMan2TZu" fullword wide
	$a2 = ".3ds.7z.accdb.ai.asp.aspx.avhd.back.bak.c.cfg.conf.cpp.cs.ctl.dbf.disk.djvu.doc.docx.dwg.eml.fdb.gz.h.hdd.kdbx.mail.mdb.msg.nrg.ora.ost.ova.ovf.pdf.php.pmf.ppt.pptx.pst.pvi.py.pyc.rar.rtf.sln.sql.tar.vbox.vbs.vcb.vdi.vfd.vmc.vmdk.vmsd.vmx.vsdx.vsv.work.xls" fullword wide
	$a3 = "DESTROY ALL OF YOUR DATA PLEASE ENSURE THAT YOUR POWER CABLE IS PLUGGED" fullword ascii
	$a4 = "1Mz7153HMuxXTuR2R1t78mGSdzaAtNbBWX" fullword ascii
	$a5 = "wowsmith123456posteo.net." fullword wide
condition:
	uint16(0) == 0x5A4D and filesize < 1000000 and any of them 
}

/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-03-24
	Identifier: Petya Ransomware
*/

/* Rule Set ----------------------------------------------------------------- */

rule Petya_Ransomware {
	meta:
		description = "Detects Petya Ransomware"
		author = "Florian Roth"
		reference = "http://www.heise.de/newsticker/meldung/Erpressungs-Trojaner-Petya-riegelt-den-gesamten-Rechner-ab-3150917.html"
		date = "2016-03-24"
		hash = "26b4699a7b9eeb16e76305d843d4ab05e94d43f3201436927e13b3ebafa90739"
	strings:
		$a1 = "<description>WinRAR SFX module</description>" fullword ascii

		$s1 = "BX-Proxy-Manual-Auth" fullword wide
		$s2 = "<!--The ID below indicates application support for Windows 10 -->" fullword ascii
		$s3 = "X-HTTP-Attempts" fullword wide
		$s4 = "@CommandLineMode" fullword wide
		$s5 = "X-Retry-After" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 500KB and $a1 and 3 of ($s*)
}

rule Ransom_Petya {
meta:
    description = "Regla para detectar Ransom.Petya con md5 AF2379CC4D607A45AC44D62135FB7015"
    author = "CCN-CERT"
    version = "1.0"
strings:
    $a1 = { C1 C8 14 2B F0 03 F0 2B F0 03 F0 C1 C0 14 03 C2 }
    $a2 = { 46 F7 D8 81 EA 5A 93 F0 12 F7 DF C1 CB 10 81 F6 }
    $a3 = { 0C 88 B9 07 87 C6 C1 C3 01 03 C5 48 81 C3 A3 01 00 00 }
condition:
    all of them
}

rule FE_CPE_MS17_010_RANSOMWARE {
meta:version="1.1"
      //filetype="PE"
      author="Ian.Ahl@fireeye.com @TekDefense, Nicholas.Carr@mandiant.com @ItsReallyNick"
      date="2017-06-27"
      description="Probable PETYA ransomware using ETERNALBLUE, WMIC, PsExec"
      reference = "https://www.fireeye.com/blog/threat-research/2017/06/petya-ransomware-spreading-via-eternalblue-exploit.html"
strings:
      // DRIVE USAGE
      $dmap01 = "\\\\.\\PhysicalDrive" nocase ascii wide
      $dmap02 = "\\\\.\\PhysicalDrive0" nocase ascii wide
      $dmap03 = "\\\\.\\C:" nocase ascii wide
      $dmap04 = "TERMSRV" nocase ascii wide
      $dmap05 = "\\admin$" nocase ascii wide
      $dmap06 = "GetLogicalDrives" nocase ascii wide
      $dmap07 = "GetDriveTypeW" nocase ascii wide

      // RANSOMNOTE
      $msg01 = "WARNING: DO NOT TURN OFF YOUR PC!" nocase ascii wide
      $msg02 = "IF YOU ABORT THIS PROCESS" nocase ascii wide
      $msg03 = "DESTROY ALL OF YOUR DATA!" nocase ascii wide
      $msg04 = "PLEASE ENSURE THAT YOUR POWER CABLE IS PLUGGED" nocase ascii wide
      $msg05 = "your important files are encrypted" ascii wide
      $msg06 = "Your personal installation key" nocase ascii wide
      $msg07 = "worth of Bitcoin to following address" nocase ascii wide
      $msg08 = "CHKDSK is repairing sector" nocase ascii wide
      $msg09 = "Repairing file system on " nocase ascii wide
      $msg10 = "Bitcoin wallet ID" nocase ascii wide
      $msg11 = "wowsmith123456@posteo.net" nocase ascii wide
      $msg12 = "1Mz7153HMuxXTuR2R1t78mGSdzaAtNbBWX" nocase ascii wide
      $msg_pcre = /(en|de)crypt(ion|ed\.)/     

      // FUNCTIONALITY, APIS
      $functions01 = "need dictionary" nocase ascii wide
      $functions02 = "comspec" nocase ascii wide
      $functions03 = "OpenProcessToken" nocase ascii wide
      $functions04 = "CloseHandle" nocase ascii wide
      $functions05 = "EnterCriticalSection" nocase ascii wide
      $functions06 = "ExitProcess" nocase ascii wide
      $functions07 = "GetCurrentProcess" nocase ascii wide
      $functions08 = "GetProcAddress" nocase ascii wide
      $functions09 = "LeaveCriticalSection" nocase ascii wide
      $functions10 = "MultiByteToWideChar" nocase ascii wide
      $functions11 = "WideCharToMultiByte" nocase ascii wide
      $functions12 = "WriteFile" nocase ascii wide
      $functions13 = "CoTaskMemFree" nocase ascii wide
      $functions14 = "NamedPipe" nocase ascii wide
      $functions15 = "Sleep" nocase ascii wide // imported, not in strings     

      // COMMANDS
      //  -- Clearing event logs & USNJrnl
      $cmd01 = "wevtutil cl Setup" ascii wide nocase
      $cmd02 = "wevtutil cl System" ascii wide nocase
      $cmd03 = "wevtutil cl Security" ascii wide nocase
      $cmd04 = "wevtutil cl Application" ascii wide nocase
      $cmd05 = "fsutil usn deletejournal" ascii wide nocase
      // -- Scheduled task
      $cmd06 = "schtasks " nocase ascii wide
      $cmd07 = "/Create /SC " nocase ascii wide
      $cmd08 = " /TN " nocase ascii wide
      $cmd09 = "at %02d:%02d %ws" nocase ascii wide
      $cmd10 = "shutdown.exe /r /f" nocase ascii wide
      // -- Sysinternals/PsExec and WMIC
      $cmd11 = "-accepteula -s" nocase ascii wide
      $cmd12 = "wmic"
      $cmd13 = "/node:" nocase ascii wide
      $cmd14 = "process call create" nocase ascii wide

condition:
      // (uint16(0) == 0x5A4D)
      3 of ($dmap*)
      and 2 of ($msg*)
      and 9 of ($functions*)
      and 7 of ($cmd*)
}         

rule petya_eternalblue : petya_eternalblue {
    meta:
        author      = "blueliv"
        description =  "Based on spreading petya version: 2017-06-28"
        reference = "https://blueliv.com/petya-ransomware-cyber-attack-is-spreading-across-the-globe-part-2/"
    strings:
        /* Some commands executed by the Petya variant */
       $cmd01 = "schtasks %ws/Create /SC once /TN \"\" /TR \"%ws\" /ST %02d:%0" wide
       $cmd02 = "shutdown.exe /r /f" wide
       $cmd03 = "%s \\\\%s -accepteula -s" wide
       $cmd04 = "process call create \"C:\\Windows\\System32\\rundll32.exe \\\"C:\\Windows\\%s\\\" #1" wide
       /* Strings of encrypted files */
       $str01 = "they have been encrypted. Perhaps you are busy looking" wide
        /* MBR/VBR payload */
        $mbr01 = {00 00 00 55 aa e9 ?? ??}
    condition:
        all of them
}

rule pico_ransomware {
   
   meta:
   
      description = "Rule to detect Pico Ransomware"
      author = "Marc Rivero | @seifreed"
      reference = "https://twitter.com/siri_urz/status/1035138577934557184"
      
   strings:

      $s1 = "C:\\Users\\rikfe\\Desktop\\Ransomware\\ThanatosSource\\Release\\Ransomware.pdb" fullword ascii
      $s2 = "\\Downloads\\README.txt" fullword ascii
      $s3 = "\\Music\\README.txt" fullword ascii
      $s4 = "\\Videos\\README.txt" fullword ascii
      $s5 = "\\Pictures\\README.txt" fullword ascii
      $s6 = "\\Desktop\\README.txt" fullword ascii
      $s7 = "\\Documents\\README.txt" fullword ascii
      $s8 = "/c taskkill /im " fullword ascii
      $s9 = "\\AppData\\Roaming\\" fullword ascii
      $s10 = "gMozilla/5.0 (Windows NT 6.1) Thanatos/1.1" fullword wide
      $s11 = "AppData\\Roaming" fullword ascii
      $s12 = "\\Downloads" fullword ascii
      $s13 = "operator co_await" fullword ascii
   
   condition:
      ( uint16(0) == 0x5a4d and filesize < 700KB ) and all of them
}

rule Revil_Ransomware : ransomware {
   meta:
      author = "Josh Lemon"
      description = "Detects REvil Linux - Revix 1.1 and 1.2"
      reference = "https://angle.ankura.com/post/102hcny/revix-linux-ransomware"
      date = "2021-11-04"
      version = "1.1"
      hash1 = "f864922f947a6bb7d894245b53795b54b9378c0f7633c521240488e86f60c2c5"
      hash2 = "559e9c0a2ef6898fabaf0a5fb10ac4a0f8d721edde4758351910200fe16b5fa7"
      hash3 = "ea1872b2835128e3cb49a0bc27e4727ca33c4e6eba1e80422db19b505f965bc4"
   strings:
      $s1 = "Usage example: elf.exe --path /vmfs/ --threads 5" fullword ascii 
      $s2 = "uname -a && echo \" | \" && hostname" fullword ascii
      $s3 = "esxcli --formatter=csv --format-param=fields==\"WorldID,DisplayName\" vm process list" ascii
      $s4 = "awk -F \"\\\"*,\\\"*\" '{system(\"esxcli" ascii
      $s5 = "--silent (-s) use for not stoping VMs mode" fullword ascii
      $s6 = "!!!BY DEFAULT THIS SOFTWARE USES 50 THREADS!!!" fullword ascii
      $s7 = "%d:%d: Comment not allowed here" fullword ascii
      $s8 = "Error decoding user_id %d " fullword ascii 
      $s9 = "Error read urandm line %d!" fullword ascii
      $s10 = "%d:%d: Unexpected `%c` in comment opening sequence" fullword ascii
      $s11 = "%d:%d: Unexpected EOF in block comment" fullword ascii
      $s12 = "Using silent mode, if you on esxi - stop VMs manualy" fullword ascii
      $s13 = "rand: try to read %hu but get %lu bytes" fullword ascii
      $s14 = "Revix" fullword ascii
      $s15 = "without --path encrypts current dir" fullword ascii
      
      $e1 = "[%s] already encrypted" fullword ascii
      $e2 = "File [%s] was encrypted" fullword ascii
      $e3 = "File [%s] was NOT encrypted" fullword ascii
      $e4 = "Encrypting [%s]" fullword ascii

   condition:
      uint16(0) == 0x457f and filesize < 300KB and ( 4 of ($s*) and 2 of ($e*))
}




/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/
rule Ransom_Satana
{
    meta:
        description = "Regla para detectar Ransom.Satana"
        author = "CCN-CERT"
        version = "1.0"
    strings:
        $a = { 21 00 73 00 61 00 74 00 61 00 6E 00 61 00 21 00 2E 00 74 00 78 00 74 00 00 }
        $b = { 74 67 77 79 75 67 77 71 }
        $c = { 53 77 76 77 6E 67 75 }
        $d = { 45 6E 75 6D 4C 6F 63 61 6C 52 65 73 }
        $e = { 57 4E 65 74 4F 70 65 6E 45 6E 75 6D 57 00 }
        $f = { 21 53 41 54 41 4E 41 21 }
    condition:
        $b or $c and $d and $a and $e and $f
}

rule Ransom_Satana_Dropper
{
    meta:
        description = "Regla para detectar el dropper de Ransom.Satana"
        author = "CCN-CERT"
        version = "1.0"
    strings:
        $a = { 25 73 2D 54 72 79 45 78 63 65 70 74 }
        $b = { 64 3A 5C 6C 62 65 74 77 6D 77 79 5C 75 69 6A 65 75 71 70 6C 66 77 75 62 2E 70 64 62 }
        $c = { 71 66 6E 74 76 74 68 62 }
    condition:
        all of them
}

rule unpacked_shiva_ransomware {

   meta:

      description = "Rule to detect an unpacked sample of Shiva ransopmw"
      author = "Marc Rivero | @seifreed"
      reference = "https://twitter.com/malwrhunterteam/status/1037424962569732096"
    
   strings:

      $s1 = "c:\\Users\\sys\\Desktop\\v 0.5\\Shiva\\Shiva\\obj\\Debug\\shiva.pdb" fullword ascii
      $s2 = "This email will be as confirmation you are ready to pay for decryption key." fullword wide
      $s3 = "Your important files are now encrypted due to a security problem with your PC!" fullword wide
      $s4 = "write.php?info=" fullword wide
      $s5 = " * Do not try to decrypt your data using third party software, it may cause permanent data loss." fullword wide
      $s6 = " * Do not rename encrypted files." fullword wide
      $s7 = ".compositiontemplate" fullword wide
      $s8 = "You have to pay for decryption in Bitcoins. The price depends on how fast you write to us." fullword wide
      $s9 = "\\READ_IT.txt" fullword wide
      $s10 = ".lastlogin" fullword wide
      $s11 = ".logonxp" fullword wide
      $s12 = " * Decryption of your files with the help of third parties may cause increased price" fullword wide
      $s13 = "After payment we will send you the decryption tool that will decrypt all your files." fullword wide
   
   condition:

      ( uint16(0) == 0x5a4d and filesize < 800KB ) and all of them 
}


rule sigma_ransomware {

  meta:
    author = "J from THL <j@techhelplist.com>"
    date = "20180509"
    reference1 = "https://www.virustotal.com/#/file/705ad78bf5503e6022f08da4c347afb47d4e740cfe6c39c08550c740c3be96ba"
    reference2 = "https://www.virustotal.com/#/file/bb3533440c27a115878ae541aba3bda02d441f3ea1864b868862255aabb0c8ff"
    version = 1
    maltype = "Ransomware"
    filetype = "memory"

  strings:
    $a = ".php?"
    $b = "uid="
    $c = "&uname="
    $d = "&os="
    $e = "&pcname="
    $f = "&total="
    $g = "&country="
    $h = "&network="
    $i = "&subid="

  condition:
    all of them
}

rule SnakeRansomware
{
    meta:
        Author = "Nishan Maharjan"
        Description = "A yara rule to catch snake ransomware"
        Reference = "https://medium.com/@nishanmaharjan17/malware-analysis-snake-ransomware-a0e66f487017"
        Data = "15th May 2020"
    strings:
        $go_build_id = "Go build ID: \"X6lNEpDhc_qgQl56x4du/fgVJOqLlPCCIekQhFnHL/rkxe6tXCg56Ez88otHrz/Y-lXW-OhiIbzg3-ioGRz\""
        $math_rand_seed_calling = { 89 C8 BB 00 CA 9A 3B 89 D1 F7 E3 81 E1 FF FF FF 3F 89 C3 01 C8 89 C6 05 00 00 1A 3D 89 04 24 69 ED 00 CA 9A 3B 01 EA 89 CD C1 F9 1F 01 EB 11 CA 81 C6 00 00 1A 3D 81 D2 EB 03 B2 A1 89 54 24 04 E8 10 62 F6 FF }
        $encryption_function = {64 8B 0D 14 00 00 00 8B 89 00 00 00 00 3B 61 08 0F 86 38 01 00 00 83 EC 3C E8 32 1A F3 FF 8D 7C 24 28 89 E6 E8 25 EA F0 FF 8B 44 24 2C 8B 4C 24 28 89 C2 C1 E8 1F C1 E0 1F 85 C0 0F 84 FC 00 00 00 D1 E2 89 CB C1 E9 1F 09 D1 89 DA D1 E3 C1 EB 1F 89 CD D1 E1 09 D9 89 CB 81 C1 80 7F B1 D7 C1 ED 1F 81 C3 80 7F B1 D7 83 D5 0D 89 C8 BB 00 CA 9A 3B 89 D1 F7 E3 81 E1 FF FF FF 3F 89 C3 01 C8 89 C6 05 00 00 1A 3D 89 04 24 69 ED 00 CA 9A 3B 01 EA 89 CD C1 F9 1F 01 EB 11 CA 81 C6 00 00 1A 3D 81 D2 EB 03 B2 A1 89 54 24 04 E8 10 62 F6 FF 31 C0 EB 79 89 44 24 20 8B 4C 24 40 8D 14 C1 8B 1A 89 5C 24 24 8B 52 04 89 54 24 1C C7 04 24 05 00 00 00 E8 48 FE FF FF 8B 44 24 08 8B 4C 24 04 C7 04 24 00 00 00 00 8B 54 24 24 89 54 24 04 8B 5C 24 1C 89 5C 24 08 89 4C 24 0C 89 44 24 10 E8 EC DD EF FF 8B 44 24 18 8B 4C 24 14 89 4C 24 08 89 44 24 0C 8B 44 24 24 89 04 24 8B 44 24 1C 89 44 24 04 E8 68 BB F3 FF 8B 44 24 20 40}
    condition:
        all of them     
}


/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule stampado_overlay
{
meta:
description = "Catches Stampado samples looking for \\r at the beginning of PE overlay section"
reference = ""
author = "Fernando Merces, FTR, Trend Micro"
date = "2016-07"
md5 = "a393b9536a1caa34914636d3da7378b5"
md5 = "dbf3707a9cd090853a11dda9cfa78ff0"
md5 = "dd5686ca7ec28815c3cf3ed3dbebdff2"
md5 = "6337f0938e4a9c0ef44ab99deb0ef466"

condition:
pe.characteristics == 0x122 and
pe.number_of_sections == 5 and
pe.imports("VERSION.dll", "VerQueryValueW") and uint8(pe.sections[4].raw_data_offset + pe.sections[4].raw_data_size) == 0x0d

}

rule TeslaCrypt {
meta:
    description = "Regla para detectar Tesla con md5"
    author = "CCN-CERT"
    version = "1.0"
strings:
    $ = { 4E 6F 77 20 69 74 27 73 20 25 49 3A 25 4D 25 70 2E 00 00 00 76 61 6C 20 69 73 20 25 64 0A 00 00 }
condition:
    all of them
}

/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"


rule Win32Toxic : tox ransomware
{
meta:
	author = "@GelosSnake"
	date = "2015-06-02"
	description = "https://blogs.mcafee.com/mcafee-labs/meet-tox-ransomware-for-the-rest-of-us"
	hash0 = "70624c13be4d8a4c1361be38b49cb3eb"
	hash1 = "4f20d25cd3ae2e5c63d451d095d97046"
	hash2 = "e0473434cc83b57c4b579d585d4c4c57"
	hash3 = "c52090d184b63e5cc71b524153bb079e"
	hash4 = "7ac0b49baba9914b234cde62058c96a5"
	hash5 = "048c007de4902b6f4731fde45fa8e6a9"
	hash6 = "238ef3e35b14e304c87b9c62f18953a9"
	hash7 = "8908ccd681f66429c578a889e6e708e1"
	hash8 = "de9fe2b7d9463982cc77c78ee51e4d51"
	hash9 = "37add8d26a35a3dc9700b92b67625fa4"
	hash10 = "a0f30e89a3431fca1d389f90dba1d56e"
	hash11 = "d4d0658302c731003bf0683127618bd9"
	hash12 = "d1d89e1c7066f41c1d30985ac7b569db"
	hash13 = "97d52d7281dfae8ff9e704bf30ce2484"
	hash14 = "2cc85be01e86e0505697cf61219e66da"
	hash15 = "02ecfb44b9b11b846ea8233d524ecda3"
	hash16 = "703a6ebe71131671df6bc92086c9a641"
	hash17 = "df23629b4a4aed05d6a453280256c05a"
	hash18 = "07466ff2572f16c63e1fee206b081d11"
	hash19 = "792a1c0971775d32bad374b288792468"
	hash20 = "fb7fd5623fa6b7791a221fad463223cd"
	hash21 = "83a562aab1d66e5d170f091b2ae6a213"
	hash22 = "99214c8c9ff4653b533dc1b19a21d389"
	hash23 = "a92aec198eee23a3a9a145e64d0250ee"
	hash24 = "e0f7e6b96ca72b9755965b9dac3ce77e"
	hash25 = "f520fc947a6d5edb87aa01510bee9c8d"
	hash26 = "6d7babbe5e438539a9fa2c5d6128d3b4"
	hash27 = "3133c2231fcee5d6b0b4c988a5201da1"
	hash28 = "e5b1d198edc413376e0c0091566198e4"
	hash29 = "50515b5a6e717976823895465d5dc684"
	hash30 = "510389e8c7f22f2076fc7c5388e01220"
	hash31 = "60573c945aa3b8cfaca0bdb6dd7d2019"
	hash32 = "394187056697463eba97382018dfe151"
	hash33 = "045a5d3c95e28629927c72cf3313f4cd"
	hash34 = "70951624eb06f7db0dcab5fc33f49127"
	hash35 = "5def9e3f7b15b2a75c80596b5e24e0f4"
	hash36 = "35a42fb1c65ebd7d763db4abb26d33b0"
	hash37 = "b0030f5072864572f8e6ba9b295615fc"
	hash38 = "62706f48689f1ba3d1d79780010b8739"
	hash39 = "be86183fa029629ee9c07310cd630871"
	hash40 = "9755c3920d3a38eb1b5b7edbce6d4914"
	hash41 = "cb42611b4bed97d152721e8db5abd860"
	hash42 = "5475344d69fc6778e12dc1cbba23b382"
	hash43 = "8c1bf70742b62dec1b350a4e5046c7b6"
	hash44 = "6a6541c0f63f45eff725dec951ec90a7"
	hash45 = "a592c5bee0d81ee127cbfbcb4178afe8"
	hash46 = "b74c6d86ec3904f4d73d05b2797f1cc3"
	hash47 = "28d76fd4dd2dbfc61b0c99d2ad08cd8e"
	hash48 = "fc859ae67dc1596ac3fdd79b2ed02910"
	hash49 = "cb65d5e929da8ff5c8434fd8d36e5dfb"
	hash50 = "888dd1acce29cd37f0696a0284ab740a"
	hash51 = "0e3e231c255a5eefefd20d70c247d5f0"
	hash52 = "e5ebe35d934106f9f4cebbd84e04534b"
	hash53 = "3b580f1fa0c961a83920ce32b4e4e86d"
	hash54 = "d807a704f78121250227793ea15aa9c4"
	hash55 = "db462159bddc0953444afd7b0d57e783"
	hash56 = "2ed4945fb9e6202c10fad0761723cb0e"
	hash57 = "51183ab4fd2304a278e36d36b5fb990c"
	hash58 = "65d602313c585c8712ea0560a655ddeb"
	hash59 = "0128c12d4a72d14bb67e459b3700a373"
	hash60 = "5d3dfc161c983f8e820e59c370f65581"
	hash61 = "d4dd475179cd9f6180d5b931e8740ed6"
	hash62 = "5dd3782ce5f94686448326ddbbac934c"
	hash63 = "c85c6171a7ff05d66d497ad0d73a51ed"
	hash64 = "b42dda2100da688243fe85a819d61e2e"
	hash65 = "a5cf8f2b7d97d86f4d8948360f3db714"
	hash66 = "293cae15e4db1217ea72581836a6642c"
	hash67 = "56c3a5bae3cb1d0d315c1353ae67cf58"
	hash68 = "c86dc1d0378cc0b579a11d873ac944e7"
	hash69 = "54cef0185798f3ec1f4cb95fad4ddd7c"
	hash70 = "eb2eff9838043b67e8024ccadcfe1a8f"
	hash71 = "78778fe62ee28ef949eec2e7e5961ca8"
	hash72 = "e75c5762471a490d49b79d01da745498"
	hash73 = "1564d3e27b90a166a0989a61dc3bd646"
	hash74 = "59ba111403842c1f260f886d69e8757d"
	hash75 = "d840dfbe52a04665e40807c9d960cccc"
	hash76 = "77f543f4a8f54ecf84b15da8e928d3f9"
	hash77 = "bd9512679fdc1e1e89a24f6ebe0d5ad8"
	hash78 = "202f042d02be4f6469ed6f2e71f42c04"
	hash79 = "28f827673833175dd9094002f2f9b780"
	hash80 = "0ff10287b4c50e0d11ab998a28529415"
	hash81 = "644daa2b294c5583ce6aa8bc68f1d21f"
	hash82 = "1c9db47778a41775bbcb70256cc1a035"
	hash83 = "c203bc5752e5319b81cf1ca970c3ca96"
	hash84 = "656f2571e4f5172182fc970a5b21c0e7"
	hash85 = "c17122a9864e3bbf622285c4d5503282"
	hash86 = "f9e3a9636b45edbcef2ee28bd6b1cfbb"
	hash87 = "291ff8b46d417691a83c73a9d3a30cc9"
	hash88 = "1217877d3f7824165bb28281ccc80182"
	hash89 = "18419d775652f47a657c5400d4aef4a3"
	hash90 = "04417923bf4f2be48dd567dfd33684e2"
	hash91 = "31efe902ec6a5ab9e6876cfe715d7c84"
	hash92 = "a2e4472c5097d7433b91d65579711664"
	hash93 = "98854d7aba1874c39636ff3b703a1ed1"
	hash94 = "5149f0e0a56b33e7bbed1457aab8763f"
	hash95 = "7a4338193ce12529d6ae5cfcbb1019af"
	hash96 = "aa7f37206aba3cbe5e11d336424c549a"
	hash97 = "51cad5d45cdbc2940a66d044d5a8dabf"
	hash98 = "85edb7b8dee5b60e3ce32e1286207faa"
	hash99 = "34ca5292ae56fea78ba14abe8fe11f06"
	hash100 = "154187f07621a9213d77a18c0758960f"
	hash101 = "4e633f0478b993551db22afddfa22262"
	hash102 = "5c50e4427fe178566cada96b2afbc2d4"
	hash103 = "263001ac21ef78c31f4ca7ad2e7f191d"
	hash104 = "53fd9e7500e3522065a2dabb932d9dc5"
	hash105 = "48043dc55718eb9e5b134dac93ebb5f6"
	hash106 = "ca19a1b85363cfed4d36e3e7b990c8b6"
	hash107 = "41b5403a5443a3a84f0007131173c126"
	hash108 = "6f3833bc6e5940155aa804e58500da81"
	hash109 = "9bd50fcfa7ca6e171516101673c4e795"
	hash110 = "6d52ba0d48d5bf3242cd11488c75b9a7"
	hash111 = "c52afb663ff4165e407f53a82e34e1d5"
	hash112 = "5a16396d418355731c6d7bb7b21e05f7"
	hash113 = "05559db924e71cccee87d21b968d0930"
	hash114 = "824312bf8e8e7714616ba62997467fa8"
	hash115 = "dfec435e6264a0bfe47fc5239631903c"
	hash116 = "3512e7da9d66ca62be3418bead2fb091"
	hash117 = "7ad4df88db6f292e7ddeec7cf63fa2bc"
	hash118 = "d512da73d0ca103df3c9e7c074babc99"
	hash119 = "c622b844388c16278d1bc768dcfbbeab"
	hash120 = "170ffa1cd19a1cecc6dae5bdd10efb58"
	hash121 = "3a19c91c1c0baa7dd4a9def2e0b7c3e9"
	hash122 = "3b7ce3ceb8d2b85ab822f355904d47ce"
	hash123 = "a7bac2ace1f04a7ad440bd2f5f811edc"
	hash124 = "66594a62d8c98e1387ec8deb3fe39431"
	hash125 = "a1add9e5d7646584fd4140528d02e4c3"
	hash126 = "11328bbf5a76535e53ab35315321f904"
	hash127 = "048f19d79c953e523675e96fb6e417a9"
	hash128 = "eb65fc2922eafd62defd978a3215814b"
	hash129 = "51cc9987f86a76d75bf335a8864ec250"
	hash130 = "a7f91301712b5a3cc8c3ab9c119530ce"
	hash131 = "de976a5b3d603161a737e7b947fdbb9a"
	hash132 = "288a3659cc1aec47530752b3a31c232b"
	hash133 = "91da679f417040558059ccd5b1063688"
	hash134 = "4ce9a0877b5c6f439f3e90f52eb85398"
	hash135 = "1f9e097ff9724d4384c09748a71ef99d"
	hash136 = "7d8a64a94e71a5c24ad82e8a58f4b7e6"
	hash137 = "db119e3c6b57d9c6b739b0f9cbaeb6fd"
	hash138 = "52c9d25179bf010a4bb20d5b5b4e0615"
	hash139 = "4b9995578d51fb891040a7f159613a99"
	sample_filetype = "exe"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "n:;;t:;;t:;;t:;;t:;;t:;;t:;;t:;;t:;;t:;;t:;;t:;;t:;;t;<<t;<<t;<<t;<<t;<<t;<<t;<<t;<<t<<<t;<<t;<<t;<<"
	$string1 = "t;<<t;<<t<<<t<<"
	$string2 = ">>><<<"
condition:
	2 of them
}

rule screenlocker_acroware {

   meta:

      description = "Rule to detect Acroware ScreenLocker"
      author = "Marc Rivero | @seifreed"
      reference = "https://www.bleepingcomputer.com/news/security/the-week-in-ransomware-august-31st-2018-devs-on-vacation/"
      
   strings:

      $s1 = "C:\\Users\\patri\\Documents\\Visual Studio 2015\\Projects\\Advanced Ransi\\Advanced Ransi\\obj\\Debug\\Advanced Ransi.pdb" fullword ascii
      $s2 = "All your Personal Data got encrypted and the decryption key is stored on a hidden" fullword ascii
      $s3 = "alphaoil@mail2tor.com any try of removing this Ransomware will result in an instantly " fullword ascii
      $s4 = "HKEY_CURRENT_USER\\SoftwareE\\Microsoft\\Windows\\CurrentVersion\\Run" fullword wide
      $s5 = "webserver, after 72 hours the decryption key will get removed and your personal" fullword ascii
      
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB ) and all of them
}



rule locdoor_ransomware {

   meta:

      description = "Rule to detect Locdoor/DryCry"
      author = "Marc Rivero | @seifreed"
      reference = "https://twitter.com/leotpsc/status/1036180615744376832"

   strings:

      $s1 = "copy \"Locdoor.exe\" \"C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\temp00000000.exe\"" fullword ascii
      $s2 = "copy wscript.vbs C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\wscript.vbs" fullword ascii
      $s3 = "!! Your computer's important files have been encrypted! Your computer's important files have been encrypted!" fullword ascii
      $s4 = "echo CreateObject(\"SAPI.SpVoice\").Speak \"Your computer's important files have been encrypted! " fullword ascii    
      $s5 = "! Your computer's important files have been encrypted! " fullword ascii
      $s7 = "This program is not supported on your operating system." fullword ascii
      $s8 = "echo Your computer's files have been encrypted to Locdoor Ransomware! To make a recovery go to localbitcoins.com and create a wa" ascii
      $s9 = "Please enter the password." fullword ascii

   condition:

      ( uint16(0) == 0x5a4d and filesize < 600KB ) and all of them 
}

rule screenlocker_5h311_1nj3c706 {

   meta:

      description = "Rule to detect the screenlocker 5h311_1nj3c706"
      author = "Marc Rivero | @seifreed"
      reference = "https://twitter.com/demonslay335/status/1038060120461266944"

   strings:

      $s1 = "C:\\Users\\Hoang Nam\\source\\repos\\WindowsApp22\\WindowsApp22\\obj\\Debug\\WindowsApp22.pdb" fullword ascii
      $s2 = "cmd.exe /cREG add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\ActiveDesktop /v NoChangingWallPaper /t REG_DWOR" wide
      $s3 = "C:\\Users\\file1.txt" fullword wide
      $s4 = "C:\\Users\\file2.txt" fullword wide
      $s5 = "C:\\Users\\file.txt" fullword wide
      $s6 = " /v Wallpaper /t REG_SZ /d %temp%\\IMG.jpg /f" fullword wide
      $s7 = " /v DisableAntiSpyware /t REG_DWORD /d 1 /f" fullword wide
      $s8 = "All your file has been locked. You must pay money to have a key." fullword wide
      $s9 = "After we receive Bitcoin from you. We will send key to your email." fullword wide
   
   condition:

      ( uint16(0) == 0x5a4d and filesize < 200KB ) and all of them 
}

rule shrug2_ransomware {

   meta:

      description = "Rule to detect Shrug2 ransomware"
      author = "Marc Rivero | @seifreed"
      reference = "https://blogs.quickheal.com/new-net-ransomware-shrug2/"
       
   strings:

      $s1 = "C:\\Users\\Gamer\\Desktop\\Shrug2\\ShrugTwo\\ShrugTwo\\obj\\Debug\\ShrugTwo.pdb" fullword ascii
      $s2 = "http://tempacc11vl.000webhostapp.com/" fullword wide
      $s4 = "Shortcut for @ShrugDecryptor@.exe" fullword wide
      $s5 = "C:\\Users\\" fullword wide
      $s6 = "http://clients3.google.com/generate_204" fullword wide
      $s7 = "\\Desktop\\@ShrugDecryptor@.lnk" fullword wide
   
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB ) and all of them 
}

rule termite_ransomware {

   meta:

      description = "Rule to detect the Termite Ransomware"
      author = "McAfee ATR Team"
      date = "2018-08-28"
      rule_version = "v1"
      malware_type = "ransomware"
      malware_family = "Ransom:W32/Termite"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      reference = "https://www.bleepingcomputer.com/news/security/the-week-in-ransomware-august-31st-2018-devs-on-vacation/"
      hash = "021ca4692d3a721af510f294326a31780d6f8fcd9be2046d1c2a0902a7d58133"
      
   strings:
      
      $s1 = "C:\\Windows\\SysNative\\mswsock.dll" fullword ascii
      $s2 = "C:\\Windows\\SysWOW64\\mswsock.dll" fullword ascii
      $s3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Termite.exe" fullword ascii
      $s4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Payment.exe" fullword ascii
      $s5 = "C:\\Windows\\Termite.exe" fullword ascii
      $s6 = "\\Shell\\Open\\Command\\" fullword ascii
      $s7 = "t314.520@qq.com" fullword ascii
      $s8 = "(*.JPG;*.PNG;*.BMP;*.GIF;*.ICO;*.CUR)|*.JPG;*.PNG;*.BMP;*.GIF;*.ICO;*.CUR|JPG" fullword ascii
      
   condition:
   
      ( uint16(0) == 0x5a4d and
      filesize < 6000KB ) and
      all of them 
}
rule anatova_ransomware {

   meta:

      description = "Rule to detect the Anatova Ransomware"
      author = "Marc Rivero | McAfee ATR Team"
      date = "2019-01-22"
      rule_version = "v1"
      malware_type = "ransomware"
      malware_family = "Ransom:W32/Anatova"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      reference = "https://securingtomorrow.mcafee.com/other-blogs/mcafee-labs/happy-new-year-2019-anatova-is-here/"
      hash = "97fb79ca6fc5d24384bf5ae3d01bf5e77f1d2c0716968681e79c097a7d95fb93"

   strings:

      $regex = /anatova[0-9]@tutanota.com/
        
    condition:

        uint16(0) == 0x5a4d and
        filesize < 2000KB and
        $regex
}


rule Ransom_Babuk {
    meta:
        description = "Rule to detect Babuk Locker"
        author = "TS @ McAfee ATR"
        date = "2021-01-19"
        hash = "e10713a4a5f635767dcd54d609bed977"
        rule_version = "v2"
        malware_family = "Ransom:Win/Babuk"
        malware_type = "Ransom"
        mitre_attack = "T1027, T1083, T1057, T1082, T1129, T1490, T1543.003"

    strings:
        $s1 = {005C0048006F007700200054006F00200052006500730074006F0072006500200059006F00750072002000460069006C00650073002E007400780074}
        //  \ How To Restore Your Files .txt
        $s2 = "delete shadows /all /quiet" fullword wide

        $pattern1 = {006D656D74617300006D65706F63730000736F70686F730000766565616D0000006261636B7570000047785673730000004778426C7200000047784657440000004778435644000000477843494D67720044656657617463680000000063634576744D67720000000063635365744D677200000000536176526F616D005254567363616E0051424643536572766963650051424944505365727669636500000000496E747569742E517569636B426F6F6B732E46435300}
        $pattern2 = {004163725363683253766300004163726F6E69734167656E74000000004341534144324457656253766300000043414152435570646174655376630000730071}
        $pattern3 = {FFB0154000C78584FDFFFFB8154000C78588FDFFFFC0154000C7858CFDFFFFC8154000C78590FDFFFFD0154000C78594FDFFFFD8154000C78598FDFFFFE0154000C7859CFDFFFFE8154000C785A0FDFFFFF0154000C785A4FDFFFFF8154000C785A8FDFFFF00164000C785ACFDFFFF08164000C785B0FDFFFF10164000C785B4FDFFFF18164000C785B8FDFFFF20164000C785BCFDFFFF28164000C785C0FDFFFF30164000C785C4FDFFFF38164000C785C8FDFFFF40164000C785CCFDFFFF48164000C785D0FDFFFF50164000C785D4FDFFFF581640}
        $pattern4 = {400010104000181040002010400028104000301040003810400040104000481040005010400058104000601040006C10400078104000841040008C10400094104000A0104000B0104000C8104000DC104000E8104000F01040000011400008114000181140002411400038114000501140005C11400064114000741140008C114000A8114000C0114000E0114000F4114000101240002812400034124000441240005412400064124000741240008C124000A0124000B8124000D4124000EC1240000C1340002813400054134000741340008C134000A4134000C4134000E8134000FC134000141440003C144000501440006C144000881440009C144000B4144000CC144000E8144000FC144000141540003415400048154000601540007815}
 
    condition:
        filesize >= 15KB and filesize <= 90KB and 
        1 of ($s*) and 3 of ($pattern*) 
}

rule RANSOM_Babuk_Packed_Feb2021 {

    meta:
        description = "Rule to detect Babuk Locker packed"
        author = "McAfee ATR"
        date = "2021-02-19"
        hash = "48e0f7d87fe74a2b61c74f0d32e6a8a5"
        rule_version = "v1"
        malware_family = "Ransom:Win/Babuk"
        malware_type = "Ransom"
        mitre_attack = "T1027.005, T1027, T1083, T1082, T1059, T1129"

    strings:

        // First stage
        $first_stage1 = { 81 ec 30 04 00 00 68 6c 49 43 00 ff 15 74 20 43 00 a3 60 4e f8 02 b8 db d9 2b 00 ba c5 62 8e 76 b9 35 11 5f 39 eb 09 8d a4 24 00 00 00 00 8b ff 89 14 24 89 4c 24 04 81 04 24 25 10 a3 3b 81 04 24 cf e0 fb 07 81 04 24 35 26 9f 42 81 04 24 65 2b 39 06 81 04 24 3c 37 33 5b 81 44 24 04 48 4f c2 5d 83 e8 01 c7 05 54 4e f8 02 00 00 00 00 75 bf 8b 0d 54 aa 43 00 53 8b 1d 58 20 43 00 55 8b 2d 60 20 43 00 56 81 c1 01 24 0a 00 57 8b 3d 50 20 43 00 89 0d 64 4e f8 02 33 f6 eb 03 8d 49 00 81 f9 fc 00 00 00 75 08 6a 00 ff 15 40 20 43 00 6a 00 ff d7 8b 0d 64 4e f8 02 81 f9 7c 0e 00 00 75 19 6a 00 ff d3 6a 00 6a 00 8d 44 24 48 50 6a 00 6a 00 ff d5 8b 0d 64 4e f8 02 81 fe e5 84 c1 09 7e 0a 81 7c 24 2c 0f 11 00 00 75 12 46 8b c6 99 83 fa 14 7c aa 7f 07 3d 30 c1 cf c7 72 a1 51 6a 00 ff 15 2c 20 43 00 8b 0d 08 a4 43 00 33 f6 a3 f4 31 f8 02 89 0d f4 07 fb 02 39 35 64 4e f8 02 76 10 8b c6 e8 56 e4 ff ff 46 3b 35 64 4e f8 02 72 f0 8b 35 80 20 43 00 bf f0 72 e9 00 8b ff 81 3d 64 4e f8 02 4d 09 00 00 75 04 6a 00 ff d6 83 ef 01 75 eb e8 d6 e3 ff ff e8 11 fe ff ff e8 0c e4 ff ff 5f 5e 5d 33 c0 5b 81 c4 30 04 00 00 c3 }
        $first_stage2 = {81ec3??4????68????????ff??????????a3????????b8????????ba????????b9????????eb??891424894c240481????????????81????????????81????????????81????????????81????????????81??????????????83e801c7??????????????????75??8b??????????538b??????????558b??????????5681??????????578b??????????89??????????33f6eb??81??????????75??6a??ff??????????6a??ffd78b??????????81??????????75??6a??ffd36a??6a??8d442448506a??6a??ffd58b??????????81??????????7e??817c242c0f11????75??468bc69983????7c??7f??3d????????72??516a??ff??????????8b??????????33f6a3????????89??????????39??????????76??8bc6e8????????463b??????????72??8b??????????bf????????8bff81??????????????????75??6a??ffd683ef0175??e8????????e8????????e8????????5f5e5d33c05b81c43??4????c3}
        $first_stage3 = {81ec3??4????68????????ff??????????a3????????b8????????ba????????b9????????[2-6]891424894c240481????????????81????????????81????????????81????????????81????????????81??????????????83e801c7??????????????????[2-6]8b??????????538b??????????558b??????????5681??????????578b??????????89??????????33f6[2-6]81??????????[2-6]6a??ff??????????6a??ffd78b??????????81??????????[2-6]6a??ffd36a??6a??8d442448506a??6a??ffd58b??????????81??????????[2-6]817c242c0f11????[2-6]468bc69983????[2-6][2-6]3d????????[2-6]516a??ff??????????8b??????????33f6a3????????89??????????39??????????[2-6]8bc6e8????????463b??????????[2-6]8b??????????bf????????8bff81??????????????????[2-6]6a??ffd683ef01[2-6]e8????????e8????????e8????????5f5e5d33c05b81c43??4????c3}
        $first_stage4 = { 81 EC 30 04 00 00 68 6C 49 43 00 FF 15 ?? ?? ?? ?? A3 ?? ?? ?? ?? B8 DB D9 2B 00 BA C5 62 8E 76 B9 35 11 5F 39 EB ?? 8D A4 24 ?? ?? ?? ?? 8B FF 89 14 24 89 4C 24 ?? 81 04 24 25 10 A3 3B 81 04 24 CF E0 FB 07 81 04 24 35 26 9F 42 81 04 24 65 2B 39 06 81 04 24 3C 37 33 5B 81 44 24 ?? 48 4F C2 5D 83 E8 01 C7 05 ?? ?? ?? ?? 00 00 00 00 75 ?? 8B 0D ?? ?? ?? ?? 53 8B 1D ?? ?? ?? ?? 55 8B 2D ?? ?? ?? ?? 56 81 C1 01 24 0A 00 57 8B 3D ?? ?? ?? ?? 89 0D ?? ?? ?? ?? 33 F6 EB ?? 8D 49 ?? 81 F9 FC 00 00 00 75 ?? 6A 00 FF 15 ?? ?? ?? ?? 6A 00 FF D7 8B 0D ?? ?? ?? ?? 81 F9 7C 0E 00 00 75 ?? 6A 00 FF D3 6A 00 6A 00 8D 44 24 ?? 50 6A 00 6A 00 FF D5 8B 0D ?? ?? ?? ?? 81 FE E5 84 C1 09 7E ?? 81 7C 24 ?? 0F 11 00 00 75 ?? 46 8B C6 99 83 FA 14 7C ?? 7F ?? 3D 30 C1 CF C7 72 ?? 51 6A 00 FF 15 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 33 F6 A3 ?? ?? ?? ?? 89 0D ?? ?? ?? ?? 39 35 ?? ?? ?? ?? 76 ?? 8B C6 E8 ?? ?? ?? ?? 46 3B 35 ?? ?? ?? ?? 72 ?? 8B 35 ?? ?? ?? ?? BF F0 72 E9 00 8B FF 81 3D ?? ?? ?? ?? 4D 09 00 00 75 ?? 6A 00 FF D6 83 EF 01 75 ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 5F 5E 5D 33 C0 5B 81 C4 30 04 00 00 C3}
    
        // Files encryption function 
        $files_encryption1 = { 8a 46 02 c1 e9 02 88 47 02 83 ee 02 83 ef 02 83 f9 08 72 88 fd f3 a5 fc ff 24 95 20 81 40 00 }
        $files_encryption2 = {8a4602c1e90288470283ee0283ef0283????72??fdf3a5fcff????????????}
        $files_encryption3 = { 8A 46 ?? C1 E9 02 88 47 ?? 83 EE 02 83 EF 02 83 F9 08 72 ?? FD F3 A5 FC FF 24 95 ?? ?? ?? ??}

    condition:
        filesize <= 300KB and 
        any of ($first_stage*) and
        any of ($files_encryption*)
}


rule badrabbit_ransomware {
   
   meta:

      description = "Rule to detect Bad Rabbit Ransomware"
      author = "Marc Rivero | McAfee ATR Team"
      rule_version = "v1"
      malware_type = "ransomware"
      malware_family = "Ransom:W32/BadRabbit"
      actor_type = "Cybercrime"
      actor_group = "Unknown" 
      reference = "https://securelist.com/bad-rabbit-ransomware/82851/"

   strings:
   
      $s1 = "schtasks /Create /RU SYSTEM /SC ONSTART /TN rhaegal /TR \"%ws /C Start \\\"\\\" \\\"%wsdispci.exe\\\" -id %u && exit\"" fullword wide
      $s2 = "C:\\Windows\\System32\\rundll32.exe \"C:\\Windows\\" fullword wide
      $s3 = "process call create \"C:\\Windows\\System32\\rundll32.exe" fullword wide
      $s4 = "need to do is submit the payment and get the decryption password." fullword wide
      $s5 = "schtasks /Create /SC once /TN drogon /RU SYSTEM /TR \"%ws\" /ST %02d:%02d:00" fullword wide
      $s6 = "rundll32 %s,#2 %s" fullword ascii
      $s7 = " \\\"C:\\Windows\\%s\\\" #1 " fullword wide
      $s8 = "Readme.txt" fullword wide
      $s9 = "wbem\\wmic.exe" fullword wide
      $s10 = "SYSTEM\\CurrentControlSet\\services\\%ws" fullword wide

      $og1 = { 39 74 24 34 74 0a 39 74 24 20 0f 84 9f }
      $og2 = { 74 0c c7 46 18 98 dd 00 10 e9 34 f0 ff ff 8b 43 }
      $og3 = { 8b 3d 34 d0 00 10 8d 44 24 28 50 6a 04 8d 44 24 }

      $oh1 = { 39 5d fc 0f 84 03 01 00 00 89 45 c8 6a 34 8d 45 }
      $oh2 = { e8 14 13 00 00 b8 ff ff ff 7f eb 5b 8b 4d 0c 85 }
      $oh3 = { e8 7b ec ff ff 59 59 8b 75 08 8d 34 f5 48 b9 40 }

      $oj4 = { e8 30 14 00 00 b8 ff ff ff 7f 48 83 c4 28 c3 48 }
      $oj5 = { ff d0 48 89 45 e0 48 85 c0 0f 84 68 ff ff ff 4c }
      $oj6 = { 85 db 75 09 48 8b 0e ff 15 34 8f 00 00 48 8b 6c }

      $ok1 = { 74 0c c7 46 18 c8 4a 40 00 e9 34 f0 ff ff 8b 43 }
      $ok2 = { 68 f8 6c 40 00 8d 95 e4 f9 ff ff 52 ff 15 34 40 }
      $ok3 = { e9 ef 05 00 00 6a 10 58 3b f8 73 30 8b 45 f8 85 }


   condition:

      uint16(0) == 0x5a4d and
      filesize < 1000KB and
      (all of ($s*) and
      all of ($og*)) or
      all of ($oh*) or
      all of ($oj*) or
      all of ($ok*)
}

rule bitpaymer_ransomware {
   
   meta:
   
      description = "Rule to detect BitPaymer Ransomware"
      author = "Marc Rivero | McAfee ATR Team"
      date = "2019-11-08"
      rule_version = "v1"
      malware_type = "ransomware"
      malware_family = "Ransom:W32/BitPaymer"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      reference = "https://www.mcafee.com/blogs/other-blogs/mcafee-labs/spanish-mssp-targeted-by-bitpaymer-ransomware/"
        
   strings:

      $s1 = "IEncrypt.dll" fullword wide
      $op0 = { e8 5f f3 ff ff ff b6 e0 }
      $op1 = { e8 ad e3 ff ff 59 59 8b 75 08 8d 34 f5 38 eb 42 }
      $op2 = { e9 45 ff ff ff 33 ff 8b 75 0c 6a 04 e8 c1 d1 ff }

      $pdb = "S:\\Work\\_bin\\Release-Win32\\wp_encrypt.pdb" fullword ascii
      $oj0 = { 39 74 24 34 75 53 8d 4c 24 18 e8 b8 d1 ff ff ba }
      $oj1 = { 5f 8b c6 5e c2 08 00 56 8b f1 8d 4e 34 e8 91 af }
      $oj2 = { 8b cb 8d bd 50 ff ff ff 8b c1 89 5f 04 99 83 c1 }

      $t1 = ".C:\\aaa_TouchMeNot_.txt" fullword wide
      $ok0 = { e8 b5 34 00 00 ff 74 24 18 8d 4c 24 54 e8 80 39 }
      $ok1 = { 8b 5d 04 33 ff 8b 44 24 34 89 44 24 5c 85 db 7e }
      $ok2 = { 55 55 ff 74 24 20 8d 4c 24 34 e8 31 bf 00 00 55 }

      $random = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+" fullword ascii
      $oi0 = { a1 04 30 ac 00 8b ce 0f af c2 03 c0 99 8b e8 89 }
      $oi1 = { e8 64 a2 ff ff 85 c0 74 0c 8d 4d d8 51 ff 35 64 }
      $oi2 = { c7 03 d4 21 ac 00 e8 86 53 00 00 89 73 10 89 7b }
      $ou0 = { e8 64 a2 ff ff 85 c0 74 0c 8d 4d d8 51 ff 35 60 }
      $ou1 = { a1 04 30 04 00 8b ce 0f af c2 03 c0 99 8b e8 89 }
      $ou2 = { 8d 4c 24 10 e8 a0 da ff ff 68 d0 21 04 00 8d 4c }
      $oa1 = { 56 52 ba 00 10 0c 00 8b f1 e8 28 63 00 00 8b c6 }
      $oa2 = { 81 3d 50 30 0c 00 53 c6 d2 43 56 8b f1 75 23 ba }
      $oy0 = { c7 06 cc 21 a6 00 c7 46 08 }
      $oy1 = { c7 06 cc 21 a6 00 c7 46 08 }
      $oy2 = { c7 06 cc 21 a6 00 c7 46 08 }
      $oh1 = { e8 74 37 00 00 a3 00 30 fe 00 8d 4c 24 1c 8d 84 }
      $oh2 = { 56 52 ba 00 10 fe 00 8b f1 e8 28 63 00 00 8b c6 }

   condition:

      (uint16(0) == 0x5a4d and
      filesize < 1000KB) and
      ($s1 and
      all of ($op*)) or
      ($pdb and
      all of ($oj*)) or
      ($t1 and
      all of ($ok*)) or
      ($random and
      all of ($oi*)) or
      ($random and
      all of ($ou*)) or
      ($random and
      all of ($oa*) and
      $ou0) or
      ($random and
      all of ($oy*)) or
      ($random and
      all of ($oh*)) or
      ($random and
      $ou0) or
      ($random and
      $oi1)
}

rule BlackMatter
{
    /*
    Rule to detect first version of BlackMatter
    */
    meta:
        author = "ATR McAfee"
    
    strings:
        $a = { 30 26 46 4B 85 DB 75 02 EB 15 C1 E8 10 30 06 46 4B 85 DB 75 02 EB 08 30 26 46 4B 85 DB 75 C8 }
    condition:
        uint16(0) == 0x5A4D and $a
}

rule buran_ransomware {
      
      meta:

            description = "Rule to detect Buran ransomware"
            author = "Marc Rivero | McAfee ATR Team"
            date = "2019-11-05"
            rule_version = "v1"
            malware_type = "ransomware"
            malware_family = "Ransom:W32/Buran"
            actor_type = "Cybercrime"
            actor_group = "Unknown"
            reference = "https://www.mcafee.com/blogs/other-blogs/mcafee-labs/buran-ransomware-the-evolution-of-vegalocker/"
            
      strings:

            $s1 = { 5? 8B ?? 81 C? ?? ?? ?? ?? 5? 5? 5? 33 ?? 89 ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 89 ?? ?? 89 ?? ?? 89 ?? ?? 89 ?? ?? 89 ?? ?? 89 ?? ?? 89 ?? ?? 8D ?? ?? E8 ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 ?? 5? 68 ?? ?? ?? ?? 64 ?? ?? 64 ?? ?? C6 ?? ?? ?? ?? ?? ?? 33 ?? 5? 68 ?? ?? ?? ?? 64 ?? ?? 64 ?? ?? 8D ?? ?? ?? ?? ?? BA ?? ?? ?? ?? 8B ?? ?? E8 ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 6A ?? 8B ?? ?? E8 ?? ?? ?? ?? 5? E8 ?? ?? ?? ?? 8B ?? ?? E8 ?? ?? ?? ?? 84 ?? 0F 85 }
            $s2 = { 4? 33 ?? 8D ?? ?? 0F B6 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? FF 7? ?? 8D ?? ?? 8B ?? ?? 8B ?? ?? 8B ?? 8B ?? FF 5? ?? FF 7? ?? 8D ?? ?? 0F B6 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? FF 7? ?? 8D ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B ?? ?? 5? 8D ?? ?? 0F B6 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? FF 7? ?? 8D ?? ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B ?? ?? 8D ?? ?? E8 ?? ?? ?? ?? 8D ?? ?? 8B ?? ?? E8 ?? ?? ?? ?? 8B ?? ?? 8D ?? ?? E8 ?? ?? ?? ?? 8B ?? ?? 8D ?? ?? E8 ?? ?? ?? ?? 8B ?? ?? 8D ?? ?? E8 ?? ?? ?? ?? FF 7? ?? 8D ?? ?? 0F B6 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? FF 7? ?? 8D ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B ?? ?? 5? E8 ?? ?? ?? ?? 85 ?? 74 }
            $s3 = { A1 ?? ?? ?? ?? 99 5? 5? A1 ?? ?? ?? ?? 99 5? 5? 8B ?? ?? 8B ?? ?? ?? 8B ?? ?? E8 ?? ?? ?? ?? 5? 5? 8B ?? ?? 8B ?? ?? ?? 8B ?? ?? ?? 03 ?? ?? 13 ?? ?? ?? 83 ?? ?? E8 ?? ?? ?? ?? 5? 5? 8B ?? ?? 8B ?? ?? ?? 8B ?? ?? ?? 03 ?? ?? 13 ?? ?? ?? 83 ?? ?? 89 ?? ?? 89 ?? ?? A1 ?? ?? ?? ?? 99 5? 5? 8B ?? ?? 8B ?? ?? 8B ?? ?? ?? 8B ?? ?? ?? E8 ?? ?? ?? ?? 8B ?? ?? 8B ?? ?? 03 ?? ?? ?? 13 ?? ?? ?? 89 ?? ?? 89 ?? ?? A1 ?? ?? ?? ?? 4? 99 89 ?? ?? 89 ?? ?? FF 7? ?? FF 7? ?? 8B ?? ?? 8B ?? ?? E8 ?? ?? ?? ?? 3B ?? ?? 75 }
            $s4 = { 5? 5? 5? 5? 8B ?? 33 ?? 5? 68 ?? ?? ?? ?? 64 ?? ?? 64 ?? ?? 68 ?? ?? ?? ?? 8D ?? ?? E8 ?? ?? ?? ?? 8B ?? ?? B2 ?? A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B ?? 89 ?? ?? 8D ?? ?? A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B ?? ?? 8B ?? ?? E8 ?? ?? ?? ?? 8D ?? ?? A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B ?? ?? 8B ?? ?? 8B ?? ?? E8 ?? ?? ?? ?? 8D ?? ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B ?? ?? 8D ?? ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D ?? ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B ?? ?? 8D ?? ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 ?? ?? ?? 0F 84 }
            $s5 = { 5? 8B ?? 83 ?? ?? 5? 5? 5? 89 ?? ?? 8B ?? 89 ?? ?? 8B ?? ?? 8B ?? ?? 8B ?? ?? 8B ?? ?? ?? 8B ?? ?? ?? 83 ?? ?? 83 ?? ?? 5? 5? A1 ?? ?? ?? ?? 99 E8 ?? ?? ?? ?? 89 ?? ?? E8 ?? ?? ?? ?? 89 ?? ?? E8 ?? ?? ?? ?? 89 ?? ?? 8B ?? 8B ?? ?? 8B ?? ?? E8 ?? ?? ?? ?? 8D ?? ?? 8B ?? ?? 8B ?? E8 ?? ?? ?? ?? 8B ?? ?? 8B ?? E8 ?? ?? ?? ?? 8B ?? ?? 2B ?? 8B ?? 4? 5? 8B ?? ?? 8B ?? 83 ?? ?? B9 ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 ?? ?? 83 ?? ?? 0F 8C }
            
      condition:

           uint16(0) == 0x5a4d and
           all of them
}


rule clop_ransom_note {

   meta:

      description = "Rule to detect Clop Ransomware Note"
      author = "Marc Rivero | McAfee ATR Team"
      date = "2019-08-01"
      rule_version = "v1"
      malware_type = "ransomware"
      malware_family = "Ransom:W32/Clop"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      reference = "https://www.mcafee.com/blogs/other-blogs/mcafee-labs/clop-ransomware/"
      
   strings:

      $s1 = "If you want to restore your files write to emails" fullword ascii
      $s2 = "All files on each host in the network have been encrypted with a strong algorithm." fullword ascii
      $s3 = "Shadow copies also removed, so F8 or any other methods may damage encrypted data but not recover." fullword ascii
      $s4 = "You will receive decrypted samples and our conditions how to get the decoder." fullword ascii
      $s5 = "DO NOT RENAME OR MOVE the encrypted and readme files." fullword ascii
      $s6 = "(Less than 6 Mb each, non-archived and your files should not contain valuable information" fullword ascii
      $s7 = "We exclusively have decryption software for your situation" fullword ascii
      $s8 = "Do not rename encrypted files." fullword ascii
      $s9 = "DO NOT DELETE readme files." fullword ascii
      $s10 = "Nothing personal just business" fullword ascii
      $s11 = "eqaltech.su" fullword ascii

   condition:

      ( uint16(0) == 0x6f59) and 
      filesize < 10KB and
      all of them
}

rule RANSOM_Darkside
{
    meta:
    
        description = "Rule to detect packed and unpacked samples of DarkSide"
        author = "Marc Rivero | McAfee ATR Team"
        date = "2020-08-11"
        rule_version = "v1"
        malware_type = "ransomware"
        malware_family = "Ransom:W32/DarkSide"
        actor_type = "Cybercrime"
        actor_group = "Unknown"
        hash1 = "9cee5522a7ca2bfca7cd3d9daba23e9a30deb6205f56c12045839075f7627297"
    
    strings:

        $pattern_0 = { CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC558BEC5053515256570FEFC0660FEFC033DB8B7D088B450C33D2B910000000F7F185C0740B0F110783C7104885C075F585D27502EB5892B908000000F7F185C0740B0F7F0783C7084885C075F585D27502EB3B92B904000000F7F185C0740A891F83C7044885C075F685D27502EB1F92B902000000F7F185C0740B66891F83C7024885C075F585D27502EB02881F5F5E5A595B585DC20800558BEC5053515256578B750C8B7D088B451033D2B910000000F7F185C074110F10060F110783C61083C7104885C075EF85D27502EB6892B908000000F7F185C074110F6F060F7F0783C60883C7084885C075EF85D27502EB4592B904000000F7F185C0740F8B1E891F83C60483C7044885C075F185D27502EB2492B902000000F7F185C0740E66891F83C60283C7024885C075F285D27502EB048A1E881F5F5E5A595B585DC20C00558BEC53515256578B4D0C8B75088B7D1033C033DBAC8AD8C0E80480E30F3C0072063C09770204303C0A72063C0F7702045780FB00720880FB09770380C33080FB0A720880FB0F770380C35766AB8AC366AB4985C975BE6633C066AB5F5E5A595B5DC20C00558BEC53515256578B75088B7D0C55FCB2808A0683C601880783C701BB0200000002D275058A164612D273E602D275058A164612D2734F33C002D275058A164612D20F83DB00000002D275058A164612D213C002D275058A164612D213C002D275058A164612D213C002D275058A164612D213C074068BDF2BD88A03880747BB02000000EB9BB80100000002D275058A164612D213C002D275058A164612D272EA2BC3BB010000007528B90100000002D275058A164612D213C902D275058A164612D272EA568BF72BF5F3A45EE94FFFFFFF48C1E0088A06468BE8B90100000002D275058A164612D213C902D275058A164612D272EA3D007D000083D9FF3D0005000083D9FF3D8000000083D1003D8000000083D100568BF72BF0F3A45EE9FEFEFFFF8A064633C9C0E801741783D1028BE8568BF72BF0F3A45EBB01000000E9DDFEFFFF5D2B7D0C8BC75F5E5A595B5DC20800558BEC53515256578B7D088B450CB9FF00000033D2F7F185C074188BD868FF00000057E8AD00000081C7FF0000004B85DB75EA85D274075257E8970000005F5E5A595B5DC20800558BEC5351525657B9F0000000BEB2B640008B45088B108B58048B78088B400C89540E0C89440E08895C0E04893C0E81EA101010102D1010101081EB1010101081EF1010101083E91079D533D233C98B750C33DB8B7D108A81B2B6400002141E02D08AA2B2B64000438882B2B6400088A1B2B640003BDF7306FEC175DAEB0633DBFEC175D25F5E5A595B5DC20C00558BEC535152565733C0A3C2B84000A3C6B84000B9400000008D35B2B640008D3DB2B74000F3A58B7D088B15C2B840008B4D0C8B1DC6B840004F33C0029AB3B740008A82B3B740008AABB2B740008883B2B7400088AAB3B7400002C5478A80B2B74000FEC23007FEC975D18915C2B84000891DC6B840005F5E5A595B5DC2080053515256578D35047040008D3DCAB84000FF76FC56E891FEFFFF56E8864500008BD8FF76FC56E888FBFFFF8B46FC8D3406B915000000E85C010000AD5056E868FEFFFF56E85D4500008BD8FF76FC56E85FFBFFFF8B46FC8D3406B93D000000E833010000AD5056E83FFEFFFF5256E8334500008BD85AFF76FC56E834FBFFFF8B46FC8D3406B915000000E808010000AD5056E814FEFFFF5256E8084500008BD85AFF76FC56E809FBFFFF8B46FC8D3406B904000000E8DD000000AD5056E8E9FDFFFF5256E8DD4400008BD85AFF76FC56E8DEFAFFFF8B46FC8D3406B906000000E8B2000000AD5056E8BEFDFFFF5256E8B24400008BD85AFF76FC56E8B3FAFFFF8B46FC8D3406B901000000E887000000AD5056E893FDFFFF5256E8874400008BD85AFF76FC56E888FAFFFF8B46FC8D3406B903000000E85C000000AD5056E868FDFFFF5256E85C4400008BD85AFF76FC56E85DFAFFFF8B46FC8D3406B901000000E831000000AD5056E83DFDFFFF5256E8314400008BD85AFF76FC56E832FAFFFF8B46FC8D3406B902000000E8060000005F5E5A595BC3ADFF76FC56E80AFDFFFF515653E8F743000059ABFF76FC56E8FFF9FFFF8B46FC8D34064985C975D8C3558BEC81EC1401000053515256578D85ECFEFFFF50FF1516B940008BB5F0FEFFFF8BBDF4FEFFFF83FE05750583FF01720583FE057313B8000000005F5E5A595B8BE55DC3E9DA00000083FE05751883FF017513B8330000005F5E5A595B8BE55DC3E9BD00000083FE05751883FF027513B8340000005F5E5A595B8BE55DC3E9A000000083FE06751785FF7513B83C0000005F5E5A595B8BE55DC3E98400000083FE06751583FF017510B83D0000005F5E5A595B8BE55DC3EB6A83FE06751583FF027510B83E0000005F5E5A595B8BE55DC3EB5083FE06751583FF037510B83F0000005F5E5A595B8BE55DC3EB3683FE0A751485FF7510B8640000005F5E5A595B8BE55DC3EB1D83FE0A750583FF00770583FE0A760EB8FFFFFF7F5F5E5A595B8BE55DC3B8FFFFFFFF5F5E5A595B8BE55DC3558BEC83C4F853515256576A0068800000006A026A006A006800000040FF7508FF1526B940008945FC837DFCFF74226A008D45F850FF7510FF750CFF75FCFF1536B9400085C07409FF75FCFF153EB940005F5E5A595B8BE55DC20C008BFF558BEC5351525657837D0C0074728D3DAABA4000837D100075086A1057E842F8FFFFFF750CFF750868EFBEADDEFF15F6B84000FF750CFF750850FF15F6B840003107FF750CFF750850FF15F6B84000314704FF750CFF750850FF15F6B84000314708FF750CFF750850FF15F6B8400031470CB8AABA40005F5E5A595B5DC20C00B8000000005F5E5A595B5DC20C00558BEC5351525657FF7508FF15DEB8400083C4048BD88D045D02000000506A00FF35AEB64000FF15BEB940008BF085F67434FF750856FF15CEB8400083C4088D43016A006A0050FF75086AFF566A006A00FF1506BA4000566A00FF35AEB64000FF15C6B940008BC35F5E5A595B5DC2040053515657833DBABA400000750B68BABA4000FF15F2B8400068BABA4000FF15F2B840008BD15F5E595BC3558BEC5351525657BB080000008B7508E8C1FFFFFF83FB05750433C033D28944DEFC8954DEF84B85DB75E55F5E5A595B5DC204008D4000558BEC81EC0001000053515256578D45B083C00F83E0F089850CFFFFFF8D8560FFFFFF83C00F83E0F0898508FFFFFF8D8510FFFFFF83C00F83E0F0898504FFFFFF837D14000F84750300008BB504FFFFFF0F57C00F11060F1146100F1146200F1146308B75088BBD0CFFFFFF0F10060F104E100F1056200F105E300F11070F114F100F1157200F115F30837D1440732A8B4510898500FFFFFF8B9504FFFFFF8BFA8B750C8B4D148A440EFF88440FFF4985C975F389550C8955108BB50CFFFFFF8BBD08FFFFFF0F10060F104E100F1056200F105E300F11070F114F100F1157200F115F305556BD0A0000008B078B5F108B4F208B57308BF003F2C1C60733DE8BF303F0C1C60933CE8BF103F3C1C60D33D68BF203F1C1C61233C68907895F10894F208957308B47148B5F248B4F348B57048BF003F2C1C60733DE8BF303F0C1C60933CE8BF103F3C1C60D33D68BF203F1C1C61233C6894714895F24894F348957048B47288B5F388B4F088B57188BF003F2C1C60733DE8BF303F0C1C60933CE8BF103F3C1C60D33D68BF203F1C1C61233C6894728895F38894F088957188B473C8B5F0C8B4F1C8B572C8BF003F2C1C60733DE8BF303F0C1C60933CE8BF103F3C1C60D33D68BF203F1C1C61233C689473C }
        $pattern_1 = { 70211F3B6E97C50000473D000000A000004602003EBBFF1F92CC558BEC5053515256570FEFC0660333DBFBFFEDFF8B7D088B450C33D2B9100000F7F185C0740B0F110783C710480A692EFB7F75F585D27502EB5892B9081C7F08B60F592E3B040A891F38049B641979F61F02661CD6FEBFEC023802881F5F5E5A595B585DC25D977E20634F8B750C9110110F1006252383FD94C61097EF6819AC59BA226F7F089DEFD8EE0119450F8B1E82C604A23E033232F1240EC602B9EC91C1A5F2048A1EA70CA12CCBD9A64D757D42E9FEFFBFAC8AD8C0E80480E30F3C0072063C09770204303C0A090FB66F6DBB5780FB140804150380C3300C0ADADFFE790F5766AB8AC3034985C975BE6646FF252CD6096564610C55FCB2806FDF86DB8A069701887801BBAD0299058A164FD62EFB4612D273E60A4F430C0F83DB7F2A7B602613C00A74068BDF2BD821EC63DB8A03644762EB9BB80142900BFBFB72EA2BC3BB1C7528B923C96F7FFB1F568BF72BF5F3A45EE94D01D248C1E008C3468BE8DE1EC26E0C0449303D007D4B83D9FF0DD93CD907058000D100BDB01BF250F04C33C974017417B1D8B0B61902561B96204B06E1C25D2B398BC75208111AEE18EDB9FF2660F4F8EFDDF7188BD8680E579B03D981C70B4B85DB75EAEE94CD5EFE7407521546B9F0256F7F6BB7BE02A6B24D50108B58048B7807400C895FF7FFDB540E03440E08895C0E04893C0E81EA10002D048168ED9FB1EB05EF83E91079D57EC0DFFFFDE4EC80108A814A02141E02D08AA20A436BFFBFDF88820688A1053BDF7306FEC175DAEB062C076E0B29A3D227F8A327A8C27DFBEDFE04C6B940998D35378D3D05A7B2F3A57DBC8FF7F31520B41D242A9A1BFB8DDD1CB38A8205AB28888305AA11D88DFFFE02C5478A800EFEC23007FEA0D189402F9684D8893D0D7C6BF07BF8CF6004A8CAFF76FC5630040549FF33FFDBAC59109C0C8B46FC8D3406B9150F477291BD05F0AD50283D52C252D961295A532A02B902BB04550608B902B90103E10843260299C3AD8615B2BF2751565333F959AB329FE0EEF874D8C33F81EC1468C885ECFE7777DFF0FFFF50FF4FA9168BB5F00C8BBDF40583FE055877F74BA483FF017205097313B86D00695BF36DFA8BE55DC36C073C2118751C3300D21C210234DF04D2FD06751785FF1B3C1555109AC11EC8B83DEB6A19023EA419644250033FC866DE2636690A75141864FECDEE4C1DDE00770A760EB8FFFFFF7F1B927C490DFF3083C4AEFD7A84F82D6A0068976A02080AFE8FB07509405A083B268945FC837DFCFF7422916D73DF188D45F85072020C1DFC34ECB0AE3672090C3E59746B43DACC8BFFCE3C0D7472E1AD44FB51AAAA0B04576A1057BC67BF3F16470868EFBEADDE3FA8F6105090BDB0670C31070E47040F92F50EC9080CB8624E071B5913D85CD6A8DE6D1FDF6AF9E4D88D045D6D50DAFF58F78F7D63AEC6BE8BF085F6743429562ADDDCE1CBCE088D430119FDBDFF56B027ECEF0A1AAA065639C68BC37077FB9C630484FAF4BAF10B6807A31DB0B14CF20A8BD12DE09A3871989ABBFD24E84013CB376608A783FB048DD2D90317B87FDEFC87DEF8C4E55D49C628308D17EE000DC32FF145B083C027E0F089850CE3FD202387B960051108102B99FE37040B7D14000F8475C41E0FA6DBC5F60F571C119846100320ED17EF8930B1BD4EB0104E17D32CDBCB1056105E3026074F57CDE6E26E5F304840732AE457008B6FF017BF954D8BFAFB4D148A3FFF88447B6DFBD30FFFA3F389550C02106E5359FDF0A964085556BD0A14078B5F6FFFDFBE354F208B5792F003F2C1C60733DE8BF303F0080933CEED2FFFF28BF103F30D33D68BF203F11233C68907892ECBB26D96898947143A243404CBD612202F3B24342CCBB22C0428380818CBB25C802838081820CBB22C3C0C1C2CDFB22C173C0C1C2CED0463476063760CED04750C53606363ED187510ED18D80863637510ED2C6424ED3036C2142C6524ED30234C818D6538ED3065386DA30DFC4D85ED0F851B975E5DF30702CBE5726BC80357105F1867206FB6022F972877307F380F0C024EE572B9DC1EFE56FE5EFE66FE6EA6D996CBFE76FE7E7F3D7F7F94A6699A7F7F7F7F7F9AE5C8708D6B5757575D8C966B57BED8FE2011BFE4B834118B9DA7274320837B2086F1B195000824E977EF1866C335DB32C500E4B2BD154E8B55BA338942200524B5655BFA24EB16831940030C6D370297C0237485CAFC86C21297EE1A818880308D7D80F3B920B16FE21DF2F3ABB900DF518D7580F810CD33E7FED1168D7604E2F92175128B06194DA6ECED078D7F17F473181911C9600933C441290CD5BB0A5B5B59F033E476B05505E00CEDAA9BBDB266E03AA5D908A6BFB960DDDFFCDD4FE0C64580018BA98F7EF05D0C81C379B981A849B1BE07D84150F8510851FC8DAB8360115F547B8D626FADBB1D508D3B50E874D3815240D3E0BF6563F02203740F9908199BBB4B1961646306AE9B780C830627307DC7E63041B73BDB06F8410ECB8A369391B8D51A68A41F000B8278E2C406CE1F0926023676729008AA12F80C1A24446B4B22170E54206317F226F8C37EF45B18B8C3F8EF238B71C65E4E62F475F8F46A0514066C737F01CE04EB43EB3F3D310A1B1CB5D84CD837C2EBC60D2C5A839117A1C12C4468F7BBA5196AD2C86AD6616CDBD8288E2E33ED3CAD1D14C3999178FF733C02CA74D72E71A1A14402EBFC1C332275D4565858CA5D4F846D35570F06E6AC62895FE9BF454B183B480875278D1F30AABEC220586C3BEA0F2C3A0E186BD5E850C63826070017E40793C5F30C0262CC0D776B110D6F68081017F4FDDD58B2C77568040110976256A3D8B3C4B2CC11D3D23DE2DB4636F677FC57FB571F34102048BC03A1088DA3ADD5456CD8C2BE227A30C3A3B18D922A9B1C2C6A9BDB095B62106E38E18B5E12C37BD86CB0403753132F6E56A573B367B10FBC59A8EE97CD409E848530675464A1183064849F924030C31A2C72E1248313F88D1DCF6C125B166CECFC53EC531BB519E4027936286BC0D263936C0F6A245FD4C70B24B15766738C09E89B4A2C585392A89C53325426816407AA7E5111040C8D9913E810EF52A937B527344930AA660C5E017648727CC960E3F07304ADA50B27ACDB8F2D60F0B5833EAF15107A641F05D019EBCCCBACDD2578763D4FA9744A4A0FFC0618E9E3147A6517C1293AECB517D9F88B122E0146336C2CD67D7C5224760B1D0E08506FC8096E7ACA96504FB6B1B1463FD3A6521911F424E1FC5A0142A91AD9A722EC3EEE6B18B26B1C3D7DB1D75EAFFC8D7531831C8535BF8E68EB803FAA5219367958D984534FBE3C1B690664B0B03CCC09209966A401B44050C83336C9ECA29D0004D88465B109215A244576CF58C96AF0346AF4AE9D3DB360BC0E3989C005A9247508F153A7A564036F644553F675A3D4253BAC3956120C5AEBE66EC682D922722568F4C058B36FD730DAEDB57D14450DAA0BD716168151969EAE69921D76C8D85E08626E130C9C11C00D07C160C7846481EDFF72C8A1BDE3DF9F813C18DEADBEEF980340EBF2C631F9EC4E04136DA456A4A1FC8EAC7E73C8C1E0068BD82373CCBB46C6DE01B16A1630408086A44CB2810B2C2F3616500A17F3DE5F0BAB8EAEA556561FFBE5B2F6150A374D358D83E6070A67B303593A5A56223D5A89E4C8254EB60FE492B3D95E56223D5E4FD9EC447286176256223D223972C96250561FB9E46C766656223D6641363B911C26276A56223D488E5C726A51F62E72362B90C7223D6E9D488E5C52C6367256472E399B223D724B963E9CCD4E247656223D7627922397537E427A56964BCE66223D7A545890672269727E72CCA759E47E0AC8A912678203C11A01B23557FBC2E08A53D968243106BE91ACB86472A8C319698152773D833C038C907C420BB3345B061008091C095EE251887010EBDE251B5A160CE0FD66B80904A10B9566ABE74C161266A4D19EE614ECA72DE3F8DC0F84A129461DF421D89E3DE828139F83DA062D4FEEF350ECD3AEFCF6EB6399F833D285D255B390DB6BFDC90530940107A842EB14BB162E2CC12B8B1BD4CB4D33C9192BFFAE400830040E4183F9080E04AC5F713904576A57014C7042E2C8681122C63664F381D8ED9E70B470B8182C883DA58E0EFFE62C080B5B180C256C469348D2C1B408AC1CEC840704300A44AA0EBBB6044381DC0C4BA62EEA1D487CDA4AE10E58D4DC194871F43A5F5DB37064FBF086F034798B83C9A26B096057B0571E7F83172666FD47FE5CFA66C704475C00D565F15702444702D9EB3D62598B151A11EA0B3531B614F06592BA0E46348A5D3932DAC81B1A386C90410C03802C26E0B1CCCD19502B1B035C4379AA3ACD09D534968523BBEB6953CCECBFEC511DB68B27C8F4CB75EC39326FD94ED2820BEB1E27F41821E12E7548293B02750759AC12C23B9616FF57C6082997A5EC1C846C4EC80C6D026D0630968DE46D06251CA43358A41AF84F9CD06CEBA91B5C107EDA562CE1F7C049A5AE83702B0CCB523367A364CD46000B08DD35AD8C91877A08E63C5798CC25C3AC9C86AD927DC615A3A3DC53E7CA217946B6431A1010E864489E911414F0183891906718F8A44D6148561EEBA0D3363ACC9DD08BC8C45110BA36D092BA42CE140510960626A37C49D0736C658C67F0524156E89E609103 }
   
    condition:

        $pattern_0 or $pattern_1 and filesize < 5831344
}

rule RANSOM_Darkside_DLL_May2021 {
    meta:
        description = "Rule to detect Darkside Ransomware as a DLL"
        author = "TS @ McAfee ATR"
        date = "2021-05-14"
        rule_type = "Public"
        rule_version = "v1"
        malware_type = "Ransom"
        hash = "f587adbd83ff3f4d2985453cd45c7ab1"
    strings:
        $s1 = "encryptor2.dll" wide ascii
        $s2 = "DisableThreadLibraryCalls" wide ascii
        $s3 = "KERNEL32.dll" wide ascii
        $pattern1 = {D24DC8855EDD487B3CD2D545F11031E1FA85C2F2440712445F67D105B326533A77BA75B3383A98CE97EAA2B95798DCFA6B75B5573662F9ED5DC9B7D2E582FD94104E210F3EA62A1826B26B952FFBD5A70A97E6EC3D14794577A2980A0ED1EE02CA291623DD3721A7E68223EDA56F9E1325FE36E191D5C41F7227D55EDC3D5B9359C819}
        $pattern2 = {87FC982E066F585B73D417C0D5F75B86B9F9F8286B4CC42BB2053912D595A68C07C0EDD0159AC785880C5483E246D3501F6523D05078B9B7510711423948D4CB367C83C0833BD04AD6DC655E1BEEA38770470BB48B6EBA70944E952526E4D87A03BAA485D7B4DA1318A00EF07FA76C0D}
        $pattern3 = {1B6F099F1C3C62BBF5543FA03B919C7BF5E477D256CE79D98C55ACE8D69CDC9373B2F0A2B51414776D5226B74BF9A7CB935C9DD04BCFC19FC81418F7A39244A730697E1BC05418BF41DE50E4C8609533591CE80617D476E686B36CF2AE914CB3AFD720A33C0D5DE438F1CD0B}
        $pattern4 = {5060E373F1D3B3BB8D15C851BBFC73F60390681C488F7C0B80FC2EDBC1ED88CEA82014B9223A70EA0BB7DD0D2560A29D39381FEE7B73AE22683AE05C369918F8C5772678A9F29CEF65854238D1C2B762CC12706637154F57A9}
        $pattern5 = {EE452560DBD5A4F46FB562C9C707C8D014BB8F1C18E4467E249F5AC69A87954F5B69650B7A759CE2DD075E99CBCBA37A9C5A0650EDF06285F8F990AF6B94FBA08E3C0B2EBDE3C155ECDB06C30F95D76695}
    condition:
        filesize >= 45KB and filesize <= 70KB and 
        all of ($s*) and 4 of ($pattern*)        
}

rule RANSOM_Exorcist
{
    meta:
       
        description = "Rule to detect Exorcist"
        author = "McAfee ATR Team"
        date = "2020-09-01"
        rule_version = "v1"
        malware_type = "ransomware"
        malware_family = "Ransomware:W32/Exorcist"
        actor_type = "Cybercrime"
        hash1 = "793dcc731fa2c6f7406fd52c7ac43926ac23e39badce09677128cce0192e19b0"
        actor_type = "Cybercrime"
        actor_group = "Unknown"
    
    strings:

        $sq1 = { 48 8B C4 48 89 58 08 48 89 70 10 48 89 78 18 4C 89 60 20 55 41 56 41 57 48 8D 68 A1 48 81 EC 90 00 00 00 49 8B F1 49 8B F8 4C 8B FA 48 8B D9 E8 ?? ?? ?? ?? 45 33 E4 85 C0 0F 85 B1 00 00 00 48 8B D7 48 8B CB E8 9E 02 00 00 85 C0 0F 85 9E 00 00 00 33 D2 48 8B CB E8 ?? ?? ?? ?? 45 33 C0 48 8D 15 ?? ?? ?? ?? 48 8B CB E8 ?? ?? ?? ?? 45 8D 44 24 01 48 8B D7 48 8B C8 E8 ?? ?? ?? ?? 48 8B D0 48 8B CB 48 8B F8 FF 15 ?? ?? ?? ?? 4C 89 64 24 30 45 33 C9 C7 44 24 28 80 00 00 E8 45 33 C0 BA 00 00 00 C0 C7 44 24 20 03 00 00 00 48 8B CF FF 15 ?? ?? ?? ?? 4C 8B F0 48 8D 48 FF 48 83 F9 FD 77 25 48 8D 55 2F 48 8B C8 FF 15 ?? ?? ?? ?? 4C 39 65 2F 75 3B 49 8B CE FF 15 ?? ?? ?? ?? 48 8B CF FF 15 ?? ?? ?? ?? 48 8B CF E8 ?? ?? ?? ?? 4C 8D 9C 24 90 00 00 00 49 8B 5B 20 49 8B 73 28 49 8B 7B 30 4D 8B 63 38 49 8B E3 41 5F 41 5E 5D C3 48 8D 45 FB 4C 89 65 1F 4C 8D 4D FF 48 89 44 24 20 4C 8B C6 4C 89 65 07 48 8D 55 07 4C 89 65 FF 48 8D 4D 1F 44 89 65 FB E8 ?? ?? ?? ?? 45 33 C9 4C 8D 05 3C F5 FF FF 49 8B D7 49 8B CE FF 15 ?? ?? ?? ?? 48 8D 55 17 49 8B CE FF 15 ?? ?? ?? ?? 49 8B CE 44 89 65 F7 E8 ?? ?? ?? ?? 49 8B F4 4C 89 65 0F 4C 39 65 17 0F 8E 9D 00 00 00 C1 E0 10 44 8B F8 F0 FF 45 F7 B9 50 00 00 00 E8 ?? ?? ?? ?? 8B 4D 13 48 8B D8 89 48 14 89 70 10 4C 89 60 18 44 89 60 28 4C 89 70 30 48 8B 4D 07 48 89 48 48 48 8D 45 F7 B9 00 00 01 00 48 89 43 40 E8 ?? ?? ?? ?? 33 D2 48 89 43 20 41 B8 00 00 01 00 48 8B C8 E8 ?? ?? ?? ?? 48 8B 53 20 4C 8D 4B 38 41 B8 00 00 01 00 48 89 5C 24 20 49 8B CE FF 15 ?? ?? ?? ?? EB 08 33 C9 FF 15 ?? ?? ?? ?? 8B 45 F7 3D E8 03 00 00 77 EE 49 03 F7 48 89 75 0F 48 3B 75 17 0F 8C 6B FF FF FF EB 03 8B 45 F7 85 C0 74 0E 33 C9 FF 15 ?? ?? ?? ?? 44 39 65 F7 77 F2 48 8B 4D 07 E8 ?? ?? ?? ?? 48 8B 4D 1F 33 D2 E8 ?? ?? ?? ?? 49 8B CE FF 15 ?? ?? ?? ?? 4C 89 64 24 30 45 33 C9 C7 44 24 28 80 00 00 00 45 33 C0 BA 00 00 00 C0 C7 44 24 20 03 00 00 00 48 8B CF FF 15 ?? ?? ?? ?? 48 8B D8 48 8D 48 FF 48 83 F9 FD 77 51 48 8D 55 37 48 8B C8 FF 15 ?? ?? ?? ?? 48 8B 55 37 45 33 C9 45 33 C0 48 8B CB FF 15 ?? ?? ?? ?? 44 8B 45 FB 4C 8D 4D 27 48 8B 55 FF 48 8B CB 4C 89 64 24 20 FF 15 ?? ?? ?? ?? 48 8B 4D FF E8 ?? ?? ?? ?? 48 8B CB FF 15 ?? ?? ?? ?? E9 14 FE FF FF 48 8B CF E8 ?? ?? ?? ?? 48 8B 4D FF E9 06 FE FF FF }          
        $sq2 = { 48 8B C4 48 81 EC 38 01 00 00 48 8D 50 08 C7 40 08 04 01 00 00 48 8D 4C 24 20 FF 15 ?? ?? ?? ?? 48 8D 4C 24 20 E8 ?? ?? ?? ?? 48 81 C4 38 01 00 00 C3 } 

    condition:

        uint16(0) == 0x5a4d and
         any of them 
}

rule kraken_cryptor_ransomware_loader {

   meta:

      description = "Rule to detect the Kraken Cryptor Ransomware loader"
      author = "Marc Rivero | McAfee ATR Team"
      date = "2018-09-30"
      rule_version = "v1"
      malware_type = "ransomware"
      malware_family = "Ransom:W32/Kraken"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      reference = "https://www.mcafee.com/blogs/other-blogs/mcafee-labs/fallout-exploit-kit-releases-the-kraken-ransomware-on-its-victims/"
      hash = "564154a2e3647318ca40a5ffa68d06b1bd40b606cae1d15985e3d15097b512cd"

   strings:

      $pdb = "C:\\Users\\Krypton\\source\\repos\\UAC\\UAC\\obj\\Release\\UAC.pdb" fullword ascii
      $s2 = "SOFTWARE\\Classes\\mscfile\\shell\\open\\command" fullword wide
      $s3 = "public_key" fullword ascii
      $s4 = "KRAKEN DECRYPTOR" ascii
      $s5 = "UNIQUE KEY" fullword ascii

   condition:

       uint16(0) == 0x5a4d and 
       filesize < 600KB  and 
       $pdb or 
       all of ($s*)
}

rule kraken_cryptor_ransomware {
   
   meta:

      description = "Rule to detect the Kraken Cryptor Ransomware"
      author = "Marc Rivero | McAfee ATR Team"
      date = "2018-09-30"
      rule_version = "v1"
      malware_type = "ransomware"
      malware_family = "Ransom:W32/Kraken"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      reference = "https://www.mcafee.com/blogs/other-blogs/mcafee-labs/fallout-exploit-kit-releases-the-kraken-ransomware-on-its-victims/"
      hash = "564154a2e3647318ca40a5ffa68d06b1bd40b606cae1d15985e3d15097b512cd"

   strings:
     
      $s1 = "Kraken Cryptor" fullword ascii nocase
      $s2 = "support_email" fullword ascii
      $fw1 = "L0MgbmV0c2ggYWR2ZmlyZXdhbGwgZmlyZXdhbGwgYWRkIHJ1bGUgbmFtZT0iU01CIFByb3RvY29sIEJsb2NrIiBwcm90b2NvbD1UQ1AgZGlyPWluIGxvY2FscG9ydD00" ascii 
      $fw2 = "L0MgbmV0c2ggYWR2ZmlyZXdhbGwgZmlyZXdhbGwgYWRkIHJ1bGUgbmFtZT0iUkRQIFByb3RvY29sIEJsb2NrIiBwcm90b2NvbD1UQ1AgZGlyPWluIGxvY2FscG9ydD0z" ascii 
      $fw3 = "L0MgbmV0c2ggYWR2ZmlyZXdhbGwgZmlyZXdhbGwgYWRkIHJ1bGUgbmFtZT0iUkRQIFByb3RvY29sIEJsb2NrIiBwcm90b2NvbD1UQ1AgZGlyPWluIGxvY2FscG9ydD0z" ascii 
      $fw4 = "L0MgbmV0c2ggYWR2ZmlyZXdhbGwgZmlyZXdhbGwgYWRkIHJ1bGUgbmFtZT0iU01CIFByb3RvY29sIEJsb2NrIiBwcm90b2NvbD1UQ1AgZGlyPWluIGxvY2FscG9ydD00" ascii 
      $uac = "<!--<requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\" />-->   " fullword ascii
  
   condition:

      uint16(0) == 0x5a4d and
      filesize < 600KB and
      all of ($fw*) or
      all of ($s*) or
      $uac
}

rule ransom_note_kraken_cryptor_ransomware {
   
   meta:

      description = "Rule to detect the ransom note delivered by Kraken Cryptor Ransomware"
      author = "Marc Rivero | McAfee ATR Team"
      date = "2018-09-30"
      rule_version = "v1"
      malware_type = "ransomware"
      malware_family = "Ransom:W32/Kraken"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      reference = "https://www.mcafee.com/blogs/other-blogs/mcafee-labs/fallout-exploit-kit-releases-the-kraken-ransomware-on-its-victims/"

   strings:

      $s1 = "No way to recovery your files without \"KRAKEN DECRYPTOR\" software and your computer \"UNIQUE KEY\"!" fullword ascii
      $s2 = "Are you want to decrypt all of your encrypted files? If yes! You need to pay for decryption service to us!" fullword ascii
      $s3 = "The speed, power and complexity of this encryption have been high and if you are now viewing this guide." fullword ascii
      $s4 = "Project \"KRAKEN CRYPTOR\" doesn't damage any of your files, this action is reversible if you follow the instructions above." fullword ascii
      $s5 = "https://localBitcoins.com" fullword ascii
      $s6 = "For the decryption service, we also need your \"KRAKEN ENCRYPTED UNIQUE KEY\" you can see this in the top!" fullword ascii
      $s7 = "-----BEGIN KRAKEN ENCRYPTED UNIQUE KEY----- " fullword ascii
      $s8 = "All your files has been encrypted by \"KRAKEN CRYPTOR\"." fullword ascii
      $s9 = "It means that \"KRAKEN CRYPTOR\" immediately removed form your system!" fullword ascii
      $s10 = "After your payment made, all of your encrypted files has been decrypted." fullword ascii
      $s11 = "Don't delete .XKHVE files! there are not virus and are your files, but encrypted!" fullword ascii
      $s12 = "You can decrypt one of your encrypted smaller file for free in the first contact with us." fullword ascii
      $s13 = "You must register on this site and click \"BUY Bitcoins\" then choose your country to find sellers and their prices." fullword ascii
      $s14 = "-----END KRAKEN ENCRYPTED UNIQUE KEY-----" fullword ascii
      $s15 = "DON'T MODIFY \"KRAKEN ENCRYPT UNIQUE KEY\"." fullword ascii
      $s16 = "# Read the following instructions carefully to decrypt your files." fullword ascii
      $s17 = "We use best and easy way to communications. It's email support, you can see our emails below." fullword ascii
      $s18 = "DON'T USE THIRD PARTY, PUBLIC TOOLS/SOFTWARE TO DECRYPT YOUR FILES, THIS CAUSE DAMAGE YOUR FILES PERMANENTLY." fullword ascii
      $s19 = "https://en.wikipedia.org/wiki/Bitcoin" fullword ascii
      $s20 = "Please send your message with same subject to both address." fullword ascii
   
   condition:

      uint16(0) == 0x4120 and
      filesize < 9KB and
      all of them 
}

rule ransom_Linux_HelloKitty_0721 {
   meta:
      description = "rule to detect Linux variant of the Hello Kitty Ransomware"
      author = "Christiaan @ ATR"
      date = "2021-07-19"
      Rule_Version = "v1"
      malware_type = "ransomware"
      malware_family = "Ransom:Linux/HelloKitty"
      hash1 = "ca607e431062ee49a21d69d722750e5edbd8ffabcb54fa92b231814101756041"
      hash2 = "556e5cb5e4e77678110961c8d9260a726a363e00bf8d278e5302cb4bfccc3eed"

   strings:
      $v1 = "esxcli vm process kill -t=force -w=%d" fullword ascii
      $v2 = "esxcli vm process kill -t=hard -w=%d" fullword ascii
      $v3 = "esxcli vm process kill -t=soft -w=%d" fullword ascii
      $v4 = "error encrypt: %s rename back:%s" fullword ascii
      $v5 = "esxcli vm process list" fullword ascii
      $v6 = "Total VM run on host:" fullword ascii
      $v7 = "error lock_exclusively:%s owner pid:%d" fullword ascii
      $v8 = "Error open %s in try_lock_exclusively" fullword ascii
      $v9 = "Mode:%d  Verbose:%d Daemon:%d AESNI:%d RDRAND:%d " fullword ascii
      $v10 = "pthread_cond_signal() error" fullword ascii
      $v11 = "ChaCha20 for x86_64, CRYPTOGAMS by <appro@openssl.org>" fullword ascii

   condition:
      ( uint16(0) == 0x457f and filesize < 200KB and ( 8 of them )
      ) or ( all of them )
}

rule Lockbit2_Jul21 {
   meta:
      description = "simple rule to detect latest Lockbit ransomware Jul 2021"
      author = "CB @ ATR"
      date = "2021-07-28"
      version = "v1"
      hash1 = "f32e9fb8b1ea73f0a71f3edaebb7f2b242e72d2a4826d6b2744ad3d830671202"
      hash2 = "dd8fe3966ab4d2d6215c63b3ac7abf4673d9c19f2d9f35a6bf247922c642ec2d"

   strings:
      $seq1 = " /C ping 127.0.0.7 -n 3 > Nul & fsutil file setZeroData offset=0 length=524288 \"%s\" & Del /f /q \"%s\"" fullword wide
      $seq2 = "\"C:\\Windows\\system32\\mshta.exe\" \"%s\"" fullword wide
      $p1 = "C:\\windows\\system32\\%X%X%X.ico" fullword wide
      $p2 = "\\??\\C:\\windows\\system32\\%X%X%X.ico" fullword wide
      $p3 = "\\Registry\\Machine\\Software\\Classes\\Lockbit\\shell\\Open\\Command" fullword wide
      $p4 = "use ToxID: 3085B89A0C515D2FB124D645906F5D3DA5CB97CEBEA975959AE4F95302A04E1D709C3C4AE9B7" fullword wide
      $p5 = "https://tox.chat/download.html" fullword wide
      $p6 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\ICM\\Calibration" fullword wide
      $p7 = "http://lockbitapt6vx57t3eeqjofwgcglmutr3a35nygvokja5uuccip4ykyd.onion" fullword wide
      $p8 = "\\LockBit_Ransomware.hta" fullword wide
     
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and ( 1 of ($seq*) and 4 of them )
      ) or ( all of them )
}

rule LockerGogaRansomware {
   
   meta:

      description = "LockerGoga Ransomware"
      author = "Christiaan Beek - McAfee ATR team"
      date = "2019-03-20"
      rule_version = "v1"
      malware_type = "ransomware"
      malware_family = "Ransom:W32/LockerGoga"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      hash = "ba15c27f26265f4b063b65654e9d7c248d0d651919fafb68cb4765d1e057f93f"

   strings:

      $1 = "boost::interprocess::spin_recursive_mutex recursive lock overflow" fullword ascii
      $2 = ".?AU?$error_info_injector@Usync_queue_is_closed@concurrent@boost@@@exception_detail@boost@@" fullword ascii
      $3 = ".?AV?$CipherModeFinalTemplate_CipherHolder@V?$BlockCipherFinal@$00VDec@RC6@CryptoPP@@@CryptoPP@@VCBC_Decryption@2@@CryptoPP@@" fullword ascii
      $4 = "?http://crl.usertrust.com/USERTrustRSACertificationAuthority.crl0v" fullword ascii
      $5 = "cipher.exe" fullword ascii
      $6 = ".?AU?$placement_destroy@Utrace_queue@@@ipcdetail@interprocess@boost@@" fullword ascii
      $7 = "3http://crt.usertrust.com/USERTrustRSAAddTrustCA.crt0%" fullword ascii
      $8 = "CreateProcess failed" fullword ascii
      $9 = "boost::dll::shared_library::load() failed" fullword ascii
      $op1 = { 8b df 83 cb 0f 81 fb ff ff ff 7f 76 07 bb ff ff }
      $op2 = { 8b df 83 cb 0f 81 fb ff ff ff 7f 76 07 bb ff ff }

   condition:

      ( uint16(0) == 0x5a4d and
      filesize < 2000KB and
      ( 6 of them ) and
      all of ($op*)) or
      ( all of them )
}

rule loocipher_ransomware {

   meta:

      description = "Rule to detect Loocipher ransomware"
      author = "Marc Rivero | McAfee ATR Team"
      date = "2019-12-05"
      rule_version = "v1"
      malware_type = "ransomware"
      malware_family = "Ransom:W32/Loocipher"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      reference = "https://www.mcafee.com/blogs/other-blogs/mcafee-labs/analysis-of-loocipher-a-new-ransomware-family-observed-this-year/"
      hash = "7720aa6eb206e589493e440fec8690ceef9e70b5e6712a9fec9208c03cac7ff0"
      
   strings:

      $x1 = "c:\\users\\usuario\\desktop\\cryptolib\\gfpcrypt.h" fullword ascii
      $x2 = "c:\\users\\usuario\\desktop\\cryptolib\\eccrypto.h" fullword ascii
      $s3 = "c:\\users\\usuario\\desktop\\cryptolib\\gf2n.h" fullword ascii
      $s4 = "c:\\users\\usuario\\desktop\\cryptolib\\queue.h" fullword ascii
      $s5 = "ThreadUserTimer: GetThreadTimes failed with error " fullword ascii
      $s6 = "std::_Vector_const_iterator<class std::_Vector_val<struct std::_Simple_types<struct CryptoPP::ProjectivePoint> > >::operator *" fullword wide
      $s7 = "std::_Vector_const_iterator<class std::_Vector_val<struct std::_Simple_types<struct CryptoPP::ProjectivePoint> > >::operator +=" fullword wide
      $s8 = "std::basic_string<unsigned short,struct std::char_traits<unsigned short>,class std::allocator<unsigned short> >::operator []" fullword wide
      $s9 = "std::vector<struct CryptoPP::ProjectivePoint,class std::allocator<struct CryptoPP::ProjectivePoint> >::operator []" fullword wide
      $s10 = "std::_Vector_const_iterator<class std::_Vector_val<struct std::_Simple_types<class CryptoPP::Integer> > >::operator *" fullword wide
      $s11 = "std::_Vector_const_iterator<class std::_Vector_val<struct std::_Simple_types<class CryptoPP::Integer> > >::operator +=" fullword wide
      $s12 = "std::vector<struct CryptoPP::WindowSlider,class std::allocator<struct CryptoPP::WindowSlider> >::operator []" fullword wide
      $s13 = "std::istreambuf_iterator<char,struct std::char_traits<char> >::operator ++" fullword wide
      $s14 = "std::istreambuf_iterator<char,struct std::char_traits<char> >::operator *" fullword wide
      $s15 = "std::_Vector_const_iterator<class std::_Vector_val<struct std::_Simple_types<struct CryptoPP::ProjectivePoint> > >::_Compat" fullword wide
      $s16 = "std::vector<class CryptoPP::PolynomialMod2,class std::allocator<class CryptoPP::PolynomialMod2> >::operator []" fullword wide
      $s17 = "DL_ElgamalLikeSignatureAlgorithm: this signature scheme does not support message recovery" fullword ascii
      $s18 = "std::vector<struct CryptoPP::ECPPoint,class std::allocator<struct CryptoPP::ECPPoint> >::operator []" fullword wide
      $s19 = "std::vector<struct CryptoPP::EC2NPoint,class std::allocator<struct CryptoPP::EC2NPoint> >::operator []" fullword wide
      $s20 = "std::_Vector_const_iterator<class std::_Vector_val<struct std::_Simple_types<class CryptoPP::Integer> > >::_Compat" fullword wide

   condition:

      ( uint16(0) == 0x5a4d and
      filesize < 17000KB and
      ( 1 of ($x*) and
      4 of them ) ) or
      ( all of them )
}

rule ransom_monglock {
   
   meta:

      description = "Ransomware encrypting Mongo Databases "
      author = "Christiaan Beek - McAfee ATR team"
      date = "2019-04-25"
      rule_version = "v1"
      malware_type = "ransomware"
      malware_family = "Ransom:W32/MongLock"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      hash5 = "c4de2d485ec862b308d00face6b98a7801ce4329a8fc10c63cf695af537194a8"

   strings:

      $x1 = "C:\\Windows\\system32\\cmd.exe" fullword wide
      $s1 = "and a Proof of Payment together will be ignored. We will drop the backup after 24 hours. You are welcome! " fullword ascii
      $s2 = "Your File and DataBase is downloaded and backed up on our secured servers. To recover your lost data : Send 0.1 BTC to our BitCoin" ascii
      $s3 = "No valid port number in connect to host string (%s)" fullword ascii
      $s4 = "SOCKS4%s: connecting to HTTP proxy %s port %d" fullword ascii
      $s5 = "# https://curl.haxx.se/docs/http-cookies.html" fullword ascii
      $s6 = "Connection closure while negotiating auth (HTTP 1.0?)" fullword ascii
      $s7 = "detail may be available in the Windows System event log." fullword ascii
      $s8 = "Found bundle for host %s: %p [%s]" fullword ascii
      $s9 = "No valid port number in proxy string (%s)" fullword ascii


      $op0 = { 50 8d 85 78 f6 ff ff 50 ff b5 70 f6 ff ff ff 15 }
      $op1 = { 83 fb 01 75 45 83 7e 14 08 72 34 8b 0e 66 8b 45 }
      $op2 = { c7 41 0c df ff ff ff c7 41 10 }

   condition:
      ( uint16(0) == 0x5a4d and
      filesize < 2000KB and
      ( 1 of ($x*) and
      4 of them ) and
      all of ($op*)
      ) or
      ( all of them )
}

import "pe"



rule nefilim_ransomware {

   meta:

      description = "Rule to detect Nefilim ransomware"
      author = "Marc Rivero | McAfee ATR Team"
      date = "2020-03-17"
      last_update = "2020-04-03"
      rule_version = "v1"
      malware_type = "ransomware"
      malware_family = "Ransom:W32/Nefilim"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      reference = "https://www.bleepingcomputer.com/news/security/new-nefilim-ransomware-threatens-to-release-victims-data/"
      hash = "5ab834f599c6ad35fcd0a168d93c52c399c6de7d1c20f33e25cb1fdb25aec9c6"

   strings:

      $s1 = "C:\\Users\\Administrator\\Desktop\\New folder\\Release\\NEFILIM.pdb" fullword ascii
      $s2 = "oh how i did it??? bypass sofos hah" fullword ascii
      $s3 = " /c timeout /t 3 /nobreak && del \"" fullword wide
      $s4 = "NEFILIM-DECRYPT.txt" fullword wide

      $op0 = { db ff ff ff 55 8b ec 83 ec 24 53 56 57 89 55 f4 }
      $op1 = { 60 be 00 d0 40 00 8d be 00 40 ff ff 57 eb 0b 90 }
      $op2 = { 84 e0 40 00 90 d1 40 00 08 }

      /*

      BYTES:

      558BEC83EC245356578955F4294DF46A048D72038D79015A8BC78955DC8A5EFD8858FF8B5DF48A1C0388188A5EFF8858018A1E88580203F203C2FF4DDC75DE8955F48D51038D42108D59028945F8894DF0297DF0895DEC297DEC8955E8297DE88D470C8D7902894DE4297DE48955DC297DDC8B7DF8894DE02955E08D7102F645F4038B5DEC8A1C038B4DF08A14018A08885DFA8B5DE88A1C03885DFB753B0FB6DB8A9B803040000FB6C98855FF8A91803040000FB64DFA8A8980304000885DFA0FB65DFF8A9B80304000885DFB8B5DF4C1EB023293803240008B5DE48A1C3332DA8B55E0881C178A50F432D18850048A0E324DFA83C004884E108B4DDC8A0C31324DFBFF45F4880F83C60483C704837DF42C0F8266FFFFFF5F5E5BC9C3558BEC560FB6C057C1E0040345086A045F6A045E8A10301140414E75F74F75F15F5E5DC356576A045F6A048BC15E0FB6108A9280304000881083C0044E75EF414F75E65F5EC38A50058A48018850018A50098850058A500D8850098A500A88480D8A48028850028A500E88480A8A48068850068A500F88480E8A48038850038A500B88500F8A500788500B884807C3558BEC5153566A0483C1025E8A410132018A51FE8A59FF8845FD32C232C38845FF8855FE32D38AC2C0E807B31BF6EB02D232C23245FE8A51FF3245FF32118841FE8AC2C0E807F6EB02D232C23241FF8A55FD3245FF8841FF8AC2C0E807F6EB02D232C232018A51013245FF3255FE88018AC2C0E807F6EB02D232C232410183C1043245FF4E8841FD75825E5BC9C3558BEC53FF75088BCE32C0E8D3FEFFFF59B3018BCEE8EDFEFFFF8BC6E808FFFFFF8BCEE84AFFFFFFFF75088BCE8AC3E8AFFEFFFFFEC35980FB0A72D78BCEE8C4FEFFFF8BC6E8DFFEFFFF5B8BCEB00A5DE98EFEFFFF558BEC81ECC000000053568D8D40FFFFFFE85BFDFFFF33DB6A1059395D0C764D5783F91075358B75108D7DF0A5A5A58D8540FFFFFFA5508D75F0E86CFFFFFF596A0F588B4D108D1408803AFF750848C6020079EFEB03FE040833C98A540DF08B450830141843413B5D0C72B55F8B45148B4D106A102BC85E8A14018810404E75F75E5BC9C3558BEC81EC1C02000053FF75088D85E4FDFFFF50FF155C304000688C3240008D85E4FDFFFF50FF155030400033DB53536A02535368000000408D85E4FDFFFF50FF15343040008945F03BC30F849600000056578D45FC5053BE6038400056895DFCFF15083040005056E8C809000083C41085C0750753FF1500304000FF75FC8B3D2430400053FFD750FF15103040008D4DFC5150568945F8FF15083040005056E89109000083C41085C074C98B45FC8945F48D45F450FF75F8E8C909000059595385C074B18D45EC50FF75FCFF75F8FF75F0FF1528304000FF75F853FFD750FF15183040005F5E5BC9C3558BEC83E4F881EC64060000535657FF75088D84246C04000050FF155C3040008B1D5030400068B83240008D84246C04000050FFD38D442410508D84246C04000050FF15043040008944240C83F8FF0F84580300008B354C30400068C03240008D44244050FFD685C00F841D03000068C43240008D44244050FFD685C00F840903000068CC3240008D44244050FFD685C00F84F502000068D43240008D44244050FFD685C00F84E102000068E43240008D44244050FFD685C00F84CD02000068003340008D44244050FFD685C00F84B902000068083340008D44244050FFD685C00F84A502000068103340008D44244050FFD685C00F8491020000682C3340008D44244050FFD685C00F847D02000068383340008D44244050FFD685C00F8469020000684C3340008D44244050FFD685C00F8455020000685C3340008D44244050FFD685C00F844102000068703340008D44244050FFD685C00F842D020000688C3340008D44244050FFD685C00F841902000068A43340008D44244050FFD685C00F840502000068BC3340008D44244050FFD685C00F84F101000068D43340008D44244050FFD685C00F84DD01000068E83340008D44244050FFD685C00F84C901000068043440008D44244050FFD685C00F84B501000068143440008D44244050FFD685C00F84A1010000682C3440008D44244050FFD685C00F848D010000683C3440008D44244050FFD685C00F847901000068583440008D44244050FFD685C00F8465010000F644241010FF75088D842464020000507436FF155C3040008D44243C508D84246402000050FFD368803440008D84246402000050FFD38D84246002000050E896FDFFFFE91C010000FF155C3040008D44243C508D84246402000050FFD38D44243C50E8F60500008BF8C704248434400057FFD685C00F84EA000000689034400057FFD685C00F84DA000000689C34400057FFD685C00F84CA00000068A834400057FFD685C00F84BA00000068B434400057FFD685C00F84AA00000068C034400057FFD685C00F849A00000068CC34400057FFD685C00F848A00000068D834400057FFD685C0747E68E434400057FFD685C0747268F034400057FFD685C0746668FC34400057FFD685C0745A680835400057FFD685C0744E681435400057FFD685C07442682035400057FFD685C07436683435400057FFD685C0742A684035400057FFD685C0741E688C3240008D44244050FFD685C0740E8D84246002000050E829000000598D44241050FF742410FF155430400085C00F85B8FCFFFFFF74240CFF15483040005F5E5B8BE55DC3558BEC81EC4802000053565768843F4000FF15083040008B35243040005033FF57FFD68B1D1030400050FFD368843F40008945E8FF15083040008945F4B8843F4000397DF474138B4DE82BC88A10FF4DF488140140397DF475F257576A03575768000000C0FF7508FF15343040008945F83BC70F845F0300008D4DDC5150FF15383040006A1057FFD650FFD36A10578945F4FFD650FFD3FF75F48945F0E8B2040000FF75F0E8AA0400005959680001000057FFD650FFD36800010000578945CCFFD650FFD3FF75CC8B55F48945C8E8990E0000FF75C88B55F0E88E0E00008B1D1430400059595757FF75E0FF75DCFF75F8FFD357FF1540304000578D45D0506800010000FF75CCFF75F8FF1528304000FF153C30400083F8060F84B9020000FF153C30400083F8130F84AA0200008B45DC8B4DE05705000100005713CF5150FF75F8FFD3578D45D0506800010000FF75C8FF75F8FF15283040008B45DC8B4DE05705000200005713CF5150FF75F8FFD3578D45D05068843F4000FF150830400050FF75E8FF75F8FF15283040008B45E08B4DDC3BC70F8C660100007F0C81F90090D0030F86E5000000897DD4897DD83BC70F8CBC0100007F0D3BCF0F86B2010000EB038B4DDC2B4DD41B45D88945E80F889E0100007F0C81F990D003000F82900100006848E8010057FFD650FF15103040005757FF75D88945E8FF75D4FF75F8FFD3578D45C4506848E80100FF75E8FF75F8FF1530304000FF75F08B55F4FF75F06848E80100FF75E8E8AFF8FFFF83C4105757FF75D8FF75D4FF75F8FFD3578D45D0506848E80100FF75E8FF75F8FF1528304000FFD6FF75E85750FF15183040008145D490D003008B45E0117DD83945D80F8C4CFFFFFF0F8FF60000008B4DDC394DD40F823DFFFFFFE9E50000003BC77C6F7F0881F9804F1200766568C027090057FFD650FF1510304000575733C98945E85133C050FF75F8FFD3578D45C45068C0270900FF75E8FF75F8FF1530304000FF75F08B55F4FF75F068C0270900FF75E8E8F6F7FFFF83C410575733C05050FF75F8FFD3578D45D05068C0270900EB595157FFD650FF1510304000575733C98945E85133C050FF75F8FFD3578D45C450FF75DCFF75E8FF75F8FF1530304000FF75F08B55F4FF75F0FF75DCFF75E8E899F7FFFF83C410575733C05050FF75F8FFD3578D45D050FF75DCFF75E8FF75F8FF1528304000FF75E857FFD650FF1518304000FF75F8FF1558304000FF75CC57FFD68B1D1830400050FFD3FF75C8

      */

      $bp = { 558B??83????53565789????29????6A??8D????8D????5A8B??89????8A????88????8B????8A????88??8A????88????8A??88????03??03??FF????75??89????8D????8D????8D????89????89????29????89????29????89????29????8D????8D????89????29????89????29????8B????89????29????8D????F6??????8B????8A????8B????8A????8A??88????8B????8A????88????75??0FB6??8A??????????0FB6??88????8A??????????0FB6????8A??????????88????0FB6????8A??????????88????8B????C1????32??????????8B????8A????32??8B????88????8A????32??88????8A??32????83????88????8B????8A????32????FF????88??83????83????83??????0F82????????5F5E5BC9C3558B??560FB6??57C1????03????6A??5F6A??5E8A??30??40414E75??4F75??5F5E5DC356576A??5F6A??8B??5E0FB6??8A??????????88??83????4E75??414F75??5F5EC38A????8A????88????8A????88????8A????88????8A????88????8A????88????8A????88????8A????88????8A????88????8A????88????8A????88????8A????88????88????C3558B??5153566A??83????5E8A????32??8A????8A????88????32??32??88????88????32??8A??C0????B3??F6??02??32??32????8A????32????32??88????8A??C0????F6??02??32??32????8A????32????88????8A??C0????F6??02??32??32??8A????32????32????88??8A??C0????F6??02??32??32????83????32????4E88????75??5E5BC9C3558B??53FF????8B??32??E8????????59B3??8B??E8????????8B??E8????????8B??E8????????FF????8B??8A??E8????????FE??5980????72??8B??E8????????8B??E8????????5B8B??B0??5DE9????????558B??81??????????53568D??????????E8????????33??6A??5939????76??5783????75??8B????8D????A5A5A58D??????????A5508D????E8????????596A??588B????8D????80????75??48C6????79??EB??FE????33??8A??????8B????30????43413B????72??5F8B????8B????6A??2B??5E8A????88??404E75??5E5BC9C3558B??81??????????53FF????8D??????????50FF??????????68????????8D??????????50FF??????????33??53536A??535368????????8D??????????50FF??????????89????3B??0F84????????56578D????5053BE????????5689????FF??????????5056E8????????83????85??75??53FF??????????FF????8B??????????53FF??50FF??????????8D????51505689????FF??????????5056E8????????83????85??74??8B????89????8D????50FF????E8????????59595385??74??8D????50FF????FF????FF????FF??????????FF????53FF??50FF??????????5F5E5BC9C3558B??83????81??????????535657FF????8D????????????50FF??????????8B??????????68????????8D????????????50FF??8D??????508D????????????50FF??????????89??????83????0F84????????8B??????????68????????8D??????50FF??85??0F84????????68????????8D??????50FF??85??0F84????????68????????8D??????50FF??85??0F84????????68????????8D??????50FF??85??0F84????????68????????8D??????50FF??85??0F84????????68????????8D??????50FF??85??0F84????????68????????8D??????50FF??85??0F84????????68????????8D??????50FF??85??0F84????????68????????8D??????50FF??85??0F84????????68????????8D??????50FF??85??0F84????????68????????8D??????50FF??85??0F84????????68????????8D??????50FF??85??0F84????????68????????8D??????50FF??85??0F84????????68????????8D??????50FF??85??0F84????????68????????8D??????50FF??85??0F84????????68????????8D??????50FF??85??0F84????????68????????8D??????50FF??85??0F84????????68????????8D??????50FF??85??0F84????????68????????8D??????50FF??85??0F84????????68????????8D??????50FF??85??0F84????????68????????8D??????50FF??85??0F84????????68????????8D??????50FF??85??0F84????????68????????8D??????50FF??85??0F84????????F6????????FF????8D????????????5074??FF??????????8D??????508D????????????50FF??68????????8D????????????50FF??8D????????????50E8????????E9????????FF??????????8D??????508D????????????50FF??8D??????50E8????????8B??C7????????????57FF??85??0F84????????68????????57FF??85??0F84????????68????????57FF??85??0F84????????68????????57FF??85??0F84????????68????????57FF??85??0F84????????68????????57FF??85??0F84????????68????????57FF??85??0F84????????68????????57FF??85??74??68????????57FF??85??74??68????????57FF??85??74??68????????57FF??85??74??68????????57FF??85??74??68????????57FF??85??74??68????????57FF??85??74??68????????57FF??85??74??68????????57FF??85??74??68????????8D??????50FF??85??74??8D????????????50E8????????598D??????50FF??????FF??????????85??0F85????????FF??????FF??????????5F5E5B8B??5DC3558B??81??????????53565768????????FF??????????8B??????????5033??57FF??8B??????????50FF??68????????89????FF??????????89????B8????????39????74??8B????2B??8A??FF????88????4039????75??57576A??575768????????FF????FF??????????89????3B??0F84????????8D????5150FF??????????6A??57FF??50FF??6A??5789????FF??50FF??FF????89????E8????????FF????E8????????595968????????57FF??50FF??68????????5789????FF??50FF??FF????8B????89????E8????????FF????8B????E8????????8B??????????59595757FF????FF????FF????FF??57FF??????????578D????5068????????FF????FF????FF??????????FF??????????83????0F84????????FF??????????83????0F84????????8B????8B????5705????????5713??5150FF????FF??578D????5068????????FF????FF????FF??????????8B????8B????5705????????5713??5150FF????FF??578D????5068????????FF??????????50FF????FF????FF??????????8B????8B????3B??0F8C????????7F??81??????????0F86????????89????89????3B??0F8C????????7F??3B??0F86????????EB??8B????2B????1B????89????0F88????????7F??81??????????0F82????????68????????57FF??50FF??????????5757FF????89????FF????FF????FF??578D????5068????????FF????FF????FF??????????FF????8B????FF????68????????FF????E8????????83????5757FF????FF????FF????FF??578D????5068????????FF????FF????FF??????????FF??FF????5750FF??????????81????????????8B????11????39????0F8C????????0F8F????????8B????39????0F82????????E9????????3B??7C??7F??81??????????76??68????????57FF??50FF??????????575733??89????5133??50FF????FF??578D????5068????????FF????FF????FF??????????FF????8B????FF????68????????FF????E8????????83????575733??5050FF????FF??578D????5068????????EB??5157FF??50FF??????????575733??89????5133??50FF????FF??578D????50FF????FF????FF????FF??????????FF????8B????FF????FF????FF????E8????????83????575733??5050FF????FF??578D????50FF????FF????FF????FF??????????FF????57FF??50FF??????????FF????FF??????????FF????57FF??8B??????????50FF??FF???? }

      
   condition:

      uint16(0) == 0x5a4d and
      filesize < 200KB and
      all of ($s*) or
      all of ($op*) or 
      $bp
}
rule RANSOM_nefilim_go
{
    meta:

        description = "Rule to detect the new Nefilim written in GO"
        author = "Marc Rivero | McAfee ATR Team"
        date = "2020-07-13"
        rule_version = "v1"
        malware_type = "ransomware"
        malware_family = "Ransom:W32/Nefilim"
        actor_type = "Cybercrime"
        actor_group = "Unknown"
        reference = "https://www.bleepingcomputer.com/news/security/new-nefilim-ransomware-threatens-to-release-victims-data/"
        hash = "a51fec27e478a1908fc58c96eb14f3719608ed925f1b44eb67bbcc67bd4c4099"

    strings:

        $pattern = { FF20476F206275696C642049443A20226A744368374D37436A4A5732634C5F636633374A2F49625946794336635A64735F4D796A56633461642F486B6D36694A4D39327847785F4F2D65746744692F664E37434C43622D59716E374D795947565A686F220A20FFCCCCCCCCCCCCCCCCCC648B0D140000008B89000000003B6108766B83EC0CC744241400000000C7442418000000008B4424108400890424E88D0200008B44240485C0740789C183F8FF7514C744241400000000C74424180000000083C40CC3894C24088B44241083C004890424E8570200008B4424048B4C2408894C24148944241883C40CC3E8AE5A0400E979FFFFFFCCCCCCCCCCCCCCCCCC648B0D140000008B89000000003B61080F86EC00000083EC108B44241885C00F84C30000008B4424148400890424E8FD0100008B44240485C0742E89C183F8FF74E38B44241839C10F85800000008B44241C894424048B44241483C004890424E88B12000083C410C3E8620303008B442414890424C744240400000000C7442408FFFFFFFFE8A61200000FB644240C84C07507E868030300EB8B8B44241C894424048B4424148D4804890C24E83F1200008B442418894424048B442414890424E82B120000E83603030083C410C38D05408E4E008904248D05B8CC510089442404E8DA3F02000F0B8D05408E4E008904248D05B0CC510089442404E8C03F02000F0BE899590400E9F4FEFFFFCCCCCCCCE90B000000CCCCCCCCCCCCCCCCCCCCCC8B6C24048B4424088B4C240CF00FB14D000F94442410C3CCCCCCCCCCCCCCCCCCE9DBFFFFFFCCCCCCCCCCCCCCCCCCCCCC8B6C2404F7C50700000074068B05000000008B4424088B54240C8B5C24108B4C2414F00FC74D000F94442418C3CCCCCCE90B000000CCCCCCCCCCCCCCCCCCCCCC8B6C24048B44240889C1F00FC1450001C1894C240CC3CCCCCCCCCCCCCCCCCCCC8B6C2404F7C50700000074068B05000000008B7424088B7C240C8B45008B550489C389D101F311F9F00FC74D0075F1895C2410894C2414C3CCCCCCCCCCCCCCCC8B4424048B0089442408C3CCCCCCCCCC8B442404A90700000074068B05000000000F6F000F7F4424080F77C3CCCCCCCCE9CBFFFFFFCCCCCCCCCCCCCCCCCCCCCCE9BBFFFFFFCCCCCCCCCCCCCCCCCCCCCC8B6C24048B442408874500C3CCCCCCCCE9EBFFFFFFCCCCCCCCCCCCCCCCCCCCCC8B4424040FBCC074058944240CC38B4424080FBCC0740883C0208944240CC3C744240C40000000C3CCCCCCCCCCCCCCCC8B4424048B0089442408C3CCCCCCCCCC8B4424048B0089442408C3CCCCCCCCCC83EC208B4424248B088B54242889CB01D1894C241C8B6804890424895C2404896C2408894C240C8B5C242C11DD896C2418896C2410E8160100000FB644241484C074C08B44241C894424308B4424188944243483C420C3CCCCCCCCCCCCCCCCCC83EC208B4424248B08894C24188B50048954241C890424894C2404895424088B5C2428895C240C8B6C242C896C2410E8BC0000000FB644241484C074C68B442418894424308B44241C8944243483C420C3CCCCCCCCCCCCCCCCCCCCCCCCCCCCCC8B5C24048B4424088B4C240CF00FB10B0F94442410C3CCCCCCCCCCCCCCCCCCCCE9DBFFFFFFCCCCCCCCCCCCCCCCCCCCCCE9EBFEFFFFCCCCCCCCCCCCCCCCCCCCCCE9DBFEFFFFCCCCCCCCCCCCCCCCCCCCCCE9DB000000CCCCCCCCCCCCCCCCCCCCCCE97B000000CCCCCCCCCCCCCCCCCCCCCCE9CB000000CCCCCCCCCCCCCCCCCCCCCCE9BBFEFFFFCCCCCCCCCCCCCCCCCCCCCC8B6C2404F7C50700000074068B2D000000008B4424088B54240C8B5C24108B4C2414F00FC74D000F94442418C3CCCCCC8B5C24048B4424088B4C240CF00FB10B0F94442410C3CCCCCCCCCCCCCCCCCCCC8B5C24048B44240889C1F00FC10301C88944240CC3CCCCCCCCCCCCCCCCCCCCCC8B5C24048B44240887038944240CC3CCE9EBFFFFFFCCCCCCCCCCCCCCCCCCCCCC8B5C24048B4424088703C3CCCCCCCCCC8B5C24048B4424088703C3CCCCCCCCCC8B442404A90700000074068B05000000008D5C24080F6F000F7F030F77C3CCCC8B442404A90700000074068B05000000000F6F4424080F7F000F77B800000000F00FC10424C3CCCCCCCCCCCCCCCCCCCC8B4424048A5C2408F00818C3CCCCCCCC8B4424048A5C2408F02018C3CCCCCCCC648B0D140000008B89000000003B610876098B4424088944240CC3E860550400EBDECCCCCCCCCCCCCCCCCCCCCCCCCCCC648B0D140000008B89000000003B6108762B83EC108B4424148904248B44241889442404C744240801000000E8AF4400008B44240C8944241C83C410C3E80E550400EBBCCCCCCCCCCCCCCCCCCCCCCCCC648B0D140000008B89000000003B6108762B83EC108B4424148904248B44241889442404C744240802000000E85F4400008B44240C8944241C83C410C3E8BE540400EBBCCCCCCCCCCCCCCCCCCCCCCCCC648B0D140000008B89000000003B6108762B83EC108B4424148904248B44241889442404C744240810000000E80F4400008B44240C8944241C83C410C3E86E540400EBBCCCCCCCCCCCCCCCCCCCCCCCCC83EC108D42048B008B4C2414890C248B4C2418894C240489442408E8D04300008B44240C8944241C83C410C3CCCCCCCC648B0D140000008B89000000003B6108762C83EC108B4424148B088B400489442408890C248B44241889442404E88E4300008B44240C8944241C83C410C3E8ED530400EBBBCCCCCCCCCCCCCCCCCCCCCC648B0D140000008B89000000003B61080F86B600000083EC108B442414F30F10000F57C90F2EC175060F8B860000000F2EC075027B5B648B05140000008B80000000008B40188B88940000008B909800000089909400000089CBC1E11131D989D331CAC1E90731D189DAC1EB1031CB8998980000008D041A8B4C241831C835A98E7FAA69C0CD76BAC28944241C83C410C38904248B44241889442404C744240804000000E8C74200008B44240C8944241C83C410C38B44241835A98E7FAA69C0CD76BAC28944241C83C410C3E80F530400E92AFFFFFFCCCCCCCCCCCCCCCCCCCC648B0D140000008B89000000003B61080F86B800000083EC108B442414F20F10000F57C9660F2EC175060F8B87000000660F2EC075027B5B648B05140000008B80000000008B40188B88940000008B909800000089909400000089CBC1E11131D989D331CAC1E90731D189DAC1EB1031CB8998980000008D041A8B4C241831C835A98E7FAA69C0CD76BAC28944241C83C410C38904248B44241889442404C744240808000000E8E54100008B44240C8944241C83C410C38B44241835A98E7FAA69C0CD76BAC28944241C83C410C3E82D520400E928FFFFFFCCCCCCCCCCCCCCCC648B0D140000008B89000000003B6108763C83EC0C8B44241084008904248B4C2414894C2404E815FEFFFF8B44241083C0048B4C2408890424894C2404E8FEFDFFFF8B4424088944241883C40CC3E8CD510400EBABCCCCCCCCCCCCCCCCCCCCCC648B0D140000008B89000000003B6108763C83EC0C8B44241084008904248B4C2414894C2404E895FEFFFF8B44241083C0088B4C2408890424894C2404E87EFEFFFF8B4424088944241883C40CC3E86D510400EBABCCCCCCCCCCCCCCCCCCCCCC648B0D140000008B89000000003B61080F86F200000083EC248B4424288B0885C974678B49048B59108B1385D274670FB6490FF6C120742983C0048904248B44242C35A98E7FAA894424048B02FFD08B44240869C0CD76BAC28944243083C424C38B40048904248B44242C35A98E7FAA894424048B02FFD08B44240869C0CD76BAC28944243083C424C38B44242C8944243083C424C3890C24E8B2FA03008B4424088B4C2404C70424000000008D15A279500089542404C744240818000000894C240C89442410E8F46603008B4424188B4C2414894C241C894424208D05C0D24E008904248D44241C89442404E81E8E00008B44240C8B4C2408890C2489442404E87A3602000F0BE853500400E9EEFEFFFFCCCCCCCCCCCCCCCCCCCCCCCCCCCC648B0D140000008B89000000003B61080F86EF00000083EC248B4424288B0885C974648B59108B1385D274670FB6490FF6C120742983C0048904248B44242C35A98E7FAA894424048B02FFD08B44240869C0CD76BAC28944243083C424C38B40048904248B44242C35A98E7FAA894424048B02FFD08B44240869C0CD76BAC28944243083C424C38B44242C8944243083C424C3890C24E895F903008B4424088B4C2404C70424000000008D15A279500089542404C744240818000000894C240C89442410E8D76503008B4424188B4C2414894C241C894424208D05C0D24E008904248D44241C89442404E8018D00008B44240C8B4C2408890C2489442404E85D3502000F0BE8364F0400E9F1FEFFFFCC648B0D140000008B89000000003B61087606C644240C01C3 }

    condition:
    
        uint16(0) == 0x5a4d and
        filesize < 8000KB and
        all of them
}

rule nemty_ransomware {

   meta:

      description = "Rule to detect Nemty Ransomware"
      author = "Marc Rivero | McAfee ATR Team"
      date = "2020-02-23"
      rule_version = "v1"
      malware_type = "ransomware"
      malware_family = "Ransom:W32/Nemty"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      reference = "https://www.mcafee.com/blogs/other-blogs/mcafee-labs/nemty-ransomware-learning-by-doing/"
      hash = "73bf76533eb0bcc4afb5c72dcb8e7306471ae971212d05d0ff272f171b94b2d4"

   strings:

      $x1 = "/c vssadmin.exe delete shadows /all /quiet & bcdedit /set {default} bootstatuspolicy ignoreallfailures & bcdedit /set {default}" fullword ascii
      $s2 = "https://pbs.twimg.com/media/Dn4vwaRW0AY-tUu.jpg:large :D" fullword ascii
      $s3 = "MSDOS.SYS" fullword wide
      $s4 = "/c vssadmin.exe delete shadows /all /quiet & bcdedit /set {default} bootstatuspolicy ignoreallfailures & bcdedit /set {default} " ascii
      $s5 = "recoveryenabled no & wbadmin delete catalog -quiet & wmic shadowcopy delete" fullword ascii
      $s6 = "DECRYPT.txt" fullword ascii
      $s7 = "pv3mi+NQplLqkkJpTNmji/M6mL4NGe5IHsRFJirV6HSyx8mC8goskf5lXH2d57vh52iqhhEc5maLcSrIKbukcnmUwym+In1OnvHp070=" fullword ascii
      $s8 = "\\NEMTY-DECRYPT.txt\"" fullword ascii
      $s9 = "rfyPvccxgVaLvW9OOY2J090Mq987N9lif/RoIDP89luS9Ouv9gUImpgCTVGWvJzrqiS8hQ5El02LdEvKcJ+7dn3DxiXSNG1PwLrY59KzGs/gUvXnYcmT6t34qfZmr8g8" ascii
      $s10 = "IO.SYS" fullword wide
      $s11 = "QgzjKXcD1Jh/cOLBh1OMb+rWxUbToys2ArG9laNWAWk0rNIv2dnIDpc+mSbp91E8qVN8Mv8K5jC3EBr4TB8jh5Ns/onBhPZ9rLXR7wIkaXGeTZi/4/XOtO3DFiad4+vf" ascii
      $s12 = "NEMTY-DECRYPT.txt" fullword wide
      $s13 = "pvXmjPQRoUmjj0g9QZ24wvEqyvcJVvFWXc0LL2XL5DWmz8me5wElh/48FHKcpbnq8C2kwQ==" fullword ascii
      $s14 = "a/QRAGlNLvqNuONkUWCQTNfoW45DFkZVjUPn0t3tJQnHWPhJR2HWttXqYpQQIMpn" fullword ascii
      $s15 = "KeoJrLFoTgXaTKTIr+v/ObwtC5BKtMitXq8aaDT8apz98QQvQgMbncLSJWJG+bHvaMhG" fullword ascii
      $s16 = "pu/hj6YerUnqlUM9A8i+i/UhnvsIE+9XTYs=" fullword ascii
      $s17 = "grQkLxaGvL0IBGGCRlJ8Q4qQP/midozZSBhFGEDpNElwvWXhba6kTH1LoX8VYNOCZTDzLe82kUD1TSAoZ/fz+8QN7pLqol5+f9QnCLB9QKOi0OmpIS1DLlngr9YH99vt" ascii
      $s18 = "BOOTSECT.BAK" fullword wide
      $s19 = "bbVU/9TycwPO+5MgkokSHkAbUSRTwcbYy5tmDXAU1lcF7d36BTpfvzaV5/VI6ARRt2ypsxHGlnOJQUTH6Ya//Eu0jPi/6s2MmOk67csw/msiaaxuHXDostsSCC+kolVX" ascii
      $s20 = "puh4wXjVYWJzFN6aIgnClL4W/1/5Eg6bm5uEv6Dru0pfOvhmbF1SY3zav4RQVQTYMfZxAsaBYfJ+Gx+6gDEmKggypl1VcVXWRbxAuDIXaByh9aP4B2QvhLnJxZLe+AG5" ascii

   condition:
   
      ( uint16(0) == 0x5a4d and
      filesize < 400KB and
      ( 1 of ($x*) and
      4 of them ))
}

rule nemty_ransomware_2_6 {

   meta:

      description = "Rule to detect Nemty Ransomware version 2.6"
      author = "Marc Rivero | McAfee ATR Team"
      date = "2020-04-06"
      rule_version = "v1"
      malware_type = "ransomware"
      malware_family = "Ransom:W32/Nemty"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      reference = "https://www.mcafee.com/blogs/other-blogs/mcafee-labs/nemty-ransomware-learning-by-doing/"
      hash = "52b7d20d358d1774a360bb3897a889e14d416c3b2dff26156a506ff199c3388d"

   strings:

   	  /*

		BYTES:

		558BEC83EC245356578955F4294DF46A048D72038D79015A8BC78955DC8A5EFD8858FF8B5DF48A1C0388188A5EFF8858018A1E88580203F203C2FF4DDC75DE8955F48D51038D42108D59028945F8894DF0297DF0895DEC297DEC8955E8297DE88D470C8D7902894DE4297DE48955DC297DDC8B7DF8894DE02955E08D7102F645F4038B5DEC8A1C038B4DF08A14018A08885DFA8B5DE88A1C03885DFB753B0FB6DB8A9B281241000FB6C98855FF8A91281241000FB64DFA8A8928124100885DFA0FB65DFF8A9B28124100885DFB8B5DF4C1EB023293281441008B5DE48A1C3332DA8B55E0881C178A50F432D18850048A0E324DFA83C004884E108B4DDC8A0C31324DFBFF45F4880F83C60483C704837DF42C0F8266FFFFFF5F5E5BC9C3558BEC560FB6C057C1E0040345086A045F6A045E8A10301140414E75F74F75F15F5E5DC356576A045F6A048BC15E0FB6108A9228124100881083C0044E75EF414F75E65F5EC38A50058A48018850018A50098850058A500D8850098A500A88480D8A48028850028A500E88480A8A48068850068A500F88480E8A48038850038A500B88500F8A500788500B884807C3558BEC5153566A0483C1025E8A410132018A51FE8A59FF8845FD32C232C38845FF8855FE32D38AC2C0E807B31BF6EB02D232C23245FE8A51FF3245FF32118841FE8AC2C0E807F6EB02D232C23241FF8A55FD3245FF8841FF8AC2C0E807F6EB02D232C232018A51013245FF3255FE88018AC2C0E807F6EB02D232C232410183C1043245FF4E8841FD75825E5BC9C3558BEC53FF75088BCE32C0E8D3FEFFFF59B3018BCEE8EDFEFFFF8BC6E808FFFFFF8BCEE84AFFFFFFFF75088BCE8AC3E8AFFEFFFFFEC35980FB0A72D78BCEE8C4FEFFFF8BC6E8DFFEFFFF5B8BCEB00A5DE98EFEFFFF558BEC81ECC8000000A18440410033C58945FC8B4508578D8D3CFFFFFF898538FFFFFFE849FDFFFF33FF6A1058397D0C764F5683F8107534508D45EC5350E88E6000008D853CFFFFFF508D75ECE859FFFFFF83C4106A0F58803C03FF7509C60403004879F3EB03FE041833C08A4C05EC8BB538FFFFFF300C3E47403B7D0C72B35E8B4DFC33CD5FE835600000C9C3558BEC51515333C05633F632DB8945FC39450C0F8682000000578B7DFC8B55088A14178BFE83EF0074504F74374F755D217DF80FB6FB0FB6F283E70F8BDEC1EB06C1E7020BFB8A9F6811410083E63F881C088A9E681141008B75F8885C080183C002EB290FB6FB0FB6DA83E7036A02C1E704C1EB045E0BFBEB0933F60FB6FA46C1EF028A9F68114100881C0840FF45FC8ADA8B55FC3B550C72805F4E741D4E75360FB6D383E20F8A149568114100881408C64408013D83C002EB1C0FB6D383E203C1E2048A926811410088140866C74408013D3D83C0035EC60408005BC9C3558BEC33C0F6450C0375775733FF39450C766E8B4D088A0C0F80F93D746380F92B7C5C80F97A7F570FB6C98A89A811410080F9FF74498BD783E20383EA0074314A741D4A74094A752E080C3040EB288AD1C0EA0280E20F08143040C0E106EB148AD1C0EA0480E20308143040C0E104EB03C0E102880C30473B7D0C7296EB0233C05F5DC3558BEC518B0B85C974298B4304568BF18945FC3BF07413576A0133FFE81E00000083C61C3B75FC75EF5FFF33E84A630000595E33C08903894304894308C9C3558BEC807D08007420837E1410721A538B1E85FF740B575356E8835E000083C40C53E815630000595BC746140F000000897E10C60437005DC20400C701C0F24000E9E5630000558BEC568BF1C706C0F24000E8D4630000F6450801740756E8D9620000598BC65E5DC20400558BEC83E4F881ECEC020000A18440410033C4898424E80200005356578D4508508D742450E89915000068341441008D842488000000E8AE1500006A075F33C083EC1C668944244C8D45088BF433DB50897C2464895C2460E866150000E8CC0E000033C066894424308B8424B00000000344247883C41C8D4C2414897C2428895C2424E8BA1E0000538D4424505083C8FF8D74241CE8D8200000538D8424880000005083C8FFE8C72000008BDE8D442430E8A61500006A0133FFE87F160000837C2444088B44243073048D4424308D8C24A00000005150FF15DCF040008944241083F8FF0F842E0500008B3598F04000683C1441008D8424D000000050FFD685C00F84ED04000068401441008D8424D000000050FFD685C00F84D604000068481441008D8424D000000050FFD685C00F84BF04000068501441008D8424D000000050FFD685C00F84A804000068601441008D8424D000000050FFD685C00F8491040000687C1441008D8424D000000050FFD685C00F847A04000068841441008D8424D000000050FFD685C00F846304000068A01441008D8424D000000050FFD685C00F844C04000068AC1441008D8424D000000050FFD685C00F843504000068C01441008D8424D000000050FFD685C00F841E04000068D01441008D8424D000000050FFD685C00F840704000068E41441008D8424D000000050FFD685C00F84F003000068001541008D8424D000000050FFD685C00F84D903000068181541008D8424D000000050FFD685C00F84C203000068301541008D8424D000000050FFD685C00F84AB03000068481541008D8424D000000050FFD685C00F8494030000685C1541008D8424D000000050FFD685C00F847D03000068781541008D8424D000000050FFD685C00F846603000068881541008D8424D000000050FFD685C00F844F03000068A01541008D8424D000000050FFD685C00F843803000068B01541008D8424D000000050FFD685C00F842103000068CC1541008D8424D000000050FFD685C00F840A03000068F41541008D8424D000000050FFD685C00F84F302000068081641008D8424D000000050FFD685C00F84DC020000F68424A0000000108D8424CC000000508D4C246C8D4424507450E8441A0000598D4C241451E88F1A00008BD8598D442430E80E1300006A0133FF8D742418E8E31300006A018D74246CE8D813000083EC1C8D44244C8BF450E84E120000E886FCFFFF83C41CE972020000E8F41900008BD8598D442430E8C91200006A0133FF8D74246CE89E1300008D8424CC00000050FF15ACF14000508D442418E8311200008B4424146A085F397C242873048D4424148B3598F04000681816410050FFD685C00F84080200008B442414397C242873048D442414682416410050FFD685C00F84EA0100008B442414397C242873048D442414683016410050FFD685C00F84CC0100008B442414397C242873048D442414683C16410050FFD685C00F84AE0100008B442414397C242873048D442414684816410050FFD685C00F84900100008B442414397C242873048D442414685416410050FFD685C00F84720100008B442414397C242873048D442414686016410050FFD685C00F84540100008B442414397C242873048D442414686C16410050FFD685C00F84360100008B442414397C242873048D442414687816410050FFD685C00F84180100008B442414397C242873048D442414688416410050FFD685C00F84FA0000008B442414397C242873048D442414689016410050FFD685C00F84DC0000008B442414397C242873048D442414689C16410050FFD685C00F84BE0000008B442414397C242873048D44241468A816410050FFD685C00F84A00000008B442414397C242873048D44241468B416410050FFD685C00F84820000008B442414397C242873048D44241468C816410050FFD685C074688B442414397C242873048D44241468D416410050FFD685C0744E83EC1C8BC468E0164100E84110000083EC1C8D8C24040100008BC451E82F100000E83456000083C43885C075218B4C2430397C244473048D4C243083EC1C8BC451E80A100000E8CE0A000083C41C6A0133FF8D742418E84A1100008D8424A000000050FF742414FF1594F0400085C00F85DCFAFFFFFF742410FF15A0F0400033DB435333FF8D742434

		*/
         
      $pattern = { 558B??83????53565789????29????6A??8D????8D????5A8B??89????8A????88????8B????8A????88??8A????88????8A??88????03??03??FF????75??89????8D????8D????8D????89????89????29????89????29????89????29????8D????8D????89????29????89????29????8B????89????29????8D????F6??????8B????8A????8B????8A????8A??88????8B????8A????88????75??0FB6??8A??????????0FB6??88????8A??????????0FB6????8A??????????88????0FB6????8A??????????88????8B????C1????32??????????8B????8A????32??8B????88????8A????32??88????8A??32????83????88????8B????8A????32????FF????88??83????83????83??????0F82????????5F5E5BC9C3558B??560FB6??57C1????03????6A??5F6A??5E8A??30??40414E75??4F75??5F5E5DC356576A??5F6A??8B??5E0FB6??8A??????????88??83????4E75??414F75??5F5EC38A????8A????88????8A????88????8A????88????8A????88????8A????88????8A????88????8A????88????8A????88????8A????88????8A????88????8A????88????88????C3558B??5153566A??83????5E8A????32??8A????8A????88????32??32??88????88????32??8A??C0????B3??F6??02??32??32????8A????32????32??88????8A??C0????F6??02??32??32????8A????32????88????8A??C0????F6??02??32??32??8A????32????32????88??8A??C0????F6??02??32??32????83????32????4E88????75??5E5BC9C3558B??53FF????8B??32??E8????????59B3??8B??E8????????8B??E8????????8B??E8????????FF????8B??8A??E8????????FE??5980????72??8B??E8????????8B??E8????????5B8B??B0??5DE9????????558B??81??????????A1????????33??89????8B????578D??????????89??????????E8????????33??6A??5839????76??5683????75??508D????5350E8????????8D??????????508D????E8????????83????6A??5880??????75??C6??????4879??EB??FE????33??8A??????8B??????????30????47403B????72??5E8B????33??5FE8????????C9C3558B??51515333??5633??32??89????39????0F86????????578B????8B????8A????8B??83????74??4F74??4F75??21????0FB6??0FB6??83????8B??C1????C1????0B??8A??????????83????88????8A??????????8B????88??????83????EB??0FB6??0FB6??83????6A??C1????C1????5E0B??EB??33??0FB6??46C1????8A??????????88????40FF????8A??8B????3B????72??5F4E74??4E75??0FB6??83????8A????????????88????C6????????83????EB??0FB6??83????C1????8A??????????88????66????????????83????5EC6??????5BC9C3558B??33??F6??????75??5733??39????76??8B????8A????80????74??80????7C??80????7F??0FB6??8A??????????80????74??8B??83????83????74??4A74??4A74??4A75??08????40EB??8A??C0????80????08????40C0????EB??8A??C0????80????08????40C0????EB??C0????88????473B????72??EB??33??5F5DC3558B??518B??85??74??8B????568B??89????3B??74??576A??33??E8????????83????3B????75??5FFF??E8????????595E33??89??89????89????C9C3558B??80??????74??83??????72??538B??85??74??575356E8????????83????53E8????????595BC7????????????89????C6??????5DC2????C7??????????E9????????558B??568B??C7??????????E8????????F6??????74??56E8????????598B??5E5DC2????558B??83????81??????????A1????????33??89????????????5356578D????508D??????E8????????68????????8D????????????E8????????6A??5F33??83????66????????8D????8B??33??5089??????89??????E8????????E8????????33??66????????8B????????????03??????83????8D??????89??????89??????E8????????538D??????5083????8D??????E8????????538D????????????5083????E8????????8B??8D??????E8????????6A??33??E8????????83????????8B??????73??8D??????8D????????????5150FF??????????89??????83????0F84????????8B??????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????68????????8D????????????50FF??85??0F84????????F6??????????????8D????????????508D??????8D??????74??E8????????598D??????51E8????????8B??598D??????E8????????6A??33??8D??????E8????????6A??8D??????E8????????83????8D??????8B??50E8????????E8????????83????E9????????E8????????8B??598D??????E8????????6A??33??8D??????E8????????8D????????????50FF??????????508D??????E8????????8B??????6A??5F39??????73??8D??????8B??????????68????????50FF??85??0F84????????8B??????39??????73??8D??????68????????50FF??85??0F84????????8B??????39??????73??8D??????68????????50FF??85??0F84????????8B??????39??????73??8D??????68????????50FF??85??0F84????????8B??????39??????73??8D??????68????????50FF??85??0F84????????8B??????39??????73??8D??????68????????50FF??85??0F84????????8B??????39??????73??8D??????68????????50FF??85??0F84????????8B??????39??????73??8D??????68????????50FF??85??0F84????????8B??????39??????73??8D??????68????????50FF??85??0F84????????8B??????39??????73??8D??????68????????50FF??85??0F84????????8B??????39??????73??8D??????68????????50FF??85??0F84????????8B??????39??????73??8D??????68????????50FF??85??0F84????????8B??????39??????73??8D??????68????????50FF??85??0F84????????8B??????39??????73??8D??????68????????50FF??85??0F84????????8B??????39??????73??8D??????68????????50FF??85??74??8B??????39??????73??8D??????68????????50FF??85??74??83????8B??68????????E8????????83????8D????????????8B??51E8????????E8????????83????85??75??8B??????39??????73??8D??????83????8B??51E8????????E8????????83????6A??33??8D??????E8????????8D????????????50FF??????FF??????????85??0F85????????FF??????FF??????????33??435333??8D?????? }


   condition:
   
      uint16(0) == 0x5a4d and
      filesize < 1500KB and
      $pattern
}

rule purelocker_ransomware {

        meta:
              
              description = "Rule to detect PureLocker ransomware based on binary sequences"
              author = "Marc Rivero | McAfee ATR Team"
              date = "2019-11-13"
              rule_version = "v1"
              malware_type = "ransomware"
              malware_family = "Ransom:W32/PureLocker"
              actor_type = "Cybercrime"
              actor_group = "Unknown"
              reference = "https://www.pandasecurity.com/mediacenter/security/purelocker-ransomware-servers/"
              
              
        strings:
        
            $sequence = { 31??FF????E8????????83????5BC2????555357BA????????83????C7????????????4A75??E8????????8B????????????8D????E8????????8B????????????8D??????E8????????FF????8D??????????59E8????????75??FF??????8D??????????59E8????????75??EB??B8????????EB??31??21??74??31??0FBE??E9????????8D??????C7????????????C7????????????66??????????FF??????E8????????89??????52E8????????5A5052E8????????5A50FF??????E8????????8D????????????50E8????????8B??????01??89??????8B??????83????53E8????????89??????8B??????21??75??31??0FBE??E9????????68????????68????????FF????????????FF??????E8????????FF????E8????????89??01??89????????????8B????????????83????53E8????????89????????????8B????????????21??75??FF??????E8????????31??0FBE??E9????????68????????68????????FF??????FF????????????E8????????0FBE??????????83????0F85????????8B??????83????53E8????????89????????????8B????????????21??75??E9????????68????????68????????FF??????FF????????????E8????????FF??????E8????????68????????8D??????508D??????5068????????68????????68????????31??5068????????68????????FF????????????FF????????????68????????E8????????89??????8B??????21??75??31??0FBE??E9????????8D??????FF????E8????????8D??????FF????E8????????FF????????????E8????????FF????????????E8????????B8????????0FBE??E9????????EB??68????????8D??????508D??????5068????????68????????68????????31??5068????????68????????FF??????FF????????????68????????E8????????89??????8B??????21??75??31??0FBE??E9????????8D??????508D??????FF????E8????????89????????????FF??????E8????????C7??????????????FF????????????E8????????C7????????????????????C7????????????????????8B????????????21??74??E9????????0FBE????????????83????75??68????????68????????8D????????????5068????????8D??????FF????E8????????89??????EB??68????????68????????8D????????????5068????????8D??????FF????E8????????89??????8B??????21??74??E9????????0FBE????????????83????75??8D????????????8D????FF????FF??8F??????8F??????EB??8D????????????8B????9952508F??????8F??????FF??????FF??????5B5F83????7F??7C??83????77??31??EB??B8????????09??75??E9????????0FBE????????????83????75??68????????E8????????89????????????8B????????????21??75??E9????????68????????68????????68????????FF????????????FF????????????FF????????????8D??????FF????E8????????89????????????EB??68????????E8????????89??????8B??????21??75??E9????????68????????68????????FF??????8B????????????508D??????FF????E8????????89????????????8B????????????21??74??E9????????0FBE????????????83????75??8B????????????21??75??E9????????8B????????????8D????FF????FF??5B5F83????75??83????74??31??EB??B8????????09??74??E9????????EB??8B??????21??75??E9????????8B??????8B????21??75??E9????????0FBE????????????83????75??C7????????????????????FF????????????E8????????89????????????C7????????????????????68????????68????????FF????????????FF????????????8B????????????8D????FF????FF??8D??????FF????E8????????89????????????EB??C7????????????????????FF????????????E8????????89????????????C7????????????????????68????????FF????????????FF????????????8B????????????FF????8D??????FF????E8????????89????????????8B????????????21??74??E9????????0FBE????????????83????75??8B????????????21??7E??68????????68????????FF????????????E8????????FF????????????E8????????C7????????????????????EB??8B??????21??7E??68????????68????????FF??????E8????????FF??????E8????????C7??????????????0FBE????????????83????75??8B????????????21??75??E9????????8B????????????8D????89??21??75??E9????????EB??8B????????????21??75??E9????????8B????????????8D????89??21??75??E9????????8B??????83????53E8????????89????????????8B????????????21??75??E9????????68????????68????????FF??????FF????????????E8????????0FBE????????????83????75??68????????68????????FF??????FF????????????8B????????????8D????FF????FF??8D??????FF????E8????????89????????????EB??68????????FF??????FF????????????8B????????????FF????8D??????FF????E8????????89????????????FF????????????E8????????C7????????????????????0FBE????????????83????75??68????????68????????FF????????????E8????????FF????????????E8????????C7????????????????????EB??68????????68????????FF????????????E8????????FF????????????E8????????C7????????????????????8B????????????21??74??EB??68????????8D??????FF????E8????????89????????????8B????????????21??74??EB??0FBE????????????83????75??68????????31??508D??????FF????E8????????C6????????8D??????FF????E8????????8D??????FF????E8????????0FBE??????0FBE??E9????????8B????????????21??7E??FF????????????E8????????8B????????????21??7E??FF????????????E8????????8B????????????21??7E??FF????????????E8????????8B??????21??7E??FF??????E8????????8B????????????21??7E??FF????????????E8????????8D??????8B????21??7E??68????????8D??????FF????E8????????8D??????8B????21??7E??8D??????FF????E8????????8D??????8B????21??7E??8D??????FF????E8????????31??0FBE??EB??31??FF????E8????????FF????????????E8????????FF??????E8????????81??????????5F5B5DC2????31??50E8????????83????????????74??FF??????????5889????FF??????FF??????FF??????FF??????EB??EB??B8????????EB??31??83????C2????31??C2????5553BA????????83????C7????????????4A75??E8????????8B??????8D????E8????????83????????????0F84????????FF????E8????????89??01??89??????8B??????83????53E8????????89??????83????????74??68????????68????????FF??????FF??????E8????????89??3B??????75??8B??????83????538D??????5866??????FF??????5866??????FF??????5889????FF??????????5889??????8D??????508D??????5068????????68????????FF??????89??21??75??FF??????5889??????FF??????E8????????8B??????EB??31??FF????E8????????83????5B5DC2????31??50E8????????83????????????74??FF??????????5889????FF??????FF??????FF??????FF??????EB??EB??B8????????EB??31??83????C2????31??5050E8????????FF??????E8????????52E8????????5A50FF??????????8D??????????50E8????????8D??????50E8????????52E8????????5A5052E8????????5A50FF??????????8D??????????50E8????????E8????????01????E8????????8D??????50E8????????FF????8D??????????59E8????????74??52E8????????5A5052E8????????5A50FF??????????8D??????????50E8????????E8????????01????E8????????52E8????????5A5052E8????????5A50FF??????????8D??????????50E8????????E8????????01????E8????????588B??????52E8????????8D??????50E8????????EB??8B????52E8????????5A5052E8????????8B??????52E8????????8D??????50E8????????8B????52E8????????5A5052E8????????5850E8????????5A01??EB??E8????????66????????FF????E8????????FF??????E8????????83????C331??50E8????????83????????????74??FF??????????5889????FF??????FF??????FF??????FF??????FF??????FF??????FF??????FF??????FF??????FF??????FF??????EB??EB??B8????????EB??31??83????C2????555331??50505050E8????????C7??????????????FF??????E8????????89????8B????21??75??31??EB??8D??????50FF??????FF??????68????????E8????????89??21??75??8B????FF????5889??????68????????68????????FF??????E8????????FF????E8????????8B??????EB??31??83????5B5DC35331??50505050E8????????8B??????8D????E8????????FF????E8????????89??????8B??????83????53E8????????89??????83????????74??68????????FF??????FF??????FF??????E8????????21??74??FF??????FF??????68????????E8????????89??F7??89??????FF??????E8????????8B??????EB??31??FF????E8????????83????5BC2????31??50E8????????83????????????74??FF??????????5889????FF??????FF??????FF??????FF??????FF??????FF??????EB??EB??B8????????EB??31??83????C2????5553BA????????83????C7????????????4A75??E8????????8B??????8D????E8????????FF????8D??????????59E8????????74??31??E9????????52E8????????5A50FF??????????8D??????????50E8????????8B??????52E8????????8D??????50E8????????FF??????E8????????89??01??89??????8B??????83????53E8????????89??????83????????0F84????????68????????68????????FF??????FF??????E8????????89??3B??????0F85????????FF??????8D??????5866??????8B??????83????535866??????FF??????5889????C7??????????????8D??????????8D??????E8????????8D??????C7????????????C7????????????8D??????505889????68????????68????????8D??????508D??????5068????????8D??????50E8????????89??21??75??8B??????21??7E??B8????????EB??31??21??74??FF??????E8????????C7??????????????68????????68????????8D??????508D??????50FF??????E8????????89??21??75??8D??????FF????5889??????FF??????E8????????8B??????21??7E??FF??????E8????????8B??????EB??31??FF??????E8????????FF????E8????????83????5B5DC2????555357BA????????83????C7???????????? }
        
        condition:
        
          uint16(0) == 0x5a4d and
          filesize < 300KB and
          all of them
    }

rule Robbinhood_ransomware {

   meta:

      description = "Robbinhood GoLang ransowmare"
      author = "Christiaan Beek | McAfee ATR"
      date = "2019-05-10"
      rule_version = "v1"
      malware_type = "ransomware"
      malware_family = "Ransom:W32/Robbinhood"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      hash = "9977ba861016edef0c3fb38517a8a68dbf7d3c17de07266cfa515b750b0d249e"
 
   strings:

      $s1 = ".enc_robbinhood" nocase
      $s2 = "sc.exe stop SQLAgent$SQLEXPRESS" nocase
      $s3 = "pub.key" nocase
      $s4 = "main.EnableShadowFucks" nocase
      $s5 = "main.EnableRecoveryFCK" nocase
      $s6 = "main.EnableLogLaunders" nocase
      $s7 = "main.EnableServiceFuck" nocase
     

      $op0 = { 8d 05 2d 98 51 00 89 44 24 30 c7 44 24 34 1d }
      $op1 = { 8b 5f 10 01 c3 8b 47 04 81 c3 b5 bc b0 34 8b 4f }
      $op2 = { 0f b6 34 18 8d 7e d0 97 80 f8 09 97 77 39 81 fd }

   condition:

      ( uint16(0) == 0x5a4d and
      filesize < 3000KB and
      ( 1 of ($s*) ) and
      all of ($op*)) or 
      ( all of them )
}


rule Ryuk_Ransomware {

   meta:

      description = "Ryuk Ransomware hunting rule"
      author = "Christiaan Beek - McAfee ATR team"
      date = "2019-04-25"
      rule_version = "v2"
      malware_type = "ransomware"
      malware_family = "Ransom:W32/Ryuk"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      reference = "https://securingtomorrow.mcafee.com/other-blogs/mcafee-labs/ryuk-ransomware-attack-rush-to-attribution-misses-the-point/"
      
   
   strings:

      $x1 = "C:\\Windows\\System32\\cmd.exe" fullword ascii
      $x2 = "\\System32\\cmd.exe" fullword wide
      $s1 = "C:\\Users\\Admin\\Documents\\Visual Studio 2015\\Projects\\ConsoleApplication54new crypted" ascii
      $s2 = "fg4tgf4f3.dll" fullword wide
      $s3 = "lsaas.exe" fullword wide
      $s4 = "\\Documents and Settings\\Default User\\sys" fullword wide
      $s5 = "\\Documents and Settings\\Default User\\finish" fullword wide
      $s6 = "\\users\\Public\\sys" fullword wide
      $s7 = "\\users\\Public\\finish" fullword wide
      $s8 = "You will receive btc address for payment in the reply letter" fullword ascii
      $s9 = "hrmlog" fullword wide
      $s10 = "No system is safe" fullword ascii
      $s11 = "keystorage2" fullword wide
      $s12 = "klnagent" fullword wide
      $s13 = "sqbcoreservice" fullword wide
      $s14 = "tbirdconfig" fullword wide
      $s15 = "taskkill" fullword wide

      $op0 = { 8b 40 10 89 44 24 34 c7 84 24 c4 }
      $op1 = { c7 44 24 34 00 40 00 00 c7 44 24 38 01 }
    
   condition:

      ( uint16(0) == 0x5a4d and
      filesize < 400KB and
      ( 1 of ($x*) and
      4 of them ) and
      all of ($op*)) or
      ( all of them )
}

rule Ransom_Ryuk_sept2020 {
   meta:
      description = "Detecting latest Ryuk samples"
      author = "McAfe ATR"
      date = "2020-10-13"
       malware_type = "ransomware"
      malware_family = "Ransom:W32/Ryuk"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      hash1 = "cfdc2cb47ef3d2396307c487fc3c9fe55b3802b2e570bee9aea4ab1e4ed2ec28"
   strings:
      $x1 = "\" /TR \"C:\\Windows\\System32\\cmd.exe /c for /l %x in (1,1,50) do start wordpad.exe /p " fullword ascii
      $x2 = "cmd.exe /c \"bcdedit /set {default} recoveryenabled No & bcdedit /set {default}\"" fullword ascii
      $x3 = "cmd.exe /c \"bootstatuspolicy ignoreallfailures\"" fullword ascii
      $x4 = "cmd.exe /c \"vssadmin.exe Delete Shadows /all /quiet\"" fullword ascii
      $x5 = "C:\\Windows\\System32\\cmd.exe" fullword ascii
      $x6 = "cmd.exe /c \"WMIC.exe shadowcopy delete\"" fullword ascii
      $x7 = "/C REG ADD \"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"EV\" /t REG_SZ /d \"" fullword wide
      $x8 = "W/C REG DELETE \"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"EV\" /f" fullword wide
      $x9 = "\\System32\\cmd.exe" fullword wide
      $s10 = "Ncsrss.exe" fullword wide
      $s11 = "lsaas.exe" fullword wide
      $s12 = "lan.exe" fullword wide
      $s13 = "$WGetCurrentProcess" fullword ascii
      $s14 = "\\Documents and Settings\\Default User\\sys" fullword wide
      $s15 = "Ws2_32.dll" fullword ascii
      $s16 = " explorer.exe" fullword wide
      $s17 = "e\\Documents and Settings\\Default User\\" fullword wide
      $s18 = "\\users\\Public\\" fullword ascii
      $s19 = "\\users\\Public\\sys" fullword wide
      $s20 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\" fullword ascii

      $seq0 = { 2b c7 50 e8 30 d3 ff ff ff b6 8c }
      $seq1 = { d1 e0 8b 4d fc 8b 14 01 89 95 34 ff ff ff c7 45 }
      $seq2 = { d1 e0 8b 4d fc 8b 14 01 89 95 34 ff ff ff c7 45 }
   condition:
      ( uint16(0) == 0x5a4d and 
      filesize < 400KB and 
      ( 1 of ($x*) and 5 of them ) and 
      all of ($seq*)) or ( all of them )
}

rule RANSOM_RYUK_May2021 : ransomware
{
	meta:
		description = "Rule to detect latest May 2021 compiled Ryuk variant"
		author = "Marc Elias | McAfee ATR Team"
		date = "2021-05-21"
		hash = "8f368b029a3a5517cb133529274834585d087a2d3a5875d03ea38e5774019c8a"
		version = "0.1"

	strings:
		$ryuk_filemarker = "RYUKTM" fullword wide ascii
		
		$sleep_constants = { 68 F0 49 02 00 FF (15|D1) [0-4] 68 ?? ?? ?? ?? 6A 01 }
		$icmp_echo_constants = { 68 A4 06 00 00 6A 44 8D [1-6] 5? 6A 00 6A 20 [5-20] FF 15 }
		
	condition:
		uint16(0) == 0x5a4d
		and uint32(uint32(0x3C)) == 0x00004550
		and filesize < 200KB
		and ( $ryuk_filemarker
		or ( $sleep_constants 
		and $icmp_echo_constants ))
}

rule Sodinokobi
{
    meta:

        description = "This rule detect Sodinokobi Ransomware in memory in old samples and perhaps future."
        author      = "McAfee ATR team"
        rule_version = "v1"
        malware_type = "ransomware"
        malware_family = "Ransom:W32/Sodinokibi"
        actor_type = "Cybercrime"
        actor_group = "Unknown"
        version     = "1.0"
        
    strings:

        $a = { 40 0F B6 C8 89 4D FC 8A 94 0D FC FE FF FF 0F B6 C2 03 C6 0F B6 F0 8A 84 35 FC FE FF FF 88 84 0D FC FE FF FF 88 94 35 FC FE FF FF 0F B6 8C 0D FC FE FF FF }
        $b = { 0F B6 C2 03 C8 8B 45 14 0F B6 C9 8A 8C 0D FC FE FF FF 32 0C 07 88 08 40 89 45 14 8B 45 FC 83 EB 01 75 AA }

    condition:
    
        all of them
}
