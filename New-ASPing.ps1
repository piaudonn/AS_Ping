$DCIp = "10.0.0.4" #Use the IP address of the domain controller
$username = "q" #Use the samaccount name of the user account
$NetbiosDomainName = "P" #Use the domain name

# Don't change stuff after this...
$ServerName = "KRB_AS_PROBING_E"
$username_b = [System.Text.Encoding]::UTF8.GetBytes($username)
$NetbiosDom_b = [System.Text.Encoding]::UTF8.GetBytes($NetbiosDomainName)

Write-Output "[+] Crafting KRB_AS_REQ ping for $NetbiosDomainName\$username"
$AS_REQ  = 0x00, 0x00, 0x00, ( 0xC4 + $username_b.Length + $NetbiosDom_b.Length * 2 )
$AS_REQ += 0x6A, 0x81, (0xC1 + $username_b.Length + $NetbiosDom_b.Length * 2)
$AS_REQ += 0x30, 0x81, (0xBE + $username_b.Length + $NetbiosDom_b.Length * 2)
$AS_REQ += 0xA1, 0x03, 0x02, 0x01, 0x05, 0xA2, 0x03, 0x02, 0x01, 0x0A, 0xA3, 0x15, 0x30, 0x13, 0x30, 0x11, 0xA1, 0x04, 0x02, 0x02, 0x00, 0x80, 0xA2, 0x09, 0x04, 0x07, 0x30, 0x05, 0xA0, 0x03, 0x01, 0x01, 0xFF, 0xA4, 0x81, (0x9A + $username_b.Length + $NetbiosDom_b.Length * 2 )
$AS_REQ += 0x30, 0x81, (0x97 + $username_b.Length + $NetbiosDom_b.Length * 2 )
$AS_REQ += 0xA0, 0x07, 0x03, 0x05, 0x00, 0x40, 0x81, 0x00, 0x10, 0xA1, (0x0D + $username_b.Length )
$AS_REQ += 0x30, (0x0B + $username_b.Length )
$AS_REQ += 0xA0, 0x03, 0x02, 0x01, 0x01, 0xA1, ( 0x04 + $username_b.Length )
$AS_REQ += 0x30, ( 0x02 + $username_b.Length )
$AS_REQ += 0x1B, $username_b.Length
$AS_REQ += $username_b 
$AS_REQ += 0xA2, ( 0x02 + $NetbiosDom_b.Length )
$AS_REQ += 0x1B, $NetbiosDom_b.Length
$AS_REQ += $NetbiosDom_b
$AS_REQ += 0xA3, ( 0x15 + $NetbiosDom_b.Length )
$AS_REQ += 0x30, ( 0x13 + $NetbiosDom_b.Length )
$AS_REQ += 0xA0, 0x03, 0x02, 0x01, 0x02, 0xA1, (0x0C + $NetbiosDom_b.Length )
$AS_REQ += 0x30, ( 0x0A + $NetbiosDom_b.Length )
$AS_REQ += 0x1B, 0x06, 0x6B, 0x72, 0x62, 0x74, 0x67, 0x74 #krbtgt
$AS_REQ += 0x1B, $NetbiosDom_b.Length
$AS_REQ += $NetbiosDom_b
$AS_REQ += 0xA5, 0x11, 0x18, 0x0F
$AS_REQ += 0x32, 0x30, 0x33, 0x37, 0x30, 0x39, 0x31, 0x33, 0x30, 0x32, 0x34, 0x38, 0x30, 0x35, 0x5A#BOGUS DATE
$AS_REQ += 0xA6, 0x11, 0x18, 0x0F 
$AS_REQ += 0x32, 0x30, 0x33, 0x37, 0x30, 0x39, 0x31, 0x33, 0x30, 0x32, 0x34, 0x38, 0x30, 0x35, 0x5A#BOGUS DATE
$AS_REQ += 0xA7, 0x06, 0x02, 0x04
$AS_REQ += 0x01, 0x02, 0x03, 0x04 #Not so random nonce
$AS_REQ += 0xA8, 0x15, 0x30, 0x13, 0x02, 0x01, 0x12, 0x02, 0x01, 0x11, 0x02, 0x01, 0x17, 0x02, 0x01, 0x18, 0x02, 0x02, 0xFF, 0x79, 0x02, 0x01, 0x03, 0xA9, 0x1D, 0x30, 0x1B, 0x30, 0x19, 0xA0, 0x03, 0x02, 0x01, 0x14, 0xA1, 0x12, 0x04, 0x10
$AS_REQ += [System.Text.Encoding]::UTF8.GetBytes($ServerName)

Write-Output "[+] Opening TCP socket to $DCIp port 88"
$tcp = New-Object System.Net.Sockets.TcpClient
$tcp.Connect($DCIp, 88)
$stream = $tcp.GetStream()
try {
    $stream.Write($AS_REQ, 0, $AS_REQ.Length)
}
catch {
    Write-Output "[-] Cannot send the request to $DCIp"
    break
}
$buffer = New-Object byte[] 1024  # Adjust the buffer size as needed
$responseLength = $stream.Read($buffer, 0, $buffer.Length)
Write-Output "[+] Closing TCP socket"
$stream.Close()
$tcp.Close()

$AS_REP = $buffer[4..(4+$buffer[3]-1)]
if ( $AS_REP[15] -eq 30 )
{
    Write-Output "[+] Parsing KDC_ERR_PREAUTH_REQUIRED"
} else {
    $message = ""
    switch ($AS_REP[44])
    {
        0x6  { $message = "KDC_ERR_C_PRINCIPAL_UNKNOWN" }
        0x3D { $message = "KRB_ERR_FIELD_TOOLONG" }
        0x44 { $message = "KDC_ERR_WRONG_REALM" }
    }
    Write-Output "[-] 0x$($AS_REP[15].ToString("X")) - $message"
    break
}

$Etype1 = $AS_REP[99 + $NetbiosDom_b.Length * 2]
if ($Etype1 -eq 18)
{
    Write-Output "[+] User has AES keys"
    $Salt = $AS_REP[(104 + $NetbiosDom_b.Length * 2) .. (104 +$NetbiosDom_b.Length * 2 + $AS_REP[103 + $NetbiosDom_b.Length * 2] - 1)]
    Write-Output "[+] AES Salt = $([System.Text.Encoding]::UTF8.GetString($Salt))"
} elseif ($Etype1 -eq 23) {
    Write-Output "[+] User only has RC4 keys"
}
