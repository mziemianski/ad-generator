<#
.SYNOPSIS
    Skrypt do zarządzania użytkownikami i grupami Active Directory oraz uprawnieniami NTFS i udziałami sieciowymi.

.DESCRIPTION
    Ten skrypt automatyzuje tworzenie i zarządzanie kontami użytkowników, grupami, jednostkami organizacyjnymi (OU), 
    katalogami domowymi oraz udziałami sieciowymi na serwerze plików. 
    Umożliwia również naprawę kont użytkowników, resetowanie haseł, wymuszanie zmiany haseł, 
    zarządzanie uprawnieniami NTFS oraz kontrolę dostępu do udziałów.
    
    Skrypt obsługuje polskie znaki w nazwach użytkowników, loguje wszystkie operacje do pliku logów oraz oferuje interaktywne menu.
    Wspiera zarządzanie uprawnieniami na poziomie grup oraz katalogów, a także konfigurację Access Based Enumeration (ABE).

.PARAMETER Settings.xml
    Plik konfiguracyjny XML zawierający ustawienia środowiska, ścieżki do udziałów, domyślne hasła, lokalizacje plików CSV itp.

.PARAMETER users.txt
    Plik CSV z danymi użytkowników do importu i generowania kont w Active Directory.

.PARAMETER dzialy.txt
    Plik CSV z danymi grup i jednostek organizacyjnych do tworzenia struktur w Active Directory.

.EXAMPLE
    Uruchomienie skryptu:
    .\Generator.ps1

    Po uruchomieniu skrypt wyświetla interaktywne menu do wyboru operacji.

.NOTES
    Wersja: 34.0.0
    Data: 2025-08-01
    Autor: Marcin Ziemiański
	Wersja z Roaming Profiles - Działająca
	PowerShell z modułem ActiveDirectory, uprawnienia administratora domeny, dostęp do serwera plików.
	

## [33.0.0] 2025-07-27 ### Dodano obsługę suffixów AD
## [34.0.0] 2025-08-01 ### Poprawiono poziomy logowania
#>


try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}

Import-Module ActiveDirectory

# [xml]$settings = Get-Content -Path "Settings.xml" -Raw
$SettingsPath = Join-Path $PSScriptRoot "Settings.xml"
[xml]$settings = Get-Content -Path $SettingsPath -Raw


$FileServer = $settings.Settings.FileServer
$Install_OU_Name = $settings.Settings.Install_OU
$Komputery_OU_Name = $settings.Settings.Komputery_OU
$DefaultPassword = $settings.Settings.DefaultPassword
$LogFilePath = $settings.Settings.LogFilePath
$UsersFilePath = $settings.Settings.UsersFilePath
$GroupsFilePath = $settings.Settings.GroupsFilePath
$HomeShare = $settings.Settings.Home
$SkanyShare = $settings.Settings.Skany
$DzialyShare = $settings.Settings.Dzialy
$OgolnyShare = $settings.Settings.Ogolny
$MissedUsersLogPath = $settings.Settings.MissedUsersLogPath
$ProfilesShare = $settings.Settings.PROFILES
$EnableRoamingProfiles = $false
$global:SessionUPNSuffix = $null

if ($ProfilesShare.RoammingProfiles -eq "True") { $EnableRoamingProfiles = $true }


$DefaultNamingConvention = 1
if ($settings.Settings.DefaultNamingConvention) {
    $DefaultNamingConvention = [int]$settings.Settings.DefaultNamingConvention
}

function Log-Operation {
    param(
        [string]$Message,
        [string]$Level = "INFO",
        [string]$Category = "",
        [switch]$FileOnly
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $callStack = Get-PSCallStack
    $callerFunction = if ($callStack.Count -gt 1) { $callStack[1].FunctionName } else { "Global" }
    $debugEnabled = $false
    try {
        $debugEnabled = ($settings.Settings.ExtendedDebugLogging -eq "true")
    }
    catch {}

    if ($Level -eq "DEBUG" -and -not $debugEnabled) {
        return
    }

    $logEntry = if ($Category -ne "") {
        "$timestamp [$Level][$Category][$callerFunction] $Message"
    }
    else {
        "$timestamp [$Level][$callerFunction] $Message"
    }

    Add-Content -Path $LogFilePath -Value $logEntry -Encoding UTF8

    if (-not $FileOnly) {
        switch ($Level) {
            "ERROR" { Write-Host $logEntry -ForegroundColor Red }
            "WARN" { Write-Host $logEntry -ForegroundColor Yellow }
            "OK" { Write-Host $logEntry -ForegroundColor Green }
            "DEBUG" { Write-Host $logEntry -ForegroundColor DarkGray }
            default { Write-Host $logEntry -ForegroundColor Gray }
        }
    }
}


function Log-SkippedUser {
    param(
        [string]$UserInfo,
        [string]$Reason
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "$timestamp | $UserInfo | $Reason"

    # Komunikat o próbie logowania pominiętego użytkownika
    Write-Host "LOG SKIPPED USER: $entry" -ForegroundColor Yellow

    if ($MissedUsersLogPath) {
        try {
            Add-Content -Path $MissedUsersLogPath -Value $entry -Encoding UTF8
            Write-Host "Zapisano pominiętego użytkownika do pliku: $MissedUsersLogPath" -ForegroundColor Green
        }
        catch {
            Write-Host "BŁĄD zapisu pominiętego użytkownika do pliku: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    else {
        Write-Host "Ścieżka do pliku pominiętych użytkowników (MissedUsersLogPath) nie jest ustawiona!" -ForegroundColor Red
    }
}

function Remove-PolishChars($text) {
    $pl = 'ąćęłńóśźżĄĆĘŁŃÓŚŹŻ'
    $en = 'acelnoszzACELNOSZZ'
    $sb = New-Object System.Text.StringBuilder
    foreach ($c in $text.ToCharArray()) {
        $i = $pl.IndexOf($c)
        if ($i -ge 0) { $null = $sb.Append($en[$i]) }
        else { $null = $sb.Append($c) }
    }
    $sb.ToString()
}

function Select-UPNSuffix {
    param ([string[]]$Suffixes)
    if ($Suffixes.Count -eq 1) { return $Suffixes[0] }
###    Write-Host "Dostępne sufiksy UPN:"
	Log-Operation "Dostępne sufiksy UPN:" "INFO" "UPN"
    for ($i=0; $i -lt $Suffixes.Count; $i++) { Write-Host "$($i+1). $($Suffixes[$i])" }
    while ($true) {
        $choice = Read-Host "Wybierz numer sufiksu UPN"
        if ($choice -match "^\d+$" -and $choice -ge 1 -and $choice -le $Suffixes.Count) {
            return $Suffixes[$choice - 1]
        }
###        Write-Host "Błędny wybór."
		Log-Operation "Błędny wybór." "WARN" "UPN"
    }
}


function Get-Username($imie, $nazwisko, $konwencja) {
    $imie = Remove-PolishChars($imie).ToLower()
    $nazwisko = Remove-PolishChars($nazwisko).ToLower()
    switch ($konwencja) {
        1 { return ($imie[0] + $nazwisko) }
        2 { return ($imie[0] + '.' + $nazwisko) }
        3 { return ($imie + '.' + $nazwisko) }
        4 { return ($imie + '_' + $nazwisko) }
        default { return ($imie[0] + $nazwisko) }
    }
}

function Import-UserCsv($Path) {
    Import-Csv -Path $Path -Delimiter ';' -Encoding UTF8
}

function Log-NTFS-ACL($Path) {
    $acl = Get-Acl -Path $Path
    $inheritance = if ($acl.AreAccessRulesProtected) { "DZIEDZICZENIE WYŁĄCZONE" } else { "DZIEDZICZENIE WŁĄCZONE" }
    Log-Operation "NTFS: $Path - $inheritance" "OK" "NTFS"
    foreach ($ace in $acl.Access) {
        $perm = $ace.FileSystemRights
        $type = $ace.AccessControlType
        $ident = $ace.IdentityReference
        $inh = if ($ace.IsInherited) { "dziedziczone" } else { "BEZPOŚREDNIE" }
        $prop = $ace.PropagationFlags
        $inhFlags = $ace.InheritanceFlags
        Log-Operation "NTFS: $Path - $ident $type $perm [$inh] InheritanceFlags:$inhFlags PropagationFlags:$prop" "OK" "NTFS"
    }
}

function Reset-NTFSPermissions {
    param([string]$Path)

    try {
        $acl = Get-Acl -Path $Path
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($ace in @($acl.Access)) { $acl.RemoveAccessRule($ace) }

        # Ustal nazwę grupy Domain Admins w formacie domenowym
        $adDomain = Get-ADDomain
        $domainAdminsGroup = "$($adDomain.NetBIOSName)\Domain Admins"

        # Ustal czy to katalog PROFILES
        $isProfiles = $false
        if ($ProfilesShare -and $ProfilesShare.Local -and ($Path -ieq $ProfilesShare.Local -or $Path -ieq $ProfilesShare.AdminUNC)) {
            $isProfiles = $true
        }

        if ($isProfiles) {
            # SYSTEM: Full Control, This folder, subfolders and files
            $ruleSystem = New-Object System.Security.AccessControl.FileSystemAccessRule(
                "NT AUTHORITY\SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
            $acl.AddAccessRule($ruleSystem)

            # Administrators: Full Control, This folder only
            $adminSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
            $adminUser = $adminSid.Translate([System.Security.Principal.NTAccount]).Value
            $ruleAdmins = New-Object System.Security.AccessControl.FileSystemAccessRule(
                $adminUser, "FullControl", "None", "None", "Allow")
            $acl.AddAccessRule($ruleAdmins)

            # Domain Admins: Full Control, This folder, subfolders and files
            $ruleDomainAdmins = New-Object System.Security.AccessControl.FileSystemAccessRule(
                $domainAdminsGroup, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
            $acl.AddAccessRule($ruleDomainAdmins)

            # CREATOR OWNER: Full Control, Subfolders and files only
            $ruleCreator = New-Object System.Security.AccessControl.FileSystemAccessRule(
                "CREATOR OWNER", "FullControl", "ContainerInherit,ObjectInherit", "InheritOnly", "Allow")
            $acl.AddAccessRule($ruleCreator)

            # Grupa użytkowników (np. "Domain Users" lub dedykowana grupa profili): List Folder/Read Data, Create Folders/Append Data - This folder only
            # Domyślnie "Authenticated Users" – możesz zastąpić własną grupą jeśli masz dedykowaną
            $ruleUsers = New-Object System.Security.AccessControl.FileSystemAccessRule(
                "Authenticated Users", "ListDirectory,ReadData,CreateDirectories,AppendData", "None", "None", "Allow")
            $acl.AddAccessRule($ruleUsers)

            # Everyone: Brak uprawnień (nie dodawaj reguły)
        }
        else {
            # Standardowe uprawnienia dla pozostałych udziałów (przykład)
            $ruleAdmin = New-Object System.Security.AccessControl.FileSystemAccessRule(
                "BUILTIN\Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
            $acl.AddAccessRule($ruleAdmin)
            $ruleAuth = New-Object System.Security.AccessControl.FileSystemAccessRule(
                "NT AUTHORITY\Authenticated Users", "ReadAndExecute", "None", "None", "Allow")
            $acl.AddAccessRule($ruleAuth)
        }

        Set-Acl -Path $Path -AclObject $acl
        Log-NTFS-ACL $Path

        # Wyłącz dziedziczenie i zabezpiecz ACL
        ###$acl.SetAccessRuleProtection($false, $true)
        ###Set-Acl -Path $Path -AclObject $acl
    }
    catch {
        Log-Operation ("Błąd przy ustawianiu uprawnień NTFS na " + $Path + ": " + $_.Exception.Message) "ERROR" "NTFS"
    }
}


function Set-UserHomeOrSkanyPermissions {
    param([string]$Path, [string]$UserSam, [string]$DomainNetbios, [string]$LogPrefix)
    try {
        $acl = Get-Acl -Path $Path
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($ace in @($acl.Access)) { $acl.RemoveAccessRule($ace) }
        $adminSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
        $adminUser = $adminSid.Translate([System.Security.Principal.NTAccount]).Value
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($adminUser, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")))
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("CREATOR OWNER", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")))
        $userFqdn = "$DomainNetbios\$UserSam"
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($userFqdn, "Modify", "ContainerInherit,ObjectInherit", "None", "Allow")))
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($userFqdn, "Delete", "None", "None", "Deny")))
        Set-Acl -Path $Path -AclObject $acl
        Log-NTFS-ACL $Path
        $acl = Get-Acl -Path $Path
        $acl.SetAccessRuleProtection($false, $false)
        Set-Acl -Path $Path -AclObject $acl
    }
    catch {
        Log-Operation ("Błąd podczas ustawiania uprawnień na " + $Path + ": " + $_.Exception.Message) "ERROR" "NTFS"
    }
}

function Set-NTFSPermissions {
    param(
        [string]$Path,
        [array]$FullControlGroups,
        [array]$ReadGroups,
        [array]$DenyDeleteGroups,
        [array]$DenyAllGroups = @(),
        [array]$ExtraAccess = @(),
        [string]$LogPrefix = "NTFS"
    )
    try {
        $adDomain = Get-ADDomain
        $domainNetbios = $adDomain.NetBIOSName
        $acl = Get-Acl -Path $Path
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($ace in @($acl.Access)) { $acl.RemoveAccessRule($ace) }
        foreach ($group in $FullControlGroups) {
            $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                        "$domainNetbios\$group", "Modify", "ContainerInherit,ObjectInherit", "None", "Allow")))
        }
        foreach ($group in $ReadGroups) {
            $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                        "$domainNetbios\$group", "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow")))
        }
        foreach ($group in $DenyDeleteGroups) {
            $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                        "$domainNetbios\$group", "Delete", "None", "None", "Deny")))
        }
        foreach ($group in $DenyAllGroups) {
            $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                        "$domainNetbios\$group", "FullControl", "ContainerInherit,ObjectInherit", "None", "Deny")))
        }
        foreach ($entry in $ExtraAccess) {
            $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                        $entry, "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow")))
        }
        Set-Acl -Path $Path -AclObject $acl
        Log-NTFS-ACL $Path
        $acl.SetAccessRuleProtection($false, $true)
        Set-Acl -Path $Path -AclObject $acl
    }
    catch {
        Log-Operation ("Błąd podczas ustawiania uprawnień na " + $Path + ": " + $_.Exception.Message) "ERROR" "NTFS"
    }
}

function Ensure-RemoteShare {
    param([string]$ShareName, [string]$LocalPath, [string]$FileServer)
    try {
        Log-Operation ("Sprawdzanie katalogu $LocalPath i udziału $ShareName na $FileServer...") "INFO" "FILE SERVER"
        $exists = Invoke-Command -ComputerName $FileServer -ScriptBlock {
            param($ShareName, $LocalPath)
            $dirExists = Test-Path $LocalPath
            $shareExists = Get-SmbShare -Name $ShareName -ErrorAction SilentlyContinue
            return @{ Dir = $dirExists; Share = $shareExists -ne $null }
        } -ArgumentList $ShareName, $LocalPath

        if (-not $exists.Dir) {
            Invoke-Command -ComputerName $FileServer -ScriptBlock {
                param($LocalPath)
                New-Item -Path $LocalPath -ItemType Directory | Out-Null
            } -ArgumentList $LocalPath
        }

        if (-not $exists.Share) {
            Invoke-Command -ComputerName $FileServer -ScriptBlock {
                param($ShareName, $LocalPath)
                New-SmbShare -Name $ShareName -Path $LocalPath -FullAccess "Authenticated Users"
                $accessList = Get-SmbShareAccess -Name $ShareName | Where-Object { $_.AccountName -ne "NT AUTHORITY\Authenticated Users" }
                foreach ($entry in $accessList) {
                    Revoke-SmbShareAccess -Name $ShareName -AccountName $entry.AccountName -Force -Confirm:$false
                }
                $shareAcl = Get-SmbShareAccess -Name $ShareName
                $shareAcl | ForEach-Object {
                    "SHARE: $ShareName - $($_.AccountName) $($_.AccessControlType) $($_.AccessRight)"
                }
            } -ArgumentList $ShareName, $LocalPath | ForEach-Object { Log-Operation $_ "OK" "SHARE" }
            Log-Operation ("Udział " + $ShareName + " na " + $FileServer + " => " + $LocalPath + ": OK")
        }
        else {
            Log-Operation "POMINIĘTO: Katalog $LocalPath i udział $ShareName już istnieją na $FileServer."
            $shareAclRemote = Invoke-Command -ComputerName $FileServer -ScriptBlock {
                param($ShareName)
                $shareAcl = Get-SmbShareAccess -Name $ShareName -ErrorAction SilentlyContinue
                if ($shareAcl) {
                    $shareAcl | ForEach-Object {
                        "SHARE: $ShareName - $($_.AccountName) $($_.AccessControlType) $($_.AccessRight)"
                    }
                }
            } -ArgumentList $ShareName
            if ($shareAclRemote) {
                $shareAclRemote | ForEach-Object { Log-Operation $_ "OK" "SHARE" }
            }
        }
    }
    catch {
        $err = $_
        Log-Operation ("BŁĄD przy udostępnianiu " + $ShareName + " na " + $FileServer + ": " + $err.Exception.Message)
    }
}

function Ensure-OUExists {
    param(
        [string]$OUName,
        [string]$ParentDN
    )

    if ([string]::IsNullOrWhiteSpace($OUName) -or [string]::IsNullOrWhiteSpace($ParentDN)) {
        return $null
    }

    # Pobierz ustawienie z pliku XML
    $protectSetting = $settings.Settings.ProtectOUFromDeletion
    # Domyślnie włączona ochrona, jeśli nie ustawiono w XML
    if ([string]::IsNullOrWhiteSpace($protectSetting)) { $protectSetting = "True" }

    $ou = Get-ADOrganizationalUnit -Filter "Name -eq '$OUName'" -SearchBase $ParentDN -ErrorAction SilentlyContinue
    if (-not $ou) {
        try {
            # Tworzenie OU z odpowiednią ochroną
            New-ADOrganizationalUnit -Name $OUName -Path $ParentDN -ProtectedFromAccidentalDeletion:([bool]::Parse($protectSetting))
            Log-Operation "Utworzono OU: OU=${OUName},$ParentDN (ProtectedFromAccidentalDeletion=$protectSetting)" "OK" "OU"
            $ou = Get-ADOrganizationalUnit -Filter "Name -eq '$OUName'" -SearchBase $ParentDN -ErrorAction Stop
        }
        catch {
            Log-Operation ("Błąd podczas tworzenia OU ${OUName}: " + $_.Exception.Message) "ERROR" "OU"
            return $null
        }
    }
    return $ou
}


function Create-UserHomeAndSkanyFolder {
    param (
        [Parameter(Mandatory = $true)]
        [string]$SamAccountName,
        [Parameter(Mandatory = $true)]
        $HomeShare,
        [Parameter(Mandatory = $true)]
        $SkanyShare,
        [Parameter(Mandatory = $true)]
        [string]$DomainNetbios,
        [Parameter(Mandatory = $false)]
        $ProfilesShare,
        [Parameter(Mandatory = $false)]
        [bool]$EnableRoamingProfiles = $false
    )

    # HOME
    $homeUNC = Join-Path $HomeShare.UNC $SamAccountName
    $homeAdminUNC = Join-Path $HomeShare.AdminUNC $SamAccountName
    if (-not (Test-Path $homeUNC)) {
        try {
            New-Item -Path $homeUNC -ItemType Directory | Out-Null
            Log-Operation ("Utworzono katalog HOME: " + $homeUNC) "OK" "KATALOG"
        }
        catch {
            Log-Operation ("Błąd podczas tworzenia katalogu HOME: " + $homeUNC + ": " + $_.Exception.Message) "ERROR" "KATALOG"
        }
    }
    try {
        Set-UserHomeOrSkanyPermissions -Path $homeAdminUNC -UserSam $SamAccountName -DomainNetbios $DomainNetbios -LogPrefix "HOME"
    }
    catch {
        Log-Operation ("Błąd podczas ustawiania uprawnień NTFS na: " + $homeAdminUNC + ": " + $_.Exception.Message) "ERROR" "KATALOG"
    }

    # SKANY
    $skanyUNC = Join-Path $SkanyShare.UNC $SamAccountName
    $skanyAdminUNC = Join-Path $SkanyShare.AdminUNC $SamAccountName
    if (-not (Test-Path $skanyUNC)) {
        try {
            New-Item -Path $skanyUNC -ItemType Directory | Out-Null
            Log-Operation ("Utworzono katalog SKANY: " + $skanyUNC) "OK" "KATALOG"
        }
        catch {
            Log-Operation ("Błąd podczas tworzenia katalogu SKANY: " + $skanyUNC + ": " + $_.Exception.Message) "ERROR" "KATALOG"
        }
    }
    try {
        
        Set-UserHomeOrSkanyPermissions -Path $skanyAdminUNC -UserSam $SamAccountName -DomainNetbios $DomainNetbios -LogPrefix "SKANY"
    }
    catch {
        Log-Operation ("Błąd podczas ustawiania uprawnień NTFS na: " + $skanyAdminUNC + ": " + $_.Exception.Message) "ERROR" "KATALOG"
    }

}


function Create-DenyGroups {
    $adDomain = Get-ADDomain
    $distinguishedName = $adDomain.DistinguishedName
    $Install_OU_Name = $settings.Settings.Install_OU
    if ([string]::IsNullOrWhiteSpace($Install_OU_Name)) { $Install_OU_Name = "Install" }
    $Install_OU_DN = "OU=$Install_OU_Name,$distinguishedName"

    $denyGroups = @(
        "G_Deny_DZIALY",
        "G_Deny_OGOLNY",
        "G_Deny_SKANY",
        "G_Deny_HOME",
        "G_Deny_PROFILES"
    )

    foreach ($groupName in $denyGroups) {
        try {
            $group = Get-ADGroup -Filter "Name -eq '$groupName'" -SearchBase $Install_OU_DN -ErrorAction SilentlyContinue
            if (-not $group) {
                New-ADGroup -Name $groupName -GroupScope Global -GroupCategory Security -Path $Install_OU_DN
                Log-Operation ("Utworzono grupę: " + $groupName + " w " + $Install_OU_DN) "OK" "GRUPA"
            }
            else {
                Log-Operation ("Grupa " + $groupName + " już istnieje w " + $Install_OU_DN) "WARN" "GRUPA"
            }
        }
        catch {
            Log-Operation ("Błąd podczas tworzenia grupy " + $groupName + ": " + $_.Exception.Message) "ERROR" "GRUPA"
        }
    }
}


function Set-DenyGroupPermissions {
    param(
        [string]$Path,
        [string]$DenyGroup
    )
    $adDomain = Get-ADDomain
    $domainNetbios = $adDomain.NetBIOSName
    $acl = Get-Acl -Path $Path
    $denyRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "$domainNetbios\$DenyGroup", "FullControl", "ContainerInherit,ObjectInherit", "None", "Deny"
    )
    $acl.AddAccessRule($denyRule)
    Set-Acl -Path $Path -AclObject $acl
    Log-NTFS-ACL $Path
}

function Generate-Users {
    $users = Import-UserCsv $UsersFilePath
    $adDomain = Get-ADDomain
    $distinguishedName = $adDomain.DistinguishedName
    $domainNetbios = $adDomain.NetBIOSName
    $Install_OU_Name = $settings.Settings.Install_OU
    if ([string]::IsNullOrWhiteSpace($Install_OU_Name)) { $Install_OU_Name = "Install" }
    $Install_OU_DN = "OU=$Install_OU_Name,$distinguishedName"

    # Pobierz ustawienia PROFILES
    $ProfilesShare = $settings.Settings.PROFILES
    $EnableRoamingProfiles = $false
    if ($ProfilesShare.RoammingProfiles -eq "True") { $EnableRoamingProfiles = $true }

    Write-Host ""
    Write-Host "Wybierz konwencję nazewniczą dla kont użytkowników:"
    Write-Host "1. Pierwsza litera imienia + całe nazwisko (np. jnowak)"
    Write-Host "2. Pierwsza litera imienia + . + całe nazwisko (np. j.nowak)"
    Write-Host "3. Imię + . + nazwisko (np. jan.nowak)"
    Write-Host "4. Imię + _ + nazwisko (np. jan_nowak)"
    Write-Host "Jeśli w pliku '$UsersFilePath' został określony parametr 'Nazwa użytkownika' ma on priorytet"
    $prompt = "Podaj numer konwencji (1-4) [domyślnie: $DefaultNamingConvention]"
    $konwencja = Read-Host $prompt
    if ([string]::IsNullOrWhiteSpace($konwencja)) {
        $konwencja = $DefaultNamingConvention
    }
    $konwencja = [int]$konwencja

    switch ($konwencja) {
        1 { $konwencjaOpis = "1. Pierwsza litera imienia + całe nazwisko (np. jnowak)" }
        2 { $konwencjaOpis = "2. Pierwsza litera imienia + . + całe nazwisko (np. j.nowak)" }
        3 { $konwencjaOpis = "3. Imię + . + nazwisko (np. jan.nowak)" }
        4 { $konwencjaOpis = "4. Imię + _ + nazwisko (np. jan_nowak)" }
        default { $konwencjaOpis = "Nieznana konwencja ($konwencja)" }
    }

    Log-Operation "Wybrano konwencję nazewniczą dla kont użytkowników: $konwencjaOpis" "INFO" "UŻYTKOWNIK"

    $dzialyPrzetworzone = @{}

    foreach ($u in $users) {
        # 1. Sprawdź brak imienia lub nazwiska
        if (-not $u.Imie -or -not $u.Nazwisko) {
            $reason = "Brak imienia lub nazwiska"
            Log-Operation "Pominięto wiersz bez imienia lub nazwiska" "WARN" "UŻYTKOWNIK"
            Log-SkippedUser ("Brak imienia lub nazwiska w wierszu: " + ($u | ConvertTo-Csv -NoTypeInformation | Select-Object -Skip 1)) $reason
            continue
        }

        $GivenName = $u.Imie.Trim()
        $Surname = $u.Nazwisko.Trim()
        $DisplayName = "$GivenName $Surname"

        $UserName = if ($u.'Nazwa_uzytkownika') { $u.'Nazwa_uzytkownika' } else { Get-Username $GivenName $Surname $konwencja }
        $UserName = Remove-PolishChars($UserName.ToLower())
        $SamAccountName = $UserName

        $Nazwa_Dzialu = $u.Nazwa_Dzialu

        # 2. Niedozwolone znaki
        if ($SamAccountName -match '[^a-z0-9._-]') {
            $reason = "Niedozwolone znaki w nazwie użytkownika"
            Log-Operation "Nazwa użytkownika $SamAccountName zawiera niedozwolone znaki!" "ERROR" "UŻYTKOWNIK"
            Log-SkippedUser $SamAccountName $reason
            continue
        }

        # 3. Użytkownik już istnieje
        $exists = Get-ADUser -Filter "SamAccountName -eq '$SamAccountName'" -ErrorAction SilentlyContinue
        if ($exists) {
            $reason = "Użytkownik już istnieje w AD"
            Log-Operation "Użytkownik $SamAccountName już istnieje" "WARN" "UŻYTKOWNIK"
            Log-SkippedUser $SamAccountName $reason
            continue
        }

        # 4. Tworzenie OU i grup dla działu (jeśli nieprzetworzony)
        if ($Nazwa_Dzialu -and -not $dzialyPrzetworzone.ContainsKey($Nazwa_Dzialu)) {
            Generate-Groups -Dzialy @(@{ Nazwa_Dzialu = $Nazwa_Dzialu })
            $dzialyPrzetworzone[$Nazwa_Dzialu] = $true
        }

        # 5. Weryfikacja OU
        $userOUPath = $Install_OU_DN
        if ($Nazwa_Dzialu) {
            $ouObj = Find-OUByName $Nazwa_Dzialu $distinguishedName
            if ($ouObj) {
                $userOUPath = $ouObj.DistinguishedName
                Log-Operation "Znaleziono lub utworzono OU: $($userOUPath)" "OK" "OU"
            }
            else {
                $reason = "Brak OU o nazwie: $Nazwa_Dzialu i nie udało się jej utworzyć"
                Log-Operation "Brak OU o nazwie '$Nazwa_Dzialu'. Pominięto użytkownika $SamAccountName." "ERROR" "OU"
                Log-SkippedUser $SamAccountName $reason
                continue
            }
        }

        # 6. Weryfikacja wymaganych grup TYLKO dla użytkowników z wypełnioną nazwą działu w pliku 
        if ($Nazwa_Dzialu) {
            $groupRW = "G_RW_$Nazwa_Dzialu"
            $groupRO = "G_RO_$Nazwa_Dzialu"
            $groupRW_OGOLNY = "G_RW_OGOLNY_$Nazwa_Dzialu"
            $groupRW_DZIALY = "G_RW_DZIALY_$Nazwa_Dzialu"
            $groupRO_OGOLNY = "G_RO_OGOLNY_$Nazwa_Dzialu"
            $groupRO_DZIALY = "G_RO_DZIALY_$Nazwa_Dzialu"
            $groupMain = "G_$Nazwa_Dzialu"
            $groupDenyAll = "G_Deny_$Nazwa_Dzialu"
            $groupDenyOgolny = "G_Deny_OGOLNY_$Nazwa_Dzialu"
            $groupDenyDzialy = "G_Deny_DZIALY_$Nazwa_Dzialu"
            $requiredGroups = @($groupRW, $groupRO, $groupRW_OGOLNY, $groupRW_DZIALY, $groupRO_OGOLNY, $groupRO_OGOLNY, $groupRO_DZIALY, $groupMain, $groupDenyAll)
            $missingGroups = @()
            if ($userOUPath) {
                foreach ($grp in $requiredGroups) {
                    $grpObj = Get-ADGroup -Filter "Name -eq '$grp'" -SearchBase $userOUPath -ErrorAction SilentlyContinue
                    if (-not $grpObj) {
                        $missingGroups += $grp
                    }
                }
            }
            else {
                $missingGroups = $requiredGroups
            }
            if ($missingGroups.Count -gt 0) {
                $reason = "Brak wymaganych grup: " + ($missingGroups | Sort-Object -Unique -join ", ")
                Log-Operation "Pominięto użytkownika $SamAccountName z powodu: $reason" "ERROR" "GRUPA"
                Log-SkippedUser $SamAccountName $reason
                continue
            }
        }

        # 7. Dodanie użytkownika
        
		# 1. Pobierz/pamiętaj suffix UPN (prompt tylko raz)
		if (-not $global:SessionUPNSuffix) {
			$suffixes = (Get-ADForest).UPNSuffixes
			$adDomain = Get-ADDomain
			$defaultSuffix = $adDomain.DNSRoot
			if (-not $suffixes.Contains($defaultSuffix)) { $suffixes += $defaultSuffix }
			$global:SessionUPNSuffix = Select-UPNSuffix $suffixes
		}
		$upnSuffix = $global:SessionUPNSuffix
		$UserPrincipalName = "$SamAccountName@$upnSuffix"
		
		$pass = if ($u.Haslo) { $u.Haslo } else { $DefaultPassword }
        $securePass = ConvertTo-SecureString $pass -AsPlainText -Force
        try {
            New-ADUser -Name $DisplayName -DisplayName $DisplayName -GivenName $GivenName -Surname $Surname -SamAccountName $SamAccountName -UserPrincipalName $UserPrincipalName -AccountPassword $securePass -Path $userOUPath -Enabled $true
            Log-Operation "Użytkownik $SamAccountName utworzony pomyślnie w $userOUPath" "OK" "UŻYTKOWNIK"
        }
        catch {
            $reason = "Błąd podczas tworzenia użytkownika: $($_.Exception.Message)"
            Log-Operation ("Błąd podczas tworzenia użytkownika $($DisplayName): $($_.Exception.Message)") "ERROR" "UŻYTKOWNIK"
            Log-SkippedUser $SamAccountName $reason
            continue
        }

        # 8. Dodanie do grupy głównej TYLKO dla użytkowników z działu
        if ($Nazwa_Dzialu) {
            $groupMain = "G_$Nazwa_Dzialu"
            $groupRW_OGOLNY = "G_RW_OGOLNY_$Nazwa_Dzialu"
            $groupRW_DZIALY = "G_RW_DZIALY_$Nazwa_Dzialu"
			

			
            try {
                Add-ADGroupMember -Identity $groupMain -Members $SamAccountName
                Log-Operation "Dodano użytkownika $SamAccountName do grupy $groupMain" "OK" "GRUPA"
            }
            catch {
                Log-Operation ("Błąd przy dodawaniu użytkownika $($SamAccountName) do grupy $($groupMain): $($_.Exception.Message)") "ERROR" "GRUPA"
            }
			
            try {
                Add-ADGroupMember -Identity $groupRW_OGOLNY -Members $SamAccountName
                Log-Operation "Dodano użytkownika $SamAccountName do grupy $groupRW_OGOLNY" "OK" "GRUPA"
            }
            catch {
                Log-Operation ("Błąd przy dodawaniu użytkownika $($SamAccountName) do grupy $($groupRW_OGOLNY): $($_.Exception.Message)") "ERROR" "GRUPA"
            }
			
            try {
                Add-ADGroupMember -Identity $groupRW_DZIALY -Members $SamAccountName
                Log-Operation "Dodano użytkownika $SamAccountName do grupy $groupRW_DZIALY" "OK" "GRUPA"
            }
            catch {
                Log-Operation ("Błąd przy dodawaniu użytkownika $($SamAccountName) do grupy $($groupRW_DZIALY): $($_.Exception.Message)") "ERROR" "GRUPA"
            }
        }

        # 9. Katalogi HOME i SKANY
        Create-UserHomeAndSkanyFolder $SamAccountName $HomeShare $SkanyShare $domainNetbios

        $homeUNC = Join-Path $HomeShare.UNC $SamAccountName
        try {
            Set-ADUser -Identity $SamAccountName -HomeDirectory $homeUNC -HomeDrive $HomeShare.DriveLetter
            Log-Operation "Ustawiono katalog domowy $homeUNC i literę $($HomeShare.DriveLetter) dla $SamAccountName" "OK" "HOME"
        }
        catch {
            Log-Operation ("Błąd podczas ustawiania katalogu domowego dla $($DisplayName): $($_.Exception.Message)") "ERROR" "HOME"
        }

        # 10. Katalog PROFILES (Roaming Profiles)
        if ($EnableRoamingProfiles) {
    
            $profilesUNC = Join-Path $ProfilesShare.UNC $SamAccountName
            try {
                Set-ADUser -Identity $SamAccountName -ProfilePath $profilesUNC
                Log-Operation "Ustawiono ścieżkę profilu mobilnego $profilesUNC dla $SamAccountName" "OK" "PROFILES"
            }
            catch {
                Log-Operation ("Błąd podczas ustawiania ścieżki profilu mobilnego dla $($SamAccountName): $($_.Exception.Message)") "ERROR" "PROFILES"
            }
        }

    }

    Log-Operation "Koniec operacji (użytkownicy)." "OK" "UŻYTKOWNIK"
}




function Generate-Groups {
    param(
        [Parameter(Mandatory = $false)]
        [array]$Dzialy
    )

    $adDomain = Get-ADDomain
    $distinguishedName = $adDomain.DistinguishedName
    $Install_OU_Name = $settings.Settings.Install_OU
    if ([string]::IsNullOrWhiteSpace($Install_OU_Name)) { $Install_OU_Name = "Install" }
    $Install_OU_DN = "OU=$Install_OU_Name,$distinguishedName"

    if (-not $Dzialy) {
        $Dzialy = Import-Csv -Path $GroupsFilePath -Delimiter ';'
    }

    foreach ($dzial in $Dzialy) {
        $Nazwa_Dzialu = $dzial.'Nazwa_Dzialu'

        if ([string]::IsNullOrWhiteSpace($Nazwa_Dzialu)) {
            Log-Operation "Pominięto wiersz bez nazwy działu" "WARN" "GRUPA"
            continue
        }

        $ouObj = Ensure-OUExists $Nazwa_Dzialu $Install_OU_DN
        if ($null -eq $ouObj -or [string]::IsNullOrWhiteSpace($ouObj.DistinguishedName)) {
            Log-Operation "Nie udało się odnaleźć lub utworzyć OU $Nazwa_Dzialu" "ERROR" "OU"
            continue
        }
        $OUPath = $ouObj.DistinguishedName

        # Grupy podstawowe i dodatkowe DENY
        $groupRW = "G_RW_$Nazwa_Dzialu"
        $groupRO = "G_RO_$Nazwa_Dzialu"
        $groupRW_OGOLNY = "G_RW_OGOLNY_$Nazwa_Dzialu"
        $groupRW_DZIALY = "G_RW_DZIALY_$Nazwa_Dzialu"
        $groupRO_OGOLNY = "G_RO_OGOLNY_$Nazwa_Dzialu"
        $groupRO_DZIALY = "G_RO_DZIALY_$Nazwa_Dzialu"
        $groupMain = "G_$Nazwa_Dzialu"
        $groupDenyAll = "G_Deny_$Nazwa_Dzialu"
        $groupDenyOgolny = "G_Deny_OGOLNY_$Nazwa_Dzialu"
        $groupDenyDzialy = "G_Deny_DZIALY_$Nazwa_Dzialu"

        $requiredGroups = @(
            $groupRW,
            $groupRO,
            $groupMain,
            $groupDenyAll,
            $groupDenyOgolny,
            $groupDenyDzialy,
            $groupRW_OGOLNY,
            $groupRW_DZIALY,
            $groupRO_OGOLNY,
            $groupRO_DZIALY
        )

        foreach ($grp in $requiredGroups) {
            if ([string]::IsNullOrWhiteSpace($OUPath)) {
                Log-Operation "Nie można sprawdzić lub utworzyć grupy '$grp', bo ścieżka OU jest pusta!" "ERROR" "GRUPA"
                continue
            }
            if (-not (Get-ADGroup -Filter "Name -eq '$grp'" -SearchBase $OUPath -ErrorAction SilentlyContinue)) {
                try {
                    New-ADGroup -Name $grp -GroupScope Global -Path $OUPath
                    Log-Operation "Utworzono grupę: $grp w $OUPath" "OK" "GRUPA"
                }
                catch {
                    Log-Operation ("Błąd podczas tworzenia grupy " + $grp + ": " + $_.Exception.Message) "ERROR" "GRUPA"
                }
            }
        }

        # Dodaj grupę główną do RW tylko jeśli nie jest już jej członkiem
        try {
            $rwMembers = Get-ADGroupMember -Identity $groupRW -ErrorAction Stop | Where-Object { $_.objectClass -eq 'group' }
            $mainGroupObj = Get-ADGroup -Identity $groupMain -ErrorAction Stop
            $isMember = $rwMembers | Where-Object { $_.DistinguishedName -eq $mainGroupObj.DistinguishedName }
            if (-not $isMember) {
                Add-ADGroupMember -Identity $groupRW -Members $groupMain
                Log-Operation "Dodano grupę $groupMain do $groupRW" "OK" "GRUPA"
            }
            else {
                Log-Operation "Grupa $groupMain już jest członkiem $groupRW" "WARN" "GRUPA"
            }
        }
        catch {
            Log-Operation ("Błąd przy dodawaniu " + $groupMain + " do " + $groupRW + ": " + $_.Exception.Message) "ERROR" "GRUPA"
        }
		
        # Dodaj grupę główną do RW_DZIALY tylko jeśli nie jest już jej członkiem
        try {
            $rwMembers = Get-ADGroupMember -Identity $groupRW_DZIALY -ErrorAction Stop | Where-Object { $_.objectClass -eq 'group' }
            $mainGroupObj = Get-ADGroup -Identity $groupMain -ErrorAction Stop
            $isMember = $rwMembers | Where-Object { $_.DistinguishedName -eq $mainGroupObj.DistinguishedName }
            if (-not $isMember) {
                Add-ADGroupMember -Identity $groupRW_DZIALY -Members $groupMain
                Log-Operation "Dodano grupę $groupMain do $groupRW_DZIALY" "OK" "GRUPA"
            }
            else {
                Log-Operation "Grupa $groupMain już jest członkiem $groupRW_DZIALY" "WARN" "GRUPA"
            }
        }
        
        catch {
            Log-Operation ("Błąd przy dodawaniu " + $groupMain + " do " + $groupRW_DZIALY + ": " + $_.Exception.Message) "ERROR" "GRUPA"
        }
		
        # Dodaj grupę główną do RW_OGOLNY tylko jeśli nie jest już jej członkiem
        try {
            $rwMembers = Get-ADGroupMember -Identity $groupRW_OGOLNY -ErrorAction Stop | Where-Object { $_.objectClass -eq 'group' }
            $mainGroupObj = Get-ADGroup -Identity $groupMain -ErrorAction Stop
            $isMember = $rwMembers | Where-Object { $_.DistinguishedName -eq $mainGroupObj.DistinguishedName }
            if (-not $isMember) {
                Add-ADGroupMember -Identity $groupRW_OGOLNY -Members $groupMain
                Log-Operation "Dodano grupę $groupMain do $groupRW_OGOLNY" "OK" "GRUPA"
            }
            else {
                Log-Operation "Grupa $groupMain już jest członkiem $groupRW_OGOLNY" "WARN" "GRUPA"
            }
        }
        
		
		
		
        catch {
            Log-Operation ("Błąd przy dodawaniu " + $groupMain + " do " + $groupRW_OGOLNY + ": " + $_.Exception.Message) "ERROR" "GRUPA"
        }

        # Katalogi DZIALY i OGOLNY
        $dzialyUNC = Join-Path $DzialyShare.UNC $Nazwa_Dzialu
        $dzialyAdminUNC = Join-Path $DzialyShare.AdminUNC $Nazwa_Dzialu
        if (-not (Test-Path $dzialyUNC)) {
            try {
                New-Item -Path $dzialyUNC -ItemType Directory | Out-Null
                Log-Operation "Utworzono katalog $dzialyUNC" "OK" "KATALOG"
                Set-NTFSPermissions `
                    -Path $dzialyAdminUNC `
                    -FullControlGroups @($groupRW, $groupRW_DZIALY) `
                    -ReadGroups @($groupRO, $groupRO_DZIALY) `
                    -DenyDeleteGroups @($groupRW, $groupRO, $groupRW_DZIALY, $groupRO_DZIALY) `
                    -DenyAllGroups @($groupDenyAll, $groupDenyDzialy) `
                    -LogPrefix "NTFS DZIALY"
            }
            catch {
                Log-Operation ("Błąd przy tworzeniu katalogu " + $dzialyUNC + ": " + $_.Exception.Message) "ERROR" "KATALOG"
            }
        }
        $ogolnyUNC = Join-Path $OgolnyShare.UNC $Nazwa_Dzialu
        $ogolnyAdminUNC = Join-Path $OgolnyShare.AdminUNC $Nazwa_Dzialu
        if (-not (Test-Path $ogolnyUNC)) {
            try {
                New-Item -Path $ogolnyUNC -ItemType Directory | Out-Null
                Log-Operation "Utworzono katalog $ogolnyUNC" "OK" "KATALOG"
                Set-NTFSPermissions `
                    -Path $ogolnyAdminUNC `
                    -FullControlGroups @($groupRW, $groupRW_OGOLNY) `
                    -ReadGroups @($groupRO, $groupRO_OGOLNY) `
                    -DenyDeleteGroups @($groupRW, $groupRO, $groupRW_OGOLNY, $groupRO_OGOLNY) `
                    -DenyAllGroups @($groupDenyAll, $groupDenyOgolny) `
                    -ExtraAccess @("Authenticated Users") `
                    -LogPrefix "NTFS OGOLNY"
            }
            catch {
                Log-Operation ("Błąd przy tworzeniu katalogu " + $ogolnyUNC + ": " + $_.Exception.Message) "ERROR" "KATALOG"
            }
        }
        Log-Operation "Koniec operacji (grupy)." "OK" "GRUPA"
    }
}
    

function Find-OUByName {
    param(
        [string]$OUName,
        [string]$SearchBase
    )
    if ([string]::IsNullOrWhiteSpace($SearchBase)) {
        $SearchBase = (Get-ADDomain).DistinguishedName
    }
    $ou = Get-ADOrganizationalUnit -Filter "Name -eq '$OUName'" -SearchBase $SearchBase -ErrorAction SilentlyContinue
    if (-not $ou) {
        $ou = Get-ADOrganizationalUnit -Filter "Name -eq '$OUName'" -ErrorAction SilentlyContinue
    }
    return $ou
}


function Create-SingleUserInteractive {
    Log-Operation "Rozpoczęcie interaktywnego dodawania użytkownika." "OK" "UŻYTKOWNIK"

    $Imie = Read-Host "Podaj imię"
    if ([string]::IsNullOrWhiteSpace($Imie)) {
        Write-Host "Imię jest wymagane." -ForegroundColor Red
        Log-Operation "Przerwano: nie podano imienia." "WARN" "UŻYTKOWNIK"
        return
    }

    $Nazwisko = Read-Host "Podaj nazwisko"
    if ([string]::IsNullOrWhiteSpace($Nazwisko)) {
        Write-Host "Nazwisko jest wymagane." -ForegroundColor Red
        Log-Operation "Przerwano: nie podano nazwiska." "WARN" "UŻYTKOWNIK"
        return
    }

    $Dzial = Read-Host "Podaj nazwę działu (niewymagane - ENTER = domyślna lokalizacja)"
    $Haslo = Read-Host "Podaj hasło (pozostaw puste aby użyć domyślnego)"
    if ([string]::IsNullOrWhiteSpace($Haslo)) {
        $Haslo = $DefaultPassword
        Log-Operation "Nie podano hasła, użyto domyślnego." "INFO" "UŻYTKOWNIK"
    }

    
    # Budowa obiektu użytkownika do CSV
    $userObject = [PSCustomObject]@{
        Imie         = $Imie
        Nazwisko     = $Nazwisko
        Nazwa_Dzialu = $Dzial
        Haslo        = $Haslo
    
    }

    $tempCsvPath = [System.IO.Path]::GetTempFileName()
    try {
        $userObject | Export-Csv -Path $tempCsvPath -Delimiter ';' -NoTypeInformation -Encoding UTF8
        Log-Operation "Zapisano dane użytkownika do pliku tymczasowego: $tempCsvPath" "DEBUG" "UŻYTKOWNIK"
        $originalUsersFilePath = $UsersFilePath
        $script:UsersFilePath = $tempCsvPath
        Log-Operation "Wywołanie Generate-Users dla pojedynczego użytkownika ($Imie $Nazwisko, dział: $Dzial)" "INFO" "UŻYTKOWNIK"
        Generate-Users
        $script:UsersFilePath = $originalUsersFilePath
        Log-Operation "Przywrócono oryginalną ścieżkę do pliku users.txt" "DEBUG" "UŻYTKOWNIK"
    }
    catch {
        Log-Operation "Błąd podczas interaktywnego dodawania użytkownika: $($_.Exception.Message)" "ERROR" "UŻYTKOWNIK"
    }
    finally {
        Remove-Item -Path $tempCsvPath -Force -ErrorAction SilentlyContinue
        Log-Operation "Usunięto plik tymczasowy: $tempCsvPath" "DEBUG" "UŻYTKOWNIK"
    }

    # Ustawienie katalogu profilu mobilnego (roaming profiles) jeśli aktywne
    if ($EnableRoamingProfiles) {
        try {
            # Ustal nazwę użytkownika zgodnie z konwencją
            $UserName = Get-Username $Imie $Nazwisko $Konwencja
            $UserName = Remove-PolishChars($UserName.ToLower())
            $SamAccountName = $UserName

            # Ustawienie ProfilePath w AD
            $profilesUNC = Join-Path $ProfilesShare.UNC $SamAccountName
            
			# Pobierz/pamiętaj suffix UPN (prompt tylko raz)
			if (-not $global:SessionUPNSuffix) {
				$suffixes = (Get-ADForest).UPNSuffixes
				$adDomain = Get-ADDomain
				$defaultSuffix = $adDomain.DNSRoot
				if (-not $suffixes.Contains($defaultSuffix)) { $suffixes += $defaultSuffix }
				$global:SessionUPNSuffix = Select-UPNSuffix $suffixes
			}
			$upnSuffix = $global:SessionUPNSuffix
			$UserPrincipalName = "$SamAccountName@$upnSuffix"
			
			Set-ADUser -Identity $SamAccountName -UserPrincipalName $UserPrincipalName -ProfilePath $profilesUNC
            Log-Operation "Ustawiono ścieżkę profilu mobilnego $profilesUNC dla $SamAccountName" "OK" "PROFILES"
        }
        catch {
            Log-Operation ("Błąd podczas tworzenia katalogu lub ustawiania ścieżki profilu mobilnego dla $($SamAccountName): $($_.Exception.Message)") "ERROR" "PROFILES"
        }
    }

    Log-Operation "Zakończono interaktywne dodawanie użytkownika." "OK" "UŻYTKOWNIK"
}




function Create-DepartmentInteractive {
    Log-Operation "Rozpoczęcie interaktywnego dodawania działu (grupy i katalogów)." "OK" "GRUPA"

    $Nazwa_Dzialu = Read-Host "Podaj nazwę nowego działu"
    if ([string]::IsNullOrWhiteSpace($Nazwa_Dzialu)) {
        Write-Host "Nazwa działu jest wymagana." -ForegroundColor Red
        Log-Operation "Przerwano: nie podano nazwy działu." "WARN" "GRUPA"
        return
    }

    $dzialObj = [PSCustomObject]@{ Nazwa_Dzialu = $Nazwa_Dzialu }
    $tempCsvPath = [System.IO.Path]::GetTempFileName()
    try {
        $dzialObj | Export-Csv -Path $tempCsvPath -Delimiter ';' -NoTypeInformation -Encoding UTF8
        Log-Operation "Zapisano dane działu do pliku tymczasowego: $tempCsvPath" "DEBUG" "GRUPA"

        $originalGroupsFilePath = $GroupsFilePath
        $script:GroupsFilePath = $tempCsvPath

        Log-Operation "Wywołanie Generate-Groups dla działu $Nazwa_Dzialu" "INFO" "GRUPA"
        Generate-Groups

        $script:GroupsFilePath = $originalGroupsFilePath
        Log-Operation "Przywrócono oryginalną ścieżkę do pliku dzialy.txt" "DEBUG" "GRUPA"
    }
    catch {
        Log-Operation "Błąd podczas interaktywnego dodawania działu: $($_.Exception.Message)" "ERROR" "GRUPA"
    }
    finally {
        Remove-Item -Path $tempCsvPath -Force -ErrorAction SilentlyContinue
        Log-Operation "Usunięto plik tymczasowy: $tempCsvPath" "DEBUG" "GRUPA"
    }
    Log-Operation "Zakończono interaktywne dodawanie działu." "OK" "GRUPA"
}

function Create-UserProfilesFolder($SamAccountName, $ProfilesShare, $DomainNetbios) {
    $profilesUNC = Join-Path $ProfilesShare.UNC $SamAccountName
    $profilesAdminUNC = Join-Path $ProfilesShare.AdminUNC $SamAccountName

    if (-not (Test-Path $profilesUNC)) {
        New-Item -Path $profilesUNC -ItemType Directory | Out-Null
        Log-Operation "Utworzono katalog PROFILES: $profilesUNC" "OK" "KATALOG"
        Set-UserHomeOrSkanyPermissions -Path $profilesAdminUNC -UserSam $SamAccountName -DomainNetbios $DomainNetbios -LogPrefix "PROFILES"
    }
}

function Create-UserProfilesFolder {
    param (
        [Parameter(Mandatory = $true)]
        [string]$SamAccountName,
        [Parameter(Mandatory = $true)]
        $ProfilesShare,
        [Parameter(Mandatory = $true)]
        [string]$DomainNetbios
    )

    $profilesUNC = Join-Path $ProfilesShare.UNC $SamAccountName
    $profilesAdminUNC = Join-Path $ProfilesShare.AdminUNC $SamAccountName

    if (-not (Test-Path $profilesUNC)) {
        try {
            New-Item -Path $profilesUNC -ItemType Directory | Out-Null
            Log-Operation ("Utworzono katalog PROFILES: " + $profilesUNC) "OK" "PROFILES"
        }
        catch {
            Log-Operation ("Błąd podczas tworzenia katalogu PROFILES: " + $profilesUNC + ": " + $_.Exception.Message) "ERROR" "PROFILES"
            return
        }
    }
    else {
        Log-Operation ("Katalog PROFILES już istnieje: " + $profilesUNC) "OK" "PROFILES"
    }

    try {
        Set-UserHomeOrSkanyPermissions -Path $profilesAdminUNC -UserSam $SamAccountName -DomainNetbios $DomainNetbios -LogPrefix "PROFILES"
    }
    catch {
        Log-Operation ("Błąd podczas ustawiania uprawnień NTFS na: " + $profilesAdminUNC + ": " + $_.Exception.Message) "ERROR" "PROFILES"
		
    }
}

function Initialize-Environment {
    Log-Operation "=== Rozpoczęcie pracy funkcji Initialize-Environment ===" "OK" "SYSTEM"

    $adDomain = Get-ADDomain
    $distinguishedName = $adDomain.DistinguishedName
    $domainNetbios = $adDomain.NetBIOSName

    if ([string]::IsNullOrWhiteSpace($Install_OU_Name)) { $Install_OU_Name = "Install" }
    if ([string]::IsNullOrWhiteSpace($Komputery_OU_Name)) { $Komputery_OU_Name = "Komputery" }

    $Install_OU_DN = "OU=$Install_OU_Name,$distinguishedName"
    $Komputery_OU_DN = "OU=$Komputery_OU_Name,$distinguishedName"

    # Pobierz ustawienia PROFILES i sprawdź RoamingProfiles
    $ProfilesShare = $settings.Settings.PROFILES
    $EnableRoamingProfiles = $false
    if ($ProfilesShare.RoammingProfiles -eq "True") { $EnableRoamingProfiles = $true }

    # Instalacja roli File Server jeśli potrzebna
    try {
        $role = Get-WindowsFeature -ComputerName $FileServer -Name FS-FileServer -ErrorAction Stop
        if (-not $role.Installed) {
            Install-WindowsFeature -ComputerName $FileServer -Name FS-FileServer -IncludeManagementTools -ErrorAction Stop
            Log-Operation ("Rola File Server zainstalowana na " + $FileServer) "OK" "SYSTEM"
        }
        else {
            Log-Operation ("Rola File Server już zainstalowana na " + $FileServer) "OK" "SYSTEM"
        }
    }
    catch {
        $err = $_
        Log-Operation ("BŁĄD podczas sprawdzania/instalacji roli File Server na " + $FileServer + ": " + $err.Exception.Message) "ERROR" "SYSTEM"
    }

    # Tworzenie OU
    foreach ($ou in @(@{Name = $Install_OU_Name; DN = $Install_OU_DN }, @{Name = $Komputery_OU_Name; DN = $Komputery_OU_DN })) {
        try {
            if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$($ou.DN)'" -ErrorAction SilentlyContinue)) {
                New-ADOrganizationalUnit -Name $ou.Name -Path $distinguishedName
                Log-Operation ("Utworzono OU: " + $ou.DN) "OK" "OU"
            }
            else {
                Log-Operation ("OU już istnieje: " + $ou.DN) "OK" "OU"
            }
        }
        catch {
            Log-Operation ("BŁĄD przy tworzeniu OU " + $ou.Name + ": " + $_.Exception.Message) "ERROR" "OU"
        }
    }

    # Przekierowanie kont komputerów
    try {
        redircmp $Komputery_OU_DN
        Log-Operation ("Przekierowano nowe konta komputerów do: " + $Komputery_OU_DN) "OK" "SYSTEM"
    }
    catch {
        Log-Operation ("BŁĄD przy przekierowaniu kont komputerów: " + $_.Exception.Message) "ERROR" "SYSTEM"
    }

    # Przygotowanie listy udziałów
    $shares = @(
        @{Name = $HomeShare.ShareName; Path = $HomeShare.Local },
        @{Name = $DzialyShare.ShareName; Path = $DzialyShare.Local },
        @{Name = $OgolnyShare.ShareName; Path = $OgolnyShare.Local },
        @{Name = $SkanyShare.ShareName; Path = $SkanyShare.Local }
    )
    if ($EnableRoamingProfiles) {
        $shares += @{Name = $ProfilesShare.ShareName; Path = $ProfilesShare.Local }
    }

    # Tworzenie katalogów na serwerze plików i udziałów sieciowych
    foreach ($share in $shares) {
        if ([string]::IsNullOrWhiteSpace($share.Name)) { continue }
        try {
            $dirExists = Invoke-Command -ComputerName $FileServer -ScriptBlock {
                param($LocalPath)
                Test-Path -Path $LocalPath
            } -ArgumentList $share.Path

            if (-not $dirExists) {
                Invoke-Command -ComputerName $FileServer -ScriptBlock {
                    param($LocalPath)
                    New-Item -Path $LocalPath -ItemType Directory | Out-Null
                } -ArgumentList $share.Path
                Log-Operation ("Utworzono katalog " + $share.Path + " na " + $FileServer) "OK" "KATALOG"
            }
            else {
                Log-Operation ("Katalog " + $share.Path + " już istnieje na " + $FileServer) "WARN" "KATALOG"
            }
        }
        catch {
            Log-Operation ("BŁĄD przy tworzeniu katalogu " + $share.Path + " na " + $FileServer + ": " + $_.Exception.Message) "ERROR" "KATALOG"
        }

        # Tworzenie udziału sieciowego (jeśli nie istnieje)
        Ensure-RemoteShare -ShareName $share.Name -LocalPath $share.Path -FileServer $FileServer
    }

    # Włącz ABE na udziałach
    foreach ($share in $shares) {
        if ([string]::IsNullOrWhiteSpace($share.Name)) { continue }
        try {
            $result = Invoke-Command -ComputerName $FileServer -ScriptBlock {
                param($sn)
                $s = Get-SmbShare -Name $sn -ErrorAction SilentlyContinue
                if ($s -and $s.FolderEnumerationMode -ne 'AccessBased') {
                    Set-SmbShare -Name $sn -FolderEnumerationMode AccessBased -Force -Confirm:$false
                    return "WŁĄCZONO"
                }
                elseif ($s -and $s.FolderEnumerationMode -eq 'AccessBased') {
                    return "JUŻ_WŁĄCZONE"
                }
                else {
                    return "BRAK_UDZIAŁU"
                }
            } -ArgumentList $share.Name

            switch ($result) {
                "WŁĄCZONO" { Log-Operation ("Włączono Access Based Enumeration na serwerze " + $FileServer + " dla udziału: " + $share.Name) "OK" "SYSTEM" }
                "JUŻ_WŁĄCZONE" { Log-Operation ("POMINIĘTO: Access Based Enumeration już włączone na serwerze " + $FileServer + " dla udziału: " + $share.Name) "WARN" "SYSTEM" }
                "BRAK_UDZIAŁU" { Log-Operation ("BŁĄD: Udział " + $share.Name + " nie istnieje na serwerze " + $FileServer) "ERROR" "SYSTEM" }
            }
        }
        catch {
            Log-Operation ("BŁĄD przy sprawdzaniu/włączaniu ABE na serwerze " + $FileServer + " dla udziału " + $share.Name + ": " + $_.Exception.Message) "ERROR" "SYSTEM"
        }
    }

    # Reset NTFS na katalogach głównych
    Reset-NTFSPermissions -Path $DzialyShare.AdminUNC
    Reset-NTFSPermissions -Path $OgolnyShare.AdminUNC
    Reset-NTFSPermissions -Path $HomeShare.AdminUNC
    Reset-NTFSPermissions -Path $SkanyShare.AdminUNC
    if ($EnableRoamingProfiles) {
        Reset-NTFSPermissions -Path $ProfilesShare.AdminUNC
    }

    # Tworzenie grup DENY i ustawienie uprawnień DENY na głównych katalogach
    Create-DenyGroups
    Set-DenyGroupPermissions -Path $DzialyShare.AdminUNC -DenyGroup "G_Deny_Dzialy"
    Set-DenyGroupPermissions -Path $OgolnyShare.AdminUNC -DenyGroup "G_Deny_Ogolny"
    Set-DenyGroupPermissions -Path $SkanyShare.AdminUNC -DenyGroup "G_Deny_SKANY"
    Set-DenyGroupPermissions -Path $HomeShare.AdminUNC -DenyGroup "G_Deny_HOME"
    if ($EnableRoamingProfiles) {
        Set-DenyGroupPermissions -Path $ProfilesShare.AdminUNC -DenyGroup "G_Deny_PROFILES"
    }

    # Oznacz środowisko jako skonfigurowane
    $settings.Settings.Configured = "True"
    $settings.Save($SettingsPath)
	
    Log-Operation "Ustawiono True w pliku Settings.xml" "OK" "SYSTEM"
    Log-Operation "=== Zakończenie pracy funkcji Initialize-Environment ===" "OK" "SYSTEM"
    Write-Host "Przygotowanie środowiska zakończone. Configured=True ustawione w XML." -ForegroundColor Green
}



# FUNKCJE SERWISOWE

function Repair-UserAccount {
    $adDomain = Get-ADDomain
    $domainNetbios = $adDomain.NetBIOSName
    $ProfilesShare = $settings.Settings.PROFILES
    $EnableRoamingProfiles = $false
    if ($ProfilesShare.RoammingProfiles -eq "True") { $EnableRoamingProfiles = $true }

    $userQuery = Read-Host "Podaj nazwę użytkownika (login) lub imię i nazwisko"
    Log-Operation "Serwis: Rozpoczęcie naprawy konta użytkownika: $userQuery" "OK" "SERWIS"
    $user = $null
    $user = Get-ADUser -Filter "SamAccountName -eq '$userQuery'" -ErrorAction SilentlyContinue
    if (-not $user) {
        $parts = $userQuery.Split(" ", 2)
        if ($parts.Count -eq 2) {
            $user = Get-ADUser -Filter "GivenName -eq '$($parts[0])' -and Surname -eq '$($parts[1])'" -ErrorAction SilentlyContinue
        }
    }
    if (-not $user) {
        Log-Operation "Serwis: Nie znaleziono użytkownika $userQuery" "ERROR" "SERWIS"
        return
    }
    $SamAccountName = $user.SamAccountName

    # HOME/SKANY
    $homePathUNC = Join-Path $HomeShare.UNC $SamAccountName
    $skanyPathUNC = Join-Path $SkanyShare.UNC $SamAccountName
    $homePathAdmin = Join-Path $HomeShare.AdminUNC $SamAccountName
    $skanyPathAdmin = Join-Path $SkanyShare.AdminUNC $SamAccountName

    $missing = @()
    if (-not (Test-Path $homePathUNC)) { $missing += "HOME" }
    if (-not (Test-Path $skanyPathUNC)) { $missing += "SKANY" }

    if ($missing.Count -gt 0) {
        Log-Operation "Serwis: Brakujące katalogi: $($missing -join ', ') dla $SamAccountName" "WARN" "SERWIS"
        $resp = Read-Host "Czy utworzyć brakujące katalogi i nadać uprawnienia? (T/N)"
        if ($resp -eq 'T' -or $resp -eq 't') {
            if ($missing -contains "HOME") {
                New-Item -Path $homePathUNC -ItemType Directory | Out-Null
                Log-Operation "Serwis: Utworzono katalog HOME: $homePathUNC" "OK" "SERWIS"
                Set-UserHomeOrSkanyPermissions -Path $homePathAdmin -UserSam $SamAccountName -DomainNetbios $domainNetbios -LogPrefix "HOME"
            }
            if ($missing -contains "SKANY") {
                New-Item -Path $skanyPathUNC -ItemType Directory | Out-Null
                Log-Operation "Serwis: Utworzono katalog SKANY: $skanyPathUNC" "OK" "SERWIS"
                Set-UserHomeOrSkanyPermissions -Path $skanyPathAdmin -UserSam $SamAccountName -DomainNetbios $domainNetbios -LogPrefix "SKANY"
            }
        }
        else {
            Log-Operation "Serwis: Użytkownik zrezygnował z tworzenia brakujących katalogów dla $SamAccountName" "WARN" "SERWIS"
        }
    }
    else {
        Log-Operation "Serwis: Katalogi HOME i SKANY istnieją dla $SamAccountName" "WARN" "SERWIS"
        $resp = Read-Host "Czy naprawić uprawnienia NTFS w katalogach HOME i SKANY? (T/N)"
        if ($resp -eq 'T' -or $resp -eq 't') {
            Set-UserHomeOrSkanyPermissions -Path $homePathAdmin -UserSam $SamAccountName -DomainNetbios $domainNetbios -LogPrefix "HOME naprawa"
            Set-UserHomeOrSkanyPermissions -Path $skanyPathAdmin -UserSam $SamAccountName -DomainNetbios $domainNetbios -LogPrefix "SKANY naprawa"
            Log-Operation "Serwis: Naprawiono uprawnienia NTFS w katalogach HOME i SKANY dla $SamAccountName" "OK" "SERWIS"
        }
        else {
            Log-Operation "Serwis: Użytkownik zrezygnował z naprawy uprawnień NTFS dla $SamAccountName" "WARN" "SERWIS"
        }
    }

    # HOME w AD
    $userAD = Get-ADUser -Identity $SamAccountName -Properties HomeDirectory, HomeDrive
    if (-not $userAD.HomeDirectory -or -not $userAD.HomeDrive) {
        Log-Operation "Serwis: Brak ustawionego katalogu domowego lub litery dysku dla $SamAccountName" "WARN" "SERWIS"
        $resp = Read-Host "Czy ustawić katalog domowy i literę dysku? (T/N)"
        if ($resp -eq 'T' -or $resp -eq 't') {
            Set-ADUser -Identity $SamAccountName -HomeDirectory $homePathUNC -HomeDrive $HomeShare.DriveLetter
            Log-Operation "Serwis: Ustawiono katalog domowy $homePathUNC i literę $($HomeShare.DriveLetter) dla $SamAccountName" "OK" "SERWIS"
        }
        else {
            Log-Operation "Serwis: Użytkownik zrezygnował z ustawienia katalogu domowego dla $SamAccountName" "WARN" "SERWIS"
        }
    }
    else {
        Log-Operation "Serwis: Konto użytkownika $SamAccountName ma ustawiony katalog domowy i literę dysku." "OK" "SERWIS"
    }

    # ROAMING PROFILES
    if ($EnableRoamingProfiles) {
        $profilesPathUNC = Join-Path $ProfilesShare.UNC $SamAccountName
   
        $userAD = Get-ADUser -Identity $SamAccountName -Properties ProfilePath
        if (-not $userAD.ProfilePath -or $userAD.ProfilePath -ne $profilesPathUNC) {
            $resp = Read-Host "Ustaw ścieżkę profilu mobilnego w AD na $profilesPathUNC? (T/N)"
            if ($resp -eq 'T' -or $resp -eq 't') {
                Set-ADUser -Identity $SamAccountName -ProfilePath $profilesPathUNC
                Log-Operation "Serwis: Ustawiono ścieżkę profilu mobilnego $profilesPathUNC dla $SamAccountName" "OK" "SERWIS"
            }
        }
    }


    Log-Operation "Serwis: Naprawa konta zakończona dla $SamAccountName" "OK" "SERWIS"
}



function Repair-NTFS-RootDirs {
    Log-Operation "Serwis: Rozpoczęcie naprawy uprawnień NTFS na głównych katalogach HOME, SKANY, OGOLNY, DZIALY, PROFILES" "OK" "SERWIS"
    try {
        Reset-NTFSPermissions -Path $HomeShare.AdminUNC
        Reset-NTFSPermissions -Path $SkanyShare.AdminUNC
        Reset-NTFSPermissions -Path $OgolnyShare.AdminUNC
        Reset-NTFSPermissions -Path $DzialyShare.AdminUNC
        Set-DenyGroupPermissions -Path $DzialyShare.AdminUNC -DenyGroup "G_Deny_Dzialy"
        Set-DenyGroupPermissions -Path $OgolnyShare.AdminUNC -DenyGroup "G_Deny_Ogolny"
        Set-DenyGroupPermissions -Path $SkanyShare.AdminUNC -DenyGroup "G_Deny_SKANY"
        Set-DenyGroupPermissions -Path $HomeShare.AdminUNC -DenyGroup "G_Deny_HOME"
        if ($EnableRoamingProfiles) {
            Reset-NTFSPermissions -Path $ProfilesShare.AdminUNC
            Set-DenyGroupPermissions -Path $ProfilesShare.AdminUNC -DenyGroup "G_Deny_PROFILES"
        }
        Log-Operation "Serwis: Naprawiono uprawnienia NTFS na głównych katalogach 'HOME', 'SKANY', 'OGOLNY', 'DZIALY', 'PROFILES'" "OK" "SERWIS"
    }
    catch {
        Log-Operation ("Serwis: Błąd podczas naprawy uprawnień NTFS na głównych katalogach: " + $_.Exception.Message) "ERROR" "SERWIS"
    }
}


function Repair-NTFS-SubDirs {
    ### Write-Host "Naprawa uprawnień NTFS na podkatalogach DZIALY i OGOLNY..." -ForegroundColor Cyan
    Log-Operation "Serwis: Rozpoczęcie naprawy uprawnień NTFS na podkatalogach 'DZIALY' i 'OGOLNY'" "OK" "SERWIS"
    $adDomain = Get-ADDomain
    $domainNetbios = $adDomain.NetBIOSName

    # DZIALY
    $dzialyPath = $DzialyShare.AdminUNC
    if (Test-Path $dzialyPath) {
        Get-ChildItem -Path $dzialyPath -Directory | ForEach-Object {
            $subdir = $_.FullName
            $groupName = $_.Name
            $groupRW = "G_RW_$groupName"
            $groupRO = "G_RO_$groupName"
            $groupRW_DZIALY = "G_RW_DZIALY_$groupName"
            $groupRO_DZIALY = "G_RO_DZIALY_$groupName"
            $groupDenyAll = "G_Deny_$groupName"
            $groupDenyDzialy = "G_Deny_DZIALY_$groupName"
            try {
                Set-NTFSPermissions `
                    -Path $subdir `
                    -FullControlGroups @($groupRW, $groupRW_DZIALY) `
                    -ReadGroups @($groupRO, $groupRO_DZIALY) `
                    -DenyDeleteGroups @($groupRW, $groupRO, $groupRW_DZIALY, $groupRO_DZIALY) `
                    -DenyAllGroups @($groupDenyAll, $groupDenyDzialy) `
                    -LogPrefix "NTFS DZIALY"
            }
            catch {
                Log-Operation "Błąd naprawy uprawnień w $subdir : $($_.Exception.Message)" "ERROR" "NTFS"
            }
        }
    }
    else {
        Log-Operation "Ścieżka DZIALY nie istnieje : $dzialyPath" "ERROR" "NTFS"
    }

    # OGOLNY
    $ogolnyPath = $OgolnyShare.AdminUNC
    if (Test-Path $ogolnyPath) {
        Get-ChildItem -Path $ogolnyPath -Directory | ForEach-Object {
            $subdir = $_.FullName
            $groupName = $_.Name
            $groupRW = "G_RW_$groupName"
            $groupRO = "G_RO_$groupName"
            $groupRW_OGOLNY = "G_RW_OGOLNY_$groupName"
            $groupRO_OGOLNY = "G_RO_OGOLNY_$groupName"
            $groupDenyAll = "G_Deny_$groupName"
            $groupDenyOgolny = "G_Deny_OGOLNY_$groupName"
            try {
                Set-NTFSPermissions `
                    -Path $subdir `
                    -FullControlGroups @($groupRW, $groupRW_OGOLNY) `
                    -ReadGroups @($groupRO, $groupRO_OGOLNY) `
                    -DenyDeleteGroups @($groupRW, $groupRO, $groupRW_OGOLNY, $groupRO_OGOLNY) `
                    -DenyAllGroups @($groupDenyAll, $groupDenyOgolny) `
                    -ExtraAccess @("Authenticated Users") `
                    -LogPrefix "NTFS OGOLNY"
            }
            catch {
                Log-Operation "Błąd naprawy uprawnień w $subdir : $($_.Exception.Message)" "ERROR" "NTFS"
            }
        }
    }
    else {
        Log-Operation "Ścieżka OGOLNY nie istnieje : $ogolnyPath" "ERROR" "NTFS"
    }

    Log-Operation "Serwis: Naprawiono uprawnienia NTFS na podkatalogach DZIALY i OGOLNY" "OK" "SERWIS"
}

function Repair-NTFS-HomeAndSkanySubDirs {
    Log-Operation "Serwis: Rozpoczęcie naprawy uprawnień NTFS na podkatalogach 'HOME', 'SKANY')" "OK" "SERWIS"
    try {
        $adDomain = Get-ADDomain
        $domainNetbios = $adDomain.NetBIOSName
    }
    catch {
        Log-Operation "Błąd pobierania informacji o domenie : $($_.Exception.Message)" "ERROR" "NTFS"
        return
    }

    # Naprawa podkatalogów HOME
    $homePath = $HomeShare.AdminUNC
    if (Test-Path $homePath) {
        Get-ChildItem -Path $homePath -Directory | ForEach-Object {
            $subdir = $_.FullName
            $userName = $_.Name
            try {
                Set-UserHomeOrSkanyPermissions -Path $subdir -UserSam $userName -DomainNetbios $domainNetbios -LogPrefix "HOME"
                Log-Operation "Naprawiono uprawnienia HOME dla $subdir" "OK" "NTFS"
            }
            catch {
                Log-Operation "Błąd naprawy uprawnień HOME w $subdir : $($_.Exception.Message)" "ERROR" "NTFS"
            }
        }
    }
    else {
        Log-Operation "Ścieżka HOME nie istnieje: $homePath" "ERROR" "NTFS"
    }

    # Naprawa podkatalogów SKANY
    $skanyPath = $SkanyShare.AdminUNC
    if (Test-Path $skanyPath) {
        Get-ChildItem -Path $skanyPath -Directory | ForEach-Object {
            $subdir = $_.FullName
            $userName = $_.Name
            try {
                Set-UserHomeOrSkanyPermissions -Path $subdir -UserSam $userName -DomainNetbios $domainNetbios -LogPrefix "SKANY"
                Log-Operation "Naprawiono uprawnienia SKANY dla $subdir" "OK" "NTFS"
            }
            catch {
                Log-Operation "Błąd naprawy uprawnień SKANY w $subdir : $($_.Exception.Message)" "ERROR" "NTFS"
            }
        }
    }
    else {
        Log-Operation "Ścieżka SKANY nie istnieje: $skanyPath" "ERROR" "NTFS"
    }

    
    Log-Operation "Serwis: Naprawiono uprawnienia NTFS na podkatalogach HOME, SKANY oraz PROFILES (jeśli aktywne)" "OK" "SERWIS"
}

function Repair-UsersInOU {
    $adDomain = Get-ADDomain
    $domainNetbios = $adDomain.NetBIOSName
    $ProfilesShare = $settings.Settings.PROFILES
    $EnableRoamingProfiles = $false
    if ($ProfilesShare.RoammingProfiles -eq "True") { $EnableRoamingProfiles = $true }

    $distinguishedName = $adDomain.DistinguishedName
    $ouInput = Read-Host "Podaj nazwę jednostki organizacyjnej lub ścieżkę LDAP"
    if ([string]::IsNullOrWhiteSpace($ouInput)) {
        Log-Operation "Nie podano jednostki organizacyjnej." "WARN" "SERWIS"
        return
    }

    $searchBase = $null
    if ($ouInput -like "OU=*,*" -or $ouInput -like "DC=*,*") {
        $searchBase = $ouInput
    }
    else {
        $ouObj = Find-OUByName $ouInput $distinguishedName
        if ($ouObj) {
            $searchBase = $ouObj.DistinguishedName
            Log-Operation ("Serwis: Znaleziono OU: " + $ouObj.Name + " (" + $searchBase + ")") "OK" "SERWIS"
        }
        else {
            Log-Operation ("Serwis: Nie znaleziono OU o nazwie " + $ouInput + " w domenie!") "ERROR" "SERWIS"
            return
        }
    }

    try {
        $users = Get-ADUser -SearchBase $searchBase -Filter * -ErrorAction Stop
    }
    catch {
        Log-Operation ("Serwis: Błąd podczas wyszukiwania użytkowników w jednostce: " + $_.Exception.Message) "ERROR" "SERWIS"
        return
    }

    if (!$users -or $users.Count -eq 0) {
        Log-Operation ("Serwis: Nie znaleziono użytkowników w jednostce " + $searchBase) "WARN" "SERWIS"
        return
    }

    Log-Operation ("Serwis: Znaleziono " + $users.Count + " użytkowników w jednostce " + $searchBase) "OK" "SERWIS"
    foreach ($user in $users) {
        $SamAccountName = $user.SamAccountName
        Log-Operation ("Serwis: Sprawdzanie użytkownika " + $SamAccountName) "INFO" "SERWIS"

        # HOME/SKANY
        $homePathUNC = Join-Path $HomeShare.UNC $SamAccountName
        $skanyPathUNC = Join-Path $SkanyShare.UNC $SamAccountName
        $homePathAdmin = Join-Path $HomeShare.AdminUNC $SamAccountName
        $skanyPathAdmin = Join-Path $SkanyShare.AdminUNC $SamAccountName

        $missing = @()
        if (-not (Test-Path $homePathUNC)) { $missing += "HOME" }
        if (-not (Test-Path $skanyPathUNC)) { $missing += "SKANY" }

        if ($missing.Count -gt 0) {
            Log-Operation ("Serwis: Brakujące katalogi: " + ($missing -join ', ') + " dla " + $SamAccountName) "WARN" "SERWIS"
            $resp = Read-Host "Czy utworzyć brakujące katalogi i nadać uprawnienia? (T/N)"
            if ($resp -eq 'T' -or $resp -eq 't') {
                if ($missing -contains "HOME") {
                    New-Item -Path $homePathUNC -ItemType Directory | Out-Null
                    Log-Operation ("Serwis: Utworzono katalog HOME: " + $homePathUNC) "OK" "SERWIS"
                    Set-UserHomeOrSkanyPermissions -Path $homePathAdmin -UserSam $SamAccountName -DomainNetbios $domainNetbios -LogPrefix "HOME"
                }
                if ($missing -contains "SKANY") {
                    New-Item -Path $skanyPathUNC -ItemType Directory | Out-Null
                    Log-Operation ("Serwis: Utworzono katalog SKANY: " + $skanyPathUNC) "OK" "SERWIS"
                    Set-UserHomeOrSkanyPermissions -Path $skanyPathAdmin -UserSam $SamAccountName -DomainNetbios $domainNetbios -LogPrefix "SKANY"
                }
            }
            else {
                Log-Operation ("Serwis: Użytkownik zrezygnował z tworzenia brakujących katalogów dla " + $SamAccountName) "WARN" "SERWIS"
            }
        }
        else {
            Log-Operation ("Serwis: Katalogi HOME i SKANY istnieją dla " + $SamAccountName) "OK" "SERWIS"
        }

        $userAD = Get-ADUser -Identity $SamAccountName -Properties HomeDirectory, HomeDrive
        if (-not $userAD.HomeDirectory -or -not $userAD.HomeDrive) {
            Log-Operation ("Serwis: Brak ustawionego katalogu domowego lub litery dysku dla " + $SamAccountName) "WARN" "SERWIS"
            $resp = Read-Host "Czy ustawić katalog domowy i literę dysku? (T/N)"
            if ($resp -eq 'T' -or $resp -eq 't') {
                Set-ADUser -Identity $SamAccountName -HomeDirectory $homePathUNC -HomeDrive $HomeShare.DriveLetter
                Log-Operation ("Serwis: Ustawiono katalog domowy " + $homePathUNC + " i literę " + $HomeShare.DriveLetter + " dla " + $SamAccountName) "OK" "SERWIS"
            }
            else {
                Log-Operation ("Serwis: Użytkownik zrezygnował z ustawienia katalogu domowego dla " + $SamAccountName) "WARN" "SERWIS"
            }
        }
        else {
            Log-Operation ("Serwis: Konto użytkownika " + $SamAccountName + " ma ustawiony katalog domowy i literę dysku.") "OK" "SERWIS"
        }


    }
    Log-Operation ("Serwis: Naprawa kont użytkowników w jednostce zakończona dla jednostki " + $searchBase) "OK" "SERWIS"
}


function Reset-PasswordsInOU {
    $adDomain = Get-ADDomain
    $distinguishedName = $adDomain.DistinguishedName

    $ouInput = Read-Host "Podaj nazwę jednostki organizacyjnej lub ścieżkę LDAP"
    if ([string]::IsNullOrWhiteSpace($ouInput)) {
        Log-Operation "Serwis: Nie podano jednostki organizacyjnej." "ERROR" "SERWIS"
        return
    }

    # Szukaj OU po nazwie lub DN
    $searchBase = $null
    if ($ouInput -like "OU=*,*" -or $ouInput -like "DC=*,*") {
        $searchBase = $ouInput
    }
    else {
        $ouObj = Find-OUByName $ouInput $distinguishedName
        if ($ouObj) {
            $searchBase = $ouObj.DistinguishedName
            Log-Operation ("Serwis: Znaleziono OU: " + $ouObj.Name + " (" + $searchBase + ")") "OK" "SERWIS"
        }
        else {
            Log-Operation ("Serwis: Nie znaleziono OU o nazwie " + $ouInput + " w domenie!") "ERROR" "SERWIS"
            return
        }
    }

    $users = @()
    try {
        $users = Get-ADUser -SearchBase $searchBase -Filter * -ErrorAction Stop
    }
    catch {
        Log-Operation ("Serwis: Błąd podczas wyszukiwania użytkowników w jednostce: " + $_.Exception.Message) "ERROR" "SERWIS"
        return
    }

    if (!$users -or $users.Count -eq 0) {
        Log-Operation ("Serwis: Nie znaleziono użytkowników w jednostce " + $searchBase) "WARN" "SERWIS"
        return
    }

    $newPassword = Read-Host "Podaj nowe hasło dla wszystkich użytkowników (wpisz ostrożnie!)"
    if ([string]::IsNullOrWhiteSpace($newPassword)) {
        Log-Operation "Nie podano hasła. Operacja przerwana." "ERROR" "SERWIS"
        return
    }
    $securePass = ConvertTo-SecureString $newPassword -AsPlainText -Force

    foreach ($user in $users) {
        try {
            Set-ADAccountPassword -Identity $user.SamAccountName -NewPassword $securePass -Reset
            Log-Operation ("Serwis: Zresetowano hasło użytkownika " + $user.SamAccountName) "OK" "SERWIS"
        }
        catch {
            Log-Operation ("Serwis: Błąd przy resetowaniu hasła użytkownika " + $user.SamAccountName + ": " + $_.Exception.Message) "ERROR" "SERWIS"
        }
    }
    Log-Operation ("Serwis: Zresetowano hasła wszystkich użytkowników w jednostce " + $searchBase) "OK" "SERWIS"
}


function Force-PasswordChangeInOU {
    $adDomain = Get-ADDomain
    $distinguishedName = $adDomain.DistinguishedName

    $ouInput = Read-Host "Podaj nazwę jednostki organizacyjnej lub ścieżkę LDAP"
    if ([string]::IsNullOrWhiteSpace($ouInput)) {
        Log-Operation "Nie podano jednostki organizacyjnej." "ERROR" "SERWIS"
        return
    }

    # Szukaj OU po nazwie lub DN
    $searchBase = $null
    if ($ouInput -like "OU=*,*" -or $ouInput -like "DC=*,*") {
        $searchBase = $ouInput
    }
    else {
        $ouObj = Find-OUByName $ouInput $distinguishedName
        if ($ouObj) {
            $searchBase = $ouObj.DistinguishedName
            Log-Operation ("Serwis: Znaleziono OU: " + $ouObj.Name + " (" + $searchBase + ")") "OK" "SERWIS"
        }
        else {
            Write-Host "Nie znaleziono OU o nazwie '$ouInput' w domenie!" -ForegroundColor Red
            return
        }
    }

    $users = @()
    try {
        $users = Get-ADUser -SearchBase $searchBase -Filter * -ErrorAction Stop
    }
    catch {
        Log-Operation ("Serwis: Błąd podczas wyszukiwania użytkowników w jednostce: " + $_.Exception.Message) "ERROR" "SERWIS"
        return
    }

    if (!$users -or $users.Count -eq 0) {
        Log-Operation ("Serwis: Nie znaleziono użytkowników w jednostce " + $searchBase) "WARN" "SERWIS"
        return
    }

    foreach ($user in $users) {
        try {
            Set-ADUser -Identity $user.SamAccountName -ChangePasswordAtLogon $true
            Log-Operation ("Serwis: Wymuszono zmianę hasła przy następnym logowaniu dla " + $user.SamAccountName) "OK" "SERWIS"
        }
        catch {
            Log-Operation ("Serwis: Błąd przy wymuszaniu zmiany hasła dla " + $user.SamAccountName + ": " + $_.Exception.Message) "ERROR" "SERWIS"
        }
    }
    Log-Operation ("Serwis: Wymuszono zmianę haseł przy następnym logowaniu dla wszystkich użytkowników w jednostce " + $searchBase) "OK" "SERWIS"
}

function Disable-ForcePasswordChangeInOU {
    $adDomain = Get-ADDomain
    $distinguishedName = $adDomain.DistinguishedName

    $ouInput = Read-Host "Podaj nazwę jednostki organizacyjnej lub ścieżkę LDAP"
    if ([string]::IsNullOrWhiteSpace($ouInput)) {
        Log-Operation "Nie podano jednostki organizacyjnej." "ERROR" "SERWIS"
        return
    }

    # Szukaj OU po nazwie lub DN
    $searchBase = $null
    if ($ouInput -like "OU=*,*" -or $ouInput -like "DC=*,*") {
        $searchBase = $ouInput
    }
    else {
        $ouObj = Find-OUByName $ouInput $distinguishedName
        if ($ouObj) {
            $searchBase = $ouObj.DistinguishedName
            Log-Operation ("Serwis: Znaleziono OU: " + $ouObj.Name + " (" + $searchBase + ")") "OK" "SERWIS"
        }
        else {
            Log-Operation ("Serwis: Nie znaleziono OU o nazwie " + $ouInput + " w domenie!") "ERROR" "SERWIS"
            return
        }
    }

    $users = @()
    try {
        $users = Get-ADUser -SearchBase $searchBase -Filter * -ErrorAction Stop
    }
    catch {
        Log-Operation ("Serwis: Błąd podczas wyszukiwania użytkowników w jednostce: " + $_.Exception.Message) "ERROR" "SERWIS"
        return
    }

    if (!$users -or $users.Count -eq 0) {
        Log-Operation ("Serwis: Nie znaleziono użytkowników w jednostce " + $searchBase) "WARN" "SERWIS"
        return
    }

    foreach ($user in $users) {
        try {
            Set-ADUser -Identity $user.SamAccountName -ChangePasswordAtLogon $false
            Log-Operation ("Serwis: Wyłączono zmianę hasła przy następnym logowaniu dla " + $user.SamAccountName) "OK" "SERWIS"
        }
        catch {
            Log-Operation ("Serwis: Błąd przy wyłączaniu wymuszaniu zmiany hasła dla " + $user.SamAccountName + ": " + $_.Exception.Message) "ERROR" "SERWIS"
        }
    }
    Log-Operation ("Serwis: Wyłączono wymuszenie zmiana haseł przy następnym logowaniu dla wszystkich użytkowników w jednostce " + $searchBase) "OK" "SERWIS"
}


function Disable-AccountsInOU {
    $adDomain = Get-ADDomain
    $distinguishedName = $adDomain.DistinguishedName

    $ouInput = Read-Host "Podaj nazwę jednostki organizacyjnej lub ścieżkę LDAP"
    if ([string]::IsNullOrWhiteSpace($ouInput)) {
        Log-Operation "Nie podano jednostki organizacyjnej." "ERROR" "SERWIS"
        return
    }

    # Szukaj OU po nazwie lub DN
    $searchBase = $null
    if ($ouInput -like "OU=*,*" -or $ouInput -like "DC=*,*") {
        $searchBase = $ouInput
    }
    else {
        $ouObj = Find-OUByName $ouInput $distinguishedName
        if ($ouObj) {
            $searchBase = $ouObj.DistinguishedName
            Log-Operation ("Serwis: Znaleziono OU: " + $ouObj.Name + " (" + $searchBase + ")") "OK" "SERWIS"
        }
        else {
            Log-Operation ("Serwis: Nie znaleziono OU o nazwie " + $ouInput + " w domenie!") "ERROR" "SERWIS"
            return
        }
    }

    $users = @()
    try {
        $users = Get-ADUser -SearchBase $searchBase -Filter * -ErrorAction Stop
    }
    catch {
        Log-Operation ("Serwis: Błąd podczas wyszukiwania użytkowników w jednostce: " + $_.Exception.Message) "ERROR" "SERWIS"
        return
    }

    if (!$users -or $users.Count -eq 0) {
        Log-Operation ("Serwis: Nie znaleziono użytkowników w jednostce " + $searchBase) "WARN" "SERWIS"
        return
    }

    foreach ($user in $users) {
        try {
            Disable-ADAccount -Identity $user.SamAccountName
            Log-Operation ("Serwis: Wyłączono konto użytkownika " + $user.SamAccountName) "OK" "SERWIS"
        }
        catch {
            Log-Operation ("Serwis: Błąd przy wyłączaniu konta użytkownika " + $user.SamAccountName + ": " + $_.Exception.Message) "ERROR" "SERWIS"
        }
    }
    Log-Operation ("Serwis: Wyłączono wszystkie konta użytkowników w jednostce " + $searchBase) "OK" "SERWIS"
}

function Enable-AccountsInOU {
    $adDomain = Get-ADDomain
    $distinguishedName = $adDomain.DistinguishedName

    $ouInput = Read-Host "Podaj nazwę jednostki organizacyjnej lub ścieżkę LDAP"
    if ([string]::IsNullOrWhiteSpace($ouInput)) {
        Log-Operation "Nie podano jednostki organizacyjnej." "ERROR" "SERWIS"
        return
    }

    # Szukaj OU po nazwie lub DN
    $searchBase = $null
    if ($ouInput -like "OU=*,*" -or $ouInput -like "DC=*,*") {
        $searchBase = $ouInput
    }
    else {
        $ouObj = Find-OUByName $ouInput $distinguishedName
        if ($ouObj) {
            $searchBase = $ouObj.DistinguishedName
            Log-Operation ("Serwis: Znaleziono OU: " + $ouObj.Name + " (" + $searchBase + ")") "OK" "SERWIS"
        }
        else {
            Log-Operation ("Serwis: Nie znaleziono OU o nazwie " + $ouInput + " w domenie!") "ERROR" "SERWIS"
            return
        }
    }

    $users = @()
    try {
        $users = Get-ADUser -SearchBase $searchBase -Filter * -ErrorAction Stop
    }
    catch {
        Log-Operation ("Serwis: Błąd podczas wyszukiwania użytkowników w jednostce: " + $_.Exception.Message) "ERROR" "SERWIS"
        return
    }

    if (!$users -or $users.Count -eq 0) {
        Log-Operation ("Serwis: Nie znaleziono użytkowników w jednostce " + $searchBase) "WARN" "SERWIS"
        return
    }

    foreach ($user in $users) {
        try {
            Enable-ADAccount -Identity $user.SamAccountName
            Log-Operation ("Serwis: Włączono konto użytkownika " + $user.SamAccountName) "OK" "SERWIS"
        }
        catch {
            Log-Operation ("Serwis: Błąd przy włączaniu konta użytkownika " + $user.SamAccountName + ": " + $_.Exception.Message) "ERROR" "SERWIS"
        }
    }
    Log-Operation ("Serwis: Włączono wszystkie konta użytkowników w jednostce " + $searchBase) "OK" "SERWIS"
}

function Create-MissingGroupsInOUAndChildren {
    # Pętla wymuszająca poprawny input
    do {
        $OUInput = Read-Host "Podaj nazwę jednostki organizacyjnej lub pełny DN (np. OU=IT,OU=Oddzial,DC=...)"
        if ([string]::IsNullOrWhiteSpace($OUInput)) {
            Log-Operation "Nie podano jednostki organizacyjnej. Proszę spróbuj ponownie." "ERROR" "SERWIS"
        }
    } while ([string]::IsNullOrWhiteSpace($OUInput))

    $adDomain = Get-ADDomain
    $domainDN = $adDomain.DistinguishedName

    # Ustal DN OU i nazwę działu
    $searchBase = $null
    $Nazwa_Dzialu = $null

    if ($OUInput -like "OU=*,*" -or $OUInput -like "DC=*,*") {
        $searchBase = $OUInput
        if ($searchBase -match "^OU=([^,]+),") {
            $Nazwa_Dzialu = $Matches[1]
        }
    }
    else {
        # Szukaj po nazwie w całym drzewie domeny (rekurencyjnie)
        $ouList = @(Get-ADOrganizationalUnit -Filter "Name -eq '$OUInput'" -SearchBase $domainDN -SearchScope Subtree -ErrorAction SilentlyContinue)
        if ($ouList.Count -eq 0) {
            Log-Operation "Nie znaleziono OU o nazwie '$OUInput' w domenie!" "ERROR" "SERWIS"
            return
        }
        elseif ($ouList.Count -eq 1) {
            $searchBase = $ouList[0].DistinguishedName
            $Nazwa_Dzialu = $ouList[0].Name
            Log-Operation "Znaleziono OU: $Nazwa_Dzialu ($searchBase)" "OK" "SERWIS"
        }
        else {
            Log-Operation "Znaleziono kilka OU o nazwie '$OUInput':" "WARN" "SERWIS"
            for ($i = 0; $i -lt $ouList.Count; $i++) {
                Write-Host "$($i+1). $($ouList[$i].DistinguishedName)"
            }
            $choice = Read-Host "Podaj numer OU, której chcesz użyć"
            if ($choice -match '^\d+$' -and $choice -ge 1 -and $choice -le $ouList.Count) {
                $searchBase = $ouList[$choice - 1].DistinguishedName
                $Nazwa_Dzialu = $ouList[$choice - 1].Name
                Log-Operation "Wybrano OU: $Nazwa_Dzialu ($searchBase)" "OK" "SERWIS"
            }
            else {
                Log-Operation "Nieprawidłowy wybór." "ERROR" "SERWIS"
                return
            }
        }
    }

    if ([string]::IsNullOrWhiteSpace($searchBase)) {
        Log-Operation "Nie można ustalić DN jednostki organizacyjnej." "ERROR" "SERWIS"
        return
    }

    # Pobierz wszystkie OU podrzędne (rekurencyjnie)
    $allOUs = @($searchBase)
    $childOUs = @(Get-ADOrganizationalUnit -SearchBase $searchBase -SearchScope Subtree -Filter * -ErrorAction SilentlyContinue)
    if ($childOUs.Count -gt 0) {
        $allOUs += $childOUs | ForEach-Object { $_.DistinguishedName }
    }

    foreach ($ouDN in $allOUs) {
        if ($ouDN -match '^OU=([^,]+),') {
            $ouName = $Matches[1]
        }
        else {
            $ouName = "Unknown"
        }

        # Grupy podstawowe i dodatkowe DENY
        $groupRW = "G_RW_$ouName"
        $groupRO = "G_RO_$ouName"
        $groupRW_OGOLNY = "G_RW_OGOLNY_$ouName"
        $groupRW_DZIALY = "G_RW_DZIALY_$ouName"
        $groupRO_OGOLNY = "G_RO_OGOLNY_$ouName"
        $groupRO_DZIALY = "G_RO_DZIALY_$ouName"
        $groupMain = "G_$ouName"
        $groupDenyAll = "G_Deny_$ouName"
        $groupDenyOgolny = "G_Deny_OGOLNY_$ouName"
        $groupDenyDzialy = "G_Deny_DZIALY_$ouName"

        $requiredGroups = @(
            $groupRW,
            $groupRO,
            $groupMain,
            $groupDenyAll,
            $groupDenyOgolny,
            $groupDenyDzialy,
            $groupRW_OGOLNY,
            $groupRW_DZIALY,
            $groupRO_OGOLNY,
            $groupRO_DZIALY
        )

        foreach ($grp in $requiredGroups) {
            if (-not (Get-ADGroup -Filter "Name -eq '$grp'" -SearchBase $ouDN -ErrorAction SilentlyContinue)) {
                try {
                    New-ADGroup -Name $grp -GroupScope Global -Path $ouDN
                    Log-Operation "Serwis: Utworzono brakującą grupę: $grp w $ouDN" "OK" "SERWIS"
                }
                catch {
                    Log-Operation ("Serwis: Błąd podczas tworzenia grupy " + $grp + ": " + $_.Exception.Message) "ERROR" "SERWIS"
                }
            }
            else {
                Log-Operation "Serwis: Grupa $grp już istnieje w $ouDN" "WARN" "SERWIS"
            }
        }
		
        # Dodaj grupę główną do RW tylko jeśli nie jest już jej członkiem
        try {
            $rwMembers = Get-ADGroupMember -Identity $groupRW -ErrorAction Stop | Where-Object { $_.objectClass -eq 'group' }
            $mainGroupObj = Get-ADGroup -Identity $groupMain -ErrorAction Stop
            $isMember = $rwMembers | Where-Object { $_.DistinguishedName -eq $mainGroupObj.DistinguishedName }
            if (-not $isMember) {
                Add-ADGroupMember -Identity $groupRW -Members $groupMain
                Log-Operation "Dodano grupę $groupMain do $groupRW" "OK" "GRUPA"
            }
            else {
                Log-Operation "Grupa $groupMain już jest członkiem $groupRW" "WARN" "GRUPA"
            }
        }
        catch {
            Log-Operation ("Błąd przy dodawaniu " + $groupMain + " do " + $groupRW + ": " + $_.Exception.Message) "ERROR" "GRUPA"
        }
		
        # Dodaj grupę główną do RW_DZIALY tylko jeśli nie jest już jej członkiem
        try {
            $rwMembers = Get-ADGroupMember -Identity $groupRW_DZIALY -ErrorAction Stop | Where-Object { $_.objectClass -eq 'group' }
            $mainGroupObj = Get-ADGroup -Identity $groupMain -ErrorAction Stop
            $isMember = $rwMembers | Where-Object { $_.DistinguishedName -eq $mainGroupObj.DistinguishedName }
            if (-not $isMember) {
                Add-ADGroupMember -Identity $groupRW_DZIALY -Members $groupMain
                Log-Operation "Dodano grupę $groupMain do $groupRW_DZIALY" "OK" "GRUPA"
            }
            else {
                Log-Operation "Grupa $groupMain już jest członkiem $groupRW_DZIALY" "WARN" "GRUPA"
            }
        }
        
        catch {
            Log-Operation ("Błąd przy dodawaniu " + $groupMain + " do " + $groupRW_DZIALY + ": " + $_.Exception.Message) "ERROR" "GRUPA"
        }

		
        # Dodaj grupę główną do RW_OGOLNY tylko jeśli nie jest już jej członkiem
        try {
            $rwMembers = Get-ADGroupMember -Identity $groupRW_OGOLNY -ErrorAction Stop | Where-Object { $_.objectClass -eq 'group' }
            $mainGroupObj = Get-ADGroup -Identity $groupMain -ErrorAction Stop
            $isMember = $rwMembers | Where-Object { $_.DistinguishedName -eq $mainGroupObj.DistinguishedName }
            if (-not $isMember) {
                Add-ADGroupMember -Identity $groupRW_OGOLNY -Members $groupMain
                Log-Operation "Dodano grupę $groupMain do $groupRW_OGOLNY" "OK" "GRUPA"
            }
            else {
                Log-Operation "Grupa $groupMain już jest członkiem $groupRW_OGOLNY" "WARN" "GRUPA"
            }
        }
        
        catch {
            Log-Operation ("Błąd przy dodawaniu " + $groupMain + " do " + $groupRW_OGOLNY + ": " + $_.Exception.Message) "ERROR" "GRUPA"
        }

		
    }

    Write-Host "Operacja zakończona." -ForegroundColor Cyan
    Log-Operation "Operacja zakończona." "OK" "SERWIS"
}


function Create-MissingFoldersInOUAndChildren {
    # Pobierz domenę i ścieżki udziałów
    $adDomain = Get-ADDomain
    $domainDN = $adDomain.DistinguishedName
    $dzialyAdminUNC = $DzialyShare.AdminUNC
    $ogolnyAdminUNC = $OgolnyShare.AdminUNC

    # Zapytaj użytkownika o OU startowe (możesz też ustawić domyślne)
    $OUInput = Read-Host "Podaj nazwę jednostki organizacyjnej lub pełny DN (np. OU=IT,OU=Oddzial,DC=...)"
    if ([string]::IsNullOrWhiteSpace($OUInput)) {
        Log-Operation "Nie podano jednostki organizacyjnej. Przerwano." "ERROR" "SERWIS"
        return
    }

    # Ustal DN OU i nazwę działu
    $searchBase = $null
    if ($OUInput -like "OU=*,*" -or $OUInput -like "DC=*,*") {
        $searchBase = $OUInput
    }
    else {
        $ouList = @(Get-ADOrganizationalUnit -Filter "Name -eq '$OUInput'" -SearchBase $domainDN -SearchScope Subtree -ErrorAction SilentlyContinue)
        if ($ouList.Count -eq 0) {
            Log-Operation "Nie znaleziono OU o nazwie '$OUInput' w domenie!" "ERROR" "SERWIS"
            return
        }
        elseif ($ouList.Count -eq 1) {
            $searchBase = $ouList[0].DistinguishedName
        }
        else {
            Write-Host "Znaleziono kilka OU o nazwie '$OUInput':"
            Log-Operation "Znaleziono kilka OU o nazwie '$OUInput':" "WARN" "SERWIS"
            for ($i = 0; $i -lt $ouList.Count; $i++) {
                Write-Host "$($i+1). $($ouList[$i].DistinguishedName)"
                Log-Operation "$($i+1). $($ouList[$i].DistinguishedName)" "WARN" "SERWIS"
            }
            $choice = Read-Host "Podaj numer OU, której chcesz użyć"
            if ($choice -match '^\d+$' -and $choice -ge 1 -and $choice -le $ouList.Count) {
                $searchBase = $ouList[$choice - 1].DistinguishedName
            }
            else {
                Log-Operation "Nieprawidłowy wybór." "ERROR" "SERWIS"
                return
            }
        }
    }

    if ([string]::IsNullOrWhiteSpace($searchBase)) {
        Log-Operation "Nie można ustalić DN jednostki organizacyjnej." "ERROR" "SERWIS"
        return
    }

    # Pobierz wszystkie OU podrzędne (rekurencyjnie)
    $allOUs = @($searchBase)
    $childOUs = @(Get-ADOrganizationalUnit -SearchBase $searchBase -SearchScope Subtree -Filter * -ErrorAction SilentlyContinue)
    if ($childOUs.Count -gt 0) {
        $allOUs += $childOUs | ForEach-Object { $_.DistinguishedName }
    }

    foreach ($ouDN in $allOUs) {
        if ($ouDN -match '^OU=([^,]+),') {
            $ouName = $Matches[1]
        }
        else {
            $ouName = "Unknown"
        }

        # Ścieżki katalogów na podstawie nazwy OU
        $dzialyPath = Join-Path $dzialyAdminUNC $ouName
        $ogolnyPath = Join-Path $ogolnyAdminUNC $ouName

        # Nazwy grup powiązanych z OU
        $groupRW = "G_RW_$ouName"
        $groupRO = "G_RO_$ouName"
        $groupRW_OGOLNY = "G_RW_OGOLNY_$ouName"
        $groupRW_DZIALY = "G_RW_DZIALY_$ouName"
        $groupRO_OGOLNY = "G_RO_OGOLNY_$ouName"
        $groupRO_DZIALY = "G_RO_DZIALY_$ouName"
        $groupMain = "G_$ouName"
        $groupDenyAll = "G_Deny_$ouName"
        $groupDenyOgolny = "G_Deny_OGOLNY_$ouName"
        $groupDenyDzialy = "G_Deny_DZIALY_$ouName"

        # Utwórz katalog DZIALY jeśli nie istnieje
        if (-not (Test-Path $dzialyPath)) {
            try {
                New-Item -Path $dzialyPath -ItemType Directory | Out-Null
                Log-Operation "Utworzono brakujący katalog DZIALY: $dzialyPath" "OK" "KATALOG"
                Set-NTFSPermissions `
                    -Path $dzialyPath `
                    -FullControlGroups @($groupRW, $groupRW_DZIALY) `
                    -ReadGroups @($groupRO, $groupRO_DZIALY) `
                    -DenyDeleteGroups @($groupRW, $groupRO, $groupRW_DZIALY, $groupRO_DZIALY) `
                    -DenyAllGroups @($groupDenyAll, $groupDenyDzialy) `
                    -LogPrefix "NTFS DZIALY"
            }
            catch {
                Log-Operation ("Błąd tworzenia katalogu DZIALY ${dzialyPath}: " + $_.Exception.Message) "ERROR" "KATALOG"
            }
        }

        # Utwórz katalog OGOLNY jeśli nie istnieje
        if (-not (Test-Path $ogolnyPath)) {
            try {
                New-Item -Path $ogolnyPath -ItemType Directory | Out-Null
                Log-Operation "Utworzono brakujący katalog OGOLNY: $ogolnyPath" "OK" "KATALOG"
                Set-NTFSPermissions `
                    -Path $ogolnyPath `
                    -FullControlGroups @($groupRW, $groupRW_OGOLNY) `
                    -ReadGroups @($groupRO, $groupRO_OGOLNY) `
                    -DenyDeleteGroups @($groupRW, $groupRO, $groupRW_OGOLNY, $groupRO_OGOLNY) `
                    -DenyAllGroups @($groupDenyAll, $groupDenyOgolny) `
                    -ExtraAccess @("Authenticated Users") `
                    -LogPrefix "NTFS OGOLNY"
            }
            catch {
                Log-Operation ("Błąd tworzenia katalogu OGOLNY ${ogolnyPath}: " + $_.Exception.Message) "ERROR" "KATALOG"
            }
        }
    }

    Log-Operation "Serwis: Uzupełniono brakujące katalogi w 'DZIALY' i 'OGOLNY' na podstawie struktury jednostki $ouDN." "OK" "SERWIS"
}


function Convert-UniversalToGlobalGroups {
    $adDomain = Get-ADDomain
    $distinguishedName = $adDomain.DistinguishedName

    $ouInput = Read-Host "Podaj nazwę jednostki organizacyjnej lub ścieżkę LDAP"
    if ([string]::IsNullOrWhiteSpace($ouInput)) {
        Log-Operation "Nie podano jednostki organizacyjnej" "ERROR" "OU"
        return
    }

    # Wyszukiwanie OU
    $searchBase = $null
    if ($ouInput -match "OU=|DC=") {
        $searchBase = $ouInput
    }
    else {
        $ouObj = Find-OUByName -OUName $ouInput -SearchBase $distinguishedName
        if ($ouObj) {
            $searchBase = $ouObj.DistinguishedName
            Log-Operation "Znaleziono OU: $($ouObj.Name) ($searchBase)" "OK" "OU"
        }
        else {
            Write-Host "Nie znaleziono OU '$ouInput'" -ForegroundColor Red
            Log-Operation "Nie znaleziono OU '$ouInput'" "ERROR" "OU"
            return
        }
    }

    # Pobieranie grup uniwersalnych
    $universalGroups = @()
    try {
        $universalGroups = Get-ADGroup `
            -SearchBase $searchBase `
            -SearchScope Subtree `
            -Filter "GroupScope -eq 'Universal'" `
            -ErrorAction Stop
    }
    catch {
        Log-Operation "Błąd pobierania grup: $($_.Exception.Message)" "ERROR" "GRUPA"
        return
    }

    # Konwersja grup
    foreach ($group in $universalGroups) {
        try {
            Set-ADGroup `
                -Identity $group.DistinguishedName `
                -GroupScope Global `
                -Confirm:$false
            Log-Operation "Zmieniono zakres grupy $($group.Name) na Global" "OK" "GRUPA"
        }
        catch {
            Log-Operation "Błąd konwersji grupy $($group.Name): $($_.Exception.Message)" "ERROR" "GRUPA"
        }
    }
}





# KONIEC FUNKCJI SERWISOWYCH




# MENU GŁÓWNE
Log-Operation "=== ROZPOCZĘCIE WYWOŁANIA SKRYPTU ===" "OK" "SYSTEM"


# Logowanie ścieżki do pliku XML
Log-Operation "Ścieżka do pliku XML: $SettingsPath" "INFO" "SYSTEM"

# Logowanie bieżącej zawartości pliku XML
try {
    $xmlContent = Get-Content -Path $SettingsPath -Raw -Encoding UTF8
    Log-Operation "`n=== POCZĄTEK PLIKU $SettingsPath ===`n$xmlContent`n=== KONIEC PLIKU $SettingsPath ===`n" "INFO" "SYSTEM" -FileOnly
}
catch {
    Log-Operation "Błąd odczytu pliku XML: $($_.Exception.Message)" "ERROR" "SYSTEM"
}

# Logowanie bieżącej zawartości pliku users.txt
try {
    if (Test-Path $UsersFilePath) {
        $usersContent = Get-Content -Path $UsersFilePath -Raw -Encoding UTF8
        Log-Operation "`n=== POCZĄTEK PLIKU $UsersFilePath ===`n$usersContent`n=== KONIEC PLIKU $UsersFilePath ===`n" "INFO" "SYSTEM" -FileOnly
    }
    else {
        Log-Operation "Plik users.txt nie istnieje: $UsersFilePath" "WARN" "SYSTEM"
    }
}
catch {
    Log-Operation "Błąd odczytu pliku users.txt: $($_.Exception.Message)" "ERROR" "SYSTEM"
}

# Logowanie bieżącej zawartości pliku dzialy.txt
try {
    if (Test-Path $GroupsFilePath) {
        $dzialyContent = Get-Content -Path $GroupsFilePath -Raw -Encoding UTF8
        Log-Operation "`n=== POCZĄTEK PLIKU $GroupsFilePath ===`n$dzialyContent`n=== KONIEC PLIKU $GroupsFilePath ===`n" "INFO" "SYSTEM" -FileOnly
    }
    else {
        Log-Operation "Plik dzialy.txt nie istnieje: $GroupsFilePath" "WARN" "SYSTEM"
    }
}
catch {
    Log-Operation "Błąd odczytu pliku dzialy.txt: $($_.Exception.Message)" "ERROR" "SYSTEM"
}



while ($true) {
    Write-Host ""
    Write-Host "=== MENU GŁÓWNE ===" -ForegroundColor Cyan
    Write-Host "0. Przygotowanie środowiska (Jednostki organizacyjne, ścieżki, udziały sieciowe, uprawnienia do głównych katalogów, ABE)" -ForegroundColor DarkGray
    Write-Host "1. Generowanie kont użytkowników, katalogów domowych, katalogów w folderze 'HOME'' SKANY' na postawie pliku " -NoNewLine
	Write-Host "'$UsersFilePath'" -ForegroundColor Green
    Write-Host "2. Generowanie jednostek organizacyjnych, grup, katalogów współdzielonych w folderach 'DZIALY' i 'OGOLNY' na podstawie pliku " -NoNewLine
	Write-Host "'$GroupsFilePath'"-ForegroundColor Green
    Write-Host "3. Interaktywne tworzenie pojedynczego użytkownika wraz z katalogami w folderach 'HOME' 'SKANY'"
    Write-Host "4. Interaktywne tworzenie pojedynczego działu wraz z grupami katalogami w folderach 'DZIALY' i 'OGOLNY'"

    #    Write-Host "S. Menu serwisowe" -ForegroundColor Yellow -BackgroundColor Red
    Write-Host "Q. Wyjście"
    $opcja = Read-Host "Podaj numer opcji"
    if ($opcja -eq 'Q' -or $opcja -eq 'q') { break }
    if ($opcja -eq 'S' -or $opcja -eq 's') {
        Log-Operation "=== WYWOŁANO MENU SERWISOWE ===" "OK" "SERWIS"
        while ($true) {
            Write-Host ""
            Write-Host "=== MENU SERWISOWE ===" -ForegroundColor Magenta
            Write-Host ""
            Write-Host "1. Naprawa wskazanego konta użytkownika"
            Write-Host "2. Naprawa wszystkich kont użytkowników we wskazanej jednostce"
            Write-Host "3. Naprawa uprawnień katalogów głównych ('HOME', 'SKANY', 'DZIALY', 'OGOLNY', 'PROFILES')"
            Write-Host "4. Naprawa brakujących grup we wskazanej jednostce"
            Write-Host "5. Utworzenie brakujących podkatalogów ('DZIALY', 'OGOLNY') na postawie struktury OU wskazanej jednostki"
            Write-Host "6. Naprawa uprawnień podkatalogów ('DZIALY', 'OGOLNY')"
            Write-Host "7. Naprawa uprawnień podkatalogów ('HOME', 'SKANY')"
            Write-Host "8. Reset haseł użytkowników we wskazanej jednostce"
            Write-Host "9. Wymuszenie zmiany hasła użytkowników we wskazanej jednostce"
            Write-Host "10. Wyłączenie wymuszenia zmiany hasła użytkowników we wskazanej jednostce"
            Write-Host "11. Wyłączenie wszystkich kont użytkowników we wskazanej jednostce"
            Write-Host "12. Włączenie wszystkich kont użytkowników we wskazanej jednostce"
            Write-Host "13. Konwersja grup uniwersalnych na globalne we wskazanej jednostce"
            Write-Host "Q. Wyjście do menu głównego"
            $serwis = Read-Host "Podaj numer opcji serwisowej"
            if ($serwis -eq "Q" -or $serwis -eq "q") { break }
            if ($serwis -eq "1") { Repair-UserAccount }
            elseif ($serwis -eq "2") { Repair-UsersInOU }
            elseif ($serwis -eq "3") { Repair-NTFS-RootDirs }
            elseif ($serwis -eq "4") { Create-MissingGroupsInOUAndChildren }
            elseif ($serwis -eq "5") { Create-MissingFoldersInOUAndChildren }
            elseif ($serwis -eq "6") { Repair-NTFS-SubDirs }
            elseif ($serwis -eq "7") { Repair-NTFS-HomeAndSkanySubDirs }
            elseif ($serwis -eq "8") { Reset-PasswordsInOU }
            elseif ($serwis -eq "9") { Force-PasswordChangeInOU }
            elseif ($serwis -eq "10") { Disable-ForcePasswordChangeInOU }
            elseif ($serwis -eq "11") { Disable-AccountsInOU }
            elseif ($serwis -eq "12") { Enable-AccountsInOU }
            elseif ($serwis -eq "13") { Convert-UniversalToGlobalGroups }

            else { Write-Host "Nieprawidłowa opcja serwisowa!" -ForegroundColor Red }
        }
        continue
    }
    if ($opcja -eq '0') {
        if ($settings.Settings.Configured -eq "True") {
            Write-Host "Operacja niedozwolona."  -ForegroundColor Yellow -BackgroundColor Red
            Log-Operation "=== WYWOŁANO NIEDOZWOLONĄ OPCJĘ [0] ===" "WARN" "SYSTEM"
            continue
        }
        Initialize-Environment
        continue
    }
    if ($opcja -eq '1') {
        Generate-Users
        continue
    }
    if ($opcja -eq '2') {
        Generate-Groups
        continue
    }
    if ($opcja -eq '3') {
        Create-SingleUserInteractive
        continue
    }
    if ($opcja -eq '4') {
        Create-DepartmentInteractive
        continue
    }
	
    Write-Host "Nieprawidłowa opcja!" -ForegroundColor Red
}

Log-Operation "=== ZAKOŃCZENIE WYWOŁANIA SKRYPTU ===" "OK" "SYSTEM"
Write-Host "`nZakończono działanie skryptu." -ForegroundColor Cyan
