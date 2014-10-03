# Created by Casey Cochran with Rentech Inc.  
# 
# This script recursively searches a folder tree specified by the user and
# generates a list of all explicit permissions defined on any folder in the tree.
# This is useful for determining where permission cascades begin, and for
# discovering explicit permissions down the folder tree where cascades have been broken.
# 
# The script takes a required parameter, which is a drive letter or UNC path
# of the root folder where the script will begin the recursive search. There are three
# optional parameters, email, recipients and TOPTextHTML all of which are related to 
# emailing the data. email parameter is a switch enabling email. Recipients is a 
# parameter that accepts a comma delimited list of email addresses. TOPTextHTML is
# used to add header HTML before the report (useful for sending a report direct to 
# a user like in a scheduled task)
#
# 
# Examples
# -------------------
# .\FindExplicitACLs -rootpath C:\WINDOWS -verbose
# .\FindExplicitACLs -rootpath \\myserver\mypath
# .\FindExplicitACLs -rootpath \\myserver\mypath -email -recipients test@test.com -recipients test@test.com -TOPTextHTML "<B>Filesystem audit of \\myserver\mypath:</b>"
#
[cmdletBinding()]
param (
	[parameter(Mandatory=$true,ValueFromPipeline=$true,HelpMessage="The root filesystem to scan (IE: C:\WINDOWS or \\myserver\mypath")]$rootpath,
	[switch]$email,
	[string]$recipients,
	[String]$TOPTextHTML
)

#Clear any existing errors before starting
$Error.Clear()

$logpath = "FindExplicitACL_TRANSCRIPT.log"
Start-Transcript -Path $logpath
Write-Verbose "Verbose Mode Enabled"

#This function checks that a needed module is loaded, if not loads it.
Function Get-MyModule {
	Param([string]$name)
	if(-not(Get-Module -name $name)) {
		if(Get-Module -ListAvailable | Where-Object { $_.name -eq $name }) {
			Import-Module -Name $name
			$true
		} #end if module available then import
		else { $false } #module not available
	} # end if not module
	else { $true } #module already loaded
} #end function get-MyModule 


# Call funtion to load module and break out of script if not available. 

if ((Get-MyModule activedirectory) -eq $false) { "ActiveDirectory Module could not be loaded. Please make sure it is installed." ; break }


#Sets the output file for the report
$filedate = get-date -UFormat %m-%d-%Y_%s
$rootFS = $rootpath.Split("\")[($rootpath.Split("\").count-1)]
$outfile = "ExplicitACLs_$rootfs_$filedate.csv"
$outfileHTML = "ExplicitACLsHTML_$rootfs_$filedate.HTML"

# Create object variable for the results of the search
$members = @()
#get the currently logged in domain
$wmiDomain = (Get-WmiObject Win32_NTDomain -Filter "DnsForestName = '$( (Get-WmiObject Win32_ComputerSystem).Domain)'").DomainName
write-verbose "$wmiDomain"

#get all folders and subfolders of the $rootpath (user input)
Write-Verbose "Starting scan of root folder: $rootpath"
$folders = Get-ChildItem -Recurse $rootpath -Exclude "*.*" -errorvariable +file_errors | Where-Object {$_.PSisContainer }
if ($file_errors) {$File_ErrorsHTML = $file_errors | select Exception,targetobject | convertto-html}

write-verbose "Collected folders, starting processing of ACL's"
#foreach folder we will get the ACL info for all NON-Inherited security ACL's
ForEach ($Folder in $folders) {
	write-verbose "$folder"
	# get the ACL info for the folder (this shows the user\groups with access to the folder)
	$acl = Get-Acl -Path $Folder.FullName
	# get the access for the folder (This shows the access rights, whether its allowed or denied, user\group, inheritance)
	$access = $acl.access
	# If the access is not inherited (this is what we are looking for) we will log the information
	if ( $access | Where-Object { $_.IsInherited -eq $False }) {
		write-verbose "Folder not inheriting: $Folder"
		#gather each entry in the ACL Access info and we will add that info to a variable
		foreach ($accessentry in ($access | Where-Object { $_.IsInherited -eq $False })) {
			$member = New-Object PSObject
			$member | Add-Member -MemberType NoteProperty -Name "Folder" -Value $Folder
			$member | Add-Member -MemberType NoteProperty -Name "IsInherited" -Value $accessentry.IsInherited
			$member | Add-Member -MemberType NoteProperty -Name "IdentityReference" -Value ($accessentry.IdentityReference) 
			#Determine the IdentityReference Manager. We do this because most likely rights are assigned via groups, and the group manager is deemed the OWNER of the data, otherwise if a user was entered this will return the users manager
			$cleanedIdentity = ($accessentry.IdentityReference -replace "^$wmiDomain\\") 
			Write-Verbose "Cleaned Identity: $cleanedIdentity"
			If (Get-ADObject -filter {sAMAccountName -like $cleanedIdentity} -properties managedby) { 
				if ((get-aduser (Get-ADObject -ErrorAction SilentlyContinue -filter {sAMAccountName -like $cleanedIdentity} -properties managedby).ManagedBy -properties mail).mail) {
					$member | Add-Member -MemberType NoteProperty -Name "IdentityReferenceManager" -Value (get-aduser (Get-ADObject -filter {sAMAccountName -like $cleanedIdentity} -properties managedby).ManagedBy -properties mail).mail 
				} Else {
					$member | Add-Member -MemberType NoteProperty -Name "IdentityReferenceManager" -Value "N/A"
				}
				#Add property to indicate if the object is a group
				If ((Get-ADObject -filter {sAMAccountName -like $cleanedIdentity} -properties managedby).ObjectClass -eq "group") {
					$member | Add-Member -MemberType NoteProperty -Name "IsGroup" -Value "Yes"
				} else { 
					$member | Add-Member -MemberType NoteProperty -Name "IsGroup" -Value "No" 
				}
			} ELSE { $member | Add-Member -MemberType NoteProperty -Name "IdentityReferenceManager" -Value "LocalServerAccount"}
			$member | Add-Member -MemberType NoteProperty -Name "AccessControlType" -Value $accessentry.AccessControlType
			$member | Add-Member -MemberType NoteProperty -Name "FileSystemRights" -Value $accessentry.FileSystemRights
			#Add the variable info to an array variable 
			$members += $member
			write-verbose $member
			#clear variables so we do not get bad data later
			$cleanedIdentity = $null
			$member = $null
		}
	}
	#clear variables so we do not get bad data later
	$acl = $null
	$access = $null
	$accessentry = $null
}

#Save the data to a csv and output to console and save the data to be used globally
$members | Export-csv $outfile -notypeinfo -force
$members
$global:members = $members

# Create an HTML report to email to the owner to confirm the rights assignment
#setup HTML report header
$permissionsHTML = '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"  "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
					<html xmlns="http://www.w3.org/1999/xhtml">
					<head>
					<title>HTML TABLE</title>
					<style>
						BODY{background-color:White;}
						TABLE{border-width: 1px;border-style: solid;border-color: black;border-collapse: collapse;}
						caption{border-width: 1px;padding: 0px;border-style: solid;border-color: black;background-color:DeepSkyBlue; text-align:left}
						TH{border-width: 1px;padding: 0px;border-style: solid;border-color: black;background-color:PaleTurquoise}
						TD{border-width: 1px;padding: 0px;border-style: solid;border-color: black;background-color:white}
					</style>
					</head><body>' + $TOPTextHTML + '
					<br><br>The following folders have permissions set within the share ' + $rootpath + '. The folders and permissions are listed below.<br><br><br>'
#Because we have many listings with the same folder we want to only use unique folders
$filteredFolders = $members | select -Unique folder
#for each unique folder we will process
foreach ($folder in $filteredFolders) { 
	#Add to HTML report that a folder has unique permissions
	$permissionsHTML = $permissionsHTML + '<table id="BasicTable" cellspacing="2" border=1><caption><b>' + $folder.folder + '</b></caption><tr><th>User\Group Name</th><th>User\Group Members</th><th>User\Group Manager</th><th>Permissions</th></tr>'
	#get entities with access to the foler
	$entities = $members | where { $_.Folder -like $folder.folder }
	#get entities with access to the foler process add info to HTML report
	foreach ($entity in $entities) {
		if ($entity.isgroup -eq "Yes" -AND $entity.IdentityReference -notlike "*BUILTIN\*" ) { #test to see if the identity is a group, and not a LOCAL DEFAULT (Builtin) group
			write-verbose "Entity $($entity.IdentityReference) is a group. getting group members"
			$groupmembers = ((Get-ADGroupMember ($entity.IdentityReference -replace "^$wmiDomain\\")) | select -expand samaccountname) -join ","
			$permissionsHTML = $permissionsHTML + '<tr><td>' + $entity.IdentityReference + '</td><td>' + $groupmembers + '</td><td>' + $entity.IdentityReferenceManager + '</td><td>' + $entity.AccessControlType + "\" + $entity.FileSystemRights + '</td></tr>'
		} else {
			$permissionsHTML = $permissionsHTML + '<tr><td>' + $entity.IdentityReference + '</td><td>' + $entity.IdentityReference + '</td><td>' + $entity.IdentityReferenceManager + '</td><td>' + $entity.AccessControlType + "\" + $entity.FileSystemRights + '</td></tr>'
		}
	}	
	$permissionsHTML = $permissionsHTML + "</table><br>"
	$entities = $null
	$groupmembers = $null
}
$filteredFolders = $null

#add error text if errors were observed
if ($File_ErrorsHTML -or $error){ 
	$permissionsHTML = $permissionsHTML + "<br><br>The following errors were encountered (may include access denied errors which need to be resolved for accurate results):<br>$File_ErrorsHTML <br><br>$error"
}
#drop a copy of the output to the filesystem 
$permissionsHTML | out-file $outfileHTML -force

if ($email) { #Send Email
	# if no recipient defined, send to the user who ran the script
	if (!($recipients)) {  $recipients = ([adsisearcher]"(samaccountname=$env:USERNAME)").FindOne().Properties.mail }
	$mycreds = get-credential -Message "Please enter your email credentials (used to send report)"
	Send-MailMessage -to $recipients -from (([adsisearcher]"(samaccountname=$env:USERNAME)").FindOne().Properties.mail) -Subject "Filesystem Audit - $rootpath"  -BodyAsHtml "$permissionsHTML" -Credential $mycreds -SmtpServer smtp.MAILSERVER.com
}

stop-Transcript
