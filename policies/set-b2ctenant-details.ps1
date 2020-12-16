$B2CTenantName = "uscitizencenter"                     # not nameofmytenant.onmicrosoft.com
$ProxyIdentityExperienceFrameworkAppId = "72bdbb1d-de8c-4a79-8f62-8f2e3ca412ae"        # guid of the AppID for ProxyIdentityExperienceFramework
$IdentityExperienceFrameworkAppId = "35d79ddf-c928-4776-8b69-0dd65a52cff0"             # guid of the AppID for IdentityExperienceFramework
$storagePath = "https://ccuspocverifier.blob.core.windows.net/root/"
# $AppInsightInstrumentationKey = "..."                 # guid of the AppInsighs Instrumentation Key
$ServiceUrl = "https://ccusdidpoc-verifier.azurewebsites.net"

$PolicyPath = (get-location).Path
$files = get-childitem -path $PolicyPath -name -include *.xml | Where-Object {! $_.PSIsContainer }
foreach( $file in $files ) {
    $PolicyFile = (Join-Path -Path $PolicyPath -ChildPath $file)
    $PolicyData = Get-Content $PolicyFile

    $PolicyData = $PolicyData.Replace("yourtenant", $B2CTenantName)
    $PolicyData = $PolicyData.Replace("ProxyIdentityExperienceFrameworkAppId", $ProxyIdentityExperienceFrameworkAppId)
    $PolicyData = $PolicyData.Replace("IdentityExperienceFrameworkAppId", $IdentityExperienceFrameworkAppId)
    $PolicyData = $PolicyData.Replace("https://your-storage-account.blob.core.windows.net/your-container/", $storagePath)
    $PolicyData = $PolicyData.Replace("https://your-app-name-that-must-be-unique.azurewebsites.net", $ServiceUrl)
#    $PolicyData = $PolicyData.Replace("AppInsightInstrumentationKey", $AppInsightInstrumentationKey)

    Set-Content -Path $PolicyFile -Value $PolicyData
}