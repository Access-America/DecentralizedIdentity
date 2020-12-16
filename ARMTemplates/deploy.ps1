Param(
   [Parameter(Mandatory=$false)][switch]$Login = $False, 
   [Parameter(Mandatory=$false)][switch]$CreateResource = $False, 
   [Parameter(Mandatory=$false)][switch]$DeployApp = $False, 
   [Parameter(Mandatory=$false)][switch]$DeleteResource = $False, 
   [Parameter(Mandatory=$false)][string]$resourceGroupName = "",
   [Parameter(Mandatory=$true)][string]$AppServiceName = "",
   [Parameter(Mandatory=$false)][string]$AppServicePlanName = "",
   [Parameter(Mandatory=$False)][string]$Location = "West Europe",
   [Parameter(Mandatory=$False)][string]$TemplateUri = "https://raw.githubusercontent.com/cljung/b2c-vc-verifier/main/ARMTemplates/template.json"
)

if ( $resourceGroupName -eq "") {
    $resourceGroupName = "$AppServiceName-rg"
}
if ( $AppServicePlanName -eq "" ) {
    $AppServicePlanName = "$AppServiceName-plan"
}

if ( $Login ) {
    Connect-AzAccount
}

if ( $CreateResource ) {
    New-AzResourceGroup -Name $resourceGroupName -Location $Location
    
    # deploy JSOn template    
    get-Date -format 's'

    New-AzResourceGroupDeployment -ResourceGroupName $resourceGroupName -TemplateUri $templateUri `
        -appServiceName $AppServiceName -appServicePlanName $AppServicePlanName -siteLocation $Location 

    get-Date -format 's'
}

if ( $DeployApp ) {
    get-Date -format 's'
    # https://docs.microsoft.com/en-us/azure/app-service/deploy-zip
    pushd ..\verifier
    $ZipFile = "$((get-location).Path)\verifier.zip"
    if (Test-Path $ZipFile) {
        Remove-Item $ZipFile -Force
    }
    Compress-Archive -Path * -DestinationPath $ZipFile
    Publish-AzWebapp -ResourceGroupName $resourceGroupName -Name $AppServiceName -ArchivePath $ZipFile -Force
    Remove-Item $ZipFile -Force
    popd
    get-Date -format 's'
}

if ( $DeleteResource ) {
    get-Date -format 's'
    Remove-AzResourceGroup -Name $resourceGroupName -Force
    get-Date -format 's'
}
