# b2c-vc-verifier

This is a modified version of the Verifiable Credentials verifier sample located [here](https://github.com/Azure-Samples/active-directory-verifiable-credentials/tree/main/verifier). It is modified to be a REST API that works with Azure AD B2C so that you can integrate it with an app that is protected by Azure AD B2C.

With this sample, you can use Verifiable Credentials as a way to authenticate to B2C. You can do that in two ways:
- One way is linking a Verifiable Credential card in the Microsoft Authenticator wallet to a B2C account. In this case the subject of the JWT token that B2C issues will be the objectId of the B2C user. 
- The other way is skipping the account linking and use the VC stand alone. In this case the subject of the JWT token that B2C issues will be the VC subject. 

In order to use the Verifiable Credentials with Azure AD B2C, you need to deploy the following:

1. Deploy this node.js verifier to an Azure App Service
1. Create an Azure Storage Account and deploy the custom html that B2C uses (explained [here](https://docs.microsoft.com/en-us/azure/active-directory-b2c/customize-ui-with-html?pivots=b2c-user-flow#2-create-an-azure-blob-storage-account))
1. Deploy an Azure AD B2C instance and setting up B2C Identity Experience Framework (explained [here](https://docs.microsoft.com/en-us/azure/active-directory-b2c/custom-policy-get-started))
1. Modify and upload the B2C Custom Policies in this github repo

# Deploy the VC Verifier to Azure App Service

## Method 1 - Installing the app without cloning it to your local laptop

Deploy the Azure AppService resource via clicking this button and providing the details.

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fcljung%2Fb2c-vc-verifier%2Fmain%2FARMTemplates%2Ftemplate.json)

Then, in portal.azure.com and in the AppService panel for your deployment, click on open SSH in the menu, then issue these commands

```bash
cd site
apt-get install git
git clone https://github.com/cljung/b2c-vc-verifier.git
cp ./b2c-vc-verifier/verifier/* ./wwwroot
cd ./wwwroot
npm install
```
  
The `npm install` command will take some time and also end with some errors, but that can be ignored. When it is completed, restart the AppService and you are good to go.

## Method 2 - Installing the app via Powershell

1. git clone this repository on your local computer
1. Open a powershell command prompt and navigate to the `ARMTemplates` folder
1. Run the command

```powershell
.\deploy.ps1 -CreateResource -DeployApp -AppServiceName "your-app-name-that-must-be-unique"
```

The deployment will take some 5-10 minutes. When completed, test that the deployment works via browsing to `https://your-app-name-that-must-be-unique.azurewebsites.net/echo`.

If you want to remove the deployment completly, you either delete the resource group in portal.azure.com or run the powershell command

```powershell
.\deploy.ps1 -DeleteResource -AppServiceName "your-app-name-that-must-be-unique"
```

# Deploy the custom html

- Create an Azure Storage Account and CORS enable it for your B2C tenant, as explained [here](https://docs.microsoft.com/en-us/azure/active-directory-b2c/customize-ui-with-html?pivots=b2c-user-flow#2-create-an-azure-blob-storage-account)). You should perform step 2 through 3.1. Note that you can select `LRS` for Replication as `RA-GRS` is a bit overkill.
- Edit the `selfAsserted.html` file and replace the url reference `var apiUrl = "https://cljungvcverifier.azurewebsites.net";` with the url for your Azure App Service deployment.
- Edit both `selfAsserted.html` and `unified.html` and replace `https://your-storage-account.blob.core.windows.net/your-container/` with the name of your storage account and container.
- Upload the files whoareyou.jpg, selfAsserted.html, unified.html to the container in the Azure Storage.
- Copy the full url to the files and test that you can access them in a browser.

Note that in `selfAsserted.html` there is a link to the page `https://cljungvcissuer.azurewebsites.net/` for issuing Verifiable Credentials of the Ninja kind. This is a deployment of the sample [VC Issuer](https://github.com/Azure-Samples/active-directory-verifiable-credentials/tree/main/verifier) and if you create your own issuer, you should replace this link.

# Deploy an Azure AD B2C instance

You need an B2C tenant instance for this sample to work. The current B2C price model is free for 50K MAU per month, so the deployment will not cost anything. How to deploy a B2C tenant is explained in the documentation [here](https://docs.microsoft.com/en-us/azure/active-directory-b2c/custom-policy-get-started). You should follow that documentation and stop when you come to section "Custom policy starter pack". You do not need to complete the Facebook part, but you should create a face Policy Key named `FacebookSecret` with a fake value like `abc123`.

# Modify and upload the B2C Custom Policies

The XML files in the [policies](/policies) folder are the B2C Custom Policies. These files are in a generic state and need to be updated to match your tenant. Therefor, the following needs to be done:

- Search-and-replace all references to `yourtenant.onmicrosoft.com` with your real tenant name, for example `contosob2c.onmicrosof.com`, in all policy xml files.
- Search-and-replace all references to `yourstorageaccount.blob.core.windows.net` with your real storage account in file `TrustFrameworkExtensions.xml`. Make sure the path matches to the full path of each uploaded html document in previous section.
- Find the `login-NonInteractive` TechnicalProfile in the `TrustFrameworkExtensions.xml` file and replace the guids for the IdentityExperienceFramework and ProxyIdentityExperienceFramework applications. You need to replace it with the AppIDs (client_id's) from the registered applications in your B2C tenant.
- Find the `ServiceUrl` for the VC Verifier deployed in Azure AppService and update it.
- Possibly add your AppInsights InstrumentationKey so you can get trace events when the B2C policy engine executes your policy.
- Upload the policies in order: `TrustFrameworkBase.xml`, `TrustFrameworkExtensions.xml` and then the rest in no particular order.

## Script to make all changes
In order to make the search-and-replace easier, there is a powershell script called [set-b2ctenant-detail.ps1](/policies/set-b2ctenant-detail.ps1) that will do all this for you and make the policies ready for upload. If you replace the variable settings in the first 6 lines with your values, you can then run this script on the folder of the policy files.

```powershell
$B2CTenantName = "nameofmytenant"                     # not nameofmytenant.onmicrosoft.com
$ProxyIdentityExperienceFrameworkAppId = "..."        # guid of the AppID for ProxyIdentityExperienceFramework
$IdentityExperienceFrameworkAppId = "..."             # guid of the AppID for IdentityExperienceFramework
$storagePath = "https://your-storage-account.blob.core.windows.net/your-container/"
$AppInsightInstrumentationKey = "..."                 # guid of the AppInsighs Instrumentation Key
$ServiceUrl = "https://your-app-name-that-must-be-unique.azurewebsites.net"

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
    $PolicyData = $PolicyData.Replace("AppInsightInstrumentationKey", $AppInsightInstrumentationKey)

    Set-Content -Path $PolicyFile -Value $PolicyData
}
```

# Registering a Test Application in your B2C tenant

You should have created a test application during the "Custom Policy Getting Started" section above. If you didn't, follow the documentation [here](https://docs.microsoft.com/en-us/azure/active-directory-b2c/tutorial-register-applications?tabs=app-reg-ga). Make sure you set the Redirect URI type to `Web` and the redirectUri to `https://jwt.ms` as it makes testing B2C policies easy.

# Testing your Verifiable Credentials

1. Create a B2C account
    1. Click on the `B2C_1A_VC_susi` policy in the portal, select your test app and run the policy and https://jwt.ms as the reply url.
    1. In the sign in user interface, select `Sign up` and create an account
1. Link a VC to your account
    1. Click on the `B2C_1A_VC_Link`  policy in the portal, select your test app and run the policy and https://jwt.ms as the reply url.
    1. Sign in using the email/password you just registered
    1. When the QR code comes, scan it with your VC in the Authenticator app on your phone
    1. When you get to the jwt.ms page, your VC is linked to the account
1. Try signing in to your B2C account using your VC
    1. Click on the `B2C_1A_VC_susi_vc`  policy in the portal, select your test app and run the policy and https://jwt.ms as the reply 
    1. When the QR code comes, scan it with your VC in the Authenticator app on your phone
    1. When you get to the jwt.ms page, notice that the `sub` claim is the objectId of your B2C user
1. Try signing in using only your VC
    1. Click on the `B2C_1A_VC_signin`  policy in the portal, select your test app and run the policy and https://jwt.ms as the reply 
    1. When the QR code comes, scan it with your VC in the Authenticator app on your phone
    1. When you get to the jwt.ms page, notice that the `sub` claim is not the objectId of your B2C user, but something from the VC token.