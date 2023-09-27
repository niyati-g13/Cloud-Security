# PowerShell script file to be executed as a AWS Lambda function. 
# 
# When executing in Lambda the following variables will be predefined.
#   $LambdaInput - A PSObject that contains the Lambda function input data.
#   $LambdaContext - An Amazon.Lambda.Core.ILambdaContext object that contains information about the currently running Lambda environment.
#
# The last item in the PowerShell pipeline will be returned as the result of the Lambda function.
#
# To include PowerShell modules with your Lambda function, like the AWSPowerShell.NetCore module, add a "#Requires" statement 
# indicating the module and version.

#Requires -Modules @{ModuleName='AWSPowerShell.NetCore';ModuleVersion='3.3.422.0'}

# Uncomment to send the input event to CloudWatch Logs
Write-Host (ConvertTo-Json -InputObject $LambdaInput -Compress -Depth 5)

#$ORAccountIDs = (Get-ORGAccountList -ErrorAction SilentlyContinue).ID

Try {
    
    #If ( $LambdaInput.AccountID ) {

        $AccountIDs = $LambdaInput.AccountIDs

    #} #Elseif ( $ORAccountIDs ) {
    
    #   $AccountIDs = $ORAccountIDs

    #} Else {

    #   $AccountIds = (Get-EC2SecurityGroup -GroupNames "default")[0].OwnerId

    #}

    Write-Host "Account IDs - $AccountIds"

    Foreach ( $AccountId in $AccountIDs ) {
        
        Write-Host "Collecting Public Access Acl and Policy Settings on Account ID - $AccountId"
               
        #$Settings = Get-S3CPublicAccessBlock -AccountId $AccountId 

        If ( !($Settings.BlockPublicAcls) -or !($Settings.BlockPublicPolicy) ) {

            Add-S3CPublicAccessBlock -AccountId $AccountId -PublicAccessBlockConfiguration_BlockPublicAcl $true -PublicAccessBlockConfiguration_BlockPublicPolicy $true -Force
            
            $Settings = Get-S3CPublicAccessBlock -AccountId $AccountId 

            If ( $Settings.BlockPublicAcls -and $Settings.BlockPublicPolicy ) {

                Write-Host "Successly Enabled BlockPublicAcls and BlockPublicPolicy on Account ID - $AccountId"
            } Else {
                Write-Host "Failed to Enable BlockPublicAcls and BlockPublicPolicy on Account ID - $AccountId"
            }

        } Else {
            Write-Host "BlockPublicAcls and BlockPublicPolicy is Already Enabled on Account ID - $AccountId"
        }
    }

} Catch {

    Write-Error  "Error: $($_.Exception.Message)"
}
