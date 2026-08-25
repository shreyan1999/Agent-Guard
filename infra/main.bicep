// Subscription-scoped entry point for `azd provision` / `azd up`.
// Creates one resource group and delegates resource creation to resources.bicep.
targetScope = 'subscription'

@minLength(1)
@maxLength(64)
@description('Environment name; derives resource names and the azd-env-name tag.')
param environmentName string

@minLength(1)
@description('Primary Azure region for all resources.')
param location string

@secure()
@description('Optional API keys (token:subject:tenant:roles, comma/newline separated). Empty leaves the API open (anonymous admin).')
param apiKeys string = ''

@description('Optional CORS allowlist. Same-origin hosting needs none.')
param corsOrigins string = ''

// A stable, name-safe suffix derived from the deployment identity.
var resourceToken = toLower(uniqueString(subscription().id, environmentName, location))
var tags = { 'azd-env-name': environmentName }

resource resourceGroup 'Microsoft.Resources/resourceGroups@2024-11-01' = {
  name: 'rg-${environmentName}'
  location: location
  tags: tags
}

module resources 'resources.bicep' = {
  name: 'resources'
  scope: resourceGroup
  params: {
    location: location
    resourceToken: resourceToken
    tags: tags
    apiKeys: apiKeys
    corsOrigins: corsOrigins
  }
}

output AZURE_LOCATION string = location
output AZURE_CONTAINER_REGISTRY_ENDPOINT string = resources.outputs.registryLoginServer
output SERVICE_WEB_URI string = resources.outputs.webUri
