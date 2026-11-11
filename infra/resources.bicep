// Resource-group-scoped resources for AgentGuard.
// One container running the FastAPI API and the built React dashboard, on
// Azure Container Apps, pulling from a private registry via a managed identity.
@description('Region for all resources.')
param location string

@description('Name-safe suffix shared by all resources.')
param resourceToken string

@description('Tags applied to every resource, including azd-env-name.')
param tags object

@secure()
@description('Optional API keys; when set, surfaced to the app as a secret.')
param apiKeys string = ''

@description('Optional CORS allowlist.')
param corsOrigins string = ''

// The container listens on 8000 (see the Dockerfile); ingress must match.
var appPort = 8000
var abbrs = {
  registry: 'cr'
  identity: 'id'
  containerAppsEnv: 'cae'
  containerApp: 'ca'
  logAnalytics: 'log'
}

// A placeholder until `azd deploy` builds and pushes the real image; the
// azd-service-name tag binds this app to the `web` service in azure.yaml.
var placeholderImage = 'mcr.microsoft.com/azuredocs/containerapps-helloworld:latest'

// Built-in AcrPull role, so the app's identity can pull from the registry.
var acrPullRoleId = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  '7f951dda-4ed3-4680-a7ca-43fe172d538d'
)

resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: '${abbrs.logAnalytics}-${resourceToken}'
  location: location
  tags: tags
  properties: {
    sku: { name: 'PerGB2018' }
    retentionInDays: 30
  }
}

resource identity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: '${abbrs.identity}-${resourceToken}'
  location: location
  tags: tags
}

// Private registry. Anonymous pull stays disabled and the admin user is off;
// the app authenticates with its managed identity.
resource registry 'Microsoft.ContainerRegistry/registries@2023-07-01' = {
  name: '${abbrs.registry}${resourceToken}'
  location: location
  tags: tags
  sku: { name: 'Standard' }
  properties: {
    adminUserEnabled: false
    anonymousPullEnabled: false
  }
}

// Grant the app's identity permission to pull images from the registry.
resource acrPull 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(registry.id, identity.id, acrPullRoleId)
  scope: registry
  properties: {
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: acrPullRoleId
  }
}

resource containerEnv 'Microsoft.App/managedEnvironments@2025-01-01' = {
  name: '${abbrs.containerAppsEnv}-${resourceToken}'
  location: location
  tags: tags
  properties: {
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsConfiguration: {
        customerId: logAnalytics.properties.customerId
        sharedKey: logAnalytics.listKeys().primarySharedKey
      }
    }
  }
}

// Secrets and env vars are only added when a value is supplied, so an open
// (anonymous-admin) deployment carries no empty secret.
var appSecrets = empty(apiKeys) ? [] : [
  { name: 'agt-api-keys', value: apiKeys }
]
var apiKeyEnv = empty(apiKeys) ? [] : [
  { name: 'AGT_API_KEYS', secretRef: 'agt-api-keys' }
]
var corsEnv = empty(corsOrigins) ? [] : [
  { name: 'AGT_CORS_ORIGINS', value: corsOrigins }
]

resource containerApp 'Microsoft.App/containerApps@2025-01-01' = {
  name: '${abbrs.containerApp}-${resourceToken}'
  location: location
  tags: union(tags, { 'azd-service-name': 'web' })
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${identity.id}': {}
    }
  }
  properties: {
    managedEnvironmentId: containerEnv.id
    configuration: {
      activeRevisionsMode: 'Single'
      ingress: {
        external: true
        targetPort: appPort
        transport: 'auto'
        allowInsecure: false
      }
      registries: [
        {
          server: registry.properties.loginServer
          identity: identity.id
        }
      ]
      secrets: appSecrets
    }
    template: {
      containers: [
        {
          name: 'web'
          image: placeholderImage
          resources: {
            cpu: json('0.5')
            memory: '1.0Gi'
          }
          env: concat([
            { name: 'AGT_HOST', value: '0.0.0.0' }
          ], apiKeyEnv, corsEnv)
        }
      ]
      scale: {
        // Pinned to one replica, deliberately. Every piece of governance state
        // this app holds — the agent registry, trust scores, the in-memory
        // Merkle audit chain, MCP rate-limit budgets and AGT's ring
        // circuit-breaker counters — lives in the process. A second replica
        // does not share any of it: the audit chain forks, an agent registered
        // on one replica is unregistered on the other, and an agent probing
        // its sandbox gets a fresh violation budget per replica. Scaling this
        // out needs shared state first; until then more replicas would produce
        // wrong governance answers rather than more throughput.
        minReplicas: 1
        maxReplicas: 1
      }
    }
  }
  // The image pull identity must hold AcrPull before the app is created.
  dependsOn: [
    acrPull
  ]
}

output registryLoginServer string = registry.properties.loginServer
output webUri string = 'https://${containerApp.properties.configuration.ingress.fqdn}'
