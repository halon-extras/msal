# Microsoft Authentication Library (MSAL) plugin

This plugin is a wrapper for the [Microsoft Authentication Library (MSAL) for Go](https://github.com/AzureAD/microsoft-authentication-library-for-go) library. It enables you to acquire security tokens to call protected APIs.

## Installation

Follow the [instructions](https://docs.halon.io/manual/comp_install.html#installation) in our manual to add our package repository and then run the below command.

### Ubuntu

```
apt-get install halon-extras-msal
```

### RHEL

```
yum install halon-extras-msal
```

## Configuration
For the configuration schema, see [msal.schema.json](msal.schema.json). Below is a sample configuration.

### smtpd.yaml

```
plugins:
  - id: msal
    config:
      tenants:
        - id: tenant1
          type: public
          client_id: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
          authority: https://login.microsoftonline.com/organizations
          scopes:
            - https://outlook.office.com/SMTP.Send
          cache_file: /tmp/msal_tenant1_cache.json
        - id: tenant2
          type: confidential
          client_id: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
          client_secret: xxxxx~xxxxxxxxxxxxxxxxxxxxxx_xxxxxxxx
          authority: https://login.microsoftonline.com/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
          scopes:
            - https://graph.microsoft.com/.default
          cache_file: /tmp/msal_tenant2_cache.json
```

## Exported functions

### msal(id, [, options])

Fetch an OAuth2 access token using the provided credentials.

**Params**

- id `string` - The ID of the tenant as configured in `smtpd.yaml`
- options `array` - Options array

The following options are available in the **options** array.

- username `string` - The username (Ony applicable to tenants of type `public`)
- password `string` - The password (Ony applicable to tenants of type `public`)

**Returns**

A successful fetch will return an associative array with a `result` key that contains the access token. On error an associative array with a `error` key will be provided.