# Microsoft Authentication Library (MSAL) plugin

This plugin is a wrapper for the [Microsoft Authentication Library (MSAL) for Go](https://github.com/AzureAD/microsoft-authentication-library-for-go) library. It supports fetching OAuth2 access tokens for users in Office 365.

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
          client_id: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
          authority: https://login.microsoftonline.com/organizations
          scopes:
            - https://outlook.office.com/SMTP.Send
          cache_file: /tmp/msal_tenant1_cache.json
```

## Exported functions

### msal(options)

Fetch an OAuth2 access token using the provided credentials.

**Params**

- options `array` - Options array

The following options are available in the **options** array.

- id `string` - The ID of the tenant as configured in `smtpd.yaml` (See above)
- username `string` - The username for the mailbox in Office 365
- password `string` - The password for the mailbox in Office 365

**Returns**

A successful fetch will return an associative array with a `result` key that contains the access token. On error an associative array with a `error` key will be provided.

## Example

Below is an example on how to send email through Office 365 using OAuth2.

### predelivery.hsl

```
$tenant = "tenant1";
$username = "xxxx@tenant1.onmicrosoft.com";
$password = "xxxxxxxx";

$result = msal(["id" => $tenant, "username" => $username, "password" => $password]);

if (!$result["result"]) {
    Queue([
        "reason" => "Could not fetch access token",
        "increment_retry" => false,
        "delay" => 60
    ]);
}

$password = "user=".$username."\x01auth=Bearer ".$result["result"]."\x01\x01";

Try([
    "server" => "smtp.office365.com",
    "port" => 587,
    "saslmechanism" => "XOAUTH2",
    "saslpassword" => $password
]);
```
