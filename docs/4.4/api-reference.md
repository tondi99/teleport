---
title: Teleport API Reference
description: The detailed guide to Teleport API
---

# Teleport API Reference

In most cases, you can interact with Teleport using our CLI tools, [tsh](cli-docs.md#tsh) and [tctl](cli-docs.md#tctl). However, there are some scenarios where you may need to interact with Teleport programmatically. For this purpose, you can directly use the same API that `tctl` and `tsh` use.

!!! Note
    We are currently working on improving our API Documentation. If you have an API suggestion, [please complete our survey](https://docs.google.com/forms/d/1HPQu5Asg3lR0cu5crnLDhlvovGpFVIIbDMRvqclPhQg/edit).

## Go Examples

!!! Note
    The Go examples depend on some code that won't be released until Teleport 5.0. Until then, it would be best to start experimenting with the API with the latest [master branch of Teleport](https://github.com/gravitational/teleport).

Below are some code examples that can be used with Teleport to perform a few key tasks.

Before you begin:

- Install [Go](https://golang.org/doc/install) 1.13+ and Setup Go Dev Environment
- Have access to a Teleport Auth server ([quickstart](quickstart.md))

The easiest way to get started with the Teleport API is to clone the [Go Client Example](https://github.com/gravitational/teleport/tree/master/examples/go-client) in our github repo. Follow the README there to quickly authenticate the API with your Teleport Auth Server and test the API.

Or if you prefer, follow the authentication, client, and packages sections below to add the necessary files to a new directory called `/api-examples`. At the end, you should have this file structure:

```
api-examples
+-- api-admin.yaml
+-- certs
|   +-- api-admin.cas
|   +-- api-admin.crt
|   +-- api-admin.key
+-- client.go
+-- go.mod
+-- go.sum
+-- main.go
```

## Authentication

In order to interact with the API, you will need to provision appropriate
TLS certificates. In order to provision certificates, you will need to create a
user with appropriate permissions. You should only give the api user permissions for what it actually needs.

To quickly get started with the api, you can use this api-admin user, but in real usage make sure to have stringent permissions in place.

```yaml
# Copy and Paste the below and run on the Teleport Auth server.
$ cat > api-admin.yaml <<EOF
{!examples/go-client/api-admin.yaml!}
EOF

$ tctl create -f api-admin.yaml
$ mkdir -p certs
$ tctl auth sign --format=tls --user=api-admin --out=certs/api-admin
```

This should result in three PEM encoded files being generated in the `/certs` directory: `api-admin.crt`, `api-admin.key`, and `api-admin.cas` (certificate, private key, and CA certs respectively).

Move the `/certs` folder into your `/api-examples` folder.

!!! Note
    By default, `tctl auth sign` produces certificates with a relatively short lifetime. See our [Kubernetes Section](kubernetes-ssh.md#using-teleport-kubernetes-with-automation) for more information on automating the signing process for short lived certificates.

    While we encourage you to use short lived certificates, we understand you may not have all the infrastructure to issues and obtain them at the onset. You can use the --ttl flag to extend the lifetime of a certificate in these cases but understand this reduces your security posture

## Go Client

Add `client.go` into `/api-examples`.

**client.go**

```go
{!examples/go-client/client.go!}
```

## Go Packages

Copy the Teleport module's go.mod below into `/api-examples` and then run `go mod tidy` to slim it down to only what's needed for these api examples.

```
{!go.mod!}
```

## Main file

Add this main file to your `/api-examples` folder. Now you can simply plug in the examples below and then run `go run .` to see them in action.

**main.go**

```go
package main

import (
  "fmt"
  "log"
)

func main() {
  log.Printf("Starting Teleport client...")
  client, err := connectClient()
  if err != nil {
    log.Fatalf("Failed to create client: %v", err)
  }
}
```

## Object Model

Many of our primary objects, such as `Roles` or `Tokens`, the fields that `Model` has within them. To keep the documentation below readable, we will refer to these fields as `Model`. The Teleport auth server's database uses these fields to identify and manage them.

```go
// Model is a model of the fields that all Teleport objects have
type Model struct {
  // Kind is a resource kind
  Kind string
  // SubKind is an optional resource sub kind, used in some resources
  SubKind string
  // Version is version
  Version string
  // Metadata is User metadata
  Metadata struct {
    // Name is an object name
    Name string
    // Namespace is object namespace. The field should be called "namespace"
    // when it returns in Teleport 2.4.
    Namespace string
    // Description is object description
    Description string
    // Labels is a set of labels
    Labels map[string]string
    // Expires is a global expiry time header can be set on any resource in the
    // system.
    Expires *time.Time
    // ID is a record ID
    ID int64
  }
}
```

## Roles

Every user in Teleport is assigned a set of [roles](enterprise/ssh-rbac.md#roles). A user's roles defines what actions or resources the user is allowed or denied to access.

Some of the permissions a role could define include:

- Which SSH nodes a user can or cannot access.
- Ability to replay recorded sessions.
- Ability to update cluster configuration.
- Which UNIX logins a user is allowed to use when logging into servers.

!!! Note
    The open source edition of Teleport automatically assigns every user to the built-in `admin` role, but Teleport Enterprise allows administrators to define their own roles with far greater control over the user permissions.

You can manage roles with the Teleport CLI tool [tctl](cli-docs.md#tctl), or programmatically with the RPC calls documented below.

You may want to use the API to manage roles if:

- You want to write a program that can always ensure certain roles exist on your system and do not want to orchestrate `tctl` to do this.
- You want to dynamically create short lived roles.
- You want to dynamically create roles with fields filled that Teleport currently does not support.

### The Role Object

A Teleport `role` is defined by its `Spec`, which contains its `Allow` rules, `Deny` rules, and OpenSSH `Options`. We'll break these down piece by piece below.

To see a role example in `yaml` form, look at the the admin role in the [RBAC documentation](enterprise/ssh-rbac.md). You'll notice that the role object below has the same exact nested structure as it's `yaml` counterpart.

```go
// RoleV3 represents role resource specification
type RoleV3 struct {
  // Model Fields are fields that all Teleport objects have - see above
  Model Fields
  // Spec is the role specification
  Spec RoleSpecV3 struct {
    // Options is for OpenSSH options like agent forwarding.
    Options RoleOptions
    // Allow is the set of conditions evaluated to grant access.
    Allow RoleConditions
    // Deny is the set of conditions evaluated to deny access. Deny takes priority over allow.
    Deny RoleConditions
  }
}
```

### Role Options

The `RoleOptions` struct defines what OpenSSH actions a user is allowed to use.

```go
// RoleOptions is a set of role options
type RoleOptions struct {
  // ForwardAgent is SSH agent forwarding. default true.
  ForwardAgent Bool
  // MaxSessionTTL defines how long a SSH session can last for.
  MaxSessionTTL Duration
  // PortForwarding defines if the certificate will have "permit-port-forwarding"
  // in the certificate. PortForwarding is true if not set.
  PortForwarding *BoolOption // struct { Value bool } - Nullable boolean
  CertificateFormat string
  // ClientIdleTimeout sets disconnect clients on idle timeout behavior,
  // if set to 0 means do not disconnect, otherwise is set to the idle duration.
  ClientIdleTimeout Duration
  // DisconnectExpiredCert sets disconnect clients on expired certificates.
  DisconnectExpiredCert Bool
  // BPF defines what events to record for the BPF-based session recorder.
  BPF []string
  // PermitX11Forwarding authorizes use of X11 forwarding.
  PermitX11Forwarding Bool
  // MaxConnections defines the maximum number of
  // concurrent connections a user may hold.
  MaxConnections int64
  // MaxSessions defines the maximum number of
  // concurrent sessions per connection.
  MaxSessions int64
}
```

### Role Conditions

The `RoleConditions` struct allows for precise permission combinations between a role's `Allow` and `Deny` fields.

!!! Note
     If a user has multiple roles, their role permissions will be evaluated together, which can potentially lead to conflicting rules. Since deny rules take priority over allow rules, this can cause a user to be denied expected permissions. However, this also allows you to take a much more modular and sustainable approach ro roles.

Most roles will only need to define a few of these fields.

```go
// RoleConditions is a set of conditions that must all match to be allowed or denied access.
type RoleConditions struct {
  // Logins is a list of *nix system logins,  e.g. "root".
  Logins []string
  // Namespaces is a list of namespaces (used to partition a cluster).
  Namespaces []string
  // NodeLabels is a map of node labels (used to dynamically grant access to nodes).
  NodeLabels Labels // essentially map[string][]string
  // Rules is a list of rules and their access levels. Rules represents allow or deny rule
  // that is executed to check if user or service have access to resource
  Rules []Rule struct {
    // Resources is a list of resources
    Resources []string
    // Verbs is a list of verbs
    Verbs []string
    // Where specifies optional advanced matcher
    Where string
    // Actions specifies optional actions taken when this rule matches
    Actions []string
  }
  // KubeGroups is a list of kubernetes groups that Teleport users with this role will be
  KubeGroups []string
  // A list of roles that this role can request access to
  Request *AccessRequestConditions struct {
    Roles []string
  }
  // KubeUsers is an optional list of kubernetes users that Teleport users with this role will be
  KubeUsers []string
  // AppLabels is a map of labels used as part of the RBAC system.
  AppLabels Labels // essentially map[string][]string
  // ClusterLabels is a map of node labels (used to dynamically grant access to clusters).
  ClusterLabels Labels // essentially map[string][]string
}
```

A couple of these fields are worth further explanation.

**Labels**: Labels are arbitrary key-value pairs that can be used to differentiate nodes, apps, or leaf clusters by key attributes. For example, `NodeLabels` might have the key `environment`, with its value set to `development`, `staging`, or `production` according to the node's location.

```go
services.Labels{
  "environment": utils.Strings{"development", "staging"},
}
```

Depending on which field you put these labels in, you can allow/deny access to any nodes, apps, or leaf clusters with the given labels. These labels can be very useful in systems where you need to carefully manage access across your many clusters, e.g. if you are managing clusters for several outside groups.

**Rules**
A rule consists of two parts: the resources and verbs. Here's an example of a rule describing "read only" verbs applied to the SSH `sessions` resource. Depending on if it's under `Allow` or `Deny`, it means "allow/deny users of this role the ability to read or list active SSH sessions".

```go
services.NewRule(
  services.KindSession,
  services.RO(), // helper function to get 'read only' verbs ("list" and "read")
)
```

**Resources**

These are all of the possible resource values, which can be found in the `services` package.

```go
KindUser              = "user"
KindLicense           = "license"
KindRole              = "role"
KindAccessRequest     = "access_request"
KindPluginData        = "plugin_data"
KindOIDC              = "oidc"
KindSAML              = "saml"
KindGithub            = "github"
KindOIDCRequest       = "oidc_request"
KindSAMLRequest       = "saml_request"
KindGithubRequest     = "github_request"
KindWebSession        = "web_session"
KindAuthServer        = "auth_server"
KindProxy             = "proxy"
KindNode              = "node"
KindAppServer         = "app_server"
KindToken             = "token"
KindCertAuthority     = "cert_authority"
KindOIDCConnector     = "oidc"
KindSAMLConnector     = "saml"
KindGithubConnector   = "github"
KindClusterConfig     = "cluster_config"
KindSemaphore         = "semaphore"
MetaNameClusterConfig = "cluster-config"
KindClusterName       = "cluster_name"
MetaNameClusterName   = "cluster-name"
KindStaticTokens      = "static_tokens"
MetaNameStaticTokens  = "static-tokens"
KindTrustedCluster    = "trusted_cluster"
KindIdentity          = "identity"
KindKubeService       = "kube_service"
```

**Verbs**

These are all of the possible resource values, which can be found in the `services` package.

```go
VerbList          = "list"
VerbCreate        = "create"
VerbRead          = "read"
VerbReadNoSecrets = "readnosecrets"
VerbUpdate        = "update"
VerbDelete        = "delete"
VerbRotate        = "rotate"
```

There are also helper functions `RW()`, `RO()`, and `ReadNoSecrets()` in the `services` package to quickly get read/write verbs, read only verbs, and read only verbs with `readnosecrets` respectively.

### Retrieve Role

This is the equivalent of `tctl get role/admin`.

```go
role, err := client.GetRole("admin")
if err != nil {
  return err
}
```

### Create Role

You can use the `UpsertRole` RPC to programmatically create a new role. This is the equivalent of `tctl create -f auditor-role.yaml`, where the `-f` flag signals to overwrite the auditor role if it exists already.

Suppose you wanted to create a role for an auditor that could view all sessions, but could not access any servers. Using `tctl`, you would first create a role that allows reading and listing of the session resource like below. In addition, the user is explicitly denied access to all nodes in the deny block.

```
$ cat << EOF > /tmp/auditor-role.yaml
kind: role
version: v3
metadata:
  name: auditor
spec:
  options:
    max_session_ttl: 8h
  allow:
    rules:
    - resources: [session]
      verbs: [list, read]
  deny: {}
    node_labels: '*': '*'
EOF
$ tctl create -f /tmp/auditor-role.yaml
```

To do something similar with the API:

```go
role, err := services.NewRole("auditor", services.RoleSpecV3{
  Options: services.RoleOptions{
    MaxSessionTTL: services.Duration(time.Hour),
  },
  Allow: services.RoleConditions{
    Logins: []string{"auditor"},
    Rules: []services.Rule{
      services.NewRule(services.KindSession, services.RO()),
    },
  },
  Deny: services.RoleConditions{
    NodeLabels: services.Labels{"*": []string{"*"}},
  },
})
if err != nil {
  return err
}
if err = client.UpsertRole(ctx, role); err != nil {
  return err
}
```

### Update Role

The `UpsertRole` RPC can also be used to update an existing role. You can change a role's field with the setter functions available, or directly.

```go
// retrieve role
role, err := client.GetRole("auditor")
if err != nil {
  return err
}

// update the auditor role to be expired
role.SetExpiry(time.Now())
if err := client.UpsertRole(ctx, role); err != nil {
  return err
}
```

### Delete Role

This is the equivalent of `tctl rm auditor-role.yaml`.

```go
if err := client.DeleteRole(ctx, "auditor"); err != nil {
  return err
}
```

## Tokens

Teleport is a "clustered" system, meaning it only allows access to hosts that had been previously granted cluster membership. To achieve this, a cluster has "join tokens" which can be shared to extend trust.

A remote host can exchange one of these tokens with the cluster's auth server to receive signed certificates and become a trusted Teleport host (auth, node, or proxy server). Likewise, a Teleport cluster can exchange a token to become a [trusted cluster](admin-guide.md#trusted-clusters).

These tokens can be predefined static tokens, or dynamic tokens with a short life time. The latter can be generated by `tctl` or this API, and is more secure.

You may want to use this API to manage tokens if:

- You have a program that dynamically adds new hosts to clusters
- You want to programmatically add leaf clusters to a trusted cluster

### The Token Object

The Token has a Roles field, which defines what roles this token provides in the root cluster.

`Role` is a custom string type with pre-defined values, e.g. `RoleAuth`, `RoleNode`, `RoleProxy`, and `RoleTrustedCluster`. You can check the teleport package to see more.

```go
type ProvisionTokenV2 struct {
  // Model Fields are fields that all Teleport objects have - see above
  Model Fields
  // Spec is the token specification
  Spec ProvisionTokenSpecV2 struct {
    // Roles is a list of roles associated with the token, that will be converted to
    // metadata in the SSH and X509 certificates issued to the user of the token
    Roles []teleport.Role // string
  }
}
```

**Roles**

Not to be confused with [RBAC Roles](api-reference.md#roles), the `Roles` field on a Token determines what server roles a new host can take on in a cluster.

These are all of the possible role values, which can be found in the `teleport` package.

```go
RoleAuth           Role = "Auth"
RoleWeb            Role = "Web"
RoleNode           Role = "Node"
RoleProxy          Role = "Proxy"
RoleAdmin          Role = "Admin"
RoleProvisionToken Role = "ProvisionToken"
RoleTrustedCluster Role = "Trusted_cluster"
RoleSignup         Role = "Signup"
RoleNop            Role = "Nop"
RoleRemoteProxy    Role = "RemoteProxy"
RoleKube           Role = "Kube"
RoleApp            Role = "App"
```

### Retrieve Token

The closest equivalent is `tctl tokens ls`.

```go
token, err := client.GetToken(tokenString)
if err != nil {
  return err
}
```

### Create Token

You can use the `GenerateToken` RPC to programmatically create a new token. This is the equivalent of `tctl tokens add --type=[Role] --value=[Token] --ttl=[TTL]`.

By default, Teleport will create a random 16 byte string using the `CryptoRandomHex` function in our `utils` package. If you want to customize this yourself, simply provide the `Token` field, though we strongly recommend utilizing best security practices.

You can also set `TTL` to a maximum of 48 hours, but the shorter life time the more secure your cluster will be.

```go
// generate a token for adding a new proxy host to a cluster
tokenString, err := client.GenerateToken(ctx, auth.GenerateTokenRequest{
  Roles: teleport.Roles{teleport.RoleProxy},
  // Token will be a randomly generated 16 byte hex string
  // TTL will default to 30 minutes
})
if err != nil {
  return err
}

// generate a token for adding a remote cluster to a trusted cluster
tokenString, err := client.GenerateToken(ctx, auth.GenerateTokenRequest{
  Token: customSecureString,
  Roles: teleport.Roles{teleport.RoleTrustedCluster},
  TTL:   time.Minute,
})
if err != nil {
  return err
}
```

### Update Token

`UpsertToken` is essentially the same as `GenerateToken` without the default/randomly generated fields, so it is best used only for updating.

```go
// updates the token to be a proxy token
token.SetRoles(teleport.Roles{teleport.RoleProxy})
if err := client.UpsertToken(token); err != nil {
  return err
}
```

### Delete Token

This is equivalent to `tctl tokens rm [tokenString]`.

```go
if err := client.DeleteToken(tokenString); err != nil {
  return err
}
```

## Cluster Labels

Cluster Labels can be used for [RBAC](enterprise/ssh-rbac.md) with leaf clusters in a [Trusted Cluster](trustedclusters.md).

You may want to use the following RPC's to manage your cluster labels if:

- You want to programmatically manage cluster labels from your root cluster, for access control or otherwise
- You have a complex cluster labeling system that would benefit from automation with the API
- You have a large distributed trusted cluster where careful access control is crucial

### Create a Leaf Cluster Join Token with Labels

To create a leaf cluster with cluster labels, you can create a token with the desired labels, and use that token to add the leaf cluster. Check the [Tokens](api-reference.md#Tokens) section of this page for more information on tokens.

```go
tokenString, err := client.GenerateToken(ctx, auth.GenerateTokenRequest{
  Roles: teleport.Roles{teleport.RoleTrustedCluster},
  // Leaf clusters added with this token will inherit these labels
  Labels: map[string]string{
    "env": "staging",
  },
})
```

!!! Note
    Currently, it is not straightforward to add new leaf clusters with the API, but it is possible with `RegisterUsingToken`. Until we properly document this RPC, follow the trusted cluster [join token docs](trustedclusters.md#join-tokens) to create a leaf cluster with this token using `tctl`.

### Update a Leaf Cluster's labels

You can also update a leaf cluster's labels from the root cluster using the `UpdateRemoteCluster` RPC. This is the equivalent of `tctl update rc/[leafClusterName] --set-labels=env=prod`.

```go
rc, err := client.GetRemoteCluster("leafClusterName")
if err != nil {
  return err
}

md := rc.GetMetadata()
md.Labels = map[string]string{"env": "prod"}
rc.SetMetadata(md)

if err = client.UpdateRemoteCluster(ctx, rc); err != nil {
  return err
}

```

## Access Workflow

[Access Workflow](enterprise/workflow/index.md) can be used by Teleport users to request one or more additional roles. These requests can be partially or fully approved or denied by a Teleport Administrator.

You may want to use manage Access Workflow using the API if:

 You want to automatically administer the scaling up and down of permissions for developers depending on their task

For example, you could have a team of contractors which need database access for some tasks, but should not have it permanently. To do this, you can give them the `contractor` role below, which allows them to request the `dba` role.

```yaml
kind: role
metadata:
  name: contractor
spec:
  options:
    # ...
  allow:
    request:
      roles: ['dba']
    # ...
  deny:
    # ...
```

```yaml
kind: role
metadata:
  name: dba
spec:
  options:
    # ...
    # Only allows the contractor to use this role for 1 hour from time of request.
    max_session_ttl: 1h
  allow:
    # ...
  deny:
    # ...
```

Now if a contractor has a task requiring dba access, they can request dba access.To approve the request, you need a request administrator with read and write permissions to access requests.

```yaml
kind: role
metadata:
  name: request-admin
spec:
  options:
    # ...
  allow:
    rules:
    - resources: [access_request]
      verbs: [list, read, update, delete]
  deny:
    # ...
```

A `request-admin` can list all current requests, resolve them, and delete them. Notice that `request-admin` is not a great job to have if this is all handled manually.

With the API, you can automatically manage the requesting and or resolution of requests in order to streamline this process. Better yet, this opens up the ability to leverage external identity providers and other [external tools](enterprise/workflow.md#integrating-with-an-external-tool), such as slack, to manage these requests according to your custom configuration.

### The Access Request Object

An `AccessRequest`

```go
// AccessRequest represents an access request resource specification
type AccessRequestV3 struct {
  // Model Fields are fields that all Teleport objects have - see above
  Model Fields
  // Spec is an AccessReqeust specification
  Spec AccessRequestSpecV3 struct {
    // User is the name of the user to whom the roles will be applied.
    User string
    // Roles is the name of the roles being requested.
    Roles []string
    // State is the current state of this access request.
    State RequestState
    // Created encodes the time at which the request was registered with the auth server.
    Created time.Time
    // Expires constrains the maximum lifetime of any login session for which this request is active.
    Expires time.Time
    // RequestReason is an optional message explaining the reason for the request.
    RequestReason string
    // ResolveReason is an optional message explaining the reason for the resolution
    // of the request (approval, denial, etc...).
    ResolveReason string
    // ResolveAnnotations is a set of arbitrary values received from plugins or other resolving parties during approval/denial.  Importantly, these annotations are included in the access_request.update event, allowing plugins to propagate arbitrary structured data to the audit log.
    ResolveAnnotations wrappers.Traits
    // SystemAnnotations is a set of programmatically generated annotations attached to pending access requests by teleport. These annotations serve as a mechanism for administrators to pass extra information to plugins when they process pending access requests.
    SystemAnnotations wrappers.Traits
  }
}
```

### Retrieve Access Requests

This is equivalent to `tctl request ls`.

```go
filter := services.AccessRequestFilter{State: services.RequestState_PENDING}
ars, err := client.GetAccessRequests(ctx, filter)
if err != nil {
  return err
}
```

### Create Access Request

This is equivalent to `tctl request create api-admin --roles=admin`.

```go
// create a new access request for api-admin to use the admin role in the cluster
ar, err := services.NewAccessRequest("api-admin", "admin")
if err != nil {
  return err
}

// use access request setters to set other fields
accessReq.SetRequestReason("I need more power.")
accessReq.SetAccessExpiry(time.Now().Add(time.Hour))

if err = client.CreateAccessRequest(ctx, accessReq); err != nil {
  return err
}
```

### Approve Access Request

This is equivalent to `tctl request approve [accessReqID]`.

```go
aruApprove := services.AccessRequestUpdate{
  RequestID: accessReqID,
  State:     services.RequestState_APPROVED,
}
if err := client.SetAccessRequestState(ctx, aruApprove); err != nil {
  return err
}
```

### Deny Access Request

This is equivalent to `tctl request deny [accessReqID]`.

```go
aruDeny := services.AccessRequestUpdate{
  RequestID: accessReqID,
  State:     services.RequestState_DENIED,
}
if err := client.SetAccessRequestState(ctx, aruDeny); err != nil {
  return err
}
```

### Delete Access Request

This is equivalent to `tctl request rm [accessReqID]`.

```go
if err := client.DeleteAccessRequest(ctx, accessReqID); err != nil {
  return err
}
```

## Certificate Authority

It might be useful to retrieve your [Certificate Authority](architecture/authentication.md#ssh-certificates) through the API if it is rotating frequently.

```go
ca, err := client.GetCertAuthority(services.CertAuthID{
  DomainName: clusterName,
  Type:       services.HostCA,
}, false)
if err != nil {
  return err
}
```