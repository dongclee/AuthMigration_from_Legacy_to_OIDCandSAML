#requires -Version 5.1
<#
.SYNOPSIS
    DNGRMS Authentication Migration Practical Demo Launcher v1.1.35

.DESCRIPTION
    Generates and operates a customer-demo ASP.NET Core 8 web application that demonstrates:
      1) Legacy/local ID + password authentication backed by SQLite
      2) Dual-run migration to Microsoft Entra ID with OpenID Connect (OIDC)
      3) Migration to Microsoft Entra ID with SAML 2.0
      4) Pilot, cutover, rollback, evidence collection, and cleanup

    The launcher is intentionally stateful and menu-driven. It does not store passwords,
    client secrets, tokens, or private keys in its JSON state file.

    IMPORTANT: This is a training/demo implementation. SQLite and a minimum paid App Service Basic B1 plan
    are selected to minimize cost. They are not the recommended production architecture for
    a scaled or mission-critical workload.

.VERSION
    1.1.13

.TESTED DESIGN TARGET
    Windows PowerShell 5.1 or PowerShell 7.x
    .NET SDK 8.x
    Az.Accounts / Az.Resources / Az.Websites
    Microsoft.Graph.Authentication
    ASP.NET Core 8
    ITfoxtec.Identity.Saml2.MvcCore 4.21.0 (BSD-3-Clause)

.NOTES
    Authoring date: 2026-10-31
    v1.1.35 Menu 51 redirect-aware HttpClient probe hotfix:
      - Replaces Invoke-WebRequest MaximumRedirection=0 with HttpClientHandler.AllowAutoRedirect=false so 301/302 responses remain normal HTTP responses on Windows PowerShell 5.x and PowerShell 7.x
      - Captures the OIDC Location header without following Microsoft Entra and validates that /account/oidc returns a bounded redirect response
      - Keeps per-endpoint timeout/transport categorization and complete evidence matrix generation
    v1.1.34 Menu 51 bounded coexistence-endpoint probe hotfix:
      - Replaces the blocking HttpWebRequest GetResponse path in Menu 51 with per-endpoint bounded Invoke-WebRequest probes
      - Treats expected no-redirect HTTP responses as evidence and records timeout/transport failures per endpoint without aborting the whole matrix
      - Verifies /health=200 and that Local, OIDC, and SAML initiation/metadata paths are independently reachable during Dual coexistence
      - Writes a complete endpoint matrix to evidence before determining PASS/FAIL
    v1.1.33 Entra self-signed SAML token-signing certificate trust hotfix:
      - Sets ITfoxtec Saml2Configuration.CertificateValidationMode=None because the Entra application token-signing certificate is self-signed and explicitly pinned through federation metadata
      - Keeps SAML XML signature validation enabled: Unbind still validates the message signature against SignatureValidationCertificates loaded from the application-specific Entra metadata
      - Normalizes existing generated Program.cs during Menu 24 Upgrade/Redeploy so no Menu 10 rerun is required
      - Preserves issuer, audience, time, replay, signed-assertion, IdentityModel 8.22.0, SQLite, and existing SAML/OIDC state contracts
    v1.1.32 non-gallery SAML msiam_access pilot-assignment hotfix:
      - Prefers the enabled user-assignable msiam_access role for Microsoft Entra non-gallery SAML template applications
      - Does not confuse the separate User app role with enterprise-application Default Access
      - Requires exactly one enabled msiam_access role when multiple user-assignable roles are present; otherwise fails safely
      - Preserves Graph appRoleAssignedTo creation and principal/resource/role read-back verification
    v1.1.31 SAML pilot-user app-role assignment contract hotfix:
      - Reads the target Service Principal appRoles before assignment instead of always posting the all-zero appRoleId
      - Selects the only enabled user-assignable role when one exists; uses the zero appRoleId only when the resource exposes no app roles
      - Fails safely rather than guessing when multiple enabled user-assignable roles exist
      - Creates the assignment through servicePrincipal/appRoleAssignedTo and verifies principalId, resourceId, and appRoleId by Graph read-back
      - Preserves the existing OIDC Menu 33 assignment behavior through the same idempotent helper
    v1.1.30 Menu 42 certificate-lifetime input validation hotfix:
      - Replaces the undefined Read-Integer call with the launcher's supported Read-Choice helper
      - Validates the entered lifetime as an integer from 30 through 1095 days before any Graph certificate operation
      - Keeps Menu 42 idempotent: no certificate or Service Principal change occurs until input validation passes
      - Preserves all v1.1.29 SAML certificate, preferred thumbprint, metadata, and App Service trust checks
    v1.1.29 Menu 42 SAML token-signing certificate and metadata trust contract:
      - Creates a short-lived self-signed SAML token-signing certificate through servicePrincipal/addTokenSigningCertificate when no active certificate exists
      - Reuses an existing active signing certificate when present and never writes PFX private material or password credentials to launcher state/evidence
      - Selects the created/reused certificate as preferredTokenSigningKeyThumbprint and verifies keyCredentials plus preferred thumbprint by Graph read-back
      - Applies the tenant/app-specific federation metadata URL to App Service and validates metadata contains an X509Certificate before Menu 42 succeeds
      - Stores only non-secret certificate metadata such as display name, key ID, thumbprint, and validity dates in evidence
    v1.1.28 Non-gallery SAML application-template creation and safe replacement contract:
      - Menu 40 creates the SAML enterprise application by instantiating the Microsoft Graph non-gallery application template 8adf8e6e-67b2-4cf2-a259-e3dc5476c621
      - Detects the earlier ordinary App Registration-based SAML object and replaces it only when state IDs, client ID, and expected display name all match
      - Captures pre-replacement Application and Service Principal evidence before deletion and records the new template-instantiated object IDs
      - Verifies the new Service Principal references the expected application template before Menu 40 succeeds
      - Menu 41 remains responsible for preferredSingleSignOnMode=saml and exact Entity ID / ACS / sign-on read-back
    v1.1.27 Menu 41 atomic SAML SSO-mode and Application Web contract hotfix:
      - Replaces the rejected composite service-principal PATCH with an atomic preferredSingleSignOnMode=saml PATCH
      - Stores Entity ID in application.identifierUris, ACS in application.web.redirectUris, and sign-on URL in application.web.homePageUrl
      - Performs read-back after the Service Principal step and again after the Application step
      - Records the exact stage and Graph state in evidence and reports success only when all values match
      - Preserves the /saml/acs Application Web redirect because Microsoft Entra uses it as the SAML Reply URL for this non-gallery app
    v1.1.26 Menu 41 actual SAML enterprise SSO-mode and Graph read-back hotfix:
      - Sets preferredSingleSignOnMode=saml on the SAML service principal before reporting Basic SAML Configuration success
      - Configures Entity ID on the Application object and ACS/sign-on values on the Service Principal, then performs bounded Graph read-back
      - Removes only the erroneous /saml/acs entry from the App Registration web.redirectUris while preserving unrelated web redirect URIs
      - Writes Menu 41 evidence and blocks Menu 42 unless SSO mode, Entity ID, ACS, and sign-on URL all match exactly
      - Preserves Menu 42 responsibility for federation metadata and App Service SAML runtime settings
    v1.1.25 OIDC PackageReference wildcard-normalization hotfix:
      - Detects Microsoft.AspNetCore.Authentication.OpenIdConnect regardless of indentation and 8.0.* versus exact 8.0.33 version syntax
      - Replaces the existing OIDC reference with one canonical 8.0.33 reference before inserting aligned IdentityModel 8.22.0 references
      - Rejects duplicate OIDC references and verifies the canonical package graph before publish
      - Preserves v1.1.24 Upgrade/Redeploy mode and all Menu 24, Graph, SQLite, OIDC, and SAML contracts
    v1.1.24 aligned IdentityModel OIDC callback and upgrade-redeploy contract:
      - Pins every Microsoft.IdentityModel and System.IdentityModel.Tokens.Jwt package used by OIDC and SAML to 8.22.0
      - Normalizes existing generated csproj files and rejects any publish/ZIP that retains IdentityModel 7.x or mixed major/minor families
      - Allows Menu 24 Upgrade/Redeploy mode after a prior successful deployment when seed settings are absent but the persistent database already contains at least two users
      - Preserves /home/data, Dual mode, OIDC settings, App Registration, pilot assignment, audit state, and the validated SQLite SONAME bootstrap
      - Menu 36 prints the required aligned IdentityModel contract before opening the browser and does not claim browser-session success by itself
    v1.1.23 Menu 3 Graph-scope scalar-safety hotfix:
      - Forces missing Graph-scope pipeline results into an array before Count evaluation under StrictMode
      - Revalidates the Graph context after Connect-MgGraph and confirms tenant, scopes, and live /me access before Menu 3 succeeds
      - Preserves the v1.1.22 Menu 30 prerequisite banner and Menu 31 bounded Graph read-back contract
    v1.1.22 Microsoft Graph prerequisite and OIDC callback read-back contract:
      - Adds an explicit Menu 30 prerequisite banner requiring Menu 3 Microsoft Graph delegated sign-in
      - Validates Graph tenant alignment, required delegated scopes, and a live /me call before creating or reusing Entra objects
      - Menu 31 PATCHes the Application object and then performs bounded Microsoft Graph read-back until web.redirectUris and web.logoutUrl exactly match
      - Writes Menu 31 Graph verification evidence and only reports success after the read-back contract passes
      - Updates Portal UI guidance for Authentication (Preview) and the old Web platform experience
    v1.1.21 post-success seed-cleanup scalar-safety hotfix:
      - Preserves the validated v1.1.20 SQLite SONAME bootstrap and healthy restart-persistence path
      - Forces seed-removal verification results into an array before Count evaluation under StrictMode
      - Makes the recovery backup test type-safe rather than assuming every restored object exposes Count
      - Corrects final success evidence wording from the retired e_sqlite3 contract to system sqlite3 SONAME/provider evidence
    v1.1.20 App Service versioned system SQLite loader contract:
      - Includes the v1.1.19 deterministic Program.cs SetProvider/FreezeProvider normalization
      - Preserves SQLitePCLRaw.provider.sqlite3 but resolves App Service's versioned libsqlite3.so.0 through a writable-runtime libsqlite3.so symlink
      - The bootstrap discovers libsqlite3.so.0 only under trusted /usr/lib and /lib roots, fails fast if absent, exports LD_LIBRARY_PATH, and prints DNGRMS-SQLITE-SONAME evidence
      - Forces the mounted package to be copied to writable /home before execution so the compatibility symlink is always available
      - Validates the bootstrap SONAME contract before ZIP creation and rejects prior packages by immutable launcher identity
    v1.1.18 idempotent generated-project normalization hotfix:
      - Replaces all recognized SQLite PackageReference lines as a set instead of relying on indentation-sensitive whole-block equality
      - Accepts partially migrated v1.1.15/v1.1.16/v1.1.17 generated projects and normalizes them to one canonical v1.1.18 provider graph
      - Corrects PowerShell regex escaping in the source and deps contract checks
      - Never requires Menu 10 merely because the existing generated project has mixed SQLite package references
    v1.1.17 deterministic provider-version and ZIP validation hotfix:
      - Pins both SQLitePCLRaw.provider.sqlite3 and SQLitePCLRaw.provider.winsqlite3 to the published 2.1.11 version; prevents NU1603 approximate resolution to winsqlite3 3.0.0
      - Migrates the already-generated v1.1.16 2.1.13 provider references in place when Menu 24 starts
      - Removes the obsolete -Archive and -ExpectedMode arguments passed to Test-LinuxX64DeploymentPackage after its v1.1.16 signature changed
      - Validates the Linux provider as mandatory for Azure; records the Windows provider for local compatibility without treating its deps key as a Linux startup gate
      - Keeps bundled libe_sqlite3.so forbidden, preserving the App Service glibc ABI fix
    v1.1.16 App Service glibc-compatible system SQLite provider contract:
      - Removes the bundled e_sqlite3 native binary from Azure Linux publish output because the observed App Service 7.0 host exposes an older glibc than the bundled library requires
      - Uses Microsoft.EntityFrameworkCore.Sqlite.Core plus Microsoft.Data.Sqlite.Core so no e_sqlite3 native bundle is selected transitively
      - Configures SQLitePCLRaw.provider.sqlite3 explicitly on Linux to load the platform libsqlite3.so.0 without a bundled glibc dependency
      - Configures SQLitePCLRaw.provider.winsqlite3 explicitly on Windows so Menu 11-18 local win-x64 validation remains supported
      - Rewrites existing Menu 10 generated source automatically when Menu 24 starts; Menu 10 does not need to be rerun
      - Validates the managed provider graph and rejects any Azure package that still contains libe_sqlite3.so or an e_sqlite3 provider
      - Preserves Kudu status-4 separation, bounded health probes, /home/data persistence, one-time seed removal, immutable package identity, and Entra bearer SCM deployment
    v1.1.15 deterministic SQLite native-provider and fail-fast runtime contract:
      - Pins the supported .NET 8 EF Core/SQLite packages to Microsoft.EntityFrameworkCore.Sqlite 8.0.33, Microsoft.Data.Sqlite 8.0.33, and SQLitePCLRaw system providers 2.1.11
      - Uses the main Microsoft.Data.Sqlite package so the default bundle is auto-initialized, then forces a native load with an in-memory connection before DbContext registration
      - Requires Linux publish output and ZIPs to contain the system sqlite3 provider and explicitly reject bundled libe_sqlite3.so
      - Verifies the deps.json package graph and native RID asset before Kudu submission and records the native library hash in the immutable package manifest
      - Keeps only the newest physical log tail, correlates it to the current deployment/restart cutover, and prints the earliest explicit application exception chain
      - Stops Kudu Location polling immediately at the first status 4; after three main-worker health probes, it collects current-startup evidence and fails without an unrelated repair/recycle loop
      - Bounds every Menu 24 health gate to three probes while preserving seeded-user, restart-persistence, seed-removal, and final post-removal verification
      - Preserves Menu 0-23 state, Basic B1, Entra bearer SCM, Run-From-Package, /home/data, seed safety, and Windows PowerShell 5.1/PowerShell 7.x compatibility
    v1.1.14 current-startup exception correlation and SQLite initialization recovery:
      - Preserves log line boundaries and accepts only container evidence at or after the current deployment/restart cutover
      - Prints the earliest explicit exception from the current startup, preventing old .NET/runtime or missing-bootstrap text from winning classification
      - Stops Kudu Location polling immediately at the first authoritative status 4 and permits no later Location request
      - Performs at most three health probes, then applies one cause-specific repair or fails fast; generic recycle loops are removed
      - Adds a non-destructive /home/data SQLite target preflight; invalid/empty/path-directory targets are quarantined rather than deleted
      - Emits SQLite primary/extended error codes from DemoSeeder and uses bounded retries only for BUSY/LOCKED/IOERR startup conditions
      - Synchronizes the generated v1.1.13 ASP.NET Core source contract before rebuilding packages, preserving Menu 0-23 state and artifacts
      - Keeps Basic B1, Entra bearer SCM, Run-From-Package, seed safety, restart persistence, and Windows PowerShell 5.1/7.x support
    v1.1.13 deterministic Menu 24 completion and writable-home bootstrap:
      - Stops Kudu Location polling immediately on the first authoritative status 4 instead of mixing deployment and runtime readiness in one loop
      - Caps Kudu status polling at 12 requests and performs runtime readiness as a separate three-probe phase
      - Treats Kudu/SCM wwwroot as diagnostic-only because the SCM container is not the main Run-From-Package worker mount
      - Starts SelfContainedLinuxX64 through /bin/sh and the package bootstrap, which copies a read-only mount to writable /home, applies chmod 755, and execs the apphost
      - Verifies package identity through the running main app container; Kudu/VFS package visibility is never a success gate
      - Performs one deliberate post-status-4 recycle to mount the selected package, then succeeds or emits one bounded diagnostic bundle without repetitive polling
      - Preserves Basic B1, Entra bearer Kudu, immutable package deployment, /home/data SQLite, seed rollback/removal, restart persistence, and PS 5.1/7.x support
    v1.1.12 immutable-package identity and direct Linux apphost startup contract:
      - Treats WEBSITE_RUN_FROM_PACKAGE=1 as a read-only /home/site/wwwroot package mount and never writes startup artifacts there
      - Uses /home/site/wwwroot/DngrmsDemo.Web directly for SelfContainedLinuxX64 instead of depending on a shell wrapper
      - Clears and verifies any previous appCommandLine before applying and re-verifying the selected startup command
      - Adds a unique root package manifest plus a runtime-served identity marker with hashes of the selected publish artifacts
      - Requires the selected package identity, apphost, bootstrap, runtime libraries, and executable ZIP mode through Kudu/VFS
      - Re-verifies appCommandLine after Kudu status 4 and repairs a stale framework-dependent startup contract only when observed
      - Verifies the same package identity through the running app before and after the restart-persistence test
      - Removes all DNGRMS_SEED_* one-time settings only after health, identity, seeded-user, and persistence gates pass
      - Preserves Menu 0-23, Basic B1, Entra bearer Kudu, /home/data safety, status 4, and Windows PowerShell 5.1/7.x support
    v1.1.11 App Service Linux runtime-contract preflight and self-contained fallback:
      - Reads the Web App's actual configured linuxFxVersion before deployment and queries available Linux stacks
      - Attempts DOTNETCORE|8.0 only when it is advertised or already configured, then restarts and verifies the effective configuration
      - Runs a quote-free Kudu direct dotnet --info/--list-runtimes inventory before ZIP submission
      - Uses FrameworkDependentNet8 only when Microsoft.NETCore.App 8.x and Microsoft.AspNetCore.App 8.x are both visible
      - Automatically builds and selects a separate linux-x64 self-contained package when the .NET 8 shared runtime is unavailable
      - Keeps the win-x64 self-contained local artifact completely separate from the Azure Linux artifact
      - Uses a package-root POSIX bootstrap that copies the immutable package to writable /home, applies 0755, and execs the Linux apphost
      - Prints and evidences configured linuxFxVersion, available stacks, direct runtime inventory, selected package mode, and startup command
      - Preserves B1, Entra bearer Kudu SCM, Kudu status 4, Run-From-Package, /home/data SQLite, seed rollback/removal, and PS 5.1/7.x support
    v1.1.10 Windows PowerShell 5.1 StreamReader compatibility integration:
      - Replaces every direct StreamReader construction with one exact-overload helper
      - Invokes StreamReader(Stream, Encoding, Boolean, Int32, Boolean) through reflection to avoid PowerShell constructor-binder ambiguity
      - Uses explicit UTF-8, BOM detection, 4096-byte buffering, and leave-open semantics for ZIP metadata and Kudu/HTTP response text
      - Disposes each reader and owning ZIP/HTTP stream deterministically without changing Menu 0-23 or Menu 24 safety gates
      - Preserves runtime startup exception capture, bounded repair, confirmed-ICU-only remediation, Kudu status 4, Run-From-Package, /home/data, and seed recovery
    v1.1.9 bounded runtime-startup diagnosis and repair:
      - Stops repetitive deployment output after Kudu status 4, a stable package mount, and three consecutive unhealthy probes
      - Captures Kudu Docker/container logs and a bounded Kudu-side selected-startup probe before changing settings
      - Extracts and prints the first available startup exception or console failure without exposing secrets
      - Applies DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1 only when the captured evidence explicitly confirms a missing ICU dependency
      - Performs at most four evidence-driven runtime repair attempts, with three health probes after each repair
      - Distinguishes deployment, package/RID, shared-runtime, ICU, SQLite permission, application configuration, and unclassified startup failures
      - Publishes Menu 19 as an explicit linux-x64 framework-dependent .NET 8 package and validates runtimeconfig/deps metadata
      - Preserves B1, state, /home/data, seed settings, Run-From-Package, and the terminal-record-first Kudu verification controls
    v1.1.9 terminal-record-first Kudu ZIP deployment verification:
      - Treats the final deployment id returned by the asynchronous zipdeploy Location as authoritative correlation
      - Permanently stops requesting that exact Location URL after its first HTTP 404
      - Always queries and prints the final deployment record, every log entry, and each details_url response before status 3 is returned
      - Verifies DngrmsDemo.Web.dll, deps.json, runtimeconfig.json, and appsettings.json in /home/site/wwwroot
      - Requires Kudu status 4, two stable selected-package identity snapshots, and Healthy/Connected; status 3 can never be promoted to success
      - Uses WEBSITE_RUN_FROM_PACKAGE=1 for .NET 8 ZIP deployment so the runtime reads a mounted immutable package instead of copying over live wwwroot files
      - Classifies deployment failures separately from runtime readiness failures and retries once only for evidence-backed repairable deployment causes
      - Reasserts SCM_DO_BUILD_DURING_DEPLOYMENT=false and ENABLE_ORYX_BUILD=false; seed and /home/data safety controls remain unchanged
      - Verifies a non-empty /home/data/dngrms-demo.db, at least two seeded users, and restart persistence
      - Preserves the quote-free /home/data verification and all prior safety controls
      - Removed the shell -c argument and shell-text-in-JSON nesting from the Kudu command path
      - Uploads a short LF-normalized POSIX script through Kudu VFS, then invokes it with a quote-free command
      - Central command-payload validator rejects quotes, shell metacharacters, substitutions, and line breaks
      - /home/data validation creates the directory, verifies writability and mode, writes, reads, and removes a marker
      - Actual secret-free command/script payloads and redacted HTTP/result evidence are persisted
      - Temporary marker and script cleanup uses Kudu VFS with verification-friendly HTTP status handling
      - HTTP 202 Accepted remains valid while deployment status is 0, 1, or 2
      - Per-deployment records are queried by id as auxiliary evidence instead of becoming the primary success gate
      - Basic B1 is enforced as the minimum guided paid App Service configuration
      - Linux .NET 8 startup contract, Entra bearer-token Kudu ZIP deployment, health, SQLite persistence,
        seed-removal recovery, and redacted diagnostic evidence remain integrated
      - Windows PowerShell 5.1 and PowerShell 7.x parser support
      - Braced variable interpolation before a literal colon
      - No PowerShell 7-only null-coalescing or HTTP switches in launcher code
      - TLS 1.2 and NuGet provider preparation for Windows PowerShell 5.1
      - UTF-8 BOM distribution for Windows PowerShell 5.1 text decoding
      - Hashtable-safe state summary and verified state-file round trip
      - Azure context synchronization before subscription-scoped validation
      - Concrete subscription ID in Microsoft.Web REST paths (no unresolved placeholder)
      - SAML metadata generated with XDocument/XElement (no nested raw string)
      - Generated C#, Razor, JSON, and project-file static validation
      - UTF-8/en-US .NET CLI process environment and UTF-8 build logs
      - Application-owned public authentication scheme constants
      - No dependency on ITfoxtec internal Saml2Constants type
      - No Range/Index syntax in IQueryable expression trees
      - Provider-safe query materialization before password evidence formatting
      - win-x64 self-contained seed/local-run artifact from Menu 11
      - Shared-runtime discovery with non-blocking self-contained fallback
      - Menu 12/13/14/16/18 app-local executable execution
    No secret is intentionally written to state/*.json or evidence/*.json.
#>

[CmdletBinding()]
param(
    [string]$StatePath,
    [switch]$SkipBanner
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# Windows PowerShell 5.1 can default to older TLS protocols. PSGallery, Azure,
# Microsoft Graph, and NuGet endpoints require TLS 1.2. This is harmless on
# PowerShell 7.x and is intentionally best-effort for cross-edition support.
try {
    [Net.ServicePointManager]::SecurityProtocol =
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
}
catch {
    # PowerShell 7 on some non-Windows platforms doesn't use ServicePointManager.
}

$script:LauncherVersion = '1.1.39'
$script:EfCoreSqlitePackageVersion = '8.0.33'
$script:MicrosoftDataSqlitePackageVersion = '8.0.33'
$script:SQLitePclRawBundleVersion = '2.1.11'
$script:SQLiteProviderMode = 'SystemSqlite3'
$script:SQLiteNativeLibraryName = 'libe_sqlite3.so'
$script:LauncherName = 'DNGRMS Authentication Migration Practical Demo Launcher'
$script:Root = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$script:SourceRoot = Join-Path $script:Root 'src/DngrmsDemo.Web'
$script:StateRoot = Join-Path $script:Root 'state'
$script:EvidenceRoot = Join-Path $script:Root 'evidence'
$script:LogRoot = Join-Path $script:Root 'logs'
$script:PackageRoot = Join-Path $script:Root 'packages'
$script:PublishRoot = Join-Path $script:Root 'publish/DngrmsDemo.Web-framework-dependent-linux-x64'
$script:LinuxSelfContainedRoot = Join-Path $script:Root 'publish/DngrmsDemo.Web-selfcontained-linux-x64'
$script:LinuxSelfContainedExecutable = Join-Path $script:LinuxSelfContainedRoot 'DngrmsDemo.Web'
$script:SelfContainedRoot = Join-Path $script:Root 'publish/DngrmsDemo.Web-selfcontained-win-x64'
$script:SelfContainedExecutable = Join-Path $script:SelfContainedRoot 'DngrmsDemo.Web.exe'
$script:StatePath = if ($StatePath) { $StatePath } else { Join-Path $script:StateRoot 'dngrms-auth-demo.state.json' }
$script:State = $null
$script:LastDotNetInvocation = $null
$script:ActiveAzureDeploymentMode = 'FrameworkDependentNet8'
$script:ActiveAzureLinuxFxVersion = 'DOTNETCORE|8.0'
$script:ActiveAzureStartupCommand = 'dotnet DngrmsDemo.Web.dll'
$script:ExpectedPackageIdentity = $null
$script:PostDeploymentStartupContractEvidence = $null
$script:Menu24DeploymentSubmittedUtc = [DateTime]::MinValue
$script:Menu24RuntimeLogNotBeforeUtc = [DateTime]::MinValue
$script:RequiredModules = [ordered]@{
    'Az.Accounts'                    = '3.0.0'
    'Az.Resources'                   = '7.0.0'
    'Az.Websites'                    = '3.0.0'
    'Microsoft.Graph.Authentication'= '2.0.0'
}

foreach ($directory in @($script:StateRoot, $script:EvidenceRoot, $script:LogRoot, $script:PackageRoot)) {
    if (-not (Test-Path -LiteralPath $directory)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }
}

function Write-Color {
    param(
        [Parameter(Mandatory)][string]$Text,
        [ConsoleColor]$Color = [ConsoleColor]::Gray,
        [switch]$NoNewline
    )
    Write-Host $Text -ForegroundColor $Color -NoNewline:$NoNewline
}

function Write-Line {
    param([char]$Character = '-', [int]$Length = 94)
    Write-Host ($Character.ToString() * $Length) -ForegroundColor DarkGray
}

function Write-DemoHeader {
    param(
        [Parameter(Mandatory)][string]$Menu,
        [Parameter(Mandatory)][string]$Objective,
        [string[]]$AzurePortal,
        [string[]]$EntraPortal,
        [string[]]$Expected
    )
    Clear-Host
    Write-Line '='
    Write-Color " $script:LauncherName v$script:LauncherVersion" Cyan
    Write-Color "`n Menu $Menu" Yellow
    Write-Line '='
    Write-Color '[DEMO OBJECTIVE]' Green
    Write-Host "`n$Objective"
    Write-Color "`n[CURRENT STATE]" Green
    Write-Host "`nAuthentication mode : $($script:State.AuthenticationMode)"
    Write-Host "Web app             : $($script:State.WebAppName)"
    Write-Host "Resource group       : $($script:State.ResourceGroupName)"
    if ($AzurePortal) {
        Write-Color "`n[PORTAL UI - AZURE]" Green
        foreach ($path in $AzurePortal) { Write-Host "`n- $path" -NoNewline }
        Write-Host
    }
    if ($EntraPortal) {
        Write-Color "`n[PORTAL UI - ENTRA]" Green
        foreach ($path in $EntraPortal) { Write-Host "`n- $path" -NoNewline }
        Write-Host
    }
    if ($Expected) {
        Write-Color "`n[EXPECTED RESULT]" Green
        foreach ($item in $Expected) { Write-Host "`n- $item" -NoNewline }
        Write-Host
    }
    Write-Line
}

function Write-Step {
    param([Parameter(Mandatory)][string]$Text)
    Write-Color "[STEP] " Cyan -NoNewline
    Write-Host $Text
}

function Write-Success {
    param([Parameter(Mandatory)][string]$Text)
    Write-Color "[SUCCESS] " Green -NoNewline
    Write-Host $Text
}

function Write-WarningMessage {
    param([Parameter(Mandatory)][string]$Text)
    Write-Color "[WARNING] " Yellow -NoNewline
    Write-Host $Text
}

function Write-Failure {
    param([Parameter(Mandatory)][string]$Text)
    Write-Color "[FAILED] " Red -NoNewline
    Write-Host $Text
}

function Read-Choice {
    param(
        [Parameter(Mandatory)][string]$Prompt,
        [string]$Default
    )
    $suffix = if ($Default) { " [$Default]" } else { '' }
    $value = Read-Host "$Prompt$suffix"
    if ([string]::IsNullOrWhiteSpace($value)) { return $Default }
    return $value.Trim()
}

function Read-YesNo {
    param([Parameter(Mandatory)][string]$Prompt, [bool]$Default = $false)
    $label = if ($Default) { '[Y/n]' } else { '[y/N]' }
    $value = (Read-Host "$Prompt $label").Trim().ToLowerInvariant()
    if (-not $value) { return $Default }
    return $value -in @('y','yes','예','네')
}

function Read-RequiredSecureString {
    param([Parameter(Mandatory)][string]$Prompt)
    while ($true) {
        $secure = Read-Host $Prompt -AsSecureString
        $plain = ConvertFrom-SecureStringToPlainText -SecureString $secure
        if ($plain.Length -ge 12) { return $secure }
        Write-WarningMessage 'Use at least 12 characters for the demo password.'
    }
}

function ConvertFrom-SecureStringToPlainText {
    param([Parameter(Mandatory)][securestring]$SecureString)
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
}

function New-DefaultState {
    $suffix = (Get-Random -Minimum 10000 -Maximum 99999).ToString()
    return [ordered]@{
        SchemaVersion              = '1.0'
        LauncherVersion            = $script:LauncherVersion
        CreatedUtc                 = [DateTime]::UtcNow.ToString('o')
        LastUpdatedUtc             = [DateTime]::UtcNow.ToString('o')
        TenantId                   = ''
        SubscriptionId             = ''
        SubscriptionName           = ''
        Location                   = 'koreacentral'
        ResourceGroupName          = "rg-dngrms-auth-demo-$suffix"
        AppServicePlanName         = "asp-dngrms-auth-$suffix"
        WebAppName                 = "dngrms-auth-demo-$suffix"
        AppServiceSku              = 'B1'
        AuthenticationMode         = 'Local'
        SourceRoot                 = $script:SourceRoot
        LocalDatabasePath          = (Join-Path $script:Root 'data/dngrms-demo.db')
        OidcApplicationObjectId    = ''
        OidcApplicationClientId    = ''
        OidcServicePrincipalId     = ''
        SamlApplicationObjectId    = ''
        SamlApplicationClientId    = ''
        SamlServicePrincipalId     = ''
        SamlEntityId               = ''
        SamlMetadataUrl            = ''
        SamlClaimsMappingPolicyId  = ''
        OidcPasswordKeyId          = ''
        OidcPasswordEndDateTime    = ''
        WebAppResourceId           = ''
        DeploymentZipPath                         = ''
        DeploymentFrameworkDependentZipPath       = ''
        DeploymentSelfContainedLinuxX64ZipPath    = ''
        DeploymentPackageMode                     = ''
        DeploymentRuntimeId                        = 'linux-x64'
        DeploymentFrameworkDependent              = $true
        DeploymentStartupCommand                   = ''
        LinuxSelfContainedPublishPath              = ''
        LinuxSelfContainedExecutablePath           = ''
        LinuxSelfContainedPublishUtc               = ''
        SelfContainedPublishPath                   = ''
        SelfContainedExecutablePath                = ''
        SelfContainedRuntimeId                     = 'win-x64'
        SelfContainedPublishUtc                    = ''
        AspNetCoreSharedRuntimeSeen= $false
        AspNetCoreSharedRuntimes   = @()
        LocalProcessId             = 0
        DemoAdminUserName          = 'dngrms-admin'
        DemoStandardUserName       = 'dngrms-user'
        PilotUserPrincipalName     = ''
        CompletedMenus             = @()
        Notes                      = @()
    }
}

function ConvertTo-HashtableRecursive {
    param([Parameter(Mandatory)]$InputObject)
    if ($InputObject -is [System.Collections.IDictionary]) {
        $result = [ordered]@{}
        foreach ($key in $InputObject.Keys) { $result[$key] = ConvertTo-HashtableRecursive $InputObject[$key] }
        return $result
    }
    if ($InputObject -is [pscustomobject]) {
        $result = [ordered]@{}
        foreach ($property in $InputObject.PSObject.Properties) {
            $result[$property.Name] = ConvertTo-HashtableRecursive $property.Value
        }
        return $result
    }
    if (($InputObject -is [System.Collections.IEnumerable]) -and -not ($InputObject -is [string])) {
        return @($InputObject | ForEach-Object { ConvertTo-HashtableRecursive $_ })
    }
    return $InputObject
}

function Save-State {
    $script:State.LauncherVersion = $script:LauncherVersion
    $script:State.LastUpdatedUtc = [DateTime]::UtcNow.ToString('o')
    $tempPath = "${script:StatePath}.tmp"
    $json = $script:State | ConvertTo-Json -Depth 20
    $encoding = New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $false
    [IO.File]::WriteAllText($tempPath, $json, $encoding)
    Move-Item -LiteralPath $tempPath -Destination $script:StatePath -Force
}

function Assert-GuidText {
    param(
        [Parameter(Mandatory)][string]$Value,
        [Parameter(Mandatory)][string]$Label
    )
    $parsed = [Guid]::Empty
    if ([string]::IsNullOrWhiteSpace($Value) -or -not [Guid]::TryParse($Value.Trim(), [ref]$parsed)) {
        throw "$Label '$Value' is not a valid GUID."
    }
    return $parsed.ToString()
}

function Get-CurrentAzureContextSnapshot {
    $context = Assert-AzureContext
    if ($null -eq $context.Subscription -or [string]::IsNullOrWhiteSpace([string]$context.Subscription.Id)) {
        throw 'The current Azure context does not contain a subscription. Run menu 3 and select a subscription.'
    }
    if ($null -eq $context.Tenant -or [string]::IsNullOrWhiteSpace([string]$context.Tenant.Id)) {
        throw 'The current Azure context does not contain a tenant. Run menu 3 again.'
    }

    return [pscustomobject]@{
        TenantId         = Assert-GuidText -Value ([string]$context.Tenant.Id) -Label 'Tenant ID'
        SubscriptionId   = Assert-GuidText -Value ([string]$context.Subscription.Id) -Label 'Subscription ID'
        SubscriptionName = [string]$context.Subscription.Name
        Environment      = [string]$context.Environment.Name
    }
}

function Sync-StateFromAzureContext {
    param([switch]$Save)
    $snapshot = Get-CurrentAzureContextSnapshot
    $script:State['TenantId'] = $snapshot.TenantId
    $script:State['SubscriptionId'] = $snapshot.SubscriptionId
    $script:State['SubscriptionName'] = $snapshot.SubscriptionName
    if ($Save) { Save-State }
    return $snapshot
}

function Get-StateSummaryObject {
    # State is an ordered hashtable. Select-Object reads hashtable object
    # properties (Keys, Values, Count), not arbitrary keys such as TenantId.
    # Explicit key projection is required in both Windows PowerShell 5.1 and 7.x.
    return [pscustomobject][ordered]@{
        TenantId           = [string]$script:State['TenantId']
        SubscriptionId     = [string]$script:State['SubscriptionId']
        SubscriptionName   = [string]$script:State['SubscriptionName']
        Location           = [string]$script:State['Location']
        ResourceGroupName  = [string]$script:State['ResourceGroupName']
        AppServicePlanName = [string]$script:State['AppServicePlanName']
        WebAppName         = [string]$script:State['WebAppName']
        AppServiceSku      = [string]$script:State['AppServiceSku']
    }
}

function Assert-StateConfiguration {
    $summary = Get-StateSummaryObject
    $summary.TenantId = Assert-GuidText -Value $summary.TenantId -Label 'State TenantId'
    $summary.SubscriptionId = Assert-GuidText -Value $summary.SubscriptionId -Label 'State SubscriptionId'
    foreach ($name in @('Location','ResourceGroupName','AppServicePlanName','WebAppName','AppServiceSku')) {
        if ([string]::IsNullOrWhiteSpace([string]($summary.$name))) {
            throw "State value '$name' is empty. Run menu 4 again."
        }
    }
    return $summary
}

function Save-AndVerifyState {
    Save-State
    if (-not (Test-Path -LiteralPath $script:StatePath)) {
        throw "State file was not created: $script:StatePath"
    }
    $savedObject = Get-Content -LiteralPath $script:StatePath -Raw -Encoding UTF8 | ConvertFrom-Json
    $saved = ConvertTo-HashtableRecursive $savedObject
    foreach ($name in @('TenantId','SubscriptionId','Location','ResourceGroupName','AppServicePlanName','WebAppName','AppServiceSku')) {
        if ([string]::IsNullOrWhiteSpace([string]($saved[$name]))) {
            throw "State verification failed: '$name' is empty in $script:StatePath"
        }
        if ([string]($saved[$name]) -ne [string]($script:State[$name])) {
            throw "State verification failed: '$name' differs between memory and $script:StatePath"
        }
    }
    # Reload the exact persisted representation so subsequent menus use the
    # verified state-file values rather than an unverified in-memory object.
    $script:State = $saved
    return [pscustomobject]@{
        Path              = $script:StatePath
        LastUpdatedUtc    = [string]$saved['LastUpdatedUtc']
        SubscriptionId    = [string]$saved['SubscriptionId']
        ResourceGroupName = [string]$saved['ResourceGroupName']
        WebAppName        = [string]$saved['WebAppName']
    }
}

function Ensure-StateConfigurationDefaults {
    $defaults = New-DefaultState
    foreach ($name in @('Location','ResourceGroupName','AppServicePlanName','WebAppName','AppServiceSku')) {
        if ([string]::IsNullOrWhiteSpace([string]($script:State[$name]))) {
            $script:State[$name] = $defaults[$name]
        }
    }
}

function Load-State {
    if (Test-Path -LiteralPath $script:StatePath) {
        $raw = Get-Content -LiteralPath $script:StatePath -Raw -Encoding UTF8 | ConvertFrom-Json
        $script:State = ConvertTo-HashtableRecursive $raw
        foreach ($pair in (New-DefaultState).GetEnumerator()) {
            if (-not $script:State.Contains($pair.Key)) { $script:State[$pair.Key] = $pair.Value }
        }
    }
    else {
        $script:State = New-DefaultState
        Save-State
    }
}

function Complete-Menu {
    param([Parameter(Mandatory)][string]$Menu)
    $completed = @($script:State.CompletedMenus)
    if ($completed -notcontains $Menu) { $script:State.CompletedMenus = @($completed + $Menu) }
    Save-State
}

function Add-StateNote {
    param([Parameter(Mandatory)][string]$Text)
    $existing = @()
    if ($null -ne $script:State.Notes) {
        if ($script:State.Notes -is [System.Collections.IDictionary]) {
            foreach ($entry in $script:State.Notes.GetEnumerator()) {
                $existing += ("{0}={1}" -f [string]$entry.Key,[string]$entry.Value)
            }
        }
        elseif ($script:State.Notes -is [System.Collections.IEnumerable] -and -not ($script:State.Notes -is [string])) {
            foreach ($entry in $script:State.Notes) { $existing += [string]$entry }
        }
        else { $existing += [string]$script:State.Notes }
    }
    $newNote = "$(Get-Date -Format s) $Text"
    $script:State.Notes = @($existing + @($newNote))
    Save-State
}

function Assert-Command {
    param([Parameter(Mandatory)][string]$Name, [string]$Guidance)
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "Required command '$Name' was not found. $Guidance"
    }
}

function Assert-Module {
    param([Parameter(Mandatory)][string]$Name)
    if (-not (Get-Module -ListAvailable -Name $Name)) {
        throw "PowerShell module '$Name' is missing. Run menu 2 first."
    }
    Import-Module $Name -ErrorAction Stop
}

function Assert-AzureContext {
    Assert-Module 'Az.Accounts'
    $context = Get-AzContext -ErrorAction SilentlyContinue
    if (-not $context -or -not $context.Subscription) { throw 'Azure context is missing. Run menu 3.' }
    return $context
}

function Assert-GraphContext {
    Assert-Module 'Microsoft.Graph.Authentication'
    $context = Get-MgContext -ErrorAction SilentlyContinue
    if (-not $context) { throw 'Microsoft Graph context is missing. Run menu 3.' }
    return $context
}

function Assert-GraphDelegatedPrerequisite {
    param([string[]]$RequiredScopes = @('Application.ReadWrite.All','AppRoleAssignment.ReadWrite.All','User.Read'))
    $context = Assert-GraphContext
    if ($script:State.TenantId -and ([string]$context.TenantId -ne [string]$script:State.TenantId)) {
        throw "Microsoft Graph tenant mismatch. Expected=$($script:State.TenantId); Actual=$($context.TenantId). Run Menu 3 and sign in to the correct tenant."
    }
    $actualScopes = @($context.Scopes)
    $missingScopes = @($RequiredScopes | Where-Object { $actualScopes -notcontains $_ })
    if (@($missingScopes).Count -gt 0) {
        throw "Microsoft Graph delegated scopes are missing: $($missingScopes -join ', '). Run Menu 3 and complete Graph consent before continuing."
    }
    try {
        $null = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/me?$select=id,userPrincipalName' -OutputType PSObject -ErrorAction Stop
    }
    catch {
        throw "Microsoft Graph session is unavailable or expired. Run Menu 3 and sign in again. Detail=$($_.Exception.Message)"
    }
    return $context
}

function Invoke-GraphJson {
    param(
        [Parameter(Mandatory)][ValidateSet('GET','POST','PATCH','DELETE')][string]$Method,
        [Parameter(Mandatory)][string]$Uri,
        $Body
    )
    Assert-GraphContext | Out-Null
    $parameters = @{ Method = $Method; Uri = $Uri; OutputType = 'PSObject' }
    if ($null -ne $Body) {
        $parameters.Body = ($Body | ConvertTo-Json -Depth 30 -Compress)
        $parameters.ContentType = 'application/json'
    }
    return Invoke-MgGraphRequest @parameters
}

function Get-WebAppBaseUrl {
    if (-not $script:State.WebAppName) { throw 'Web app name is not configured.' }
    return "https://$($script:State.WebAppName).azurewebsites.net"
}

function Get-AzWebAppSettingsHashtable {
    Assert-Module 'Az.Websites'
    $webApp = Get-AzWebApp -ResourceGroupName $script:State.ResourceGroupName -Name $script:State.WebAppName -ErrorAction Stop
    $result = @{}
    try {
        $rest = Invoke-AzRestMethod -Method POST -Path "$($webApp.Id)/config/appsettings/list?api-version=2023-12-01"
        $properties = ($rest.Content | ConvertFrom-Json).properties
        foreach ($property in $properties.PSObject.Properties) { $result[$property.Name] = [string]$property.Value }
    }
    catch {
        Write-WarningMessage "REST app-settings read failed; falling back to Az.Websites object: $($_.Exception.Message)"
        foreach ($property in @($webApp.SiteConfig.AppSettings)) { $result[$property.Name] = [string]$property.Value }
    }
    return $result
}

function Set-AzWebAppSettingsSafe {
    param([Parameter(Mandatory)][hashtable]$Settings)
    Assert-Module 'Az.Websites'
    $merged = Get-AzWebAppSettingsHashtable
    foreach ($key in $Settings.Keys) { $merged[$key] = [string]$Settings[$key] }
    Set-AzWebApp -ResourceGroupName $script:State.ResourceGroupName -Name $script:State.WebAppName -AppSettings $merged | Out-Null
}

function Remove-AzWebAppSettingSafe {
    param([Parameter(Mandatory)][string[]]$Names)
    Assert-Module 'Az.Websites'
    $settings = Get-AzWebAppSettingsHashtable
    foreach ($name in $Names) { $settings.Remove($name) }
    Set-AzWebApp -ResourceGroupName $script:State.ResourceGroupName -Name $script:State.WebAppName -AppSettings $settings | Out-Null
}

function Set-AuthenticationMode {
    param([Parameter(Mandatory)][ValidateSet('Local','Oidc','Saml','Dual')][string]$Mode)
    Set-AzWebAppSettingsSafe @{ 'DNGRMS_AUTH_MODE' = $Mode }
    $script:State.AuthenticationMode = $Mode
    Save-State
    Restart-AzWebApp -ResourceGroupName $script:State.ResourceGroupName -Name $script:State.WebAppName | Out-Null
    Write-Success "Authentication mode changed to $Mode."
}

function Write-EvidenceJson {
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)]$Data)
    $safeName = $Name -replace '[^A-Za-z0-9_.-]', '_'
    $path = Join-Path $script:EvidenceRoot "$(Get-Date -Format 'yyyyMMdd-HHmmss')-$safeName.json"
    $Data | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $path -Encoding UTF8
    return $path
}

function Wait-WebEndpoint {
    param([Parameter(Mandatory)][string]$Uri, [int]$TimeoutSeconds = 240)
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        try {
            $response = Invoke-WebRequest -Uri $Uri -Method Get -UseBasicParsing -TimeoutSec 20 -ErrorAction Stop
            if ($response.StatusCode -in @(200,301,302,401,403)) { return $response }
        }
        catch { Write-Host '.' -NoNewline }
        Start-Sleep -Seconds 8
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "Endpoint did not become ready within $TimeoutSeconds seconds: $Uri"
}

function Get-HttpStatusNoRedirect {
    <#
      PowerShell 7 has an HTTP-error suppression switch that 5.1 lacks.
      HttpWebRequest is used here because it is available in both Windows
      PowerShell 5.1 (.NET Framework) and PowerShell 7.x (.NET).
    #>
    param([Parameter(Mandatory)][string]$Uri, [int]$TimeoutSeconds = 30)

    $request = [System.Net.HttpWebRequest][System.Net.WebRequest]::Create($Uri)
    $request.Method = 'GET'
    $request.AllowAutoRedirect = $false
    $request.Timeout = $TimeoutSeconds * 1000
    $response = $null
    try {
        $response = $request.GetResponse()
    }
    catch [System.Net.WebException] {
        if ($null -eq $_.Exception.Response) { throw }
        $response = $_.Exception.Response
    }

    try {
        $statusCode = [int]$response.StatusCode
        $location = [string]$response.Headers['Location']
        return [pscustomobject]@{
            StatusCode = $statusCode
            Location   = $location
        }
    }
    finally {
        if ($null -ne $response) { $response.Close() }
    }
}


function Get-ObjectPropertyValue {
    param($InputObject, [Parameter(Mandatory)][string]$Name, $Default = $null)
    if ($null -eq $InputObject) { return $Default }
    if ($InputObject -is [System.Collections.IDictionary]) {
        if ($InputObject.Contains($Name)) { return $InputObject[$Name] }
        return $Default
    }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -ne $property) { return $property.Value }
    return $Default
}

function Get-SafeBodySnippet {
    param([string]$Body, [int]$MaximumLength = 1200)
    if ([string]::IsNullOrWhiteSpace($Body)) { return '' }
    $value = ($Body -replace '[\r\n\t]+', ' ' -replace '\s{2,}', ' ').Trim()
    if ($value.Length -gt $MaximumLength) { return $value.Substring(0, $MaximumLength) + '...[truncated]' }
    return $value
}

function Read-StreamText {
    <#
       Cross-edition text reader used for ZIP entries and HTTP/Kudu response streams.
       Windows PowerShell 5.1 can bind New-Object constructor arguments differently
       from PowerShell 7.x. Resolve and invoke the exact five-parameter constructor
       so no three-argument StreamReader overload is required.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][System.IO.Stream]$Stream,
        [System.Text.Encoding]$Encoding = [System.Text.Encoding]::UTF8,
        [bool]$DetectEncodingFromByteOrderMarks = $true,
        [ValidateRange(128,1048576)][int]$BufferSize = 4096,
        [bool]$LeaveOpen = $true
    )

    if ($null -eq $Encoding) { $Encoding = [System.Text.Encoding]::UTF8 }
    $parameterTypes = [Type[]]@(
        [System.IO.Stream],
        [System.Text.Encoding],
        [System.Boolean],
        [System.Int32],
        [System.Boolean]
    )
    $constructor = [System.IO.StreamReader].GetConstructor($parameterTypes)
    if ($null -eq $constructor) {
        throw 'The required StreamReader(Stream, Encoding, Boolean, Int32, Boolean) constructor is unavailable.'
    }

    $reader = $null
    try {
        $constructorArguments = [object[]]@(
            $Stream,
            $Encoding,
            [bool]$DetectEncodingFromByteOrderMarks,
            [int]$BufferSize,
            [bool]$LeaveOpen
        )
        $reader = [System.IO.StreamReader]$constructor.Invoke($constructorArguments)
        return [string]$reader.ReadToEnd()
    }
    finally {
        if ($null -ne $reader) { $reader.Dispose() }
    }
}

function Read-ZipArchiveEntryText {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)]$Entry)

    $entryStream = $null
    try {
        $entryStream = $Entry.Open()
        return Read-StreamText -Stream $entryStream -Encoding ([System.Text.Encoding]::UTF8) `
            -DetectEncodingFromByteOrderMarks $true -BufferSize 4096 -LeaveOpen $true
    }
    finally {
        if ($null -ne $entryStream) { $entryStream.Dispose() }
    }
}

function Get-HttpFailureCategory {
    param([int]$StatusCode, [string]$Body, [string]$ErrorMessage)
    if ($StatusCode -eq 0) { return 'TransportFailure' }
    if ($StatusCode -eq 401) { return 'Unauthorized' }
    if ($StatusCode -eq 403) {
        if ($Body -match '(?i)site\s+disabled|web app is stopped') { return 'SiteDisabledStopped' }
        return 'Forbidden'
    }
    if ($StatusCode -eq 404) { return 'NotFound' }
    if ($StatusCode -eq 408 -or $StatusCode -eq 429) { return 'TransientHttp' }
    if ($StatusCode -ge 500) { return 'ServerUnavailable' }
    return 'None'
}

function Invoke-DngrmsHttpRequest {
    <# Cross-edition HTTP wrapper. Unlike Invoke-WebRequest in Windows PowerShell 5.1,
       this returns non-2xx responses as data and never mistakes an HTTP 202 for a
       transport failure. Access tokens are accepted only in memory and are not logged. #>
    param(
        [Parameter(Mandatory)][ValidateSet('GET','POST','PUT','DELETE')][string]$Method,
        [Parameter(Mandatory)][string]$Uri,
        [hashtable]$Headers,
        [string]$ContentType,
        [string]$BodyText,
        [string]$UploadFilePath,
        [int]$TimeoutSeconds = 60
    )

    $request = [System.Net.HttpWebRequest][System.Net.WebRequest]::Create($Uri)
    $request.Method = $Method
    $request.AllowAutoRedirect = $false
    $request.KeepAlive = $true
    $request.Timeout = [Math]::Max(1000, $TimeoutSeconds * 1000)
    $request.ReadWriteTimeout = [Math]::Max(1000, $TimeoutSeconds * 1000)
    $request.UserAgent = "DNGRMS-Auth-Migration-Demo-Launcher/$script:LauncherVersion"
    if ($ContentType) { $request.ContentType = $ContentType }
    if ($Headers) {
        foreach ($name in $Headers.Keys) { $request.Headers[[string]$name] = [string]$Headers[$name] }
    }

    $requestStream = $null
    $fileStream = $null
    try {
        if ($UploadFilePath) {
            if (-not (Test-Path -LiteralPath $UploadFilePath -PathType Leaf)) { throw "Upload file does not exist: $UploadFilePath" }
            $fileInfo = Get-Item -LiteralPath $UploadFilePath
            $request.ContentLength = $fileInfo.Length
            $requestStream = $request.GetRequestStream()
            $fileStream = [IO.File]::OpenRead($UploadFilePath)
            $fileStream.CopyTo($requestStream)
        }
        elseif ($null -ne $BodyText -and $Method -ne 'GET') {
            $bytes = [Text.Encoding]::UTF8.GetBytes($BodyText)
            $request.ContentLength = $bytes.Length
            $requestStream = $request.GetRequestStream()
            $requestStream.Write($bytes, 0, $bytes.Length)
        }
    }
    finally {
        if ($null -ne $fileStream) { $fileStream.Dispose() }
        if ($null -ne $requestStream) { $requestStream.Dispose() }
    }

    $response = $null
    $transportError = ''
    try { $response = $request.GetResponse() }
    catch [System.Net.WebException] {
        $transportError = $_.Exception.Message
        if ($null -ne $_.Exception.Response) { $response = $_.Exception.Response }
    }
    catch { $transportError = $_.Exception.Message }

    if ($null -eq $response) {
        return [pscustomobject]@{
            Uri=$Uri; StatusCode=0; StatusDescription=''; Location=''; Headers=[ordered]@{}; Body='';
            ErrorMessage=$transportError; FailureCategory='TransportFailure'; CapturedUtc=[DateTime]::UtcNow.ToString('o')
        }
    }

    try {
        $body = ''
        $stream = $response.GetResponseStream()
        if ($null -ne $stream) {
            try {
                $body = Read-StreamText -Stream $stream -Encoding ([System.Text.Encoding]::UTF8) `
                    -DetectEncodingFromByteOrderMarks $true -BufferSize 4096 -LeaveOpen $true
            }
            finally { $stream.Dispose() }
        }
        $headerMap = [ordered]@{}
        foreach ($name in @($response.Headers.AllKeys)) { $headerMap[$name] = [string]$response.Headers[$name] }
        $statusCode = [int]$response.StatusCode
        return [pscustomobject]@{
            Uri=$Uri
            StatusCode=$statusCode
            StatusDescription=[string]$response.StatusDescription
            Location=[string]$response.Headers['Location']
            Headers=$headerMap
            Body=$body
            ErrorMessage=$transportError
            FailureCategory=(Get-HttpFailureCategory -StatusCode $statusCode -Body $body -ErrorMessage $transportError)
            CapturedUtc=[DateTime]::UtcNow.ToString('o')
        }
    }
    finally { $response.Close() }
}

function ConvertTo-HttpEvidenceSummary {
    param($Response)
    if ($null -eq $Response) { return $null }
    return [pscustomobject][ordered]@{
        CapturedUtc=[string](Get-ObjectPropertyValue $Response 'CapturedUtc' '')
        Uri=[string](Get-ObjectPropertyValue $Response 'Uri' '')
        StatusCode=[int](Get-ObjectPropertyValue $Response 'StatusCode' 0)
        StatusDescription=[string](Get-ObjectPropertyValue $Response 'StatusDescription' '')
        Location=[string](Get-ObjectPropertyValue $Response 'Location' '')
        FailureCategory=[string](Get-ObjectPropertyValue $Response 'FailureCategory' '')
        ErrorMessage=[string](Get-ObjectPropertyValue $Response 'ErrorMessage' '')
        BodySnippet=(Get-SafeBodySnippet -Body ([string](Get-ObjectPropertyValue $Response 'Body' '')))
    }
}

function Get-AzBearerTokenText {
    Assert-Module 'Az.Accounts'
    $tokenResult = Get-AzAccessToken -ResourceUrl 'https://management.azure.com/' -ErrorAction Stop
    $tokenValue = Get-ObjectPropertyValue $tokenResult 'Token' $null
    if ($tokenValue -is [securestring]) { $tokenText = ConvertFrom-SecureStringToPlainText $tokenValue }
    else { $tokenText = [string]$tokenValue }
    if ([string]::IsNullOrWhiteSpace($tokenText)) { throw 'Get-AzAccessToken returned an empty management-plane bearer token.' }
    return $tokenText
}

function Get-AppServicePlanSnapshot {
    Assert-Module 'Az.Websites'
    $plan = Get-AzAppServicePlan -ResourceGroupName $script:State.ResourceGroupName -Name $script:State.AppServicePlanName -ErrorAction Stop
    $skuObject = Get-ObjectPropertyValue $plan 'Sku' $null
    if ($null -eq $skuObject) { $skuObject = Get-ObjectPropertyValue $plan 'SkuDescription' $null }
    $skuName = [string](Get-ObjectPropertyValue $skuObject 'Name' '')
    if (-not $skuName) { $skuName = [string](Get-ObjectPropertyValue $plan 'WorkerSize' '') }
    $tier = [string](Get-ObjectPropertyValue $skuObject 'Tier' '')
    if (-not $tier) { $tier = [string](Get-ObjectPropertyValue $plan 'Tier' '') }
    return [pscustomobject][ordered]@{
        CapturedUtc=[DateTime]::UtcNow.ToString('o')
        Name=[string](Get-ObjectPropertyValue $plan 'Name' $script:State.AppServicePlanName)
        ResourceGroup=$script:State.ResourceGroupName
        SkuName=$skuName
        Tier=$tier
        WorkerSize=[string](Get-ObjectPropertyValue $plan 'WorkerSize' '')
        Status=[string](Get-ObjectPropertyValue $plan 'Status' '')
        IsMinimumPaidB1=(($skuName -eq 'B1') -or (($tier -eq 'Basic') -and ([string](Get-ObjectPropertyValue $plan 'WorkerSize' '')) -in @('Small','B1')))
    }
}

function Assert-MinimumPaidB1Plan {
    Write-Step 'Enforcing the minimum guided paid App Service plan (Basic B1)...'
    $before = Get-AppServicePlanSnapshot
    $scaled = $false
    if (-not $before.IsMinimumPaidB1) {
        Write-Step "App Service plan is not B1 (SKU=$($before.SkuName); Tier=$($before.Tier)). Scaling to minimum paid Basic B1..."
        Set-AzAppServicePlan -ResourceGroupName $script:State.ResourceGroupName -Name $script:State.AppServicePlanName -Tier Basic -WorkerSize Small | Out-Null
        $scaled = $true
    }
    $deadline = [DateTime]::UtcNow.AddSeconds(240)
    do {
        $after = Get-AppServicePlanSnapshot
        if ($after.IsMinimumPaidB1) { break }
        Start-Sleep -Seconds 6
    } while ([DateTime]::UtcNow -lt $deadline)
    if (-not $after.IsMinimumPaidB1) { throw "App Service plan did not reach Basic B1. Current SKU=$($after.SkuName); Tier=$($after.Tier)." }
    $script:State.AppServiceSku = 'B1'
    Save-State
    return [pscustomobject][ordered]@{ Before=$before; ScaleInvoked=$scaled; After=$after; GuidedMinimumPaidSku='B1' }
}

function Get-WebAppManagementSnapshot {
    Assert-Module 'Az.Websites'
    $app = Get-AzWebApp -ResourceGroupName $script:State.ResourceGroupName -Name $script:State.WebAppName -ErrorAction Stop
    return [pscustomobject][ordered]@{
        CapturedUtc=[DateTime]::UtcNow.ToString('o')
        Name=[string](Get-ObjectPropertyValue $app 'Name' $script:State.WebAppName)
        State=[string](Get-ObjectPropertyValue $app 'State' '')
        AvailabilityState=[string](Get-ObjectPropertyValue $app 'AvailabilityState' '')
        Enabled=(Get-ObjectPropertyValue $app 'Enabled' $true)
        HostNames=@(Get-ObjectPropertyValue $app 'HostNames' @())
        DefaultHostName=[string](Get-ObjectPropertyValue $app 'DefaultHostName' "$($script:State.WebAppName).azurewebsites.net")
        ResourceGroup=$script:State.ResourceGroupName
    }
}

function Ensure-WebAppRunning {
    Write-Step 'Checking App Service management state before any Kudu SCM operation...'
    $before = Get-WebAppManagementSnapshot
    Write-Host "App Service state before Kudu: $($before.State)"
    $startInvoked = $false
    if ($before.State -ne 'Running') {
        Write-Step "App Service is '$($before.State)'; starting it before any Kudu operation..."
        Start-AzWebApp -ResourceGroupName $script:State.ResourceGroupName -Name $script:State.WebAppName | Out-Null
        $startInvoked = $true
    }
    $deadline = [DateTime]::UtcNow.AddSeconds(240)
    do {
        $after = Get-WebAppManagementSnapshot
        if ($after.State -eq 'Running') { break }
        Start-Sleep -Seconds 6
    } while ([DateTime]::UtcNow -lt $deadline)
    if ($after.State -ne 'Running') { throw "App Service did not reach Running state. Current state: $($after.State)." }
    return [pscustomobject][ordered]@{ Before=$before; StartInvoked=$startInvoked; After=$after }
}

function Get-AppServiceSiteConfigSnapshot {
    $app = Get-AzWebApp -ResourceGroupName $script:State.ResourceGroupName -Name $script:State.WebAppName -ErrorAction Stop
    $config = Get-AzResource -ResourceId "$($app.Id)/config/web" -ApiVersion '2023-12-01' -ExpandProperties -ErrorAction Stop
    $properties = Get-ObjectPropertyValue $config 'Properties' $null
    if ($null -eq $properties) { $properties = $config }
    return [pscustomobject][ordered]@{
        CapturedUtc=[DateTime]::UtcNow.ToString('o')
        ResourceId="$($app.Id)/config/web"
        LinuxFxVersion=[string](Get-ObjectPropertyValue $properties 'linuxFxVersion' '')
        StartupCommand=[string](Get-ObjectPropertyValue $properties 'appCommandLine' '')
        AlwaysOn=(Get-ObjectPropertyValue $properties 'alwaysOn' $false)
        HealthCheckPath=[string](Get-ObjectPropertyValue $properties 'healthCheckPath' '')
    }
}

function Get-LinuxAppServiceAvailableRuntimeSnapshot {
    Write-Step 'Querying the Linux runtimes currently advertised by Azure App Service...'
    $context = Assert-AzureContext
    $subscriptionId = [string]$context.Subscription.Id
    if ([string]::IsNullOrWhiteSpace($subscriptionId)) { $subscriptionId = [string]$script:State.SubscriptionId }
    $restPath = "/subscriptions/$subscriptionId/providers/Microsoft.Web/availableStacks?osTypeSelected=Linux&api-version=2023-12-01"
    $rawSources = @()
    $errors = @()
    try {
        $rest = Invoke-AzRestMethod -Method GET -Path $restPath
        $raw = [string](Get-ObjectPropertyValue $rest 'Content' '')
        if (-not [string]::IsNullOrWhiteSpace($raw)) { $rawSources += [pscustomobject]@{ Source='Microsoft.Web availableStacks REST'; Text=$raw } }
    }
    catch { $errors += "Microsoft.Web availableStacks REST: $($_.Exception.Message)" }

    $azCommand = Get-Command az -ErrorAction SilentlyContinue
    if ($null -ne $azCommand) {
        $previousPreference = $ErrorActionPreference
        try {
            $ErrorActionPreference = 'Continue'
            $azLines = @(& az webapp list-runtimes --os linux --output json 2>&1 | ForEach-Object { [string]$_ })
            $azExitCode = $LASTEXITCODE
            if ($azExitCode -eq 0) { $rawSources += [pscustomobject]@{ Source='az webapp list-runtimes --os linux'; Text=($azLines -join "`n") } }
            else { $errors += "az webapp list-runtimes exited with code $azExitCode." }
        }
        catch { $errors += "az webapp list-runtimes: $($_.Exception.Message)" }
        finally { $ErrorActionPreference = $previousPreference }
    }

    $runtimeValues = @()
    foreach ($source in $rawSources) {
        $rawText = [string]$source.Text
        foreach ($match in [regex]::Matches($rawText, '(?i)DOTNETCORE\|\d+(?:\.\d+)+')) {
            $runtimeValues += $match.Value.ToUpperInvariant()
        }
        try {
            $parsed = $rawText | ConvertFrom-Json
            $topItems = @((Get-ObjectPropertyValue $parsed 'value' @()))
            if ($topItems.Count -eq 0) { $topItems = @($parsed) }
            foreach ($item in $topItems) {
                $itemJson = $item | ConvertTo-Json -Depth 40 -Compress
                if ($itemJson -notmatch '(?i)(dotnetcore|dotnet core|asp\.net core|\.net core)') { continue }
                foreach ($versionMatch in [regex]::Matches($itemJson, '(?i)"(?:runtimeVersion|majorVersion)"\s*:\s*"(?<version>\d+(?:\.\d+)+)"')) {
                    $runtimeValues += "DOTNETCORE|$($versionMatch.Groups['version'].Value)"
                }
            }
        }
        catch { }
    }
    $runtimeValues = @($runtimeValues | Sort-Object -Unique)
    return [pscustomobject][ordered]@{
        CapturedUtc=[DateTime]::UtcNow.ToString('o')
        QuerySucceeded=($rawSources.Count -gt 0)
        Sources=@($rawSources | ForEach-Object { $_.Source })
        LinuxFxVersions=$runtimeValues
        DotNet8Advertised=($runtimeValues -contains 'DOTNETCORE|8.0')
        Errors=$errors
        RestPath=$restPath
    }
}

function Get-PreferredSelfContainedHostStack {
    param($AvailableRuntimes, [string]$ConfiguredLinuxFxVersion)
    $candidates = @((Get-ObjectPropertyValue $AvailableRuntimes 'LinuxFxVersions' @()) | Where-Object { $_ -match '^DOTNETCORE\|\d+(?:\.\d+)+$' })
    $sorted = @($candidates | Sort-Object { [version](($_ -split '\|',2)[1]) } -Descending)
    if ($sorted.Count -gt 0) { return [string]$sorted[0] }
    if ($ConfiguredLinuxFxVersion -match '^DOTNETCORE\|') { return $ConfiguredLinuxFxVersion }
    return 'DOTNETCORE|8.0'
}

function Set-LinuxAppServiceStartupContract {
    param(
        [Parameter(Mandatory)][ValidateSet('FrameworkDependentNet8','SelfContainedLinuxX64')][string]$PackageDeploymentMode,
        [string]$LinuxFxVersion
    )
    if ([string]::IsNullOrWhiteSpace($LinuxFxVersion)) {
        $LinuxFxVersion = if ($PackageDeploymentMode -eq 'FrameworkDependentNet8') { 'DOTNETCORE|8.0' } else { $script:ActiveAzureLinuxFxVersion }
    }
    $startupCommand = if ($PackageDeploymentMode -eq 'FrameworkDependentNet8') { 'dotnet DngrmsDemo.Web.dll' } else { '/bin/sh /home/site/wwwroot/dngrms-start-selfcontained.sh' }
    Write-Step "Transitioning the App Service Linux startup contract. Mode=$PackageDeploymentMode; linuxFxVersion=$LinuxFxVersion; Startup=$startupCommand"
    $app = Get-AzWebApp -ResourceGroupName $script:State.ResourceGroupName -Name $script:State.WebAppName -ErrorAction Stop
    $resourceId = "$($app.Id)/config/web"
    $before = Get-AppServiceSiteConfigSnapshot
    $clearApplied = $false
    $clearVerified = [string]::IsNullOrWhiteSpace([string]$before.StartupCommand)

    # A two-phase transition prevents an old framework-dependent command from
    # surviving a switch to the self-contained package. The blank value is
    # verified before the final command is written.
    if (-not $clearVerified) {
        Set-AzResource -ResourceId $resourceId -ApiVersion '2023-12-01' -Properties @{
            linuxFxVersion=$LinuxFxVersion
            appCommandLine=''
            alwaysOn=$true
            http20Enabled=$true
            minTlsVersion='1.2'
            ftpsState='Disabled'
            healthCheckPath='/health'
        } -Force | Out-Null
        $clearApplied = $true
        $clearDeadline = [DateTime]::UtcNow.AddSeconds(90)
        do {
            Start-Sleep -Seconds 2
            $cleared = Get-AppServiceSiteConfigSnapshot
            $clearVerified = [string]::IsNullOrWhiteSpace([string]$cleared.StartupCommand)
        } while (-not $clearVerified -and [DateTime]::UtcNow -lt $clearDeadline)
        if (-not $clearVerified) {
            throw "App Service did not clear the previous startup command. Previous=$($before.StartupCommand); Actual=$($cleared.StartupCommand)."
        }
    }

    Set-AzResource -ResourceId $resourceId -ApiVersion '2023-12-01' -Properties @{
        linuxFxVersion=$LinuxFxVersion
        appCommandLine=$startupCommand
        alwaysOn=$true
        http20Enabled=$true
        minTlsVersion='1.2'
        ftpsState='Disabled'
        healthCheckPath='/health'
    } -Force | Out-Null
    Set-AzWebApp -ResourceGroupName $script:State.ResourceGroupName -Name $script:State.WebAppName -HttpsOnly $true | Out-Null
    Set-AzWebAppSettingsSafe @{
        'WEBSITE_RUN_FROM_PACKAGE'='1'
        'SCM_DO_BUILD_DURING_DEPLOYMENT'='false'
        'ENABLE_ORYX_BUILD'='false'
        'WEBSITES_CONTAINER_START_TIME_LIMIT'='600'
        'WEBSITE_WARMUP_PATH'='/health'
        'WEBSITE_WARMUP_STATUSES'='200'
        'ASPNETCORE_ENVIRONMENT'='Production'
    }
    $script:ActiveAzureDeploymentMode = $PackageDeploymentMode
    $script:ActiveAzureLinuxFxVersion = $LinuxFxVersion
    $script:ActiveAzureStartupCommand = $startupCommand
    $script:State['DeploymentPackageMode'] = $PackageDeploymentMode
    $script:State['DeploymentRuntimeId'] = 'linux-x64'
    $script:State['DeploymentFrameworkDependent'] = ($PackageDeploymentMode -eq 'FrameworkDependentNet8')
    $script:State['DeploymentStartupCommand'] = $startupCommand
    Save-State

    $deadline = [DateTime]::UtcNow.AddSeconds(90)
    do {
        Start-Sleep -Seconds 2
        $actual = Get-AppServiceSiteConfigSnapshot
        $persisted = ($actual.LinuxFxVersion -eq $LinuxFxVersion -and $actual.StartupCommand -eq $startupCommand)
    } while (-not $persisted -and [DateTime]::UtcNow -lt $deadline)
    if ($actual.LinuxFxVersion -ne $LinuxFxVersion) {
        throw "App Service did not persist the requested linuxFxVersion. Requested=$LinuxFxVersion; Actual=$($actual.LinuxFxVersion)."
    }
    if ($actual.StartupCommand -ne $startupCommand) {
        throw "App Service did not persist the requested startup command. Requested=$startupCommand; Actual=$($actual.StartupCommand)."
    }
    return [pscustomobject][ordered]@{
        PackageDeploymentMode=$PackageDeploymentMode
        RequestedLinuxFxVersion=$LinuxFxVersion
        ActualLinuxFxVersion=$actual.LinuxFxVersion
        ConfiguredBefore=$before
        PreviousStartupCommand=[string]$before.StartupCommand
        PreviousStartupCommandCleared=$clearApplied
        ClearVerified=$clearVerified
        StartupCommand=$startupCommand
        DirectLinuxAppHost=$false
        BootstrapCopiesMountedPackageToWritableHome=($PackageDeploymentMode -eq 'SelfContainedLinuxX64')
        AlwaysOn=$actual.AlwaysOn
        RunFromPackage='1'
        ScmBuildDuringDeployment='false'
        OryxBuild='false'
        WarmupPath='/health'
        WarmupStatuses='200'
        RequiresSharedMicrosoftNetCoreApp8=($PackageDeploymentMode -eq 'FrameworkDependentNet8')
    }
}

function Set-LinuxNet8StartupContract {
    param([string]$PackageDeploymentMode = '', [string]$LinuxFxVersion = '')
    if ([string]::IsNullOrWhiteSpace($PackageDeploymentMode)) { $PackageDeploymentMode = $script:ActiveAzureDeploymentMode }
    if ([string]::IsNullOrWhiteSpace($PackageDeploymentMode)) { $PackageDeploymentMode = 'FrameworkDependentNet8' }
    if ([string]::IsNullOrWhiteSpace($LinuxFxVersion)) {
        $LinuxFxVersion = if ($PackageDeploymentMode -eq 'FrameworkDependentNet8') { 'DOTNETCORE|8.0' } else { $script:ActiveAzureLinuxFxVersion }
    }
    return Set-LinuxAppServiceStartupContract -PackageDeploymentMode $PackageDeploymentMode -LinuxFxVersion $LinuxFxVersion
}

function Get-KuduDotNetRuntimeSnapshot {
    param([Parameter(Mandatory)][string]$BearerToken, [string]$Label = 'PreDeployment')
    Write-Step "Collecting the Kudu/direct .NET runtime inventory ($Label)..."
    $nonce = [Guid]::NewGuid().ToString('N').Substring(0,10)
    $scriptName = "dngrms-runtime-inventory-$nonce.sh"
    $scriptPath = "/home/$scriptName"
    $scriptUri = "$(Get-KuduBaseUrl)/api/vfs/$scriptName"
    $scriptText = @(
        '#!/bin/sh'
        'set +e'
        'echo DNGRMS_DOTNET_INFO_BEGIN'
        'dotnet --info'
        'echo DNGRMS_DOTNET_RUNTIMES_BEGIN'
        'dotnet --list-runtimes'
        'probe_code=$?'
        'echo DNGRMS_DOTNET_RUNTIMES_END'
        'echo DNGRMS_RUNTIME_INVENTORY_EXIT_CODE=$probe_code'
        'exit 0'
    ) -join "`n"
    $scriptText += "`n"
    $upload = $null
    $execution = $null
    try {
        $upload = Invoke-KuduRequest -Method PUT -Uri $scriptUri -BearerToken $BearerToken -Headers @{'If-Match'='*'} -ContentType 'application/octet-stream' -BodyText $scriptText -TimeoutSeconds 120
        if ($upload.StatusCode -notin @(200,201,204)) { throw "Runtime inventory script upload failed with HTTP $($upload.StatusCode)." }
        $execution = Invoke-KuduSimpleCommand -Command "/bin/sh $scriptPath" -WorkingDirectory '/home' -BearerToken $BearerToken -TimeoutSeconds 120
    }
    finally {
        try { $null = Invoke-KuduRequest -Method DELETE -Uri $scriptUri -BearerToken $BearerToken -Headers @{'If-Match'='*'} -TimeoutSeconds 60 } catch { }
    }
    $output = Protect-KuduDiagnosticText -Text (([string]$execution.Output) + "`n" + ([string]$execution.Error)) -MaximumLength 50000
    $runtimeLines = @($output -split "`r?`n" | Where-Object { $_ -match '^Microsoft\.(NETCore|AspNetCore)\.App\s+\d+(?:\.\d+)+' })
    $core8 = @($runtimeLines | Where-Object { $_ -match '^Microsoft\.NETCore\.App\s+8\.' })
    $aspNet8 = @($runtimeLines | Where-Object { $_ -match '^Microsoft\.AspNetCore\.App\s+8\.' })
    $exitCode = -1
    $match = [regex]::Match($output, 'DNGRMS_RUNTIME_INVENTORY_EXIT_CODE=(\d+)')
    if ($match.Success) { [void][int]::TryParse($match.Groups[1].Value, [ref]$exitCode) }
    return [pscustomobject][ordered]@{
        CapturedUtc=[DateTime]::UtcNow.ToString('o')
        Label=$Label
        ScriptSha256=(Get-TextSha256 -Text $scriptText)
        UploadHttp=if ($null -ne $upload) { ConvertTo-HttpEvidenceSummary $upload } else { $null }
        CommandHttp=if ($null -ne $execution) { $execution.Http } else { $null }
        CommandExitCode=if ($null -ne $execution) { $execution.ExitCode } else { -1 }
        RuntimeInventoryExitCode=$exitCode
        RuntimeLines=$runtimeLines
        MicrosoftNetCoreApp8Lines=$core8
        MicrosoftAspNetCoreApp8Lines=$aspNet8
        MicrosoftNetCoreApp8Visible=($core8.Count -gt 0)
        MicrosoftAspNetCoreApp8Visible=($aspNet8.Count -gt 0)
        Net8SharedRuntimeReady=($core8.Count -gt 0 -and $aspNet8.Count -gt 0)
        Output=$output
    }
}

function Write-AzureRuntimeContractConsole {
    param([Parameter(Mandatory)]$Contract)
    Write-Host ''
    Write-Host '[PRE-DEPLOYMENT RUNTIME CONTRACT]' -ForegroundColor Cyan
    Write-Host ("  Configured linuxFxVersion before : {0}" -f $Contract.ConfiguredBefore.LinuxFxVersion)
    Write-Host ("  Available Linux runtimes          : {0}" -f ((@($Contract.AvailableLinuxRuntimes.LinuxFxVersions) -join ', ')))
    Write-Host ("  Available-runtime query succeeded : {0}" -f $Contract.AvailableLinuxRuntimes.QuerySucceeded)
    Write-Host ("  .NET 8 stack advertised           : {0}" -f $Contract.AvailableLinuxRuntimes.DotNet8Advertised)
    if ($null -ne $Contract.RuntimeInventoryAfterNet8) {
        Write-Host ("  Kudu/direct runtime list after 8  : {0}" -f ((@($Contract.RuntimeInventoryAfterNet8.RuntimeLines) -join '; ')))
        Write-Host ("  Shared .NET 8 runtime ready       : {0}" -f $Contract.RuntimeInventoryAfterNet8.Net8SharedRuntimeReady)
    }
    if ($null -ne $Contract.RuntimeInventoryAfterFallback) {
        Write-Host ("  Kudu/direct runtime list fallback : {0}" -f ((@($Contract.RuntimeInventoryAfterFallback.RuntimeLines) -join '; ')))
    }
    Write-Host ("  Configured linuxFxVersion final   : {0}" -f $Contract.ConfiguredAfter.LinuxFxVersion)
    Write-Host ("  Package deployment mode           : {0}" -f $Contract.PackageDeploymentMode)
    Write-Host ("  Startup command                   : {0}" -f $Contract.StartupContract.StartupCommand)
    Write-Host ("  Selected package                  : {0}" -f $Contract.SelectedZipPath)
    Write-Host ("  Selected package id               : {0}" -f ([string](Get-ObjectPropertyValue $Contract.ExpectedPackageIdentity 'PackageId' '')))
    Write-Host ("  Selection reason                  : {0}" -f $Contract.SelectionReason)
}

function Resolve-AzureDeploymentRuntimeContract {
    param([Parameter(Mandatory)][string]$BearerToken)
    $before = Get-AppServiceSiteConfigSnapshot
    $available = Get-LinuxAppServiceAvailableRuntimeSnapshot
    $attemptNet8 = ($available.DotNet8Advertised -or $before.LinuxFxVersion -eq 'DOTNETCORE|8.0')
    $net8Startup = $null
    $net8Inventory = $null
    $fallbackInventory = $null
    $selectedPath = ''
    $mode = ''
    $reason = ''

    if ($attemptNet8) {
        $net8Startup = Set-LinuxAppServiceStartupContract -PackageDeploymentMode 'FrameworkDependentNet8' -LinuxFxVersion 'DOTNETCORE|8.0'
        Restart-AzWebApp -ResourceGroupName $script:State.ResourceGroupName -Name $script:State.WebAppName | Out-Null
        $null = Ensure-WebAppRunning
        $null = Wait-KuduReady -BearerToken $BearerToken -TimeoutSeconds 300
        $net8Inventory = Get-KuduDotNetRuntimeSnapshot -BearerToken $BearerToken -Label 'After DOTNETCORE|8.0 restart'
    }

    if ($null -ne $net8Inventory -and $net8Inventory.Net8SharedRuntimeReady) {
        $selectedPath = Get-FrameworkDependentDeploymentPackage
        $mode = 'FrameworkDependentNet8'
        $reason = 'DOTNETCORE|8.0 is configured and the direct runtime inventory exposes Microsoft.NETCore.App 8.x plus Microsoft.AspNetCore.App 8.x.'
        $startup = $net8Startup
    }
    else {
        $selectedPath = Ensure-LinuxSelfContainedDeploymentPackage
        $mode = 'SelfContainedLinuxX64'
        $hostFx = Get-PreferredSelfContainedHostStack -AvailableRuntimes $available -ConfiguredLinuxFxVersion $before.LinuxFxVersion
        $startup = Set-LinuxAppServiceStartupContract -PackageDeploymentMode $mode -LinuxFxVersion $hostFx
        # Updating siteConfig can recycle the worker. Do not add a second explicit restart
        # while the previous package is still mounted; deployment will recycle again.
        $null = Ensure-WebAppRunning
        $null = Wait-KuduReady -BearerToken $BearerToken -TimeoutSeconds 300
        $fallbackInventory = Get-KuduDotNetRuntimeSnapshot -BearerToken $BearerToken -Label 'Self-contained fallback host'
        if (-not $attemptNet8) {
            $reason = 'DOTNETCORE|8.0 was not advertised by the platform and was not the current configured stack; the Linux self-contained artifact was selected before deployment.'
        }
        else {
            $reason = 'DOTNETCORE|8.0 was applied and restarted, but the direct runtime inventory did not expose both required .NET 8 shared frameworks; the Linux self-contained artifact was selected before deployment.'
        }
    }

    $selectedPackageContract = Test-DeploymentZipContract -ZipPath $selectedPath -ExpectedMode $mode
    $script:ExpectedPackageIdentity = $selectedPackageContract.LinuxX64RuntimeContract.PackageManifest
    $after = Get-AppServiceSiteConfigSnapshot
    $script:State['DeploymentZipPath'] = $selectedPath
    $script:State['DeploymentPackageMode'] = $mode
    $script:State['DeploymentRuntimeId'] = 'linux-x64'
    $script:State['DeploymentFrameworkDependent'] = ($mode -eq 'FrameworkDependentNet8')
    $script:State['DeploymentStartupCommand'] = $startup.StartupCommand
    Save-State
    $contract = [pscustomobject][ordered]@{
        CapturedUtc=[DateTime]::UtcNow.ToString('o')
        ConfiguredBefore=$before
        AvailableLinuxRuntimes=$available
        AttemptedDotNet8Stack=$attemptNet8
        DotNet8StartupContract=$net8Startup
        RuntimeInventoryAfterNet8=$net8Inventory
        RuntimeInventoryAfterFallback=$fallbackInventory
        PackageDeploymentMode=$mode
        SelectedZipPath=$selectedPath
        SelectedPackageContract=$selectedPackageContract
        ExpectedPackageIdentity=$script:ExpectedPackageIdentity
        StartupContract=$startup
        ConfiguredAfter=$after
        SelectionReason=$reason
        SharedRuntimeDependencyEliminated=($mode -eq 'SelfContainedLinuxX64')
    }
    Write-AzureRuntimeContractConsole -Contract $contract
    return $contract
}

function ConvertTo-RuntimeLogLines {
    param(
        [string]$Text,
        [string]$Source = 'Runtime',
        [int]$MaximumLines = 2000
    )
    $results = @()
    if ([string]::IsNullOrWhiteSpace($Text)) { return $results }

    # Do not call Protect-KuduDiagnosticText before splitting. That routine
    # intentionally flattens CR/LF and was the reason old and current startup
    # failures became one synthetic line in v1.1.13.
    $normalized = $Text.Replace("`r`n","`n").Replace("`r","`n")
    $physicalLines = @($normalized -split "`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($physicalLines.Count -gt $MaximumLines) { $physicalLines = @($physicalLines | Select-Object -Last $MaximumLines) }
    $index = 0
    foreach ($rawLine in $physicalLines) {
        $index++
        $safeLine = Protect-KuduDiagnosticText -Text $rawLine -MaximumLength 8000
        $timestampUtc = [DateTime]::MinValue
        $hasTimestamp = $false
        $match = [regex]::Match($safeLine, '(?<!\d)(?<timestamp>20\d{2}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?Z)')
        if ($match.Success) {
            $parsed = [DateTime]::MinValue
            if ([DateTime]::TryParse($match.Groups['timestamp'].Value, [Globalization.CultureInfo]::InvariantCulture,
                    [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$parsed)) {
                $timestampUtc = $parsed.ToUniversalTime()
                $hasTimestamp = $true
            }
        }
        $results += [pscustomobject][ordered]@{
            Source=$Source
            Sequence=$index
            Text=$safeLine
            HasTimestamp=$hasTimestamp
            TimestampUtc=if ($hasTimestamp) { $timestampUtc.ToString('o') } else { '' }
        }
    }
    return $results
}

function Select-CorrelatedRuntimeLogLines {
    param([object[]]$Lines, [DateTime]$NotBeforeUtc = [DateTime]::MinValue)
    if ($NotBeforeUtc -eq [DateTime]::MinValue) { return @($Lines) }
    $cutoff = $NotBeforeUtc.ToUniversalTime().AddSeconds(-5)
    $selected = @()
    $sourceFresh = @{}
    foreach ($line in @($Lines)) {
        $source = [string](Get-ObjectPropertyValue $line 'Source' 'Runtime')
        $hasTimestamp = ConvertTo-KuduBoolean (Get-ObjectPropertyValue $line 'HasTimestamp' $false)
        if ($hasTimestamp) {
            $stamp = ConvertTo-KuduUtcDateTime (Get-ObjectPropertyValue $line 'TimestampUtc' '')
            $sourceFresh[$source] = ($null -ne $stamp -and $stamp -ge $cutoff)
        }
        # Timestamp-free stack continuations are accepted only after a fresh
        # timestamp in the same physical source file.
        if ($hasTimestamp -and $sourceFresh[$source]) { $selected += $line }
        elseif (-not $hasTimestamp -and $sourceFresh.ContainsKey($source) -and $sourceFresh[$source]) { $selected += $line }
    }
    return @($selected)
}

function Get-FirstCorrelatedStartupException {
    param([object[]]$Lines)
    $ordered = @($Lines | Sort-Object `
        @{ Expression={ $stamp = ConvertTo-KuduUtcDateTime (Get-ObjectPropertyValue $_ 'TimestampUtc' ''); if ($null -eq $stamp) { [DateTime]::MaxValue } else { $stamp } } }, `
        @{ Expression={ [string](Get-ObjectPropertyValue $_ 'Source' '') } }, `
        @{ Expression={ [int](Get-ObjectPropertyValue $_ 'Sequence' 0) } })
    $explicitPattern = '(?i)(\[DNGRMS-STARTUP-EXCEPTION\]|Unhandled exception|Microsoft\.Data\.Sqlite\.SqliteException|System\.[A-Za-z0-9_.]+Exception\s*:|SQLite Error \d+|DllNotFoundException|TypeInitializationException|couldn.?t find a valid ICU|hostfxr.*not found|framework.*not found)'
    $anchorLine = $ordered | Where-Object { [string](Get-ObjectPropertyValue $_ 'Text' '') -match $explicitPattern } | Select-Object -First 1
    if ($null -eq $anchorLine) {
        $anchorLine = $ordered | Where-Object { [string](Get-ObjectPropertyValue $_ 'Text' '') -match '(?i)(aborted \(core dumped\)|exit code 134|failed to start site)' } | Select-Object -First 1
    }
    if ($null -eq $anchorLine) {
        return [pscustomobject][ordered]@{ Found=$false; Source=''; TimestampUtc=''; Text=''; Lines=@() }
    }
    $source = [string](Get-ObjectPropertyValue $anchorLine 'Source' '')
    $sequence = [int](Get-ObjectPropertyValue $anchorLine 'Sequence' 0)
    $block = @($Lines | Where-Object {
        [string](Get-ObjectPropertyValue $_ 'Source' '') -eq $source -and
        [int](Get-ObjectPropertyValue $_ 'Sequence' 0) -ge $sequence -and
        [int](Get-ObjectPropertyValue $_ 'Sequence' 0) -le ($sequence + 40)
    } | Sort-Object Sequence)
    return [pscustomobject][ordered]@{
        Found=$true
        Source=$source
        TimestampUtc=[string](Get-ObjectPropertyValue $anchorLine 'TimestampUtc' '')
        Text=(@($block | ForEach-Object { [string](Get-ObjectPropertyValue $_ 'Text' '') }) -join "`n")
        Lines=$block
    }
}

function Get-KuduRuntimeLogFile {
    param(
        [Parameter(Mandatory)][string]$UriText,
        [Parameter(Mandatory)][string]$BearerToken,
        [string]$Source = 'KuduLogFile',
        [DateTime]$NotBeforeUtc = [DateTime]::MinValue
    )
    try {
        $uri = Resolve-KuduDiagnosticUri -UriText $UriText
        $response = Invoke-KuduRequest -Method GET -Uri $uri -BearerToken $BearerToken -TimeoutSeconds 60
        $lines = @(ConvertTo-RuntimeLogLines -Text ([string]$response.Body) -Source $Source -MaximumLines 5000)
        return [pscustomobject][ordered]@{
            Source=$Source
            Http=(ConvertTo-HttpEvidenceSummary $response)
            Lines=$lines
            CorrelatedLines=@(Select-CorrelatedRuntimeLogLines -Lines $lines -NotBeforeUtc $NotBeforeUtc)
            Error=''
        }
    }
    catch {
        return [pscustomobject][ordered]@{ Source=$Source; Http=$null; Lines=@(); CorrelatedLines=@(); Error=(Protect-KuduDiagnosticText -Text $_.Exception.Message -MaximumLength 1200) }
    }
}

function Get-KuduContainerLogSnapshot {
    param(
        [Parameter(Mandatory)][string]$BearerToken,
        [DateTime]$NotBeforeUtc = [DateTime]::MinValue
    )
    $dockerUri = "$(Get-KuduBaseUrl)/api/logs/docker"
    $dockerResponse = Invoke-KuduRequest -Method GET -Uri $dockerUri -BearerToken $BearerToken -TimeoutSeconds 60
    $parsedDocker = ConvertFrom-KuduResponseJson -Response $dockerResponse
    $descriptors = @()
    if ($null -ne $parsedDocker) {
        $entryProperty = Get-ObjectPropertyValue $parsedDocker 'entries' $null
        if ($null -ne $entryProperty) { $descriptors = @($entryProperty) }
        else { $descriptors = @($parsedDocker) }
    }
    $files = @()
    $lines = @()
    $descriptorIndex = 0
    foreach ($descriptor in $descriptors) {
        $descriptorIndex++
        $message = [string](Get-ObjectPropertyValue $descriptor 'message' '')
        if (-not [string]::IsNullOrWhiteSpace($message)) {
            $lines += @(ConvertTo-RuntimeLogLines -Text $message -Source "DockerApi[$descriptorIndex]" -MaximumLines 400)
        }
        $href = [string](Get-ObjectPropertyValue $descriptor 'href' '')
        if ([string]::IsNullOrWhiteSpace($href)) { $href = [string](Get-ObjectPropertyValue $descriptor 'url' '') }
        $path = [string](Get-ObjectPropertyValue $descriptor 'path' '')
        if (-not [string]::IsNullOrWhiteSpace($href)) {
            $sourceName = if (-not [string]::IsNullOrWhiteSpace($path)) { "Docker:$path" } else { "DockerLog[$descriptorIndex]" }
            $file = Get-KuduRuntimeLogFile -UriText $href -BearerToken $BearerToken -Source $sourceName -NotBeforeUtc $NotBeforeUtc
            $files += $file
            $lines += @($file.Lines)
        }
    }

    $vfsResponse = Invoke-KuduRequest -Method GET -Uri "$(Get-KuduBaseUrl)/api/vfs/LogFiles/" -BearerToken $BearerToken -TimeoutSeconds 60
    $parsedVfs = ConvertFrom-KuduResponseJson -Response $vfsResponse
    $candidateCount = 0
    if ($null -ne $parsedVfs) {
        foreach ($item in @($parsedVfs)) {
            $name = [string](Get-ObjectPropertyValue $item 'name' '')
            $href = [string](Get-ObjectPropertyValue $item 'href' '')
            $mime = [string](Get-ObjectPropertyValue $item 'mime' '')
            if ($candidateCount -ge 24) { break }
            if ([string]::IsNullOrWhiteSpace($href) -or $mime -eq 'inode/directory') { continue }
            if ($name -notmatch '(?i)(docker|container|default|stdout|stderr|startup|eventlog|\.log$|\.txt$)') { continue }
            $candidateCount++
            $file = Get-KuduRuntimeLogFile -UriText $href -BearerToken $BearerToken -Source "LogFiles:$name" -NotBeforeUtc $NotBeforeUtc
            $files += $file
            $lines += @($file.Lines)
        }
    }
    if ($lines.Count -gt 12000) { $lines = @($lines | Select-Object -Last 12000) }
    $correlated = @(Select-CorrelatedRuntimeLogLines -Lines $lines -NotBeforeUtc $NotBeforeUtc)
    $firstException = Get-FirstCorrelatedStartupException -Lines $correlated
    return [pscustomobject][ordered]@{
        CapturedUtc=[DateTime]::UtcNow.ToString('o')
        NotBeforeUtc=if ($NotBeforeUtc -eq [DateTime]::MinValue) { '' } else { $NotBeforeUtc.ToUniversalTime().ToString('o') }
        DockerLogApiHttp=(ConvertTo-HttpEvidenceSummary $dockerResponse)
        LogFilesVfsHttp=(ConvertTo-HttpEvidenceSummary $vfsResponse)
        DescriptorCount=$descriptors.Count
        Files=$files
        Lines=$lines
        CorrelatedLines=$correlated
        FirstCorrelatedException=$firstException
        RetrievedLogs=$lines.Count
        CorrelatedLogLines=$correlated.Count
    }
}

function Invoke-KuduDotNetStartupProbe {
    param([Parameter(Mandatory)][string]$BearerToken)
    $nonce = [Guid]::NewGuid().ToString('N').Substring(0,10)
    $scriptName = "dngrms-menu24-direct-startup-$nonce.sh"
    $scriptPath = "/home/$scriptName"
    $scriptVfsUri = "$(Get-KuduBaseUrl)/api/vfs/$scriptName"
    $logName = "dngrms-menu24-direct-startup-$nonce.log"
    $logPath = "/home/LogFiles/$logName"
    $logVfsUri = "$(Get-KuduBaseUrl)/api/vfs/LogFiles/$logName"
    $startupInvocation = if ($script:ActiveAzureDeploymentMode -eq 'SelfContainedLinuxX64') {
        '/bin/sh /home/site/wwwroot/dngrms-start-selfcontained.sh'
    }
    else {
        'dotnet DngrmsDemo.Web.dll'
    }
    $scriptText = @(
        '#!/bin/sh'
        'set +e'
        'cd /home/site/wwwroot || exit 90'
        'export ASPNETCORE_URLS=http://127.0.0.1:5099'
        'export ASPNETCORE_ENVIRONMENT=Production'
        "rm -f $logPath"
        "timeout 25s $startupInvocation >$logPath 2>&1"
        'probe_code=$?'
        "cat $logPath"
        'echo DNGRMS_DIRECT_EXIT_CODE=$probe_code'
        'exit 0'
    ) -join "`n"
    $scriptText += "`n"
    $upload = $null
    $execution = $null
    $logRead = $null
    try {
        $upload = Invoke-KuduRequest -Method PUT -Uri $scriptVfsUri -BearerToken $BearerToken -Headers @{'If-Match'='*'} `
            -ContentType 'application/octet-stream' -BodyText $scriptText -TimeoutSeconds 120
        if ($upload.StatusCode -notin @(200,201,204)) {
            throw "Direct startup probe upload failed with HTTP $($upload.StatusCode)."
        }
        $execution = Invoke-KuduSimpleCommand -Command "/bin/sh $scriptPath" -WorkingDirectory '/home' -BearerToken $BearerToken -TimeoutSeconds 90
        $logRead = Invoke-KuduRequest -Method GET -Uri $logVfsUri -BearerToken $BearerToken -TimeoutSeconds 60
    }
    finally {
        try { $null = Invoke-KuduRequest -Method DELETE -Uri $scriptVfsUri -BearerToken $BearerToken -Headers @{'If-Match'='*'} -TimeoutSeconds 60 } catch { }
    }
    $combined = ''
    if ($null -ne $execution) { $combined = ([string]$execution.Output) + "`n" + ([string]$execution.Error) }
    if ($null -ne $logRead -and -not [string]::IsNullOrWhiteSpace([string]$logRead.Body)) { $combined += "`n" + [string]$logRead.Body }
    $safeText = Protect-KuduDiagnosticText -Text $combined -MaximumLength 40000
    $directExitCode = -1
    $match = [regex]::Match($safeText, 'DNGRMS_DIRECT_EXIT_CODE=(\d+)')
    if ($match.Success) { [void][int]::TryParse($match.Groups[1].Value, [ref]$directExitCode) }
    $firstException = ''
    foreach ($line in @($safeText -split "`r?`n")) {
        if ($line -match '(?i)(unhandled exception|couldn.?t find a valid ICU|system\.[a-z].*exception|failed to load|hostfxr|framework.*not found|permission denied|unable to open database|aborted|core dumped)') {
            $firstException = Protect-KuduDiagnosticText -Text $line -MaximumLength 4000
            break
        }
    }
    return [pscustomobject][ordered]@{
        CapturedUtc=[DateTime]::UtcNow.ToString('o')
        ScriptSha256=(Get-TextSha256 -Text $scriptText)
        UploadHttp=if ($null -ne $upload) { ConvertTo-HttpEvidenceSummary $upload } else { $null }
        CommandHttp=if ($null -ne $execution) { $execution.Http } else { $null }
        CommandExitCode=if ($null -ne $execution) { $execution.ExitCode } else { -1 }
        DirectProcessExitCode=$directExitCode
        Output=$safeText
        FirstException=$firstException
        PackageDeploymentMode=$script:ActiveAzureDeploymentMode
        StartupInvocation=$startupInvocation
        LogPath=$logPath
        LogHttp=if ($null -ne $logRead) { ConvertTo-HttpEvidenceSummary $logRead } else { $null }
    }
}

function Get-RuntimeStartupFailureClassification {
    param($ContainerSnapshot, $DirectProbe)
    $parts = @()
    $correlated = @((Get-ObjectPropertyValue $ContainerSnapshot 'CorrelatedLines' @()))
    foreach ($entry in $correlated) { $parts += [string](Get-ObjectPropertyValue $entry 'Text' '') }
    $first = Get-ObjectPropertyValue $ContainerSnapshot 'FirstCorrelatedException' $null
    if ($null -ne $first) { $parts += [string](Get-ObjectPropertyValue $first 'Text' '') }
    if ($null -ne $DirectProbe) {
        $parts += [string](Get-ObjectPropertyValue $DirectProbe 'FirstException' '')
        $parts += [string](Get-ObjectPropertyValue $DirectProbe 'Output' '')
    }
    $text = Protect-KuduDiagnosticText -Text ($parts -join "`n") -MaximumLength 60000
    $category = 'RuntimeStartupFailureUnclassified'
    $repairable = $false
    $rootCauseFound = -not [string]::IsNullOrWhiteSpace([string](Get-ObjectPropertyValue $first 'Text' ''))
    $action = 'Fail fast with the current-startup exception; do not recycle without a matched repair rule.'

    if ($text -match '(?is)(SQLite Error (11|26)|database disk image is malformed|file is not a database|SQLITE_(CORRUPT|NOTADB))') {
        $category = 'SqliteInvalidOrCorruptDatabase'
        $repairable = $true
        $action = 'Stop the Web App, quarantine (never delete) the invalid SQLite file and sidecars, then restart so the retained one-time seed values can create a new database.'
    }
    elseif ($text -match '(?is)(SQLite Error 1:.*(no such table|no such column)|database schema.*incompatible)') {
        $category = 'SqliteSchemaIncompatible'
        $repairable = $true
        $action = 'Stop the Web App, quarantine the incompatible demo database, then rebuild it from the current model and retained one-time seed settings.'
    }
    elseif ($text -match '(?is)(SQLite Error (8|14)|SQLite[^\r\n]*(readonly|permission denied|unable to open)|unable to open database file|attempt to write a readonly database|access to the path[^\r\n]*denied)') {
        $category = 'SqliteDataPathAccessFailure'
        $repairable = $true
        $action = 'Revalidate and normalize the existing /home/data target without deleting it, then restart once.'
    }
    elseif ($text -match '(?is)(SQLite Error (5|6|10)|database is locked|database table is locked|SQLITE_(BUSY|LOCKED|IOERR))') {
        $category = 'SqliteTransientLockOrIoFailure'
        $repairable = $true
        $action = 'Perform one stop/start cycle after the application-level bounded retry was exhausted; preserve the database and sidecars.'
    }
    elseif ($text -match '(?is)(GLIBC_2\.33.*libe_sqlite3|libe_sqlite3.*GLIBC_2\.33|DllNotFoundException.*e_sqlite3|SQLitePCLRaw[^\r\n]*(provider|native|load))') {
        $category = 'LegacyBundledSqliteAbiMismatch'
        $repairable = $false
        $action = 'Fail fast. v1.1.16 packages must use the platform sqlite3 provider and must not contain libe_sqlite3.so. Rebuild is required before submission.'
    }
    elseif ($text -match '(?is)(couldn.?t find a valid ICU|no valid ICU package|libicu[^\r\n]*(missing|not found)|globalization[^\r\n]*invariant)') {
        $category = 'MissingIcuRuntimeDependency'
        $repairable = $true
        $action = 'Set DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1 only for this confirmed current-startup ICU failure, then restart once.'
    }
    elseif ($script:ActiveAzureDeploymentMode -eq 'SelfContainedLinuxX64' -and $text -match '(?is)(dotnet\s+DngrmsDemo\.Web\.dll|App:\s*/home/site/wwwroot/DngrmsDemo\.Web\.dll)') {
        $category = 'StaleFrameworkDependentStartupContract'
        $repairable = $true
        $action = 'Reapply the selected self-contained bootstrap startup command and restart once.'
    }
    elseif ($text -match '(?is)(Microsoft\.NETCore\.App[^\r\n]*(not found|missing)|framework[^\r\n]*not found|hostfxr[^\r\n]*(not found|failed)|libhostfxr)') {
        $category = 'DotNetSharedRuntimeMissing'
        $repairable = $false
        $action = 'Fail fast. This classification is based only on current-cutover logs; rebuild/select SelfContainedLinuxX64 if confirmed.'
    }
    elseif ($text -match '(?is)(bad image format|exec format error|wrong ELF class|runtime target[^\r\n]*win-|win-x64[^\r\n]*(linux|incompatible))') {
        $category = 'LinuxRuntimeIdentifierMismatch'
        $repairable = $false
        $action = 'Fail fast and rebuild the explicit linux-x64 package.'
    }
    elseif ($text -match '(?is)(Unhandled exception|System\.(Argument|InvalidOperation|Configuration|TypeInitialization|FileNotFound|FileLoad)[A-Za-z]*Exception)') {
        $category = 'ApplicationStartupException'
        $repairable = $false
        $action = 'Fail fast with the captured current-startup exception; seed settings and /home/data remain unchanged.'
    }
    return [pscustomobject][ordered]@{
        Category=$category
        RootCauseFound=$rootCauseFound
        Repairable=$repairable
        RepairAction=$action
        FirstException=if ($null -ne $first) { [string](Get-ObjectPropertyValue $first 'Text' '') } elseif ($null -ne $DirectProbe) { [string](Get-ObjectPropertyValue $DirectProbe 'FirstException' '') } else { '' }
        EvidenceText=$text
        CorrelatedLineCount=$correlated.Count
        LogNotBeforeUtc=[string](Get-ObjectPropertyValue $ContainerSnapshot 'NotBeforeUtc' '')
    }
}

function Write-RuntimeStartupDiagnosticBundle {
    param(
        [Parameter(Mandatory)][string]$BearerToken,
        [Parameter(Mandatory)][string]$Trigger,
        [int]$RepairAttempt = 0,
        [DateTime]$NotBeforeUtc = [DateTime]::MinValue
    )
    if ($NotBeforeUtc -eq [DateTime]::MinValue) { $NotBeforeUtc = $script:Menu24RuntimeLogNotBeforeUtc }
    $container = Get-KuduContainerLogSnapshot -BearerToken $BearerToken -NotBeforeUtc $NotBeforeUtc
    $direct = $null
    $directError = ''
    # A Kudu-side process is not the main worker and can introduce false runtime
    # evidence. Current main-worker container logs are authoritative after the
    # deployment/restart cutover for both package modes.
    $directError = 'Skipped: current main-worker logs after the recorded cutover are authoritative; SCM/Kudu is a separate container.'
    $classification = Get-RuntimeStartupFailureClassification -ContainerSnapshot $container -DirectProbe $direct
    $data = [pscustomobject][ordered]@{
        LauncherVersion=$script:LauncherVersion
        CapturedUtc=[DateTime]::UtcNow.ToString('o')
        LogNotBeforeUtc=if ($NotBeforeUtc -eq [DateTime]::MinValue) { '' } else { $NotBeforeUtc.ToUniversalTime().ToString('o') }
        Trigger=$Trigger
        RepairAttempt=$RepairAttempt
        Classification=$classification
        ContainerLogs=$container
        KuduSideStartupProbe=$direct
        KuduSideStartupProbeError=$directError
        SecurityNote='****** passwords, bearer tokens, API keys, client secrets, and JWT-like values are redacted or excluded.'
    }
    $path = Write-EvidenceJson -Name 'menu24-runtime-startup-diagnostics' -Data $data
    $data | Add-Member -NotePropertyName EvidencePath -NotePropertyValue $path
    Write-Host ''
    Write-Host '[RUNTIME STARTUP DIAGNOSTICS - CURRENT CUTOVER ONLY]' -ForegroundColor Cyan
    Write-Host ("  Trigger={0}" -f $Trigger)
    Write-Host ("  LogNotBeforeUtc={0}" -f $data.LogNotBeforeUtc)
    Write-Host ("  Category={0}; RootCauseFound={1}; Repairable={2}" -f $classification.Category,$classification.RootCauseFound,$classification.Repairable)
    Write-Host ("  RepairAction={0}" -f $classification.RepairAction)
    Write-Host ("  RetrievedLines={0}; CorrelatedLines={1}; KuduDockerLogApiHTTP={2}; Evidence={3}" -f $container.RetrievedLogs,$container.CorrelatedLogLines,(Get-KuduHttpStatusLabel $container.DockerLogApiHttp),$path)
    Write-Host ''
    Write-Host '[LATEST CORRELATED STARTUP EXCEPTION]' -ForegroundColor Yellow
    $first = Get-ObjectPropertyValue $container 'FirstCorrelatedException' $null
    if ($null -ne $first -and (ConvertTo-KuduBoolean (Get-ObjectPropertyValue $first 'Found' $false))) {
        foreach ($line in @((Get-ObjectPropertyValue $first 'Lines' @()))) { Write-Host ("{0}: {1}" -f $line.Source,$line.Text) }
    }
    else {
        Write-Host 'No explicit exception line was found after the current cutover; failing without using older log text.'
        $fallback = @($container.CorrelatedLines | Where-Object { $_.Text -match '(?i)(fatal|error|aborted|core dumped|exit code|containerstartupfailure|failed to start|permission denied|unable to open)' } | Select-Object -First 20)
        foreach ($entry in $fallback) { Write-Host ("{0}: {1}" -f $entry.Source,$entry.Text) }
    }
    return $data
}

function Wait-RuntimeHealthProbe {
    param([int]$ProbeCount = 3, [int]$IntervalSeconds = 8)
    $history = @()
    $last = $null
    for ($index = 1; $index -le $ProbeCount; $index++) {
        $last = Get-HealthContractProbe
        $history += $last
        Write-Host ("Runtime health poll {0}: HTTP={1}; Status={2}; Database={3}; HealthyConnected={4}" -f $index,(Get-KuduHttpStatusLabel $last.Http),$last.Status,$last.Database,$last.HealthyConnected)
        if ($last.HealthyConnected) { return [pscustomobject][ordered]@{ Succeeded=$true; Last=$last; History=$history } }
        if ($index -lt $ProbeCount) { Start-Sleep -Seconds $IntervalSeconds }
    }
    return [pscustomobject][ordered]@{ Succeeded=$false; Last=$last; History=$history }
}

function Invoke-RuntimeStartupRepair {
    param(
        [Parameter(Mandatory)]$Classification,
        [Parameter(Mandatory)][string]$BearerToken,
        [Parameter(Mandatory)][ValidateRange(1,1)][int]$Attempt
    )
    $category = [string](Get-ObjectPropertyValue $Classification 'Category' 'RuntimeStartupFailureUnclassified')
    $repairable = ConvertTo-KuduBoolean (Get-ObjectPropertyValue $Classification 'Repairable' $false)
    $action = [string](Get-ObjectPropertyValue $Classification 'RepairAction' '')
    $started = [DateTime]::UtcNow
    $succeeded = $false
    $errorText = ''
    $operation = ''
    $detail = $null
    if (-not $repairable) {
        return [pscustomobject][ordered]@{ Attempt=$Attempt; Category=$category; Invoked=$false; Succeeded=$false; Operation='FailFastNotRepairable'; Action=$action; StartedUtc=$started.ToString('o'); CompletedUtc=[DateTime]::UtcNow.ToString('o'); Error=''; Detail=$null }
    }
    try {
        if ($category -eq 'MissingIcuRuntimeDependency') {
            $operation = 'Confirmed current-startup ICU compatibility setting plus one restart'
            Set-AzWebAppSettingsSafe @{ 'DOTNET_SYSTEM_GLOBALIZATION_INVARIANT'='1' }
            $script:Menu24RuntimeLogNotBeforeUtc = [DateTime]::UtcNow
            Restart-AzWebApp -ResourceGroupName $script:State.ResourceGroupName -Name $script:State.WebAppName | Out-Null
        }
        elseif ($category -eq 'SqliteDataPathAccessFailure') {
            $operation = 'Non-destructive SQLite target normalization plus one restart'
            $detail = Repair-KuduSqliteTarget -BearerToken $BearerToken
            $script:Menu24RuntimeLogNotBeforeUtc = [DateTime]::UtcNow
            Restart-AzWebApp -ResourceGroupName $script:State.ResourceGroupName -Name $script:State.WebAppName | Out-Null
        }
        elseif ($category -in @('SqliteInvalidOrCorruptDatabase','SqliteSchemaIncompatible')) {
            $operation = 'Quarantine invalid/incompatible demo database after failed startup, then start once'
            # Do not call Stop-AzWebApp before the Kudu operation: stopping the
            # site can also disable SCM. After three failed startup probes the
            # main process is already absent; Kudu performs an atomic rename.
            $detail = Repair-KuduSqliteTarget -BearerToken $BearerToken -QuarantineExistingDatabase
            $script:Menu24RuntimeLogNotBeforeUtc = [DateTime]::UtcNow
            Restart-AzWebApp -ResourceGroupName $script:State.ResourceGroupName -Name $script:State.WebAppName | Out-Null
        }
        elseif ($category -eq 'SqliteTransientLockOrIoFailure') {
            $operation = 'One bounded stop/start preserving SQLite and sidecars'
            Stop-AzWebApp -ResourceGroupName $script:State.ResourceGroupName -Name $script:State.WebAppName | Out-Null
            Start-Sleep -Seconds 6
            $script:Menu24RuntimeLogNotBeforeUtc = [DateTime]::UtcNow
            Start-AzWebApp -ResourceGroupName $script:State.ResourceGroupName -Name $script:State.WebAppName | Out-Null
        }
        elseif ($category -eq 'StaleFrameworkDependentStartupContract') {
            $operation = 'Reapply selected startup contract plus one restart'
            $detail = Set-LinuxAppServiceStartupContract -PackageDeploymentMode $script:ActiveAzureDeploymentMode -LinuxFxVersion $script:ActiveAzureLinuxFxVersion
            $script:Menu24RuntimeLogNotBeforeUtc = [DateTime]::UtcNow
            Restart-AzWebApp -ResourceGroupName $script:State.ResourceGroupName -Name $script:State.WebAppName | Out-Null
        }
        else { throw "No cause-specific automatic repair is defined for $category." }
        $succeeded = $true
    }
    catch { $errorText = Protect-KuduDiagnosticText -Text $_.Exception.Message -MaximumLength 3000 }
    return [pscustomobject][ordered]@{
        Attempt=$Attempt; Category=$category; Invoked=$true; Succeeded=$succeeded; Operation=$operation; Action=$action;
        StartedUtc=$started.ToString('o'); CompletedUtc=[DateTime]::UtcNow.ToString('o'); Error=$errorText; Detail=$detail
    }
}

function Invoke-BoundedRuntimeRecovery {
    param(
        [Parameter(Mandatory)][string]$BearerToken,
        [string]$Trigger = 'Three current-cutover health probes failed'
    )
    $diagnostic = Write-RuntimeStartupDiagnosticBundle -BearerToken $BearerToken -Trigger $Trigger -RepairAttempt 0 -NotBeforeUtc $script:Menu24RuntimeLogNotBeforeUtc
    $classification = $diagnostic.Classification
    if (-not (ConvertTo-KuduBoolean (Get-ObjectPropertyValue $classification 'Repairable' $false))) {
        return [pscustomobject][ordered]@{ Outcome='Failed'; Determination='CurrentStartupCauseFailFast'; Classification=$classification; Diagnostics=@($diagnostic); Repairs=@(); HealthHistory=@(); Attempts=0 }
    }
    $repair = Invoke-RuntimeStartupRepair -Classification $classification -BearerToken $BearerToken -Attempt 1
    if (-not $repair.Succeeded) {
        return [pscustomobject][ordered]@{ Outcome='Failed'; Determination='CauseSpecificRepairFailed'; Classification=$classification; Diagnostics=@($diagnostic); Repairs=@($repair); HealthHistory=@(); Attempts=1 }
    }
    Start-Sleep -Seconds 10
    $health = Wait-RuntimeHealthProbe -ProbeCount 3 -IntervalSeconds 8
    if ($health.Succeeded) {
        return [pscustomobject][ordered]@{ Outcome='Succeeded'; Determination='HealthyConnectedAfterSingleCauseSpecificRepair'; Classification=$classification; Diagnostics=@($diagnostic); Repairs=@($repair); HealthHistory=$health.History; Attempts=1 }
    }
    $after = Write-RuntimeStartupDiagnosticBundle -BearerToken $BearerToken -Trigger 'Single cause-specific repair followed by three failed health probes' -RepairAttempt 1 -NotBeforeUtc $script:Menu24RuntimeLogNotBeforeUtc
    return [pscustomobject][ordered]@{ Outcome='Failed'; Determination='HealthFailedAfterSingleCauseSpecificRepair'; Classification=$after.Classification; Diagnostics=@($diagnostic,$after); Repairs=@($repair); HealthHistory=$health.History; Attempts=1 }
}

function Get-FileSha256 {
    param([Parameter(Mandatory)][string]$Path)
    $algorithm = [Security.Cryptography.SHA256]::Create()
    $stream = [IO.File]::OpenRead($Path)
    try { return ([BitConverter]::ToString($algorithm.ComputeHash($stream))).Replace('-','').ToLowerInvariant() }
    finally { $stream.Dispose(); $algorithm.Dispose() }
}

function Get-ZipEntrySha256 {
    param([Parameter(Mandatory)]$Entry)
    $algorithm = [Security.Cryptography.SHA256]::Create()
    $stream = $Entry.Open()
    try { return ([BitConverter]::ToString($algorithm.ComputeHash($stream))).Replace('-','').ToLowerInvariant() }
    finally { $stream.Dispose(); $algorithm.Dispose() }
}

function Test-Elf64X64Header {
    param([Parameter(Mandatory)][byte[]]$Bytes, [Parameter(Mandatory)][string]$Name)
    if ($Bytes.Length -lt 20) { throw "$Name is too small to be a valid ELF binary." }
    $magicOk = ($Bytes[0] -eq 0x7f -and $Bytes[1] -eq 0x45 -and $Bytes[2] -eq 0x4c -and $Bytes[3] -eq 0x46)
    $class64 = ($Bytes[4] -eq 2)
    $littleEndian = ($Bytes[5] -eq 1)
    $machineX64 = ($Bytes[18] -eq 0x3e -and $Bytes[19] -eq 0x00)
    if (-not ($magicOk -and $class64 -and $littleEndian -and $machineX64)) {
        throw "$Name is not a little-endian x86-64 ELF library. Magic=$magicOk; ELF64=$class64; LittleEndian=$littleEndian; MachineX64=$machineX64."
    }
    return [pscustomobject][ordered]@{ Name=$Name; ElfMagic=$magicOk; ElfClass='ELF64'; Endianness='Little'; Machine='x86-64'; Valid=$true }
}

function Test-Elf64X64File {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Required native library is missing: $Path" }
    $stream = [IO.File]::OpenRead($Path)
    try {
        $bytes = New-Object byte[] 64
        $read = $stream.Read($bytes,0,$bytes.Length)
        if ($read -lt 20) { throw "Native library is too small: $Path" }
        return Test-Elf64X64Header -Bytes $bytes -Name $Path
    }
    finally { $stream.Dispose() }
}

function Get-ZipEntryHeaderBytes {
    param([Parameter(Mandatory)]$Entry, [int]$Count = 64)
    $stream = $Entry.Open()
    try {
        $bytes = New-Object byte[] $Count
        $read = $stream.Read($bytes,0,$bytes.Length)
        if ($read -eq $bytes.Length) { return $bytes }
        $actual = New-Object byte[] $read
        [Array]::Copy($bytes,$actual,$read)
        return $actual
    }
    finally { $stream.Dispose() }
}

function Assert-IdentityModelDepsContract {
    param(
        [Parameter(Mandatory)][string]$DepsText,
        [string]$Source = 'deps.json'
    )
    $required = @(
        'Microsoft.IdentityModel.Abstractions','Microsoft.IdentityModel.JsonWebTokens','Microsoft.IdentityModel.Logging',
        'Microsoft.IdentityModel.Protocols','Microsoft.IdentityModel.Protocols.OpenIdConnect','Microsoft.IdentityModel.Tokens',
        'Microsoft.IdentityModel.Tokens.Saml','Microsoft.IdentityModel.Xml','System.IdentityModel.Tokens.Jwt'
    )
    $versions = [ordered]@{}
    foreach ($name in $required) {
        $match = [regex]::Match($DepsText,'(?m)"' + [regex]::Escape($name) + '/(?<version>[0-9]+\.[0-9]+\.[0-9]+)"')
        if (-not $match.Success) { throw "IdentityModel contract in $Source is missing $name." }
        $versions[$name] = $match.Groups['version'].Value
        if ($versions[$name] -ne '8.22.0') { throw "IdentityModel contract in $Source is not aligned. $name=$($versions[$name]); Expected=8.22.0." }
    }
    $forbidden = [regex]::Matches($DepsText,'(?m)"(?<name>(?:Microsoft|System)\.IdentityModel[^"/]*)/(?<version>7\.[0-9]+\.[0-9]+)"')
    if ($forbidden.Count -gt 0) {
        $detail = @($forbidden | ForEach-Object { "$($_.Groups['name'].Value)/$($_.Groups['version'].Value)" }) -join ', '
        throw "IdentityModel contract in $Source contains forbidden 7.x assets: $detail"
    }
    return [pscustomobject][ordered]@{ Source=$Source; Aligned=$true; ExpectedVersion='8.22.0'; Versions=[pscustomobject]$versions }
}

function Assert-SqliteLinuxX64PublishContract {
    param([Parameter(Mandatory)][string]$PublishDirectory)
    $requiredFiles = @(
        'Microsoft.Data.Sqlite.dll','Microsoft.EntityFrameworkCore.Sqlite.dll','SQLitePCLRaw.core.dll',
        'SQLitePCLRaw.provider.sqlite3.dll','SQLitePCLRaw.provider.winsqlite3.dll','DngrmsDemo.Web.deps.json'
    )
    $files = @()
    foreach ($name in $requiredFiles) {
        $path = Join-Path $PublishDirectory $name
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "System-SQLite publish contract is missing $name in $PublishDirectory." }
        $item = Get-Item -LiteralPath $path
        if ($item.Length -le 0) { throw "System-SQLite publish contract contains an empty file: $name" }
        $files += [pscustomobject][ordered]@{ Name=$name; SizeBytes=$item.Length; Sha256=(Get-FileSha256 -Path $path) }
    }
    $forbiddenNative = Join-Path $PublishDirectory 'libe_sqlite3.so'
    if (Test-Path -LiteralPath $forbiddenNative) { throw 'v1.1.16 rejects libe_sqlite3.so because it can require a newer glibc than the App Service worker image.' }
    $depsText = [IO.File]::ReadAllText((Join-Path $PublishDirectory 'DngrmsDemo.Web.deps.json'))
    $identityModelContract = Assert-IdentityModelDepsContract -DepsText $depsText -Source (Join-Path $PublishDirectory 'DngrmsDemo.Web.deps.json')
    $checks = [ordered]@{
        EfCoreSqliteCore = ($depsText -match 'Microsoft\.EntityFrameworkCore\.Sqlite\.Core/8\.0\.33')
        MicrosoftDataSqliteCore = ($depsText -match 'Microsoft\.Data\.Sqlite\.Core/8\.0\.33')
        LinuxSystemSqliteProvider = ($depsText -match 'SQLitePCLRaw\.provider\.sqlite3/2\.1\.11')
        WindowsProviderRecorded = ($depsText -match 'SQLitePCLRaw\.provider\.winsqlite3/2\.1\.11')
        BundledESqlite3Absent = ($depsText -notmatch 'SQLitePCLRaw\.(bundle_e_sqlite3|provider\.e_sqlite3)')
        NativeESqlite3AssetAbsent = ($depsText -notmatch 'libe_sqlite3\.so')
    }
    foreach ($name in @('EfCoreSqliteCore','MicrosoftDataSqliteCore','LinuxSystemSqliteProvider','BundledESqlite3Absent','NativeESqlite3AssetAbsent')) { if (-not $checks[$name]) { throw "System-SQLite deps.json contract failed: $name." } }
    return [pscustomobject][ordered]@{
        CapturedUtc=[DateTime]::UtcNow.ToString('o'); RuntimeIdentifier='linux-x64'; ProviderMode='SystemSqlite3';
        EfCoreSqliteVersion=$script:EfCoreSqlitePackageVersion; MicrosoftDataSqliteVersion=$script:MicrosoftDataSqlitePackageVersion;
        SQLitePclRawVersion=$script:SQLitePclRawBundleVersion; NativeLibrary='Platform libsqlite3.so.0'; BundledNativeLibraryPresent=$false;
        ManagedFiles=$files; DepsChecks=[pscustomobject]$checks; IdentityModelContract=$identityModelContract
    }
}

function Write-DeploymentPackageIdentityFiles {
    param(
        [Parameter(Mandatory)][string]$SourceDirectory,
        [Parameter(Mandatory)][ValidateSet('FrameworkDependentNet8','SelfContainedLinuxX64')][string]$PackageDeploymentMode,
        [Parameter(Mandatory)][string]$StartupCommand
    )
    $mainPath = Join-Path $SourceDirectory 'DngrmsDemo.Web.dll'
    $runtimeConfigPath = Join-Path $SourceDirectory 'DngrmsDemo.Web.runtimeconfig.json'
    $depsPath = Join-Path $SourceDirectory 'DngrmsDemo.Web.deps.json'
    foreach ($path in @($mainPath,$runtimeConfigPath,$depsPath)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Package identity input is missing: $path" }
    }
    $appHostPath = Join-Path $SourceDirectory 'DngrmsDemo.Web'
    $bootstrapPath = Join-Path $SourceDirectory 'dngrms-start-selfcontained.sh'
    $isSelfContained = ($PackageDeploymentMode -eq 'SelfContainedLinuxX64')
    if ($isSelfContained -and -not (Test-Path -LiteralPath $appHostPath -PathType Leaf)) { throw "Self-contained apphost is missing: $appHostPath" }
    if ($isSelfContained -and -not (Test-Path -LiteralPath $bootstrapPath -PathType Leaf)) { throw "Self-contained bootstrap is missing: $bootstrapPath" }
    $manifest = [ordered]@{
        SchemaVersion='1.2'
        PackageId=[Guid]::NewGuid().ToString('N')
        LauncherVersion=$script:LauncherVersion
        PackageDeploymentMode=$PackageDeploymentMode
        RuntimeIdentifier='linux-x64'
        TargetFramework='net8.0'
        FrameworkDependent=(-not $isSelfContained)
        StartupCommand=$StartupCommand
        MainAssemblySha256=(Get-FileSha256 -Path $mainPath)
        RuntimeConfigSha256=(Get-FileSha256 -Path $runtimeConfigPath)
        DepsSha256=(Get-FileSha256 -Path $depsPath)
        AppHostSha256=if ($isSelfContained) { Get-FileSha256 -Path $appHostPath } else { '' }
        BootstrapSha256=if ($isSelfContained) { Get-FileSha256 -Path $bootstrapPath } else { '' }
        EfCoreSqliteVersion=$script:EfCoreSqlitePackageVersion
        MicrosoftDataSqliteVersion=$script:MicrosoftDataSqlitePackageVersion
        SQLiteProviderMode='SystemSqlite3'
        SQLitePclRawVersion=$script:SQLitePclRawBundleVersion
        SQLiteLinuxProvider='SQLitePCLRaw.provider.sqlite3'
        SQLiteWindowsProvider='SQLitePCLRaw.provider.winsqlite3'
        SQLiteNativeLibrary='Platform libsqlite3.so.0'
        SQLiteNativeLibrarySha256=''
        BundledNativeLibraryPresent=$false
        CreatedUtc=[DateTime]::UtcNow.ToString('o')
        RunFromPackage='1'
        PackageRoot='/home/site/wwwroot'
    }
    $json = $manifest | ConvertTo-Json -Depth 12
    $json = $json.Replace("`r`n","`n").Replace("`r","`n") + "`n"
    $utf8NoBom = New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $false
    [IO.File]::WriteAllText((Join-Path $SourceDirectory 'dngrms-package-manifest.json'), $json, $utf8NoBom)
    $staticRoot = Join-Path $SourceDirectory 'wwwroot'
    if (-not (Test-Path -LiteralPath $staticRoot -PathType Container)) { New-Item -ItemType Directory -Path $staticRoot -Force | Out-Null }
    [IO.File]::WriteAllText((Join-Path $staticRoot 'dngrms-package-identity.json'), $json, $utf8NoBom)
    return [pscustomobject]$manifest
}

function Test-LinuxX64DeploymentPackage {
    param([Parameter(Mandatory)]$Entries, [Parameter(Mandatory)][string]$RuntimeConfigText, [Parameter(Mandatory)][string]$DepsText)
    $rootNames = @($Entries | ForEach-Object { $_.FullName })
    foreach ($name in @('DngrmsDemo.Web.dll','DngrmsDemo.Web.deps.json','DngrmsDemo.Web.runtimeconfig.json','appsettings.json','dngrms-package-manifest.json','wwwroot/dngrms-package-identity.json')) {
        if ($rootNames -cnotcontains $name) { throw "ZIP is missing required root entry: $name" }
    }
    if ($rootNames -ccontains 'libe_sqlite3.so' -or $DepsText -match 'SQLitePCLRaw\.(bundle_e_sqlite3|provider\.e_sqlite3)|libe_sqlite3\.so') {
        throw 'ZIP contains the rejected bundled e_sqlite3 contract. Menu 24 must rebuild it with the v1.1.16 system-SQLite provider graph.'
    }
    $identityModelContract = Assert-IdentityModelDepsContract -DepsText $DepsText -Source 'deployment ZIP DngrmsDemo.Web.deps.json'
    foreach ($name in @('Microsoft.Data.Sqlite.dll','Microsoft.EntityFrameworkCore.Sqlite.dll','SQLitePCLRaw.core.dll','SQLitePCLRaw.provider.sqlite3.dll','SQLitePCLRaw.provider.winsqlite3.dll')) {
        if ($rootNames -cnotcontains $name) { throw "ZIP system-SQLite contract is missing $name." }
    }
    $checks = [ordered]@{
        EfCoreSqliteCore=($DepsText -match 'Microsoft\.EntityFrameworkCore\.Sqlite\.Core/8\.0\.33')
        MicrosoftDataSqliteCore=($DepsText -match 'Microsoft\.Data\.Sqlite\.Core/8\.0\.33')
        LinuxSystemSqliteProvider=($DepsText -match 'SQLitePCLRaw\.provider\.sqlite3/2\.1\.11')
        WindowsSystemSqliteProvider=($DepsText -match 'SQLitePCLRaw\.provider\.winsqlite3/2\.1\.11')
    }
    foreach ($key in @('EfCoreSqliteCore','MicrosoftDataSqliteCore','LinuxSystemSqliteProvider')) { if (-not $checks[$key]) { throw "ZIP system-SQLite deps contract failed: $key." } }
    $runtimeConfig = $RuntimeConfigText | ConvertFrom-Json
    $runtimeOptions = Get-ObjectPropertyValue $runtimeConfig 'runtimeOptions' $null
    $tfm = [string](Get-ObjectPropertyValue $runtimeOptions 'tfm' '')
    if ($tfm -ne 'net8.0') { throw "ZIP target framework is not net8.0: $tfm" }
    $manifestEntry = $Entries | Where-Object { $_.FullName -ceq 'dngrms-package-manifest.json' } | Select-Object -First 1
    $identityEntry = $Entries | Where-Object { $_.FullName -ceq 'wwwroot/dngrms-package-identity.json' } | Select-Object -First 1
    $manifestText = Read-ZipArchiveEntryText -Entry $manifestEntry
    if ($manifestText -ne (Read-ZipArchiveEntryText -Entry $identityEntry)) { throw 'Package manifest and runtime identity marker differ.' }
    $manifest = $manifestText | ConvertFrom-Json
    if ([string](Get-ObjectPropertyValue $manifest 'LauncherVersion' '') -ne $script:LauncherVersion) { throw 'Package manifest launcher version does not match v1.1.21.' }
    if ([string](Get-ObjectPropertyValue $manifest 'SchemaVersion' '') -ne '1.2') { throw 'Package manifest does not contain the v1.1.21 system-SQLite schema.' }
    if ([string](Get-ObjectPropertyValue $manifest 'SQLiteProviderMode' '') -ne 'SystemSqlite3') { throw 'Package manifest does not select SystemSqlite3.' }
    $mode=[string](Get-ObjectPropertyValue $manifest 'PackageDeploymentMode' '')
    $selfContained=($mode -eq 'SelfContainedLinuxX64')
    if ($mode -notin @('FrameworkDependentNet8','SelfContainedLinuxX64')) { throw "Unknown package mode: $mode" }
    if ($selfContained -and ($rootNames -cnotcontains 'DngrmsDemo.Web' -or $rootNames -cnotcontains 'dngrms-start-selfcontained.sh')) { throw 'Self-contained ZIP is missing its Linux apphost or bootstrap.' }
    return [pscustomobject][ordered]@{
        TargetFramework=$tfm; FrameworkDependent=(-not $selfContained); ExplicitLinuxX64=$true; LinuxX64Compatible=$true;
        PackageDeploymentMode=$mode; SelfContainedRuntimeIncluded=$selfContained; RequiresSharedMicrosoftNetCoreApp8=(-not $selfContained);
        LinuxAppHostAtRoot=($rootNames -ccontains 'DngrmsDemo.Web'); BootstrapScriptAtRoot=($rootNames -ccontains 'dngrms-start-selfcontained.sh');
        StartupCommand=[string](Get-ObjectPropertyValue $manifest 'StartupCommand' ''); PackageId=[string](Get-ObjectPropertyValue $manifest 'PackageId' '');
        PackageManifest=$manifest; RuntimeIdentityMarkerAtRoot=$true; IdentityHashesVerified=$true;
        SQLiteNativeLibraryAtRoot=$false; SQLiteNativeLibrarySha256=''; SQLiteNativeElf=$null;
        SQLiteManagedAssets=@('Microsoft.Data.Sqlite.dll','Microsoft.EntityFrameworkCore.Sqlite.dll','SQLitePCLRaw.core.dll','SQLitePCLRaw.provider.sqlite3.dll','SQLitePCLRaw.provider.winsqlite3.dll');
        SQLiteDepsChecks=[pscustomobject]$checks; SQLiteBundleContractVerified=$true; SQLiteProviderMode='SystemSqlite3'; IdentityModelContract=$identityModelContract
    }
}

function Test-DeploymentZipContract {
    param(
        [Parameter(Mandatory)][string]$ZipPath,
        [ValidateSet('Any','FrameworkDependentNet8','SelfContainedLinuxX64')][string]$ExpectedMode = 'Any'
    )
    Write-Step "Validating ZIP package root structure and Linux runtime contract. ExpectedMode=$ExpectedMode"
    if (-not (Test-Path -LiteralPath $ZipPath -PathType Leaf)) { throw "Deployment ZIP does not exist: $ZipPath" }
    Add-Type -AssemblyName System.IO.Compression -ErrorAction SilentlyContinue
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
    $archive = [IO.Compression.ZipFile]::OpenRead($ZipPath)
    try {
        $entries = @($archive.Entries | Where-Object { -not [string]::IsNullOrWhiteSpace($_.Name) })
        $rootNames = @($entries | Where-Object { $_.FullName -notmatch '[/\\]' } | ForEach-Object { $_.FullName })
        $required = @('DngrmsDemo.Web.dll','DngrmsDemo.Web.deps.json','DngrmsDemo.Web.runtimeconfig.json','appsettings.json','dngrms-package-manifest.json')
        $missing = @($required | Where-Object { $rootNames -notcontains $_ })
        if ($missing.Count -gt 0) { throw "ZIP startup contract failed. Missing root files: $($missing -join ', '). The publish files must be at the ZIP root." }
        $top = @($entries | ForEach-Object { ($_.FullName -split '[/\\]')[0] } | Sort-Object -Unique | Select-Object -First 16)
        $runtimeConfigEntry = $entries | Where-Object { $_.FullName -ceq 'DngrmsDemo.Web.runtimeconfig.json' } | Select-Object -First 1
        $depsEntry = $entries | Where-Object { $_.FullName -ceq 'DngrmsDemo.Web.deps.json' } | Select-Object -First 1
        $runtimeConfigText = Read-ZipArchiveEntryText -Entry $runtimeConfigEntry
        $depsText = Read-ZipArchiveEntryText -Entry $depsEntry
        $linuxContract = Test-LinuxX64DeploymentPackage -Entries $entries -RuntimeConfigText $runtimeConfigText -DepsText $depsText
        if ($ExpectedMode -ne 'Any' -and $linuxContract.PackageDeploymentMode -ne $ExpectedMode) {
            throw "ZIP package mode mismatch. Expected=$ExpectedMode; Actual=$($linuxContract.PackageDeploymentMode)."
        }
        return [pscustomobject][ordered]@{
            ZipPath=$ZipPath
            ZipLengthBytes=(Get-Item -LiteralPath $ZipPath).Length
            FileCount=$entries.Count
            MainAssemblyAtRoot=$true
            RequiredRootFiles=$required
            TopLevelEntries=$top
            PackageDeploymentMode=$linuxContract.PackageDeploymentMode
            LinuxX64RuntimeContract=$linuxContract
        }
    }
    finally { $archive.Dispose() }
}

function New-LinuxDeploymentZip {
    param(
        [Parameter(Mandatory)][string]$SourceDirectory,
        [Parameter(Mandatory)][string]$DestinationPath,
        [string[]]$ExecutableRelativePaths = @()
    )
    if (-not (Test-Path -LiteralPath $SourceDirectory -PathType Container)) { throw "Publish directory does not exist: $SourceDirectory" }
    Add-Type -AssemblyName System.IO.Compression -ErrorAction SilentlyContinue
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $DestinationPath) { Remove-Item -LiteralPath $DestinationPath -Force }
    $destinationDirectory = Split-Path -Parent $DestinationPath
    if (-not (Test-Path -LiteralPath $destinationDirectory)) { New-Item -ItemType Directory -Path $destinationDirectory -Force | Out-Null }
    $root = [IO.Path]::GetFullPath($SourceDirectory).TrimEnd([char[]]@([IO.Path]::DirectorySeparatorChar,[IO.Path]::AltDirectorySeparatorChar))
    $fileStream = [IO.File]::Open($DestinationPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    $archive = $null
    try {
        $parameterTypes = [Type[]]@([IO.Stream],[IO.Compression.ZipArchiveMode],[bool])
        $constructor = [IO.Compression.ZipArchive].GetConstructor($parameterTypes)
        if ($null -eq $constructor) { throw 'Required ZipArchive(Stream, ZipArchiveMode, Boolean) constructor is unavailable.' }
        $constructorArguments = [object[]]@($fileStream,[IO.Compression.ZipArchiveMode]::Create,$false)
        $archive = [IO.Compression.ZipArchive]$constructor.Invoke($constructorArguments)
        foreach ($file in @(Get-ChildItem -LiteralPath $root -Recurse -File | Sort-Object FullName)) {
            $relative = $file.FullName.Substring($root.Length).TrimStart([char[]]@([char]92,[char]47)) -replace '\\','/'
            $entry = $archive.CreateEntry($relative, [IO.Compression.CompressionLevel]::Optimal)
            if ($ExecutableRelativePaths -ccontains $relative) { $entry.ExternalAttributes = -2115174400 }
            else { $entry.ExternalAttributes = -2119958528 }
            $input = [IO.File]::OpenRead($file.FullName)
            $output = $entry.Open()
            try { $input.CopyTo($output) }
            finally { $output.Dispose(); $input.Dispose() }
        }
    }
    finally {
        if ($null -ne $archive) { $archive.Dispose() }
        else { $fileStream.Dispose() }
    }
    return $DestinationPath
}

function Sync-GeneratedMenu24SourceContract {
    $projectPath = Join-Path $script:SourceRoot 'DngrmsDemo.Web.csproj'
    $programPath = Join-Path $script:SourceRoot 'Program.cs'
    $seederPath = Join-Path $script:SourceRoot 'Services/DemoSeeder.cs'
    foreach ($path in @($projectPath,$programPath,$seederPath)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Generated source is missing: $path. Run Menu 10 before Menu 24." }
    }
    $utf8NoBom = New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $false
    $changed = @()
    $project = [IO.File]::ReadAllText($projectPath)
    $canonicalSqliteReferences = @'
    <PackageReference Include="Microsoft.EntityFrameworkCore.Sqlite.Core" Version="8.0.33" />
    <PackageReference Include="Microsoft.Data.Sqlite.Core" Version="8.0.33" />
    <PackageReference Include="SQLitePCLRaw.provider.sqlite3" Version="2.1.11" />
    <PackageReference Include="SQLitePCLRaw.provider.winsqlite3" Version="2.1.11" />
'@.Trim()
    $sqliteReferencePattern = '(?m)^[ \t]*<PackageReference Include="(?:Microsoft\.EntityFrameworkCore\.Sqlite(?:\.Core)?|Microsoft\.Data\.Sqlite(?:\.Core)?|SQLitePCLRaw\.(?:bundle_e_sqlite3|provider\.(?:e_sqlite3|sqlite3|winsqlite3)))" Version="[^"]+"[ \t]*/>[ \t]*(?:\r?\n)?'
    $sqliteMatches = [regex]::Matches($project,$sqliteReferencePattern)
    if ($sqliteMatches.Count -eq 0) {
        throw 'No recognized SQLite PackageReference was found in DngrmsDemo.Web.csproj. The generated source is incomplete; run Menu 10 only in this exceptional case.'
    }
    $firstIndex = $sqliteMatches[0].Index
    $normalizedProject = [regex]::Replace($project,$sqliteReferencePattern,'')
    $project = $normalizedProject.Insert($firstIndex,$canonicalSqliteReferences + [Environment]::NewLine)
    $changed += 'DngrmsDemo.Web.csproj:CanonicalSQLiteProviderGraph2.1.11'
    foreach ($requiredReference in @(
        'Microsoft.EntityFrameworkCore.Sqlite.Core" Version="8.0.33"',
        'Microsoft.Data.Sqlite.Core" Version="8.0.33"',
        'SQLitePCLRaw.provider.sqlite3" Version="2.1.11"',
        'SQLitePCLRaw.provider.winsqlite3" Version="2.1.11"')) {
        if (-not $project.Contains($requiredReference)) { throw "Canonical SQLite project normalization failed: $requiredReference" }
    }
    if ($project -match 'SQLitePCLRaw\.(?:bundle_e_sqlite3|provider\.e_sqlite3)') {
        throw 'Canonical SQLite project normalization left an e_sqlite3 package reference behind.'
    }
    $identityModelNames = @(
        'Microsoft.IdentityModel.Abstractions','Microsoft.IdentityModel.JsonWebTokens','Microsoft.IdentityModel.Logging',
        'Microsoft.IdentityModel.Protocols','Microsoft.IdentityModel.Protocols.OpenIdConnect','Microsoft.IdentityModel.Tokens',
        'Microsoft.IdentityModel.Tokens.Saml','Microsoft.IdentityModel.Xml','System.IdentityModel.Tokens.Jwt'
    )
    $identityPattern = '(?m)^[ \t]*<PackageReference Include="(?:' + (($identityModelNames | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')" Version="[^"]+"[ \t]*/>[ \t]*(?:\r?\n)?'
    $project = [regex]::Replace($project,$identityPattern,'')
    $oidcPattern = '(?m)^[ \t]*<PackageReference Include="Microsoft\.AspNetCore\.Authentication\.OpenIdConnect" Version="[^"]+"[ \t]*/>[ \t]*(?:\r?\n)?'
    $oidcMatches = [regex]::Matches($project,$oidcPattern)
    if ($oidcMatches.Count -ne 1) { throw "Exactly one OIDC PackageReference is required before normalization; found $($oidcMatches.Count)." }
    $oidcInsertIndex = $oidcMatches[0].Index
    $project = [regex]::Replace($project,$oidcPattern,'')
    $oidcReference = '    <PackageReference Include="Microsoft.AspNetCore.Authentication.OpenIdConnect" Version="8.0.33" />'
    $identityLines = @($identityModelNames | ForEach-Object { '    <PackageReference Include="' + $_ + '" Version="8.22.0" />' }) -join [Environment]::NewLine
    $canonicalOidcGraph = $oidcReference + [Environment]::NewLine + $identityLines + [Environment]::NewLine
    $project = $project.Insert($oidcInsertIndex,$canonicalOidcGraph)
    $canonicalOidcCount = ([regex]::Matches($project,'Microsoft\.AspNetCore\.Authentication\.OpenIdConnect" Version="8\.0\.33"')).Count
    if ($canonicalOidcCount -ne 1) { throw "Canonical OIDC PackageReference normalization failed; count=$canonicalOidcCount." }
    foreach ($identityName in $identityModelNames) {
        $expectedIdentityReference = $identityName + '" Version="8.22.0"'
        if (-not $project.Contains($expectedIdentityReference)) { throw "IdentityModel PackageReference normalization failed: $identityName" }
    }
    $changed += 'DngrmsDemo.Web.csproj:Oidc8.0.33AndIdentityModelAligned8.22.0'
    if ($project -notmatch '<PublishSingleFile>false</PublishSingleFile>') {
        $oldPublishProperties = '    <InvariantGlobalization>false</InvariantGlobalization>'
        $newPublishProperties = @'
    <InvariantGlobalization>false</InvariantGlobalization>
    <PublishSingleFile>false</PublishSingleFile>
    <PublishTrimmed>false</PublishTrimmed>
    <PublishReadyToRun>false</PublishReadyToRun>
'@.TrimEnd()
        if (-not $project.Contains($oldPublishProperties)) { throw 'The project publish-property anchor was not found. Rerun Menu 10.' }
        $project = $project.Replace($oldPublishProperties,$newPublishProperties)
        $changed += 'DngrmsDemo.Web.csproj:NativePublishProperties'
    }
    [IO.File]::WriteAllText($projectPath,$project,$utf8NoBom)

    $program = [IO.File]::ReadAllText($programPath)
    $samlChainTrustLine = 'samlConfig.CertificateValidationMode = System.ServiceModel.Security.X509CertificateValidationMode.None;'
    $samlSignAnchor = 'samlConfig.SignAuthnRequest = false;'
    if (-not $program.Contains($samlSignAnchor)) { throw 'Program.cs SAML SignAuthnRequest anchor was not found. Rerun Menu 10.' }
    $program = [regex]::Replace($program,'(?m)^[ \t]*samlConfig\.CertificateValidationMode\s*=.*;[ \t]*(?:\r?\n)?','')
    $samlAnchorIndex = $program.IndexOf($samlSignAnchor,[StringComparison]::Ordinal)
    $samlInsertAt = $samlAnchorIndex + $samlSignAnchor.Length
    $program = $program.Insert($samlInsertAt,[Environment]::NewLine + '    // Entra signing key is explicitly pinned from federation metadata; skip OS chain trust only.' + [Environment]::NewLine + '    ' + $samlChainTrustLine)
    if (([regex]::Matches($program,[regex]::Escape($samlChainTrustLine))).Count -ne 1) { throw 'Program.cs SAML certificate-validation normalization failed.' }
    $changed += 'Program.cs:EntraMetadataPinnedSamlCertificateTrust'
    $canonicalProviderBlock = @'
try
{
    // v1.1.20 selects the operating-system SQLite provider after bootstrap resolves libsqlite3.so.0.
    if (OperatingSystem.IsWindows())
    {
        SQLitePCL.raw.SetProvider(new SQLitePCL.SQLite3Provider_winsqlite3());
    }
    else
    {
        SQLitePCL.raw.SetProvider(new SQLitePCL.SQLite3Provider_sqlite3());
    }
    SQLitePCL.raw.FreezeProvider();
    using var nativeProbe = new Microsoft.Data.Sqlite.SqliteConnection("Data Source=:memory:;Mode=Memory;Cache=Private;Pooling=False");
    nativeProbe.Open();
    using var versionCommand = nativeProbe.CreateCommand();
    versionCommand.CommandText = "SELECT sqlite_version();";
    var nativeVersion = Convert.ToString(versionCommand.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture) ?? "unknown";
    Console.WriteLine($"[DNGRMS-SQLITE-NATIVE] Provider=system-sqlite3 Version={nativeVersion} RID={System.Runtime.InteropServices.RuntimeInformation.RuntimeIdentifier}");
}
catch (Exception ex)
{
    var depth = 0;
    for (Exception? current = ex; current is not null; current = current.InnerException)
    {
        Console.Error.WriteLine($"[DNGRMS-STARTUP-EXCEPTION] Stage=SqliteNativeProvider Depth={depth} Type={current.GetType().FullName} Message={current.Message}");
        depth++;
    }
    Console.Error.WriteLine(ex.ToString());
    throw;
}
'@.Trim()
    $dbContextAnchor = 'builder.Services.AddDbContext<DemoDbContext>(options => options.UseSqlite(sqliteConnectionString));'
    $anchorIndex = $program.IndexOf($dbContextAnchor,[StringComparison]::Ordinal)
    if ($anchorIndex -lt 0) { throw 'Program.cs DbContext anchor was not found. Refusing to publish.' }
    $prefix = $program.Substring(0,$anchorIndex)
    $probeStart = $prefix.LastIndexOf('try',[StringComparison]::Ordinal)
    if ($probeStart -lt 0) { throw 'Program.cs SQLite native-probe try block was not found before DbContext registration.' }
    $probeSlice = $program.Substring($probeStart,$anchorIndex - $probeStart)
    if ($probeSlice -notmatch 'nativeProbe\.Open\(\)' -or $probeSlice -notmatch 'Stage=SqliteNativeProvider') { throw 'Program.cs native-probe block could not be identified safely.' }
    $program = $program.Substring(0,$probeStart) + $canonicalProviderBlock + [Environment]::NewLine + $program.Substring($anchorIndex)
    $changed += 'Program.cs:CanonicalSystemSQLiteProviderInitialization'
    $setProviderCount = ([regex]::Matches($program,'SQLitePCL\.raw\.SetProvider\(')).Count
    $setProviderIndex = $program.IndexOf('SQLitePCL.raw.SetProvider(',[StringComparison]::Ordinal)
    $freezeProviderIndex = $program.IndexOf('SQLitePCL.raw.FreezeProvider();',[StringComparison]::Ordinal)
    $nativeOpenIndex = $program.IndexOf('nativeProbe.Open();',[StringComparison]::Ordinal)
    $dbContextIndex = $program.IndexOf($dbContextAnchor,[StringComparison]::Ordinal)
    if ($setProviderCount -ne 2) { throw "Program.cs must contain exactly two OS-branch SetProvider call sites; found $setProviderCount." }
    if ($setProviderIndex -lt 0 -or $freezeProviderIndex -le $setProviderIndex -or $nativeOpenIndex -le $freezeProviderIndex -or $dbContextIndex -le $nativeOpenIndex) { throw 'Program.cs provider initialization ordering failed.' }
    if ($program -notmatch 'SQLite3Provider_winsqlite3' -or $program -notmatch 'SQLite3Provider_sqlite3' -or $program -notmatch 'Provider=system-sqlite3' -or $program -match 'bundle_e_sqlite3 dependency') { throw 'Program.cs canonical system-SQLite provider contract failed.' }
    if ($program -notmatch '\[DNGRMS-STARTUP-EXCEPTION\].*Stage=EnsureCreatedAndSeed') {
        $old = @'
using (var scope = app.Services.CreateScope())
{
    var seeder = scope.ServiceProvider.GetRequiredService<DemoSeeder>();
    await seeder.EnsureCreatedAndSeedAsync();
}
'@
        $new = @'
try
{
    using var scope = app.Services.CreateScope();
    var seeder = scope.ServiceProvider.GetRequiredService<DemoSeeder>();
    await seeder.EnsureCreatedAndSeedAsync();
}
catch (Exception ex)
{
    var depth = 0;
    for (Exception? current = ex; current is not null; current = current.InnerException)
    {
        Console.Error.WriteLine($"[DNGRMS-STARTUP-EXCEPTION] Stage=EnsureCreatedAndSeed Depth={depth} Type={current.GetType().FullName} Message={current.Message}");
        depth++;
    }
    Console.Error.WriteLine(ex.ToString());
    throw;
}
'@
        if (-not $program.Contains($old.Trim())) { throw 'Program.cs startup seeding block is not a recognized v1.1.13 contract. Rerun Menu 10.' }
        $program = $program.Replace($old.Trim(),$new.Trim())
        $changed += 'Program.cs:StartupException'
    }
    if ($program -match 'var root = ex;\s*while \(root\.InnerException') {
        $oldCatch = @'
catch (Exception ex)
{
    var root = ex;
    while (root.InnerException is not null) root = root.InnerException;
    Console.Error.WriteLine($"[DNGRMS-STARTUP-EXCEPTION] Stage=EnsureCreatedAndSeed Type={root.GetType().FullName} Message={root.Message}");
    throw;
}
'@.Trim()
        $newCatch = @'
catch (Exception ex)
{
    var depth = 0;
    for (Exception? current = ex; current is not null; current = current.InnerException)
    {
        Console.Error.WriteLine($"[DNGRMS-STARTUP-EXCEPTION] Stage=EnsureCreatedAndSeed Depth={depth} Type={current.GetType().FullName} Message={current.Message}");
        depth++;
    }
    Console.Error.WriteLine(ex.ToString());
    throw;
}
'@.Trim()
        if (-not $program.Contains($oldCatch)) { throw 'Program.cs startup exception block was not recognized. Rerun Menu 10.' }
        $program = $program.Replace($oldCatch,$newCatch)
        $changed += 'Program.cs:StartupExceptionChain'
    }
    [IO.File]::WriteAllText($programPath,$program,$utf8NoBom)

    $seeder = [IO.File]::ReadAllText($seederPath)
    if ($seeder -notmatch 'using Microsoft\.Data\.Sqlite;') {
        $seeder = $seeder.Replace('using Microsoft.AspNetCore.Identity;' + [Environment]::NewLine + 'using Microsoft.EntityFrameworkCore;', 'using Microsoft.AspNetCore.Identity;' + [Environment]::NewLine + 'using Microsoft.Data.Sqlite;' + [Environment]::NewLine + 'using Microsoft.EntityFrameworkCore;')
        if ($seeder -notmatch 'using Microsoft\.Data\.Sqlite;') { throw 'DemoSeeder.cs using block is not a recognized v1.1.13 contract. Rerun Menu 10.' }
        $changed += 'DemoSeeder.cs:SqliteUsing'
    }
    if ($seeder -notmatch 'EnsureDatabaseCreatedAsync') {
        $seeder = $seeder.Replace('await db.Database.EnsureCreatedAsync();','await EnsureDatabaseCreatedAsync();')
        $marker = '    private async Task UpsertUserAsync(string userName, string password, string displayName, string role, string email)'
        $helper = @'
    private async Task EnsureDatabaseCreatedAsync()
    {
        const int maximumAttempts = 3;
        for (var attempt = 1; attempt <= maximumAttempts; attempt++)
        {
            try
            {
                await db.Database.OpenConnectionAsync();
                await db.Database.ExecuteSqlRawAsync("PRAGMA busy_timeout=30000;");
                await using (var command = db.Database.GetDbConnection().CreateCommand())
                {
                    command.CommandText = "SELECT sqlite_version();";
                    var version = Convert.ToString(await command.ExecuteScalarAsync(), System.Globalization.CultureInfo.InvariantCulture) ?? "unknown";
                    Console.WriteLine($"[DNGRMS-SQLITE-CONNECTION] State=Open Version={version} DataSource={db.Database.GetDbConnection().DataSource}");
                }
                await db.Database.EnsureCreatedAsync();
                return;
            }
            catch (SqliteException ex) when (attempt < maximumAttempts && ex.SqliteErrorCode is 5 or 6 or 10)
            {
                Console.Error.WriteLine($"[DNGRMS-SQLITE-RETRY] Attempt={attempt} Primary={ex.SqliteErrorCode} Extended={ex.SqliteExtendedErrorCode} Message={ex.Message}");
                await Task.Delay(TimeSpan.FromSeconds(attempt * 2));
            }
            catch (Exception ex)
            {
                var depth = 0;
                for (Exception? current = ex; current is not null; current = current.InnerException)
                {
                    if (current is SqliteException sqlite)
                        Console.Error.WriteLine($"[DNGRMS-STARTUP-EXCEPTION] Stage=EnsureCreated Depth={depth} Type={current.GetType().FullName} Primary={sqlite.SqliteErrorCode} Extended={sqlite.SqliteExtendedErrorCode} Message={current.Message}");
                    else
                        Console.Error.WriteLine($"[DNGRMS-STARTUP-EXCEPTION] Stage=EnsureCreated Depth={depth} Type={current.GetType().FullName} Message={current.Message}");
                    depth++;
                }
                Console.Error.WriteLine(ex.ToString());
                throw;
            }
            finally
            {
                await db.Database.CloseConnectionAsync();
            }
        }
    }

'@
        if (-not $seeder.Contains($marker)) { throw 'DemoSeeder.cs method anchor is not a recognized v1.1.13 contract. Rerun Menu 10.' }
        $seeder = $seeder.Replace($marker,$helper + $marker)
        $changed += 'DemoSeeder.cs:BoundedEnsureCreated'
    }
    $oldSeederHelper = @'
    private async Task EnsureDatabaseCreatedAsync()
    {
        const int maximumAttempts = 3;
        for (var attempt = 1; attempt <= maximumAttempts; attempt++)
        {
            try
            {
                await db.Database.ExecuteSqlRawAsync("PRAGMA busy_timeout=30000;");
                await db.Database.EnsureCreatedAsync();
                return;
            }
            catch (SqliteException ex) when (attempt < maximumAttempts && ex.SqliteErrorCode is 5 or 6 or 10)
            {
                Console.Error.WriteLine($"[DNGRMS-SQLITE-RETRY] Attempt={attempt} Primary={ex.SqliteErrorCode} Extended={ex.SqliteExtendedErrorCode} Message={ex.Message}");
                await Task.Delay(TimeSpan.FromSeconds(attempt * 2));
            }
            catch (SqliteException ex)
            {
                Console.Error.WriteLine($"[DNGRMS-STARTUP-EXCEPTION] Stage=EnsureCreated Primary={ex.SqliteErrorCode} Extended={ex.SqliteExtendedErrorCode} Message={ex.Message}");
                throw;
            }
        }
    }
'@.Trim()
    $newSeederHelper = @'
    private async Task EnsureDatabaseCreatedAsync()
    {
        const int maximumAttempts = 3;
        for (var attempt = 1; attempt <= maximumAttempts; attempt++)
        {
            try
            {
                await db.Database.OpenConnectionAsync();
                await db.Database.ExecuteSqlRawAsync("PRAGMA busy_timeout=30000;");
                await using (var command = db.Database.GetDbConnection().CreateCommand())
                {
                    command.CommandText = "SELECT sqlite_version();";
                    var version = Convert.ToString(await command.ExecuteScalarAsync(), System.Globalization.CultureInfo.InvariantCulture) ?? "unknown";
                    Console.WriteLine($"[DNGRMS-SQLITE-CONNECTION] State=Open Version={version} DataSource={db.Database.GetDbConnection().DataSource}");
                }
                await db.Database.EnsureCreatedAsync();
                return;
            }
            catch (SqliteException ex) when (attempt < maximumAttempts && ex.SqliteErrorCode is 5 or 6 or 10)
            {
                Console.Error.WriteLine($"[DNGRMS-SQLITE-RETRY] Attempt={attempt} Primary={ex.SqliteErrorCode} Extended={ex.SqliteExtendedErrorCode} Message={ex.Message}");
                await Task.Delay(TimeSpan.FromSeconds(attempt * 2));
            }
            catch (Exception ex)
            {
                var depth = 0;
                for (Exception? current = ex; current is not null; current = current.InnerException)
                {
                    if (current is SqliteException sqlite)
                        Console.Error.WriteLine($"[DNGRMS-STARTUP-EXCEPTION] Stage=EnsureCreated Depth={depth} Type={current.GetType().FullName} Primary={sqlite.SqliteErrorCode} Extended={sqlite.SqliteExtendedErrorCode} Message={current.Message}");
                    else
                        Console.Error.WriteLine($"[DNGRMS-STARTUP-EXCEPTION] Stage=EnsureCreated Depth={depth} Type={current.GetType().FullName} Message={current.Message}");
                    depth++;
                }
                Console.Error.WriteLine(ex.ToString());
                throw;
            }
            finally
            {
                await db.Database.CloseConnectionAsync();
            }
        }
    }
'@.Trim()
    if ($seeder.Contains($oldSeederHelper)) {
        $seeder = $seeder.Replace($oldSeederHelper,$newSeederHelper)
        $changed += 'DemoSeeder.cs:ExplicitConnectionAndExceptionChain'
    }
    elseif ($seeder -notmatch '\[DNGRMS-SQLITE-CONNECTION\].*State=Open') {
        throw 'DemoSeeder.cs database initialization helper is not recognized. Rerun Menu 10.'
    }
    [IO.File]::WriteAllText($seederPath,$seeder,$utf8NoBom)
    $result = [pscustomobject][ordered]@{
        CapturedUtc=[DateTime]::UtcNow.ToString('o')
        ContractVersion=$script:LauncherVersion
        ChangedFiles=$changed
        ProgramSha256=(Get-FileSha256 -Path $programPath)
        ProjectSha256=(Get-FileSha256 -Path $projectPath)
        DemoSeederSha256=(Get-FileSha256 -Path $seederPath)
        Synchronized=$true
    }
    Write-EvidenceJson -Name 'menu24-source-contract-sync' -Data $result | ForEach-Object { $result | Add-Member -NotePropertyName EvidencePath -NotePropertyValue $_ }
    Write-Host ("Generated source contract: v{0}; Changes={1}; Evidence={2}" -f $script:LauncherVersion,(@($changed) -join ','),$result.EvidencePath)
    return $result
}

function Build-LinuxFrameworkDependentDeploymentPackage {
    if (-not (Test-Path (Join-Path $script:SourceRoot 'DngrmsDemo.Web.csproj'))) { throw 'Generated source is missing. Run Menu 10 before building the Linux deployment package.' }
    if (Test-Path -LiteralPath $script:PublishRoot) { Remove-Item -LiteralPath $script:PublishRoot -Recurse -Force }
    New-Item -ItemType Directory -Path $script:PublishRoot -Force | Out-Null
    $publish = Invoke-DotNet -Arguments @('publish','-c','Release','-r','linux-x64','--self-contained','false','--nologo','-o',$script:PublishRoot) -PassThru
    $sqliteNativeContract = Assert-SqliteLinuxX64PublishContract -PublishDirectory $script:PublishRoot
    $packageIdentity = Write-DeploymentPackageIdentityFiles -SourceDirectory $script:PublishRoot -PackageDeploymentMode 'FrameworkDependentNet8' -StartupCommand 'dotnet DngrmsDemo.Web.dll'
    $zipPath = Join-Path $script:PackageRoot "DngrmsDemo.Web-v${script:LauncherVersion}-framework-dependent-net8-linux-x64.zip"
    $null = New-LinuxDeploymentZip -SourceDirectory $script:PublishRoot -DestinationPath $zipPath
    $contract = Test-DeploymentZipContract -ZipPath $zipPath -ExpectedMode 'FrameworkDependentNet8'
    if (-not $contract.LinuxX64RuntimeContract.ExplicitLinuxX64) { throw 'Framework-dependent Menu 19 package did not produce an explicit linux-x64 runtime target.' }
    $script:State['DeploymentFrameworkDependentZipPath'] = $zipPath
    Save-State
    return [pscustomobject][ordered]@{ Publish=$publish; SQLiteNativeContract=$sqliteNativeContract; Package=$contract; PackageIdentity=$packageIdentity; ZipPath=$zipPath; PackageDeploymentMode='FrameworkDependentNet8' }
}

function Build-LinuxSelfContainedDeploymentPackage {
    if (-not (Test-Path (Join-Path $script:SourceRoot 'DngrmsDemo.Web.csproj'))) { throw 'Generated source is missing. Run Menu 10 before building the Linux self-contained deployment package.' }
    if (Test-Path -LiteralPath $script:LinuxSelfContainedRoot) { Remove-Item -LiteralPath $script:LinuxSelfContainedRoot -Recurse -Force }
    New-Item -ItemType Directory -Path $script:LinuxSelfContainedRoot -Force | Out-Null
    $publish = Invoke-DotNet -Arguments @('publish','-c','Release','-r','linux-x64','--self-contained','true','--nologo','-o',$script:LinuxSelfContainedRoot) -PassThru
    $sqliteNativeContract = Assert-SqliteLinuxX64PublishContract -PublishDirectory $script:LinuxSelfContainedRoot
    if (-not (Test-Path -LiteralPath $script:LinuxSelfContainedExecutable -PathType Leaf)) { throw "Linux self-contained apphost is missing: $script:LinuxSelfContainedExecutable" }
    foreach ($runtimeFile in @('libcoreclr.so','libhostfxr.so')) {
        if (-not (Test-Path -LiteralPath (Join-Path $script:LinuxSelfContainedRoot $runtimeFile) -PathType Leaf)) { throw "Linux self-contained publish is incomplete: $runtimeFile is missing." }
    }
    $bootstrapPath = Join-Path $script:LinuxSelfContainedRoot 'dngrms-start-selfcontained.sh'
    $bootstrapText = @'
#!/bin/sh
set -eu
source_root=/home/site/wwwroot
target_root=/home/site/dngrms-selfcontained-runtime
rm -rf "$target_root"
mkdir -p "$target_root"
cp -R "$source_root"/. "$target_root"/
chmod 755 "$target_root/DngrmsDemo.Web"
sqlite_soname=""
for candidate in \
  /usr/lib/x86_64-linux-gnu/libsqlite3.so.0 \
  /lib/x86_64-linux-gnu/libsqlite3.so.0 \
  /usr/lib64/libsqlite3.so.0 \
  /lib64/libsqlite3.so.0 \
  /usr/lib/libsqlite3.so.0 \
  /lib/libsqlite3.so.0
do
  if [ -r "$candidate" ]; then
    sqlite_soname="$candidate"
    break
  fi
done
if [ -z "$sqlite_soname" ]; then
  echo "[DNGRMS-STARTUP-EXCEPTION] Stage=SqliteSonameResolution Message=libsqlite3.so.0 was not found under trusted system library roots" >&2
  exit 72
fi
ln -sf "$sqlite_soname" "$target_root/libsqlite3.so"
ln -sf "$sqlite_soname" "$target_root/sqlite3.so"
export LD_LIBRARY_PATH="$target_root${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
echo "[DNGRMS-SQLITE-SONAME] Source=$sqlite_soname Alias=$target_root/libsqlite3.so"
cd "$target_root"
exec ./DngrmsDemo.Web
'@
    $bootstrapText = $bootstrapText.Replace("`r`n","`n").Replace("`r","`n").TrimStart() + "`n"
    $utf8NoBom = New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $false
    [IO.File]::WriteAllText($bootstrapPath, $bootstrapText, $utf8NoBom)
    $writtenBootstrap = [IO.File]::ReadAllText($bootstrapPath)
    foreach ($requiredBootstrapToken in @('libsqlite3.so.0','ln -sf','$target_root/libsqlite3.so','LD_LIBRARY_PATH','DNGRMS-SQLITE-SONAME','exec ./DngrmsDemo.Web')) {
        if (-not $writtenBootstrap.Contains($requiredBootstrapToken)) { throw "Self-contained bootstrap SQLite SONAME contract is missing: $requiredBootstrapToken" }
    }
    $packageIdentity = Write-DeploymentPackageIdentityFiles -SourceDirectory $script:LinuxSelfContainedRoot -PackageDeploymentMode 'SelfContainedLinuxX64' -StartupCommand '/bin/sh /home/site/wwwroot/dngrms-start-selfcontained.sh'
    $zipPath = Join-Path $script:PackageRoot "DngrmsDemo.Web-v${script:LauncherVersion}-self-contained-linux-x64.zip"
    $null = New-LinuxDeploymentZip -SourceDirectory $script:LinuxSelfContainedRoot -DestinationPath $zipPath -ExecutableRelativePaths @('DngrmsDemo.Web','dngrms-start-selfcontained.sh')
    $contract = Test-DeploymentZipContract -ZipPath $zipPath -ExpectedMode 'SelfContainedLinuxX64'
    $script:State['DeploymentSelfContainedLinuxX64ZipPath'] = $zipPath
    $script:State['LinuxSelfContainedPublishPath'] = $script:LinuxSelfContainedRoot
    $script:State['LinuxSelfContainedExecutablePath'] = $script:LinuxSelfContainedExecutable
    $script:State['LinuxSelfContainedPublishUtc'] = [DateTime]::UtcNow.ToString('o')
    Save-State
    return [pscustomobject][ordered]@{ Publish=$publish; SQLiteNativeContract=$sqliteNativeContract; Package=$contract; PackageIdentity=$packageIdentity; ZipPath=$zipPath; PackageDeploymentMode='SelfContainedLinuxX64' }
}

function Get-FrameworkDependentDeploymentPackage {
    $candidates = @([string]$script:State['DeploymentFrameworkDependentZipPath'], [string]$script:State['DeploymentZipPath']) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    foreach ($candidate in $candidates) {
        if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) { continue }
        try {
            $contract = Test-DeploymentZipContract -ZipPath $candidate -ExpectedMode 'FrameworkDependentNet8'
            if ($contract.LinuxX64RuntimeContract.ExplicitLinuxX64) {
                $script:State['DeploymentFrameworkDependentZipPath'] = $candidate
                Save-State
                return $candidate
            }
        }
        catch { Write-WarningMessage "Existing framework-dependent package is not reusable: $($_.Exception.Message)" }
    }
    Write-WarningMessage 'No validated explicit linux-x64 framework-dependent package exists. Rebuilding it before deployment.'
    $built = Build-LinuxFrameworkDependentDeploymentPackage
    return [string]$built.ZipPath
}

function Ensure-LinuxSelfContainedDeploymentPackage {
    $candidate = [string]$script:State['DeploymentSelfContainedLinuxX64ZipPath']
    if (-not [string]::IsNullOrWhiteSpace($candidate) -and (Test-Path -LiteralPath $candidate -PathType Leaf)) {
        try {
            $null = Test-DeploymentZipContract -ZipPath $candidate -ExpectedMode 'SelfContainedLinuxX64'
            return $candidate
        }
        catch { Write-WarningMessage "Existing Linux self-contained package is not reusable: $($_.Exception.Message)" }
    }
    Write-WarningMessage 'Building the safe linux-x64 self-contained fallback because the App Service worker does not expose the required .NET 8 shared runtime.'
    $built = Build-LinuxSelfContainedDeploymentPackage
    return [string]$built.ZipPath
}

function Get-RedactedMenu24Settings {
    param([hashtable]$Settings)
    $safe = [ordered]@{}
    foreach ($name in @('DNGRMS_AUTH_MODE','DNGRMS_DB_PATH','ASPNETCORE_ENVIRONMENT','WEBSITE_RUN_FROM_PACKAGE','SCM_DO_BUILD_DURING_DEPLOYMENT','ENABLE_ORYX_BUILD','WEBSITES_CONTAINER_START_TIME_LIMIT','WEBSITE_WARMUP_PATH','WEBSITE_WARMUP_STATUSES')) {
        $safe[$name] = [string]$Settings[$name]
    }
    foreach ($name in @('DNGRMS_SEED_ADMIN_PASSWORD','DNGRMS_SEED_USER_PASSWORD','DNGRMS_SEED_ADMIN_EMAIL','DNGRMS_DEMO_ADMIN_KEY')) {
        $safe[$name] = if ([string]::IsNullOrWhiteSpace([string]$Settings[$name])) { 'Missing' } else { 'Present (redacted)' }
    }
    return [pscustomobject]$safe
}

function Assert-Menu24Settings {
    Write-Step 'Validating redacted app settings and preserving seed values in process memory for failure recovery...'
    $settings = Get-AzWebAppSettingsHashtable
    if ([string]::IsNullOrWhiteSpace([string]$settings['DNGRMS_DEMO_ADMIN_KEY'])) { throw "Required setting 'DNGRMS_DEMO_ADMIN_KEY' is missing. Run Menu 23." }
    $seedSecretsPresent = -not [string]::IsNullOrWhiteSpace([string]$settings['DNGRMS_SEED_ADMIN_PASSWORD']) -and -not [string]::IsNullOrWhiteSpace([string]$settings['DNGRMS_SEED_USER_PASSWORD'])
    if (-not $seedSecretsPresent) {
        $status = Get-DemoStatusSnapshot
        $existingUserCount = [int](Get-ObjectPropertyValue $status 'userCount' -1)
        if ($existingUserCount -lt 2) { throw "Seed settings are absent and the persistent database is not ready. ExistingUserCount=$existingUserCount. Run Menu 23, then Menu 24." }
        Write-WarningMessage "Menu 24 Upgrade/Redeploy mode selected: seed secrets are absent, but /home/data already contains $existingUserCount users. Existing identities and audit state will be preserved."
        $settings['DNGRMS_MENU24_DEPLOYMENT_INTENT'] = 'UpgradeRedeployExistingDatabase'
    }
    else { $settings['DNGRMS_MENU24_DEPLOYMENT_INTENT'] = 'InitialSeedDeployment' }
    if ([string]$settings['DNGRMS_DB_PATH'] -ne '/home/data/dngrms-demo.db') { throw 'DNGRMS_DB_PATH must be /home/data/dngrms-demo.db for persistent Linux App Service storage.' }
    if ([string]$settings['WEBSITE_RUN_FROM_PACKAGE'] -ne '1') { throw 'WEBSITE_RUN_FROM_PACKAGE must be 1 so ZIP deployment does not copy over live wwwroot files.' }
    if ([string]$settings['SCM_DO_BUILD_DURING_DEPLOYMENT'] -ne 'false') { throw 'SCM_DO_BUILD_DURING_DEPLOYMENT must be false for the prebuilt Linux deployment ZIP.' }
    if ([string]$settings['ENABLE_ORYX_BUILD'] -ne 'false') { throw 'ENABLE_ORYX_BUILD must be false for the prebuilt Linux deployment ZIP.' }
    return $settings
}

function Get-KuduBaseUrl {
    return "https://$($script:State.WebAppName).scm.azurewebsites.net"
}

function Invoke-KuduRequest {
    param(
        [Parameter(Mandatory)][ValidateSet('GET','POST','PUT','DELETE')][string]$Method,
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][string]$BearerToken,
        [hashtable]$Headers,
        [string]$ContentType,
        [string]$BodyText,
        [string]$UploadFilePath,
        [int]$TimeoutSeconds = 60
    )
    $requestHeaders = @{ Authorization = "Bearer $BearerToken" }
    if ($Headers) {
        foreach ($name in $Headers.Keys) {
            if ([string]$name -ieq 'Authorization') { throw 'Authorization is managed by Invoke-KuduRequest and cannot be overridden.' }
            $requestHeaders[[string]$name] = [string]$Headers[$name]
        }
    }
    return Invoke-DngrmsHttpRequest -Method $Method -Uri $Uri -Headers $requestHeaders `
        -ContentType $ContentType -BodyText $BodyText -UploadFilePath $UploadFilePath -TimeoutSeconds $TimeoutSeconds
}

function Wait-KuduReady {
    param([Parameter(Mandatory)][string]$BearerToken, [int]$TimeoutSeconds = 420)
    Write-Step 'Waiting for the independent SCM/Kudu deployment endpoint with the Entra bearer token...'
    $uri = "$(Get-KuduBaseUrl)/api/deployments"
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $restartInvoked = $false
    $started = [DateTime]::UtcNow
    $last = $null
    do {
        $last = Invoke-KuduRequest -Method GET -Uri $uri -BearerToken $BearerToken -TimeoutSeconds 45
        if ($last.StatusCode -in @(200,202)) {
            return [pscustomobject][ordered]@{ Response=(ConvertTo-HttpEvidenceSummary $last); RestartInvoked=$restartInvoked }
        }
        if ($last.StatusCode -in @(401,403) -and $last.FailureCategory -ne 'SiteDisabledStopped') {
            throw "SCM/Kudu authorization failed with HTTP $($last.StatusCode). Category=$($last.FailureCategory); Body=$(Get-SafeBodySnippet $last.Body)"
        }
        if (-not $restartInvoked -and ([DateTime]::UtcNow - $started).TotalSeconds -ge 120 -and $last.FailureCategory -in @('SiteDisabledStopped','ServerUnavailable','TransportFailure')) {
            Write-WarningMessage 'SCM/Kudu is still unavailable; recycling the Web App once and continuing the readiness poll.'
            Restart-AzWebApp -ResourceGroupName $script:State.ResourceGroupName -Name $script:State.WebAppName | Out-Null
            $restartInvoked = $true
        }
        Write-Host '.' -NoNewline
        Start-Sleep -Seconds 8
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "SCM/Kudu did not become ready within $TimeoutSeconds seconds. HTTP=$($last.StatusCode); Category=$($last.FailureCategory); Body=$(Get-SafeBodySnippet $last.Body)"
}

function New-KuduSimpleCommandPayload {
    <# The Kudu command field is deliberately limited to a simple executable plus
       whitespace-separated path/option tokens. Shell operators, quotes, command
       substitution, variables, and line breaks are rejected. Complex POSIX logic
       must be uploaded as a script file and invoked as: /bin/sh /home/<safe-name>.sh #>
    param(
        [Parameter(Mandatory)][string]$Command,
        [string]$WorkingDirectory = '/home'
    )
    if ([string]::IsNullOrWhiteSpace($Command)) { throw 'Kudu command cannot be empty.' }
    if ($Command -notmatch '^[A-Za-z0-9_./%+=:@ -]+$') {
        throw 'Kudu command contains quoting or shell metacharacters. Upload a POSIX script file and invoke it by path instead.'
    }
    if ($Command -match '[\r\n]' -or $Command -match '[;&|<>`$(){}\[\]''"]') {
        throw 'Kudu command contains a forbidden shell construct. Only a simple executable and literal arguments are allowed.'
    }
    if ($WorkingDirectory -notmatch '^/[A-Za-z0-9_./-]*$' -or $WorkingDirectory -match '\.\.') {
        throw 'Kudu working directory must be a simple absolute POSIX path without parent traversal.'
    }
    return [pscustomobject][ordered]@{ command=$Command; dir=$WorkingDirectory }
}

function Invoke-KuduSimpleCommand {
    param(
        [Parameter(Mandatory)][string]$Command,
        [Parameter(Mandatory)][string]$BearerToken,
        [string]$WorkingDirectory = '/home',
        [int]$TimeoutSeconds = 120
    )
    $payloadObject = New-KuduSimpleCommandPayload -Command $Command -WorkingDirectory $WorkingDirectory
    $payloadJson = $payloadObject | ConvertTo-Json -Compress
    $response = Invoke-KuduRequest -Method POST -Uri "$(Get-KuduBaseUrl)/api/command" -BearerToken $BearerToken `
        -ContentType 'application/json; charset=utf-8' -BodyText $payloadJson -TimeoutSeconds $TimeoutSeconds

    $commandResult = $null
    if (-not [string]::IsNullOrWhiteSpace($response.Body)) {
        try { $commandResult = $response.Body | ConvertFrom-Json } catch { $commandResult = $null }
    }
    $exitCode = -1
    $outputText = ''
    $errorText = ''
    if ($null -ne $commandResult) {
        $exitCodeValue = Get-ObjectPropertyValue $commandResult 'ExitCode' $null
        if ($null -ne $exitCodeValue) { $exitCode = [int]$exitCodeValue }
        $outputText = [string](Get-ObjectPropertyValue $commandResult 'Output' '')
        $errorText = [string](Get-ObjectPropertyValue $commandResult 'Error' '')
    }
    return [pscustomobject][ordered]@{
        Payload=$payloadObject
        PayloadJson=$payloadJson
        Http=(ConvertTo-HttpEvidenceSummary $response)
        Parsed=$null -ne $commandResult
        ExitCode=$exitCode
        Output=$outputText
        Error=$errorText
    }
}

function Get-TextSha256 {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($Text)
        return ([BitConverter]::ToString($algorithm.ComputeHash($bytes))).Replace('-','').ToLowerInvariant()
    }
    finally { $algorithm.Dispose() }
}

function Test-KuduHomeDataWrite {
    param([Parameter(Mandatory)][string]$BearerToken)
    Write-Step 'Verifying /home/data with an uploaded POSIX script and a quote-free Kudu command payload...'

    $nonce = [Guid]::NewGuid().ToString('N')
    $scriptName = ".dngrms-home-data-write-$nonce.sh"
    $scriptPath = "/home/$scriptName"
    $scriptVfsUri = "$(Get-KuduBaseUrl)/api/vfs/$scriptName"
    $markerName = ".dngrms-write-test-$nonce"
    $markerPath = "/home/data/$markerName"
    $markerVfsUri = "$(Get-KuduBaseUrl)/api/vfs/data/$markerName"
    $expectedContent = "DNGRMS_HOME_DATA_WRITE_$nonce"
    $scriptTemplate = @'
#!/bin/sh
set -eu
umask 077
data_dir=/home/data
marker=__MARKER_PATH__
expected=__EXPECTED_CONTENT__
mkdir -p "$data_dir"
test -d "$data_dir"
test -w "$data_dir"
permissions=$(stat -c %a "$data_dir")
printf '%s\n' "$expected" > "$marker"
test -s "$marker"
actual=$(cat "$marker")
test "$actual" = "$expected"
rm -f "$marker"
test ! -e "$marker"
printf 'DNGRMS_HOME_DATA_WRITE_OK permissions=%s bytes=%s\n' "$permissions" "${#actual}"
'@
    $scriptText = $scriptTemplate.Replace('__MARKER_PATH__',$markerPath).Replace('__EXPECTED_CONTENT__',$expectedContent)
    $scriptText = $scriptText.Replace("`r`n","`n").Replace("`r","`n").TrimStart() + "`n"
    $scriptSha256 = Get-TextSha256 -Text $scriptText
    $command = "/bin/sh $scriptPath"
    $payloadPreview = New-KuduSimpleCommandPayload -Command $command -WorkingDirectory '/home'
    $payloadJsonPreview = $payloadPreview | ConvertTo-Json -Compress

    $uploadResponse = $null
    $commandExecution = $null
    $markerDeleteResponse = $null
    $scriptDeleteResponse = $null
    $failureReason = ''
    try {
        $uploadResponse = Invoke-KuduRequest -Method PUT -Uri $scriptVfsUri -BearerToken $BearerToken `
            -Headers @{'If-Match'='*'} -ContentType 'application/octet-stream' -BodyText $scriptText -TimeoutSeconds 120
        if ($uploadResponse.StatusCode -notin @(200,201,204)) {
            $failureReason = "POSIX test script upload failed with HTTP $($uploadResponse.StatusCode). Category=$($uploadResponse.FailureCategory); Body=$(Get-SafeBodySnippet $uploadResponse.Body)"
        }
        else {
            $commandExecution = Invoke-KuduSimpleCommand -Command $command -WorkingDirectory '/home' -BearerToken $BearerToken -TimeoutSeconds 120
            if ($commandExecution.Http.StatusCode -ne 200) {
                $failureReason = "Kudu command returned HTTP $($commandExecution.Http.StatusCode). Category=$($commandExecution.Http.FailureCategory)"
            }
            elseif (-not $commandExecution.Parsed) { $failureReason = 'Kudu command response was not valid JSON.' }
            elseif ($commandExecution.ExitCode -ne 0) { $failureReason = "POSIX script returned ExitCode=$($commandExecution.ExitCode)." }
            elseif ($commandExecution.Output -notmatch 'DNGRMS_HOME_DATA_WRITE_OK') { $failureReason = 'POSIX script did not emit the success marker.' }
            elseif ($commandExecution.Output -notmatch 'permissions=[0-7]{3,4}') { $failureReason = 'POSIX script did not report the /home/data permission mode.' }
        }
    }
    catch { $failureReason = $_.Exception.Message }
    finally {
        # Cleanup uses the Kudu VFS API rather than another shell command, so it
        # cannot introduce a second quoting layer even when the test script fails.
        try {
            $markerDeleteResponse = Invoke-KuduRequest -Method DELETE -Uri $markerVfsUri -BearerToken $BearerToken `
                -Headers @{'If-Match'='*'} -TimeoutSeconds 60
        }
        catch { $markerDeleteResponse = [pscustomobject]@{ StatusCode=0; FailureCategory='CleanupTransportFailure'; ErrorMessage=$_.Exception.Message; Body=''; CapturedUtc=[DateTime]::UtcNow.ToString('o'); Uri=$markerVfsUri; StatusDescription=''; Location='' } }
        try {
            $scriptDeleteResponse = Invoke-KuduRequest -Method DELETE -Uri $scriptVfsUri -BearerToken $BearerToken `
                -Headers @{'If-Match'='*'} -TimeoutSeconds 60
        }
        catch { $scriptDeleteResponse = [pscustomobject]@{ StatusCode=0; FailureCategory='CleanupTransportFailure'; ErrorMessage=$_.Exception.Message; Body=''; CapturedUtc=[DateTime]::UtcNow.ToString('o'); Uri=$scriptVfsUri; StatusDescription=''; Location='' } }
    }

    $markerRemoved = $null -ne $markerDeleteResponse -and $markerDeleteResponse.StatusCode -in @(200,204,404)
    $scriptRemoved = $null -ne $scriptDeleteResponse -and $scriptDeleteResponse.StatusCode -in @(200,204,404)
    if ([string]::IsNullOrWhiteSpace($failureReason) -and -not $markerRemoved) { $failureReason = 'Temporary marker cleanup could not be verified.' }
    if ([string]::IsNullOrWhiteSpace($failureReason) -and -not $scriptRemoved) { $failureReason = 'Temporary POSIX script cleanup could not be verified.' }

    $commandHttp = $null
    $commandHttpStatus = 0
    $exitCode = -1
    $outputText = ''
    $errorText = ''
    $parsed = $false
    $actualPayload = $payloadPreview
    $actualPayloadJson = $payloadJsonPreview
    if ($null -ne $commandExecution) {
        $commandHttp = $commandExecution.Http
        $commandHttpStatus = [int]$commandExecution.Http.StatusCode
        $exitCode = $commandExecution.ExitCode
        $outputText = $commandExecution.Output
        $errorText = $commandExecution.Error
        $parsed = $commandExecution.Parsed
        $actualPayload = $commandExecution.Payload
        $actualPayloadJson = $commandExecution.PayloadJson
    }

    $permissionMode = ''
    if ($outputText -match 'permissions=(?<mode>[0-7]{3,4})') { $permissionMode = [string]$Matches['mode'] }

    $evidence = [ordered]@{
        CapturedUtc=[DateTime]::UtcNow.ToString('o')
        ExecutionMode='Uploaded POSIX script file; quote-free Kudu command invocation'
        ScriptPath=$scriptPath
        ScriptPayload=$scriptText
        ScriptPayloadSha256=$scriptSha256
        ScriptUpload=(ConvertTo-HttpEvidenceSummary $uploadResponse)
        CommandPayload=$actualPayload
        CommandPayloadJson=$actualPayloadJson
        CommandHttp=$commandHttp
        CommandHttpStatus=$commandHttpStatus
        CommandResponseParsed=$parsed
        ExitCode=$exitCode
        Output=(Get-SafeBodySnippet -Body $outputText)
        Error=(Get-SafeBodySnippet -Body $errorText)
        WorkingDirectory='/home'
        DataDirectory='/home/data'
        PermissionMode=$permissionMode
        MarkerPath=$markerPath
        Succeeded=[string]::IsNullOrWhiteSpace($failureReason)
        Writable=[string]::IsNullOrWhiteSpace($failureReason)
        MarkerRemoved=$markerRemoved
        ScriptRemoved=$scriptRemoved
        MarkerCleanup=(ConvertTo-HttpEvidenceSummary $markerDeleteResponse)
        ScriptCleanup=(ConvertTo-HttpEvidenceSummary $scriptDeleteResponse)
        FailureReason=$failureReason
        SecurityNote='The Entra bearer token is memory-only and excluded. The command and script payloads contain no credential or secret.'
    }
    $evidenceName = if ([string]::IsNullOrWhiteSpace($failureReason)) { 'kudu-home-data-write-success' } else { 'kudu-home-data-write-failure' }
    $evidencePath = Write-EvidenceJson -Name $evidenceName -Data $evidence
    $evidence['EvidencePath'] = $evidencePath

    return [pscustomobject]$evidence
}

function Repair-KuduSqliteTarget {
    param(
        [Parameter(Mandatory)][string]$BearerToken,
        [switch]$QuarantineExistingDatabase
    )
    Write-Step 'Inspecting the exact SQLite target under /home/data without deleting persistent data...'
    $nonce = [Guid]::NewGuid().ToString('N')
    $scriptName = ".dngrms-sqlite-target-$nonce.sh"
    $scriptPath = "/home/$scriptName"
    $scriptVfsUri = "$(Get-KuduBaseUrl)/api/vfs/$scriptName"
    $quarantineRequested = if ($QuarantineExistingDatabase) { '1' } else { '0' }
    $scriptTemplate = @'
#!/bin/sh
set -eu
umask 007
data_dir=/home/data
db=/home/data/dngrms-demo.db
nonce=__NONCE__
force_quarantine=__FORCE_QUARANTINE__
mkdir -p "$data_dir"
chmod u+rwx,g+rwx "$data_dir" 2>/dev/null || true
state=Absent
repair=None
archive=
archive_target() {
  suffix="$1"
  archive="${db}.${suffix}.${nonce}"
  mv "$db" "$archive"
  for sidecar in "${db}-wal" "${db}-shm" "${db}-journal"; do
    if [ -e "$sidecar" ]; then mv "$sidecar" "${sidecar}.${suffix}.${nonce}"; fi
  done
}
if [ -d "$db" ]; then
  state=PathWasDirectory
  archive_target invalid-directory
  repair=QuarantinedDirectoryTarget
elif [ -e "$db" ]; then
  size=$(wc -c < "$db" | tr -d ' ')
  if [ "$force_quarantine" = 1 ]; then
    state=ExistingDatabase
    archive_target cause-specific-repair
    repair=QuarantinedExistingDatabase
  elif [ "$size" -eq 0 ]; then
    state=EmptyFile
    archive_target empty
    repair=QuarantinedEmptyFile
  elif [ "$size" -lt 16 ]; then
    state=TooSmallForSQLite
    archive_target invalid-header
    repair=QuarantinedInvalidHeader
  else
    header=$(dd if="$db" bs=16 count=1 2>/dev/null | od -An -tx1 | tr -d ' \n')
    if [ "$header" != 53514c69746520666f726d6174203300 ]; then
      state=NotSQLiteHeader
      archive_target invalid-header
      repair=QuarantinedInvalidHeader
    else
      state=ValidSQLiteHeader
      chmod u+rw,g+rw "$db" 2>/dev/null || true
      for sidecar in "${db}-wal" "${db}-shm" "${db}-journal"; do
        if [ -e "$sidecar" ]; then chmod u+rw,g+rw "$sidecar" 2>/dev/null || true; fi
      done
      repair=PermissionsNormalized
    fi
  fi
fi
probe="${data_dir}/.dngrms-sqlite-write-${nonce}"
printf 'ok\n' > "$probe"
rm -f "$probe"
printf 'DNGRMS_SQLITE_TARGET_OK state=%s repair=%s archive=%s\n' "$state" "$repair" "$archive"
'@
    $scriptText = $scriptTemplate.Replace('__NONCE__',$nonce).Replace('__FORCE_QUARANTINE__',$quarantineRequested)
    $scriptText = $scriptText.Replace("`r`n","`n").Replace("`r","`n").TrimStart() + "`n"
    $upload = $null
    $execution = $null
    $cleanup = $null
    $failure = ''
    try {
        $upload = Invoke-KuduRequest -Method PUT -Uri $scriptVfsUri -BearerToken $BearerToken -Headers @{'If-Match'='*'} -ContentType 'application/octet-stream' -BodyText $scriptText -TimeoutSeconds 120
        if ($upload.StatusCode -notin @(200,201,204)) { throw "SQLite target script upload failed with HTTP $($upload.StatusCode)." }
        $execution = Invoke-KuduSimpleCommand -Command "/bin/sh $scriptPath" -WorkingDirectory '/home' -BearerToken $BearerToken -TimeoutSeconds 120
        if ($execution.Http.StatusCode -ne 200 -or -not $execution.Parsed -or $execution.ExitCode -ne 0 -or $execution.Output -notmatch 'DNGRMS_SQLITE_TARGET_OK') {
            throw "SQLite target inspection failed. HTTP=$($execution.Http.StatusCode); ExitCode=$($execution.ExitCode); Output=$(Get-SafeBodySnippet $execution.Output); Error=$(Get-SafeBodySnippet $execution.Error)"
        }
    }
    catch { $failure = Protect-KuduDiagnosticText -Text $_.Exception.Message -MaximumLength 3000 }
    finally {
        try { $cleanup = Invoke-KuduRequest -Method DELETE -Uri $scriptVfsUri -BearerToken $BearerToken -Headers @{'If-Match'='*'} -TimeoutSeconds 60 } catch { }
    }
    $state = ''
    $repair = ''
    $archive = ''
    if ($null -ne $execution -and $execution.Output -match 'DNGRMS_SQLITE_TARGET_OK\s+state=(?<state>\S+)\s+repair=(?<repair>\S+)\s+archive=(?<archive>\S*)') {
        $state = [string]$Matches['state']; $repair = [string]$Matches['repair']; $archive = [string]$Matches['archive']
    }
    $result = [pscustomobject][ordered]@{
        CapturedUtc=[DateTime]::UtcNow.ToString('o')
        DatabasePath='/home/data/dngrms-demo.db'
        State=$state
        Repair=$repair
        QuarantineRequested=[bool]$QuarantineExistingDatabase
        QuarantinePath=$archive
        ExistingDataDeleted=$false
        Succeeded=[string]::IsNullOrWhiteSpace($failure)
        FailureReason=$failure
        UploadHttp=if ($null -ne $upload) { ConvertTo-HttpEvidenceSummary $upload } else { $null }
        CommandHttp=if ($null -ne $execution) { $execution.Http } else { $null }
        CommandExitCode=if ($null -ne $execution) { $execution.ExitCode } else { -1 }
        Output=if ($null -ne $execution) { Get-SafeBodySnippet $execution.Output } else { '' }
        ScriptCleanup=if ($null -ne $cleanup) { ConvertTo-HttpEvidenceSummary $cleanup } else { $null }
    }
    $path = Write-EvidenceJson -Name 'menu24-sqlite-target' -Data $result
    $result | Add-Member -NotePropertyName EvidencePath -NotePropertyValue $path
    if (-not $result.Succeeded) { throw "SQLite target preflight/repair failed: $failure Evidence=$path" }
    Write-Host ("SQLite target: State={0}; Repair={1}; Quarantine={2}; Evidence={3}" -f $result.State,$result.Repair,$result.QuarantinePath,$path)
    return $result
}

function Resolve-DeploymentStatusUri {
    param([string]$Location)
    if ([string]::IsNullOrWhiteSpace($Location)) { return "$(Get-KuduBaseUrl)/api/deployments/latest" }
    $baseUri = New-Object -TypeName System.Uri -ArgumentList "$(Get-KuduBaseUrl)/"
    $absolute = $null
    if ([Uri]::TryCreate($Location, [UriKind]::Absolute, [ref]$absolute)) {
        if ($absolute.Scheme -ne 'https' -or $absolute.Host -ine $baseUri.Host) {
            throw "Kudu returned a deployment status URL outside the expected HTTPS SCM host. Host=$($absolute.Host)"
        }
        return $absolute.AbsoluteUri
    }
    $resolved = New-Object -TypeName System.Uri -ArgumentList $baseUri,$Location
    return $resolved.AbsoluteUri
}

function Get-UriQueryParameterValue {
    param([string]$UriText, [Parameter(Mandatory)][string]$Name)
    if ([string]::IsNullOrWhiteSpace($UriText)) { return '' }
    $uri = $null
    if (-not [Uri]::TryCreate($UriText, [UriKind]::Absolute, [ref]$uri)) { return '' }
    $query = $uri.Query.TrimStart('?')
    foreach ($part in @($query -split '&')) {
        if ([string]::IsNullOrWhiteSpace($part)) { continue }
        $pair = $part -split '=',2
        $key = [Uri]::UnescapeDataString(($pair[0] -replace '\+',' '))
        if ($key -ieq $Name) {
            if ($pair.Count -lt 2) { return '' }
            return [Uri]::UnescapeDataString(($pair[1] -replace '\+',' '))
        }
    }
    return ''
}

function ConvertTo-KuduUtcDateTime {
    param($Value)
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
    $parsed = [DateTimeOffset]::MinValue
    if ([DateTimeOffset]::TryParse([string]$Value, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$parsed)) {
        return $parsed.UtcDateTime
    }
    $kuduLocationTime = [DateTime]::MinValue
    $dateTimeStyles = [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal
    if ([DateTime]::TryParseExact([string]$Value, 'yyyy-MM-dd_HH-mm-ssZ', [Globalization.CultureInfo]::InvariantCulture, $dateTimeStyles, [ref]$kuduLocationTime)) {
        return $kuduLocationTime
    }
    return $null
}

function ConvertTo-KuduBoolean {
    param($Value, [bool]$Default = $false)
    if ($Value -is [bool]) { return [bool]$Value }
    if ($null -eq $Value) { return $Default }
    $parsed = $false
    if ([bool]::TryParse([string]$Value, [ref]$parsed)) { return $parsed }
    return $Default
}

function Get-KuduDeploymentSummary {
    param($Deployment)
    if ($null -eq $Deployment) { return $null }
    $status = $null
    $statusValue = Get-ObjectPropertyValue $Deployment 'status' $null
    $parsedStatus = -1
    if ($null -ne $statusValue -and [int]::TryParse([string]$statusValue, [ref]$parsedStatus)) { $status = $parsedStatus }
    return [pscustomobject][ordered]@{
        Id=[string](Get-ObjectPropertyValue $Deployment 'id' '')
        Status=$status
        StatusText=[string](Get-ObjectPropertyValue $Deployment 'status_text' '')
        Complete=(ConvertTo-KuduBoolean (Get-ObjectPropertyValue $Deployment 'complete' $false))
        Active=(ConvertTo-KuduBoolean (Get-ObjectPropertyValue $Deployment 'active' $false))
        IsTemporary=(ConvertTo-KuduBoolean (Get-ObjectPropertyValue $Deployment 'is_temp' $false))
        Deployer=[string](Get-ObjectPropertyValue $Deployment 'deployer' '')
        Message=[string](Get-ObjectPropertyValue $Deployment 'message' '')
        Progress=[string](Get-ObjectPropertyValue $Deployment 'progress' '')
        ReceivedTime=[string](Get-ObjectPropertyValue $Deployment 'received_time' '')
        StartTime=[string](Get-ObjectPropertyValue $Deployment 'start_time' '')
        EndTime=[string](Get-ObjectPropertyValue $Deployment 'end_time' '')
        Url=[string](Get-ObjectPropertyValue $Deployment 'url' '')
        LogUrl=[string](Get-ObjectPropertyValue $Deployment 'log_url' '')
    }
}

function ConvertFrom-KuduResponseJson {
    param($Response)
    if ($null -eq $Response -or [string]::IsNullOrWhiteSpace([string]$Response.Body)) { return $null }
    try { return ($Response.Body | ConvertFrom-Json) } catch { return $null }
}

function Protect-KuduDiagnosticText {
    param([string]$Text, [int]$MaximumLength = 20000)
    if ([string]::IsNullOrWhiteSpace($Text)) { return '' }
    $safe = $Text
    $safe = $safe -replace '(?i)(authorization\s*[:=]\s*)(bearer|basic)\s+[^\s,;]+', '$1******'
    $safe = $safe -replace '(?i)(password|passwd|pwd|client[_-]?secret|api[_-]?key|DNGRMS_DEMO_ADMIN_KEY|DNGRMS_SEED_ADMIN_PASSWORD|DNGRMS_SEED_USER_PASSWORD)(\s*[=:]\s*)[^\s,;\r\n]+', '$1$2******'
    $safe = $safe -replace '(?i)\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\b', '******'
    $safe = ($safe -replace '[\r\n\t]+', ' ' -replace '\s{2,}', ' ').Trim()
    if ($safe.Length -le $MaximumLength) { return $safe }
    $half = [Math]::Max(1, [int](($MaximumLength - 80) / 2))
    return $safe.Substring(0, $half) + ' ...[redacted diagnostic middle truncated; ending retained]... ' + $safe.Substring($safe.Length - $half)
}

function Resolve-KuduDiagnosticUri {
    param([Parameter(Mandatory)][string]$UriText)
    $baseUri = New-Object -TypeName System.Uri -ArgumentList "$(Get-KuduBaseUrl)/"
    $absolute = $null
    if ([Uri]::TryCreate($UriText, [UriKind]::Absolute, [ref]$absolute)) {
        if ($absolute.Scheme -ne 'https' -or $absolute.Host -ine $baseUri.Host) {
            throw "Kudu diagnostic URL was outside the expected HTTPS SCM host. Host=$($absolute.Host)"
        }
        return $absolute.AbsoluteUri
    }
    $resolved = New-Object -TypeName System.Uri -ArgumentList $baseUri,$UriText
    if ($resolved.Scheme -ne 'https' -or $resolved.Host -ine $baseUri.Host) {
        throw "Kudu diagnostic URL was outside the expected HTTPS SCM host. Host=$($resolved.Host)"
    }
    return $resolved.AbsoluteUri
}

function Test-KuduFailureText {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $false }
    return ($Text -match '(?i)\b(failed|failure|error|exception|denied|locked|cannot|could not|unable to|not permitted|read-only|resource busy|in use|directory not empty|no space left|quota exceeded)\b')
}

function Get-KuduDeploymentLogSnapshot {
    param(
        [Parameter(Mandatory)][string]$DeploymentId,
        [Parameter(Mandatory)][string]$BearerToken
    )
    $encodedId = [Uri]::EscapeDataString($DeploymentId)
    $uri = "$(Get-KuduBaseUrl)/api/deployments/$encodedId/log"
    $response = Invoke-KuduRequest -Method GET -Uri $uri -BearerToken $BearerToken -TimeoutSeconds 60
    $parsed = ConvertFrom-KuduResponseJson -Response $response
    $entries = @()
    if ($null -ne $parsed) {
        foreach ($entry in @($parsed)) {
            $typeValue = Get-ObjectPropertyValue $entry 'type' $null
            $type = -1
            if ($null -ne $typeValue) { [void][int]::TryParse([string]$typeValue, [ref]$type) }
            $message = Protect-KuduDiagnosticText -Text ([string](Get-ObjectPropertyValue $entry 'message' '')) -MaximumLength 2000
            $detailsUrl = [string](Get-ObjectPropertyValue $entry 'details_url' '')
            $details = $null
            if (-not [string]::IsNullOrWhiteSpace($detailsUrl)) {
                try {
                    $resolvedDetailsUrl = Resolve-KuduDiagnosticUri -UriText $detailsUrl
                    $detailsResponse = Invoke-KuduRequest -Method GET -Uri $resolvedDetailsUrl -BearerToken $BearerToken -TimeoutSeconds 60
                    $detailsBody = [string]$detailsResponse.Body
                    $details = [pscustomobject][ordered]@{
                        Uri=$resolvedDetailsUrl
                        Http=(ConvertTo-HttpEvidenceSummary $detailsResponse)
                        OriginalLength=$detailsBody.Length
                        ContentTruncated=($detailsBody.Length -gt 20000)
                        Content=(Protect-KuduDiagnosticText -Text $detailsBody -MaximumLength 20000)
                    }
                }
                catch {
                    $details = [pscustomobject][ordered]@{
                        Uri=$detailsUrl
                        Http=$null
                        Content=''
                        ReadError=(Protect-KuduDiagnosticText -Text $_.Exception.Message -MaximumLength 1200)
                    }
                }
            }
            $detailsText = if ($null -ne $details) { [string](Get-ObjectPropertyValue $details 'Content' '') } else { '' }
            $entryFailure = ($type -ge 2 -or (Test-KuduFailureText -Text $message) -or (Test-KuduFailureText -Text $detailsText))
            $entries += [pscustomobject][ordered]@{
                Id=[string](Get-ObjectPropertyValue $entry 'id' '')
                Type=$type
                Message=$message
                DetailsUrl=$detailsUrl
                Details=$details
                LogTime=[string](Get-ObjectPropertyValue $entry 'log_time' '')
                HasFailureSignal=$entryFailure
            }
        }
    }
    $hasExplicitFailure = $false
    $hasPositiveCompletion = $false
    foreach ($entry in $entries) {
        if ($entry.HasFailureSignal) { $hasExplicitFailure = $true }
        $combined = "{0} {1}" -f [string]$entry.Message,$(if ($null -ne $entry.Details) { [string]$entry.Details.Content } else { '' })
        if ($combined -match '(?i)deployment\s+(was\s+)?successful|successfully\s+deployed|deployment\s+completed\s+successfully|zip\s+deployment\s+successful') {
            $hasPositiveCompletion = $true
        }
    }
    return [pscustomobject][ordered]@{
        DeploymentId=$DeploymentId
        LogUri=$uri
        Http=(ConvertTo-HttpEvidenceSummary $response)
        Entries=$entries
        HasExplicitFailure=$hasExplicitFailure
        HasPositiveCompletion=$hasPositiveCompletion
    }
}

function Write-KuduDeploymentLogConsole {
    param([Parameter(Mandatory)][string]$Label, $RecordSnapshot, $LogSnapshot)
    $recordHttp = Get-KuduHttpStatusLabel (Get-ObjectPropertyValue $RecordSnapshot 'Http' $null)
    $record = Get-ObjectPropertyValue $RecordSnapshot 'Record' $null
    if ($null -ne $record) {
        $statusLabel = if ($null -ne $record.Status) { [string]$record.Status } else { 'unknown' }
        Write-Host ("  {0} record: HTTP={1}; Id={2}; Status={3}; Complete={4}; StatusText={5}" -f $Label,$recordHttp,[string]$record.Id,$statusLabel,[bool]$record.Complete,(Protect-KuduDiagnosticText -Text ([string]$record.StatusText) -MaximumLength 1200))
        Write-Host ("    Message={0}" -f (Protect-KuduDiagnosticText -Text ([string]$record.Message) -MaximumLength 2000))
        Write-Host ("    Progress={0}" -f (Protect-KuduDiagnosticText -Text ([string]$record.Progress) -MaximumLength 2000))
    }
    else {
        Write-Host ("  {0} record: HTTP={1}; no parsed record" -f $Label,$recordHttp)
    }

    if ($null -eq $LogSnapshot) {
        Write-Host ("  {0} log: not available" -f $Label)
        return
    }
    $logHttp = Get-KuduHttpStatusLabel (Get-ObjectPropertyValue $LogSnapshot 'Http' $null)
    $entries = @((Get-ObjectPropertyValue $LogSnapshot 'Entries' @()))
    Write-Host ("  {0} log: HTTP={1}; Entries={2}; FailureSignal={3}" -f $Label,$logHttp,$entries.Count,[bool](Get-ObjectPropertyValue $LogSnapshot 'HasExplicitFailure' $false))
    $entryNumber = 0
    foreach ($entry in $entries) {
        $entryNumber++
        Write-Host ("    entry[{0}]: Type={1}; Time={2}; Message={3}" -f $entryNumber,[string]$entry.Type,[string]$entry.LogTime,[string]$entry.Message)
        if ($null -ne $entry.Details) {
            $detailsHttp = Get-KuduHttpStatusLabel (Get-ObjectPropertyValue $entry.Details 'Http' $null)
            $detailsContent = [string](Get-ObjectPropertyValue $entry.Details 'Content' '')
            $detailsError = [string](Get-ObjectPropertyValue $entry.Details 'ReadError' '')
            $detailsLength = [int](Get-ObjectPropertyValue $entry.Details 'OriginalLength' 0)
            $detailsTruncated = [bool](Get-ObjectPropertyValue $entry.Details 'ContentTruncated' $false)
            Write-Host ("      details: HTTP={0}; OriginalLength={1}; Truncated={2}; Content={3}; ReadError={4}" -f $detailsHttp,$detailsLength,$detailsTruncated,$detailsContent,$detailsError)
        }
        elseif (-not [string]::IsNullOrWhiteSpace([string]$entry.DetailsUrl)) {
            Write-Host ("      details: URL was present but no details payload was collected: {0}" -f [string]$entry.DetailsUrl)
        }
    }
}

function Get-KuduWwwrootContractSnapshot {
    param([Parameter(Mandatory)][string]$BearerToken)
    $mode = if ([string]::IsNullOrWhiteSpace([string]$script:ActiveAzureDeploymentMode)) { 'FrameworkDependentNet8' } else { [string]$script:ActiveAzureDeploymentMode }
    $required = @('DngrmsDemo.Web.dll','DngrmsDemo.Web.deps.json','DngrmsDemo.Web.runtimeconfig.json','appsettings.json','dngrms-package-manifest.json')
    if ($mode -eq 'SelfContainedLinuxX64') {
        $required += @('DngrmsDemo.Web','dngrms-start-selfcontained.sh','libcoreclr.so','libhostfxr.so')
    }
    $uri = "$(Get-KuduBaseUrl)/api/vfs/site/wwwroot/"
    $response = Invoke-KuduRequest -Method GET -Uri $uri -BearerToken $BearerToken -TimeoutSeconds 45
    $parsed = ConvertFrom-KuduResponseJson -Response $response
    $files = @()
    $missing = @()
    foreach ($requiredName in $required) {
        $found = $null
        if ($null -ne $parsed) {
            foreach ($item in @($parsed)) {
                if ([string](Get-ObjectPropertyValue $item 'name' '') -ceq $requiredName) { $found = $item; break }
            }
        }
        $size = 0L
        if ($null -ne $found) { [void][long]::TryParse([string](Get-ObjectPropertyValue $found 'size' '0'), [ref]$size) }
        $exists = ($null -ne $found -and $size -gt 0)
        if (-not $exists) { $missing += $requiredName }
        $files += [pscustomobject][ordered]@{
            Name=$requiredName
            Exists=$exists
            SizeBytes=$size
            ModifiedTime=if ($null -ne $found) { [string](Get-ObjectPropertyValue $found 'mtime' '') } else { '' }
            Mode=if ($null -ne $found) { [string](Get-ObjectPropertyValue $found 'mode' '') } else { '' }
            Path="/home/site/wwwroot/$requiredName"
        }
    }
    $manifestUri = "$(Get-KuduBaseUrl)/api/vfs/site/wwwroot/dngrms-package-manifest.json"
    $manifestResponse = Invoke-KuduRequest -Method GET -Uri $manifestUri -BearerToken $BearerToken -TimeoutSeconds 45
    $manifest = ConvertFrom-KuduResponseJson -Response $manifestResponse
    $expectedId = [string](Get-ObjectPropertyValue $script:ExpectedPackageIdentity 'PackageId' '')
    $expectedMode = [string](Get-ObjectPropertyValue $script:ExpectedPackageIdentity 'PackageDeploymentMode' $mode)
    $expectedStartup = [string](Get-ObjectPropertyValue $script:ExpectedPackageIdentity 'StartupCommand' $script:ActiveAzureStartupCommand)
    $actualId = [string](Get-ObjectPropertyValue $manifest 'PackageId' '')
    $actualMode = [string](Get-ObjectPropertyValue $manifest 'PackageDeploymentMode' '')
    $actualStartup = [string](Get-ObjectPropertyValue $manifest 'StartupCommand' '')
    $actualLauncher = [string](Get-ObjectPropertyValue $manifest 'LauncherVersion' '')
    $identityMatched = ($manifestResponse.StatusCode -eq 200 -and -not [string]::IsNullOrWhiteSpace($actualId) -and $actualId -eq $expectedId -and $actualMode -eq $expectedMode -and $actualStartup -eq $expectedStartup -and $actualLauncher -eq $script:LauncherVersion)
    return [pscustomobject][ordered]@{
        CapturedUtc=[DateTime]::UtcNow.ToString('o')
        Http=(ConvertTo-HttpEvidenceSummary $response)
        RequiredFiles=$required
        Files=$files
        MissingFiles=$missing
        PackageDeploymentMode=$mode
        ManifestHttp=(ConvertTo-HttpEvidenceSummary $manifestResponse)
        PackageManifest=$manifest
        ExpectedPackageId=$expectedId
        ActualPackageId=$actualId
        IdentityMatched=$identityMatched
        ExpectedStartupCommand=$expectedStartup
        ManifestStartupCommand=$actualStartup
        Ready=($response.StatusCode -eq 200 -and $missing.Count -eq 0 -and $identityMatched)
        Path='/home/site/wwwroot'
        RunFromPackageReadOnlyExpected=$true
    }
}

function Get-KuduMainAssemblySnapshot {
    param([Parameter(Mandatory)][string]$BearerToken)
    $contract = Get-KuduWwwrootContractSnapshot -BearerToken $BearerToken
    $main = $null
    foreach ($file in @($contract.Files)) {
        if ([string]$file.Name -ieq 'DngrmsDemo.Web.dll') { $main = $file; break }
    }
    return [pscustomobject][ordered]@{
        CapturedUtc=$contract.CapturedUtc
        Http=$contract.Http
        Exists=($null -ne $main -and $main.Exists)
        Name=if ($null -ne $main) { [string]$main.Name } else { '' }
        SizeBytes=if ($null -ne $main) { [long]$main.SizeBytes } else { 0L }
        ModifiedTime=if ($null -ne $main) { [string]$main.ModifiedTime } else { '' }
        Path='/home/site/wwwroot/DngrmsDemo.Web.dll'
    }
}

function Get-HealthContractProbe {
    $uri = "$(Get-WebAppBaseUrl)/health"
    $response = Invoke-DngrmsHttpRequest -Method GET -Uri $uri -TimeoutSeconds 45
    $health = ConvertFrom-KuduResponseJson -Response $response
    $status = [string](Get-ObjectPropertyValue $health 'status' '')
    $database = [string](Get-ObjectPropertyValue $health 'database' '')
    return [pscustomobject][ordered]@{
        CapturedUtc=[DateTime]::UtcNow.ToString('o')
        Http=(ConvertTo-HttpEvidenceSummary $response)
        Status=$status
        Database=$database
        HealthyConnected=($response.StatusCode -eq 200 -and $status -eq 'Healthy' -and $database -eq 'Connected')
    }
}

function Get-KuduDeploymentCollectionSnapshot {
    param([Parameter(Mandatory)][string]$BearerToken)
    $uri = "$(Get-KuduBaseUrl)/api/deployments"
    $response = Invoke-KuduRequest -Method GET -Uri $uri -BearerToken $BearerToken -TimeoutSeconds 45
    $parsed = ConvertFrom-KuduResponseJson -Response $response
    $records = @()
    if ($null -ne $parsed) {
        foreach ($item in @($parsed)) {
            $summary = Get-KuduDeploymentSummary -Deployment $item
            if ($null -ne $summary) { $records += $summary }
        }
    }
    return [pscustomobject][ordered]@{ Http=(ConvertTo-HttpEvidenceSummary $response); Records=$records }
}

function Get-KuduLatestDeploymentSnapshot {
    param([Parameter(Mandatory)][string]$BearerToken)
    $uri = "$(Get-KuduBaseUrl)/api/deployments/latest"
    $response = Invoke-KuduRequest -Method GET -Uri $uri -BearerToken $BearerToken -TimeoutSeconds 45
    $parsed = ConvertFrom-KuduResponseJson -Response $response
    return [pscustomobject][ordered]@{ Http=(ConvertTo-HttpEvidenceSummary $response); Record=(Get-KuduDeploymentSummary -Deployment $parsed) }
}

function Get-KuduDeploymentRecordSnapshot {
    param(
        [Parameter(Mandatory)][string]$DeploymentId,
        [Parameter(Mandatory)][string]$BearerToken
    )
    $encodedId = [Uri]::EscapeDataString($DeploymentId)
    $uri = "$(Get-KuduBaseUrl)/api/deployments/$encodedId"
    $response = Invoke-KuduRequest -Method GET -Uri $uri -BearerToken $BearerToken -TimeoutSeconds 45
    $parsed = ConvertFrom-KuduResponseJson -Response $response
    return [pscustomobject][ordered]@{
        DeploymentId=$DeploymentId
        Http=(ConvertTo-HttpEvidenceSummary $response)
        Record=(Get-KuduDeploymentSummary -Deployment $parsed)
    }
}

function Find-CorrelatedKuduDeployment {
    param(
        [object[]]$Records,
        [Parameter(Mandatory)]$Correlation
    )
    $best = $null
    foreach ($record in @($Records)) {
        if ($null -eq $record) { continue }
        $idExact = (-not [string]::IsNullOrWhiteSpace([string]$Correlation.TempDeploymentId) -and [string]$record.Id -eq [string]$Correlation.TempDeploymentId)
        if ($idExact) {
            # A nonterminal temp record must not outrank a correlated final record.
            $exactScore = if (($null -ne $record.Status -and [int]$record.Status -in @(3,4)) -or $record.Complete) { 1000 } else { 15 }
            $exactCandidate = [pscustomobject][ordered]@{ Matched=$true; MatchReason='Exact temporary deployment id'; Score=$exactScore; Record=$record }
            if ($null -eq $best -or $exactScore -gt $best.Score) { $best = $exactCandidate }
            if ($exactScore -eq 1000) { return $best }
            continue
        }

        $expectedDeployer = [string]$Correlation.Deployer
        if ([string]::IsNullOrWhiteSpace($expectedDeployer)) { $expectedDeployer = [string]$Correlation.LocationDeployer }
        $deployerAvailable = -not [string]::IsNullOrWhiteSpace($expectedDeployer)
        $deployerMatch = $deployerAvailable -and -not [string]::IsNullOrWhiteSpace([string]$record.Deployer) -and ([string]$record.Deployer -ieq $expectedDeployer)

        $expectedMessage = ([string]$Correlation.Message -replace '\s+',' ').Trim()
        $recordMessage = ([string]$record.Message -replace '\s+',' ').Trim()
        $messageAvailable = -not [string]::IsNullOrWhiteSpace($expectedMessage)
        $messageMatch = $messageAvailable -and -not [string]::IsNullOrWhiteSpace($recordMessage) -and ($recordMessage -eq $expectedMessage)

        $expectedReceivedText = [string]$Correlation.ReceivedTime
        if ([string]::IsNullOrWhiteSpace($expectedReceivedText)) { $expectedReceivedText = [string]$Correlation.LocationTime }
        $expectedReceived = ConvertTo-KuduUtcDateTime $expectedReceivedText
        $actualReceived = ConvertTo-KuduUtcDateTime $record.ReceivedTime
        $receivedAvailable = $null -ne $expectedReceived
        $receivedDeltaSeconds = [double]::PositiveInfinity
        if ($receivedAvailable -and $null -ne $actualReceived) { $receivedDeltaSeconds = [Math]::Abs(($actualReceived - $expectedReceived).TotalSeconds) }
        # A narrow received_time window prevents a failed record from a prior
        # attempt from being mistaken for the current retry merely because the
        # deployer and message are identical.
        $receivedMatch = $receivedAvailable -and $receivedDeltaSeconds -le 45

        $submitted = ConvertTo-KuduUtcDateTime $Correlation.SubmittedUtc
        $inSubmissionWindow = $false
        if ($null -ne $submitted -and $null -ne $actualReceived) {
            $submissionDelta = ($actualReceived - $submitted).TotalSeconds
            $inSubmissionWindow = ($submissionDelta -ge -15 -and $submissionDelta -le 1800)
        }

        $matched = $false
        $reason = ''
        $score = 0
        if ($deployerMatch) { $score += 25 }
        if ($messageMatch) { $score += 35 }
        if ($receivedMatch) { $score += 45 }
        if ($inSubmissionWindow) { $score += 10 }
        if (-not $record.IsTemporary) { $score += 5 }

        if ($deployerAvailable -and $messageAvailable -and $receivedAvailable) {
            $matched = $deployerMatch -and $messageMatch -and $receivedMatch
            if ($matched) { $reason = 'Same deployer, message, and received_time window' }
        }
        elseif ($receivedAvailable -and (($deployerAvailable -and $deployerMatch) -or ($messageAvailable -and $messageMatch))) {
            $matched = $receivedMatch
            if ($matched) { $reason = 'Same received_time window and available submission identity' }
        }
        elseif (-not $receivedAvailable -and $deployerAvailable -and $messageAvailable) {
            $matched = $deployerMatch -and $messageMatch -and $inSubmissionWindow
            if ($matched) { $reason = 'Same deployer and message within submission window' }
        }
        elseif (-not $receivedAvailable -and $deployerAvailable -and -not $messageAvailable) {
            $matched = $deployerMatch -and $inSubmissionWindow
            if ($matched) { $reason = 'Same deployer within submission window' }
        }

        if ($matched -and ($null -eq $best -or $score -gt $best.Score)) {
            $best = [pscustomobject][ordered]@{ Matched=$true; MatchReason=$reason; Score=$score; Record=$record }
        }
    }
    return $best
}

function Compare-KuduWwwrootContract {
    param($Baseline, $Current, [string]$SubmittedUtc)
    $baselineHttp = Get-ObjectPropertyValue $Baseline 'Http' $null
    $baselineHttpStatus = [int](Get-ObjectPropertyValue $baselineHttp 'StatusCode' 0)
    $baselineFiles = @(Get-ObjectPropertyValue $Baseline 'Files' @())
    $currentFiles = @(Get-ObjectPropertyValue $Current 'Files' @())
    $submitted = ConvertTo-KuduUtcDateTime $SubmittedUtc
    $changes = @()
    $mainChangedOrFresh = $false

    foreach ($currentFile in $currentFiles) {
        $before = $null
        foreach ($candidate in $baselineFiles) {
            if ([string]$candidate.Name -ieq [string]$currentFile.Name) { $before = $candidate; break }
        }
        $beforeExists = ($null -ne $before -and (ConvertTo-KuduBoolean (Get-ObjectPropertyValue $before 'Exists' $false)))
        $changedFromBaseline = $false
        if ($baselineHttpStatus -eq 200) {
            if (-not $beforeExists -and $currentFile.Exists) { $changedFromBaseline = $true }
            elseif ($beforeExists -and $currentFile.Exists) {
                if ([long]$currentFile.SizeBytes -ne [long]$before.SizeBytes) { $changedFromBaseline = $true }
                elseif (-not [string]::IsNullOrWhiteSpace([string]$currentFile.ModifiedTime) -and [string]$currentFile.ModifiedTime -ne [string]$before.ModifiedTime) { $changedFromBaseline = $true }
            }
        }
        $modified = ConvertTo-KuduUtcDateTime $currentFile.ModifiedTime
        $freshForSubmission = ($currentFile.Exists -and $null -ne $modified -and $null -ne $submitted -and $modified -ge $submitted.AddMinutes(-5))
        $changedOrFresh = ($changedFromBaseline -or $freshForSubmission)
        if ([string]$currentFile.Name -ieq 'DngrmsDemo.Web.dll') { $mainChangedOrFresh = $changedOrFresh }
        $changes += [pscustomobject][ordered]@{
            Name=[string]$currentFile.Name
            Exists=[bool]$currentFile.Exists
            SizeBytes=[long]$currentFile.SizeBytes
            ModifiedTime=[string]$currentFile.ModifiedTime
            BaselineExists=$beforeExists
            BaselineSizeBytes=if ($null -ne $before) { [long]$before.SizeBytes } else { 0L }
            BaselineModifiedTime=if ($null -ne $before) { [string]$before.ModifiedTime } else { '' }
            ChangedFromBaseline=$changedFromBaseline
            FreshForSubmission=$freshForSubmission
            ChangedOrFresh=$changedOrFresh
        }
    }

    $contractReady = (ConvertTo-KuduBoolean (Get-ObjectPropertyValue $Current 'Ready' $false))
    $identityMatched = (ConvertTo-KuduBoolean (Get-ObjectPropertyValue $Current 'IdentityMatched' $false))
    if ($identityMatched) { $mainChangedOrFresh = $true }
    return [pscustomobject][ordered]@{
        ContractReady=$contractReady
        IdentityMatched=$identityMatched
        ExpectedPackageId=[string](Get-ObjectPropertyValue $Current 'ExpectedPackageId' '')
        ActualPackageId=[string](Get-ObjectPropertyValue $Current 'ActualPackageId' '')
        MainAssemblyChangedOrFresh=$mainChangedOrFresh
        TerminalContentReady=($contractReady -and $identityMatched)
        MissingFiles=@(Get-ObjectPropertyValue $Current 'MissingFiles' @())
        FileChanges=$changes
        BaselineHttpStatus=$baselineHttpStatus
    }
}

function Get-KuduWwwrootFingerprint {
    param($Snapshot)
    $parts = @()
    $files = @(Get-ObjectPropertyValue $Snapshot 'Files' @())
    foreach ($file in @($files | Sort-Object -Property Name)) {
        $parts += ('{0}:{1}:{2}:{3}' -f [string]$file.Name,[bool]$file.Exists,[long]$file.SizeBytes,[string]$file.ModifiedTime)
    }
    $parts += ('package-id:{0}:identity-match:{1}' -f [string](Get-ObjectPropertyValue $Snapshot 'ActualPackageId' ''),[bool](Get-ObjectPropertyValue $Snapshot 'IdentityMatched' $false))
    return ($parts -join '|')
}

function Get-KuduHttpStatusLabel {
    param($Http)
    if ($null -eq $Http) { return 'n/a' }
    return [string](Get-ObjectPropertyValue $Http 'StatusCode' 'n/a')
}

function Write-KuduReconciliationConsole {
    param([Parameter(Mandatory)][int]$Cycle, [Parameter(Mandatory)]$Recovery)
    $tempGet = Get-KuduHttpStatusLabel (Get-ObjectPropertyValue $Recovery.ExactTemporaryDeployment 'Http' $null)
    $tempLogHttp = Get-KuduHttpStatusLabel (Get-ObjectPropertyValue $Recovery.TemporaryDeploymentLog 'Http' $null)
    $latestHttp = Get-KuduHttpStatusLabel (Get-ObjectPropertyValue $Recovery.Latest 'Http' $null)
    $listHttp = Get-KuduHttpStatusLabel (Get-ObjectPropertyValue $Recovery.DeploymentList 'Http' $null)
    $finalGet = Get-KuduHttpStatusLabel (Get-ObjectPropertyValue $Recovery.CandidateFinalDeployment 'Http' $null)
    $finalLogHttp = Get-KuduHttpStatusLabel (Get-ObjectPropertyValue $Recovery.CandidateFinalDeploymentLog 'Http' $null)
    $matchedGet = Get-KuduHttpStatusLabel (Get-ObjectPropertyValue $Recovery.DirectMatchedDeployment 'Http' $null)
    $matchedLogHttp = Get-KuduHttpStatusLabel (Get-ObjectPropertyValue $Recovery.MatchedDeploymentLog 'Http' $null)
    Write-Host ("Kudu reconcile {0}: temp GET={1}; temp log={2}; latest={3}; list/history={4}; final GET={5}; final log={6}; matched GET={7}; matched log={8}" -f $Cycle,$tempGet,$tempLogHttp,$latestHttp,$listHttp,$finalGet,$finalLogHttp,$matchedGet,$matchedLogHttp)

    $tempRecord = Get-ObjectPropertyValue $Recovery.ExactTemporaryDeployment 'Record' $null
    $tempStatus = if ($null -ne $tempRecord -and $null -ne $tempRecord.Status) { [string]$tempRecord.Status } else { 'unknown' }
    Write-Host ("  temp result: Id={0}; Status={1}; Complete={2}; HTTP={3}" -f $(if ($null -ne $tempRecord) { [string]$tempRecord.Id } else { [string]$Recovery.Correlation.TempDeploymentId }),$tempStatus,$(if ($null -ne $tempRecord) { [bool]$tempRecord.Complete } else { $false }),$tempGet)

    $latestRecord = Get-ObjectPropertyValue $Recovery.Latest 'Record' $null
    $latestStatus = if ($null -ne $latestRecord -and $null -ne $latestRecord.Status) { [string]$latestRecord.Status } else { 'unknown' }
    Write-Host ("  latest result: Id={0}; Status={1}; Complete={2}; HTTP={3}" -f $(if ($null -ne $latestRecord) { [string]$latestRecord.Id } else { '' }),$latestStatus,$(if ($null -ne $latestRecord) { [bool]$latestRecord.Complete } else { $false }),$latestHttp)

    $listRecords = @($Recovery.DeploymentList.Records)
    $listPreview = @()
    foreach ($record in @($listRecords | Select-Object -First 6)) {
        $recordStatus = if ($null -ne $record.Status) { [string]$record.Status } else { 'unknown' }
        $listPreview += ("{0}:{1}" -f [string]$record.Id,$recordStatus)
    }
    $listPreviewText = if ($listPreview.Count -eq 0) { 'none' } else { $listPreview -join ', ' }
    Write-Host ("  list/history result: Count={0}; Preview={1}; HTTP={2}" -f $listRecords.Count,$listPreviewText,$listHttp)

    $match = Get-ObjectPropertyValue $Recovery 'MatchedDeployment' $null
    if ($null -ne $match -and $null -ne $match.Record) {
        $statusLabel = if ($null -ne $match.Record.Status) { [string]$match.Record.Status } else { 'unknown' }
        Write-Host ("  matched deployment: Id={0}; Status={1}; Complete={2}; Temporary={3}; Reason={4}" -f [string]$match.Record.Id,$statusLabel,[bool]$match.Record.Complete,[bool]$match.Record.IsTemporary,[string]$match.MatchReason)
    }
    else { Write-Host '  matched deployment: none' }

    # The final id returned by the Location response is never replaced by a temp match.
    if ($null -ne $Recovery.CandidateFinalDeployment) {
        Write-KuduDeploymentLogConsole -Label 'FINAL' -RecordSnapshot $Recovery.CandidateFinalDeployment -LogSnapshot $Recovery.CandidateFinalDeploymentLog
    }
    elseif ($null -ne $Recovery.DirectMatchedDeployment) {
        Write-KuduDeploymentLogConsole -Label 'MATCHED' -RecordSnapshot $Recovery.DirectMatchedDeployment -LogSnapshot $Recovery.MatchedDeploymentLog
    }

    $tempLogEntries = @((Get-ObjectPropertyValue $Recovery.TemporaryDeploymentLog 'Entries' @()))
    $finalLogEntries = @((Get-ObjectPropertyValue $Recovery.CandidateFinalDeploymentLog 'Entries' @()))
    Write-Host ("  log summary: TempEntries={0}; FinalEntries={1}; TempFailure={2}; FinalFailure={3}" -f $tempLogEntries.Count,$finalLogEntries.Count,$(ConvertTo-KuduBoolean (Get-ObjectPropertyValue $Recovery.TemporaryDeploymentLog 'HasExplicitFailure' $false)),$(ConvertTo-KuduBoolean (Get-ObjectPropertyValue $Recovery.CandidateFinalDeploymentLog 'HasExplicitFailure' $false)))

    $missing = @($Recovery.WwwrootChange.MissingFiles)
    $missingText = if ($missing.Count -eq 0) { 'none' } else { $missing -join ',' }
    $wwwHttp = Get-KuduHttpStatusLabel $Recovery.WwwrootContract.Http
    $healthHttp = Get-KuduHttpStatusLabel $Recovery.Health.Http
    Write-Host ("  readiness: wwwroot HTTP={0}; ContractReady={1}; IdentityMatched={2}; PackageId={3}; Missing={4}; health HTTP={5}; Status={6}; Database={7}; HealthyConnected={8}; ExplicitFailure={9}" -f $wwwHttp,[bool]$Recovery.WwwrootChange.ContractReady,[bool]$Recovery.WwwrootChange.IdentityMatched,[string]$Recovery.WwwrootChange.ActualPackageId,$missingText,$healthHttp,[string]$Recovery.Health.Status,[string]$Recovery.Health.Database,[bool]$Recovery.Health.HealthyConnected,[bool]$Recovery.ExplicitFailure)
}

function Get-KuduDeploymentFailureClassification {
    param($Recovery)
    $parts = @()
    foreach ($snapshotName in @('CandidateFinalDeployment','DirectMatchedDeployment','ExactTemporaryDeployment','Latest')) {
        $snapshot = Get-ObjectPropertyValue $Recovery $snapshotName $null
        $record = Get-ObjectPropertyValue $snapshot 'Record' $null
        if ($null -ne $record) {
            $parts += [string]$record.StatusText
            $parts += [string]$record.Message
            $parts += [string]$record.Progress
        }
    }
    foreach ($logName in @('CandidateFinalDeploymentLog','MatchedDeploymentLog','TemporaryDeploymentLog')) {
        $log = Get-ObjectPropertyValue $Recovery $logName $null
        foreach ($entry in @((Get-ObjectPropertyValue $log 'Entries' @()))) {
            $parts += [string]$entry.Message
            if ($null -ne $entry.Details) { $parts += [string](Get-ObjectPropertyValue $entry.Details 'Content' '') }
        }
    }
    $text = Protect-KuduDiagnosticText -Text ($parts -join ' | ') -MaximumLength 12000
    $category = 'KuduDeploymentFailureUnknown'
    $repairable = $false
    $repairAction = 'No automatic retry because the retrieved failure text did not prove a safe repair path.'

    if ($text -match '(?i)locked|resource busy|in use|EBUSY|ETXTBSY|access.+denied|permission denied|unauthorizedaccessexception|read-only file system|cannot delete|failed to delete|directory not empty|file exists|copy.+failed|failed.+copy') {
        $category = 'FileSystemContentConflict'
        $repairable = $true
        $repairAction = 'Reassert package-based deployment and no-build SCM settings, recycle the worker, wait for SCM readiness, and retry once.'
    }
    elseif ($text -match '(?i)run.from.package|sitepackages|packagename\.txt|wwwroot.+read.only|package.+mount') {
        $category = 'RunFromPackageTransition'
        $repairable = $true
        $repairAction = 'Reassert WEBSITE_RUN_FROM_PACKAGE=1, recycle the worker, wait for SCM readiness, and retry once.'
    }
    elseif ($text -match '(?i)timed?\s*out|timeout|connection.+reset|temporar(?:y|ily)|deployment.+in progress|another deployment|service unavailable|gateway timeout|HTTP\s*(409|423|429|500|502|503|504)') {
        $category = 'TransientScmFailure'
        $repairable = $true
        $repairAction = 'Recycle once, wait for SCM readiness, and retry the same validated package once.'
    }
    elseif ($text -match '(?i)no space left|quota|disk.+full|ENOSPC') {
        $category = 'StorageQuotaFailure'
        $repairAction = 'Free App Service storage or increase capacity before retrying.'
    }
    elseif ($text -match '(?i)central directory|invalid.+zip|corrupt.+zip|cannot.+extract|failed.+extract|bad.+archive') {
        $category = 'InvalidOrUnextractablePackage'
        $repairAction = 'Rebuild Menu 19 output and validate the ZIP; do not retry the same package.'
    }
    elseif ($text -match '(?i)oryx|build.+failed|dotnet.+publish|restore.+failed|compilation') {
        $category = 'UnexpectedBuildFailure'
        $repairAction = 'Keep SCM/Oryx build disabled for the framework-dependent publish output and inspect why build automation was invoked.'
    }

    return [pscustomobject][ordered]@{
        Phase='Deployment'
        Category=$category
        Repairable=$repairable
        RepairAction=$repairAction
        EvidenceText=$text
    }
}

function Invoke-KuduDeploymentReconciliation {
    param(
        [Parameter(Mandatory)]$Correlation,
        [Parameter(Mandatory)][string]$BearerToken,
        $BaselineWwwroot,
        [string]$CandidateDeploymentId
    )
    $exactTemporary = $null
    $tempLog = $null
    $tempId = [string](Get-ObjectPropertyValue $Correlation 'TempDeploymentId' '')
    if (-not [string]::IsNullOrWhiteSpace($tempId)) {
        $exactTemporary = Get-KuduDeploymentRecordSnapshot -DeploymentId $tempId -BearerToken $BearerToken
        $tempLog = Get-KuduDeploymentLogSnapshot -DeploymentId $tempId -BearerToken $BearerToken
    }

    $candidateFinal = $null
    $candidateFinalLog = $null
    if (-not [string]::IsNullOrWhiteSpace($CandidateDeploymentId) -and $CandidateDeploymentId -ne $tempId) {
        $candidateFinal = Get-KuduDeploymentRecordSnapshot -DeploymentId $CandidateDeploymentId -BearerToken $BearerToken
        $candidateFinalLog = Get-KuduDeploymentLogSnapshot -DeploymentId $CandidateDeploymentId -BearerToken $BearerToken
    }

    $latest = Get-KuduLatestDeploymentSnapshot -BearerToken $BearerToken
    $collection = Get-KuduDeploymentCollectionSnapshot -BearerToken $BearerToken
    $records = @()
    if ($null -ne $exactTemporary -and $null -ne $exactTemporary.Record) { $records += $exactTemporary.Record }
    if ($null -ne $candidateFinal -and $null -ne $candidateFinal.Record) { $records += $candidateFinal.Record }
    if ($null -ne $latest.Record) { $records += $latest.Record }
    foreach ($record in @($collection.Records)) { $records += $record }

    $match = $null
    if ($null -ne $candidateFinal -and $null -ne $candidateFinal.Record) {
        $match = [pscustomobject][ordered]@{ Matched=$true; MatchReason='Final deployment id returned by submission Location'; Score=2000; Record=$candidateFinal.Record }
    }
    else {
        $match = Find-CorrelatedKuduDeployment -Records $records -Correlation $Correlation
    }

    $directMatched = $null
    $directMatchedLog = $null
    if ($null -ne $match -and $null -ne $match.Record -and -not [string]::IsNullOrWhiteSpace([string]$match.Record.Id)) {
        $matchedId = [string]$match.Record.Id
        if ($null -ne $candidateFinal -and $matchedId -eq [string]$candidateFinal.DeploymentId) {
            $directMatched = $candidateFinal
            $directMatchedLog = $candidateFinalLog
        }
        elseif ($matchedId -eq $tempId) {
            $directMatched = $exactTemporary
            $directMatchedLog = $tempLog
        }
        else {
            $directMatched = Get-KuduDeploymentRecordSnapshot -DeploymentId $matchedId -BearerToken $BearerToken
            $directMatchedLog = Get-KuduDeploymentLogSnapshot -DeploymentId $matchedId -BearerToken $BearerToken
        }
    }

    $wwwroot = Get-KuduWwwrootContractSnapshot -BearerToken $BearerToken
    $wwwrootChange = Compare-KuduWwwrootContract -Baseline $BaselineWwwroot -Current $wwwroot -SubmittedUtc ([string]$Correlation.SubmittedUtc)
    $health = Get-HealthContractProbe

    $explicitFailure = $false
    $positiveLog = $false
    $failureSources = @()
    $seenRecordIds = @{}
    foreach ($snapshot in @($exactTemporary,$candidateFinal,$directMatched)) {
        if ($null -eq $snapshot -or $null -eq $snapshot.Record) { continue }
        $record = $snapshot.Record
        $recordId = [string]$record.Id
        if ($seenRecordIds.ContainsKey($recordId)) { continue }
        $seenRecordIds[$recordId] = $true
        if ($null -ne $record.Status -and [int]$record.Status -eq 3) {
            $explicitFailure = $true
            $failureSources += "deployment status 3: $recordId"
        }
        elseif ($record.Complete -and ($null -eq $record.Status -or [int]$record.Status -ne 4)) {
            $explicitFailure = $true
            $failureSources += "completed without status 4: $recordId"
        }
    }

    $seenLogIds = @{}
    foreach ($log in @($tempLog,$candidateFinalLog,$directMatchedLog)) {
        if ($null -eq $log) { continue }
        $logId = [string]$log.DeploymentId
        if ($seenLogIds.ContainsKey($logId)) { continue }
        $seenLogIds[$logId] = $true
        if ($log.HasExplicitFailure) {
            $explicitFailure = $true
            $failureSources += "deployment log failure: $logId"
        }
        if ($log.HasPositiveCompletion) { $positiveLog = $true }
    }

    $matchedStatus4 = $false
    if ($null -ne $match -and $null -ne $match.Record -and $null -ne $match.Record.Status) { $matchedStatus4 = ([int]$match.Record.Status -eq 4) }
    $crossValidatedSuccess = ($matchedStatus4 -and $wwwrootChange.ContractReady -and $health.HealthyConnected -and -not $explicitFailure)

    $result = [pscustomobject][ordered]@{
        CapturedUtc=[DateTime]::UtcNow.ToString('o')
        Correlation=$Correlation
        ExactTemporaryDeployment=$exactTemporary
        TemporaryDeploymentLog=$tempLog
        CandidateFinalDeployment=$candidateFinal
        CandidateFinalDeploymentLog=$candidateFinalLog
        Latest=$latest
        DeploymentList=$collection
        DirectMatchedDeployment=$directMatched
        MatchedDeployment=$match
        MatchedDeploymentLog=$directMatchedLog
        WwwrootContract=$wwwroot
        BaselineWwwrootContract=$BaselineWwwroot
        WwwrootChange=$wwwrootChange
        Health=$health
        ExplicitFailure=$explicitFailure
        FailureSources=$failureSources
        PositiveCompletionLog=$positiveLog
        MatchedStatus4=$matchedStatus4
        CrossValidatedSuccess=$crossValidatedSuccess
        FailureClassification=$null
    }
    if ($explicitFailure) { $result.FailureClassification = Get-KuduDeploymentFailureClassification -Recovery $result }
    return $result
}

function Submit-KuduZipDeployment {
    param([Parameter(Mandatory)][string]$ZipPath, [Parameter(Mandatory)][string]$BearerToken)
    Write-Step 'Publishing ZIP through Kudu SCM with an Entra bearer token...'
    $submittedUtc = [DateTime]::UtcNow.ToString('o')
    $submitUri = "$(Get-KuduBaseUrl)/api/zipdeploy?isAsync=true"
    $response = Invoke-KuduRequest -Method POST -Uri $submitUri -BearerToken $BearerToken -ContentType 'application/zip' `
        -UploadFilePath $ZipPath -TimeoutSeconds 600
    if ($response.StatusCode -notin @(200,202)) {
        throw "Kudu ZIP submission failed. HTTP=$($response.StatusCode); Category=$($response.FailureCategory); Location=$($response.Location); Body=$(Get-SafeBodySnippet $response.Body)"
    }
    $pollUri = Resolve-DeploymentStatusUri -Location $response.Location
    $submissionObject = ConvertFrom-KuduResponseJson -Response $response
    $submissionSummary = Get-KuduDeploymentSummary -Deployment $submissionObject
    $correlation = [pscustomobject][ordered]@{
        SubmittedUtc=$submittedUtc
        Location=$pollUri
        LocationDeployer=(Get-UriQueryParameterValue -UriText $pollUri -Name 'deployer')
        LocationTime=(Get-UriQueryParameterValue -UriText $pollUri -Name 'time')
        TempDeploymentId=if ($null -ne $submissionSummary) { [string]$submissionSummary.Id } else { '' }
        Deployer=if ($null -ne $submissionSummary) { [string]$submissionSummary.Deployer } else { '' }
        ReceivedTime=if ($null -ne $submissionSummary) { [string]$submissionSummary.ReceivedTime } else { '' }
        Message=if ($null -ne $submissionSummary) { [string]$submissionSummary.Message } else { '' }
        FirstSeenUtc=''
    }
    Write-Host "Kudu submit: HTTP=$($response.StatusCode) $($response.StatusDescription); Location=$pollUri"
    return [pscustomobject][ordered]@{
        Submit=(ConvertTo-HttpEvidenceSummary $response)
        PollUri=$pollUri
        Correlation=$correlation
    }
}

function Invoke-KuduDeploymentRepair {
    param(
        [Parameter(Mandatory)]$FailureClassification,
        [Parameter(Mandatory)][string]$BearerToken
    )
    if (-not (ConvertTo-KuduBoolean (Get-ObjectPropertyValue $FailureClassification 'Repairable' $false))) {
        throw 'Automatic deployment repair was requested for a failure that was not classified as repairable.'
    }
    Write-Step ("Applying one bounded deployment repair. Category={0}; Action={1}" -f [string]$FailureClassification.Category,[string]$FailureClassification.RepairAction)
    $before = Get-RedactedMenu24Settings -Settings (Get-AzWebAppSettingsHashtable)
    Set-AzWebAppSettingsSafe @{
        'WEBSITE_RUN_FROM_PACKAGE'='1'
        'SCM_DO_BUILD_DURING_DEPLOYMENT'='false'
        'ENABLE_ORYX_BUILD'='false'
        'WEBSITES_CONTAINER_START_TIME_LIMIT'='600'
        'WEBSITE_WARMUP_PATH'='/health'
        'WEBSITE_WARMUP_STATUSES'='200'
    }
    Restart-AzWebApp -ResourceGroupName $script:State.ResourceGroupName -Name $script:State.WebAppName | Out-Null
    $running = Ensure-WebAppRunning
    $scm = Wait-KuduReady -BearerToken $BearerToken -TimeoutSeconds 420
    $after = Get-RedactedMenu24Settings -Settings (Get-AzWebAppSettingsHashtable)
    return [pscustomobject][ordered]@{
        CapturedUtc=[DateTime]::UtcNow.ToString('o')
        Category=[string]$FailureClassification.Category
        RepairAction=[string]$FailureClassification.RepairAction
        Before=$before
        After=$after
        RestartInvoked=$true
        WebAppReadiness=$running
        ScmReadiness=$scm
        SeedSettingsChanged=$false
        HomeDataChanged=$false
    }
}

function Confirm-PostDeploymentStartupContract {
    param([Parameter(Mandatory)][string]$BearerToken)
    $expected = [string]$script:ActiveAzureStartupCommand
    $before = Get-AppServiceSiteConfigSnapshot
    $reapplied = $false
    $transition = $null
    if ($before.StartupCommand -ne $expected -or $before.LinuxFxVersion -ne $script:ActiveAzureLinuxFxVersion) {
        Write-WarningMessage "The persisted post-deployment startup contract drifted. Expected=$expected; Actual=$($before.StartupCommand). Reapplying the selected contract."
        $transition = Set-LinuxAppServiceStartupContract -PackageDeploymentMode $script:ActiveAzureDeploymentMode -LinuxFxVersion $script:ActiveAzureLinuxFxVersion
        Restart-AzWebApp -ResourceGroupName $script:State.ResourceGroupName -Name $script:State.WebAppName | Out-Null
        $reapplied = $true
        $null = Ensure-WebAppRunning
        $null = Wait-KuduReady -BearerToken $BearerToken -TimeoutSeconds 300
    }
    $after = Get-AppServiceSiteConfigSnapshot
    $verified = ($after.StartupCommand -eq $expected -and $after.LinuxFxVersion -eq $script:ActiveAzureLinuxFxVersion)
    if (-not $verified) { throw "Post-deployment startup contract verification failed. Expected=$expected; Actual=$($after.StartupCommand); linuxFxVersion=$($after.LinuxFxVersion)." }
    return [pscustomobject][ordered]@{
        CapturedUtc=[DateTime]::UtcNow.ToString('o')
        PackageDeploymentMode=$script:ActiveAzureDeploymentMode
        ExpectedStartupCommand=$expected
        Before=$before
        Reapplied=$reapplied
        Transition=$transition
        After=$after
        Verified=$verified
        FrameworkDependentCommandAbsent=($script:ActiveAzureDeploymentMode -ne 'SelfContainedLinuxX64' -or $after.StartupCommand -ne 'dotnet DngrmsDemo.Web.dll')
    }
}

function Get-RuntimePackageIdentityProbe {
    param([Parameter(Mandatory)]$ExpectedPackageIdentity, [string]$Label = 'Runtime')
    $expectedId = [string](Get-ObjectPropertyValue $ExpectedPackageIdentity 'PackageId' '')
    $uri = "$(Get-WebAppBaseUrl)/dngrms-package-identity.json?packageId=$expectedId"
    $response = Invoke-DngrmsHttpRequest -Method GET -Uri $uri -TimeoutSeconds 60
    $identity = ConvertFrom-KuduResponseJson -Response $response
    $actualId = [string](Get-ObjectPropertyValue $identity 'PackageId' '')
    $actualMode = [string](Get-ObjectPropertyValue $identity 'PackageDeploymentMode' '')
    $actualStartup = [string](Get-ObjectPropertyValue $identity 'StartupCommand' '')
    $expectedMode = [string](Get-ObjectPropertyValue $ExpectedPackageIdentity 'PackageDeploymentMode' '')
    $expectedStartup = [string](Get-ObjectPropertyValue $ExpectedPackageIdentity 'StartupCommand' '')
    $matched = ($response.StatusCode -eq 200 -and $actualId -eq $expectedId -and $actualMode -eq $expectedMode -and $actualStartup -eq $expectedStartup)
    return [pscustomobject][ordered]@{
        CapturedUtc=[DateTime]::UtcNow.ToString('o')
        Label=$Label
        Http=(ConvertTo-HttpEvidenceSummary $response)
        ExpectedPackageId=$expectedId
        ActualPackageId=$actualId
        ExpectedMode=$expectedMode
        ActualMode=$actualMode
        ExpectedStartupCommand=$expectedStartup
        ActualStartupCommand=$actualStartup
        IdentityMatched=$matched
        RuntimeContainerServedIdentity=($response.StatusCode -eq 200)
        Identity=$identity
    }
}

function Assert-RuntimePackageIdentity {
    param([Parameter(Mandatory)]$ExpectedPackageIdentity, [string]$Label = 'Runtime')
    Write-Step "Verifying the mounted package identity through the running app container ($Label)..."
    $probe = Get-RuntimePackageIdentityProbe -ExpectedPackageIdentity $ExpectedPackageIdentity -Label $Label
    if (-not $probe.IdentityMatched) {
        throw "Runtime package identity mismatch. Expected=$($probe.ExpectedPackageId); Actual=$($probe.ActualPackageId); HTTP=$($probe.Http.StatusCode); Mode=$($probe.ActualMode); Startup=$($probe.ActualStartupCommand)."
    }
    return $probe
}

function Wait-KuduDeployment {
    <# Deployment and runtime readiness are deliberately separate.
       Phase 1 polls only the authoritative async Location and stops at the
       first terminal Kudu status. Phase 2 verifies the persisted startup
       contract, recycles the main worker once so Run-From-Package is mounted,
       and performs at most three health probes. Kudu/SCM wwwroot is retained
       as diagnostic evidence only; it is not the main worker's package mount. #>
    param(
        [Parameter(Mandatory)][string]$PollUri,
        [Parameter(Mandatory)][string]$BearerToken,
        [Parameter(Mandatory)]$CorrelationSeed,
        $BaselineWwwroot,
        [int]$TimeoutSeconds = 300,
        [int]$PollIntervalSeconds = 10,
        [ValidateRange(1,20)][int]$MaxPollCount = 12
    )
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $history = @()
    $recoveryHistory = @()
    $restartHistory = @()
    $runtimeDiagnosticsHistory = @()
    $runtimeRepairHistory = @()
    $runtimeHealthHistory = @()
    $correlation = $CorrelationSeed
    $candidateDeploymentId = ''
    $terminalDeployment = $null
    $terminalRecovery = $null
    $postDeploymentStartupContract = $null
    $locationStoppedUtc = ''

    for ($cycle = 1; $cycle -le $MaxPollCount -and [DateTime]::UtcNow -lt $deadline; $cycle++) {
        $response = Invoke-KuduRequest -Method GET -Uri $PollUri -BearerToken $BearerToken -TimeoutSeconds 60
        $deploymentObject = ConvertFrom-KuduResponseJson -Response $response
        $deployment = Get-KuduDeploymentSummary -Deployment $deploymentObject
        $statusKnown = ($null -ne $deployment -and $null -ne $deployment.Status)
        $status = if ($statusKnown) { [int]$deployment.Status } else { -1 }
        $statusText = if ($null -ne $deployment) { [string]$deployment.StatusText } else { '' }
        $deploymentId = if ($null -ne $deployment) { [string]$deployment.Id } else { '' }
        if (-not [string]::IsNullOrWhiteSpace($deploymentId)) {
            $candidateDeploymentId = $deploymentId
            if ([string]::IsNullOrWhiteSpace([string]$correlation.TempDeploymentId)) { $correlation.TempDeploymentId = $deploymentId }
        }
        if ($null -ne $deployment) {
            if ([string]::IsNullOrWhiteSpace([string]$correlation.Deployer) -and -not [string]::IsNullOrWhiteSpace([string]$deployment.Deployer)) { $correlation.Deployer = [string]$deployment.Deployer }
            if ([string]::IsNullOrWhiteSpace([string]$correlation.ReceivedTime) -and -not [string]::IsNullOrWhiteSpace([string]$deployment.ReceivedTime)) { $correlation.ReceivedTime = [string]$deployment.ReceivedTime }
            if ([string]::IsNullOrWhiteSpace([string]$correlation.Message) -and -not [string]::IsNullOrWhiteSpace([string]$deployment.Message)) { $correlation.Message = [string]$deployment.Message }
            if ([string]::IsNullOrWhiteSpace([string]$correlation.FirstSeenUtc)) { $correlation.FirstSeenUtc = [DateTime]::UtcNow.ToString('o') }
        }
        $statusLabel = if ($statusKnown) { [string]$status } else { 'unknown' }
        Write-Host "Kudu status poll ${cycle}/${MaxPollCount}: HTTP=$($response.StatusCode); DeploymentStatus=$statusLabel; Id=$deploymentId; StatusText=$statusText"
        $history += [pscustomobject][ordered]@{
            Cycle=$cycle; CapturedUtc=[DateTime]::UtcNow.ToString('o'); LocationRequestIssued=$true;
            PollUri=$PollUri; HttpStatus=$response.StatusCode; DeploymentStatus=if ($statusKnown) { $status } else { $null };
            StatusText=$statusText; DeploymentId=$deploymentId; Terminal=($status -in @(3,4))
        }

        if ($response.StatusCode -in @(401,403)) {
            return [pscustomobject][ordered]@{
                Outcome='Failed'; Determination='LocationAuthorizationFailure'; FailurePhase='Deployment'; FailureReason="Kudu Location request failed authorization with HTTP $($response.StatusCode)."; FailureClassification=$null;
                Deployment=$deploymentObject; History=$history; RecoveryHistory=$recoveryHistory; ReadinessRestartHistory=$restartHistory; PostDeploymentStartupContract=$null;
                RuntimeDiagnosticsHistory=$runtimeDiagnosticsHistory; RuntimeRepairHistory=$runtimeRepairHistory; RuntimeHealthHistory=$runtimeHealthHistory;
                FinalPollUri=$PollUri; LocationPollingStopped=$true; LocationStoppedUtc=[DateTime]::UtcNow.ToString('o'); Correlation=$correlation
            }
        }
        if ($response.StatusCode -notin @(0,200,202,404,409,423,429,500,502,503,504)) {
            return [pscustomobject][ordered]@{
                Outcome='Failed'; Determination='NonRetryableLocationHttpFailure'; FailurePhase='Deployment'; FailureReason="Kudu Location request returned HTTP $($response.StatusCode) $($response.StatusDescription). Category=$($response.FailureCategory)."; FailureClassification=$null;
                Deployment=$deploymentObject; History=$history; RecoveryHistory=$recoveryHistory; ReadinessRestartHistory=$restartHistory; PostDeploymentStartupContract=$null;
                RuntimeDiagnosticsHistory=$runtimeDiagnosticsHistory; RuntimeRepairHistory=$runtimeRepairHistory; RuntimeHealthHistory=$runtimeHealthHistory;
                FinalPollUri=$PollUri; LocationPollingStopped=$true; LocationStoppedUtc=[DateTime]::UtcNow.ToString('o'); Correlation=$correlation
            }
        }

        if ($statusKnown -and $status -eq 3) {
            $terminalRecovery = Invoke-KuduDeploymentReconciliation -Correlation $correlation -BearerToken $BearerToken -BaselineWwwroot $BaselineWwwroot -CandidateDeploymentId $candidateDeploymentId
            $recoveryHistory += $terminalRecovery
            Write-KuduReconciliationConsole -Cycle $cycle -Recovery $terminalRecovery
            $classification = Get-KuduDeploymentFailureClassification -Recovery $terminalRecovery
            return [pscustomobject][ordered]@{
                Outcome='Failed'; Determination='ExplicitCorrelatedDeploymentFailure'; FailurePhase='Deployment'; FailureReason="Authoritative Kudu deployment reached status 3. Id=$deploymentId; StatusText=$statusText"; FailureClassification=$classification;
                Deployment=$deployment; History=$history; RecoveryHistory=$recoveryHistory; ReadinessRestartHistory=$restartHistory; PostDeploymentStartupContract=$null;
                RuntimeDiagnosticsHistory=$runtimeDiagnosticsHistory; RuntimeRepairHistory=$runtimeRepairHistory; RuntimeHealthHistory=$runtimeHealthHistory;
                FinalPollUri=''; LocationPollingStopped=$true; LocationStoppedUtc=[DateTime]::UtcNow.ToString('o'); Correlation=$correlation
            }
        }
        if ($statusKnown -and $status -eq 4) {
            $terminalDeployment = $deployment
            $locationStoppedUtc = [DateTime]::UtcNow.ToString('o')
            Write-Success "Kudu deployment reached status 4 on poll $cycle. Deployment polling is finished; runtime readiness is now evaluated separately."
            break
        }

        if ($response.StatusCode -eq 404) {
            $fallback = Invoke-KuduDeploymentReconciliation -Correlation $correlation -BearerToken $BearerToken -BaselineWwwroot $BaselineWwwroot -CandidateDeploymentId $candidateDeploymentId
            $recoveryHistory += $fallback
            if ($fallback.ExplicitFailure) {
                $classification = Get-KuduDeploymentFailureClassification -Recovery $fallback
                return [pscustomobject][ordered]@{
                    Outcome='Failed'; Determination='ExplicitCorrelatedDeploymentFailure'; FailurePhase='Deployment'; FailureReason='The Location URL returned 404 and correlated Kudu evidence reported a deployment failure.'; FailureClassification=$classification;
                    Deployment=if ($null -ne $fallback.MatchedDeployment) { $fallback.MatchedDeployment.Record } else { $deploymentObject }; History=$history; RecoveryHistory=$recoveryHistory; ReadinessRestartHistory=$restartHistory; PostDeploymentStartupContract=$null;
                    RuntimeDiagnosticsHistory=$runtimeDiagnosticsHistory; RuntimeRepairHistory=$runtimeRepairHistory; RuntimeHealthHistory=$runtimeHealthHistory;
                    FinalPollUri=''; LocationPollingStopped=$true; LocationStoppedUtc=[DateTime]::UtcNow.ToString('o'); Correlation=$correlation
                }
            }
            if ($fallback.MatchedStatus4) {
                $terminalDeployment = $fallback.MatchedDeployment.Record
                $terminalRecovery = $fallback
                $locationStoppedUtc = [DateTime]::UtcNow.ToString('o')
                Write-Success "Correlated Kudu deployment reached status 4 after the Location URL returned 404. Deployment polling is finished."
                break
            }
        }
        if ($cycle -lt $MaxPollCount -and [DateTime]::UtcNow -lt $deadline) { Start-Sleep -Seconds $PollIntervalSeconds }
    }

    if ($null -eq $terminalDeployment) {
        return [pscustomobject][ordered]@{
            Outcome='Failed'; Determination='KuduStatus4NotObservedWithinBound'; FailurePhase='Deployment'; FailureReason="Kudu status 4 was not observed within $MaxPollCount polls and $TimeoutSeconds seconds."; FailureClassification=$null;
            Deployment=$null; History=$history; RecoveryHistory=$recoveryHistory; ReadinessRestartHistory=$restartHistory; PostDeploymentStartupContract=$null;
            RuntimeDiagnosticsHistory=$runtimeDiagnosticsHistory; RuntimeRepairHistory=$runtimeRepairHistory; RuntimeHealthHistory=$runtimeHealthHistory;
            FinalPollUri=''; LocationPollingStopped=$true; LocationStoppedUtc=[DateTime]::UtcNow.ToString('o'); Correlation=$correlation
        }
    }

    # One terminal reconciliation captures the final record/log and the SCM view.
    # Missing files in SCM wwwroot are diagnostic-only for Run-From-Package.
    if ($null -eq $terminalRecovery) {
        $terminalRecovery = Invoke-KuduDeploymentReconciliation -Correlation $correlation -BearerToken $BearerToken -BaselineWwwroot $BaselineWwwroot -CandidateDeploymentId $candidateDeploymentId
        $recoveryHistory += $terminalRecovery
    }
    Write-KuduReconciliationConsole -Cycle $history.Count -Recovery $terminalRecovery
    if ($terminalRecovery.ExplicitFailure) {
        $classification = Get-KuduDeploymentFailureClassification -Recovery $terminalRecovery
        return [pscustomobject][ordered]@{
            Outcome='Failed'; Determination='ExplicitFailureAfterStatus4Reconciliation'; FailurePhase='Deployment'; FailureReason='Final Kudu record/log reconciliation contained an explicit failure signal.'; FailureClassification=$classification;
            Deployment=$terminalDeployment; History=$history; RecoveryHistory=$recoveryHistory; ReadinessRestartHistory=$restartHistory; PostDeploymentStartupContract=$null;
            RuntimeDiagnosticsHistory=$runtimeDiagnosticsHistory; RuntimeRepairHistory=$runtimeRepairHistory; RuntimeHealthHistory=$runtimeHealthHistory;
            FinalPollUri=''; LocationPollingStopped=$true; LocationStoppedUtc=$locationStoppedUtc; Correlation=$correlation
        }
    }

    try {
        $postDeploymentStartupContract = Confirm-PostDeploymentStartupContract -BearerToken $BearerToken
    }
    catch {
        return [pscustomobject][ordered]@{
            Outcome='Failed'; Determination='PostDeploymentStartupContractMismatch'; FailurePhase='Runtime'; FailureReason=$_.Exception.Message; FailureClassification=$null;
            Deployment=$terminalDeployment; History=$history; RecoveryHistory=$recoveryHistory; ReadinessRestartHistory=$restartHistory; PostDeploymentStartupContract=$postDeploymentStartupContract;
            RuntimeDiagnosticsHistory=$runtimeDiagnosticsHistory; RuntimeRepairHistory=$runtimeRepairHistory; RuntimeHealthHistory=$runtimeHealthHistory;
            FinalPollUri=''; LocationPollingStopped=$true; LocationStoppedUtc=$locationStoppedUtc; Correlation=$correlation
        }
    }

    Write-Step 'Recycling the main Web App once so the new immutable package is mounted, then performing at most three runtime health probes...'
    try {
        $script:Menu24RuntimeLogNotBeforeUtc = [DateTime]::UtcNow
        Restart-AzWebApp -ResourceGroupName $script:State.ResourceGroupName -Name $script:State.WebAppName | Out-Null
        $restartHistory += [pscustomobject][ordered]@{ CapturedUtc=[DateTime]::UtcNow.ToString('o'); Invoked=$true; Succeeded=$true; Error=''; Phase='PostStatus4PackageMount' }
    }
    catch {
        $restartHistory += [pscustomobject][ordered]@{ CapturedUtc=[DateTime]::UtcNow.ToString('o'); Invoked=$true; Succeeded=$false; Error=$_.Exception.Message; Phase='PostStatus4PackageMount' }
        return [pscustomobject][ordered]@{
            Outcome='Failed'; Determination='PostStatus4RecycleFailed'; FailurePhase='Runtime'; FailureReason=$_.Exception.Message; FailureClassification=$null;
            Deployment=$terminalDeployment; History=$history; RecoveryHistory=$recoveryHistory; ReadinessRestartHistory=$restartHistory; PostDeploymentStartupContract=$postDeploymentStartupContract;
            RuntimeDiagnosticsHistory=$runtimeDiagnosticsHistory; RuntimeRepairHistory=$runtimeRepairHistory; RuntimeHealthHistory=$runtimeHealthHistory;
            FinalPollUri=''; LocationPollingStopped=$true; LocationStoppedUtc=$locationStoppedUtc; Correlation=$correlation
        }
    }
    Start-Sleep -Seconds 12
    $health = Wait-RuntimeHealthProbe -ProbeCount 3 -IntervalSeconds 12
    $runtimeHealthHistory += $health.History
    if ($health.Succeeded) {
        try {
            $identity = Assert-RuntimePackageIdentity -ExpectedPackageIdentity $script:ExpectedPackageIdentity -Label 'immediately after status 4 and package-mount recycle'
        }
        catch {
            return [pscustomobject][ordered]@{
                Outcome='Failed'; Determination='RuntimePackageIdentityMismatch'; FailurePhase='Runtime'; FailureReason=$_.Exception.Message; FailureClassification=$null;
                Deployment=$terminalDeployment; History=$history; RecoveryHistory=$recoveryHistory; ReadinessRestartHistory=$restartHistory; PostDeploymentStartupContract=$postDeploymentStartupContract;
                RuntimeDiagnosticsHistory=$runtimeDiagnosticsHistory; RuntimeRepairHistory=$runtimeRepairHistory; RuntimeHealthHistory=$runtimeHealthHistory;
                FinalPollUri=''; LocationPollingStopped=$true; LocationStoppedUtc=$locationStoppedUtc; Correlation=$correlation
            }
        }
        return [pscustomobject][ordered]@{
            Outcome='Succeeded'; Determination='KuduStatus4AndMainWorkerHealthyConnected'; FailurePhase=''; FailureReason=''; FailureClassification=$null;
            Deployment=$terminalDeployment; History=$history; RecoveryHistory=$recoveryHistory; ReadinessRestartHistory=$restartHistory; PostDeploymentStartupContract=$postDeploymentStartupContract;
            RuntimePackageIdentity=$identity; RuntimeDiagnosticsHistory=$runtimeDiagnosticsHistory; RuntimeRepairHistory=$runtimeRepairHistory; RuntimeHealthHistory=$runtimeHealthHistory;
            FinalPollUri=''; LocationPollingStopped=$true; LocationStoppedUtc=$locationStoppedUtc; Correlation=$correlation
        }
    }

    $diagnostic = Write-RuntimeStartupDiagnosticBundle -BearerToken $BearerToken -Trigger 'Kudu status 4 followed by three unsuccessful main-worker health probes' -RepairAttempt 0 -NotBeforeUtc $script:Menu24RuntimeLogNotBeforeUtc
    $runtimeDiagnosticsHistory += $diagnostic
    $classification = $diagnostic.Classification
    # The package, provider graph, native RID asset, ELF architecture and hash were
    # already validated before submission. After three failed main-worker probes,
    # print only current-cutover evidence and fail without any unrelated recycle.
    $repairable = $false
    return [pscustomobject][ordered]@{
        Outcome='Failed'; Determination='RuntimeStartupCauseFailFast'; FailurePhase='Runtime';
        FailureReason="Kudu reached status 4, but the main worker did not reach Healthy/Connected. The newest correlated startup exception was printed and no unrelated recycle loop was used. Category=$([string]$classification.Category)";
        FailureClassification=$classification; Deployment=$terminalDeployment; History=$history; RecoveryHistory=$recoveryHistory; ReadinessRestartHistory=$restartHistory; PostDeploymentStartupContract=$postDeploymentStartupContract;
        RuntimeDiagnosticsHistory=$runtimeDiagnosticsHistory; RuntimeRepairHistory=$runtimeRepairHistory; RuntimeHealthHistory=$runtimeHealthHistory;
        FinalPollUri=''; LocationPollingStopped=$true; LocationStoppedUtc=$locationStoppedUtc; Correlation=$correlation
    }
}

function Wait-HealthContract {
    param([int]$TimeoutSeconds = 600, [ValidateRange(1,3)][int]$ProbeCount = 3, [int]$IntervalSeconds = 12)
    Write-Step "Checking /health for Healthy/Connected with at most $ProbeCount probes..."
    $result = Wait-RuntimeHealthProbe -ProbeCount $ProbeCount -IntervalSeconds $IntervalSeconds
    if ($result.Succeeded) { return $result.Last }
    $last = $result.Last
    throw "/health did not reach Healthy/Connected after $ProbeCount probes. HTTP=$(Get-KuduHttpStatusLabel $last.Http); Status=$($last.Status); Database=$($last.Database)."
}

function Get-DemoStatusSnapshot {
    $uri = "$(Get-WebAppBaseUrl)/api/demo/status"
    $response = Invoke-DngrmsHttpRequest -Method GET -Uri $uri -TimeoutSeconds 60
    if ($response.StatusCode -ne 200) { throw "Demo status endpoint returned HTTP $($response.StatusCode). Body=$(Get-SafeBodySnippet $response.Body)" }
    try { $status = $response.Body | ConvertFrom-Json }
    catch { throw "Demo status endpoint did not return valid JSON. Body=$(Get-SafeBodySnippet $response.Body)" }
    return $status
}

function Get-KuduSqliteSnapshot {
    param(
        [Parameter(Mandatory)][string]$BearerToken,
        [int]$MaxAttempts = 5,
        [int]$RetryDelaySeconds = 5
    )
    $uri = "$(Get-KuduBaseUrl)/api/vfs/data/"
    $history = @()
    $response = $null
    $querySucceeded = $false
    $found = $null
    $size = 0L

    # The main app and the SCM/Kudu container warm independently. Confirm SCM readiness,
    # but do not treat a transient readiness failure as proof that SQLite is missing.
    try { $null = Wait-KuduReady -BearerToken $BearerToken -TimeoutSeconds 90 }
    catch { Write-Warning "SCM/Kudu readiness precheck did not complete. VFS retries will continue. Detail: $($_.Exception.Message)" }

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        $response = Invoke-KuduRequest -Method GET -Uri $uri -BearerToken $BearerToken -TimeoutSeconds 45
        $history += [pscustomobject][ordered]@{
            Attempt=$attempt
            CapturedUtc=[DateTime]::UtcNow.ToString('o')
            Http=(ConvertTo-HttpEvidenceSummary $response)
        }
        Write-Host ("Kudu SQLite VFS probe {0}/{1}: HTTP={2}; Category={3}" -f $attempt,$MaxAttempts,$response.StatusCode,$response.FailureCategory)

        if ($response.StatusCode -eq 200) {
            $querySucceeded = $true
            $parsed = ConvertFrom-KuduResponseJson -Response $response
            if ($null -ne $parsed) {
                foreach ($item in @($parsed)) {
                    if ([string](Get-ObjectPropertyValue $item 'name' '') -ieq 'dngrms-demo.db') { $found = $item; break }
                }
            }
            if ($null -ne $found) { [void][long]::TryParse([string](Get-ObjectPropertyValue $found 'size' '0'), [ref]$size) }
            break
        }

        if ($response.StatusCode -in @(401,403)) {
            throw "Kudu VFS authorization failed with HTTP $($response.StatusCode). Category=$($response.FailureCategory); Body=$(Get-SafeBodySnippet $response.Body)"
        }

        $retryable = ($response.StatusCode -in @(0,408,429,500,502,503,504) -or $response.FailureCategory -in @('TransportFailure','Timeout','ServerUnavailable','SiteDisabledStopped'))
        if (-not $retryable) { break }
        if ($attempt -lt $MaxAttempts) { Start-Sleep -Seconds $RetryDelaySeconds }
    }

    return [pscustomobject][ordered]@{
        CapturedUtc=[DateTime]::UtcNow.ToString('o')
        QuerySucceeded=$querySucceeded
        Attempts=$history.Count
        RetryHistory=$history
        Http=if ($null -ne $response) { ConvertTo-HttpEvidenceSummary $response } else { $null }
        Path='/home/data/dngrms-demo.db'
        Exists=($querySucceeded -and $null -ne $found -and $size -gt 0)
        SizeBytes=$size
        ModifiedTime=if ($null -ne $found) { [string](Get-ObjectPropertyValue $found 'mtime' '') } else { '' }
        FailureReason=if (-not $querySucceeded) { 'KuduVfsUnavailable' } elseif ($null -eq $found -or $size -le 0) { 'SQLiteFileMissingOrEmpty' } else { '' }
    }
}

function Test-SqliteRestartPersistence {
    param([Parameter(Mandatory)][string]$BearerToken)
    Write-Step 'Verifying SQLite creation, seeded users, and persistence across an App Service restart...'
    $sqliteBefore = Get-KuduSqliteSnapshot -BearerToken $BearerToken
    if (-not $sqliteBefore.QuerySucceeded) { throw "SQLite creation verification could not query Kudu VFS after $($sqliteBefore.Attempts) attempts. This is an SCM/Kudu transport failure, not proof that /home/data/dngrms-demo.db is missing. LastHTTP=$($sqliteBefore.Http.StatusCode); Category=$($sqliteBefore.Http.FailureCategory)." }
    if (-not $sqliteBefore.Exists) { throw "SQLite creation verification reached Kudu VFS successfully, but /home/data/dngrms-demo.db was missing or empty. HTTP=$($sqliteBefore.Http.StatusCode)." }
    $before = Get-DemoStatusSnapshot
    $beforeUsers = [int](Get-ObjectPropertyValue $before 'userCount' -1)
    $beforeAudit = [int](Get-ObjectPropertyValue $before 'auditCount' -1)
    if ($beforeUsers -lt 2) { throw "Seed verification failed before restart. Expected at least 2 users; found $beforeUsers." }
    Restart-AzWebApp -ResourceGroupName $script:State.ResourceGroupName -Name $script:State.WebAppName | Out-Null
    $healthAfterRestart = Wait-HealthContract -TimeoutSeconds 600
    $after = Get-DemoStatusSnapshot
    $afterUsers = [int](Get-ObjectPropertyValue $after 'userCount' -1)
    $afterAudit = [int](Get-ObjectPropertyValue $after 'auditCount' -1)
    $sqliteAfter = Get-KuduSqliteSnapshot -BearerToken $BearerToken
    if (-not $sqliteAfter.QuerySucceeded) { throw "SQLite persistence verification could not query Kudu VFS after $($sqliteAfter.Attempts) attempts. This is an SCM/Kudu transport failure, not proof that /home/data/dngrms-demo.db is missing. LastHTTP=$($sqliteAfter.Http.StatusCode); Category=$($sqliteAfter.Http.FailureCategory)." }
    if (-not $sqliteAfter.Exists) { throw "SQLite persistence verification reached Kudu VFS successfully, but /home/data/dngrms-demo.db was missing or empty. HTTP=$($sqliteAfter.Http.StatusCode)." }
    if ($beforeUsers -ne $afterUsers) { throw "SQLite persistence failed: user count changed from $beforeUsers to $afterUsers after restart." }
    return [pscustomobject][ordered]@{
        SqliteBeforeRestart=$sqliteBefore; SqliteAfterRestart=$sqliteAfter;
        BeforeUserCount=$beforeUsers; AfterUserCount=$afterUsers;
        BeforeAuditCount=$beforeAudit; AfterAuditCount=$afterAudit;
        HealthAfterRestart=$healthAfterRestart; SeededUsersVerified=($beforeUsers -ge 2); Persistent=$true
    }
}

function Write-Menu24DiagnosticBundle {
    param(
        [Parameter(Mandatory)][string]$ErrorMessage,
        $PlanEvidence,
        $WebAppEvidence,
        $ZipEvidence,
        $StartupEvidence,
        $SettingsEvidence,
        $MainSiteEvidence,
        $ScmEvidence,
        $HomeDataWriteEvidence,
        $DeploymentEvidence
    )
    $directory = Join-Path $script:EvidenceRoot ("menu24-failure-{0}" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
    $liveDiagnostics = $null
    try {
        $token = Get-AzBearerTokenText
        try {
            $latest = Get-KuduLatestDeploymentSnapshot -BearerToken $token
            $deploymentList = Get-KuduDeploymentCollectionSnapshot -BearerToken $token
            $wwwrootContract = Get-KuduWwwrootContractSnapshot -BearerToken $token
            $health = Get-HealthContractProbe
            $exactTemporary = $null
            $temporaryLog = $null
            $finalDeployment = $null
            $finalDeploymentLog = $null
            $correlation = Get-ObjectPropertyValue $DeploymentEvidence 'SubmissionCorrelation' $null
            $tempId = [string](Get-ObjectPropertyValue $correlation 'TempDeploymentId' '')
            if (-not [string]::IsNullOrWhiteSpace($tempId)) {
                $exactTemporary = Get-KuduDeploymentRecordSnapshot -DeploymentId $tempId -BearerToken $token
                $temporaryLog = Get-KuduDeploymentLogSnapshot -DeploymentId $tempId -BearerToken $token
            }
            $finalRecordFromEvidence = Get-ObjectPropertyValue $DeploymentEvidence 'FinalDeployment' $null
            $finalId = [string](Get-ObjectPropertyValue $finalRecordFromEvidence 'Id' '')
            if ([string]::IsNullOrWhiteSpace($finalId)) { $finalId = [string](Get-ObjectPropertyValue $finalRecordFromEvidence 'id' '') }
            if ([string]::IsNullOrWhiteSpace($finalId)) {
                $attempts = @(Get-ObjectPropertyValue $DeploymentEvidence 'Attempts' @())
                if ($attempts.Count -gt 0) {
                    $lastAttemptFinal = Get-ObjectPropertyValue $attempts[$attempts.Count - 1] 'FinalDeployment' $null
                    $finalId = [string](Get-ObjectPropertyValue $lastAttemptFinal 'Id' '')
                    if ([string]::IsNullOrWhiteSpace($finalId)) { $finalId = [string](Get-ObjectPropertyValue $lastAttemptFinal 'id' '') }
                }
            }
            if (-not [string]::IsNullOrWhiteSpace($finalId) -and $finalId -ne $tempId) {
                $finalDeployment = Get-KuduDeploymentRecordSnapshot -DeploymentId $finalId -BearerToken $token
                $finalDeploymentLog = Get-KuduDeploymentLogSnapshot -DeploymentId $finalId -BearerToken $token
                Write-KuduDeploymentLogConsole -Label 'FINAL-DIAGNOSTIC' -RecordSnapshot $finalDeployment -LogSnapshot $finalDeploymentLog
            }
            $liveDiagnostics = [pscustomobject][ordered]@{
                Latest=$latest
                DeploymentList=$deploymentList
                ExactTemporaryDeployment=$exactTemporary
                TemporaryDeploymentLog=$temporaryLog
                FinalDeployment=$finalDeployment
                FinalDeploymentLog=$finalDeploymentLog
                WwwrootContract=$wwwrootContract
                Health=$health
            }
        }
        finally { $token = $null }
    }
    catch { $liveDiagnostics = [pscustomobject]@{ DiagnosticReadError=(Protect-KuduDiagnosticText -Text $_.Exception.Message -MaximumLength 2000) } }

    $bundle = [ordered]@{
        LauncherVersion=$script:LauncherVersion
        CapturedUtc=[DateTime]::UtcNow.ToString('o')
        Error=(Protect-KuduDiagnosticText -Text $ErrorMessage -MaximumLength 12000)
        Plan=$PlanEvidence
        WebApp=$WebAppEvidence
        Zip=$ZipEvidence
        Startup=$StartupEvidence
        AppSettings=$SettingsEvidence
        MainSitePreDeployment=$MainSiteEvidence
        ScmReadiness=$ScmEvidence
        HomeDataWrite=$HomeDataWriteEvidence
        Deployment=$DeploymentEvidence
        LiveKuduAndSiteDiagnostics=$liveDiagnostics
        SecurityNote='Bearer tokens, passwords, API keys, client secrets, and JWT-like values are redacted or excluded.'
    }
    $path = Join-Path $directory 'summary.json'
    $bundle | ConvertTo-Json -Depth 60 | Set-Content -LiteralPath $path -Encoding UTF8
    return $directory
}

function Invoke-DotNet {
    param(
        [Parameter(Mandatory)][string[]]$Arguments,
        [string]$WorkingDirectory = $script:SourceRoot,
        [switch]$PassThru
    )
    Assert-Command 'dotnet' 'Install the .NET 8 SDK, then run menu 1 again.'
    if (-not (Test-Path -LiteralPath $WorkingDirectory)) {
        throw "dotnet working directory does not exist: $WorkingDirectory"
    }

    # Force stable, readable native-process output on Windows PowerShell 5.1
    # and PowerShell 7.x. DOTNET_CLI_FORCE_UTF8_ENCODING is the official .NET
    # switch for UTF-8 console output; en-US also avoids localized mojibake in
    # older Windows console hosts.
    $dotnetEnvironment = [ordered]@{
        'DOTNET_NOLOGO'                  = '1'
        'DOTNET_CLI_TELEMETRY_OPTOUT'   = '1'
        'DOTNET_CLI_UI_LANGUAGE'        = 'en-US'
        'DOTNET_CLI_FORCE_UTF8_ENCODING'= '1'
        'NUGET_XMLDOC_MODE'             = 'skip'
    }
    $previousEnvironment = @{}
    foreach ($name in $dotnetEnvironment.Keys) {
        $existing = Get-Item -LiteralPath "Env:$name" -ErrorAction SilentlyContinue
        $previousEnvironment[$name] = [pscustomobject]@{
            Exists = ($null -ne $existing)
            Value  = if ($null -ne $existing) { [string]$existing.Value } else { $null }
        }
        Set-Item -LiteralPath "Env:$name" -Value $dotnetEnvironment[$name]
    }

    $previousConsoleEncoding = $null
    $consoleEncodingChanged = $false
    $previousPowerShellEncoding = $global:OutputEncoding
    $previousErrorActionPreference = $ErrorActionPreference
    $utf8NoBom = New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $false
    try {
        $previousConsoleEncoding = [Console]::OutputEncoding
        [Console]::OutputEncoding = $utf8NoBom
        $consoleEncodingChanged = $true
    }
    catch {
        # PowerShell ISE and some redirected hosts don't expose a writable
        # console handle. DOTNET_CLI_FORCE_UTF8_ENCODING and en-US still apply.
    }
    $global:OutputEncoding = $utf8NoBom

    $commandName = if ($Arguments.Count -gt 0) { $Arguments[0] } else { 'dotnet' }
    $safeCommandName = $commandName -replace '[^A-Za-z0-9_.-]', '_'
    $logPath = Join-Path $script:LogRoot ("dotnet-{0}-{1}.log" -f $safeCommandName, (Get-Date -Format 'yyyyMMdd-HHmmss'))
    $startedUtc = [DateTime]::UtcNow
    Push-Location $WorkingDirectory
    try {
        # Windows PowerShell 5.1 may represent native stderr as ErrorRecord.
        # Continue long enough to capture all output, then enforce exit code.
        $ErrorActionPreference = 'Continue'
        $nativeOutput = @(& dotnet @Arguments 2>&1)
        $exitCode = $LASTEXITCODE
        $ErrorActionPreference = $previousErrorActionPreference
        $outputLines = @($nativeOutput | ForEach-Object { [string]$_ })
        foreach ($line in $outputLines) { Write-Host $line }
        [IO.File]::WriteAllLines($logPath, [string[]]$outputLines, $utf8NoBom)

        $script:LastDotNetInvocation = [pscustomobject][ordered]@{
            Command      = "dotnet $($Arguments -join ' ')"
            WorkingDirectory = $WorkingDirectory
            ExitCode     = $exitCode
            StartedUtc   = $startedUtc.ToString('o')
            CompletedUtc = [DateTime]::UtcNow.ToString('o')
            LogPath      = $logPath
            OutputLines  = $outputLines.Count
            Output       = $outputLines
            UiLanguage   = 'en-US'
            Utf8Forced   = $true
        }
        if ($exitCode -ne 0) {
            throw "dotnet command failed with exit code ${exitCode}: dotnet $($Arguments -join ' '). UTF-8 log: $logPath"
        }
        if ($PassThru) { return $script:LastDotNetInvocation }
    }
    finally {
        Pop-Location
        if ($consoleEncodingChanged -and $null -ne $previousConsoleEncoding) {
            try { [Console]::OutputEncoding = $previousConsoleEncoding } catch { }
        }
        $global:OutputEncoding = $previousPowerShellEncoding
        $ErrorActionPreference = $previousErrorActionPreference
        foreach ($name in $dotnetEnvironment.Keys) {
            if ($previousEnvironment[$name].Exists) {
                Set-Item -LiteralPath "Env:$name" -Value $previousEnvironment[$name].Value
            }
            else {
                Remove-Item -LiteralPath "Env:$name" -ErrorAction SilentlyContinue
            }
        }
    }
}

function Get-DotNetRuntimeInventory {
    Assert-Command 'dotnet' 'Install the .NET 8 SDK, then run menu 1 again.'
    $result = Invoke-DotNet -Arguments @('--list-runtimes') -WorkingDirectory $script:Root -PassThru
    $lines = @($result.Output)
    $aspNetCoreRuntimes = @($lines | Where-Object { $_ -match '^Microsoft\.AspNetCore\.App\s+8\.' })
    $dotnetCommand = Get-Command dotnet -ErrorAction Stop
    $dotnetPath = if ($dotnetCommand.Path) { [string]$dotnetCommand.Path } else { [string]$dotnetCommand.Source }
    return [pscustomobject][ordered]@{
        DotNetPath              = $dotnetPath
        AllRuntimeLines         = $lines
        AspNetCore8RuntimeLines = $aspNetCoreRuntimes
        AspNetCore8Visible      = ($aspNetCoreRuntimes.Count -gt 0)
        LogPath                 = $result.LogPath
    }
}

function Get-SelfContainedExecutablePath {
    $candidate = [string]$script:State['SelfContainedExecutablePath']
    if (-not [string]::IsNullOrWhiteSpace($candidate) -and (Test-Path -LiteralPath $candidate -PathType Leaf)) {
        return $candidate
    }
    if (Test-Path -LiteralPath $script:SelfContainedExecutable -PathType Leaf) {
        return $script:SelfContainedExecutable
    }
    throw 'Self-contained local executable is missing. Rerun menu 11 to publish win-x64 before menu 12.'
}

function Invoke-SelfContainedApp {
    param(
        [string[]]$Arguments,
        [string]$WorkingDirectory = $script:SelfContainedRoot,
        [switch]$PassThru
    )
    $executable = Get-SelfContainedExecutablePath
    if (-not (Test-Path -LiteralPath $WorkingDirectory)) {
        throw "Self-contained working directory does not exist: $WorkingDirectory"
    }
    $previousConsoleEncoding = $null
    $consoleEncodingChanged = $false
    $previousPowerShellEncoding = $global:OutputEncoding
    $previousErrorActionPreference = $ErrorActionPreference
    $utf8NoBom = New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $false
    try {
        $previousConsoleEncoding = [Console]::OutputEncoding
        [Console]::OutputEncoding = $utf8NoBom
        $consoleEncodingChanged = $true
    } catch { }
    $global:OutputEncoding = $utf8NoBom
    $executableBaseName = [IO.Path]::GetFileNameWithoutExtension($executable) -replace '[^A-Za-z0-9_.-]','_'
    $logPath = Join-Path $script:LogRoot ("selfcontained-{0}-{1}.log" -f $executableBaseName, (Get-Date -Format 'yyyyMMdd-HHmmss'))
    $startedUtc = [DateTime]::UtcNow
    Push-Location $WorkingDirectory
    try {
        $ErrorActionPreference = 'Continue'
        $nativeOutput = @(& $executable @Arguments 2>&1)
        $exitCode = $LASTEXITCODE
        $ErrorActionPreference = $previousErrorActionPreference
        $outputLines = @($nativeOutput | ForEach-Object { [string]$_ })
        foreach ($line in $outputLines) { Write-Host $line }
        [IO.File]::WriteAllLines($logPath, [string[]]$outputLines, $utf8NoBom)
        $result = [pscustomobject][ordered]@{
            Executable=$executable; Arguments=($Arguments -join ' '); WorkingDirectory=$WorkingDirectory;
            ExitCode=$exitCode; StartedUtc=$startedUtc.ToString('o'); CompletedUtc=[DateTime]::UtcNow.ToString('o');
            LogPath=$logPath; OutputLines=$outputLines.Count; Output=$outputLines
        }
        if ($exitCode -ne 0) {
            throw "Self-contained application failed with exit code ${exitCode}: $executable $($Arguments -join ' '). UTF-8 log: $logPath"
        }
        if ($PassThru) { return $result }
    }
    finally {
        Pop-Location
        if ($consoleEncodingChanged -and $null -ne $previousConsoleEncoding) {
            try { [Console]::OutputEncoding = $previousConsoleEncoding } catch { }
        }
        $global:OutputEncoding = $previousPowerShellEncoding
        $ErrorActionPreference = $previousErrorActionPreference
    }
}

function Start-SelfContainedAppProcess {
    param(
        [Parameter(Mandatory)][string[]]$Arguments,
        [Parameter(Mandatory)][string]$StandardOutputPath,
        [Parameter(Mandatory)][string]$StandardErrorPath
    )
    $executable = Get-SelfContainedExecutablePath
    return Start-Process -FilePath $executable -ArgumentList $Arguments -WorkingDirectory $script:SelfContainedRoot `
        -RedirectStandardOutput $StandardOutputPath -RedirectStandardError $StandardErrorPath -PassThru
}

function Write-ProjectFile {
    param([Parameter(Mandatory)][string]$RelativePath, [Parameter(Mandatory)][string]$Content)
    $path = Join-Path $script:SourceRoot $RelativePath
    $directory = Split-Path -Parent $path
    if (-not (Test-Path -LiteralPath $directory)) { New-Item -ItemType Directory -Path $directory -Force | Out-Null }
    $encoding = New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $false
    [IO.File]::WriteAllText($path, $Content, $encoding)
}

function Test-BalancedTextDelimiters {
    param(
        [Parameter(Mandatory)][string]$Text,
        [Parameter(Mandatory)][string]$Name
    )
    $pairs = @{ ')'='('; ']'='['; '}'='{' }
    $stack = New-Object System.Collections.Stack
    $inString = $false
    $inChar = $false
    $escaped = $false
    $inLineComment = $false
    $inBlockComment = $false
    for ($index = 0; $index -lt $Text.Length; $index++) {
        $character = $Text[$index]
        $next = if ($index + 1 -lt $Text.Length) { $Text[$index + 1] } else { [char]0 }
        if ($inLineComment) { if ($character -eq "`n") { $inLineComment=$false }; continue }
        if ($inBlockComment) { if ($character -eq '*' -and $next -eq '/') { $inBlockComment=$false; $index++ }; continue }
        if ($inString -or $inChar) {
            if ($escaped) { $escaped=$false; continue }
            if ($character -eq '\') { $escaped=$true; continue }
            if ($inString -and $character -eq '"') { $inString=$false; continue }
            if ($inChar -and $character -eq "'") { $inChar=$false; continue }
            continue
        }
        if ($character -eq '/' -and $next -eq '/') { $inLineComment=$true; $index++; continue }
        if ($character -eq '/' -and $next -eq '*') { $inBlockComment=$true; $index++; continue }
        if ($character -eq '"') { $inString=$true; continue }
        if ($character -eq "'") { $inChar=$true; continue }
        if ('([{'.Contains([string]$character)) { $stack.Push($character); continue }
        if (')]}'.Contains([string]$character)) {
            if ($stack.Count -eq 0 -or $stack.Pop() -ne $pairs[[string]$character]) {
                throw "Generated source delimiter mismatch in $Name near character $index."
            }
        }
    }
    if ($inString -or $inChar -or $inBlockComment -or $stack.Count -ne 0) {
        throw "Generated source contains an unterminated string/comment/delimiter in $Name."
    }
}

function Test-GeneratedProjectArtifacts {
    if (-not (Test-Path -LiteralPath $script:SourceRoot)) { throw 'Generated source directory is missing.' }
    $files = @(Get-ChildItem -LiteralPath $script:SourceRoot -Recurse -File)
    if ($files.Count -lt 20) { throw "Generated project is incomplete. File count=$($files.Count)." }

    $results = @()
    foreach ($file in $files) {
        $extension = $file.Extension.ToLowerInvariant()
        if ($extension -notin @('.cs','.cshtml','.json','.csproj')) { continue }
        $content = Get-Content -LiteralPath $file.FullName -Raw -Encoding UTF8
        if ([string]::IsNullOrWhiteSpace($content)) { throw "Generated file is empty: $($file.FullName)" }
        if ($extension -eq '.cs' -and $content.Contains('"""')) {
            throw "C# raw string literals are forbidden in generated source: $($file.FullName)"
        }
        if ($extension -eq '.cs' -and $content.Contains('Saml2Constants')) {
            throw "Generated source references a non-public ITfoxtec scheme constant: $($file.FullName)"
        }
        if ($extension -eq '.cs' -and $content -match '\[[^\]\r\n]*\.\.') {
            throw "Range/Index syntax is forbidden in generated source to protect EF Core expression trees: $($file.FullName)"
        }
        if ($extension -eq '.json') {
            try { $null = $content | ConvertFrom-Json }
            catch { throw "Invalid generated JSON '$($file.FullName)': $($_.Exception.Message)" }
        }
        elseif ($extension -eq '.csproj') {
            try { $null = [xml]$content }
            catch { throw "Invalid generated project XML '$($file.FullName)': $($_.Exception.Message)" }
        }
        elseif ($extension -eq '.cs') {
            Test-BalancedTextDelimiters -Text $content -Name $file.FullName
        }
        elseif ($extension -eq '.cshtml') {
            if ($content -match '\?ReturnUrl=@Uri\.EscapeDataString\(') {
                throw "Nested Razor attribute quoting is forbidden: $($file.FullName)"
            }
        }
        $relativePath = $file.FullName.Substring($script:SourceRoot.Length).TrimStart([char[]]@([char]92,[char]47))
        $results += [pscustomobject]@{ File=$relativePath; Extension=$extension; Bytes=$file.Length; Status='Passed' }
    }
    if (@($results | Where-Object Extension -eq '.cs').Count -lt 10) { throw 'Generated C# source set is incomplete.' }
    $schemeFile = Join-Path $script:SourceRoot 'AuthenticationSchemes.cs'
    $schemeSource = Get-Content -LiteralPath $schemeFile -Raw -Encoding UTF8
    if ($schemeSource -notmatch 'ApplicationCookie\s*=\s*"saml2"' -or
        $schemeSource -notmatch 'OpenIdConnect\s*=\s*"oidc"') {
        throw 'Generated authentication scheme contract is invalid.'
    }
    $evidencePath = Write-EvidenceJson -Name 'generated-project-static-validation' -Data $results
    Write-Success "Generated project static validation passed for $($results.Count) source/config files."
    Write-Host "Evidence: $evidencePath"
    return $results
}

function Get-RandomSecretText {
    param([int]$Bytes = 32)
    $buffer = New-Object -TypeName byte[] -ArgumentList $Bytes
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($buffer) }
    finally { if ($null -ne $rng) { $rng.Dispose() } }
    return [Convert]::ToBase64String($buffer).TrimEnd('=').Replace('+','-').Replace('/','_')
}

function Show-Architecture {
    @'

  Browser
     |
     | HTTPS
     v
  +---------------------------------------------------------+
  | DNGRMS Demo Web App - ASP.NET Core 8 / App Service      |
  |                                                         |
  | Auth mode: Local | Dual | OIDC | SAML                   |
  +----------------------+----------------------------------+
                         |
           +-------------+-------------+
           |                           |
           v                           v
  +------------------+       +---------------------------+
  | SQLite           |       | Microsoft Entra ID        |
  | User/Profile     |       | OIDC App Registration     |
  | Password Hash    |       | SAML Enterprise App       |
  | Role/Mapping     |       | MFA / Conditional Access  |
  | Audit            |       | Sign-in Logs              |
  +------------------+       +---------------------------+

  Migration principle:
  Authentication responsibility moves to Entra ID.
  DNGRMS business profile, role, mapping, and audit data remain in the app database.
'@ | Write-Host
}

function Show-Menu {
    Clear-Host
    Write-Line '='
    Write-Color " $script:LauncherName v$script:LauncherVersion" Cyan
    Write-Host
    Write-Line '='
    Write-Host " Current mode : $($script:State.AuthenticationMode)"
    Write-Host " Web app      : $($script:State.WebAppName)"
    Write-Host " State        : $script:StatePath"
    Write-Line
    Write-Color ' PREPARATION' Yellow
    Write-Host @'
  0  Demo overview and safety notes
  1  Diagnose local prerequisites
  2  Install/update required PowerShell modules
  3  Sign in to Azure and Microsoft Graph
  4  Configure demo names, subscription, region, and SKU
  5  Validate Azure providers, permissions, and name availability
  6  Display/export state (secret-free)
  7  Display target architecture
  8  Display minimum-cost strategy
  9  Run integrated preflight checks

 LOCAL APPLICATION
 10  Generate complete ASP.NET Core 8 application source
 11  Restore and build the application
 12  Initialize SQLite and seed local demo users
 13  Display local users and database evidence
 14  Run the app locally
 15  Test local login endpoint and health
 16  Demonstrate password-hash storage
 17  Demonstrate role authorization design
 18  Display local authentication audit
 19  Publish and create deployment ZIP

 AZURE APP SERVICE
 20  Create resource group
 21  Create minimum paid B1 Linux App Service plan
 22  Create .NET 8 Linux Web App and startup contract
 23  Configure App Service settings and secure seed values
 24  Kudu async ZIP deploy, persistence check, and seed cleanup
 25  Validate health, runtime, and startup
 26  Validate Azure-hosted local login
 27  Restart app and verify SQLite persistence
 28  Enable/display App Service logs
 29  Capture Azure portal evidence

 OIDC MIGRATION
 30  Create/reuse OIDC app registration and service principal
 31  Configure OIDC redirect and logout URIs
 32  Create OIDC client secret and configure the Web App
 33  Assign the signed-in pilot user to the OIDC enterprise app
 34  Validate OIDC settings and discovery document
 35  Switch to Dual mode (Local + OIDC)
 36  Open/test Entra OIDC sign-in
 37  Display OIDC claims evidence URL
 38  Explain/verify OIDC identity linking
 39  Test OIDC logout and session reset

 SAML MIGRATION
 40  Create/reuse SAML enterprise application
 41  Configure SP Entity ID, ACS, and sign-on URLs
 42  Configure Entra SAML mode and application metadata
 43  Configure basic SAML claims policy (best effort)
 44  Validate Entra SAML federation metadata and signing certificate
 45  Assign the signed-in pilot user to the SAML enterprise app
 46  Switch to SAML mode
 47  Open/test SP-initiated SAML sign-in
 48  Display SAML assertion validation evidence URL
 49  Explain/verify SAML identity linking

 CUTOVER / ROLLBACK
 50  Switch pilot users to Dual mode
 51  Validate Local/OIDC/SAML coexistence
 52  Stop creating new local passwords (application setting)
 53  Disable local login for a selected user
 54  Make OIDC the default authentication mode
 55  Validate the break-glass local administrator
 56  Verify ordinary local login rejection
 57  Display OIDC vs SAML evidence matrix
 58  Roll back authentication mode
 59  Generate final evidence summary

 OPTIONAL / CLEANUP
 90  Compare with App Service Easy Auth
 91  Scale App Service plan to B1
 92  Scale App Service plan to F1
 93  Inventory all demo resources
 94  Remove OIDC application credential
 95  Delete Entra OIDC/SAML applications
 96  Delete Azure resource group
 97  Remove local generated artifacts
 98  Archive secret-free state and evidence
 99  Verify cleanup
  Q  Quit
'@
    Write-Line
}

Load-State

function Invoke-Menu0 {
    Write-DemoHeader '0' 'Introduce the end-to-end legacy authentication migration demonstration.' `
        -Expected @('No Azure resource is created.', 'No credential or secret is stored in state.')
    Show-Architecture
    Write-WarningMessage 'Training/demo only. Do not use demo passwords or SQLite architecture as a production baseline.'
    Write-WarningMessage 'Conditional Access and MFA require suitable tenant licensing and policy preparation.'
    Write-Host "`nCustomer talk track:"
    Write-Host '  We keep the application and its business authorization data, while moving authentication responsibility from an application password table to Microsoft Entra ID.'
    Complete-Menu '0'
}

function Invoke-Menu1 {
    Write-DemoHeader '1' 'Diagnose local PowerShell, .NET, modules, file system, and network prerequisites.' `
        -Expected @('Windows PowerShell 5.1 or PowerShell 7.x', '.NET SDK 8.x', 'ASP.NET Core shared runtime inventory or self-contained fallback', 'Writable launcher directory')
    $checks = @()
    $checks += [pscustomobject]@{ Check='PowerShell'; Required='5.1 or 7.x'; Actual=$PSVersionTable.PSVersion.ToString(); Pass=($PSVersionTable.PSVersion -ge [version]'5.1') }
    $dotnet = Get-Command dotnet -ErrorAction SilentlyContinue
    $dotnetVersion = if ($dotnet) { (& dotnet --version) } else { 'Not installed' }
    $checks += [pscustomobject]@{ Check='.NET SDK'; Required='8.x'; Actual=$dotnetVersion; Pass=($dotnetVersion -match '^8\.') }
    $runtimeInventory = $null
    if ($dotnet) {
        try {
            $runtimeInventory = Get-DotNetRuntimeInventory
            $runtimeActual = if ($runtimeInventory.AspNetCore8Visible) {
                $runtimeInventory.AspNetCore8RuntimeLines -join '; '
            }
            else {
                'Microsoft.AspNetCore.App 8.x not visible to this dotnet host'
            }
            $fallbackReady = Test-Path -LiteralPath $script:SelfContainedExecutable -PathType Leaf
            $runtimePass = $runtimeInventory.AspNetCore8Visible -or $fallbackReady -or ($dotnetVersion -match '^8\.')
            $runtimeRequirement = 'Microsoft.AspNetCore.App 8.x OR Menu 11 win-x64 self-contained artifact'
            $checks += [pscustomobject]@{ Check='ASP.NET Core runtime'; Required=$runtimeRequirement; Actual=$runtimeActual; Pass=$runtimePass }
            $script:State['AspNetCoreSharedRuntimeSeen'] = [bool]$runtimeInventory.AspNetCore8Visible
            $script:State['AspNetCoreSharedRuntimes'] = @($runtimeInventory.AspNetCore8RuntimeLines)
            Save-State
            if (-not $runtimeInventory.AspNetCore8Visible) {
                Write-WarningMessage 'Microsoft.AspNetCore.App 8.x is not visible. This is non-blocking: Menu 11 publishes a win-x64 self-contained local executable.'
            }
        }
        catch {
            $checks += [pscustomobject]@{ Check='ASP.NET Core runtime'; Required='Runtime inventory or self-contained fallback'; Actual=$_.Exception.Message; Pass=($dotnetVersion -match '^8\.') }
            Write-WarningMessage 'Runtime inventory was inconclusive. The .NET 8 SDK can still create the Menu 11 self-contained fallback.'
        }
    }
    foreach ($module in $script:RequiredModules.Keys) {
        $found = Get-Module -ListAvailable -Name $module | Sort-Object Version -Descending | Select-Object -First 1
        $actualVersion = if ($found) { $found.Version.ToString() } else { 'Missing' }
        $checks += [pscustomobject]@{ Check="Module: $module"; Required=$script:RequiredModules[$module]; Actual=$actualVersion; Pass=($null -ne $found) }
    }
    $probe = Join-Path $script:Root '.write-test'
    try { Set-Content -LiteralPath $probe -Value 'ok' -Encoding UTF8; Remove-Item $probe -Force; $writable=$true } catch { $writable=$false }
    $checks += [pscustomobject]@{ Check='Workspace writable'; Required='True'; Actual=$writable; Pass=$writable }
    $checks | Format-Table -AutoSize
    Write-EvidenceJson -Name 'local-prerequisites' -Data $checks | ForEach-Object { Write-Host "Evidence: $_" }
    if ($checks.Pass -contains $false) { Write-WarningMessage 'Resolve failed checks or run menu 2 for PowerShell modules.' }
    else { Write-Success 'All required local checks passed.'; Complete-Menu '1' }
}

function Invoke-Menu2 {
    Write-DemoHeader '2' 'Install only missing or older required PowerShell modules.' `
        -Expected @('Modules are installed for CurrentUser.', 'Existing newer modules are preserved.')
    if ($PSVersionTable.PSVersion.Major -eq 5) {
        Write-Step 'Preparing TLS 1.2 and the NuGet package provider for Windows PowerShell 5.1...'
        if (-not (Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue)) {
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Scope CurrentUser -Force | Out-Null
        }
    }
    if (-not (Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue)) {
        Register-PSRepository -Default
    }
    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
    foreach ($module in $script:RequiredModules.Keys) {
        $minimum = [version]$script:RequiredModules[$module]
        $found = Get-Module -ListAvailable -Name $module | Sort-Object Version -Descending | Select-Object -First 1
        if (-not $found -or $found.Version -lt $minimum) {
            Write-Step "Installing $module (minimum $minimum)..."
            Install-Module -Name $module -MinimumVersion $minimum -Scope CurrentUser -Repository PSGallery -AllowClobber -Force
        }
        else { Write-Host "$module $($found.Version) already satisfies the requirement." }
    }
    Write-Success 'Required modules are available.'
    Complete-Menu '2'
}

function Invoke-Menu3 {
    Write-DemoHeader '3' 'Sign in to Azure and Microsoft Graph with the scopes needed for the demo.' `
        -AzurePortal @('Azure portal > Subscriptions > <subscription> > Access control (IAM)') `
        -EntraPortal @('Microsoft Entra admin center > Identity > Applications') `
        -Expected @('Azure context selected', 'Microsoft Graph delegated context selected')
    Assert-Module 'Az.Accounts'
    $azContext = Get-AzContext -ErrorAction SilentlyContinue
    if (-not $azContext) { Connect-AzAccount | Out-Null; $azContext = Get-AzContext }
    $script:State.TenantId = $azContext.Tenant.Id
    $script:State.SubscriptionId = $azContext.Subscription.Id
    $script:State.SubscriptionName = $azContext.Subscription.Name
    Assert-Module 'Microsoft.Graph.Authentication'
    $requiredScopes = @(
        'Application.ReadWrite.All',
        'AppRoleAssignment.ReadWrite.All',
        'Policy.Read.All',
        'Policy.ReadWrite.ApplicationConfiguration',
        'User.Read'
    )
    $mg = Get-MgContext -ErrorAction SilentlyContinue
    $missingScope = @(if ($mg) { @($requiredScopes | Where-Object { @($mg.Scopes) -notcontains $_ }) } else { $requiredScopes })
    if (-not $mg -or @($missingScope).Count -gt 0) {
        Connect-MgGraph -TenantId $script:State.TenantId -Scopes $requiredScopes -NoWelcome
    }
    $mg = Get-MgContext -ErrorAction SilentlyContinue
    if (-not $mg) { throw 'Microsoft Graph sign-in did not establish a context. Rerun Menu 3.' }
    if ([string]$mg.TenantId -ne [string]$script:State.TenantId) { throw "Microsoft Graph tenant mismatch after sign-in. Expected=$($script:State.TenantId); Actual=$($mg.TenantId)." }
    $missingAfterConnect = @($requiredScopes | Where-Object { @($mg.Scopes) -notcontains $_ })
    if (@($missingAfterConnect).Count -gt 0) { throw "Microsoft Graph consent is incomplete. Missing scopes: $($missingAfterConnect -join ', '). Rerun Menu 3 and grant consent." }
    try {
        $me = Invoke-GraphJson GET 'https://graph.microsoft.com/v1.0/me?$select=userPrincipalName,mail'
        $script:State.PilotUserPrincipalName = $me.userPrincipalName
    }
    catch { Write-WarningMessage "Could not resolve current Graph user email for automatic identity linking: $($_.Exception.Message)" }
    Save-State
    Write-Success "Azure: $($script:State.SubscriptionName) / $($script:State.TenantId)"
    Write-Success "Graph tenant: $((Get-MgContext).TenantId)"
    Complete-Menu '3'
}

function Invoke-Menu4 {
    Write-DemoHeader '4' 'Configure deterministic resource names, region, subscription, and App Service SKU.' `
        -Expected @('Azure context and selected subscription are revalidated.', 'Names are saved and read back from the secret-free state file.')

    Ensure-StateConfigurationDefaults
    $current = Get-CurrentAzureContextSnapshot
    Write-Host "Current subscription: $($current.SubscriptionName) ($($current.SubscriptionId))"

    $subscriptionInput = Read-Choice 'Subscription ID' $current.SubscriptionId
    $requestedSubscriptionId = Assert-GuidText -Value $subscriptionInput -Label 'Subscription ID'

    # Set-AzContext officially accepts -Subscription. Re-read the resulting
    # context and compare IDs so Menu 4 never trusts only the user's input.
    Write-Step "Selecting Azure subscription $requestedSubscriptionId..."
    Set-AzContext -Subscription $requestedSubscriptionId -Tenant $current.TenantId | Out-Null
    $selected = Get-CurrentAzureContextSnapshot
    if ($selected.SubscriptionId -ne $requestedSubscriptionId) {
        throw "Azure context selection failed. Requested '$requestedSubscriptionId' but current context is '$($selected.SubscriptionId)'."
    }

    $script:State['SubscriptionId'] = $selected.SubscriptionId
    $script:State['SubscriptionName'] = $selected.SubscriptionName
    $script:State['TenantId'] = $selected.TenantId
    $script:State['Location'] = Read-Choice 'Azure region' ([string]$script:State['Location'])
    $script:State['ResourceGroupName'] = Read-Choice 'Resource group name' ([string]$script:State['ResourceGroupName'])
    $script:State['AppServicePlanName'] = Read-Choice 'App Service plan name' ([string]$script:State['AppServicePlanName'])
    $script:State['WebAppName'] = (Read-Choice 'Globally unique Web App name' ([string]$script:State['WebAppName'])).ToLowerInvariant()
    $sku = (Read-Choice 'App Service SKU (guided minimum paid SKU is B1)' 'B1').ToUpperInvariant()
    if ($sku -ne 'B1') { throw 'The v1.1.15 guided deployment requires Basic B1. Use B1 or delete the lab after the demo.' }
    $script:State['AppServiceSku'] = 'B1'

    Assert-StateConfiguration | Out-Null
    $verification = Save-AndVerifyState

    Write-Color "`n[VERIFIED CONFIGURATION]" Green
    Get-StateSummaryObject | Format-List
    Write-Color '[STATE FILE ROUND-TRIP]' Green
    $verification | Format-List
    Write-Success 'Demo configuration was saved, read back, and verified.'
    Complete-Menu '4'
}

function Invoke-Menu5 {
    Write-DemoHeader '5' 'Validate resource providers, Azure location, and the globally unique Web App name.' `
        -AzurePortal @('Azure portal > Subscriptions > Resource providers') `
        -Expected @('Microsoft.Web and Microsoft.Resources registered', 'Web App name available or already owned by this resource group')
    # The active Az context is the source of truth for subscription-scoped
    # operations. Synchronize it into state before constructing any REST path.
    $contextSnapshot = Sync-StateFromAzureContext -Save
    Ensure-StateConfigurationDefaults
    $stateSummary = Assert-StateConfiguration
    if ($stateSummary.SubscriptionId -ne $contextSnapshot.SubscriptionId) {
        throw "State/context mismatch. State='$($stateSummary.SubscriptionId)', Context='$($contextSnapshot.SubscriptionId)'. Run menu 4."
    }
    $subscriptionId = $contextSnapshot.SubscriptionId
    Write-Step "Validating resources in subscription $subscriptionId ($($contextSnapshot.SubscriptionName))..."

    Assert-Module 'Az.Resources'
    foreach ($providerName in @('Microsoft.Web','Microsoft.Resources')) {
        $provider = Get-AzResourceProvider -ProviderNamespace $providerName
        if (($provider | Select-Object -First 1).RegistrationState -ne 'Registered') {
            Write-Step "Registering $providerName..."
            Register-AzResourceProvider -ProviderNamespace $providerName | Out-Null
        }
        Write-Success "$providerName is registered."
    }
    $existing = Get-AzResource -ResourceType 'Microsoft.Web/sites' -Name $stateSummary.WebAppName -ErrorAction SilentlyContinue
    if ($existing -and $existing.ResourceGroupName -ne $stateSummary.ResourceGroupName) {
        throw "Web App name is already used in another accessible resource group: $($existing.ResourceGroupName)"
    }
    try {
        # Do not use an unresolved format placeholder; Invoke-AzRestMethod sends
        # Path exactly as supplied. A concrete, validated GUID is required.
        $restPath = "/subscriptions/$subscriptionId/providers/Microsoft.Web/checkNameAvailability?api-version=2023-12-01"
        $payload = @{ name=$stateSummary.WebAppName; type='Microsoft.Web/sites' } | ConvertTo-Json -Compress
        $availability = Invoke-AzRestMethod -Method POST -Path $restPath -Payload $payload
        $availabilityResult = $availability.Content | ConvertFrom-Json
        $availabilityResult | Format-List
        Write-Success "Microsoft.Web name availability request used subscription $subscriptionId."
    }
    catch {
        throw "Web App name availability validation failed for subscription '$subscriptionId': $($_.Exception.Message)"
    }
    Save-AndVerifyState | Out-Null
    Complete-Menu '5'
}

function Invoke-Menu6 {
    Write-DemoHeader '6' 'Display and export the current secret-free execution state.' `
        -Expected @('No password, access token, refresh token, or client secret is present.')
    $script:State | ConvertTo-Json -Depth 20 | Write-Host
    Write-Host "`nState file: $script:StatePath"
    Complete-Menu '6'
}

function Invoke-Menu7 {
    Write-DemoHeader '7' 'Explain the Local-to-OIDC-to-SAML target architecture and trust boundaries.'
    Show-Architecture
    Complete-Menu '7'
}

function Invoke-Menu8 {
    Write-DemoHeader '8' 'Explain the minimum-cost paid operating strategy.' `
        -Expected @('Basic B1 is the guided minimum paid plan', 'One Linux Web App and SQLite keep the lab compact', 'Delete the resource group after the demo')
    @'
COST STRATEGY
- Guided default: Linux App Service Basic B1, one app, SQLite, and the default azurewebsites.net TLS endpoint.
- B1 is the minimum paid dedicated configuration used by Menu 21 and enforced again by Menu 24.
- No VM, Azure SQL, Key Vault, custom domain, deployment slot, or Application Insights is required.
- Menu 92 can scale a completed lab down to F1, but Menu 24 will return the plan to B1 before deployment.
- Microsoft Entra licensing, Conditional Access, Identity Protection, and external identities are not created by this launcher.
- Cost varies by agreement, currency, region, and usage. Confirm with Azure Pricing Calculator and Cost Management.
- Delete the demo resource group with Menu 96 when evidence collection is complete.
'@ | Write-Host
    Complete-Menu '8'
}

function Invoke-Menu9 {
    Write-DemoHeader '9' 'Run an integrated preflight gate before source generation or Azure deployment.'
    $results = @()
    $results += [pscustomobject]@{Item='PowerShell 5.1 or 7.x';Pass=($PSVersionTable.PSVersion -ge [version]'5.1');Detail=$PSVersionTable.PSVersion.ToString()}
    $dotnetVersion = if (Get-Command dotnet -ErrorAction SilentlyContinue) { (& dotnet --version) } else { 'Missing' }
    $results += [pscustomobject]@{Item='.NET SDK 8.x';Pass=($dotnetVersion -match '^8\.');Detail=$dotnetVersion}
    if ($dotnetVersion -match '^8\.') {
        try {
            $runtimeInventory = Get-DotNetRuntimeInventory
            $fallbackReady = Test-Path -LiteralPath $script:SelfContainedExecutable -PathType Leaf
            $runtimeDetail = if ($runtimeInventory.AspNetCore8Visible) {
                $runtimeInventory.AspNetCore8RuntimeLines -join '; '
            }
            elseif ($fallbackReady) {
                "Shared runtime missing; self-contained fallback ready: $script:SelfContainedExecutable"
            }
            else {
                'Shared runtime missing; Menu 11 will create the self-contained fallback'
            }
            $results += [pscustomobject]@{Item='ASP.NET Core execution';Pass=$true;Detail=$runtimeDetail}
            if (-not $runtimeInventory.AspNetCore8Visible) {
                Write-WarningMessage $runtimeDetail
            }
        }
        catch {
            $results += [pscustomobject]@{Item='ASP.NET Core execution';Pass=$true;Detail='Runtime inventory unavailable; Menu 11 self-contained publish required'}
        }
    }
    else {
        $results += [pscustomobject]@{Item='ASP.NET Core execution';Pass=$false;Detail='No .NET 8 SDK; self-contained artifact cannot be built'}
    }
    foreach ($module in $script:RequiredModules.Keys) {
        $found = Get-Module -ListAvailable $module | Sort-Object Version -Descending | Select-Object -First 1
        $moduleDetail = if ($found) { $found.Version } else { 'Missing' }
        $results += [pscustomobject]@{Item=$module;Pass=($null -ne $found);Detail=$moduleDetail}
    }
    $az = if (Get-Command Get-AzContext -ErrorAction SilentlyContinue) { Get-AzContext -ErrorAction SilentlyContinue } else { $null }
    $mg = if (Get-Command Get-MgContext -ErrorAction SilentlyContinue) { Get-MgContext -ErrorAction SilentlyContinue } else { $null }
    $azureDetail = if ($az) { $az.Subscription.Name } else { 'Not connected' }
    $graphDetail = if ($mg) { $mg.TenantId } else { 'Not connected' }
    $results += [pscustomobject]@{Item='Azure context';Pass=($null -ne $az);Detail=$azureDetail}
    $results += [pscustomobject]@{Item='Graph context';Pass=($null -ne $mg);Detail=$graphDetail}
    $results | Format-Table -AutoSize
    Write-EvidenceJson -Name 'integrated-preflight' -Data $results | ForEach-Object { Write-Host "Evidence: $_" }
    if ($results.Pass -contains $false) { throw 'Preflight failed. Resolve the failed items and rerun menu 9.' }
    Write-Success 'Integrated preflight passed.'
    Complete-Menu '9'
}

function Invoke-Menu10 {
    Write-DemoHeader '10' 'Generate the complete ASP.NET Core 8 MVC application source for Local, OIDC, and SAML authentication.' `
        -Expected @('A buildable .NET 8 project is written under src/DngrmsDemo.Web.', 'No secret is embedded in source code.')

    if ((Test-Path -LiteralPath $script:SourceRoot) -and (Get-ChildItem -LiteralPath $script:SourceRoot -Force -ErrorAction SilentlyContinue)) {
        if (-not (Read-YesNo 'Existing generated source will be replaced. Continue?')) { return }
        Remove-Item -LiteralPath $script:SourceRoot -Recurse -Force
    }
    New-Item -ItemType Directory -Path $script:SourceRoot -Force | Out-Null

    Write-Step 'Writing project and package references...'
    Write-ProjectFile 'DngrmsDemo.Web.csproj' @'
<Project Sdk="Microsoft.NET.Sdk.Web">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
    <Nullable>enable</Nullable>
    <ImplicitUsings>enable</ImplicitUsings>
    <RuntimeIdentifiers>win-x64;linux-x64</RuntimeIdentifiers>
    <InvariantGlobalization>false</InvariantGlobalization>
    <PublishSingleFile>false</PublishSingleFile>
    <PublishTrimmed>false</PublishTrimmed>
    <PublishReadyToRun>false</PublishReadyToRun>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Microsoft.AspNetCore.Authentication.OpenIdConnect" Version="8.0.33" />
    <PackageReference Include="Microsoft.IdentityModel.Abstractions" Version="8.22.0" />
    <PackageReference Include="Microsoft.IdentityModel.JsonWebTokens" Version="8.22.0" />
    <PackageReference Include="Microsoft.IdentityModel.Logging" Version="8.22.0" />
    <PackageReference Include="Microsoft.IdentityModel.Protocols" Version="8.22.0" />
    <PackageReference Include="Microsoft.IdentityModel.Protocols.OpenIdConnect" Version="8.22.0" />
    <PackageReference Include="Microsoft.IdentityModel.Tokens" Version="8.22.0" />
    <PackageReference Include="Microsoft.IdentityModel.Tokens.Saml" Version="8.22.0" />
    <PackageReference Include="Microsoft.IdentityModel.Xml" Version="8.22.0" />
    <PackageReference Include="System.IdentityModel.Tokens.Jwt" Version="8.22.0" />
    <PackageReference Include="Microsoft.EntityFrameworkCore.Sqlite.Core" Version="8.0.33" />
    <PackageReference Include="Microsoft.Data.Sqlite.Core" Version="8.0.33" />
    <PackageReference Include="SQLitePCLRaw.provider.sqlite3" Version="2.1.11" />
    <PackageReference Include="SQLitePCLRaw.provider.winsqlite3" Version="2.1.11" />
    <PackageReference Include="ITfoxtec.Identity.Saml2.MvcCore" Version="4.21.0" />
  </ItemGroup>
</Project>
'@

    Write-ProjectFile 'AuthenticationSchemes.cs' @'
namespace DngrmsDemo.Web;

/// <summary>
/// Authentication scheme names owned by this application.
/// ITfoxtec AddSaml2 registers its application cookie under the literal
/// scheme name "saml2". The package's internal scheme constant isn't a public
/// API, so application code uses this explicit contract instead.
/// </summary>
public static class AuthenticationSchemes
{
    public const string ApplicationCookie = "saml2";
    public const string OpenIdConnect = "oidc";
}
'@

    Write-ProjectFile 'appsettings.json' @'
{
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.AspNetCore": "Warning",
      "Microsoft.EntityFrameworkCore.Database.Command": "Warning"
    }
  },
  "AllowedHosts": "*",
  "Demo": {
    "AuthenticationMode": "Local",
    "DatabasePath": "data/dngrms-demo.db",
    "StopLocalPasswordCreation": false,
    "AdminUserName": "dngrms-admin",
    "StandardUserName": "dngrms-user"
  },
  "Oidc": {
    "TenantId": "",
    "ClientId": "",
    "ClientSecret": "",
    "CallbackPath": "/signin-oidc",
    "SignedOutCallbackPath": "/signout-callback-oidc"
  },
  "Saml2": {
    "Enabled": false,
    "Issuer": "",
    "IdPMetadata": ""
  }
}
'@

    Write-ProjectFile 'Program.cs' @'
using System.Security.Claims;
using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.MvcCore;
using ITfoxtec.Identity.Saml2.MvcCore.Configuration;
using ITfoxtec.Identity.Saml2.Schemas.Metadata;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using DngrmsDemo.Web;
using DngrmsDemo.Web.Data;
using DngrmsDemo.Web.Services;

var builder = WebApplication.CreateBuilder(args);

// Environment variables use double underscore for nested configuration keys.
// Examples: Oidc__ClientId, Saml2__IdPMetadata, Demo__DatabasePath.
var authMode = Environment.GetEnvironmentVariable("DNGRMS_AUTH_MODE")
               ?? builder.Configuration["Demo:AuthenticationMode"]
               ?? "Local";
var databasePath = Environment.GetEnvironmentVariable("DNGRMS_DB_PATH")
                   ?? builder.Configuration["Demo:DatabasePath"]
                   ?? "data/dngrms-demo.db";
if (!Path.IsPathRooted(databasePath))
{
    databasePath = Path.Combine(builder.Environment.ContentRootPath, databasePath);
}
databasePath = Path.GetFullPath(databasePath);
var databaseDirectory = Path.GetDirectoryName(databasePath)
    ?? throw new InvalidOperationException($"The SQLite database path has no parent directory: {databasePath}");
Directory.CreateDirectory(databaseDirectory);
if (Directory.Exists(databasePath))
{
    throw new InvalidOperationException($"The SQLite database target is a directory, not a file: {databasePath}");
}
var sqliteConnectionString = new Microsoft.Data.Sqlite.SqliteConnectionStringBuilder
{
    DataSource = databasePath,
    Mode = Microsoft.Data.Sqlite.SqliteOpenMode.ReadWriteCreate,
    Cache = Microsoft.Data.Sqlite.SqliteCacheMode.Private,
    Pooling = false,
    DefaultTimeout = 30
}.ToString();

try
{
    // v1.1.20 selects the operating-system SQLite provider after bootstrap resolves libsqlite3.so.0.
    if (OperatingSystem.IsWindows())
    {
        SQLitePCL.raw.SetProvider(new SQLitePCL.SQLite3Provider_winsqlite3());
    }
    else
    {
        SQLitePCL.raw.SetProvider(new SQLitePCL.SQLite3Provider_sqlite3());
    }
    SQLitePCL.raw.FreezeProvider();
    using var nativeProbe = new Microsoft.Data.Sqlite.SqliteConnection("Data Source=:memory:;Mode=Memory;Cache=Private;Pooling=False");
    nativeProbe.Open();
    using var versionCommand = nativeProbe.CreateCommand();
    versionCommand.CommandText = "SELECT sqlite_version();";
    var nativeVersion = Convert.ToString(versionCommand.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture) ?? "unknown";
    Console.WriteLine($"[DNGRMS-SQLITE-NATIVE] Provider=system-sqlite3 Version={nativeVersion} RID={System.Runtime.InteropServices.RuntimeInformation.RuntimeIdentifier}");
}
catch (Exception ex)
{
    var depth = 0;
    for (Exception? current = ex; current is not null; current = current.InnerException)
    {
        Console.Error.WriteLine($"[DNGRMS-STARTUP-EXCEPTION] Stage=SqliteNativeProvider Depth={depth} Type={current.GetType().FullName} Message={current.Message}");
        depth++;
    }
    Console.Error.WriteLine(ex.ToString());
    throw;
}

builder.Services.AddDbContext<DemoDbContext>(options => options.UseSqlite(sqliteConnectionString));
builder.Services.AddScoped<DemoSeeder>();
builder.Services.AddScoped<IdentityLinkService>();
builder.Services.AddScoped<AuditService>();
builder.Services.AddHttpContextAccessor();
builder.Services.AddHttpClient();
builder.Services.AddControllersWithViews();
builder.Services.AddRazorPages();
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminOnly", policy => policy.RequireRole("Admin"));
});

// ITfoxtec registers its SAML cookie scheme as the default scheme. Local password,
// OIDC, and SAML all issue the same application session cookie so the protected
// business application does not depend on the upstream protocol.
var samlMetadata = builder.Configuration["Saml2:IdPMetadata"];
var samlEnabled = bool.TryParse(builder.Configuration["Saml2:Enabled"], out var parsedSamlEnabled) && parsedSamlEnabled;
builder.Services.BindConfig<Saml2Configuration>(builder.Configuration, "Saml2", (serviceProvider, samlConfig) =>
{
    samlConfig.Issuer = builder.Configuration["Saml2:Issuer"] ?? "urn:dngrms:demo:not-configured";
    samlConfig.SignAuthnRequest = false;
    // Entra application token-signing certificates created for this demo are self-signed.
    // Chain trust is intentionally not used; SAML XML signatures remain mandatory and are
    // validated against SignatureValidationCertificates loaded from application-specific metadata.
    samlConfig.CertificateValidationMode = System.ServiceModel.Security.X509CertificateValidationMode.None;
    samlConfig.AllowedAudienceUris.Add(samlConfig.Issuer);
    if (samlEnabled && Uri.TryCreate(samlMetadata, UriKind.Absolute, out var metadataUri))
    {
        try
        {
            var clientFactory = serviceProvider.GetRequiredService<IHttpClientFactory>();
            var descriptor = new EntityDescriptor();
            descriptor.ReadIdPSsoDescriptorFromUrlAsync(clientFactory, metadataUri).GetAwaiter().GetResult();
            if (descriptor.IdPSsoDescriptor is null)
            {
                throw new InvalidOperationException("IdP metadata did not contain an IdPSsoDescriptor.");
            }
            samlConfig.AllowedIssuer = descriptor.EntityId;
            samlConfig.SingleSignOnDestination = descriptor.IdPSsoDescriptor.SingleSignOnServices.First().Location;
            var logoutService = descriptor.IdPSsoDescriptor.SingleLogoutServices.FirstOrDefault();
            if (logoutService is not null) samlConfig.SingleLogoutDestination = logoutService.Location;
            foreach (var certificate in descriptor.IdPSsoDescriptor.SigningCertificates.Where(c => c.NotAfter > DateTime.UtcNow))
            {
                samlConfig.SignatureValidationCertificates.Add(certificate);
            }
            if (samlConfig.SignatureValidationCertificates.Count == 0)
            {
                throw new InvalidOperationException("No currently valid SAML signing certificate was found in IdP metadata.");
            }
        }
        catch (Exception ex)
        {
            // Keep health/home available so configuration can be repaired. SAML login refuses
            // to start until SingleSignOnDestination and validation certificates are loaded.
            Console.Error.WriteLine($"SAML metadata bootstrap warning: {ex.Message}");
        }
    }
    return samlConfig;
});
builder.Services.AddSaml2(loginPath: "/account/login", slidingExpiration: true,
    cookieSameSite: SameSiteMode.Lax, cookieSecurePolicy: CookieSecurePolicy.Always,
    cookieName: "DNGRMS.Demo.Session");

var tenantId = builder.Configuration["Oidc:TenantId"];
var clientId = builder.Configuration["Oidc:ClientId"];
var clientSecret = builder.Configuration["Oidc:ClientSecret"];
if (!string.IsNullOrWhiteSpace(tenantId) && !string.IsNullOrWhiteSpace(clientId) && !string.IsNullOrWhiteSpace(clientSecret))
{
    builder.Services.AddAuthentication()
        .AddOpenIdConnect(AuthenticationSchemes.OpenIdConnect, "Microsoft Entra ID (OIDC)", options =>
        {
            options.SignInScheme = AuthenticationSchemes.ApplicationCookie;
            options.Authority = $"https://login.microsoftonline.com/{tenantId}/v2.0";
            options.ClientId = clientId;
            options.ClientSecret = clientSecret;
            options.ResponseType = OpenIdConnectResponseType.Code;
            options.UsePkce = true;
            options.CallbackPath = builder.Configuration["Oidc:CallbackPath"] ?? "/signin-oidc";
            options.SignedOutCallbackPath = builder.Configuration["Oidc:SignedOutCallbackPath"] ?? "/signout-callback-oidc";
            options.SaveTokens = false;
            options.MapInboundClaims = false;
            options.GetClaimsFromUserInfoEndpoint = false;
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                NameClaimType = "name",
                RoleClaimType = "roles"
            };
            options.Events = new OpenIdConnectEvents
            {
                OnTokenValidated = async context =>
                {
                    var linker = context.HttpContext.RequestServices.GetRequiredService<IdentityLinkService>();
                    context.Principal = await linker.EnrichExternalPrincipalAsync(context.Principal!, "OIDC");
                    var audit = context.HttpContext.RequestServices.GetRequiredService<AuditService>();
                    var userName = context.Principal.FindFirst("dngrms_user_name")?.Value ?? context.Principal.Identity?.Name ?? "Unknown";
                    var issuer = context.Principal.Claims.FirstOrDefault()?.Issuer;
                    var subject = context.Principal.FindFirst("sub")?.Value;
                    await audit.WriteAsync("OIDC", userName, "Success", issuer, subject);
                },
                OnRemoteFailure = context =>
                {
                    context.HandleResponse();
                    var safeMessage = Uri.EscapeDataString(context.Failure?.Message ?? "OIDC remote authentication failed.");
                    context.Response.Redirect($"/account/login?error={safeMessage}");
                    return Task.CompletedTask;
                }
            };
        });
}

var app = builder.Build();
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/home/error");
    app.UseHsts();
}
app.UseForwardedHeaders();
app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();
app.UseSaml2(); // ITfoxtec calls ASP.NET Core UseAuthentication() exactly once.
app.UseAuthorization();
app.MapControllerRoute(name: "default", pattern: "{controller=Home}/{action=Index}/{id?}");
app.MapRazorPages();

try
{
    using var scope = app.Services.CreateScope();
    var seeder = scope.ServiceProvider.GetRequiredService<DemoSeeder>();
    await seeder.EnsureCreatedAndSeedAsync();
}
catch (Exception ex)
{
    var depth = 0;
    for (Exception? current = ex; current is not null; current = current.InnerException)
    {
        Console.Error.WriteLine($"[DNGRMS-STARTUP-EXCEPTION] Stage=EnsureCreatedAndSeed Depth={depth} Type={current.GetType().FullName} Message={current.Message}");
        depth++;
    }
    Console.Error.WriteLine(ex.ToString());
    throw;
}

if (args.Contains("--seed-only", StringComparer.OrdinalIgnoreCase))
{
    Console.WriteLine("Database initialization completed. Exiting because --seed-only was specified.");
    return;
}

if (args.Contains("--list-users", StringComparer.OrdinalIgnoreCase) ||
    args.Contains("--password-evidence", StringComparer.OrdinalIgnoreCase) ||
    args.Contains("--list-audit", StringComparer.OrdinalIgnoreCase))
{
    using var inspectionScope = app.Services.CreateScope();
    var db = inspectionScope.ServiceProvider.GetRequiredService<DemoDbContext>();
    if (args.Contains("--list-audit", StringComparer.OrdinalIgnoreCase))
    {
        // SQLite cannot translate DateTimeOffset ordering. Materialize first, then sort safely in memory.
        var auditRows = await db.AuthenticationAudits.AsNoTracking().ToListAsync();
        var audit = auditRows.OrderByDescending(x => x.TimestampUtc).Take(100)
            .Select(x => new { x.TimestampUtc, x.Method, x.UserName, x.Result, x.Issuer, x.Subject, x.CorrelationId, x.SafeDetail }).ToList();
        Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(audit, new System.Text.Json.JsonSerializerOptions { WriteIndented = true }));
    }
    else
    {
        // Materialize the EF Core query before formatting password evidence.
        // Range/Index syntax isn't valid in expression trees and cannot be
        // translated by the SQLite provider.
        var userRows = await db.Users.AsNoTracking().OrderBy(x => x.Id).ToListAsync();
        var users = userRows.Select(x => new
        {
            x.Id, x.UserName, x.DisplayName, x.Email, x.Role, x.IsEnabled, x.LocalLoginAllowed,
            x.EntraObjectId, x.OidcSubject, x.SamlNameId,
            PasswordEvidence = string.IsNullOrEmpty(x.PasswordHash)
                ? "Missing"
                : $"Present; length={x.PasswordHash.Length}; prefix={x.PasswordHash.Substring(0, Math.Min(12, x.PasswordHash.Length))}..."
        }).ToList();
        Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(users, new System.Text.Json.JsonSerializerOptions { WriteIndented = true }));
    }
    return;
}

Console.WriteLine($"DNGRMS demo starting. Authentication mode={authMode}; Database={databasePath}");
app.Run();
'@

    Write-ProjectFile 'Models/DemoUser.cs' @'
using System.ComponentModel.DataAnnotations;

namespace DngrmsDemo.Web.Models;

public sealed class DemoUser
{
    public int Id { get; set; }
    [MaxLength(128)] public string UserName { get; set; } = string.Empty;
    [MaxLength(128)] public string NormalizedUserName { get; set; } = string.Empty;
    [MaxLength(256)] public string PasswordHash { get; set; } = string.Empty;
    [MaxLength(128)] public string DisplayName { get; set; } = string.Empty;
    [MaxLength(256)] public string Email { get; set; } = string.Empty;
    [MaxLength(64)] public string Department { get; set; } = "Demo Operations";
    [MaxLength(32)] public string Role { get; set; } = "User";
    public bool IsEnabled { get; set; } = true;
    public bool LocalLoginAllowed { get; set; } = true;
    public int FailedLoginCount { get; set; }
    public DateTimeOffset? LockoutEndUtc { get; set; }
    [MaxLength(128)] public string? EntraObjectId { get; set; }
    [MaxLength(256)] public string? OidcSubject { get; set; }
    [MaxLength(512)] public string? SamlNameId { get; set; }
    [MaxLength(512)] public string? ExternalIssuer { get; set; }
    public DateTimeOffset CreatedUtc { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset UpdatedUtc { get; set; } = DateTimeOffset.UtcNow;
}
'@

    Write-ProjectFile 'Models/AuthenticationAudit.cs' @'
using System.ComponentModel.DataAnnotations;

namespace DngrmsDemo.Web.Models;

public sealed class AuthenticationAudit
{
    public long Id { get; set; }
    public DateTimeOffset TimestampUtc { get; set; } = DateTimeOffset.UtcNow;
    [MaxLength(32)] public string Method { get; set; } = string.Empty;
    [MaxLength(128)] public string UserName { get; set; } = string.Empty;
    [MaxLength(32)] public string Result { get; set; } = string.Empty;
    [MaxLength(256)] public string? Issuer { get; set; }
    [MaxLength(128)] public string? Subject { get; set; }
    [MaxLength(64)] public string CorrelationId { get; set; } = string.Empty;
    [MaxLength(512)] public string? SafeDetail { get; set; }
}
'@

    Write-ProjectFile 'Models/LoginViewModel.cs' @'
using System.ComponentModel.DataAnnotations;

namespace DngrmsDemo.Web.Models;

public sealed class LoginViewModel
{
    [Required, Display(Name = "User ID")]
    public string UserName { get; set; } = string.Empty;
    [Required, DataType(DataType.Password), Display(Name = "Password")]
    public string Password { get; set; } = string.Empty;
    public string? ReturnUrl { get; set; }
    public string? Error { get; set; }
}
'@

    Write-ProjectFile 'Data/DemoDbContext.cs' @'
using Microsoft.EntityFrameworkCore;
using DngrmsDemo.Web.Models;

namespace DngrmsDemo.Web.Data;

public sealed class DemoDbContext(DbContextOptions<DemoDbContext> options) : DbContext(options)
{
    public DbSet<DemoUser> Users => Set<DemoUser>();
    public DbSet<AuthenticationAudit> AuthenticationAudits => Set<AuthenticationAudit>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<DemoUser>().HasIndex(x => x.NormalizedUserName).IsUnique();
        modelBuilder.Entity<DemoUser>().HasIndex(x => x.EntraObjectId);
        modelBuilder.Entity<DemoUser>().HasIndex(x => x.OidcSubject);
        modelBuilder.Entity<AuthenticationAudit>().HasIndex(x => x.TimestampUtc);
    }
}
'@

    Write-ProjectFile 'Services/DemoSeeder.cs' @'
using Microsoft.AspNetCore.Identity;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using DngrmsDemo.Web.Data;
using DngrmsDemo.Web.Models;

namespace DngrmsDemo.Web.Services;

public sealed class DemoSeeder(DemoDbContext db, IConfiguration configuration)
{
    public async Task EnsureCreatedAndSeedAsync()
    {
        await EnsureDatabaseCreatedAsync();
        var stopCreation = bool.TryParse(Environment.GetEnvironmentVariable("DNGRMS_STOP_LOCAL_PASSWORD_CREATION")
                                          ?? configuration["Demo:StopLocalPasswordCreation"], out var stop) && stop;
        if (stopCreation) return;

        var adminPassword = Environment.GetEnvironmentVariable("DNGRMS_SEED_ADMIN_PASSWORD");
        var userPassword = Environment.GetEnvironmentVariable("DNGRMS_SEED_USER_PASSWORD");
        if (string.IsNullOrWhiteSpace(adminPassword) && string.IsNullOrWhiteSpace(userPassword)) return;

        var adminName = Environment.GetEnvironmentVariable("DNGRMS_SEED_ADMIN_USERNAME")
                        ?? configuration["Demo:AdminUserName"] ?? "dngrms-admin";
        var userName = Environment.GetEnvironmentVariable("DNGRMS_SEED_USER_USERNAME")
                       ?? configuration["Demo:StandardUserName"] ?? "dngrms-user";
        var adminEmail = Environment.GetEnvironmentVariable("DNGRMS_SEED_ADMIN_EMAIL")
                         ?? $"{adminName}@dngrms-demo.invalid";
        if (!string.IsNullOrWhiteSpace(adminPassword))
            await UpsertUserAsync(adminName, adminPassword, "DNGRMS Demo Administrator", "Admin", adminEmail);
        if (!string.IsNullOrWhiteSpace(userPassword))
            await UpsertUserAsync(userName, userPassword, "DNGRMS Demo User", "User", $"{userName}@dngrms-demo.invalid");
        await db.SaveChangesAsync();
    }

    private async Task EnsureDatabaseCreatedAsync()
    {
        const int maximumAttempts = 3;
        for (var attempt = 1; attempt <= maximumAttempts; attempt++)
        {
            try
            {
                await db.Database.OpenConnectionAsync();
                await db.Database.ExecuteSqlRawAsync("PRAGMA busy_timeout=30000;");
                await using (var command = db.Database.GetDbConnection().CreateCommand())
                {
                    command.CommandText = "SELECT sqlite_version();";
                    var version = Convert.ToString(await command.ExecuteScalarAsync(), System.Globalization.CultureInfo.InvariantCulture) ?? "unknown";
                    Console.WriteLine($"[DNGRMS-SQLITE-CONNECTION] State=Open Version={version} DataSource={db.Database.GetDbConnection().DataSource}");
                }
                await db.Database.EnsureCreatedAsync();
                return;
            }
            catch (SqliteException ex) when (attempt < maximumAttempts && ex.SqliteErrorCode is 5 or 6 or 10)
            {
                Console.Error.WriteLine($"[DNGRMS-SQLITE-RETRY] Attempt={attempt} Primary={ex.SqliteErrorCode} Extended={ex.SqliteExtendedErrorCode} Message={ex.Message}");
                await Task.Delay(TimeSpan.FromSeconds(attempt * 2));
            }
            catch (Exception ex)
            {
                var depth = 0;
                for (Exception? current = ex; current is not null; current = current.InnerException)
                {
                    if (current is SqliteException sqlite)
                        Console.Error.WriteLine($"[DNGRMS-STARTUP-EXCEPTION] Stage=EnsureCreated Depth={depth} Type={current.GetType().FullName} Primary={sqlite.SqliteErrorCode} Extended={sqlite.SqliteExtendedErrorCode} Message={current.Message}");
                    else
                        Console.Error.WriteLine($"[DNGRMS-STARTUP-EXCEPTION] Stage=EnsureCreated Depth={depth} Type={current.GetType().FullName} Message={current.Message}");
                    depth++;
                }
                Console.Error.WriteLine(ex.ToString());
                throw;
            }
            finally
            {
                await db.Database.CloseConnectionAsync();
            }
        }
    }

    private async Task UpsertUserAsync(string userName, string password, string displayName, string role, string email)
    {
        var normalized = userName.Trim().ToUpperInvariant();
        var user = await db.Users.SingleOrDefaultAsync(x => x.NormalizedUserName == normalized);
        if (user is null)
        {
            user = new DemoUser
            {
                UserName = userName.Trim(), NormalizedUserName = normalized,
                DisplayName = displayName, Email = email,
                Role = role, LocalLoginAllowed = true, IsEnabled = true
            };
            db.Users.Add(user);
        }
        user.Role = role;
        user.DisplayName = displayName;
        user.Email = email;
        user.IsEnabled = true;
        user.LocalLoginAllowed = true;
        user.UpdatedUtc = DateTimeOffset.UtcNow;
        user.PasswordHash = new PasswordHasher<DemoUser>().HashPassword(user, password);
    }
}
'@

    Write-ProjectFile 'Services/AuditService.cs' @'
using DngrmsDemo.Web.Data;
using DngrmsDemo.Web.Models;

namespace DngrmsDemo.Web.Services;

public sealed class AuditService(DemoDbContext db, IHttpContextAccessor accessor)
{
    public async Task WriteAsync(string method, string userName, string result, string? issuer = null,
        string? subject = null, string? safeDetail = null)
    {
        var context = accessor.HttpContext;
        db.AuthenticationAudits.Add(new AuthenticationAudit
        {
            Method = method, UserName = userName, Result = result,
            Issuer = Truncate(issuer, 256), Subject = Truncate(subject, 128),
            CorrelationId = context?.TraceIdentifier ?? Guid.NewGuid().ToString("N"),
            SafeDetail = Truncate(safeDetail, 512)
        });
        await db.SaveChangesAsync();
    }

    private static string? Truncate(string? value, int max) =>
        string.IsNullOrWhiteSpace(value) ? value : value.Substring(0, Math.Min(value.Length, max));
}
'@

    Write-ProjectFile 'Services/IdentityLinkService.cs' @'
using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using DngrmsDemo.Web.Data;
using DngrmsDemo.Web.Models;

namespace DngrmsDemo.Web.Services;

public sealed class IdentityLinkService(DemoDbContext db)
{
    public async Task<ClaimsPrincipal> EnrichExternalPrincipalAsync(ClaimsPrincipal incoming, string method)
    {
        var oid = Find(incoming, "oid", "http://schemas.microsoft.com/identity/claims/objectidentifier");
        var subject = Find(incoming, "sub", ClaimTypes.NameIdentifier);
        var nameId = Find(incoming, ClaimTypes.NameIdentifier,
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier");
        var email = Find(incoming, "preferred_username", "email", ClaimTypes.Email,
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress");
        var issuer = incoming.Claims.FirstOrDefault()?.Issuer;

        DemoUser? user = null;
        if (!string.IsNullOrWhiteSpace(oid)) user = await db.Users.SingleOrDefaultAsync(x => x.EntraObjectId == oid);
        if (user is null && !string.IsNullOrWhiteSpace(subject)) user = await db.Users.SingleOrDefaultAsync(x => x.OidcSubject == subject);
        if (user is null && !string.IsNullOrWhiteSpace(nameId)) user = await db.Users.SingleOrDefaultAsync(x => x.SamlNameId == nameId);
        if (user is null && !string.IsNullOrWhiteSpace(email))
        {
            user = await db.Users.SingleOrDefaultAsync(x => x.Email.ToUpper() == email.ToUpper()
                || x.NormalizedUserName == email.ToUpper());
        }
        if (user is null)
        {
            var baseName = (email ?? oid ?? subject ?? nameId ?? $"external-{Guid.NewGuid():N}").Trim();
            if (baseName.Length > 128) baseName = baseName.Substring(0, 128);
            var normalized = baseName.ToUpperInvariant();
            if (await db.Users.AnyAsync(x => x.NormalizedUserName == normalized))
                normalized = $"{normalized.Substring(0, Math.Min(normalized.Length, 100))}-{Guid.NewGuid():N}";
            user = new DemoUser
            {
                UserName = baseName, NormalizedUserName = normalized,
                DisplayName = Find(incoming, "name", ClaimTypes.Name) ?? baseName,
                Email = email ?? string.Empty, Role = "User",
                IsEnabled = true, LocalLoginAllowed = false
            };
            db.Users.Add(user);
        }
        if (!user.IsEnabled) throw new UnauthorizedAccessException("The mapped DNGRMS account is disabled.");
        if (!string.IsNullOrWhiteSpace(oid)) user.EntraObjectId = oid;
        if (method.Equals("OIDC", StringComparison.OrdinalIgnoreCase) && !string.IsNullOrWhiteSpace(subject)) user.OidcSubject = subject;
        if (method.Equals("SAML", StringComparison.OrdinalIgnoreCase) && !string.IsNullOrWhiteSpace(nameId)) user.SamlNameId = nameId;
        user.ExternalIssuer = issuer;
        user.UpdatedUtc = DateTimeOffset.UtcNow;
        await db.SaveChangesAsync();

        var identity = new ClaimsIdentity(incoming.Claims, method, "name", ClaimTypes.Role);
        AddOrReplace(identity, ClaimTypes.Name, user.DisplayName);
        AddOrReplace(identity, ClaimTypes.NameIdentifier, user.Id.ToString());
        AddOrReplace(identity, ClaimTypes.Role, user.Role);
        AddOrReplace(identity, "dngrms_user_name", user.UserName);
        AddOrReplace(identity, "auth_method", method);
        AddOrReplace(identity, "dngrms_local_login_allowed", user.LocalLoginAllowed.ToString());
        return new ClaimsPrincipal(identity);
    }

    private static string? Find(ClaimsPrincipal principal, params string[] types) =>
        types.Select(type => principal.FindFirst(type)?.Value).FirstOrDefault(value => !string.IsNullOrWhiteSpace(value));

    private static void AddOrReplace(ClaimsIdentity identity, string type, string value)
    {
        foreach (var claim in identity.FindAll(type).ToArray()) identity.RemoveClaim(claim);
        identity.AddClaim(new Claim(type, value));
    }
}
'@

    Write-ProjectFile 'Controllers/HomeController.cs' @'
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using DngrmsDemo.Web;
using DngrmsDemo.Web.Data;

namespace DngrmsDemo.Web.Controllers;

public sealed class HomeController(DemoDbContext db, IConfiguration configuration) : Controller
{
    [AllowAnonymous]
    public IActionResult Index()
    {
        ViewBag.AuthMode = Environment.GetEnvironmentVariable("DNGRMS_AUTH_MODE")
                           ?? configuration["Demo:AuthenticationMode"] ?? "Local";
        ViewBag.OidcConfigured = !string.IsNullOrWhiteSpace(configuration["Oidc:ClientId"]);
        ViewBag.SamlConfigured = bool.TryParse(configuration["Saml2:Enabled"], out var enabled) && enabled;
        return View();
    }

    [Authorize]
    public IActionResult Dashboard() => View();

    [Authorize]
    public IActionResult AuthDebug()
    {
        var safeClaims = User.Claims
            .Where(c => !c.Type.Contains("token", StringComparison.OrdinalIgnoreCase))
            .OrderBy(c => c.Type)
            .Select(c => new { c.Type, c.Value, c.Issuer }).ToArray();
        return View(safeClaims);
    }

    [Authorize(Policy = "AdminOnly")]
    public async Task<IActionResult> Admin()
    {
        return View(await db.Users.OrderBy(x => x.Id).ToListAsync());
    }

    [AllowAnonymous, HttpGet("health")]
    public async Task<IActionResult> Health()
    {
        var canConnect = await db.Database.CanConnectAsync();
        return Ok(new
        {
            status = canConnect ? "Healthy" : "Degraded",
            version = "1.1.3",
            utc = DateTimeOffset.UtcNow,
            authenticationMode = Environment.GetEnvironmentVariable("DNGRMS_AUTH_MODE")
                                 ?? configuration["Demo:AuthenticationMode"] ?? "Local",
            database = canConnect ? "Connected" : "Unavailable"
        });
    }

    [AllowAnonymous]
    public IActionResult Error() => View();
}
'@

    Write-ProjectFile 'Controllers/AccountController.cs' @'
using System.Security.Claims;
using ITfoxtec.Identity.Saml2;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using DngrmsDemo.Web;
using DngrmsDemo.Web.Data;
using DngrmsDemo.Web.Models;
using DngrmsDemo.Web.Services;

namespace DngrmsDemo.Web.Controllers;

[AllowAnonymous]
[Route("account")]
public sealed class AccountController(DemoDbContext db, AuditService audit, IConfiguration configuration) : Controller
{
    [HttpGet("login")]
    public IActionResult Login(string? returnUrl = null, string? error = null) =>
        View(new LoginViewModel { ReturnUrl = returnUrl, Error = error });

    [HttpPost("login")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Login(LoginViewModel model)
    {
        var mode = CurrentMode();
        if (mode != "Local" && mode != "Dual")
        {
            await audit.WriteAsync("Local", model.UserName, "Denied", safeDetail: $"Local login is disabled in {mode} mode");
            ModelState.AddModelError(string.Empty, $"Local login is disabled while authentication mode is {mode}.");
            return View(model);
        }
        if (!ModelState.IsValid) return View(model);
        var normalized = model.UserName.Trim().ToUpperInvariant();
        var user = await db.Users.SingleOrDefaultAsync(x => x.NormalizedUserName == normalized);
        if (user is null || !user.IsEnabled || !user.LocalLoginAllowed)
        {
            await audit.WriteAsync("Local", model.UserName, "Denied", safeDetail: "Unknown, disabled, or local login blocked");
            ModelState.AddModelError(string.Empty, "Invalid credentials or local login is disabled.");
            return View(model);
        }
        if (user.LockoutEndUtc is not null && user.LockoutEndUtc > DateTimeOffset.UtcNow)
        {
            await audit.WriteAsync("Local", user.UserName, "Locked");
            ModelState.AddModelError(string.Empty, "The account is temporarily locked.");
            return View(model);
        }
        var verification = new PasswordHasher<DemoUser>().VerifyHashedPassword(user, user.PasswordHash, model.Password);
        if (verification == PasswordVerificationResult.Failed)
        {
            user.FailedLoginCount++;
            if (user.FailedLoginCount >= 5) user.LockoutEndUtc = DateTimeOffset.UtcNow.AddMinutes(5);
            await db.SaveChangesAsync();
            await audit.WriteAsync("Local", user.UserName, "Failed", safeDetail: $"Failed count={user.FailedLoginCount}");
            ModelState.AddModelError(string.Empty, "Invalid credentials.");
            return View(model);
        }
        user.FailedLoginCount = 0;
        user.LockoutEndUtc = null;
        await db.SaveChangesAsync();
        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(ClaimTypes.Name, user.DisplayName),
            new Claim(ClaimTypes.Role, user.Role),
            new Claim("dngrms_user_name", user.UserName),
            new Claim("auth_method", "Local"),
            new Claim("dngrms_local_login_allowed", user.LocalLoginAllowed.ToString())
        };
        var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, "Local", ClaimTypes.Name, ClaimTypes.Role));
        await HttpContext.SignInAsync(AuthenticationSchemes.ApplicationCookie, principal,
            new AuthenticationProperties { IsPersistent = false, AllowRefresh = true });
        await audit.WriteAsync("Local", user.UserName, "Success", subject: user.Id.ToString());
        return LocalRedirect(SafeReturnUrl(model.ReturnUrl));
    }

    [HttpGet("oidc")]
    public IActionResult Oidc(string? returnUrl = null)
    {
        if (CurrentMode() != "Oidc" && CurrentMode() != "Dual")
            return RedirectToAction(nameof(Login), new { error = $"OIDC login is disabled in {CurrentMode()} mode." });
        if (string.IsNullOrWhiteSpace(configuration["Oidc:ClientId"]))
            return RedirectToAction(nameof(Login), new { error = "OIDC is not configured." });
        return Challenge(new AuthenticationProperties { RedirectUri = SafeReturnUrl(returnUrl) }, AuthenticationSchemes.OpenIdConnect);
    }

    [Authorize, HttpPost("logout")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Logout()
    {
        var method = User.FindFirst("auth_method")?.Value ?? User.Identity?.AuthenticationType ?? "Unknown";
        var user = User.FindFirst("dngrms_user_name")?.Value ?? User.Identity?.Name ?? "Unknown";
        await audit.WriteAsync(method, user, "Logout");
        await HttpContext.SignOutAsync(AuthenticationSchemes.ApplicationCookie);
        return RedirectToAction("Index", "Home");
    }

    [HttpGet("oidc-logout")]
    public IActionResult OidcLogout()
    {
        return SignOut(new AuthenticationProperties { RedirectUri = "/" },
            AuthenticationSchemes.ApplicationCookie, AuthenticationSchemes.OpenIdConnect);
    }

    private string SafeReturnUrl(string? returnUrl) =>
        !string.IsNullOrWhiteSpace(returnUrl) && Url.IsLocalUrl(returnUrl) ? returnUrl : "/home/dashboard";

    private string CurrentMode() => Environment.GetEnvironmentVariable("DNGRMS_AUTH_MODE")
                                    ?? configuration["Demo:AuthenticationMode"] ?? "Local";
}
'@

    Write-ProjectFile 'Controllers/SamlController.cs' @'
using System.Security.Authentication;
using System.Xml.Linq;
using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.MvcCore;
using ITfoxtec.Identity.Saml2.Schemas;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using DngrmsDemo.Web.Services;

namespace DngrmsDemo.Web.Controllers;

[AllowAnonymous]
[Route("saml")]
public sealed class SamlController(Saml2Configuration config, IConfiguration configuration,
    IdentityLinkService linker, AuditService audit) : Controller
{
    private const string RelayStateReturnUrl = "ReturnUrl";

    [HttpGet("login")]
    public IActionResult Login(string? returnUrl = null)
    {
        var mode = Environment.GetEnvironmentVariable("DNGRMS_AUTH_MODE")
                   ?? configuration["Demo:AuthenticationMode"] ?? "Local";
        if (mode != "Saml" && mode != "Dual")
            return RedirectToAction("Login", "Account", new { error = $"SAML login is disabled in {mode} mode." });
        var enabled = bool.TryParse(configuration["Saml2:Enabled"], out var value) && value;
        if (!enabled || config.SingleSignOnDestination is null || config.SignatureValidationCertificates.Count == 0)
            return RedirectToAction("Login", "Account", new { error = "SAML metadata or signing certificate is not ready." });
        var binding = new Saml2RedirectBinding();
        binding.SetRelayStateQuery(new Dictionary<string, string>
        {
            [RelayStateReturnUrl] = SafeReturnUrl(returnUrl)
        });
        var request = new Saml2AuthnRequest(config)
        {
            NameIdPolicy = new NameIdPolicy
            {
                AllowCreate = true,
                Format = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
            }
        };
        return binding.Bind(request).ToActionResult();
    }

    [HttpPost("acs")]
    public async Task<IActionResult> AssertionConsumerService()
    {
        var genericRequest = Request.ToGenericHttpRequest(validate: true);
        var response = new Saml2AuthnResponse(config);
        genericRequest.Binding.ReadSamlResponse(genericRequest, response);
        if (response.Status != Saml2StatusCodes.Success)
            throw new AuthenticationException($"SAML response status: {response.Status}");
        genericRequest.Binding.Unbind(genericRequest, response);
        var enriched = await linker.EnrichExternalPrincipalAsync(
            new System.Security.Claims.ClaimsPrincipal(response.ClaimsIdentity), "SAML");
        await response.CreateSession(HttpContext, claimsTransform: _ => enriched);
        var userName = enriched.FindFirst("dngrms_user_name")?.Value ?? enriched.Identity?.Name ?? "Unknown";
        var nameId = response.ClaimsIdentity.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
        var issuer = response.ClaimsIdentity.Claims.FirstOrDefault()?.Issuer;
        await audit.WriteAsync("SAML", userName, "Success", issuer, nameId);
        var relay = genericRequest.Binding.GetRelayStateQuery();
        var returnUrl = relay.TryGetValue(RelayStateReturnUrl, out var value) ? value : "/home/dashboard";
        return LocalRedirect(SafeReturnUrl(returnUrl));
    }

    [HttpGet("metadata")]
    public ContentResult Metadata()
    {
        XNamespace md = "urn:oasis:names:tc:SAML:2.0:metadata";
        var baseUrl = $"{Request.Scheme}://{Request.Host}";
        var document = new XDocument(
            new XDeclaration("1.0", "utf-8", null),
            new XElement(md + "EntityDescriptor",
                new XAttribute("entityID", config.Issuer),
                new XElement(md + "SPSSODescriptor",
                    new XAttribute("AuthnRequestsSigned", "false"),
                    new XAttribute("WantAssertionsSigned", "true"),
                    new XAttribute("protocolSupportEnumeration", "urn:oasis:names:tc:SAML:2.0:protocol"),
                    new XElement(md + "NameIDFormat", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"),
                    new XElement(md + "AssertionConsumerService",
                        new XAttribute("Binding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"),
                        new XAttribute("Location", $"{baseUrl}/saml/acs"),
                        new XAttribute("index", "0"),
                        new XAttribute("isDefault", "true"))),
                new XElement(md + "Organization",
                    new XElement(md + "OrganizationName",
                        new XAttribute(XNamespace.Xml + "lang", "en"), "DNGRMS Demo"),
                    new XElement(md + "OrganizationDisplayName",
                        new XAttribute(XNamespace.Xml + "lang", "en"), "DNGRMS Demo"),
                    new XElement(md + "OrganizationURL",
                        new XAttribute(XNamespace.Xml + "lang", "en"), $"{baseUrl}/saml/login"))));

        var xml = document.Declaration + Environment.NewLine +
                  document.ToString(SaveOptions.DisableFormatting);
        return Content(xml, "application/samlmetadata+xml", System.Text.Encoding.UTF8);
    }

    private string SafeReturnUrl(string? returnUrl) =>
        !string.IsNullOrWhiteSpace(returnUrl) && Url.IsLocalUrl(returnUrl) ? returnUrl : "/home/dashboard";
}
'@

    Write-ProjectFile 'Controllers/DemoAdminApiController.cs' @'
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using DngrmsDemo.Web.Data;

namespace DngrmsDemo.Web.Controllers;

[ApiController]
[AllowAnonymous]
[Route("api/demo")]
public sealed class DemoAdminApiController(DemoDbContext db, IConfiguration configuration) : ControllerBase
{
    [HttpGet("status")]
    public async Task<IActionResult> Status() => Ok(new
    {
        version = "1.1.3",
        authenticationMode = Environment.GetEnvironmentVariable("DNGRMS_AUTH_MODE")
                             ?? configuration["Demo:AuthenticationMode"] ?? "Local",
        userCount = await db.Users.CountAsync(),
        auditCount = await db.AuthenticationAudits.CountAsync(),
        utc = DateTimeOffset.UtcNow
    });

    [HttpGet("users")]
    public async Task<IActionResult> Users()
    {
        if (!Authorized()) return Unauthorized();
        return Ok(await db.Users.OrderBy(x => x.Id).Select(x => new
        {
            x.Id, x.UserName, x.DisplayName, x.Email, x.Role, x.IsEnabled,
            x.LocalLoginAllowed, x.EntraObjectId, x.OidcSubject, x.SamlNameId,
            hasPasswordHash = x.PasswordHash != ""
        }).ToListAsync());
    }

    [HttpPost("users/{userName}/local-login")]
    public async Task<IActionResult> SetLocalLogin(string userName, [FromQuery] bool enabled)
    {
        if (!Authorized()) return Unauthorized();
        var normalized = userName.ToUpperInvariant();
        var user = await db.Users.SingleOrDefaultAsync(x => x.NormalizedUserName == normalized);
        if (user is null) return NotFound();
        user.LocalLoginAllowed = enabled;
        user.UpdatedUtc = DateTimeOffset.UtcNow;
        await db.SaveChangesAsync();
        return Ok(new { user.UserName, user.LocalLoginAllowed });
    }

    [HttpGet("audit")]
    public async Task<IActionResult> Audit([FromQuery] int take = 50)
    {
        if (!Authorized()) return Unauthorized();
        take = Math.Clamp(take, 1, 200);
        // SQLite cannot translate DateTimeOffset ordering. Materialize first, then sort safely in memory.
        var auditRows = await db.AuthenticationAudits.AsNoTracking().ToListAsync();
        return Ok(auditRows.OrderByDescending(x => x.TimestampUtc).Take(take).ToList());
    }

    private bool Authorized()
    {
        var expected = configuration["Demo:AdminApiKey"];
        if (string.IsNullOrWhiteSpace(expected)) expected = Environment.GetEnvironmentVariable("DNGRMS_DEMO_ADMIN_KEY");
        var provided = Request.Headers["X-Demo-Admin-Key"].FirstOrDefault();
        return !string.IsNullOrWhiteSpace(expected) &&
               System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(
                   System.Text.Encoding.UTF8.GetBytes(expected),
                   System.Text.Encoding.UTF8.GetBytes(provided ?? string.Empty));
    }
}
'@

    Write-ProjectFile 'Views/_ViewImports.cshtml' @'
@using DngrmsDemo.Web
@using DngrmsDemo.Web.Models
@addTagHelper *, Microsoft.AspNetCore.Mvc.TagHelpers
'@
    Write-ProjectFile 'Views/_ViewStart.cshtml' @'
@{ Layout = "_Layout"; }
'@
    Write-ProjectFile 'Views/Shared/_Layout.cshtml' @'
@{
  var layoutAuthMethod = User.FindFirst("auth_method")?.Value;
}
<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>@ViewData["Title"] - DNGRMS Demo</title>
  <link rel="stylesheet" href="~/css/site.css" asp-append-version="true" />
</head>
<body>
<header>
  <nav class="nav">
    <a class="brand" asp-controller="Home" asp-action="Index">DNGRMS</a>
    <a asp-controller="Home" asp-action="Dashboard">Dashboard</a>
    <a asp-controller="Home" asp-action="AuthDebug">Identity Evidence</a>
    @if (User.IsInRole("Admin")) { <a asp-controller="Home" asp-action="Admin">Admin</a> }
    <span class="spacer"></span>
    @if (User.Identity?.IsAuthenticated == true)
    {
      <span class="user">@User.Identity.Name (@layoutAuthMethod)</span>
      <form asp-controller="Account" asp-action="Logout" method="post"><button class="link-button" type="submit">Sign out</button></form>
    }
    else { <a asp-controller="Account" asp-action="Login">Sign in</a> }
  </nav>
</header>
<main class="container">@RenderBody()</main>
<footer>DNGRMS Authentication Migration Demo v1.1.15 · Training use only</footer>
</body>
</html>
'@

    Write-ProjectFile 'Views/Home/Index.cshtml' @'
@{ ViewData["Title"] = "Home"; }
<section class="hero">
  <div><span class="eyebrow">CUSTOMER WEB APPLICATION MODERNIZATION</span>
    <h1>DNGRMS Authentication Migration Demo</h1>
    <p>기존 RDBMS ID/PW 인증을 유지한 상태에서 Microsoft Entra ID OIDC 또는 SAML 2.0으로 단계적으로 전환합니다.</p>
    <div class="actions"><a class="button primary" asp-controller="Account" asp-action="Login">Open sign-in page</a><a class="button" href="/health">Health evidence</a></div>
  </div>
  <div class="mode-card"><span>Current authentication mode</span><strong>@ViewBag.AuthMode</strong><small>Local → Dual → OIDC → SAML</small></div>
</section>
<section class="grid">
  <article><h2>Local authentication</h2><p>SQLite 사용자 테이블과 ASP.NET Core PasswordHasher로 기존 애플리케이션 로그인을 재현합니다.</p></article>
  <article><h2>OIDC migration</h2><p>Authorization Code Flow + PKCE를 통해 Microsoft Entra ID 인증으로 전환합니다.</p></article>
  <article><h2>SAML migration</h2><p>DNGRMS를 Service Provider로, Microsoft Entra ID를 Identity Provider로 구성합니다.</p></article>
</section>
'@

    Write-ProjectFile 'Views/Account/Login.cshtml' @'
@model LoginViewModel
@{
  ViewData["Title"] = "Sign in";
  var samlReturnUrl = Uri.EscapeDataString(Model.ReturnUrl ?? "/home/dashboard");
}
<div class="login-shell">
<section class="panel">
  <span class="eyebrow">LEGACY APPLICATION SIGN-IN</span><h1>DNGRMS Sign in</h1>
  @if (!string.IsNullOrWhiteSpace(Model.Error)) { <div class="error">@Model.Error</div> }
  <div asp-validation-summary="ModelOnly" class="error"></div>
  <form method="post" asp-action="Login">
    <input type="hidden" asp-for="ReturnUrl" />
    <label asp-for="UserName"></label><input asp-for="UserName" autocomplete="username" />
    <label asp-for="Password"></label><input asp-for="Password" autocomplete="current-password" />
    <button class="button primary wide" type="submit">Sign in with local ID/PW</button>
  </form>
  <div class="separator"><span>or federated sign-in</span></div>
  <a class="button entra wide" asp-action="Oidc" asp-route-returnUrl="@Model.ReturnUrl">Microsoft Entra ID (OIDC)</a>
  <a class="button wide" href="/saml/login?returnUrl=@samlReturnUrl">Microsoft Entra ID (SAML)</a>
</section>
<aside class="explain"><h2>What this page demonstrates</h2><ol><li>Local password hash validation</li><li>Dual-run migration</li><li>OIDC authorization code flow</li><li>SAML SP-initiated flow</li><li>One DNGRMS session after authentication</li></ol></aside>
</div>
'@

    Write-ProjectFile 'Views/Home/Dashboard.cshtml' @'
@{
  ViewData["Title"] = "Dashboard";
  var dashboardAuthMethod = User.FindFirst("auth_method")?.Value;
  var dashboardRole = User.FindFirst(System.Security.Claims.ClaimTypes.Role)?.Value;
}
<span class="eyebrow">AUTHENTICATED BUSINESS AREA</span><h1>DNGRMS Dashboard</h1>
<div class="grid"><article><h2>Signed-in user</h2><p>@User.Identity?.Name</p></article><article><h2>Authentication method</h2><p>@dashboardAuthMethod</p></article><article><h2>Application role</h2><p>@dashboardRole</p></article></div>
<p><a class="button primary" asp-action="AuthDebug">View safe identity evidence</a></p>
'@

    Write-ProjectFile 'Views/Home/AuthDebug.cshtml' @'
@model IEnumerable<dynamic>
@{ ViewData["Title"] = "Identity Evidence"; }
<span class="eyebrow">SAFE CLAIM INSPECTION</span><h1>Identity Evidence</h1>
<p>Raw access tokens, ID tokens, refresh tokens, passwords, and client secrets are never displayed.</p>
<table><thead><tr><th>Claim type</th><th>Value</th><th>Issuer</th></tr></thead><tbody>
@foreach (var claim in Model) { <tr><td>@claim.Type</td><td>@claim.Value</td><td>@claim.Issuer</td></tr> }
</tbody></table>
'@

    Write-ProjectFile 'Views/Home/Admin.cshtml' @'
@model IEnumerable<DemoUser>
@{ ViewData["Title"] = "Admin"; }
<span class="eyebrow">APPLICATION AUTHORIZATION</span><h1>DNGRMS User Mapping</h1>
<table><thead><tr><th>User</th><th>Role</th><th>Local login</th><th>Entra object</th><th>OIDC subject</th><th>SAML NameID</th></tr></thead><tbody>
@foreach (var user in Model) { <tr><td>@user.UserName<br/><small>@user.DisplayName</small></td><td>@user.Role</td><td>@user.LocalLoginAllowed</td><td>@user.EntraObjectId</td><td>@user.OidcSubject</td><td>@user.SamlNameId</td></tr> }
</tbody></table>
'@

    Write-ProjectFile 'Views/Home/Error.cshtml' @'
@{ ViewData["Title"] = "Error"; }
<div class="error"><h1>Request failed</h1><p>Review App Service logs and authentication configuration. No token or secret is shown on this page.</p></div>
'@

    Write-ProjectFile 'wwwroot/css/site.css' @'
:root{--navy:#062f57;--blue:#07529a;--cyan:#14a5e5;--green:#20a464;--ink:#142b3d;--muted:#5d7892;--bg:#f4f8fb;--line:#d9e5ee;--danger:#c83d4a}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font-family:Segoe UI,Arial,sans-serif}.nav{display:flex;align-items:center;gap:22px;padding:15px 5vw;background:var(--navy);color:white}.nav a{color:white;text-decoration:none}.brand{font-weight:800;font-size:22px;letter-spacing:.08em}.spacer{flex:1}.user{font-size:13px;color:#bfeaff}.link-button{border:0;background:none;color:white;cursor:pointer;font:inherit}.container{max-width:1180px;margin:0 auto;padding:54px 28px;min-height:78vh}.hero{display:grid;grid-template-columns:1.5fr .7fr;gap:34px;align-items:center;background:white;padding:52px;border-radius:24px;box-shadow:0 16px 44px #062f5714}.hero h1,.panel h1{font-size:44px;line-height:1.06;margin:12px 0}.hero p{font-size:19px;color:var(--muted);max-width:750px}.eyebrow{font-size:12px;font-weight:800;letter-spacing:.14em;color:var(--blue)}.mode-card{padding:28px;border-radius:18px;color:white;background:linear-gradient(135deg,var(--blue),var(--cyan));display:flex;flex-direction:column;gap:8px}.mode-card strong{font-size:42px}.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:22px;margin:30px 0}.grid article,.panel,.explain{background:white;padding:28px;border-radius:18px;border:1px solid var(--line)}.actions{display:flex;gap:12px;margin-top:25px}.button{display:inline-block;padding:12px 18px;border:1px solid var(--blue);border-radius:8px;background:white;color:var(--blue);text-decoration:none;text-align:center;cursor:pointer;font-weight:650}.button.primary,.button.entra{background:var(--blue);color:white}.wide{width:100%;margin-top:12px}.login-shell{display:grid;grid-template-columns:1fr .8fr;gap:28px;max-width:920px;margin:auto}.panel label{display:block;margin:17px 0 6px;font-weight:650}.panel input{width:100%;padding:13px;border:1px solid #a9bccb;border-radius:7px;font-size:16px}.separator{display:flex;align-items:center;gap:10px;color:var(--muted);font-size:12px;margin:25px 0 5px}.separator:before,.separator:after{content:'';height:1px;background:var(--line);flex:1}.error{padding:14px;border-left:4px solid var(--danger);background:#fff1f2;color:#7d202a;margin:14px 0}table{width:100%;border-collapse:collapse;background:white}th,td{padding:12px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top;word-break:break-word}th{background:#eaf3f9;color:var(--navy)}footer{text-align:center;padding:24px;color:var(--muted);font-size:12px}@media(max-width:800px){.hero,.login-shell,.grid{grid-template-columns:1fr}.nav{flex-wrap:wrap}.hero h1{font-size:34px}}
'@

    Write-ProjectFile 'README.md' @'
# DNGRMS Authentication Migration Demo v1.1.15

Generated by `DNGRMS-Auth-Migration-Demo-Launcher-v1.1.15.ps1`.

## Demonstrated states

1. Local ID/password authentication with SQLite and ASP.NET Core PasswordHasher
2. Dual mode with Local and Microsoft Entra OIDC
3. OIDC-only cutover using Authorization Code Flow + PKCE
4. Microsoft Entra SAML 2.0 with DNGRMS as the Service Provider
5. Local profile/role preservation and external identity linking

## Security boundaries

- Training/demo implementation; not a production architecture.
- No default password is included.
- Secrets must be supplied through environment/App Service settings.
- Raw tokens and assertions are not displayed by the application.
- The demo-admin API is disabled unless `DNGRMS_DEMO_ADMIN_KEY` is configured.
- ITfoxtec.Identity.Saml2 is third-party open source under BSD-3-Clause.
'@

    Write-ProjectFile '.gitignore' @'
bin/
obj/
data/
*.db
*.db-shm
*.db-wal
appsettings.Development.json
'@

    Test-GeneratedProjectArtifacts | Out-Null
    Write-Success "Generated ASP.NET Core project: $script:SourceRoot"
    Complete-Menu '10'
}

function Invoke-Menu11 {
    Write-DemoHeader '11' 'Restore, build, and publish a win-x64 self-contained local execution artifact.' `
        -Expected @('NuGet restore succeeds.', 'Release build succeeds without compilation errors.', 'win-x64 self-contained publish contains DngrmsDemo.Web.exe.', 'UTF-8 English CLI logs are saved under logs/.')
    if (-not (Test-Path (Join-Path $script:SourceRoot 'DngrmsDemo.Web.csproj'))) { throw 'Run menu 10 first.' }
    Test-GeneratedProjectArtifacts | Out-Null
    $restoreResult = Invoke-DotNet -Arguments @('restore','--nologo') -PassThru
    $buildResult = Invoke-DotNet -Arguments @('build','-c','Release','--no-restore','--nologo') -PassThru
    if (Test-Path -LiteralPath $script:SelfContainedRoot) {
        Remove-Item -LiteralPath $script:SelfContainedRoot -Recurse -Force
    }
    New-Item -ItemType Directory -Path $script:SelfContainedRoot -Force | Out-Null
    $publishResult = Invoke-DotNet -Arguments @(
        'publish','-c','Release','-r','win-x64','--self-contained','true','--nologo','-o',$script:SelfContainedRoot
    ) -PassThru
    if (-not (Test-Path -LiteralPath $script:SelfContainedExecutable -PathType Leaf)) {
        throw "Self-contained publish succeeded but executable is missing: $script:SelfContainedExecutable"
    }
    $executableInfo = Get-Item -LiteralPath $script:SelfContainedExecutable
    $coreClrPath = Join-Path $script:SelfContainedRoot 'coreclr.dll'
    $hostFxrPath = Join-Path $script:SelfContainedRoot 'hostfxr.dll'
    if (-not (Test-Path -LiteralPath $coreClrPath -PathType Leaf) -or
        -not (Test-Path -LiteralPath $hostFxrPath -PathType Leaf)) {
        throw 'Self-contained publish is incomplete: coreclr.dll and/or hostfxr.dll is missing.'
    }
    $publishBytes = (Get-ChildItem -LiteralPath $script:SelfContainedRoot -Recurse -File | Measure-Object -Property Length -Sum).Sum
    $script:State['SelfContainedPublishPath'] = $script:SelfContainedRoot
    $script:State['SelfContainedExecutablePath'] = $script:SelfContainedExecutable
    $script:State['SelfContainedRuntimeId'] = 'win-x64'
    $script:State['SelfContainedPublishUtc'] = [DateTime]::UtcNow.ToString('o')
    Save-State

    # Prove that the app-local executable starts without the machine-wide
    # Microsoft.AspNetCore.App shared framework. Use an isolated disposable DB
    # and no user passwords; Menu 12 performs the real credential seeding.
    $smokeDatabasePath = Join-Path $script:EvidenceRoot ("selfcontained-smoke-{0}.db" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
    try {
        $env:DNGRMS_DB_PATH = $smokeDatabasePath
        $env:DNGRMS_STOP_LOCAL_PASSWORD_CREATION = 'true'
        $smokeResult = Invoke-SelfContainedApp -Arguments @('--seed-only') -PassThru
    }
    finally {
        Remove-Item Env:DNGRMS_DB_PATH -ErrorAction SilentlyContinue
        Remove-Item Env:DNGRMS_STOP_LOCAL_PASSWORD_CREATION -ErrorAction SilentlyContinue
        foreach ($path in @($smokeDatabasePath,"$smokeDatabasePath-shm","$smokeDatabasePath-wal")) {
            Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        }
    }
    $buildEvidence = [pscustomobject][ordered]@{
        LauncherVersion = $script:LauncherVersion
        Project         = (Join-Path $script:SourceRoot 'DngrmsDemo.Web.csproj')
        RestoredUtc     = $restoreResult.CompletedUtc
        RestoreExitCode = $restoreResult.ExitCode
        RestoreLog      = $restoreResult.LogPath
        BuiltUtc        = $buildResult.CompletedUtc
        BuildExitCode   = $buildResult.ExitCode
        BuildLog        = $buildResult.LogPath
        PublishedUtc    = $publishResult.CompletedUtc
        PublishExitCode = $publishResult.ExitCode
        PublishLog      = $publishResult.LogPath
        RuntimeId       = 'win-x64'
        SelfContained   = $true
        PublishPath     = $script:SelfContainedRoot
        ExecutablePath  = $script:SelfContainedExecutable
        ExecutableBytes = $executableInfo.Length
        PublishBytes    = $publishBytes
        SmokeTestExitCode = $smokeResult.ExitCode
        SmokeTestLog      = $smokeResult.LogPath
        SmokeTestArgument = '--seed-only'
        MachineSharedRuntimeRequired = $false
        Configuration   = 'Release'
        TargetFramework = 'net8.0'
        Status          = 'Succeeded'
    }
    $evidencePath = Write-EvidenceJson -Name 'dotnet-restore-build-selfcontained-publish' -Data $buildEvidence
    $buildEvidence | Format-List
    Write-Success "Restore, Release build, and win-x64 self-contained publish completed. Evidence: $evidencePath"
    Complete-Menu '11'
}

function Invoke-Menu12 {
    Write-DemoHeader '12' 'Initialize SQLite through the win-x64 self-contained executable and securely seed two local demo users.' `
        -Expected @('No Microsoft.AspNetCore.App machine installation is required.', 'Admin and standard user are created.', 'Passwords are converted to one-way hashes.', 'Plaintext passwords are cleared from process environment.')
    if (-not (Test-Path (Join-Path $script:SourceRoot 'DngrmsDemo.Web.csproj'))) { throw 'Run menu 10 first.' }
    $selfContainedExecutable = Get-SelfContainedExecutablePath
    Write-Step "Using app-local executable: $selfContainedExecutable"
    $dataDirectory = Split-Path -Parent $script:State.LocalDatabasePath
    if (-not (Test-Path $dataDirectory)) { New-Item -ItemType Directory -Path $dataDirectory -Force | Out-Null }
    $pilotEmail = Read-Choice 'Entra pilot user UPN/email for linking to the local admin' $script:State.PilotUserPrincipalName
    $script:State.PilotUserPrincipalName = $pilotEmail
    Save-State
    $adminSecure = Read-RequiredSecureString 'Enter demo admin password (not saved)'
    $userSecure = Read-RequiredSecureString 'Enter demo standard-user password (not saved)'
    try {
        $env:DNGRMS_DB_PATH = $script:State.LocalDatabasePath
        $env:DNGRMS_SEED_ADMIN_USERNAME = $script:State.DemoAdminUserName
        $env:DNGRMS_SEED_USER_USERNAME = $script:State.DemoStandardUserName
        $env:DNGRMS_SEED_ADMIN_EMAIL = $pilotEmail
        $env:DNGRMS_SEED_ADMIN_PASSWORD = ConvertFrom-SecureStringToPlainText $adminSecure
        $env:DNGRMS_SEED_USER_PASSWORD = ConvertFrom-SecureStringToPlainText $userSecure
        $seedResult = Invoke-SelfContainedApp -Arguments @('--seed-only') -PassThru
    }
    finally {
        Remove-Item Env:DNGRMS_SEED_ADMIN_PASSWORD -ErrorAction SilentlyContinue
        Remove-Item Env:DNGRMS_SEED_USER_PASSWORD -ErrorAction SilentlyContinue
        Remove-Item Env:DNGRMS_SEED_ADMIN_USERNAME -ErrorAction SilentlyContinue
        Remove-Item Env:DNGRMS_SEED_USER_USERNAME -ErrorAction SilentlyContinue
        Remove-Item Env:DNGRMS_SEED_ADMIN_EMAIL -ErrorAction SilentlyContinue
        Remove-Item Env:DNGRMS_DB_PATH -ErrorAction SilentlyContinue
    }
    if (-not (Test-Path $script:State.LocalDatabasePath)) { throw 'SQLite database was not created.' }
    $seedEvidence = [pscustomobject][ordered]@{
        LauncherVersion=$script:LauncherVersion; Executable=$selfContainedExecutable; RuntimeId='win-x64';
        SelfContained=$true; ExitCode=$seedResult.ExitCode; CompletedUtc=$seedResult.CompletedUtc;
        LogPath=$seedResult.LogPath; DatabasePath=$script:State.LocalDatabasePath; PilotUserPrincipalName=$pilotEmail;
        SharedAspNetCoreRuntimeRequired=$false; Status='Succeeded'
    }
    $seedEvidencePath = Write-EvidenceJson -Name 'selfcontained-seed-only' -Data $seedEvidence
    Write-Success "SQLite initialized: $($script:State.LocalDatabasePath)"
    Write-Success "Self-contained seed evidence: $seedEvidencePath"
    Complete-Menu '12'
}

function Invoke-Menu13 {
    Write-DemoHeader '13' 'Display secret-free local user and identity-mapping evidence from SQLite.' `
        -Expected @('User names, roles, local-login flags, and hash presence are displayed.', 'No password or full hash is printed.')
    $env:DNGRMS_DB_PATH = $script:State.LocalDatabasePath
    try { Invoke-SelfContainedApp -Arguments @('--list-users') }
    finally { Remove-Item Env:DNGRMS_DB_PATH -ErrorAction SilentlyContinue }
    Complete-Menu '13'
}

function Invoke-Menu14 {
    Write-DemoHeader '14' 'Start the generated application locally on a fixed demo URL.' `
        -Expected @('Local URL: http://localhost:5080', 'Process ID is stored in secret-free state.')
    $selfContainedExecutable = Get-SelfContainedExecutablePath
    $existingPid = 0
    if ($null -ne $script:State.LocalProcessId -and "$($script:State.LocalProcessId)" -match '^\d+$') {
        $existingPid = [int]$script:State.LocalProcessId
    }
    if ($existingPid -gt 0 -and (Get-Process -Id $existingPid -ErrorAction SilentlyContinue)) {
        Write-WarningMessage "Local app is already running with PID $existingPid."
        return
    }
    $env:DNGRMS_DB_PATH = $script:State.LocalDatabasePath
    $env:DNGRMS_AUTH_MODE = 'Local'
    $logOut = Join-Path $script:LogRoot 'local-app.stdout.log'
    $logErr = Join-Path $script:LogRoot 'local-app.stderr.log'
    $process = Start-SelfContainedAppProcess -Arguments @('--urls','http://localhost:5080') `
        -StandardOutputPath $logOut -StandardErrorPath $logErr
    Remove-Item Env:DNGRMS_DB_PATH,Env:DNGRMS_AUTH_MODE -ErrorAction SilentlyContinue
    $script:State.LocalProcessId = $process.Id
    Save-State
    Wait-WebEndpoint -Uri 'http://localhost:5080/health' -TimeoutSeconds 90 | Out-Null
    Write-Success "Self-contained local app is running. PID=$($process.Id); URL=http://localhost:5080"
    Complete-Menu '14'
}

function Invoke-Menu15 {
    Write-DemoHeader '15' 'Validate local health and open the local ID/password login page.' `
        -Expected @('HTTP 200 from /health', 'Local login page is available')
    $health = Invoke-RestMethod -Uri 'http://localhost:5080/health' -Method Get
    $health | Format-List
    Start-Process 'http://localhost:5080/account/login'
    Write-Success 'Local health passed and sign-in page was opened.'
    Complete-Menu '15'
}

function Invoke-Menu16 {
    Write-DemoHeader '16' 'Prove that the RDBMS stores a one-way password hash rather than plaintext.' `
        -Expected @('Password hash algorithm marker/prefix is shown only in abbreviated form.', 'Plaintext is not recoverable or printed.')
    $env:DNGRMS_DB_PATH = $script:State.LocalDatabasePath
    try { Invoke-SelfContainedApp -Arguments @('--password-evidence') }
    finally { Remove-Item Env:DNGRMS_DB_PATH -ErrorAction SilentlyContinue }
    Write-Host "`nCustomer talk track: ASP.NET Core PasswordHasher stores a salted, iterated one-way representation. The password itself is never queried back from SQLite."
    Complete-Menu '16'
}

function Invoke-Menu17 {
    Write-DemoHeader '17' 'Demonstrate that application authorization remains separate from authentication.' `
        -Expected @('Admin role can open /home/admin.', 'User role can open Dashboard but is denied Admin.')
    Write-Host 'Local Admin URL : http://localhost:5080/home/admin'
    Write-Host 'Dashboard URL   : http://localhost:5080/home/dashboard'
    Write-Host 'Authorization   : [Authorize(Policy = "AdminOnly")] requires application Role=Admin.'
    Start-Process 'http://localhost:5080/home/admin'
    Complete-Menu '17'
}

function Invoke-Menu18 {
    Write-DemoHeader '18' 'Display recent local authentication audit records without exposing credentials.'
    $env:DNGRMS_DB_PATH = $script:State.LocalDatabasePath
    try { Invoke-SelfContainedApp -Arguments @('--list-audit') }
    finally { Remove-Item Env:DNGRMS_DB_PATH -ErrorAction SilentlyContinue }
    Complete-Menu '18'
}

function Invoke-Menu19 {
    Write-DemoHeader '19' 'Create separate Azure Linux framework-dependent and self-contained deployment packages without changing the win-x64 local artifact.' `
        -Expected @('Explicit linux-x64 framework-dependent .NET 8 ZIP', 'Separate linux-x64 self-contained fallback ZIP with runtime included', 'win-x64 local executable remains untouched', 'Validated runtimeconfig/deps metadata and safe package-root copy/chmod/exec bootstrap')
    $frameworkDependent = Build-LinuxFrameworkDependentDeploymentPackage
    $selfContained = Build-LinuxSelfContainedDeploymentPackage
    $script:State.DeploymentZipPath = $frameworkDependent.ZipPath
    $script:State['DeploymentPackageMode'] = 'FrameworkDependentNet8'
    $script:State['DeploymentRuntimeId'] = 'linux-x64'
    $script:State['DeploymentFrameworkDependent'] = $true
    $script:State['DeploymentStartupCommand'] = 'dotnet DngrmsDemo.Web.dll'
    Save-State
    $evidence = [pscustomobject][ordered]@{
        FrameworkDependentNet8=$frameworkDependent
        SelfContainedLinuxX64=$selfContained
        WindowsLocalArtifact=[pscustomobject][ordered]@{
            RuntimeId='win-x64'
            PublishPath=$script:SelfContainedRoot
            ExecutablePath=$script:SelfContainedExecutable
            Modified=$false
            Purpose='Menus 12, 13, 14, 16, and 18 only'
        }
    }
    $evidencePath = Write-EvidenceJson -Name 'azure-linux-dual-deployment-packages' -Data $evidence
    Write-Success "Framework-dependent Azure Linux ZIP: $($frameworkDependent.ZipPath)"
    Write-Success "Self-contained Azure Linux fallback ZIP: $($selfContained.ZipPath)"
    Write-Host "Windows local win-x64 artifact remains separate: $script:SelfContainedExecutable"
    Write-Host "Evidence: $evidencePath"
    Complete-Menu '19'
}

function Invoke-Menu20 {
    Write-DemoHeader '20' 'Create or reuse the Azure resource group.' `
        -AzurePortal @('Azure portal > Resource groups > <demo resource group>')
    Assert-AzureContext | Out-Null
    Assert-Module 'Az.Resources'
    $rg = Get-AzResourceGroup -Name $script:State.ResourceGroupName -ErrorAction SilentlyContinue
    if (-not $rg) {
        $rg = New-AzResourceGroup -Name $script:State.ResourceGroupName -Location $script:State.Location `
            -Tag @{ Purpose='DNGRMS-Auth-Demo'; Environment='Training'; LauncherVersion=$script:LauncherVersion }
    }
    $rg | Format-List ResourceGroupName,Location,ProvisioningState,ResourceId
    Write-Success 'Resource group is ready.'
    Complete-Menu '20'
}

function Invoke-Menu21 {
    Write-DemoHeader '21' 'Create or reuse a Linux App Service plan using the minimum paid Basic B1 SKU.' `
        -AzurePortal @('Azure portal > App Service plans > <demo plan> > Scale up') `
        -Expected @('Linux plan', 'Basic B1 dedicated compute', 'No Free-tier quota dependency')
    Assert-AzureContext | Out-Null
    Assert-Module 'Az.Websites'
    $plan = Get-AzAppServicePlan -ResourceGroupName $script:State.ResourceGroupName -Name $script:State.AppServicePlanName -ErrorAction SilentlyContinue
    if (-not $plan) {
        $parameters = @{
            ResourceGroupName=$script:State.ResourceGroupName; Name=$script:State.AppServicePlanName;
            Location=$script:State.Location; Tier='Basic'; WorkerSize='Small'
        }
        if ((Get-Command New-AzAppServicePlan).Parameters.ContainsKey('Linux')) { $parameters.Linux = $true }
        $plan = New-AzAppServicePlan @parameters
    }
    $evidence = Assert-MinimumPaidB1Plan
    $evidence | Format-List
    Write-Success 'Linux App Service plan is ready on the guided minimum paid Basic B1 SKU.'
    Complete-Menu '21'
}

function Invoke-Menu22 {
    Write-DemoHeader '22' 'Create or reuse the Linux Web App and configure the .NET 8 startup contract.' `
        -AzurePortal @('Azure portal > App Services > <demo app> > Settings > Configuration > Stack settings') `
        -Expected @('Linux Web App on B1', 'DOTNETCORE|8.0', 'dotnet DngrmsDemo.Web.dll', 'HTTPS only and Always On')
    Assert-AzureContext | Out-Null
    Assert-Module 'Az.Websites'
    Assert-MinimumPaidB1Plan | Out-Null
    $webApp = Get-AzWebApp -ResourceGroupName $script:State.ResourceGroupName -Name $script:State.WebAppName -ErrorAction SilentlyContinue
    if (-not $webApp) {
        $webApp = New-AzWebApp -ResourceGroupName $script:State.ResourceGroupName -Name $script:State.WebAppName `
            -Location $script:State.Location -AppServicePlan $script:State.AppServicePlanName
    }
    Set-LinuxAppServiceStartupContract -PackageDeploymentMode 'FrameworkDependentNet8' -LinuxFxVersion 'DOTNETCORE|8.0' | Format-List
    $script:State.WebAppResourceId = $webApp.Id
    $script:State.AppServiceSku = 'B1'
    Save-State
    Write-Success "Web App and Linux .NET 8 startup contract are ready: $(Get-WebAppBaseUrl)"
    Complete-Menu '22'
}

function Invoke-Menu23 {
    Write-DemoHeader '23' 'Configure persistent SQLite, Local mode, safe diagnostics, and one-time seed secrets.' `
        -AzurePortal @('Azure portal > App Services > <demo app> > Settings > Environment variables') `
        -Expected @('SQLite path under /home/data', 'Seed passwords removed only after deployment and restart persistence checks', 'Admin API protected by a random key')
    Assert-AzureContext | Out-Null
    Assert-MinimumPaidB1Plan | Out-Null
    if (-not $script:State.PilotUserPrincipalName) {
        $script:State.PilotUserPrincipalName = Read-Choice 'Entra pilot user UPN/email for linking to the local admin' ''
        Save-State
    }
    $adminSecure = Read-RequiredSecureString 'Enter Azure demo admin password (temporarily stored as App Setting)'
    $userSecure = Read-RequiredSecureString 'Enter Azure demo standard-user password (temporarily stored as App Setting)'
    $adminApiKey = Get-RandomSecretText 36
    try {
        $settings = @{
            'DNGRMS_AUTH_MODE'='Local'
            'DNGRMS_DB_PATH'='/home/data/dngrms-demo.db'
            'DNGRMS_SEED_ADMIN_USERNAME'=$script:State.DemoAdminUserName
            'DNGRMS_SEED_USER_USERNAME'=$script:State.DemoStandardUserName
            'DNGRMS_SEED_ADMIN_EMAIL'=$script:State.PilotUserPrincipalName
            'DNGRMS_SEED_ADMIN_PASSWORD'=(ConvertFrom-SecureStringToPlainText $adminSecure)
            'DNGRMS_SEED_USER_PASSWORD'=(ConvertFrom-SecureStringToPlainText $userSecure)
            'DNGRMS_DEMO_ADMIN_KEY'=$adminApiKey
            'WEBSITE_RUN_FROM_PACKAGE'='1'
            'SCM_DO_BUILD_DURING_DEPLOYMENT'='false'
            'ENABLE_ORYX_BUILD'='false'
            'WEBSITES_CONTAINER_START_TIME_LIMIT'='600'
            'WEBSITE_WARMUP_PATH'='/health'
            'WEBSITE_WARMUP_STATUSES'='200'
            'ASPNETCORE_ENVIRONMENT'='Production'
        }
        Set-AzWebAppSettingsSafe $settings
    }
    finally {
        $settings = $null
        $adminApiKey = $null
        $adminSecure = $null
        $userSecure = $null
    }
    $script:State.AuthenticationMode = 'Local'
    $script:State.AppServiceSku = 'B1'
    Save-State
    Write-Success 'App settings configured. Run Menu 24 immediately; seed values are removed only after Kudu status 4, health, and restart persistence validation.'
    Complete-Menu '23'
}

function Invoke-Menu24 {
    Write-DemoHeader '24' 'Resolve the App Service Linux runtime contract, deploy the validated immutable ZIP, stop immediately at Kudu status 4, then validate the main worker in three bounded probes before persistent seeding and cleanup.' `
        -AzurePortal @('Azure portal > App Services > <demo app> > Overview', 'Azure portal > App Services > <demo app> > Settings > Configuration > Stack settings', 'Azure portal > App Services > <demo app> > Deployment Center > Logs', 'Azure portal > App Services > <demo app> > Monitoring > Log stream') `
        -Expected @('Actual configured linuxFxVersion and available Linux runtimes are queried before deployment', 'FrameworkDependentNet8 is used only when both required .NET 8 shared frameworks are visible', 'SelfContainedLinuxX64 uses a shell bootstrap to copy the read-only mount to writable /home and execute the apphost', 'Kudu polling stops on the first status 4 and is capped at 12 requests', 'The linux-x64 ZIP must contain the pinned system-sqlite3 providers and no bundled libe_sqlite3.so before submission', 'Runtime identity is verified through the main app container rather than the separate SCM/Kudu wwwroot view', 'Basic B1, Entra Kudu, Run-From-Package, /home/data, seed rollback/removal, health, and restart persistence gates remain enforced')

    Assert-AzureContext | Out-Null
    Assert-Module 'Az.Websites'

    $planEvidence = $null
    $zipEvidence = $null
    $startupEvidence = $null
    $runtimeContractEvidence = $null
    $settingsEvidence = $null
    $webAppEvidence = $null
    $mainSiteEvidence = $null
    $scmEvidence = $null
    $homeDataWriteEvidence = $null
    $sqliteTargetEvidence = $null
    $sourceContractEvidence = $null
    $deploymentEvidence = $null
    $runtimePackageBeforeRestart = $null
    $runtimePackageAfterRestart = $null
    $finalStartupContract = $null
    $finalKuduPackageIdentity = $null
    $finalHealth = $null
    $finalRuntimePackageIdentity = $null
    $finalDemoStatus = $null
    $wwwrootBefore = $null
    $bearerToken = $null
    $seedBackup = @{}
    $seedRemovalAttempted = $false
    $success = $false

    try {
        $planEvidence = Assert-MinimumPaidB1Plan
        $sourceContractEvidence = Sync-GeneratedMenu24SourceContract
        $webAppEvidence = Ensure-WebAppRunning
        $bearerToken = Get-AzBearerTokenText
        $scmEvidence = Wait-KuduReady -BearerToken $bearerToken -TimeoutSeconds 420

        $runtimeContractEvidence = Resolve-AzureDeploymentRuntimeContract -BearerToken $bearerToken
        $startupEvidence = $runtimeContractEvidence.StartupContract
        $zipPath = [string]$runtimeContractEvidence.SelectedZipPath
        $packageMode = [string]$runtimeContractEvidence.PackageDeploymentMode
        if (-not $zipPath -or -not (Test-Path -LiteralPath $zipPath -PathType Leaf)) { throw "Selected deployment ZIP is missing. Mode=$packageMode; Path=$zipPath" }
        $zipEvidence = Test-DeploymentZipContract -ZipPath $zipPath -ExpectedMode $packageMode
        $script:ExpectedPackageIdentity = $zipEvidence.LinuxX64RuntimeContract.PackageManifest
        if ($zipEvidence.LinuxX64RuntimeContract.StartupCommand -ne $startupEvidence.StartupCommand) {
            throw "Selected package and App Service startup commands disagree. Package=$($zipEvidence.LinuxX64RuntimeContract.StartupCommand); AppService=$($startupEvidence.StartupCommand)."
        }
        $zipEvidence | Format-List

        $settings = Assert-Menu24Settings
        $settingsEvidence = Get-RedactedMenu24Settings -Settings $settings
        $settingsEvidence | Format-List
        foreach ($name in @('DNGRMS_SEED_ADMIN_USERNAME','DNGRMS_SEED_USER_USERNAME','DNGRMS_SEED_ADMIN_EMAIL','DNGRMS_SEED_ADMIN_PASSWORD','DNGRMS_SEED_USER_PASSWORD')) {
            if ($settings.ContainsKey($name)) { $seedBackup[$name] = [string]$settings[$name] }
        }
        $settings = $null

        Write-Step 'Capturing a non-blocking pre-deployment main-site probe...'
        $mainProbe = Invoke-DngrmsHttpRequest -Method GET -Uri (Get-WebAppBaseUrl) -TimeoutSeconds 30
        $disposition = 'ReachableBeforeDeployment'
        if ($mainProbe.StatusCode -eq 503) { $disposition = 'ExpectedBootstrap503BeforeZipDeployment' }
        elseif ($mainProbe.StatusCode -eq 0) { $disposition = 'TransportUnavailableBeforeDeployment' }
        elseif ($mainProbe.StatusCode -ge 500) { $disposition = 'ServerUnavailableBeforeDeployment' }
        if ($mainProbe.StatusCode -eq 503 -or $mainProbe.StatusCode -eq 0 -or $mainProbe.StatusCode -ge 500) {
            Write-WarningMessage "Main site is not ready before ZIP deployment (HTTP=$($mainProbe.StatusCode); Category=$($mainProbe.FailureCategory); Disposition=$disposition). It is recorded as evidence and does not block Kudu deployment."
        }
        $mainSiteEvidence = [pscustomobject][ordered]@{
            Probe=(ConvertTo-HttpEvidenceSummary $mainProbe); Disposition=$disposition; BlockedDeployment=$false
        }

        $homeDataWriteEvidence = Test-KuduHomeDataWrite -BearerToken $bearerToken
        if (-not $homeDataWriteEvidence.Succeeded) {
            throw "Kudu /home/data write test failed. $($homeDataWriteEvidence.FailureReason) HTTP=$($homeDataWriteEvidence.CommandHttpStatus); ExitCode=$($homeDataWriteEvidence.ExitCode); Output=$($homeDataWriteEvidence.Output); Error=$($homeDataWriteEvidence.Error); Redacted evidence=$($homeDataWriteEvidence.EvidencePath)"
        }
        $sqliteTargetEvidence = Repair-KuduSqliteTarget -BearerToken $bearerToken

        $deploymentAttempts = @()
        $deploymentResult = $null
        $submission = $null
        $repairEvidence = $null
        for ($attemptNumber = 1; $attemptNumber -le 2; $attemptNumber++) {
            Write-Step ("Capturing the pre-submission identity-verified wwwroot baseline for package deployment attempt {0}..." -f $attemptNumber)
            $wwwrootBefore = Get-KuduWwwrootContractSnapshot -BearerToken $bearerToken
            $submission = Submit-KuduZipDeployment -ZipPath $zipPath -BearerToken $bearerToken
            $script:Menu24DeploymentSubmittedUtc = [DateTime]::Parse([string]$submission.Correlation.SubmittedUtc, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
            $script:Menu24RuntimeLogNotBeforeUtc = $script:Menu24DeploymentSubmittedUtc
            $deploymentResult = Wait-KuduDeployment -PollUri $submission.PollUri -BearerToken $bearerToken `
                -CorrelationSeed $submission.Correlation -BaselineWwwroot $wwwrootBefore `
                -TimeoutSeconds 600 -PollIntervalSeconds 12
            $deploymentAttempts += [pscustomobject][ordered]@{
                Attempt=$attemptNumber
                Submission=$submission.Submit
                SubmissionCorrelation=$deploymentResult.Correlation
                BaselineWwwrootContract=$wwwrootBefore
                Outcome=$deploymentResult.Outcome
                Determination=$deploymentResult.Determination
                FailurePhase=$deploymentResult.FailurePhase
                FailureReason=$deploymentResult.FailureReason
                FailureClassification=$deploymentResult.FailureClassification
                FinalDeployment=$deploymentResult.Deployment
                FinalPollUri=$deploymentResult.FinalPollUri
                PollHistory=$deploymentResult.History
                RecoveryHistory=$deploymentResult.RecoveryHistory
                ReadinessRestartHistory=$deploymentResult.ReadinessRestartHistory
                RuntimeDiagnosticsHistory=@(Get-ObjectPropertyValue $deploymentResult 'RuntimeDiagnosticsHistory' @())
                RuntimeRepairHistory=@(Get-ObjectPropertyValue $deploymentResult 'RuntimeRepairHistory' @())
                RuntimeHealthHistory=@(Get-ObjectPropertyValue $deploymentResult 'RuntimeHealthHistory' @())
                PostDeploymentStartupContract=(Get-ObjectPropertyValue $deploymentResult 'PostDeploymentStartupContract' $null)
                LocationPollingStopped=$deploymentResult.LocationPollingStopped
                LocationStoppedUtc=$deploymentResult.LocationStoppedUtc
                RepairAppliedBeforeNextAttempt=$null
            }
            if ($deploymentResult.Outcome -eq 'Succeeded') { break }

            $repairable = $false
            if ($null -ne $deploymentResult.FailureClassification) {
                $repairable = ConvertTo-KuduBoolean (Get-ObjectPropertyValue $deploymentResult.FailureClassification 'Repairable' $false)
            }
            if ($attemptNumber -eq 1 -and $deploymentResult.FailurePhase -eq 'Deployment' -and $repairable) {
                $repairEvidence = Invoke-KuduDeploymentRepair -FailureClassification $deploymentResult.FailureClassification -BearerToken $bearerToken
                $deploymentAttempts[$deploymentAttempts.Count - 1].RepairAppliedBeforeNextAttempt = $repairEvidence
                Write-WarningMessage 'The first deployment failed for an evidence-backed repairable deployment cause. One repair was applied; the same validated ZIP will be submitted exactly once more.'
                continue
            }
            break
        }

        $deploymentEvidence = [pscustomobject][ordered]@{
            DeploymentMode="Package-based ZIP deployment (WEBSITE_RUN_FROM_PACKAGE=1); PackageDeploymentMode=$packageMode"
            PackageDeploymentMode=$packageMode
            RuntimeContract=$runtimeContractEvidence
            BuildAutomation='SCM_DO_BUILD_DURING_DEPLOYMENT=false; ENABLE_ORYX_BUILD=false'
            Attempts=$deploymentAttempts
            Repair=$repairEvidence
            Submission=if ($null -ne $submission) { $submission.Submit } else { $null }
            SubmissionCorrelation=if ($null -ne $deploymentResult) { $deploymentResult.Correlation } else { $null }
            BaselineWwwrootContract=$wwwrootBefore
            Outcome=if ($null -ne $deploymentResult) { $deploymentResult.Outcome } else { 'Failed' }
            Determination=if ($null -ne $deploymentResult) { $deploymentResult.Determination } else { 'NoDeploymentResult' }
            FailurePhase=if ($null -ne $deploymentResult) { $deploymentResult.FailurePhase } else { 'Deployment' }
            FailureReason=if ($null -ne $deploymentResult) { $deploymentResult.FailureReason } else { 'No deployment result was returned.' }
            FailureClassification=if ($null -ne $deploymentResult) { $deploymentResult.FailureClassification } else { $null }
            FinalDeployment=if ($null -ne $deploymentResult) { $deploymentResult.Deployment } else { $null }
            FinalPollUri=if ($null -ne $deploymentResult) { $deploymentResult.FinalPollUri } else { '' }
            PollHistory=if ($null -ne $deploymentResult) { $deploymentResult.History } else { @() }
            RecoveryHistory=if ($null -ne $deploymentResult) { $deploymentResult.RecoveryHistory } else { @() }
            ReadinessRestartHistory=if ($null -ne $deploymentResult) { $deploymentResult.ReadinessRestartHistory } else { @() }
            RuntimeDiagnosticsHistory=if ($null -ne $deploymentResult) { @(Get-ObjectPropertyValue $deploymentResult 'RuntimeDiagnosticsHistory' @()) } else { @() }
            RuntimeRepairHistory=if ($null -ne $deploymentResult) { @(Get-ObjectPropertyValue $deploymentResult 'RuntimeRepairHistory' @()) } else { @() }
            RuntimeHealthHistory=if ($null -ne $deploymentResult) { @(Get-ObjectPropertyValue $deploymentResult 'RuntimeHealthHistory' @()) } else { @() }
            PostDeploymentStartupContract=if ($null -ne $deploymentResult) { Get-ObjectPropertyValue $deploymentResult 'PostDeploymentStartupContract' $null } else { $null }
            LocationPollingStopped=if ($null -ne $deploymentResult) { $deploymentResult.LocationPollingStopped } else { $false }
            LocationStoppedUtc=if ($null -ne $deploymentResult) { $deploymentResult.LocationStoppedUtc } else { '' }
        }
        if ($null -eq $deploymentResult -or $deploymentResult.Outcome -ne 'Succeeded') {
            $category = ''
            $actualCause = ''
            if ($null -ne $deploymentResult -and $null -ne $deploymentResult.FailureClassification) {
                $category = [string](Get-ObjectPropertyValue $deploymentResult.FailureClassification 'Category' '')
                $actualCause = [string](Get-ObjectPropertyValue $deploymentResult.FailureClassification 'EvidenceText' '')
            }
            throw "Kudu deployment was not safely verified. Outcome=$($deploymentEvidence.Outcome); Phase=$($deploymentEvidence.FailurePhase); Determination=$($deploymentEvidence.Determination); Category=$category; Reason=$($deploymentEvidence.FailureReason); RetrievedCause=$actualCause"
        }
        $finalStatus = [int](Get-ObjectPropertyValue $deploymentResult.Deployment 'status' -1)
        if ($finalStatus -ne 4) { throw "Kudu deployment did not finish with status 4. Final status=$finalStatus. Existing startup files are not accepted as success." }
        $deploymentEvidence | Add-Member -NotePropertyName FinalStatus -NotePropertyValue $finalStatus
        $deploymentEvidence | Add-Member -NotePropertyName FinalStatusText -NotePropertyValue ([string](Get-ObjectPropertyValue $deploymentResult.Deployment 'status_text' ''))
        $deploymentEvidence | Add-Member -NotePropertyName DeploymentId -NotePropertyValue ([string](Get-ObjectPropertyValue $deploymentResult.Deployment 'id' ''))

        Write-Step 'Revalidating Healthy/Connected before the SQLite restart-persistence test...'
        $health = Wait-HealthContract -TimeoutSeconds 120
        $runtimePackageBeforeRestart = Assert-RuntimePackageIdentity -ExpectedPackageIdentity $script:ExpectedPackageIdentity -Label 'before restart persistence test'
        $persistence = Test-SqliteRestartPersistence -BearerToken $bearerToken
        $runtimePackageAfterRestart = Assert-RuntimePackageIdentity -ExpectedPackageIdentity $script:ExpectedPackageIdentity -Label 'after restart persistence test'

        Write-Step 'Removing all one-time DNGRMS_SEED_* settings only after deployment, health, package identity, and restart persistence succeeded...'
        $seedRemovalAttempted = $true
        Remove-AzWebAppSettingSafe @('DNGRMS_SEED_ADMIN_USERNAME','DNGRMS_SEED_USER_USERNAME','DNGRMS_SEED_ADMIN_EMAIL','DNGRMS_SEED_ADMIN_PASSWORD','DNGRMS_SEED_USER_PASSWORD')
        $afterRemoval = Get-AzWebAppSettingsHashtable
        $remaining = @(@('DNGRMS_SEED_ADMIN_USERNAME','DNGRMS_SEED_USER_USERNAME','DNGRMS_SEED_ADMIN_EMAIL','DNGRMS_SEED_ADMIN_PASSWORD','DNGRMS_SEED_USER_PASSWORD') | Where-Object { $afterRemoval.ContainsKey($_) })
        if (@($remaining).Count -gt 0) { throw "Seed setting removal verification failed: $(@($remaining) -join ', ')" }

        # Removing App Settings recycles the worker. Re-run the complete final
        # contract so success describes the post-cleanup state, not the state
        # immediately before seed removal.
        $finalStartupContract = Confirm-PostDeploymentStartupContract -BearerToken $bearerToken
        $finalHealth = Wait-HealthContract -TimeoutSeconds 600
        $finalKuduPackageIdentity = Get-KuduWwwrootContractSnapshot -BearerToken $bearerToken
        if (-not $finalKuduPackageIdentity.Ready -or -not $finalKuduPackageIdentity.IdentityMatched) {
            Write-WarningMessage "Kudu/SCM wwwroot does not expose the main worker Run-From-Package mount. This diagnostic view is not a success gate. Missing=$(@($finalKuduPackageIdentity.MissingFiles) -join ',')."
        }
        $finalRuntimePackageIdentity = Assert-RuntimePackageIdentity -ExpectedPackageIdentity $script:ExpectedPackageIdentity -Label 'after seed settings removal'
        $finalDemoStatus = Get-DemoStatusSnapshot
        $finalUserCount = [int](Get-ObjectPropertyValue $finalDemoStatus 'userCount' -1)
        if ($finalUserCount -lt 2 -or $finalUserCount -ne [int]$persistence.AfterUserCount) {
            throw "Final seeded-user verification failed after seed removal. Expected=$($persistence.AfterUserCount); Actual=$finalUserCount."
        }

        $successEvidence = [ordered]@{
            LauncherVersion=$script:LauncherVersion
            CapturedUtc=[DateTime]::UtcNow.ToString('o')
            Plan=$planEvidence
            Zip=$zipEvidence
            StartupContract=$startupEvidence
            PreDeploymentRuntimeContract=$runtimeContractEvidence
            PackageDeploymentMode=$packageMode
            AppSettingsBeforeRemoval=$settingsEvidence
            WebAppReadiness=$webAppEvidence
            MainSitePreDeployment=$mainSiteEvidence
            ScmReadiness=$scmEvidence
            HomeDataWrite=$homeDataWriteEvidence
            SqliteTargetPreflight=$sqliteTargetEvidence
            SourceContractSync=$sourceContractEvidence
            Deployment=$deploymentEvidence
            Health=$health
            RuntimePackageIdentityBeforeRestart=$runtimePackageBeforeRestart
            Persistence=$persistence
            RuntimePackageIdentityAfterRestart=$runtimePackageAfterRestart
            FinalStartupContractAfterSeedRemoval=$finalStartupContract
            FinalKuduPackageIdentityAfterSeedRemoval=$finalKuduPackageIdentity
            FinalHealthAfterSeedRemoval=$finalHealth
            FinalRuntimePackageIdentityAfterSeedRemoval=$finalRuntimePackageIdentity
            FinalDemoStatusAfterSeedRemoval=$finalDemoStatus
            SeedSettingsRemoved=$true
            RemovedSeedSettingNames=@('DNGRMS_SEED_ADMIN_USERNAME','DNGRMS_SEED_USER_USERNAME','DNGRMS_SEED_ADMIN_EMAIL','DNGRMS_SEED_ADMIN_PASSWORD','DNGRMS_SEED_USER_PASSWORD')
            SecurityNote='Bearer tokens and seed values are excluded from evidence.'
        }
        $evidencePath = Write-EvidenceJson -Name 'menu24-deployment-success' -Data $successEvidence
        $success = $true
        Write-Success "Deployment was safely verified in $packageMode mode ($($deploymentResult.Determination)); exact package identity, verified system-sqlite3 SONAME and managed-provider contract, writable-home bootstrap startup contract, /health Healthy/Connected, SQLite seeded users, restart persistence, seed removal, and the complete post-removal contract passed. Evidence: $evidencePath"
        Complete-Menu '24'
    }
    catch {
        $originalError = $_
        if ($seedRemovalAttempted -and $null -ne $seedBackup -and @($seedBackup.Keys).Count -gt 0) {
            try {
                Set-AzWebAppSettingsSafe $seedBackup
                Write-WarningMessage 'A failure occurred after seed removal began; the in-memory seed backup was restored for recovery.'
            }
            catch { Write-WarningMessage "Seed restoration also failed: $($_.Exception.Message)" }
        }
        else { Write-WarningMessage 'Menu 24 failed before seed removal; one-time seed settings were retained.' }

        $diagnosticPath = '<diagnostic bundle creation failed>'
        try {
            $diagnosticPath = Write-Menu24DiagnosticBundle -ErrorMessage $originalError.Exception.Message `
                -PlanEvidence $planEvidence -WebAppEvidence $webAppEvidence -ZipEvidence $zipEvidence `
                -StartupEvidence $runtimeContractEvidence -SettingsEvidence $settingsEvidence -MainSiteEvidence $mainSiteEvidence `
                -ScmEvidence $scmEvidence -HomeDataWriteEvidence $homeDataWriteEvidence -DeploymentEvidence $deploymentEvidence
        }
        catch { Write-WarningMessage "Automatic diagnostic bundle creation also failed: $($_.Exception.Message)" }
        throw "$($originalError.Exception.Message) Automatic Kudu/App Service diagnostics: $diagnosticPath"
    }
    finally {
        $bearerToken = $null
        $seedBackup = $null
        if (-not $success) { [GC]::Collect() }
    }
}

function Invoke-Menu25 {
    Write-DemoHeader '25' 'Validate Web App health, runtime configuration, HTTPS, and demo status.' `
        -AzurePortal @('Azure portal > App Services > <demo app> > Overview', 'Azure portal > App Services > <demo app> > Diagnose and solve problems')
    Assert-AzureContext | Out-Null
    $health = Invoke-RestMethod -Uri "$(Get-WebAppBaseUrl)/health" -Method Get
    $status = Invoke-RestMethod -Uri "$(Get-WebAppBaseUrl)/api/demo/status" -Method Get
    $webApp = Get-AzWebApp -ResourceGroupName $script:State.ResourceGroupName -Name $script:State.WebAppName
    $evidence = [ordered]@{ Health=$health; Status=$status; HttpsOnly=$webApp.HttpsOnly; State=$webApp.State; DefaultHostName=$webApp.DefaultHostName }
    $evidence | ConvertTo-Json -Depth 10 | Write-Host
    Write-EvidenceJson -Name 'app-service-health' -Data $evidence | ForEach-Object { Write-Host "Evidence: $_" }
    Complete-Menu '25'
}

function Invoke-Menu26 {
    Write-DemoHeader '26' 'Open the Azure-hosted Local ID/password login and validate the pre-migration state.' `
        -Expected @('User can sign in with the seeded local credential.', 'Dashboard shows auth_method=Local.')
    $url = "$(Get-WebAppBaseUrl)/account/login"
    Start-Process $url
    Write-Host "Opened: $url"
    Write-Host "After login, verify: $(Get-WebAppBaseUrl)/home/authdebug"
    Complete-Menu '26'
}

function Invoke-Menu27 {
    Write-DemoHeader '27' 'Restart the Web App and verify that SQLite user/audit state persists under /home/data.' `
        -Expected @('User count remains unchanged after restart.', 'Database reconnects successfully.')
    Assert-AzureContext | Out-Null
    $before = Invoke-RestMethod -Uri "$(Get-WebAppBaseUrl)/api/demo/status"
    Restart-AzWebApp -ResourceGroupName $script:State.ResourceGroupName -Name $script:State.WebAppName | Out-Null
    Wait-WebEndpoint -Uri "$(Get-WebAppBaseUrl)/health" -TimeoutSeconds 300 | Out-Null
    $after = Invoke-RestMethod -Uri "$(Get-WebAppBaseUrl)/api/demo/status"
    [pscustomobject]@{BeforeUserCount=$before.userCount;AfterUserCount=$after.userCount;BeforeAuditCount=$before.auditCount;AfterAuditCount=$after.auditCount} | Format-List
    if ($before.userCount -ne $after.userCount) { throw 'User count changed after restart. Persistence validation failed.' }
    Write-Success 'SQLite persistence survived the App Service restart.'
    Complete-Menu '27'
}

function Invoke-Menu28 {
    Write-DemoHeader '28' 'Enable App Service application logging and display the log-stream command.' `
        -AzurePortal @('Azure portal > App Services > <demo app> > Monitoring > App Service logs', 'Azure portal > App Services > <demo app> > Monitoring > Log stream')
    Assert-AzureContext | Out-Null
    $resource = Get-AzWebApp -ResourceGroupName $script:State.ResourceGroupName -Name $script:State.WebAppName
    try {
        Set-AzResource -ResourceId "$($resource.Id)/config/logs" -ApiVersion '2023-12-01' -Properties @{
            applicationLogs=@{ fileSystem=@{ level='Information' } };
            httpLogs=@{ fileSystem=@{ enabled=$true; retentionInMb=35; retentionInDays=3 } };
            detailedErrorMessages=@{ enabled=$true }; failedRequestsTracing=@{ enabled=$true }
        } -Force | Out-Null
        Write-Success 'Application and HTTP file-system logging enabled.'
    }
    catch { Write-WarningMessage "Logging configuration needs Portal verification: $($_.Exception.Message)" }
    Write-Host "`nOptional live stream command:"
    Write-Host "Get-AzWebAppLog -ResourceGroupName '$($script:State.ResourceGroupName)' -Name '$($script:State.WebAppName)'"
    Complete-Menu '28'
}

function Invoke-Menu29 {
    Write-DemoHeader '29' 'Capture Azure resource and application evidence for the Local baseline.' `
        -AzurePortal @('Azure portal > Resource groups > <demo resource group> > Resources')
    Assert-AzureContext | Out-Null
    $resources = Get-AzResource -ResourceGroupName $script:State.ResourceGroupName | Select-Object Name,ResourceType,Location,ResourceId
    $status = Invoke-RestMethod -Uri "$(Get-WebAppBaseUrl)/api/demo/status"
    $evidence = [ordered]@{ CapturedUtc=[DateTime]::UtcNow; Resources=$resources; ApplicationStatus=$status; State=$script:State }
    $path = Write-EvidenceJson -Name 'azure-local-baseline' -Data $evidence
    $resources | Format-Table -AutoSize
    Write-Success "Azure evidence captured: $path"
    Complete-Menu '29'
}

function Get-DemoAdminApiKey {
    $settings = Get-AzWebAppSettingsHashtable
    $key = $settings['DNGRMS_DEMO_ADMIN_KEY']
    if (-not $key) { throw 'DNGRMS_DEMO_ADMIN_KEY is not configured. Run menu 23.' }
    return $key
}

function Invoke-DemoAdminApi {
    param(
        [Parameter(Mandatory)][ValidateSet('GET','POST')][string]$Method,
        [Parameter(Mandatory)][string]$Path
    )
    $key = Get-DemoAdminApiKey
    try {
        return Invoke-RestMethod -Method $Method -Uri "$(Get-WebAppBaseUrl)$Path" -Headers @{ 'X-Demo-Admin-Key'=$key }
    }
    finally { $key = $null }
}

function Add-CurrentGraphUserAssignment {
    param([Parameter(Mandatory)][string]$ServicePrincipalId)
    $me = Invoke-GraphJson -Method GET -Uri 'https://graph.microsoft.com/v1.0/me?$select=id,displayName,userPrincipalName'
    $resource = Invoke-GraphJson -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$ServicePrincipalId`?`$select=id,appId,displayName,appRoles,appRoleAssignmentRequired"
    Invoke-GraphJson -Method PATCH -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$ServicePrincipalId" -Body @{ appRoleAssignmentRequired=$true } | Out-Null

    $enabledUserRoles = @($resource.appRoles | Where-Object {
        $_.isEnabled -eq $true -and @($_.allowedMemberTypes) -contains 'User'
    })
    if ($enabledUserRoles.Count -eq 0) {
        $selectedAppRoleId = '00000000-0000-0000-0000-000000000000'
        $selectedRoleDisplayName = 'Default Access (no appRoles exposed)'
    }
    elseif ($enabledUserRoles.Count -eq 1) {
        $selectedAppRoleId = [string]$enabledUserRoles[0].id
        $selectedRoleDisplayName = [string]$enabledUserRoles[0].displayName
    }
    else {
        $msiamAccessRoles = @($enabledUserRoles | Where-Object {
            [string]$_.displayName -ieq 'msiam_access' -or [string]$_.value -ieq 'msiam_access'
        })
        if ($msiamAccessRoles.Count -ne 1) {
            $roleSummary = @($enabledUserRoles | ForEach-Object { "$($_.displayName) [$($_.id)]" }) -join '; '
            throw "Multiple enabled user-assignable app roles exist and exactly one msiam_access role could not be selected. Roles=$roleSummary"
        }
        $selectedAppRoleId = [string]$msiamAccessRoles[0].id
        $selectedRoleDisplayName = 'Default Access (msiam_access)'
    }

    $existing = Invoke-GraphJson -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$ServicePrincipalId/appRoleAssignedTo"
    $assignment = @($existing.value | Where-Object {
        [string]$_.principalId -eq [string]$me.id -and [string]$_.resourceId -eq $ServicePrincipalId
    }) | Select-Object -First 1
    if ($assignment -and [string]$assignment.appRoleId -ne $selectedAppRoleId) {
        throw "The current user already has a different app-role assignment for this resource. ExistingAppRoleId=$($assignment.appRoleId); ExpectedAppRoleId=$selectedAppRoleId"
    }
    if (-not $assignment) {
        $assignment = Invoke-GraphJson -Method POST -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$ServicePrincipalId/appRoleAssignedTo" -Body @{
            principalId=$me.id; resourceId=$ServicePrincipalId; appRoleId=$selectedAppRoleId
        }
    }
    Start-Sleep -Seconds 2
    $readBack = Invoke-GraphJson -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$ServicePrincipalId/appRoleAssignedTo"
    $verified = @($readBack.value | Where-Object {
        [string]$_.principalId -eq [string]$me.id -and
        [string]$_.resourceId -eq $ServicePrincipalId -and
        [string]$_.appRoleId -eq $selectedAppRoleId
    }) | Select-Object -First 1
    if (-not $verified) { throw "App-role assignment read-back failed. PrincipalId=$($me.id); ResourceId=$ServicePrincipalId; AppRoleId=$selectedAppRoleId" }
    return [pscustomobject]@{
        User=$me; Assignment=$verified; Resource=$resource; SelectedAppRoleId=$selectedAppRoleId; SelectedRoleDisplayName=$selectedRoleDisplayName
    }
}

function Invoke-Menu30 {
    Write-DemoHeader '30' 'Create or reuse the Microsoft Entra OIDC application registration and service principal.' `
        -EntraPortal @('Microsoft Entra admin center > Entra ID > App registrations > All applications', 'Microsoft Entra admin center > Entra ID > Enterprise applications > All applications') `
        -Expected @('PREREQUISITE: Menu 3 Microsoft Graph delegated sign-in must be complete and current', 'Required Graph scopes and tenant alignment are validated before any write', 'Single-tenant application object', 'Enterprise application/service principal')
    Write-Host ''
    Write-Host '[PREREQUISITE - MICROSOFT GRAPH]' -ForegroundColor Yellow
    Write-Host '- Menu 3 must be completed before Menu 30.'
    Write-Host '- An active Microsoft Graph delegated session is required.'
    Write-Host '- If the session expired or consent changed, rerun Menu 3 before continuing.'
    Write-Host ''
    $graphContext = Assert-GraphDelegatedPrerequisite -RequiredScopes @('Application.ReadWrite.All','AppRoleAssignment.ReadWrite.All','User.Read')
    Write-Success "Graph prerequisite verified. Tenant=$($graphContext.TenantId); Account=$($graphContext.Account)"
    $application = $null
    if ($script:State.OidcApplicationObjectId) {
        try { $application = Invoke-GraphJson GET "https://graph.microsoft.com/v1.0/applications/$($script:State.OidcApplicationObjectId)" }
        catch { $application = $null }
    }
    if (-not $application) {
        $displayName = "DNGRMS Demo OIDC - $($script:State.WebAppName)"
        $application = Invoke-GraphJson POST 'https://graph.microsoft.com/v1.0/applications' @{
            displayName=$displayName; signInAudience='AzureADMyOrg'
            web=@{ redirectUris=@(); implicitGrantSettings=@{enableAccessTokenIssuance=$false;enableIdTokenIssuance=$false} }
        }
        $servicePrincipal = Invoke-GraphJson POST 'https://graph.microsoft.com/v1.0/servicePrincipals' @{
            appId=$application.appId; appRoleAssignmentRequired=$true; tags=@('WindowsAzureActiveDirectoryIntegratedApp')
        }
        $script:State.OidcApplicationObjectId = $application.id
        $script:State.OidcApplicationClientId = $application.appId
        $script:State.OidcServicePrincipalId = $servicePrincipal.id
        Save-State
    }
    $application | Select-Object id,appId,displayName,signInAudience | Format-List
    Write-Success 'OIDC application registration and enterprise application are ready.'
    Complete-Menu '30'
}

function Invoke-Menu31 {
    Write-DemoHeader '31' 'Configure and verify exact OIDC redirect and logout callback URIs for the Web App.' `
        -EntraPortal @(
            'Microsoft Entra admin center > Entra ID > App registrations > All applications > <DNGRMS Demo OIDC> > Manage > Authentication (Preview) > Redirect URI configuration',
            'If Preview does not show the Web platform: switch to the old experience > Platform configurations > Web > Redirect URIs / Front-channel logout URL'
        ) `
        -Expected @('Microsoft Graph PATCH targets the Application object, not the service principal', 'Graph read-back exactly matches web.redirectUris and web.logoutUrl', 'Evidence is written before success is reported')
    if (-not $script:State.OidcApplicationObjectId) { throw 'Run Menu 30 first.' }
    $null = Assert-GraphDelegatedPrerequisite -RequiredScopes @('Application.ReadWrite.All','User.Read')
    $base = Get-WebAppBaseUrl
    $expectedRedirect = "$base/signin-oidc"
    $expectedLogout = "$base/signout-callback-oidc"
    $applicationUri = "https://graph.microsoft.com/v1.0/applications/$($script:State.OidcApplicationObjectId)"
    $before = Invoke-GraphJson GET "$applicationUri`?`$select=id,appId,displayName,web"
    $body = @{
        web=@{
            redirectUris=@($expectedRedirect)
            logoutUrl=$expectedLogout
            implicitGrantSettings=@{ enableAccessTokenIssuance=$false; enableIdTokenIssuance=$false }
        }
    }
    Invoke-GraphJson PATCH $applicationUri $body | Out-Null
    $verified = $null
    $attempts = @()
    for ($attempt = 1; $attempt -le 6; $attempt++) {
        Start-Sleep -Seconds $(if ($attempt -eq 1) { 2 } else { 5 })
        $current = Invoke-GraphJson GET "$applicationUri`?`$select=id,appId,displayName,web"
        $actualRedirects = @($current.web.redirectUris)
        $actualLogout = [string]$current.web.logoutUrl
        $redirectMatched = ($actualRedirects.Count -eq 1 -and $actualRedirects[0] -ceq $expectedRedirect)
        $logoutMatched = ($actualLogout -ceq $expectedLogout)
        $attempts += [pscustomobject][ordered]@{
            Attempt=$attempt; CapturedUtc=[DateTime]::UtcNow.ToString('o'); RedirectUris=$actualRedirects;
            LogoutUrl=$actualLogout; RedirectMatched=$redirectMatched; LogoutMatched=$logoutMatched
        }
        Write-Host "Graph read-back $attempt/6: RedirectMatched=$redirectMatched; LogoutMatched=$logoutMatched"
        if ($redirectMatched -and $logoutMatched) { $verified = $current; break }
    }
    $evidence = [ordered]@{
        LauncherVersion=$script:LauncherVersion; CapturedUtc=[DateTime]::UtcNow.ToString('o');
        ApplicationObjectId=$script:State.OidcApplicationObjectId; ApplicationClientId=$script:State.OidcApplicationClientId;
        ExpectedRedirectUri=$expectedRedirect; ExpectedLogoutUrl=$expectedLogout;
        BeforeWeb=$before.web; Attempts=$attempts; Verified=($null -ne $verified);
        VerifiedWeb=if ($verified) { $verified.web } else { $null };
        PortalPaths=@(
            'Entra ID > App registrations > All applications > <DNGRMS Demo OIDC> > Authentication (Preview) > Redirect URI configuration',
            'Old experience > Platform configurations > Web > Redirect URIs / Front-channel logout URL'
        )
    }
    $evidencePath = Write-EvidenceJson -Name 'menu31-oidc-web-platform-graph-readback' -Data $evidence
    if (-not $verified) {
        $last = @($attempts)[-1]
        throw "OIDC Web platform Graph read-back verification failed. ExpectedRedirect=$expectedRedirect; ActualRedirects=$(@($last.RedirectUris) -join ','); ExpectedLogout=$expectedLogout; ActualLogout=$($last.LogoutUrl); Evidence=$evidencePath"
    }
    Write-Host "Redirect URI : $expectedRedirect"
    Write-Host "Logout URL   : $expectedLogout"
    Write-Host "Application object id : $($script:State.OidcApplicationObjectId)"
    Write-Success "OIDC Web platform URIs configured and verified through Microsoft Graph. Evidence: $evidencePath"
    Complete-Menu '31'
}

function Invoke-Menu32 {
    Write-DemoHeader '32' 'Create a short-lived OIDC client secret and place it directly in App Service settings.' `
        -EntraPortal @('Entra ID > App registrations > <DNGRMS Demo OIDC> > Certificates & secrets') `
        -AzurePortal @('App Services > <demo app> > Settings > Environment variables') `
        -Expected @('Secret value is never written to launcher state or evidence.', 'Credential lifetime defaults to 7 days.')
    if (-not $script:State.OidcApplicationObjectId) { throw 'Run menu 30 first.' }
    $days = [int](Read-Choice 'Credential lifetime in days (1-30)' '7')
    if ($days -lt 1 -or $days -gt 30) { throw 'For this demo, choose 1 through 30 days.' }
    $credential = Invoke-GraphJson POST "https://graph.microsoft.com/v1.0/applications/$($script:State.OidcApplicationObjectId)/addPassword" @{
        passwordCredential=@{
            displayName="DNGRMS demo launcher v$script:LauncherVersion"
            startDateTime=[DateTime]::UtcNow.ToString('o')
            endDateTime=[DateTime]::UtcNow.AddDays($days).ToString('o')
        }
    }
    if (-not $credential.secretText) { throw 'Microsoft Graph did not return secretText.' }
    try {
        Set-AzWebAppSettingsSafe @{
            'Oidc__TenantId'=$script:State.TenantId
            'Oidc__ClientId'=$script:State.OidcApplicationClientId
            'Oidc__ClientSecret'=$credential.secretText
            'Oidc__CallbackPath'='/signin-oidc'
            'Oidc__SignedOutCallbackPath'='/signout-callback-oidc'
        }
        $script:State.OidcPasswordKeyId = $credential.keyId
        $script:State.OidcPasswordEndDateTime = $credential.endDateTime
        Save-State
    }
    finally { $credential = $null }
    Restart-AzWebApp -ResourceGroupName $script:State.ResourceGroupName -Name $script:State.WebAppName | Out-Null
    Write-Success 'OIDC credential configured in App Service. Secret value was not stored in state.'
    Complete-Menu '32'
}

function Invoke-Menu33 {
    Write-DemoHeader '33' 'Require assignment and assign the currently signed-in Entra user as the OIDC pilot user.' `
        -EntraPortal @('Entra ID > Enterprise applications > <DNGRMS Demo OIDC> > Users and groups')
    if (-not $script:State.OidcServicePrincipalId) { throw 'Run menu 30 first.' }
    $result = Add-CurrentGraphUserAssignment $script:State.OidcServicePrincipalId
    $result.User | Select-Object displayName,userPrincipalName,id | Format-List
    Write-Success 'Current user is assigned to the OIDC enterprise application.'
    Complete-Menu '33'
}

function Invoke-Menu34 {
    Write-DemoHeader '34' 'Validate OIDC application settings and the tenant discovery document.' `
        -Expected @('Issuer and authorization/token endpoints are reachable.', 'Web App has tenant/client/secret settings.')
    if (-not $script:State.OidcApplicationClientId) { throw 'OIDC application is not configured.' }
    $discoveryUri = "https://login.microsoftonline.com/$($script:State.TenantId)/v2.0/.well-known/openid-configuration"
    $discovery = Invoke-RestMethod -Uri $discoveryUri -Method Get
    $settings = Get-AzWebAppSettingsHashtable
    [pscustomobject]@{
        Issuer=$discovery.issuer; AuthorizationEndpoint=$discovery.authorization_endpoint;
        TokenEndpoint=$discovery.token_endpoint; ClientIdConfigured=($settings['Oidc__ClientId'] -eq $script:State.OidcApplicationClientId);
        ClientSecretPresent=(-not [string]::IsNullOrWhiteSpace($settings['Oidc__ClientSecret']))
    } | Format-List
    Complete-Menu '34'
}

function Invoke-Menu35 {
    Write-DemoHeader '35' 'Enable Dual mode so Local ID/PW and Microsoft Entra OIDC can be tested side by side.' `
        -Expected @('Existing Local login remains available.', 'OIDC login becomes available after restart.')
    Set-AuthenticationMode Dual
    Wait-WebEndpoint -Uri "$(Get-WebAppBaseUrl)/health" -TimeoutSeconds 300 | Out-Null
    Complete-Menu '35'
}

function Invoke-Menu36 {
    Write-DemoHeader '36' 'Open the OIDC authorization-code-flow login from the DNGRMS application after validating the aligned IdentityModel runtime contract.' `
        -EntraPortal @('Entra ID > Monitoring & health > Sign-in logs') `
        -Expected @('IdentityModel OIDC and SAML dependencies are aligned to 8.22.0.', 'Browser redirects to Microsoft Entra ID.', 'Callback returns to /signin-oidc.', 'Menu 37 confirms the DNGRMS OIDC session and safe claims evidence.')
    $depsCandidates = @(
        (Join-Path $script:LinuxSelfContainedRoot 'DngrmsDemo.Web.deps.json'),
        (Join-Path $script:PublishRoot 'DngrmsDemo.Web.deps.json')
    )
    $depsPath = $depsCandidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
    if (-not $depsPath) { throw 'No published deps.json is available. Run Menu 24 with v1.1.35 before Menu 36.' }
    $contract = Assert-IdentityModelDepsContract -DepsText ([IO.File]::ReadAllText($depsPath)) -Source $depsPath
    Write-Host ''
    Write-Host '[OIDC IDENTITYMODEL CONTRACT]' -ForegroundColor Cyan
    $contract.Versions.PSObject.Properties | ForEach-Object { Write-Host ("{0}={1}" -f $_.Name,$_.Value) }
    Write-Success 'IdentityModel dependency family is aligned to 8.22.0. Browser flow may proceed.'
    $url = "$(Get-WebAppBaseUrl)/account/oidc?returnUrl=%2Fhome%2Fauthdebug"
    Start-Process $url
    Write-Host "Opened: $url"
    Write-WarningMessage 'Menu 36 opens the interactive browser flow. Run Menu 37 after sign-in to verify auth_method=OIDC and session creation.'
    Complete-Menu '36'
}

function Invoke-Menu37 {
    Write-DemoHeader '37' 'Display the safe OIDC claims evidence URL.' `
        -Expected @('auth_method=OIDC', 'oid/tid/sub/name claims as issued', 'No raw token displayed')
    $url = "$(Get-WebAppBaseUrl)/home/authdebug"
    Start-Process $url
    Write-Host "Evidence URL: $url"
    Complete-Menu '37'
}

function Invoke-Menu38 {
    Write-DemoHeader '38' 'Verify the application user-to-Entra identity link created during OIDC sign-in.' `
        -Expected @('Entra Object ID and OIDC subject are stored separately from local password hash.')
    $users = Invoke-DemoAdminApi GET '/api/demo/users'
    $users | Format-Table id,userName,role,localLoginAllowed,entraObjectId,oidcSubject -AutoSize
    Write-EvidenceJson -Name 'oidc-identity-linking' -Data $users | ForEach-Object { Write-Host "Evidence: $_" }
    Complete-Menu '38'
}

function Invoke-Menu39 {
    Write-DemoHeader '39' 'Clear the DNGRMS session and initiate Microsoft Entra OIDC sign-out.' `
        -Expected @('Local application cookie cleared', 'Entra logout callback returns to the app')
    $url = "$(Get-WebAppBaseUrl)/account/oidc-logout"
    Start-Process $url
    Write-Host "Opened: $url"
    Complete-Menu '39'
}

function Invoke-Menu40 {
    Write-DemoHeader '40' 'Create or safely replace the SAML application by instantiating the Microsoft Entra non-gallery SAML application template.' `
        -EntraPortal @('Entra ID > Enterprise applications > All applications') `
        -Expected @(
            'Microsoft Graph non-gallery application template is used',
            'OIDC and SAML remain separate applications',
            'Earlier ordinary App Registration-based SAML objects are replaced only after exact state/name/ID verification',
            'New Application and Service Principal IDs are persisted and verified'
        )
    $null = Assert-GraphDelegatedPrerequisite -RequiredScopes @('Application.ReadWrite.All','AppRoleAssignment.ReadWrite.All','User.Read')
    $templateId = '8adf8e6e-67b2-4cf2-a259-e3dc5476c621'
    $displayName = "DNGRMS Demo SAML - $($script:State.WebAppName)"
    $stage = 'InspectCurrentState'
    $oldApplication = $null
    $oldServicePrincipal = $null
    $replacementRequired = $false
    $instantiateResult = $null
    try {
        if (-not [string]::IsNullOrWhiteSpace([string]$script:State.SamlApplicationObjectId)) {
            try { $oldApplication = Invoke-GraphJson GET "https://graph.microsoft.com/v1.0/applications/$($script:State.SamlApplicationObjectId)?`$select=id,appId,displayName,identifierUris,web" } catch { $oldApplication = $null }
        }
        if (-not [string]::IsNullOrWhiteSpace([string]$script:State.SamlServicePrincipalId)) {
            try { $oldServicePrincipal = Invoke-GraphJson GET "https://graph.microsoft.com/v1.0/servicePrincipals/$($script:State.SamlServicePrincipalId)?`$select=id,appId,displayName,applicationTemplateId,preferredSingleSignOnMode,tags" } catch { $oldServicePrincipal = $null }
        }

        $existingTemplateMatched = ($oldApplication -and $oldServicePrincipal -and
            [string]$oldApplication.displayName -ceq $displayName -and
            [string]$oldServicePrincipal.displayName -ceq $displayName -and
            [string]$oldApplication.appId -ceq [string]$oldServicePrincipal.appId -and
            [string]$oldServicePrincipal.applicationTemplateId -ceq $templateId)

        if ($existingTemplateMatched) {
            Write-Success "Existing non-gallery SAML template instance is reusable. ApplicationObjectId=$($oldApplication.id); ServicePrincipalObjectId=$($oldServicePrincipal.id)"
            $script:State.SamlApplicationObjectId = $oldApplication.id
            $script:State.SamlApplicationClientId = $oldApplication.appId
            $script:State.SamlServicePrincipalId = $oldServicePrincipal.id
            $script:State.SamlEntityId = "api://$($oldApplication.appId)"
            Save-State
            $evidencePath = Write-EvidenceJson -Name 'menu40-saml-template-instance-reused' -Data ([ordered]@{
                LauncherVersion=$script:LauncherVersion; CapturedUtc=[DateTime]::UtcNow.ToString('o'); Outcome='Reused'; TemplateId=$templateId;
                Application=$oldApplication; ServicePrincipal=$oldServicePrincipal
            })
            $oldApplication | Select-Object id,appId,displayName | Format-List
            Write-Success "SAML non-gallery template application objects are ready. Evidence: $evidencePath"
            Complete-Menu '40'
            return
        }

        if ($oldApplication -or $oldServicePrincipal) {
            $exactOldOwnership = ($oldApplication -and $oldServicePrincipal -and
                [string]$oldApplication.id -ceq [string]$script:State.SamlApplicationObjectId -and
                [string]$oldServicePrincipal.id -ceq [string]$script:State.SamlServicePrincipalId -and
                [string]$oldApplication.appId -ceq [string]$script:State.SamlApplicationClientId -and
                [string]$oldApplication.appId -ceq [string]$oldServicePrincipal.appId -and
                [string]$oldApplication.displayName -ceq $displayName -and
                [string]$oldServicePrincipal.displayName -ceq $displayName)
            if (-not $exactOldOwnership) {
                $conflictPath = Write-EvidenceJson -Name 'menu40-saml-object-replacement-blocked' -Data ([ordered]@{
                    LauncherVersion=$script:LauncherVersion; CapturedUtc=[DateTime]::UtcNow.ToString('o'); Outcome='Blocked';
                    Reason='The existing objects do not exactly match launcher state and expected display name; automatic deletion was refused.';
                    ExpectedDisplayName=$displayName; StateApplicationObjectId=$script:State.SamlApplicationObjectId; StateServicePrincipalId=$script:State.SamlServicePrincipalId;
                    StateClientId=$script:State.SamlApplicationClientId; Application=$oldApplication; ServicePrincipal=$oldServicePrincipal
                })
                throw "Existing SAML objects failed the safe ownership contract. Automatic replacement was refused. Evidence=$conflictPath"
            }
            $replacementRequired = $true
            $beforePath = Write-EvidenceJson -Name 'menu40-pre-template-replacement' -Data ([ordered]@{
                LauncherVersion=$script:LauncherVersion; CapturedUtc=[DateTime]::UtcNow.ToString('o'); TemplateId=$templateId;
                Application=$oldApplication; ServicePrincipal=$oldServicePrincipal
            })
            Write-WarningMessage "Replacing the earlier ordinary App Registration-based SAML objects after exact ownership verification. Backup evidence: $beforePath"
            $stage = 'DeleteOldServicePrincipal'
            Invoke-GraphJson DELETE "https://graph.microsoft.com/v1.0/servicePrincipals/$($oldServicePrincipal.id)" | Out-Null
            $stage = 'DeleteOldApplication'
            Invoke-GraphJson DELETE "https://graph.microsoft.com/v1.0/applications/$($oldApplication.id)" | Out-Null
            Start-Sleep -Seconds 5
        }

        $stage = 'InstantiateNonGalleryTemplate'
        $instantiateResult = Invoke-GraphJson POST "https://graph.microsoft.com/v1.0/applicationTemplates/$templateId/instantiate" @{ displayName=$displayName }
        $application = Get-ObjectPropertyValue $instantiateResult 'application' $null
        $servicePrincipal = Get-ObjectPropertyValue $instantiateResult 'servicePrincipal' $null
        if (-not $application -or -not $servicePrincipal) { throw 'The application-template instantiate response did not include both application and servicePrincipal objects.' }

        $stage = 'VerifyTemplateInstance'
        $verifiedApplication = $null
        $verifiedServicePrincipal = $null
        for ($attempt = 1; $attempt -le 6; $attempt++) {
            Start-Sleep -Seconds $(if ($attempt -eq 1) { 3 } else { 5 })
            $verifiedApplication = Invoke-GraphJson GET "https://graph.microsoft.com/v1.0/applications/$($application.id)?`$select=id,appId,displayName"
            $verifiedServicePrincipal = Invoke-GraphJson GET "https://graph.microsoft.com/v1.0/servicePrincipals/$($servicePrincipal.id)?`$select=id,appId,displayName,applicationTemplateId,preferredSingleSignOnMode,tags"
            $templateMatched = ([string]$verifiedServicePrincipal.applicationTemplateId -ceq $templateId)
            $identityMatched = ([string]$verifiedApplication.appId -ceq [string]$verifiedServicePrincipal.appId -and [string]$verifiedApplication.displayName -ceq $displayName -and [string]$verifiedServicePrincipal.displayName -ceq $displayName)
            Write-Host "Template read-back $attempt/6: TemplateMatched=$templateMatched; IdentityMatched=$identityMatched"
            if ($templateMatched -and $identityMatched) { break }
            if ($attempt -eq 6) { throw "Non-gallery SAML template instance verification failed. TemplateId=$($verifiedServicePrincipal.applicationTemplateId)" }
        }

        $script:State.SamlApplicationObjectId = $verifiedApplication.id
        $script:State.SamlApplicationClientId = $verifiedApplication.appId
        $script:State.SamlServicePrincipalId = $verifiedServicePrincipal.id
        $script:State.SamlEntityId = "api://$($verifiedApplication.appId)"
        Save-State
        $evidencePath = Write-EvidenceJson -Name 'menu40-saml-template-instance-created' -Data ([ordered]@{
            LauncherVersion=$script:LauncherVersion; CapturedUtc=[DateTime]::UtcNow.ToString('o'); Outcome='Created'; TemplateId=$templateId;
            ReplacementPerformed=$replacementRequired; InstantiateResponse=$instantiateResult; Application=$verifiedApplication; ServicePrincipal=$verifiedServicePrincipal
        })
        $verifiedApplication | Select-Object id,appId,displayName | Format-List
        $verifiedServicePrincipal | Select-Object id,applicationTemplateId,preferredSingleSignOnMode | Format-List
        Write-Success "Non-gallery SAML template application and enterprise service principal are ready. Evidence: $evidencePath"
        Complete-Menu '40'
    }
    catch {
        $failurePath = Write-EvidenceJson -Name 'menu40-saml-template-instance-failure' -Data ([ordered]@{
            LauncherVersion=$script:LauncherVersion; CapturedUtc=[DateTime]::UtcNow.ToString('o'); Outcome='Failed'; FailedStage=$stage;
            ErrorType=$_.Exception.GetType().FullName; ErrorMessage=$_.Exception.Message; TemplateId=$templateId; ExpectedDisplayName=$displayName;
            OldApplication=$oldApplication; OldServicePrincipal=$oldServicePrincipal; InstantiateResponse=$instantiateResult
        })
        throw "$($_.Exception.Message) FailedStage=$stage; Evidence=$failurePath"
    }
}

function Invoke-Menu41 {
    Write-DemoHeader '41' 'Configure and verify the SAML Enterprise Application SSO mode and Basic SAML Configuration by atomic Microsoft Graph updates.' `
        -EntraPortal @(
            'Entra ID > Enterprise applications > <DNGRMS Demo SAML> > Single sign-on > SAML > Basic SAML Configuration',
            'After SUCCESS, use Ctrl+F5 if the portal still shows a cached OIDC-based sign-in blade'
        ) `
        -Expected @(
            'Atomic Service Principal update: preferredSingleSignOnMode=saml',
            'Application identifierUris contains the exact Entity ID',
            'Application web.redirectUris contains the exact ACS Reply URL',
            'Application web.homePageUrl contains the sign-on URL',
            'Each update is followed by Graph read-back before SUCCESS'
        )
    if (-not $script:State.SamlApplicationObjectId -or -not $script:State.SamlServicePrincipalId) { throw 'Run Menu 40 first.' }
    $null = Assert-GraphDelegatedPrerequisite -RequiredScopes @('Application.ReadWrite.All','AppRoleAssignment.ReadWrite.All','User.Read')
    $base = Get-WebAppBaseUrl
    $entityId = if ([string]::IsNullOrWhiteSpace([string]$script:State.SamlEntityId)) { "api://$($script:State.SamlApplicationClientId)" } else { [string]$script:State.SamlEntityId }
    $acsUrl = "$base/saml/acs"
    $signOnUrl = "$base/saml/login"
    $metadataUrl = "$base/saml/metadata"
    $applicationUri = "https://graph.microsoft.com/v1.0/applications/$($script:State.SamlApplicationObjectId)"
    $servicePrincipalUri = "https://graph.microsoft.com/v1.0/servicePrincipals/$($script:State.SamlServicePrincipalId)"
    $requiredSamlTemplateId = '8adf8e6e-67b2-4cf2-a259-e3dc5476c621'
    $templateContract = Invoke-GraphJson GET "$servicePrincipalUri`?`$select=id,applicationTemplateId,preferredSingleSignOnMode"
    if ([string]$templateContract.applicationTemplateId -ne $requiredSamlTemplateId) {
        throw "Run Menu 40 with v1.1.28 first. The current Service Principal is not the required non-gallery SAML template instance. ActualTemplateId=$($templateContract.applicationTemplateId)"
    }
    $stage = 'ReadBefore'
    $attempts = @()
    $applicationBefore = $null
    $servicePrincipalBefore = $null
    try {
        $applicationBefore = Invoke-GraphJson GET "$applicationUri`?`$select=id,appId,displayName,identifierUris,web"
        $servicePrincipalBefore = Invoke-GraphJson GET "$servicePrincipalUri`?`$select=id,appId,displayName,preferredSingleSignOnMode"

        $stage = 'PatchServicePrincipalMode'
        Invoke-GraphJson PATCH $servicePrincipalUri @{ preferredSingleSignOnMode='saml' } | Out-Null

        $stage = 'ReadBackServicePrincipalMode'
        $modeVerified = $false
        $servicePrincipalAfter = $null
        for ($attempt = 1; $attempt -le 6; $attempt++) {
            Start-Sleep -Seconds $(if ($attempt -eq 1) { 2 } else { 5 })
            $servicePrincipalAfter = Invoke-GraphJson GET "$servicePrincipalUri`?`$select=id,appId,displayName,preferredSingleSignOnMode"
            $modeVerified = ([string]$servicePrincipalAfter.preferredSingleSignOnMode -ceq 'saml')
            $attempts += [pscustomobject][ordered]@{ Stage='ServicePrincipalMode'; Attempt=$attempt; CapturedUtc=[DateTime]::UtcNow.ToString('o'); Actual=$servicePrincipalAfter.preferredSingleSignOnMode; Matched=$modeVerified }
            Write-Host "Service Principal read-back $attempt/6: ModeSaml=$modeVerified; Actual=$($servicePrincipalAfter.preferredSingleSignOnMode)"
            if ($modeVerified) { break }
        }
        if (-not $modeVerified) { throw "preferredSingleSignOnMode did not converge to saml. Actual=$($servicePrincipalAfter.preferredSingleSignOnMode)" }

        $stage = 'PatchApplicationSamlContract'
        $preservedRedirects = @($applicationBefore.web.redirectUris | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) -and [string]$_ -ne $acsUrl })
        $targetRedirects = @($preservedRedirects + $acsUrl | Select-Object -Unique)
        Invoke-GraphJson PATCH $applicationUri @{
            identifierUris=@($entityId)
            web=@{ redirectUris=$targetRedirects; homePageUrl=$signOnUrl }
        } | Out-Null

        $stage = 'ReadBackApplicationSamlContract'
        $applicationVerified = $false
        $applicationAfter = $null
        for ($attempt = 1; $attempt -le 6; $attempt++) {
            Start-Sleep -Seconds $(if ($attempt -eq 1) { 2 } else { 5 })
            $applicationAfter = Invoke-GraphJson GET "$applicationUri`?`$select=id,appId,displayName,identifierUris,web"
            $identifierMatched = (@($applicationAfter.identifierUris).Count -eq 1 -and [string](@($applicationAfter.identifierUris)[0]) -ceq $entityId)
            $acsMatched = (@($applicationAfter.web.redirectUris) -contains $acsUrl)
            $signOnMatched = ([string]$applicationAfter.web.homePageUrl -ceq $signOnUrl)
            $applicationVerified = ($identifierMatched -and $acsMatched -and $signOnMatched)
            $attempts += [pscustomobject][ordered]@{
                Stage='ApplicationSamlContract'; Attempt=$attempt; CapturedUtc=[DateTime]::UtcNow.ToString('o');
                IdentifierUris=@($applicationAfter.identifierUris); RedirectUris=@($applicationAfter.web.redirectUris); HomePageUrl=$applicationAfter.web.homePageUrl;
                IdentifierMatched=$identifierMatched; AcsMatched=$acsMatched; SignOnMatched=$signOnMatched; Matched=$applicationVerified
            }
            Write-Host "Application read-back $attempt/6: EntityId=$identifierMatched; ACS=$acsMatched; SignOn=$signOnMatched"
            if ($applicationVerified) { break }
        }
        if (-not $applicationVerified) { throw "Application SAML contract did not converge. IdentifierUris=$(@($applicationAfter.identifierUris) -join ','); RedirectUris=$(@($applicationAfter.web.redirectUris) -join ','); HomePageUrl=$($applicationAfter.web.homePageUrl)" }

        $stage = 'FinalVerification'
        $finalServicePrincipal = Invoke-GraphJson GET "$servicePrincipalUri`?`$select=id,appId,displayName,preferredSingleSignOnMode"
        $finalApplication = Invoke-GraphJson GET "$applicationUri`?`$select=id,appId,displayName,identifierUris,web"
        $finalModeMatched = ([string]$finalServicePrincipal.preferredSingleSignOnMode -ceq 'saml')
        $finalIdentifierMatched = (@($finalApplication.identifierUris).Count -eq 1 -and [string](@($finalApplication.identifierUris)[0]) -ceq $entityId)
        $finalAcsMatched = (@($finalApplication.web.redirectUris) -contains $acsUrl)
        $finalSignOnMatched = ([string]$finalApplication.web.homePageUrl -ceq $signOnUrl)
        if (-not ($finalModeMatched -and $finalIdentifierMatched -and $finalAcsMatched -and $finalSignOnMatched)) { throw 'Final SAML Graph contract verification failed.' }

        $evidence = [ordered]@{
            LauncherVersion=$script:LauncherVersion; CapturedUtc=[DateTime]::UtcNow.ToString('o'); Outcome='Success'; CompletedStage=$stage;
            ApplicationObjectId=$script:State.SamlApplicationObjectId; ServicePrincipalObjectId=$script:State.SamlServicePrincipalId; ApplicationClientId=$script:State.SamlApplicationClientId;
            ExpectedPreferredSingleSignOnMode='saml'; ExpectedEntityId=$entityId; ExpectedAcsUrl=$acsUrl; ExpectedSignOnUrl=$signOnUrl; SpMetadataUrl=$metadataUrl;
            ApplicationBefore=$applicationBefore; ServicePrincipalBefore=$servicePrincipalBefore; Attempts=$attempts;
            FinalApplication=$finalApplication; FinalServicePrincipal=$finalServicePrincipal;
            PortalPath='Entra ID > Enterprise applications > DNGRMS Demo SAML > Single sign-on > SAML > Basic SAML Configuration'
        }
        $evidencePath = Write-EvidenceJson -Name 'menu41-saml-enterprise-sso-atomic-readback' -Data $evidence
        $script:State.SamlEntityId = $entityId
        Save-State
        Write-Host "Preferred SSO mode      : $($finalServicePrincipal.preferredSingleSignOnMode)"
        Write-Host "Identifier (Entity ID) : $entityId"
        Write-Host "Reply URL (ACS)        : $acsUrl"
        Write-Host "Sign-on URL            : $signOnUrl"
        Write-Host "SP Metadata            : $metadataUrl"
        Write-Success "SAML Enterprise Application mode and Basic SAML Configuration were configured by atomic Graph updates and verified by read-back. Evidence: $evidencePath"
        Complete-Menu '41'
    }
    catch {
        $failureEvidence = [ordered]@{
            LauncherVersion=$script:LauncherVersion; CapturedUtc=[DateTime]::UtcNow.ToString('o'); Outcome='Failed'; FailedStage=$stage;
            ErrorType=$_.Exception.GetType().FullName; ErrorMessage=$_.Exception.Message;
            ApplicationObjectId=$script:State.SamlApplicationObjectId; ServicePrincipalObjectId=$script:State.SamlServicePrincipalId;
            ExpectedPreferredSingleSignOnMode='saml'; ExpectedEntityId=$entityId; ExpectedAcsUrl=$acsUrl; ExpectedSignOnUrl=$signOnUrl;
            ApplicationBefore=$applicationBefore; ServicePrincipalBefore=$servicePrincipalBefore; Attempts=$attempts
        }
        $failurePath = Write-EvidenceJson -Name 'menu41-saml-enterprise-sso-failure' -Data $failureEvidence
        throw "$($_.Exception.Message) FailedStage=$stage; Evidence=$failurePath"
    }
}

function Invoke-Menu42 {
    Write-DemoHeader '42' 'Create or reuse a SAML token-signing certificate, select it as preferred, and configure verified Entra federation metadata in DNGRMS.' `
        -EntraPortal @(
            'Entra ID > Enterprise applications > <DNGRMS Demo SAML> > Single sign-on > SAML > SAML Certificates',
            'Entra ID > Enterprise applications > <DNGRMS Demo SAML> > Single sign-on > SAML > Set up <application>'
        ) `
        -Expected @(
            'Service Principal SSO mode is saml',
            'An active token-signing certificate exists and is selected as the preferred signing key',
            'Certificate private material and password are never written to launcher state or evidence',
            'Tenant/application federation metadata is reachable and contains X509Certificate',
            'App Service SAML settings are applied only after certificate and metadata verification'
        )
    if (-not $script:State.SamlServicePrincipalId) { throw 'Run Menu 40 first.' }
    $null = Assert-GraphDelegatedPrerequisite -RequiredScopes @('Application.ReadWrite.All','User.Read')
    $servicePrincipalUri = "https://graph.microsoft.com/v1.0/servicePrincipals/$($script:State.SamlServicePrincipalId)"
    $stage = 'ReadServicePrincipal'
    $created = $false
    $certificateResponse = $null
    try {
        $samlSp = Invoke-GraphJson GET "$servicePrincipalUri`?`$select=id,appId,displayName,preferredSingleSignOnMode,keyCredentials,preferredTokenSigningKeyThumbprint"
        if ([string]$samlSp.preferredSingleSignOnMode -ne 'saml') { throw "Run Menu 41 with v1.1.35 first. Current preferredSingleSignOnMode=$($samlSp.preferredSingleSignOnMode)" }
        $now = [DateTime]::UtcNow
        $activeVerifyKeys = @($samlSp.keyCredentials | Where-Object {
            [string]$_.type -eq 'AsymmetricX509Cert' -and [string]$_.usage -eq 'Verify' -and
            [DateTime]$_.startDateTime -le $now.AddMinutes(5) -and [DateTime]$_.endDateTime -gt $now.AddDays(1)
        } | Sort-Object { [DateTime]$_.endDateTime } -Descending)
        $selectedVerifyKey = $activeVerifyKeys | Select-Object -First 1
        if (-not $selectedVerifyKey) {
            $stage = 'CreateTokenSigningCertificate'
            $lifetimeInput = Read-Choice 'SAML token-signing certificate lifetime in days (30-1095)' '365'
            $lifetimeDays = 0
            if (-not [int]::TryParse([string]$lifetimeInput,[ref]$lifetimeDays) -or $lifetimeDays -lt 30 -or $lifetimeDays -gt 1095) {
                throw "Certificate lifetime must be an integer from 30 through 1095 days. Actual='$lifetimeInput'. No certificate was created."
            }
            $displayName = "CN=DNGRMS Demo SAML Signing v$($script:LauncherVersion)"
            $endDateTime = $now.AddDays($lifetimeDays).ToString('o')
            $certificateResponse = Invoke-GraphJson POST "$servicePrincipalUri/addTokenSigningCertificate" @{
                displayName=$displayName; endDateTime=$endDateTime
            }
            $created = $true
            Start-Sleep -Seconds 3
            $samlSp = Invoke-GraphJson GET "$servicePrincipalUri`?`$select=id,appId,displayName,preferredSingleSignOnMode,keyCredentials,preferredTokenSigningKeyThumbprint"
            $activeVerifyKeys = @($samlSp.keyCredentials | Where-Object {
                [string]$_.type -eq 'AsymmetricX509Cert' -and [string]$_.usage -eq 'Verify' -and
                [string]$_.displayName -eq $displayName -and [DateTime]$_.endDateTime -gt $now.AddDays(1)
            } | Sort-Object { [DateTime]$_.endDateTime } -Descending)
            $selectedVerifyKey = $activeVerifyKeys | Select-Object -First 1
            if (-not $selectedVerifyKey) { throw 'The new token-signing certificate was not visible in Service Principal keyCredentials after creation.' }
        }
        $thumbprintHex = ''
        if (-not [string]::IsNullOrWhiteSpace([string]$selectedVerifyKey.customKeyIdentifier)) {
            $thumbprintHex = ([BitConverter]::ToString([Convert]::FromBase64String([string]$selectedVerifyKey.customKeyIdentifier))).Replace('-','')
        }
        if ([string]::IsNullOrWhiteSpace($thumbprintHex)) { throw 'The selected token-signing certificate does not expose a valid customKeyIdentifier thumbprint.' }
        $stage = 'SelectPreferredTokenSigningCertificate'
        Invoke-GraphJson PATCH $servicePrincipalUri @{ preferredTokenSigningKeyThumbprint=$thumbprintHex } | Out-Null

        $stage = 'VerifyPreferredTokenSigningCertificate'
        $verifiedSp = $null
        $preferredMatched = $false
        for ($attempt = 1; $attempt -le 6; $attempt++) {
            Start-Sleep -Seconds $(if ($attempt -eq 1) { 2 } else { 5 })
            $verifiedSp = Invoke-GraphJson GET "$servicePrincipalUri`?`$select=id,appId,displayName,preferredSingleSignOnMode,keyCredentials,preferredTokenSigningKeyThumbprint"
            $preferredMatched = ([string]$verifiedSp.preferredTokenSigningKeyThumbprint -ieq $thumbprintHex)
            $verifyKeyMatched = @($verifiedSp.keyCredentials | Where-Object { [string]$_.keyId -eq [string]$selectedVerifyKey.keyId -and [string]$_.usage -eq 'Verify' }).Count -ge 1
            Write-Host "Certificate read-back $attempt/6: PreferredMatched=$preferredMatched; VerifyKeyMatched=$verifyKeyMatched"
            if ($preferredMatched -and $verifyKeyMatched) { break }
        }
        if (-not $preferredMatched) { throw "preferredTokenSigningKeyThumbprint did not converge. Expected=$thumbprintHex; Actual=$($verifiedSp.preferredTokenSigningKeyThumbprint)" }

        $stage = 'ValidateFederationMetadata'
        $metadataUrl = "https://login.microsoftonline.com/$($script:State.TenantId)/federationmetadata/2007-06/federationmetadata.xml?appid=$($script:State.SamlApplicationClientId)"
        $metadataResponse = Invoke-WebRequest -Uri $metadataUrl -Method Get -UseBasicParsing
        $certificateCount = ([regex]::Matches($metadataResponse.Content, '<[^>]*X509Certificate[^>]*>')).Count
        if ($metadataResponse.StatusCode -ne 200 -or $certificateCount -lt 1) { throw "Federation metadata did not contain a signing certificate. HTTP=$($metadataResponse.StatusCode); X509CertificateElements=$certificateCount" }

        $stage = 'ApplyAppServiceSamlTrust'
        Set-AzWebAppSettingsSafe @{
            'Saml2__Enabled'='true'; 'Saml2__Issuer'=$script:State.SamlEntityId; 'Saml2__IdPMetadata'=$metadataUrl
        }
        $script:State.SamlMetadataUrl = $metadataUrl
        Save-State
        Restart-AzWebApp -ResourceGroupName $script:State.ResourceGroupName -Name $script:State.WebAppName | Out-Null
        $health = Wait-HealthContract -TimeoutSeconds 600

        $evidence = [ordered]@{
            LauncherVersion=$script:LauncherVersion; CapturedUtc=[DateTime]::UtcNow.ToString('o'); Outcome='Success'; CreatedNewCertificate=$created;
            ServicePrincipalId=$script:State.SamlServicePrincipalId; ApplicationClientId=$script:State.SamlApplicationClientId;
            Certificate=[ordered]@{
                DisplayName=$selectedVerifyKey.displayName; KeyId=$selectedVerifyKey.keyId; Thumbprint=$thumbprintHex;
                StartDateTime=$selectedVerifyKey.startDateTime; EndDateTime=$selectedVerifyKey.endDateTime; Type=$selectedVerifyKey.type; Usage=$selectedVerifyKey.usage
            };
            PreferredTokenSigningKeyThumbprint=$verifiedSp.preferredTokenSigningKeyThumbprint;
            FederationMetadataUrl=$metadataUrl; MetadataHttpStatus=$metadataResponse.StatusCode; X509CertificateElements=$certificateCount;
            AppServiceHealth=$health;
            SecretHandling='PFX private key and password credential were not persisted in launcher state or evidence.'
        }
        $evidencePath = Write-EvidenceJson -Name 'menu42-saml-signing-certificate-and-metadata' -Data $evidence
        Write-Host "Certificate display name : $($selectedVerifyKey.displayName)"
        Write-Host "Certificate key ID       : $($selectedVerifyKey.keyId)"
        Write-Host "Certificate thumbprint   : $thumbprintHex"
        Write-Host "Certificate valid from   : $($selectedVerifyKey.startDateTime)"
        Write-Host "Certificate valid until  : $($selectedVerifyKey.endDateTime)"
        Write-Host "Metadata X509 elements   : $certificateCount"
        Write-Success "SAML token-signing certificate, preferred signing key, federation metadata, and App Service trust configuration were verified. Evidence: $evidencePath"
        Complete-Menu '42'
    }
    catch {
        $failurePath = Write-EvidenceJson -Name 'menu42-saml-signing-certificate-failure' -Data ([ordered]@{
            LauncherVersion=$script:LauncherVersion; CapturedUtc=[DateTime]::UtcNow.ToString('o'); Outcome='Failed'; FailedStage=$stage;
            ErrorType=$_.Exception.GetType().FullName; ErrorMessage=$_.Exception.Message; ServicePrincipalId=$script:State.SamlServicePrincipalId;
            ApplicationClientId=$script:State.SamlApplicationClientId; CreatedNewCertificate=$created
        })
        throw "$($_.Exception.Message) FailedStage=$stage; Evidence=$failurePath"
    }
}

function Invoke-Menu43 {
    Write-DemoHeader '43' 'Create and assign a basic SAML claims mapping policy for UPN, email, and immutable object ID.' `
        -EntraPortal @('Entra ID > Enterprise applications > <DNGRMS Demo SAML> > Single sign-on > Attributes & Claims') `
        -Expected @('Basic claims retained', 'Object ID and UPN available for identity linking')
    if (-not $script:State.SamlServicePrincipalId) { throw 'Run menu 40 first.' }
    $definitionObject = @{
        ClaimsMappingPolicy=@{
            Version=1; IncludeBasicClaimSet='true'; ClaimsSchema=@(
                @{ Source='user'; ID='userprincipalname'; SamlClaimType='http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name' },
                @{ Source='user'; ID='mail'; SamlClaimType='http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress' },
                @{ Source='user'; ID='objectid'; SamlClaimType='http://schemas.microsoft.com/identity/claims/objectidentifier' }
            )
        }
    }
    try {
        $policy = Invoke-GraphJson POST 'https://graph.microsoft.com/v1.0/policies/claimsMappingPolicies' @{
            displayName="DNGRMS Demo SAML Claims - $($script:State.WebAppName)"
            definition=@(($definitionObject | ConvertTo-Json -Depth 10 -Compress))
            isOrganizationDefault=$false
        }
        Invoke-GraphJson POST "https://graph.microsoft.com/v1.0/servicePrincipals/$($script:State.SamlServicePrincipalId)/claimsMappingPolicies/`$ref" @{
            '@odata.id'="https://graph.microsoft.com/v1.0/policies/claimsMappingPolicies/$($policy.id)"
        } | Out-Null
        $script:State.SamlClaimsMappingPolicyId = $policy.id
        Save-State
        Write-Success 'Claims mapping policy created and assigned.'
    }
    catch {
        $claimsAutomationError = [string]$_.Exception.Message
        Write-WarningMessage "Claims policy automation was blocked or unsupported: $claimsAutomationError"
        Write-Host 'The default Entra SAML claims remain usable. Verify Attributes & Claims in the Entra portal before testing.'
        Add-StateNote "Menu 43 claims policy automation required portal verification. Detail=$claimsAutomationError"
        $fallbackEvidence = [ordered]@{
            LauncherVersion=$script:LauncherVersion
            CapturedUtc=[DateTime]::UtcNow.ToString('o')
            ClaimsMappingPolicyAutomation='FallbackToDefaultEntraClaims'
            PortalVerificationRequired=$true
            Error=$claimsAutomationError
            SamlServicePrincipalId=$script:State.SamlServicePrincipalId
        }
        $fallbackPath = Write-EvidenceJson -Name 'menu43-claims-policy-fallback' -Data $fallbackEvidence
        Write-Host "Evidence: $fallbackPath"
    }
    Complete-Menu '43'
}

function Invoke-Menu44 {
    Write-DemoHeader '44' 'Download and inspect Entra federation metadata, including signing certificate presence.' `
        -Expected @('EntityDescriptor is returned.', 'At least one X509Certificate element is present.')
    if (-not $script:State.SamlMetadataUrl) { throw 'Run Menu 42 with v1.1.35 first.' }
    $response = Invoke-WebRequest -Uri $script:State.SamlMetadataUrl -Method Get -UseBasicParsing
    $certificateCount = ([regex]::Matches($response.Content, '<[^>]*X509Certificate[^>]*>')).Count
    [pscustomobject]@{ StatusCode=$response.StatusCode; ContentLength=$response.Content.Length; SigningCertificateElements=$certificateCount; MetadataUrl=$script:State.SamlMetadataUrl } | Format-List
    if ($certificateCount -lt 1) { throw 'No signing certificate was found in federation metadata.' }
    Write-Success 'SAML metadata and signing certificate evidence validated.'
    Complete-Menu '44'
}

function Invoke-Menu45 {
    Write-DemoHeader '45' 'Require assignment and assign the currently signed-in Entra user as the SAML pilot user.' `
        -EntraPortal @('Entra ID > Enterprise applications > <DNGRMS Demo SAML> > Users and groups')
    if (-not $script:State.SamlServicePrincipalId) { throw 'Run menu 40 first.' }
    $result = Add-CurrentGraphUserAssignment $script:State.SamlServicePrincipalId
    $result.User | Select-Object displayName,userPrincipalName,id | Format-List
    Write-Host "Assignment role : $($result.SelectedRoleDisplayName)"
    Write-Host "App role ID     : $($result.SelectedAppRoleId)"
    $evidencePath = Write-EvidenceJson -Name 'menu45-saml-pilot-user-assignment' -Data ([ordered]@{
        LauncherVersion=$script:LauncherVersion; CapturedUtc=[DateTime]::UtcNow.ToString('o');
        ServicePrincipalId=$script:State.SamlServicePrincipalId; ServicePrincipalDisplayName=$result.Resource.displayName;
        User=[ordered]@{ Id=$result.User.id; DisplayName=$result.User.displayName; UserPrincipalName=$result.User.userPrincipalName };
        SelectedAppRoleId=$result.SelectedAppRoleId; SelectedRoleDisplayName=$result.SelectedRoleDisplayName;
        AssignmentId=$result.Assignment.id; Verified=$true
    })
    Write-Success "Current user is assigned to the SAML enterprise application and verified by Graph read-back. Evidence: $evidencePath"
    Complete-Menu '45'
}

function Invoke-Menu46 {
    Write-DemoHeader '46' 'Switch the application to SAML mode after preserving the same business application and database.'
    Set-AuthenticationMode Saml
    Wait-WebEndpoint -Uri "$(Get-WebAppBaseUrl)/health" -TimeoutSeconds 300 | Out-Null
    Complete-Menu '46'
}

function Invoke-Menu47 {
    Write-DemoHeader '47' 'Open the SP-initiated SAML flow from DNGRMS to Microsoft Entra ID.' `
        -Expected @('AuthnRequest redirects to Entra.', 'SAML Response posts to /saml/acs.', 'Signature, issuer, audience, and time are validated.')
    $url = "$(Get-WebAppBaseUrl)/saml/login?returnUrl=%2Fhome%2Fauthdebug"
    Start-Process $url
    Write-Host "Opened: $url"
    Complete-Menu '47'
}

function Invoke-Menu48 {
    Write-DemoHeader '48' 'Display safe SAML claim evidence after assertion validation.' `
        -Expected @('auth_method=SAML', 'NameID/object identifier claims', 'No raw SAML assertion displayed')
    $url = "$(Get-WebAppBaseUrl)/home/authdebug"
    Start-Process $url
    Write-Host "Evidence URL: $url"
    Complete-Menu '48'
}

function Invoke-Menu49 {
    Write-DemoHeader '49' 'Verify the SAML NameID/object identity link to the existing DNGRMS user profile.'
    $users = Invoke-DemoAdminApi GET '/api/demo/users'
    $users | Format-Table id,userName,role,localLoginAllowed,entraObjectId,samlNameId -AutoSize
    Write-EvidenceJson -Name 'saml-identity-linking' -Data $users | ForEach-Object { Write-Host "Evidence: $_" }
    Complete-Menu '49'
}

function Invoke-Menu50 {
    Write-DemoHeader '50' 'Return to Dual mode for controlled pilot coexistence and migration testing.'
    Set-AuthenticationMode Dual
    Complete-Menu '50'
}

function Invoke-Menu51 {
    Write-DemoHeader '51' 'Validate that one application exposes Local, OIDC, and SAML initiation paths during pilot coexistence.' `
        -Expected @('Health endpoint returns 200', 'Local sign-in page is reachable', 'OIDC initiation returns or redirects without following Entra', 'SAML metadata is reachable', 'Each endpoint is probed independently with warm-up and bounded retries')
    $base = Get-WebAppBaseUrl
    Write-Host 'Warming up the App Service health endpoint before coexistence probes...'
    try { Wait-WebEndpoint -Uri "$base/health" -TimeoutSeconds 90 | Out-Null }
    catch { Write-Warning "Initial health warm-up did not complete successfully. Endpoint-level retries will continue. Detail: $($_.Exception.Message)" }
    $targets = @(
        [pscustomobject]@{Path='/health'; RequiredStatus=@(200); Label='Health'},
        [pscustomobject]@{Path='/account/login'; RequiredStatus=@(200); Label='Local login'},
        [pscustomobject]@{Path='/account/oidc'; RequiredStatus=@(200,301,302,303,307,308); Label='OIDC initiation'},
        [pscustomobject]@{Path='/saml/metadata'; RequiredStatus=@(200); Label='SAML metadata'}
    )
    $results = @()
    foreach ($target in $targets) {
        $uri = "$base$($target.Path)"
        $final = $null
        for ($attempt = 1; $attempt -le 3; $attempt++) {
            $statusCode = 0
            $location = ''
            $category = 'Unknown'
            $detail = ''
            $handler = $null
            $client = $null
            $request = $null
            $response = $null
            try {
                $handler = [System.Net.Http.HttpClientHandler]::new()
                $handler.AllowAutoRedirect = $false
                $client = [System.Net.Http.HttpClient]::new($handler)
                $client.Timeout = [TimeSpan]::FromSeconds(20)
                $request = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Get,$uri)
                $response = $client.SendAsync($request).GetAwaiter().GetResult()
                $statusCode = [int]$response.StatusCode
                if ($null -ne $response.Headers.Location) { $location = [string]$response.Headers.Location.OriginalString }
                $category = 'HttpResponse'
            }
            catch {
                $detail = $_.Exception.Message
                $root = $_.Exception
                while ($null -ne $root.InnerException) { $root = $root.InnerException }
                $rootDetail = [string]$root.Message
                if ($rootDetail) { $detail = $detail + ' | Root=' + $rootDetail }
                if ($detail -match '(?i)timed out|timeout|canceled|cancelled|시간이 초과') { $category = 'Timeout' }
                else { $category = 'TransportFailure' }
            }
            finally {
                if ($null -ne $response) { $response.Dispose() }
                if ($null -ne $request) { $request.Dispose() }
                if ($null -ne $client) { $client.Dispose() }
                if ($null -ne $handler) { $handler.Dispose() }
            }
            $matched = ($target.RequiredStatus -contains $statusCode)
            $final = [pscustomobject][ordered]@{
                Label=$target.Label; Path=$target.Path; Attempt=$attempt; StatusCode=$statusCode; Location=$location; Category=$category; Expected=($target.RequiredStatus -join ','); Matched=$matched; Detail=$detail
            }
            Write-Host ("Endpoint probe: {0,-16} Attempt={1}/3 Path={2,-18} HTTP={3}; Category={4}; Matched={5}" -f $target.Label,$attempt,$target.Path,$statusCode,$category,$matched)
            if ($matched) { break }
            if ($detail) { Write-Warning ("Probe detail: {0}" -f $detail) }
            if ($attempt -lt 3) { Start-Sleep -Seconds (2 + $attempt) }
        }
        $results += $final
    }
    $evidencePath = Write-EvidenceJson -Name 'dual-mode-endpoints' -Data $results
    $results | Select-Object Label,Path,Attempt,StatusCode,Category,Matched,Location,Detail | Format-Table -AutoSize
    $failed = @($results | Where-Object { -not $_.Matched })
    if ($failed.Count -gt 0) {
        throw "Dual coexistence endpoint validation failed after retries for: $(@($failed | ForEach-Object { $_.Label + ':' + $_.Category + '/HTTP' + $_.StatusCode }) -join ', '). Evidence=$evidencePath"
    }
    Write-Success "Local, OIDC, and SAML coexistence endpoints were validated after warm-up with bounded retries. Evidence: $evidencePath"
    Complete-Menu '51'
}

function Invoke-Menu52 {
    Write-DemoHeader '52' 'Stop creating or resetting local passwords while existing pilot accounts remain intact.' `
        -Expected @('DNGRMS_STOP_LOCAL_PASSWORD_CREATION=true', 'Existing password hashes are not deleted yet')
    Set-AzWebAppSettingsSafe @{ 'DNGRMS_STOP_LOCAL_PASSWORD_CREATION'='true' }
    Restart-AzWebApp -ResourceGroupName $script:State.ResourceGroupName -Name $script:State.WebAppName | Out-Null
    Write-Success 'New local password seeding/creation is stopped.'
    Complete-Menu '52'
}

function Invoke-Menu53 {
    Write-DemoHeader '53' 'Disable local password login for a selected DNGRMS user without deleting profile, role, or mapping.'
    $userName = Read-Choice 'DNGRMS user name' $script:State.DemoStandardUserName
    $result = Invoke-DemoAdminApi POST "/api/demo/users/$([Uri]::EscapeDataString($userName))/local-login?enabled=false"
    $result | Format-List
    Write-Success "Local login disabled for $userName."
    Complete-Menu '53'
}

function Invoke-Menu54 {
    Write-DemoHeader '54' 'Make OIDC the default migration target while preserving the rollback path.'
    Set-AuthenticationMode Oidc
    Complete-Menu '54'
}

function Invoke-Menu55 {
    Write-DemoHeader '55' 'Validate that the restricted break-glass local administrator remains available during migration.' `
        -Expected @('Admin local login flag remains true.', 'Dual mode is required to expose local sign-in during emergency access.')
    $result = Invoke-DemoAdminApi POST "/api/demo/users/$([Uri]::EscapeDataString($script:State.DemoAdminUserName))/local-login?enabled=true"
    $result | Format-List
    Write-WarningMessage 'A production break-glass account requires separate monitoring, vaulting, rotation, and emergency-use controls.'
    Complete-Menu '55'
}

function Invoke-Menu56 {
    Write-DemoHeader '56' 'Verify that the ordinary demo user is blocked from local password login after cutover.'
    $users = Invoke-DemoAdminApi GET '/api/demo/users'
    $user = @($users | Where-Object userName -eq $script:State.DemoStandardUserName) | Select-Object -First 1
    $user | Format-List
    if (-not $user -or $user.localLoginAllowed) { throw 'Ordinary user local login is still enabled. Run menu 53.' }
    Start-Process "$(Get-WebAppBaseUrl)/account/login"
    Write-Success 'The data flag proves the user is blocked; use the sign-in page to demonstrate rejection.'
    Complete-Menu '56'
}

function Invoke-Menu57 {
    Write-DemoHeader '57' 'Compare the evidence and trust artifacts used by Local, OIDC, and SAML authentication.'
    @'
METHOD | PRIMARY ARTIFACT                 | CALLBACK / VALIDATION                 | APP MAPPING KEY
-------|----------------------------------|---------------------------------------|---------------------------
Local  | Password hash in SQLite          | PasswordHasher verification           | Internal DemoUser.Id
OIDC   | Authorization code + ID token    | /signin-oidc; issuer/audience/signature| oid + tid; fallback sub
SAML   | Signed XML SAML assertion        | /saml/acs; issuer/audience/time/signature| objectidentifier / NameID

All three methods create the same DNGRMS application session cookie and use the same business Role/Profile table.
Raw password, ID token, access token, refresh token, and SAML assertion are intentionally excluded from evidence output.
'@ | Write-Host
    Complete-Menu '57'
}

function Invoke-Menu58 {
    Write-DemoHeader '58' 'Roll back to a selected authentication mode without deleting application data.'
    $mode = Read-Choice 'Rollback mode (Local, Dual, Oidc, Saml)' 'Dual'
    $normalized = switch -Regex ($mode) { '^local$' {'Local'} '^dual$' {'Dual'} '^oidc$' {'Oidc'} '^saml$' {'Saml'} default { throw 'Invalid mode.' } }
    Set-AuthenticationMode $normalized
    Complete-Menu '58'
}

function Invoke-Menu59 {
    Write-DemoHeader '59' 'Generate the final secret-free evidence summary for the customer demonstration.'
    Assert-AzureContext | Out-Null
    $resources = Get-AzResource -ResourceGroupName $script:State.ResourceGroupName -ErrorAction SilentlyContinue | Select-Object Name,ResourceType,Location,ResourceId
    $status = Invoke-RestMethod -Uri "$(Get-WebAppBaseUrl)/api/demo/status"
    $users = Invoke-DemoAdminApi GET '/api/demo/users'
    $audit = Invoke-DemoAdminApi GET '/api/demo/audit?take=100'
    $summary = [ordered]@{
        LauncherVersion=$script:LauncherVersion; CapturedUtc=[DateTime]::UtcNow; State=$script:State;
        AzureResources=$resources; ApplicationStatus=$status; Users=$users; AuthenticationAudit=$audit;
        SecurityNote='Passwords, password hashes, client secrets, tokens, private keys, and raw SAML assertions are excluded.'
    }
    $path = Write-EvidenceJson -Name 'final-demo-evidence' -Data $summary
    Write-Success "Final evidence written: $path"
    Complete-Menu '59'
}

function Invoke-Menu90 {
    Write-DemoHeader '90' 'Compare application-integrated OIDC/SAML with Azure App Service built-in authentication (Easy Auth).' `
        -AzurePortal @('App Services > <demo app> > Settings > Authentication')
    @'
- Easy Auth can front the application with Microsoft Entra or generic OIDC and inject identity headers.
- It is excellent when little/no application authentication code is desired.
- App Service built-in providers do not provide a native SAML provider entry.
- This launcher keeps OIDC and SAML inside one app so protocol migration, callback handling,
  claim mapping, and the preserved business-user database can be demonstrated consistently.
- Do not enable Easy Auth on this Web App during the main demo; it would intercept requests
  before the application-level Local/OIDC/SAML comparison.
'@ | Write-Host
    Complete-Menu '90'
}

function Set-DemoPlanSku {
    param([Parameter(Mandatory)][ValidateSet('F1','B1')][string]$Sku)
    Assert-Module 'Az.Websites'
    $tier = if ($Sku -eq 'F1') { 'Free' } else { 'Basic' }
    Set-AzAppServicePlan -ResourceGroupName $script:State.ResourceGroupName -Name $script:State.AppServicePlanName -Tier $tier -WorkerSize Small | Out-Null
    $script:State.AppServiceSku = $Sku
    Save-State
    Write-Success "App Service plan changed to $Sku. Confirm region-specific charges in Cost Management."
}

function Invoke-Menu91 {
    Write-DemoHeader '91' 'Scale the App Service plan to B1 for dedicated compute before a customer presentation.'
    if (Read-YesNo 'B1 creates billable dedicated compute. Continue?') { Set-DemoPlanSku B1; Complete-Menu '91' }
}

function Invoke-Menu92 {
    Write-DemoHeader '92' 'Scale the App Service plan back to F1 to minimize lab cost.'
    Set-DemoPlanSku F1
    Complete-Menu '92'
}

function Invoke-Menu93 {
    Write-DemoHeader '93' 'Inventory Azure resources and Entra application object identifiers.'
    $resources = Get-AzResource -ResourceGroupName $script:State.ResourceGroupName -ErrorAction SilentlyContinue
    $resources | Select-Object Name,ResourceType,Location,ResourceId | Format-Table -AutoSize
    [pscustomobject]@{
        OidcApplicationClientId=$script:State.OidcApplicationClientId; OidcServicePrincipalId=$script:State.OidcServicePrincipalId;
        SamlApplicationClientId=$script:State.SamlApplicationClientId; SamlServicePrincipalId=$script:State.SamlServicePrincipalId
    } | Format-List
    Complete-Menu '93'
}

function Invoke-Menu94 {
    Write-DemoHeader '94' 'Remove the OIDC application password credential without deleting the application.'
    if (-not $script:State.OidcApplicationObjectId -or -not $script:State.OidcPasswordKeyId) { throw 'No tracked OIDC credential key ID exists.' }
    Invoke-GraphJson POST "https://graph.microsoft.com/v1.0/applications/$($script:State.OidcApplicationObjectId)/removePassword" @{
        keyId=$script:State.OidcPasswordKeyId
    } | Out-Null
    Remove-AzWebAppSettingSafe @('Oidc__ClientSecret')
    $script:State.OidcPasswordKeyId = ''
    $script:State.OidcPasswordEndDateTime = ''
    Save-State
    Write-Success 'OIDC application credential and Web App secret setting removed.'
    Complete-Menu '94'
}

function Invoke-Menu95 {
    Write-DemoHeader '95' 'Delete the Entra OIDC and SAML enterprise applications and app registrations.'
    if (-not (Read-YesNo 'Delete both Entra demo applications?')) { return }
    foreach ($spId in @($script:State.OidcServicePrincipalId,$script:State.SamlServicePrincipalId)) {
        if ($spId) { try { Invoke-GraphJson DELETE "https://graph.microsoft.com/v1.0/servicePrincipals/$spId" | Out-Null } catch { Write-WarningMessage $_.Exception.Message } }
    }
    foreach ($appId in @($script:State.OidcApplicationObjectId,$script:State.SamlApplicationObjectId)) {
        if ($appId) { try { Invoke-GraphJson DELETE "https://graph.microsoft.com/v1.0/applications/$appId" | Out-Null } catch { Write-WarningMessage $_.Exception.Message } }
    }
    foreach ($name in @('OidcApplicationObjectId','OidcApplicationClientId','OidcServicePrincipalId','SamlApplicationObjectId','SamlApplicationClientId','SamlServicePrincipalId','SamlEntityId','SamlMetadataUrl','OidcPasswordKeyId')) { $script:State[$name]='' }
    Save-State
    Write-Success 'Tracked Entra demo applications were deleted or deletion was attempted and reported.'
    Complete-Menu '95'
}

function Invoke-Menu96 {
    Write-DemoHeader '96' 'Delete the entire Azure demo resource group.'
    if (-not (Read-YesNo "Delete resource group '$($script:State.ResourceGroupName)' and all contained resources?")) { return }
    Remove-AzResourceGroup -Name $script:State.ResourceGroupName -Force
    Write-Success 'Resource group deletion request completed.'
    Complete-Menu '96'
}

function Invoke-Menu97 {
    Write-DemoHeader '97' 'Remove selected local generated source, database, publish, package, and log artifacts.'
    if ($script:State.LocalProcessId) {
        $process = Get-Process -Id ([int]$script:State.LocalProcessId) -ErrorAction SilentlyContinue
        if ($process) { Stop-Process -Id $process.Id -Force }
        $script:State.LocalProcessId = 0
    }
    foreach ($entry in @(
        @{Label='generated source';Path=$script:SourceRoot},
        @{Label='local SQLite data';Path=(Split-Path -Parent $script:State.LocalDatabasePath)},
        @{Label='publish output';Path=(Join-Path $script:Root 'publish')},
        @{Label='deployment packages';Path=$script:PackageRoot},
        @{Label='logs';Path=$script:LogRoot}
    )) {
        if ((Test-Path $entry.Path) -and (Read-YesNo "Delete $($entry.Label): $($entry.Path)?")) { Remove-Item $entry.Path -Recurse -Force }
    }
    Save-State
    Write-Success 'Selected local artifacts removed.'
    Complete-Menu '97'
}

function Invoke-Menu98 {
    Write-DemoHeader '98' 'Archive the secret-free state and evidence directory.'
    $archive = Join-Path $script:Root "DNGRMS-Demo-Evidence-v${script:LauncherVersion}-$(Get-Date -Format yyyyMMdd-HHmmss).zip"
    $items = @($script:StatePath)
    if (Test-Path $script:EvidenceRoot) { $items += $script:EvidenceRoot }
    Compress-Archive -Path $items -DestinationPath $archive -CompressionLevel Optimal
    Write-Success "Archive created: $archive"
    Complete-Menu '98'
}

function Invoke-Menu99 {
    Write-DemoHeader '99' 'Verify whether Azure and Entra demo resources still exist after cleanup.'
    $report = [ordered]@{}
    try { $report.AzureResourceGroupExists = $null -ne (Get-AzResourceGroup -Name $script:State.ResourceGroupName -ErrorAction SilentlyContinue) } catch { $report.AzureResourceGroupExists='Unknown' }
    foreach ($pair in @(
        @{Name='OidcApplicationExists';Id=$script:State.OidcApplicationObjectId;Type='applications'},
        @{Name='SamlApplicationExists';Id=$script:State.SamlApplicationObjectId;Type='applications'}
    )) {
        if (-not $pair.Id) { $report[$pair.Name]=$false; continue }
        try { Invoke-GraphJson GET "https://graph.microsoft.com/v1.0/$($pair.Type)/$($pair.Id)" | Out-Null; $report[$pair.Name]=$true }
        catch { $report[$pair.Name]=$false }
    }
    $report.LocalSourceExists = Test-Path $script:SourceRoot
    $report.LocalDatabaseExists = Test-Path $script:State.LocalDatabasePath
    [pscustomobject]$report | Format-List
    Write-EvidenceJson -Name 'cleanup-verification' -Data $report | ForEach-Object { Write-Host "Evidence: $_" }
    Complete-Menu '99'
}

$dispatch = @{
    '0'=${function:Invoke-Menu0}; '1'=${function:Invoke-Menu1}; '2'=${function:Invoke-Menu2}; '3'=${function:Invoke-Menu3};
    '4'=${function:Invoke-Menu4}; '5'=${function:Invoke-Menu5}; '6'=${function:Invoke-Menu6}; '7'=${function:Invoke-Menu7};
    '8'=${function:Invoke-Menu8}; '9'=${function:Invoke-Menu9}; '10'=${function:Invoke-Menu10}; '11'=${function:Invoke-Menu11};
    '12'=${function:Invoke-Menu12}; '13'=${function:Invoke-Menu13}; '14'=${function:Invoke-Menu14}; '15'=${function:Invoke-Menu15};
    '16'=${function:Invoke-Menu16}; '17'=${function:Invoke-Menu17}; '18'=${function:Invoke-Menu18}; '19'=${function:Invoke-Menu19};
    '20'=${function:Invoke-Menu20}; '21'=${function:Invoke-Menu21}; '22'=${function:Invoke-Menu22}; '23'=${function:Invoke-Menu23};
    '24'=${function:Invoke-Menu24}; '25'=${function:Invoke-Menu25}; '26'=${function:Invoke-Menu26}; '27'=${function:Invoke-Menu27};
    '28'=${function:Invoke-Menu28}; '29'=${function:Invoke-Menu29}; '30'=${function:Invoke-Menu30}; '31'=${function:Invoke-Menu31};
    '32'=${function:Invoke-Menu32}; '33'=${function:Invoke-Menu33}; '34'=${function:Invoke-Menu34}; '35'=${function:Invoke-Menu35};
    '36'=${function:Invoke-Menu36}; '37'=${function:Invoke-Menu37}; '38'=${function:Invoke-Menu38}; '39'=${function:Invoke-Menu39};
    '40'=${function:Invoke-Menu40}; '41'=${function:Invoke-Menu41}; '42'=${function:Invoke-Menu42}; '43'=${function:Invoke-Menu43};
    '44'=${function:Invoke-Menu44}; '45'=${function:Invoke-Menu45}; '46'=${function:Invoke-Menu46}; '47'=${function:Invoke-Menu47};
    '48'=${function:Invoke-Menu48}; '49'=${function:Invoke-Menu49}; '50'=${function:Invoke-Menu50}; '51'=${function:Invoke-Menu51};
    '52'=${function:Invoke-Menu52}; '53'=${function:Invoke-Menu53}; '54'=${function:Invoke-Menu54}; '55'=${function:Invoke-Menu55};
    '56'=${function:Invoke-Menu56}; '57'=${function:Invoke-Menu57}; '58'=${function:Invoke-Menu58}; '59'=${function:Invoke-Menu59};
    '90'=${function:Invoke-Menu90}; '91'=${function:Invoke-Menu91}; '92'=${function:Invoke-Menu92}; '93'=${function:Invoke-Menu93};
    '94'=${function:Invoke-Menu94}; '95'=${function:Invoke-Menu95}; '96'=${function:Invoke-Menu96}; '97'=${function:Invoke-Menu97};
    '98'=${function:Invoke-Menu98}; '99'=${function:Invoke-Menu99}
}

if (-not $SkipBanner) {
    Write-Host "Loaded $script:LauncherName v$script:LauncherVersion" -ForegroundColor Cyan
    Write-Host "PowerShell host: $($PSVersionTable.PSEdition) $($PSVersionTable.PSVersion)" -ForegroundColor DarkGray
    Write-Host 'No Azure resource is changed until you select a corresponding menu.' -ForegroundColor DarkGray
    Start-Sleep -Milliseconds 700
}

while ($true) {
    Show-Menu
    $selection = (Read-Host 'Select menu').Trim()
    if ($selection -match '^(q|quit|exit)$') {
        Save-State
        Write-Color 'Launcher ended normally. State was saved.' Green
        Write-Host
        break
    }
    if (-not $dispatch.ContainsKey($selection)) {
        Write-WarningMessage "Unknown menu: $selection"
        Read-Host 'Press Enter to continue' | Out-Null
        continue
    }
    try {
        & $dispatch[$selection]
    }
    catch {
        Write-Failure $_.Exception.Message
        Write-Host "`n[TECHNICAL DETAIL]" -ForegroundColor DarkGray
        Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray
        $errorPath = Join-Path $script:LogRoot "error-$(Get-Date -Format yyyyMMdd-HHmmss)-menu-$selection.txt"
        ($_ | Out-String) | Set-Content -LiteralPath $errorPath -Encoding UTF8
        Write-Host "Error log: $errorPath"
    }
    Write-Host
    Read-Host 'Press Enter to return to the menu' | Out-Null
}
