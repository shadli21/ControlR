## Breaking Changes

- Service-account API routes and client accessors now explicitly distinguish tenant-scoped and server-scoped accounts. The V1 server routes use `/api/v1/server-service-accounts`, and the V1 tenant routes use `/api/v1/tenant-service-accounts/{tenantId}`. The internal routes use `/api/server-service-accounts` and `/api/tenant-service-accounts`.
- Some of the DTOs used in the `/api/v1/*` endpoints have been changed.
  - There will be no more breaking changes to the `/api/v1/*` endpoints after this release.
- Although roles were migrated to permission presets, user tags that mapped users to devices were removed.
  - If you were using user tags to control access to devices, you will need to migrate to the new permissions system.

## Enhancements

- Added `Customers`, `Device Groups`, and `User Groups`.
- Added Tenant and Server service accounts, including API-credential issuance with configurable expiration.
- Replaced roles with a granular permissions system.
  - You can now grant users and service accounts specific permissions, scoped to the whole tenant, a customer, a device group, or an individual device.
- Existing roles get migrated to permission presets, which are bundles of related permissions that can be applied at once.
- Added a Permissions page under Tenant Admin for managing who can do what.
- Added filters on the dashboard for customer and device group.
- Added any/all match mode for filtering by tags and device groups.
- Reworked how ungrouped/untagged device display is toggled.
- Authorization changes are now logged, with tenant and server views of the activity.
- Fine-grained permissions can now be applied to Personal Access Tokens.
- Added an Effective Permissions page that shows exactly what a user or service account can do.
- Added `Customer` input to the deploy page, allowing for the device to get added to a specific customer during agent installation.
- Refactored `Deploy` page for better usability (back button, pre-populated expiration for time-based keys, grid sizing).

## Fixes

None.

## Removals

None.

## Internal

- Client authorization state now carries server-evaluated policy grants rather than
  scope-agnostic permission-name hints. Only tenant/server-wide policies are projected to
  the client; resource-specific authorization remains server-side and resource-bound.
- Deploy tag selection now evaluates the intended deployment target (new device or a
  predetermined existing device with the selected customer) before offering tag assignment,
  instead of relying on a global permission claim.
