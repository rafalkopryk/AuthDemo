using Microsoft.AspNetCore.Authorization;

namespace ConfigurableAuthorization;

public sealed record PermissionRequirement(string Permission) : IAuthorizationRequirement;
