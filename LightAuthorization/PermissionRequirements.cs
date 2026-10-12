using Microsoft.AspNetCore.Authorization;

namespace LightAuthorization;

public sealed record PermissionPresenceRequirement(string Permission) : IAuthorizationRequirement;

public sealed record ResourcePermissionRequirement(string Permission) : IAuthorizationRequirement;
