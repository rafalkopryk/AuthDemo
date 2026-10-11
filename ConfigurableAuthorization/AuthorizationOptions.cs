namespace ConfigurableAuthorization;

public sealed class AuthorizationOptions<TGrant> where TGrant : PermissionGrantOptions
{
    public Dictionary<string, string[]> ActorRoles { get; set; } = new(StringComparer.Ordinal);
    public RoleMappingOptions[] RoleMappings { get; set; } = [];
    public Dictionary<string, RoleOptions<TGrant>> Roles { get; set; } = new(StringComparer.Ordinal);
}

public sealed class RoleMappingOptions
{
    public string Actor { get; set; } = "";
    public string ClaimType { get; set; } = "";
    public string Value { get; set; } = "";
    public string Role { get; set; } = "";
}

public sealed class RoleOptions<TGrant> where TGrant : PermissionGrantOptions
{
    public TGrant[] Grants { get; set; } = [];
}

public class PermissionGrantOptions
{
    public string[] Permissions { get; set; } = [];
    public string Scope { get; set; } = "";
}
