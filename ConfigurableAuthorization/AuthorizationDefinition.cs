namespace ConfigurableAuthorization;

public sealed class AuthorizationDefinition
{
    public string? ServiceName { get; set; }
    public HashSet<string> Permissions { get; } = new(StringComparer.Ordinal);
    public HashSet<string> ActorTypes { get; } = new(StringComparer.Ordinal);
    public string ActorClaimType { get; set; } = "actor_type";
    public string? DefaultActor { get; set; }
    public string RoleClaimType { get; set; } = "app_role";
    public string InternalClaimPrefix { get; set; } = "app_";
    public HashSet<string> SpaceSeparatedClaimTypes { get; } = new(StringComparer.Ordinal) { "scope" };
}
