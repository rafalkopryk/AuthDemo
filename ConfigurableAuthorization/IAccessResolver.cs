using System.Security.Claims;

namespace ConfigurableAuthorization;

public interface IAccessResolver<TAccess> where TAccess : class
{
    /// <summary>Normalizes an authenticated principal and returns complete grants for one permission.</summary>
    Task<IReadOnlyList<TAccess>> ResolveAsync(ClaimsPrincipal user, string permission);
}
