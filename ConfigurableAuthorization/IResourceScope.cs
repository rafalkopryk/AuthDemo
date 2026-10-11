using System.Security.Claims;

namespace ConfigurableAuthorization;

/// <summary>Implements a resource scope with dependencies resolved from the current DI scope.</summary>
public interface IResourceScope<in TResource> where TResource : class
{
    ValueTask<bool> AllowsAsync(ClaimsPrincipal user, TResource resource, CancellationToken cancellationToken);
}
