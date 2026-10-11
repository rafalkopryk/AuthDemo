using System.Security.Claims;

namespace ConfigurableAuthorization;

/// <summary>Domain adapter. Implementations are registered as singletons and must be thread safe.</summary>
public interface IGrantEvaluator<in TGrant, out TAccess>
    where TGrant : PermissionGrantOptions where TAccess : class
{
    IEnumerable<string> Validate(TGrant grant);
    TAccess? Evaluate(ClaimsPrincipal user, TGrant grant);
}
