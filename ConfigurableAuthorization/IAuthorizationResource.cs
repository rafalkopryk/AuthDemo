namespace ConfigurableAuthorization;

/// <summary>Applies the complete grants to a domain resource, preserving their correlations.</summary>
public interface IAuthorizationResource<TAccess> where TAccess : class
{
    bool Authorize(string permission, IReadOnlyList<TAccess> grants);
}
