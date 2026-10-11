using Microsoft.Extensions.Options;

namespace ConfigurableAuthorization;

internal sealed class AuthorizationOptionsValidator<TGrant, TAccess>(
    AuthorizationDefinition definition, IGrantEvaluator<TGrant, TAccess> evaluator)
    : IValidateOptions<AuthorizationOptions<TGrant>>
    where TGrant : PermissionGrantOptions where TAccess : class
{
    public ValidateOptionsResult Validate(string? name, AuthorizationOptions<TGrant> options)
    {
        var errors = new List<string>();
        if (options.Roles.Count == 0) errors.Add("At least one role must be configured.");
        foreach (var (role, configuredRole) in options.Roles)
        {
            if (string.IsNullOrWhiteSpace(role) || role.Any(char.IsWhiteSpace))
                errors.Add($"Invalid role name '{role}'.");
            foreach (var grant in configuredRole.Grants)
            {
                if (grant.Permissions.Length == 0 || grant.Permissions.Any(p => !definition.Permissions.Contains(p)))
                    errors.Add($"Role '{role}' has an unknown or missing permission.");
                errors.AddRange(evaluator.Validate(grant).Select(error => $"Role '{role}': {error}"));
            }
        }
        foreach (var (actor, roles) in options.ActorRoles)
            if (!definition.ActorTypes.Contains(actor) || roles.Any(role => !options.Roles.ContainsKey(role)))
                errors.Add($"Invalid actor role binding for '{actor}'.");
        foreach (var mapping in options.RoleMappings)
            if (!definition.ActorTypes.Contains(mapping.Actor)
                || string.IsNullOrWhiteSpace(mapping.ClaimType)
                || mapping.ClaimType.StartsWith(definition.InternalClaimPrefix, StringComparison.Ordinal)
                || string.IsNullOrWhiteSpace(mapping.Value)
                || (definition.SpaceSeparatedClaimTypes.Contains(mapping.ClaimType) && mapping.Value.Any(char.IsWhiteSpace))
                || !options.Roles.ContainsKey(mapping.Role))
                errors.Add($"Invalid role mapping for '{mapping.Role}'.");
        return errors.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(errors);
    }
}
