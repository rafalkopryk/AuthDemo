using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace ConfigurableAuthorization;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddCreditAuthroization(this IServiceCollection services,
        Action<ResourceAuthorizationBuilder<PermissionGrantOptions>> configure, string configurationSection = "Authorization")
        => services.AddCreditAuthroization<PermissionGrantOptions>(configure, configurationSection);

    public static IServiceCollection AddCreditAuthroization<TGrant>(this IServiceCollection services,
        Action<ResourceAuthorizationBuilder<TGrant>> configure, string configurationSection = "Authorization")
        where TGrant : PermissionGrantOptions
    {
        var builder = new ResourceAuthorizationBuilder<TGrant>();
        configure(builder);
        if (builder.Resources.Count == 0 || builder.Resources.Values.Any(r => r.Permissions.Count == 0 || r.Scopes.Count == 0))
            throw new ArgumentException("Every resource must declare permissions and scopes.", nameof(configure));
        foreach (var type in builder.Resources.Values.SelectMany(resource => resource.Scopes.Values)
                     .Select(scope => scope.ServiceType).OfType<Type>().Distinct())
            services.TryAdd(ServiceDescriptor.Scoped(type, type));
        services.AddHttpContextAccessor();
        services.AddSingleton(builder);
        services.AddCreditAuthroization<TGrant, ResourceGrant<TGrant>, ResourceGrantEvaluator<TGrant>>(definition =>
        {
            definition.ServiceName = builder.Definition.ServiceName;
            definition.Permissions.UnionWith(builder.Definition.Permissions);
            definition.ActorTypes.UnionWith(builder.Definition.ActorTypes);
            definition.ActorClaimType = builder.Definition.ActorClaimType;
            definition.DefaultActor = builder.Definition.DefaultActor;
            definition.RoleClaimType = builder.Definition.RoleClaimType;
            definition.InternalClaimPrefix = builder.Definition.InternalClaimPrefix;
            definition.SpaceSeparatedClaimTypes.Clear();
            definition.SpaceSeparatedClaimTypes.UnionWith(builder.Definition.SpaceSeparatedClaimTypes);
        }, configurationSection);
        var legacyHandler = services.Single(s => s.ServiceType == typeof(IAuthorizationHandler)
            && s.ImplementationType == typeof(ConfiguredPermissionHandler<ResourceGrant<TGrant>>));
        services.Remove(legacyHandler);
        services.AddScoped<IAuthorizationHandler, ResourcePermissionHandler<TGrant>>();
        services.AddScoped<ResourceAuthorization<TGrant>>();
        return services;
    }

    public static IServiceCollection AddCreditAuthroization<TGrant, TAccess, TEvaluator>(
        this IServiceCollection services, Action<AuthorizationDefinition> configure,
        string configurationSection = "Authorization")
        where TGrant : PermissionGrantOptions
        where TAccess : class
        where TEvaluator : class, IGrantEvaluator<TGrant, TAccess>
    {
        if (services.Any(service => service.ServiceType == typeof(AuthorizationDefinition)))
            throw new InvalidOperationException("Configured authorization is already registered in this service collection.");
        var definition = new AuthorizationDefinition();
        configure(definition);
        if (definition.Permissions.Count == 0 || definition.ActorTypes.Count == 0
            || definition.Permissions.Any(string.IsNullOrWhiteSpace) || definition.ActorTypes.Any(string.IsNullOrWhiteSpace)
            || string.IsNullOrWhiteSpace(definition.ActorClaimType)
            || string.IsNullOrWhiteSpace(definition.InternalClaimPrefix)
            || definition.ActorClaimType.StartsWith(definition.InternalClaimPrefix, StringComparison.Ordinal)
            || !definition.RoleClaimType.StartsWith(definition.InternalClaimPrefix, StringComparison.Ordinal)
            || (definition.DefaultActor is not null && !definition.ActorTypes.Contains(definition.DefaultActor)))
            throw new ArgumentException("Invalid authorization definition.", nameof(configure));

        services.AddSingleton(definition);
        services.AddSingleton<IGrantEvaluator<TGrant, TAccess>, TEvaluator>();
        services.AddSingleton<IValidateOptions<AuthorizationOptions<TGrant>>, AuthorizationOptionsValidator<TGrant, TAccess>>();
        var options = services.AddOptions<AuthorizationOptions<TGrant>>();
        if (definition.ServiceName is { } service)
            options.Configure<IConfiguration>((value, configuration) =>
                ServiceAuthorizationConfiguration.Bind(configuration.GetSection(configurationSection), service, value));
        else
            options.BindConfiguration(configurationSection, binder => binder.ErrorOnUnknownConfiguration = true);
        options.ValidateOnStart();
        services.AddTransient<ConfiguredClaimsTransformation<TGrant>>();
        services.AddTransient<IClaimsTransformation>(provider => provider.GetRequiredService<ConfiguredClaimsTransformation<TGrant>>());
        services.AddScoped<IAccessResolver<TAccess>, ConfiguredAccessResolver<TGrant, TAccess>>();
        services.AddAuthorizationCore();
        services.AddScoped<IAuthorizationHandler, ConfiguredPermissionHandler<TAccess>>();
        return services;
    }
}
