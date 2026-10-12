using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;

namespace LightAuthorization;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddLightAuthorization(this IServiceCollection services,
        Action<LightAuthorizationBuilder> configure)
    {
        ArgumentNullException.ThrowIfNull(configure);
        var builder = new LightAuthorizationBuilder();
        configure(builder);
        var definition = builder.Build();
        services.AddSingleton(definition);
        services.AddAuthorizationCore();
        services.AddHttpContextAccessor();
        services.AddScoped<IAuthorizationHandler, PermissionPresenceHandler>();
        builder.RegisterHandlers(services);
        return services;
    }
}
