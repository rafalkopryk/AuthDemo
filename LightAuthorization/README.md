# LightAuthorization

Role i uprawnienia pochodzą z konfiguracji. Dla pojedynczych zasobów definiuje się zakres przez lambdę albo klasę z DI. Gdy ten sam zakres ma też ograniczać listy, używa się wynikowego `Access` i `.Map(...)`. Jeden zasób korzysta z jednego z tych wariantów.

## Tylko pojedynczy zasób

```csharp
services.AddLightAuthorization(options =>
{
    options.MapRole("client", user => user.HasClaim("role", "client"));
    options.MapRole("employee", user => user.HasClaim("role", "employee"));
    options.Roles(configuration.GetSection("Authorization:Roles"));

    options.Resource<Account>()
        .Scope("Own", (user, account) =>
            ReadCustomerId(user) == account.CustomerId)
        .Scope<BranchScope>("Branch");
});
```

`Account` może być istniejącą klasą domenową. Własny zakres z DI implementuje jedną metodę:

```csharp
public sealed class BranchScope(IEmployeeBranches branches) : IResourceScope<Account>
{
    public ValueTask<bool> AllowsAsync(
        ClaimsPrincipal user, Account account, CancellationToken cancellationToken) =>
        branches.ContainsAsync(user, account.BranchId, cancellationToken);
}
```

Biblioteka rejestruje `BranchScope` jako scoped. Dla tej ścieżki nie jest rejestrowany `IAccessResolver`, bo nie ma ograniczeń do zapytań. Zakresy są wybierane na podstawie tych samych przypisań w `Authorization:Roles`. Kilka pasujących zakresów oznacza OR. Brak przyznanego lub spełnionego zakresu oznacza odmowę.

## Zasób z listą

## Najprostszy przykład

```csharp
public sealed record Account(Guid CustomerId, Guid BranchId);
public sealed record AccountAccess(Guid[]? CustomerIds = null, Guid[]? BranchIds = null);

services.AddLightAuthorization(options =>
{
    options.MapRole("client", user => user.HasClaim("role", "client"));
    options.MapRole("employee", user => user.HasClaim("role", "employee"));
    options.Roles(configuration.GetSection("Authorization:Roles"));

    options.Resource<Account>().Access<AccountAccess>()
        .Map(access => access.CustomerIds, account => account.CustomerId)
        .Map(access => access.BranchIds, account => account.BranchId)
        .Scope("Own", user =>
            Guid.TryParse(user.FindFirst("customer_id")?.Value, out var id) && id != Guid.Empty
                ? new AccountAccess(CustomerIds: [id]) : null)
        .Scope("All", _ => new AccountAccess())
        .Scope<EmployeeBranchProvider>("Branch");
});
```

```json
{
  "Authorization": {
    "Roles": {
      "client": {
        "accounts.create": ["Own"],
        "accounts.close": ["Own"]
      },
      "employee": {
        "accounts.read": ["Branch"],
        "accounts.close": ["Branch"],
        "accounts.reopen": ["Branch"]
      }
    }
  }
}
```

`Roles(...)` czyta `IConfiguration`, więc źródłem może być appsettings lub zewnętrzny provider konfiguracji. Odczyt następuje przy rejestracji; zmiana konfiguracji wymaga restartu. `MapRoleMappings(section, actorResolver)` pozwala również wczytać mapowania claimów na role (`Actor`, `ClaimType`, `Value`, `Role`). Claim `scope` obsługuje wartości oddzielone spacjami. Biblioteka korzysta wyłącznie z uwierzytelnionego użytkownika; weryfikacja tokenów należy do aplikacji.

## Własny provider z DI

```csharp
public interface IEmployeeBranches
{
    Task<Guid[]> GetIdsAsync(string employeeId, CancellationToken cancellationToken);
}

public sealed class EmployeeBranchProvider(IEmployeeBranches branches)
    : IAccessProvider<AccountAccess>
{
    public async ValueTask<AccountAccess?> ResolveAsync(
        ClaimsPrincipal user, CancellationToken cancellationToken)
    {
        var employeeId = user.FindFirst("employee_id")?.Value;
        if (string.IsNullOrWhiteSpace(employeeId)) return null;

        var ids = await branches.GetIdsAsync(employeeId, cancellationToken);
        return new AccountAccess(BranchIds: ids);
    }
}
```

Aplikacja rejestruje implementację `IEmployeeBranches` w DI. `.Scope<EmployeeBranchProvider>("Branch")` automatycznie rejestruje provider jako scoped, o ile nie został już zarejestrowany. Można użyć jednej klasy providera w kilku rejestracjach. Scoped nie oznacza cache wyniku; każdy odczyt resolvera ponownie uruchamia fabryki. Powtarzający się zakres z kilku ról jest rozwiązywany raz w obrębie jednego wywołania.

Dostępna jest też fabryka `.Scope("Branch", (services, user, cancellationToken) => ...)` zwracająca `ValueTask<AccountAccess?>`.

## Zasady ograniczeń

- Cały wynik providera `null`: ten zakres nie daje dostępu.
- Pole `null`: brak ograniczenia po tym polu.
- Pusta kolekcja: żaden zasób nie pasuje do tego zakresu.
- Wszystkie mapowania jednego dostępu łączą się przez AND.
- Oddzielne dostępy z resolvera łączą się przez OR. Nie wolno osobno scalać ich klientów i oddziałów.
- Brak dostępów: odmowa.

`Map` obsługuje kolekcje (`Guid[]`, `string[]`, itp.) oraz pojedyncze opcjonalne wartości, np. `Guid? ClientId`. Porównania korzystają z domyślnego porównania typu (dla stringów dokładne, z rozróżnianiem wielkości liter). Każde pole ograniczające dostęp należy zmapować i uwzględnić w zapytaniach. Rejestracja bez żadnego `Map` jest odrzucana.

## Pojedynczy zasób

```csharp
var result = await authorizationService.AuthorizeAsync(user, account,
    [new ResourcePermissionRequirement("accounts.close")]);
```

Biblioteka rozwiązuje dostępy i sprawdza mapowania. Nie trzeba pisać własnego handlera. Handler przekazuje `HttpContext.RequestAborted`; poza HTTP używa `CancellationToken.None`. Wyjątki providerów propagują się do wywołującego.

`PermissionPresenceRequirement` jest tylko wstępnym sprawdzeniem przypisania uprawnienia. Nie rozwiązuje ograniczeń i nie wystarcza do udostępnienia zasobu lub listy. Dodatkowe warunki operacji można składać standardowym `AuthorizationPolicyBuilder`.

## Query: EF i Dapper

Wstrzyknij `IAccessResolver<Account, AccountAccess>`:

```csharp
var accesses = await resolver.ResolveAsync(user, "accounts.read", cancellationToken);
```

Wynik zawiera dane niezależne od ORM. Biblioteka nie generuje SQL. Filtry dostępu należy zastosować przed sortowaniem i paginacją. Przykład EF zachowujący AND wewnątrz alternatywy i OR między nimi:

```csharp
var permitted = db.Accounts.Where(_ => false);
foreach (var access in accesses)
{
    var alternative = db.Accounts.AsQueryable();
    if (access.CustomerIds is { } customers)
        alternative = alternative.Where(account => customers.Contains(account.CustomerId));
    if (access.BranchIds is { } branches)
        alternative = alternative.Where(account => branches.Contains(account.BranchId));
    permitted = permitted.Union(alternative);
}
var page = await permitted.OrderBy(account => account.Id)
    .Skip(skip).Take(take).ToArrayAsync(cancellationToken);
```

Powyższy przykład zakłada encję EF z kluczem `Id` oraz polami `CustomerId` i `BranchId`. Pusta lista dostępów zwraca zero rekordów. `Union` usuwa duplikaty między alternatywami.

Dla Dappera i PostgreSQL można zbudować warunek z zaufanych nazw kolumn oraz parametrów:

```csharp
var parameters = new DynamicParameters();
var alternatives = new List<string>();
for (var i = 0; i < accesses.Count; i++)
{
    var access = accesses[i];
    var conditions = new List<string>();
    if (access.CustomerIds is { } customers)
    {
        conditions.Add($"customer_id = ANY(@Customers{i})");
        parameters.Add($"Customers{i}", customers);
    }
    if (access.BranchIds is { } branches)
    {
        conditions.Add($"branch_id = ANY(@Branches{i})");
        parameters.Add($"Branches{i}", branches);
    }
    alternatives.Add(conditions.Count == 0 ? "TRUE" : "(" + string.Join(" AND ", conditions) + ")");
}
var predicate = alternatives.Count == 0 ? "FALSE" : string.Join(" OR ", alternatives);
parameters.Add("Take", take);
parameters.Add("Skip", skip);
var sql = $"SELECT * FROM customer_accounts WHERE ({predicate}) ORDER BY id LIMIT @Take OFFSET @Skip";
var rows = await connection.QueryAsync(new CommandDefinition(sql, parameters, cancellationToken: cancellationToken));
```

Wartości użytkownika są przekazywane jako parametry. Puste tablice nie dopasowują rekordów; null pola pomija dany warunek. Dodatkowe filtry zapytania należy dołączyć przez AND do całego wyrażenia w nawiasach. Dapper pozostaje zależnością aplikacji, a nie biblioteki autoryzacji.
