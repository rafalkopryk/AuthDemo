# ConfigurableAuthorization

Paczka ASP.NET Core (`net11.0`) do autoryzacji zasobów przez `IAuthorizationService`. Nie zależy od EF Core ani modeli biznesowych. Role, mapowania tożsamości i granty pochodzą z konfiguracji; aplikacja deklaruje obsługiwane zasoby i znaczenie ich zakresów.

## Szybki start: zwykły obiekt jako zasób

Skonfiguruj uwierzytelnianie, następnie zarejestruj zasób:

```csharp
public sealed record Document(Guid? OwnerId, Guid? BranchId, string Channel);

services.AddCreditAuthroization(options =>
{
    options.Service("documents");
    options.Definition.ActorTypes.Add("person");
    options.Definition.ActorClaimType = "actor_type";

    options.Resource<Document>()
        .Permissions("documents.read", "documents.edit")
        .AllowAll()
        .Own(document => document.OwnerId, claim: "client_id")
        .OwnBranch(document => document.BranchId, claim: "branch_id",
            when: document => document.Channel == "branch");
});
```

`Document` jest zwykłą klasą lub rekordem. Nie implementuje interfejsu autoryzacji. Dla podstawowych zakresów nie potrzeba własnych `GrantOptions`, `AccessGrant` ani evaluatora. Aplikacja webowa dodatkowo wywołuje `AddAuthorization()` / `AddAuthorizationBuilder()` oraz uruchamia `UseAuthentication()` przed `UseAuthorization()`.

```json
{
  "Authorization": {
    "RoleMappings": [
      { "Actor": "person", "ClaimType": "groups", "Value": "reviewers", "Role": "reviewer" }
    ],
    "Roles": {
      "reviewer": {
        "Services": {
          "documents": {
            "Grants": [
              { "Permissions": ["documents.read"], "Scope": "All" },
              { "Permissions": ["documents.edit"], "Scope": "Own" }
            ]
          },
          "loans": {
            "Grants": [
              { "Permissions": ["loans.read"], "Scope": "OwnBranch", "Products": ["retail-loan"] }
            ]
          }
        }
      }
    }
  }
}
```

Token w tym przykładzie musi zawierać dokładnie jeden `actor_type=person` oraz claim `groups=reviewers`, aby rola `reviewer` dostała granty. `Service("documents")` wybiera wyłącznie granty `Services:documents`. Inne serwisy mogą mieć inne pola, uprawnienia i zakresy. Wspólne są `RoleMappings`, `ActorRoles` i nazwy ról. Każdy serwis waliduje własne granty. Rola bez sekcji danego serwisu nie daje mu dostępu. Bez `Service(...)` nadal można używać lokalnego formatu `Roles → Grants`.

Autoryzacja następuje po pobraniu zasobu, przed wykonaniem operacji:

```csharp
var result = await authorizationService.AuthorizeAsync(
    user, document, [new PermissionRequirement("documents.edit")]);

if (!result.Succeeded)
    return Results.Forbid();
```

`PermissionRequirement` w nowym trybie wymaga zarejestrowanego zasobu. `null`, `HttpContext`, obcy typ lub uprawnienie nieprzypisane do tego typu oznaczają odmowę. Dopasowanie typu jest dokładne: podklasy i proxy wymagają osobnej rejestracji, aby nie dziedziczyć przypadkowo dostępu.

## Zakresy i walidacja

- `All` pomija porównanie właściciela i oddziału. Dodatkowe warunki nadal obowiązują.
- `Own` porównuje wskazane pole z jednym niepustym identyfikatorem GUID w claimie.
- `OwnBranch` robi to samo dla oddziału; opcjonalne `when` określa dodatkowy warunek zasobu.
- Brak, niepoprawny, pusty lub wielokrotny claim identyfikatora oznacza niespełnienie zakresu.
- Dodatkowy zakres można zarejestrować przez `.Scope("Team", (user, resource) => ...)`, np. dla identyfikatorów tekstowych.
- Zakres wymagający bazy danych lub API można zarejestrować przez `.Scope<TScope>("Team")`, gdzie `TScope` implementuje `IResourceScope<TResource>`. Paczka rejestruje implementację jako scoped i wstrzykuje jej zależności przez DI. `AllowsAsync` otrzymuje użytkownika, zasób i token anulowania; `FilterAsync` stosuje ten sam zakres do każdego zasobu. Opcjonalny argument `eligible` pozwala wstępnie wykluczyć grant na podstawie claimów, bez dostępu do zasobu.

Nieznane uprawnienia i zakresy zatrzymują start przez `ValidateOnStart()`. Jeżeli uprawnienie jest przypisane do kilku typów zasobów, każdy musi obsługiwać skonfigurowany zakres. Warunki wewnątrz grantu łączą się przez AND, kompletne granty przez OR. Paczka działa na uwierzytelnionej tożsamości i nie ufa wejściowym wewnętrznym rolom `app_*`.

Zmiana grantów wymaga restartu aplikacji (`IOptions`); nie ma częściowego przeładowywania reguł w trakcie żądania.

## Wstępne sprawdzenie na endpoincie

Opcjonalna polityka endpointu może używać osobnego wymagania:

```csharp
services.AddAuthorizationBuilder().AddPolicy("CanEditDocuments", policy => policy
    .RequireAuthenticatedUser()
    .AddRequirements(new PermissionPresenceRequirement("documents.edit")));
```

Sprawdza ono istnienie nadania uprawnienia, z uwzględnieniem wymaganych claimów zakresu i `EvaluateWhen`. Nie porównuje danych konkretnego zasobu. Operacja nadal musi wywołać `AuthorizeAsync` z właściwym zasobem i `PermissionRequirement`. Nie używaj `PermissionPresenceRequirement` jako końcowego sprawdzenia dostępu do danych.

## Warunki domenowe

Gdy grant ma dodatkowe pola, użyj `AddCreditAuthroization<MyGrantOptions>(...)`, gdzie `MyGrantOptions : PermissionGrantOptions`. `.Require((user, grant, resource) => ...)` dodaje warunek do każdego grantu bez mieszania ograniczeń między grantami. `options.ValidateWith(...)` waliduje dodatkowe pola przy starcie.

`options.EvaluateWhen((user, grant) => ...)` to opcjonalny, synchroniczny warunek użycia pojedynczego grantu. Otrzymuje użytkownika i grant, ale nie konkretny zasób. Zwrócenie `false` wyłącza ten grant podczas rozwiązywania uprawnień; może więc odrzucić grant już przy `PermissionPresenceRequirement`. Na przykład Loans odrzuca grant, gdy jego ograniczenia produktów lub kanałów nie przecinają się z claimami użytkownika. Nie trzeba rejestrować `EvaluateWhen`, jeżeli role i scope'y wystarczają.

Do warunku zależnego od pól zasobu użyj `.Require((user, grant, resource) => ...)` albo własnego `.Scope<TScope>(...)` z `IResourceScope<TResource>`, gdy sprawdzenie potrzebuje DI lub operacji asynchronicznej. Pobranie roli użytkownika z bazy lub API musi nastąpić po uwierzytelnieniu, przed rozwiązywaniem grantów; `EvaluateWhen` nie służy do takiego lookupu. Delegaty `EvaluateWhen` i `Require` działają współbieżnie, więc nie powinny przechowywać stanu żądania.

Przy tworzeniu zasobu zwaliduj kompletne żądanie, a następnie autoryzuj dedykowany zasób utworzony z jego danych. Handler autoryzacji nie uzupełnia ani nie zmienia zasobu.

Przykład z produktami i kanałami: `Loans/Features/LoanApplications/Authorization/LoanAuthorizationRegistration.cs`.

## Opcjonalne filtrowanie małych kolekcji

```csharp
// Wstrzyknięty ResourceAuthorization<PermissionGrantOptions>
var visible = await resourceAuthorization.FilterAsync(
    user, documents, "documents.read", cancellationToken);
```

Dla własnych opcji wstrzyknij `ResourceAuthorization<MyGrantOptions>`. Helper wyznacza granty raz, a potem używa tych samych reguł co `AuthorizeAsync`. Działa na załadowanych obiektach, bez tłumaczenia na SQL. Nie rozwiązuje stronicowania ani liczenia rekordów w bazie. Aktualna lista Loans korzysta z osobnego `LoanQueryAuthorization` w serwisie Loans i przekłada jego zakres odczytu na zapytanie do bazy przed `Skip`/`Take`. Ten mechanizm nie jest częścią API paczki; własny serwis musi sam zastosować ograniczenia w swojej warstwie odczytu.

## Dedykowany model zasobu

Zamiast encji EF można zarejestrować niemutowalny rekord zawierający tylko atrybuty używane do autoryzacji, np. `DocumentResource(OwnerId, BranchId, Channel)`. Dla istniejącego dokumentu twórz go z pobranych danych, a przy tworzeniu — z przygotowanego żądania. Typy encji i requestu nie muszą być rejestrowane ani implementować interfejsu.

Helper kolekcji może projektować takie zasoby i zwracać oryginalne elementy:

```csharp
var visible = await resourceAuthorization.FilterAsync(
    user, documents, document => DocumentResource.From(document),
    "documents.read", cancellationToken);
```

Przykład w Loans: `LoanApplicationResource`, wspólny dla odczytu, tworzenia, edycji i wysłania. Snapshot nie aktualizuje się przy zmianie encji; twórz go bezpośrednio przed sprawdzeniem danej operacji.

## Dotychczasowe API

Poniższy wariant trzech parametrów generycznych pozostaje dostępny dla integracji z własnym modelem dostępu. Jego historyczna obsługa `null` i `HttpContext` dotyczy wyłącznie tego wariantu; nowy tryb zasobów wymaga jawnego `PermissionPresenceRequirement` dla kontroli wstępnej. W jednym kontenerze DI rejestruj jeden wariant.

## Zaawansowany adapter — zgodność z dotychczasowym API

Dodaj referencję do projektu, skonfiguruj uwierzytelnianie aplikacji i zarejestruj autoryzację. Biblioteka rejestruje `AddAuthorizationCore()` i może działać bez routingu HTTP. W aplikacji webowej dodatkowo użyj `AddAuthorization()` lub `AddAuthorizationBuilder()` do konfiguracji polityk i middleware:

```csharp
services.AddCreditAuthroization<DocumentGrant, DocumentAccess, DocumentGrantEvaluator>(definition =>
{
    definition.Permissions.UnionWith(["documents.read", "documents.edit"]);
    definition.ActorTypes.Add("person");
    definition.ActorClaimType = "identity_kind";
    definition.SpaceSeparatedClaimTypes.Add("groups");
}, configurationSection: "DocumentAccess");
```

Przykładowa konfiguracja:

```json
{
  "DocumentAccess": {
    "RoleMappings": [
      { "Actor": "person", "ClaimType": "groups", "Value": "reviewer", "Role": "reviewer" }
    ],
    "Roles": {
      "reviewer": {
        "Grants": [
          { "Permissions": ["documents.read"], "Scope": "All" },
          { "Permissions": ["documents.edit"], "Scope": "Team" }
        ]
      }
    }
  }
}
```

Aplikacja dostarcza trzy elementy:

- `DocumentGrant : PermissionGrantOptions`: dodatkowe pola konfiguracji nadania, jeśli są potrzebne.
- `DocumentAccess`: wynik oceny pojedynczego nadania, np. dozwolony zespół i klasyfikacja.
- `DocumentGrantEvaluator : IGrantEvaluator<DocumentGrant, DocumentAccess>`: `Validate` sprawdza konfigurację domenową, `Evaluate` zwraca zakres dostępu lub `null`, gdy nie można przyznać dostępu. Implementacja jest singletonem i musi być bezpieczna dla współbieżnych wywołań. Brak wymaganego claimu powinien dawać `null`, a nie nieograniczony dostęp.

Kompletny, kompilowany przykład tych typów znajduje się w `ConfigurableAuthorization.Tests/DocumentAuthorizationTests.cs`.

## Sprawdzanie uprawnień

Polityka endpointu może wymagać `new PermissionRequirement("documents.read")`. Sprawdza to istnienie uprawnienia dla użytkownika.

Dla dostępu do danych zasób powinien implementować `IAuthorizationResource<DocumentAccess>` i sprawdzać pełne nadania. Następnie:

```csharp
var result = await authorizationService.AuthorizeAsync(
    user, document, [new PermissionRequirement("documents.edit")]);
```

`IAccessResolver<DocumentAccess>.ResolveAsync(user, permission)` udostępnia kompletne nadania do budowania filtrów zapytań. Aplikacja musi zachować warunki jednego nadania razem (AND), łączyć kompletne nadania przez OR i filtrować przed stronicowaniem. Biblioteka nie generuje zapytań do bazy danych.

`null` jako zasób oznacza świadome sprawdzenie samego uprawnienia. `HttpContext` jest obsługiwany jako zasób polityki endpointu; sprawdzenie konkretnego zasobu następuje później w aplikacji/dekoratorze. Inny nieobsługiwany typ zasobu jest odrzucany, aby przypadkowo nie pominąć kontroli danych.

## Tożsamość i konfiguracja

Biblioteka pracuje na już uwierzytelnionym `ClaimsPrincipal`. Nie weryfikuje podpisów tokenów. Rejestruje `IClaimsTransformation`, które klonuje tożsamości i odtwarza wewnętrzne role z zaufanych claimów. Transformacja jest idempotentna; oryginalny principal nie jest modyfikowany. Resolver stosuje tę samą transformację również przy wywołaniu poza HTTP.

`RoleMappings` dopasowuje wartości istniejących claimów; nie pobiera ról z bazy lub API. Gdy rola pracownika zależy np. od XNUC, aplikacja najpierw ustala ją z zaufanego źródła i dodaje własny claim do uwierzytelnionej tożsamości, a następnie mapuje ten claim na rolę w konfiguracji. Przy błędzie lookupu nie dodawaj roli. Przychodzący claim o nazwie zarezerwowanej dla wyniku lookupu trzeba usunąć przed dodaniem własnej wartości. Zewnętrzny identyfikator aplikacji technicznej również musi pochodzić ze zweryfikowanego tokenu. Paczka usuwa przychodzące wewnętrzne claimy z prefiksem `app_` i sama odtwarza role aplikacji.

`AuthorizationDefinition` określa dozwolone operacje i aktorów, claim aktora, claim roli oraz zastrzeżony prefiks wewnętrznych claimów. Domyślnie brak claimu aktora odmawia dostępu. Opcjonalne `DefaultActor` pozwala świadomie obsłużyć starsze tożsamości. Wielokrotny lub nieznany aktor zawsze odmawia dostępu. `ActorRoles` w konfiguracji umożliwia domyślne przypisanie ról wybranemu typowi aktora.

Rejestruj bibliotekę po konfiguracji uwierzytelniania. Jeśli aplikacja ma już własne `IClaimsTransformation`, zastosuj jawną kompozycję transformacji, z `ConfiguredClaimsTransformation<TGrant>` po pozostałych transformacjach. Nadawanie ról przez bibliotekę zawsze wynika z jej konfiguracji i zweryfikowanych claimów wejściowych.

Obsługiwana jest jedna definicja autoryzacji i jeden typ adaptera na kontener DI. Adapter może obsługiwać wiele rodzajów zasobów aplikacji; ponowna rejestracja zgłasza błąd zamiast nadpisywać konfigurację.

Przy wspólnej sekcji `Authorization` serwisy dzielą `RoleMappings`, `ActorRoles` i nazwy ról, lecz `Service("nazwa")` wybiera granty tylko dla danego serwisu. Każdy serwis waliduje wszystkie wspólne mapowania względem zadeklarowanych u siebie typów aktorów. Jeśli zestawy aktorów się różnią, użyj oddzielnych sekcji przez parametr `configurationSection` w `AddCreditAuthroization`.

Typowane opcje i walidacja startowa wykrywają nieznane uprawnienia, aktorów, role w mapowaniach oraz błędy zwrócone przez adapter. Nieznane pola konfiguracji są odrzucane. Konfiguracja jest wczytywana przez `IOptions` i wymaga restartu aplikacji po zmianie.
