# AuthDemo — zabezpieczenia API

Poniższa tabela opisuje domyślną konfigurację uprawnień. Wszystkie endpointy `/loan-applications` wymagają podpisanego JWT Bearer. API sprawdza podpis, issuer, audience i termin ważności. Nieprawidłowy lub brakujący token daje **401**. Brak uprawnień do operacji lub istniejącego zasobu daje **403**. Dla żądania dopuszczonego przez politykę endpointu nieistniejący wniosek daje **404**.

| Token | GET | POST / PUT / submit |
| --- | --- | --- |
| Kliencki: `client_id` (niepusty GUID), bez `token_type` lub `token_type=client` | Własne wnioski | Własne wnioski |
| Techniczny: `token_type=technical`, `scope=loans.read` | Wnioski wszystkich klientów | 403 |
| Techniczny: `token_type=technical`, `scope=loans.write` | 403 | Wnioski wszystkich klientów |
| Techniczny z oboma scope | Wnioski wszystkich klientów | Wnioski wszystkich klientów |

Uprawnienia są przypisane do konkretnego API: np. `payments.read` nie daje dostępu do Loans. Scope nie implikują się wzajemnie. `scope` może zawierać listę oddzieloną spacjami albo występować wielokrotnie.

Token techniczny wymaga jawnych scope, także gdy zawiera `client_id`. Token kliencki nie otrzymuje dostępu do cudzych danych nawet gdy zawiera scope techniczne. Nieznany lub wielokrotny `token_type` jest odrzucany.

Kliencki POST wymaga `ClientId` zgodnego z tokenem (inaczej **403**). Odczyt, edycja i wysłanie autoryzują zapisany wniosek: dostęp klienta do cudzego wniosku zwraca **403**, niezależnie od danych w żądaniu. Techniczny zapis może wskazać dowolnego klienta przy tworzeniu. Próba zmiany właściciela już autoryzowanego wniosku daje **409**, również dla klienta. Ograniczenia biznesowe, np. zapis tylko szkiców, obowiązują oba typy tokenów.

## Token lokalny

Po uruchomieniu aplikacji w środowisku Development wygeneruj token:

```sh
dotnet user-jwts create --project Loans --name demo-client --claim client_id=11111111-1111-1111-1111-111111111111 --valid-for 1h
```

Polecenie zapisuje konfigurację wystawcy i odbiorców w `Loans/appsettings.Development.json`, a klucz podpisujący w user secrets poza repozytorium. Wygenerowany token jest przeznaczony wyłącznie do lokalnego testowania. Po pierwszym wygenerowaniu tokenu uruchom ponownie zasób Loans, jeśli aplikacja już działa.

W Swagger UI kliknij **Authorize** i wklej sam token (bez prefiksu `Bearer`).

Do żądań dodaj nagłówek `Authorization: Bearer <token>`. W POST/PUT `ClientId` musi odpowiadać claimowi tokenu:

```sh
curl --cacert <certyfikat-dev.pem> https://localhost:7246/loan-applications/ \
  -H 'Authorization: Bearer <token>' \
  -H 'Content-Type: application/json' \
  -d '{"clientId":"11111111-1111-1111-1111-111111111111","applicantName":"Jan Kowalski","amount":10000,"termMonths":12,"purpose":"Remont","channel":"digital"}'
```

Użyj rzeczywistego adresu HTTPS zasobu Loans z dashboardu Aspire. Przykładowy port pochodzi z profilu uruchomienia projektu. Jeżeli system ufa certyfikatowi deweloperskiemu .NET, pomiń `--cacert`.

Dotychczasowe wnioski są dostępne dla klientów z odpowiadającym im `client_id` oraz tokenów technicznych z właściwym scope. W Development dokument OpenAPI, Swagger UI i endpointy health pozostają publiczne.

## Lokalny token techniczny

Tylko odczyt wniosków wszystkich klientów:

```sh
dotnet user-jwts create --project Loans --name loans-reader --claim token_type=technical --scope loans.read --valid-for 1h
```

Odczyt i zapis:

```sh
dotnet user-jwts create --project Loans --name loans-service --claim token_type=technical --scope loans.read --scope loans.write --valid-for 1h
```

## Token serwisu ograniczony do produktu

`product` jest kodem produktu wniosku, np. `retail-loan` (kredyt detaliczny). Kody zaczynają się małą literą, zawierają małe litery, cyfry i myślniki, mają maksymalnie 64 znaki. Pole jest opcjonalne dla zgodności z istniejącymi wnioskami; brak oznacza produkt nieprzypisany.

Serwis kanału sklep z dostępem wyłącznie do odczytu kredytów detalicznych:

```sh
dotnet user-jwts create --project Loans --name retail-loan-reader --claim token_type=technical --scope loans.read --claim allowed_product=retail-loan --claim allowed_channel=store --valid-for 1h
```

- `GET /loan-applications/?skip=0&take=20` zwraca tylko dozwolone produkty. Stronicowanie następuje po ograniczeniu klienta i produktu; `take` ma zakres 1–100.
- `GET /loan-applications/{id}` dla innego lub nieprzypisanego produktu zwraca **403**.
- Bez `loans.write` zapis zwraca **403**. Jeżeli token ma również zapis, filtr produktu obowiązuje także POST, PUT i submit; nie można zmieniać produktu istniejącego wniosku.
- Wiele claimów `allowed_product` dopuszcza wiele produktów. Błędny lub pusty claim daje **403**.
- Brak `allowed_product` zachowuje dotychczasowy dostęp do wszystkich produktów dla uprawnionych tokenów technicznych.
- Tokeny klienckie nadal mają ograniczenie właściciela; ewentualny filtr produktu dodatkowo zawęża ich dostęp.

Przy tworzeniu wniosku detalicznego dodaj do JSON `"product":"retail-loan"`; przy PUT przekaż ten sam produkt. Migracja `AddLoanProduct` dodaje nullable kolumnę: dotychczasowe rekordy pozostają nieprzypisane i nie są widoczne dla tokenu detalicznego. Istniejący zasób migracji Aspire zastosuje zmianę przy uruchomieniu aplikacji.

## Pracownik, oddział i kanał

Wniosek ma `channel`: `branch` (oddział), `digital` (cyfrowy), `store` (sklep). W kanale `branch` wymagany jest niepusty `branchId` (GUID); pozostałe kanały nie mogą mieć `branchId`. Klient podaje `channel: "digital"` przy tworzeniu wniosku i nie może podszyć się pod oddział lub sklep. Pominięty kanał przy POST daje **400**. Kanału i oddziału istniejącego wniosku nie można zmienić. Gdy PUT pomija te pola, zachowują poprzednie wartości.

Token pracowniczy sprzedawcy:

```sh
dotnet user-jwts create --project Loans --name branch-seller --claim token_type=employee --role seller --claim branch_id=33333333-3333-3333-3333-333333333333 --valid-for 1h
```

Rola `seller` pozwala wyłącznie na odczyt wniosków wszystkich klientów, których `channel=branch` i `branchId` odpowiada oddziałowi pracownika. Dotyczy listy i pobrania po ID (**403** dla pozostałych). Wnioski cyfrowe i sklepowe są niewidoczne. Dla roli `seller` zapis daje **403**, również gdy token pracownika zawiera scope techniczne lub `client_id`. Oddział pochodzi z poprawnego, pojedynczego `branch_id`; gdy claimu nie ma, może go ustalić zarejestrowany resolver na podstawie `employee_id`. Błędny lub wielokrotny `branch_id` nie uruchamia resolvera i daje **403**. Nieznane role nie dają uprawnień. Wiele ról jest obsługiwane przez powtarzany claim `role`; `seller`, `operator` i `branch_advisor` mają zdefiniowane uprawnienia.

Rola `operator` ma odczyt i edycję szkiców w tym samym zakresie oddziałowym: kanał `branch` i własny `branch_id`. Nie może tworzyć ani wysyłać wniosków (**403**), nawet z rolą `seller` i scope `loans.write`. Edycja wniosków spoza oddziału lub z kanału cyfrowego/sklepowego zwraca **403**. Wysłane wnioski pozostają nieedytowalne (**409**). Filtry produktu i kanału mogą dodatkowo zawężać zakres pracownika.

```sh
dotnet user-jwts create --project Loans --name branch-operator --claim token_type=employee --role operator --claim branch_id=33333333-3333-3333-3333-333333333333 --valid-for 1h
```

| Rola pracownika | Odczyt | Edycja | Tworzenie | Wysłanie |
| --- | --- | --- | --- | --- |
| `seller` | Własny oddział, kanał branch | 403 | 403 | 403 |
| `operator` | Własny oddział, kanał branch | Szkice w swoim oddziale, kanał branch | 403 | 403 |
| `branch_advisor` | Własny oddział, kanał branch | 403 | Własny oddział, kanał branch | Własny oddział, kanał branch |

Pracownik oddziału ma rolę `branch_advisor`. Może tworzyć wnioski w imieniu dowolnego klienta i wysyłać szkice, ale tylko w swoim oddziale i kanale `branch`. POST wymaga jawnych `channel: "branch"` i `branchId` zgodnego z claimem `branch_id`. Jawne wskazanie kanału cyfrowego/sklepowego lub innego oddziału daje **403**. Próba odczytu lub wysłania istniejącego wniosku spoza tego zakresu daje **403**. Sam `branch_advisor` nie daje prawa do edycji; można połączyć go z `operator`. Rola pracownika oddziału nie oznacza dostępu backoffice do wszystkich kanałów.

```sh
dotnet user-jwts create --project Loans --name branch-advisor --claim token_type=employee --role branch_advisor --claim branch_id=33333333-3333-3333-3333-333333333333 --valid-for 1h
```

Uprawnienia ról pracowniczych sumują się, zachowując filtr własnego oddziału i kanału `branch`. Scope techniczne w tokenie pracownika nie rozszerzają tych uprawnień.

Każda operacja ma osobną politykę API. Techniczne `loans.write` zachowuje uprawnienia do tworzenia, edycji i wysłania; role pracownicze są sprawdzane osobno.

Ograniczenie technicznego tokenu sklepu składa się z `scope=loans.read`, `allowed_product=retail-loan`, `allowed_channel=store`. Oba filtry działają łącznie. To osobny token od sprzedawcy oddziałowego. `allowed_channel` może wystąpić wielokrotnie; brak zachowuje dotychczasowy dostęp do wszystkich kanałów dla uprawnionych tokenów. Nieprawidłowy kanał daje **403**.

Migracja `AddLoanOrigin` dodaje nullable pola kanału i oddziału. Stare wnioski mają nieznane pochodzenie i nie będą widoczne dla sprzedawcy ani tokenu sklepu do czasu poprawnego przypisania ich pochodzenia. Nie przypisujemy im automatycznie oddziału ani kanału.

## Zewnętrzny dostawca

Poza Development aplikacja wymaga konfiguracji dostawcy:

```text
Authentication__Schemes__Bearer__Authority=https://identity.example.com/realms/authdemo
Authentication__Schemes__Bearer__Audience=loans-api
```

Dostawca musi udostępniać metadane OIDC i klucze podpisujące przez HTTPS oraz nadawać zaufane claimy `client_id` dla klientów lub `token_type=technical`, `scope` i opcjonalne `allowed_product` / `allowed_channel` dla integracji; dla pracownika `token_type=employee`, role oraz `branch_id` albo `employee_id` używane przez resolver oddziału. Użytkownik nie może sam nadawać sobie tych claimów. Produkcja nie korzysta z lokalnych kluczy `user-jwts`.

Konfiguracja JWT korzysta z mechanizmów ASP.NET Core: [walidacja JWT](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/configure-jwt-bearer-authentication?view=aspnetcore-10.0) oraz [lokalne tokeny user-jwts](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/jwt-authn?view=aspnetcore-10.0).

## Testy

```sh
dotnet test AuthDemo.slnx
```

Testy używają rzeczywistej walidacji podpisanych JWT i izolowanej bazy InMemory; nie wymagają Postgresa ani działającego Aspire.

Autoryzacja operacji korzysta z [polityk ASP.NET Core](https://learn.microsoft.com/en-us/aspnet/core/security/authorization/policies?view=aspnetcore-10.0).

## Normalizacja ról z tokena

Po walidacji JWT `ConfiguredClaimsTransformation<LoanGrantOptions>` implementujący `IClaimsTransformation` mapuje zewnętrzne claimy na wewnętrzny `app_role`. Transformacja kopiuje tożsamości, zachowuje oryginalny principal i jest idempotentna. Polityki korzystają wyłącznie z tej roli. Konfiguracja `Authorization:RoleMappings` zawiera wpisy `Actor`, `ClaimType`, `Value`, `Role`; domyślnie rozpoznaje `seller`, `operator`, `branch_advisor` i `analyst` w `role`, `roles` oraz `scope`. `scope` obsługuje wartości oddzielone spacjami i powtarzane claimy; dopasowanie jest dokładne i uwzględnia wielkość liter. Tablice JWT `roles` są odczytywane jako powtarzane claimy, pojedyncze `role`/`roles` nie są dzielone spacjami.

Przykład: `token_type=employee`, `scope="analyst"` mapuje się na wewnętrzną rolę `analyst`. Ta osobna rola nie ma jeszcze przypisanych operacji, więc zwraca **403**. Jeżeli analityk ma mieć dokładnie uprawnienia operatora, można świadomie zmienić wpis na:

```json
{ "Actor": "employee", "ClaimType": "scope", "Value": "analyst", "Role": "operator" }
```

Wtedy obowiązują wszystkie ograniczenia operatora, w tym własny oddział i wymagany `branch_id`. Każde mapowanie dotyczy wyłącznie wskazanego `Actor` (`client`, `employee`, `technical`); nie zmienia typu aktora. Domyślne mapowania ról pracowniczych są ograniczone do `employee`. Scope techniczne `loans.read` / `loans.write` zachowują dotychczasowe znaczenie tylko dla tokenów technicznych. Nieznane wartości nie nadają ról. Wszystkie wewnętrzne claimy `app_*` dostarczone w tokenie są usuwane z kopii principalu, a `app_role` jest wyliczany ponownie przez API. Zmiana mapowania wymaga restartu aplikacji.

Obsługa ról używa [RoleClaimType i ról ASP.NET Core](https://learn.microsoft.com/en-us/aspnet/core/security/authorization/roles?view=aspnetcore-10.0).

## Organizacja operacji na wnioskach

Serwisy i wyniki operacji znajdują się w `Loans/Features/LoanApplications`:

- Każda operacja ma osobną klasę z metodą `HandleAsync`: `ListLoanApplications`, `GetLoanApplication`, `CreateLoanApplication`, `UpdateLoanApplication`, `SubmitLoanApplication`. Klasy sprawdzają uprawnienia przez `IAuthorizationService`, walidują żądania i obsługują operacje biznesowe.
- Operacje na pojedynczym wniosku korzystają z `LoansDbContext`; lista używa `LoanApplicationReader`, który ogranicza zapytanie w bazie przed paginacją. Reguły stanu i niezmiennych pól pozostają przy zapisie wniosku.
- `LoanApplicationResult<T>` to natywny union C# 15 dla operacji zwracających dane. `Update` i `Submit` używają `LoanApplicationMutationResult`; po sukcesie zwracają `204 No Content`. `LoanApplicationHttpResults` mapuje wyniki na odpowiedzi API.

Endpointy wstrzykują klasy operacji i mapują wynik na HTTP. `Get`, `Update` i `Submit` pobierają encję i tworzą z niej `LoanApplicationResource`: niemutowalny rekord z `ClientId`, `BranchId`, `Product` i `Channel`. Tylko ten dedykowany zasób trafia do `IAuthorizationService.AuthorizeAsync` z `PermissionRequirement`. Pełna encja i request nie są zarejestrowanymi zasobami autoryzacji. Brak dostępu do istniejącego wniosku zwraca `403`, również przy bezpośrednim wywołaniu operacji. `Update` autoryzuje zapisane dane przed walidacją i zmianą pól; dane przesłane przez użytkownika nie decydują o dostępie do istniejącego wniosku.

`Create` wymaga jawnego kanału (oraz `branchId` dla kanału `branch`), waliduje żądanie i autoryzuje `LoanApplicationResource.From(request)` bez przygotowywania wartości domyślnych. Zakresy są zadeklarowane raz w `LoanAuthorizationRegistration`; produkty i kanały sprawdza `LoanGrantConditions`.

Polityki endpointów używają `PermissionPresenceRequirement` jako wstępnego sprawdzenia operacji (`403` przy braku nadania). Nie zastępuje ono autoryzacji konkretnego zasobu. `PermissionRequirement` z pustym lub niezarejestrowanym zasobem odmawia dostępu. Lista korzysta z `LoanQueryAuthorization`, który pobiera z biblioteki te same ograniczenia `LoanAccess`, których używa autoryzacja pojedynczego zasobu. `LoanApplicationReader` nakłada ograniczenia oraz filtry użytkownika w bazie przed `Skip`/`Take`; nie pobiera całej kolekcji do autoryzacji w pamięci.

Mechanizm korzysta z [autoryzacji zasobów ASP.NET Core](https://learn.microsoft.com/en-us/aspnet/core/security/authorization/resource-based?view=aspnetcore-10.0).

## Konfigurowalne nadania uprawnień

Cała konfiguracja jest w `Loans/appsettings.json`, sekcja `Authorization`:

- `ActorRoles`: role nadawane każdemu uwierzytelnionemu aktorowi danego typu; domyślnie klient otrzymuje rolę `client`.
- `RoleMappings`: mapowanie claimu dla wskazanego aktora na rolę. Obsługuje również własne claimy, np. `service_id`. Claim `scope` jest dzielony spacjami, pozostałe są dopasowywane dokładnie.
- `Roles`: dowolne nazwy ról i ich `Services:loans:Grants`. Nowa rola nie wymaga dodania stałej w kodzie.
- Każde nadanie zawiera `Permissions` oraz `Scope`; opcjonalnie `Products` i `Channels`.

Wewnętrzne uprawnienia to `loans.read`, `loans.create`, `loans.edit`, `loans.submit`. Zewnętrzne `scope=loans.write` jest domyślnie mapowane dla aktora `technical` na rolę `technical_writer`, która nadaje trzy uprawnienia zapisu.

| Zakres | Wymagana tożsamość | Ograniczenie zasobów |
| --- | --- | --- |
| `Own` | Jeden poprawny `client_id` | Właściciel wniosku zgodny z `client_id` |
| `OwnBranch` | Jeden poprawny `branch_id` lub `employee_id` i zarejestrowany `IEmployeeBranchResolver` | Własny oddział oraz kanał `branch` |
| `All` | Uwierzytelniony aktor | Bez ograniczenia właściciela/oddziału; pozostałe filtry nadal obowiązują |

Brak wymaganego identyfikatora wyłącza dane nadanie, zamiast rozszerzać je na wszystkie zasoby. Wewnątrz jednego nadania warunki łączą się przez AND; całe nadania dla danej operacji łączą się przez OR. Podpisane ograniczenia `allowed_product` i `allowed_channel` dodatkowo przecinają każde nadanie. Pominięty filtr oznacza brak ograniczenia, pusta tablica oznacza brak dostępu w ramach nadania. Listy korzystają z zakresów odczytu `All`, `Own` i `OwnBranch`; ograniczenia produktów i kanałów oraz ustalanie oddziału są współdzielone z autoryzacją pojedynczego zasobu. Resolver oddziału jest opcjonalny: aby obsłużyć tokeny z samym `employee_id`, zaimplementuj `IEmployeeBranchResolver.ResolveAsync(string employeeId, CancellationToken)` i zarejestruj go w `Program.cs` przez `builder.Services.AddScoped<IEmployeeBranchResolver, MyEmployeeBranchResolver>()`. Może używać bazy lub API pracowników; wynik jest zapamiętywany na czas jednego zakresu DI, więc kolejne granty nie odpytują źródła ponownie.

Przykład roli z odczytem wszystkich wniosków i edycją tylko własnego oddziału (fragment do dodania pod `Roles`):

```json
"reviewer": {
  "Services": {
    "loans": {
      "Grants": [
        { "Permissions": ["loans.read"], "Scope": "All" },
        { "Permissions": ["loans.edit"], "Scope": "OwnBranch" }
      ]
    }
  }
}
```

Mapowanie pod `RoleMappings`:

```json
{ "Actor": "employee", "ClaimType": "scope", "Value": "review", "Role": "reviewer" }
```

Przykład nadania serwisu sklepu:

```json
{
  "Permissions": ["loans.read"],
  "Scope": "All",
  "Products": ["retail-loan"],
  "Channels": ["store"]
}
```

Taką rolę można przypisać mapowaniem `Actor=technical`, `ClaimType=service_id`, `Value=retail-store`. Role nadają dostęp addytywnie: ta ograniczona rola nie zawęża osobnej, szerszej roli `technical_reader`, jeśli token ma także `scope=loans.read`. Dla ograniczonego serwisu wystawiaj token pasujący do właściwego mapowania; ewentualne ograniczenia w podpisanych `allowed_product` i `allowed_channel` zawężają wszystkie jego role.

Przy tworzeniu klient podaje kanał jawnie. Dla `branch` podaje też oddział zgodny z uprawnieniem. Edycja nie zmienia pochodzenia istniejącego wniosku.

Konfiguracja używa typowanych `IOptions<AuthorizationOptions<LoanGrantOptions>>` i `ValidateOnStart()`. Nieznana operacja, zakres, rola w mapowaniu, aktor, błędny produkt/kanał lub nieznane pole konfiguracji zatrzymują start aplikacji. Konfiguracja obowiązuje do restartu procesu; nie jest przeładowywana w trakcie żądania.

Nowe role i nowe kombinacje istniejących uprawnień, produktów, kanałów i zakresów wymagają tylko konfiguracji. Nowy typ zakresu wymaga deklaracji dla zasobów w `LoanAuthorizationRegistration`. Nowa operacja biznesowa wymaga własnej klasy operacji i uprawnienia. Reguły stanu wniosku (np. edycja tylko szkicu) pozostają w kodzie domenowym.

## Biblioteka autoryzacji

`ConfigurableAuthorization` jest osobnym projektem ASP.NET Core, niezależnym od modeli biznesowych, Entity Framework i sposobu walidowania JWT. Zawiera mapowanie claimów, konfigurację i jej walidację, rozwiązywanie uprawnień oraz `AuthorizationHandler`. Instrukcja użycia i punkty rozszerzeń są w [ConfigurableAuthorization/README.md](ConfigurableAuthorization/README.md).

`Loans` deklaruje dedykowany `LoanApplicationResource` w `LoanAuthorizationRegistration`, rejestrując `LoanAccess` dla zakresów `All`, `Own` i `OwnBranch`. Ten sam dostęp sprawdza pojedynczy zasób i ogranicza listę. `LoanGrantOptions` opisuje konfigurację domenową, a `LoanGrantConditions` zawęża dostęp według produktów i kanałów. Konfiguracja ról ma teraz strukturę `Roles → nazwa roli → Services → loans → Grants`; wspólne mapowania mogą być używane przez kilka serwisów. Paczka dostarcza też prosty helper `ResourceAuthorization<TGrant>.FilterAsync` dla załadowanych kolekcji.

### Wyszukiwanie w dozwolonym zakresie

`GET /loan-applications/?clientId=...&product=retail-loan&branchId=...&channel=branch&skip=0&take=20`

Wszystkie filtry są opcjonalne. Brak `clientId` oznacza wyszukiwanie w dozwolonym zakresie (np. własne wnioski klienta). Jawny filtr lub kombinacja filtrów sprzeczna ze wszystkimi dostępnymi grantami daje **403**. Parametry nie są nadpisywane. Dozwolone wyszukiwanie bez pasujących rekordów daje **200** i pustą listę; niepoprawny format parametru daje **400**. Użytkownik z dostępem oddziałowym może podać dowolny `clientId`, ale otrzyma wyłącznie jego wnioski w swoim oddziale.

`LoanQueryAuthorization.AuthorizeAsync(user, query, cancellationToken)` zwraca `AuthorizedLoanQuery` albo `null` oznaczający odmowę. Zapytanie zawiera filtry użytkownika oraz alternatywy `LoanAccess`: wewnątrz jednej alternatywy obowiązuje AND, między alternatywami OR. `null` w ograniczeniu oznacza brak ograniczenia danego pola, a pusta tablica produktów/kanałów oznacza brak dostępu. Zakres `All` nadal podlega ograniczeniom produktów i kanałów.

`LoanApplicationReader` przyjmuje wyłącznie `AuthorizedLoanQuery`. To jedyne miejsce tłumaczące ograniczenia na EF Core; inny czytnik może zastosować je w SQL lub zewnętrznym API, przed paginacją i liczeniem wyników. Samo przekazanie parametrów do zewnętrznego API nie wystarcza, jeśli API nie potrafi wymusić całego zakresu. Paczka `ConfigurableAuthorization` pozostaje niezależna od warstwy danych.

#### Własny zakres dla zasobu i listy

Nowy zakres zwraca `LoanAccess`. Ta jedna wartość służy do sprawdzenia zasobu przez `Allows(resource)` i do filtrowania w czytniku. Jeśli ustalenie zakresu wymaga DI lub operacji asynchronicznej, implementuj `IResourceAccessScope<LoanAccess>` i zarejestruj go w `LoanAuthorizationRegistration`:

```csharp
.Access<LoanAccess>()
.Scope<MyLoanScope>("MyScope")
.Constrain(LoanGrantConditions.Constrain);
```

Biblioteka rejestruje `MyLoanScope` jako scoped. `ResolveAsync(user, cancellationToken)` zwraca `LoanAccess` albo `null` przy odmowie. Produkty i kanały grantu oraz claimów zawęża `Constrain` dla każdej alternatywy osobno. `LoanQueryAuthorization` pobiera gotowe alternatywy przez `ResourceAuthorization<LoanGrantOptions>.ResolveAccessAsync<LoanApplicationResource, LoanAccess>(...)`.

Jeżeli zakres wymaga nowych pól, rozszerz `LoanAccess.Allows`, jego tłumaczenie w `LoanApplicationReader` oraz testy zgodności. Dowolnej funkcji sprawdzającej zasób nie da się automatycznie przetłumaczyć na zapytanie do bazy.

Test tłumaczenia zapytań na PostgreSQL działa bez bazy. Test wykonania można włączyć, ustawiając `LOANS_TEST_POSTGRES` na connection string do testowego PostgreSQL przed `dotnet test`. Korzysta z tabeli tymczasowej w transakcji, bez migracji ani usuwania danych.

### Przykład integracji: serwis Disbursement

Poniższy przykład pokazuje konfigurację nowego serwisu korzystającego z paczki; nie jest implementacją Disbursement w tym repozytorium. Serwis A zleca automatyczne uruchomienie, serwis B odczytuje historię po `clientId`, a pracownik o znanym XNUC i nadanej roli pobiera uruchomienie i może je ponowić. Klient nie otrzymuje dostępu. Każda operacja ma osobne uprawnienie:

| Operacja | Uprawnienie | Aktor |
| --- | --- | --- |
| Zlecenie automatycznego uruchomienia | `disbursements.request` | serwis A |
| Ponowienie | `disbursements.retry` | uprawniony pracownik |
| Pobranie po ID | `disbursements.read` | uprawniony pracownik |
| Historia po wymaganym `clientId` | `disbursements.search-by-client` | serwis B |

Najpierw Disbursement musi uwierzytelniać tokeny: walidować podpis, wystawcę, odbiorcę i czas ważności. Musi też rozpoznać token techniczny lub pracowniczy oraz zaufany identyfikator aplikacji wywołującej. W przykładzie są to `token_type` i `azp`; rzeczywiste claimy oraz sposób odróżnienia tokenu usługi od tokenu użytkownika zależą od dostawcy tożsamości. `clientId` w URL oznacza klienta biznesowego, a nie identyfikator wywołującej aplikacji.

Przykładowe zasoby to trzy zwykłe rekordy. Dwa pierwsze mogą później zyskać pola potrzebne do bardziej szczegółowych reguł:

```csharp
public sealed record DisbursementRequestResource(Guid ClientId, Guid LoanId);
public sealed record DisbursementResource(Guid Id, Guid ClientId);
public sealed record DisbursementsByClientResource(Guid ClientId);

services.AddCreditAuthroization(options =>
{
    options.Service("disbursements");
    options.Definition.ActorClaimType = "token_type";
    options.Definition.ActorTypes.UnionWith(["technical", "employee"]);
    // Bez DefaultActor: brak albo wielokrotność typu aktora odmawia dostępu.

    options.Resource<DisbursementRequestResource>()
        .Permissions("disbursements.request").AllowAll();
    options.Resource<DisbursementResource>()
        .Permissions("disbursements.retry", "disbursements.read").AllowAll();
    options.Resource<DisbursementsByClientResource>()
        .Permissions("disbursements.search-by-client").AllowAll();
});
services.AddAuthorization();
```

`All` nie przyznaje uprawnienia każdemu użytkownikowi. Oznacza brak dodatkowego ograniczenia pól zasobu dla aktora, który otrzymał już właściwy grant. W tym przykładzie pracownik z rolą może odczytać i ponowić **każde** uruchomienie. Jeżeli obowiązuje ograniczenie do przydzielonych spraw, oddziału lub zespołu, należy dodać własny scope sprawdzający to na `DisbursementResource` i nadać pracownikowi ten scope zamiast `All`. Stan pozwalający na ponowienie, idempotencja i audyt są odrębnymi regułami serwisu Disbursement.

W `Authorization:RoleMappings` dodaj mapowania aktorów na role aplikacji. Wartości `service-a`, `service-b` i `retry_operator` są tylko przykładami:

```json
[
  { "Actor": "technical", "ClaimType": "azp", "Value": "service-a", "Role": "disbursement_initiator" },
  { "Actor": "technical", "ClaimType": "azp", "Value": "service-b", "Role": "disbursement_history_reader" },
  { "Actor": "employee", "ClaimType": "verified_disbursement_role", "Value": "retry_operator", "Role": "disbursement_operator" }
]
```

W `Authorization:Roles` dodaj granty pod `Services:disbursements`:

```json
{
  "disbursement_initiator": { "Services": { "disbursements": { "Grants": [
    { "Permissions": ["disbursements.request"], "Scope": "All" }
  ] } } },
  "disbursement_history_reader": { "Services": { "disbursements": { "Grants": [
    { "Permissions": ["disbursements.search-by-client"], "Scope": "All" }
  ] } } },
  "disbursement_operator": { "Services": { "disbursements": { "Grants": [
    { "Permissions": ["disbursements.retry", "disbursements.read"], "Scope": "All" }
  ] } } }
}
```

XNUC identyfikuje pracownika, lecz sam nie nadaje roli. Jeśli rola pochodzi z zaufanego tokenu, mapowanie może wskazywać jej claim. Jeśli pochodzi z bazy lub API, po walidacji tokenu odczytaj ją po XNUC i dodaj własny claim `verified_disbursement_role=retry_operator` **przed** autoryzacją. Usuń przychodzący claim o tej nazwie, zanim dodasz wartość z Waszego źródła; przy braku XNUC, roli lub przy błędzie lookupu nie dodawaj jej. Przykładowym miejscem tej operacji jest `JwtBearerEvents.OnTokenValidated`. Paczka sama nie wykonuje lookupu ról. Jej `IClaimsTransformation` tworzy wewnętrzne `app_role` z dostarczonych, zaufanych claimów; przychodzącemu `app_role` nie ufa.

W handlerach użyj `IAuthorizationService` z `PermissionRequirement`. Dla ponowienia i pobrania po ID najpierw załaduj rekord i zbuduj `DisbursementResource` z zapisanych danych. Dla zlecenia najpierw zwaliduj żądanie i zbuduj `DisbursementRequestResource`. Dla historii wymagaj poprawnego `clientId`, autoryzuj `DisbursementsByClientResource(clientId)`, a dopiero potem pytaj źródło danych o rekordy z tym `clientId`:

```csharp
var resource = new DisbursementsByClientResource(clientId);
var authorization = await authorizationService.AuthorizeAsync(user, resource,
    [new PermissionRequirement("disbursements.search-by-client")]);
if (!authorization.Succeeded) return Results.Forbid();

var history = await repository.GetByClientIdAsync(clientId, cancellationToken);
return Results.Ok(history);
```

Zarejestruj również polityki endpointów z `PermissionPresenceRequirement` jako wstępne sprawdzenie oraz `UseAuthentication()` przed `UseAuthorization()`. Kontrolę konkretnego zasobu wykonuj zawsze w handlerze. Wyszukiwanie po wymaganym `clientId` dostępne tylko dla serwisu B nie potrzebuje zakresu odczytu z Loans; gdyby lista miała być dostępna pracownikom z ograniczeniami danych, czytnik musi nałożyć te ograniczenia przed paginacją.

Przed uruchomieniem sprawdź cztery przypadki: A może tylko zlecić, B może tylko wyszukiwać, pracownik z rolą może pobierać i ponawiać, a pracownik bez roli i klient dostają `403`. Przy współdzielonym `Authorization` pamiętaj, że `Services:disbursements` izoluje granty, lecz `RoleMappings` i `ActorRoles` są wspólne i walidowane w każdym serwisie. Jeśli zestawy aktorów się różnią, użyj osobnej sekcji konfiguracji przekazanej do `AddCreditAuthroization(..., configurationSection: "DisbursementAuthorization")`.

`ConfigurableAuthorization.Tests` odwołuje się wyłącznie do biblioteki i testuje osobny przykład dokumentów: własne typy aktorów, claimy, uprawnienia, zakres zespołu i klasyfikację dokumentów.

Projekt `Loans` używa natywnego `union` w C# 15 i ma ustawione `LangVersion=preview`. Do kompilacji jest potrzebny zestaw SDK .NET 11 obsługujący unie (Preview 5 lub nowszy).
