# AuthDemo — autoryzacja light

Loans używa biblioteki `LightAuthorization`. Sekcja `Authorization:RoleMappings` mapuje claimy zweryfikowanego JWT na role. Sekcja `Authorization:Roles` przypisuje rolom uprawnienia i nazwy zakresów, bez obiektów `Grants`. Zakresy `Own` i `All` tworzą typowany `LoanAccess`, używany zarówno przez handler ASP.NET Core, jak i filtr listy przed paginacją. API biblioteki opisuje [LightAuthorization/README.md](LightAuthorization/README.md).

| Token | Odczyt | Tworzenie, edycja i wysłanie |
| --- | --- | --- |
| Klient z pojedynczym poprawnym `client_id` | Własne wnioski | Własne wnioski |
| `token_type=technical`, `scope=loans.read` | Wszystkie wnioski | 403 |
| `token_type=technical`, `scope=loans.write` | 403 | Wszystkie wnioski |

Scope `loans.read` i `loans.write` mogą występować jako powtarzane claimy albo wartości oddzielone spacjami. Brak `token_type` lub `token_type=client` oznacza klienta. Nieznany lub wielokrotny `token_type` nie daje dostępu. Scope techniczny w tokenie klienta nie nadaje praw serwisu. Własne mapowania można dodać w `RoleMappings`, a przypisanie uprawnień zmienić w `Roles`. Role pracownicze oraz claimy `allowed_product` i `allowed_channel` nie są używane przez wersję light.

Brak albo niepoprawny token daje **401**; brak uprawnienia do operacji lub istniejącego wniosku daje **403**. Nieistniejący wniosek zwraca **404**, jeśli token ma uprawnienie do operacji. Lista klienta jest ograniczana w SQL do jego `client_id` przed stronicowaniem. Filtry `product`, `channel` i `branchId` są zwykłymi filtrami zapytania.

## Lokalny token

W środowisku Development można utworzyć token klienta:

```sh
dotnet user-jwts create --project Loans --name demo-client --claim client_id=11111111-1111-1111-1111-111111111111 --valid-for 1h
```

Token serwisu z odczytem i zapisem:

```sh
dotnet user-jwts create --project Loans --name loans-service --claim token_type=technical --scope loans.read --scope loans.write --valid-for 1h
```

Po wygenerowaniu pierwszego tokenu uruchom ponownie Loans, jeśli aplikacja już działa. W Swagger UI wklej sam token w oknie **Authorize**. Produkcja nadal wymaga standardowej konfiguracji `Authentication:Schemes:Bearer:Authority` i `Audience` dla dostawcy JWT przez HTTPS.

Biblioteka `ConfigurableAuthorization` pozostaje w rozwiązaniu jako osobny, rozbudowany wariant. Jej dokumentacja znajduje się w `ConfigurableAuthorization/README.md`.
