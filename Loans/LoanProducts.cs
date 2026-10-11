namespace Loans;

public static class LoanProducts
{
    public const string RetailLoan = "retail-loan";

    public static bool IsValidCode(string value) => value.Length is > 0 and <= 64
        && value[0] is >= 'a' and <= 'z'
        && value.All(character => character is >= 'a' and <= 'z' or >= '0' and <= '9' or '-');
}

public static class LoanChannels
{
    public const string Branch = "branch";
    public const string Digital = "digital";
    public const string Store = "store";

    public static bool IsValid(string value) => value is Branch or Digital or Store;
}
