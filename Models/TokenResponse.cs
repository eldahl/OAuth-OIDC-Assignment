public class TokenResponse
{
    public string access_token { init; get; }
    public int expires_in { init; get; }
    public string id_token { init; get; }
    public string scope { init; get; }
    public string token_type { init; get; }
    public string refresh_token { init; get; }
}
