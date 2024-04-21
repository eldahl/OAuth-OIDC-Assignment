using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.IdentityModel.Tokens;
using OpenID_Client.Models;
using static System.Net.WebRequestMethods;

namespace OpenID_Client.Controllers;

public class HomeController : Controller
{
    private readonly ILogger<HomeController> _logger;

    public static Dictionary<string, string> loginCodes = new Dictionary<string, string>();

    public HomeController(ILogger<HomeController> logger)
    {
        _logger = logger;
    }

    [Route("/")]
    public IActionResult Index()
    {
        return View();
    }

    [Route("/privacy")]
    public IActionResult Privacy()
    {
        return View();
    }

    [Route("/login")]
    public IActionResult Login()
    {
        // Parameters
        string clientId = "openid_client";
        string callback = "http://172.30.96.1:5113/callback";
        string state = Microsoft.AspNetCore.Authentication.Base64UrlTextEncoder.Encode(RandomNumberGenerator.GetBytes(42));
        //                                                                                                             \---------| Padding be damned
        // Code challange                                                                                                     /--| I just want a nice power of 2 here (╯‵□′)╯︵┻━┻
        string codeVerifier = Microsoft.AspNetCore.Authentication.Base64UrlTextEncoder.Encode(RandomNumberGenerator.GetBytes(42));
        byte[] codeVerifierHashBytes = SHA256.HashData(Encoding.UTF8.GetBytes(codeVerifier));
        string codeVerifierBase64 = Microsoft.AspNetCore.Authentication.Base64UrlTextEncoder.Encode(codeVerifierHashBytes);

        Debug.WriteLine($"state: {state}");
        Debug.WriteLine($"codeVerifier: {codeVerifier}");

        var parameters = new Dictionary<string, string?>
        {
            { "client_id", clientId },
            { "scope", "openid email phone address profile" },
            { "response_type", "code" },
            { "redirect_uri", callback },
            { "prompt", "login" },
            { "state", state },
            { "code_challenge_method", "S256" },
            { "code_challenge", codeVerifierBase64 }
        };
        var authorizationUri = QueryHelpers.AddQueryString("http://172.30.97.115:8080/realms/master/protocol/openid-connect/auth", parameters);

        loginCodes.Add(state, codeVerifier);

        return Redirect(authorizationUri);
    }

    public record AuthorizationResponse(string state, string code);

    [Route("/callback")]
    public async Task<IActionResult> CallbackAsync(AuthorizationResponse query)
    {
        // Callback logic
        var (state, code) = query;

        string clientId = "openid_client";
        string redirectUri = "http://172.30.96.1:5113/callback";
        string clientSecret = "WuBl2jYgeJU4BdK4ApJbKSCNR8miD6VS";
        string codeVerifier = loginCodes[state];

        var parameters = new Dictionary<string, string?>
        {
            { "grant_type", "authorization_code" },
            { "code", code },
            { "redirect_uri", redirectUri },
            { "code_verifier", codeVerifier },
            { "client_id", clientId },
            { "client_secret", clientSecret }
        };
        var response =
            await new HttpClient().PostAsync("http://172.30.97.115:8080/realms/master/protocol/openid-connect/token", new FormUrlEncodedContent(parameters));
        var payload = await response.Content.ReadFromJsonAsync<TokenResponse>();

        Debug.WriteLine(response);
        Debug.WriteLine(response.Content);

        // Write token to console
        Debug.WriteLine(payload?.access_token);
        Debug.WriteLine(payload?.id_token);

        
        // Verify ID token
        response = await new HttpClient().GetAsync("http://172.30.97.115:8080/realms/master/protocol/openid-connect/certs");
        var keys = await response.Content.ReadAsStringAsync();
        var jwks = JsonWebKeySet.Create(keys);
        jwks.SkipUnresolvedJsonWebKeys = false;

        JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
        handler.ValidateToken(payload.id_token, new TokenValidationParameters
        {
            IssuerSigningKeys = jwks.GetSigningKeys(),
            AudienceValidator = (audiences, token, parameters) => audiences.Contains(clientId),
            ValidateIssuer = false,
        }, out SecurityToken id_token);

        
        // Use to fetch user info
        var http = new HttpClient
        {
            DefaultRequestHeaders =
            {
                Authorization = new AuthenticationHeaderValue("Bearer", payload?.access_token)
            }
        };
        
        response = await http.GetAsync("http://172.30.97.115:8080/realms/master/protocol/openid-connect/userinfo");

        Debug.WriteLine(response);
        Debug.WriteLine(response.Content);

        var content = await response.Content.ReadFromJsonAsync<object?>();

        // Store token in cookie
        var cookieOptions = new CookieOptions
        {
            HttpOnly = true,
            Secure = false,
            Expires = DateTime.UtcNow.AddDays(1)
        };

        // Set the cookie
        Response.Cookies.Append("AuthToken", payload?.access_token, cookieOptions);

        return View(content);
    }

    [Route("/authorized")]
    public async Task<IActionResult> AuthorizedPageAsync()
    {
        // Read the token from the cookie
        string token = Request.Cookies["AuthToken"];

        if (token == string.Empty || token == null) {
            return View("AuthorizedPage", "No");
        }

        // Use to fetch user info
        var http = new HttpClient
        {
            DefaultRequestHeaders =
            {
                Authorization = new AuthenticationHeaderValue("Bearer", token)
            }
        };
        var response = await http.GetAsync("http://172.30.97.115:8080/realms/master/protocol/openid-connect/userinfo");

        Debug.WriteLine(response);
        Debug.WriteLine(response.Content);

        var content = await response.Content.ReadFromJsonAsync<object?>();

        // Continue with your action logic
        return View("AuthorizedPage", "Yes");
    }

    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error()
    {
        return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
    }
}
