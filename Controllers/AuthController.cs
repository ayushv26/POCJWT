using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace JWTPOC.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : Controller
    {
        [HttpPost("token")]
        public IActionResult Index()
        {
            var header = Request.Headers["Authorization"];
            if (header.ToString().StartsWith("Basic"))
            {
                var credValue = header.ToString().Substring("Basic ".Length).Trim();
                var usernameAndPassEncode = Encoding.UTF8.GetString(Convert.FromBase64String(credValue));

                var usernameAndPass = usernameAndPassEncode.Split(":");
                if (usernameAndPass[0] == "admin" && usernameAndPass[1] == "pass")
                {
                    var claimsData = new[] { new Claim(ClaimTypes.Name, usernameAndPass[0])};
                    var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes("asdasdasdaereryodaysdgyebbegyiieeygaiduiageud"));
                    var signInCred = new SigningCredentials(key, SecurityAlgorithms.HmacSha256Signature);

                    var token = new JwtSecurityToken(
                        issuer: "mysite.com",
                        audience: "mysite.com",
                        expires: DateTime.Now.AddMinutes(1),
                        claims: claimsData,
                        signingCredentials: signInCred
                        );
                    var tokenString = new JwtSecurityTokenHandler().WriteToken(token);
                    return Ok(tokenString);
                }
            }
            return BadRequest("Bad request");
        }
    }
}