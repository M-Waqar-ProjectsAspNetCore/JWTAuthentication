using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JWTAuthentication.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LoginController : Controller
    {
        private IConfiguration _config;

        public LoginController(IConfiguration config)
        {
            _config = config;
        }
        [AllowAnonymous]
        [HttpPost]
        public IActionResult Login([FromBody]UserModel login)
        {
            IActionResult response = Unauthorized();
            var user = AuthenticateUser(login);

            if (user != null)
            {
                var tokenString = GenerateJSONWebToken(user);
                response = Ok(new { token = tokenString });
            }

            return response;
        }

        private readonly List<string> Roles = new List<string>
        {
            "ADMIN", "USER1", "USER2", "USER3", "SUPERADMIN"
        };

        private string GenerateJSONWebToken(UserModel userInfo)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new List<Claim>();
            claims.Add(new Claim(JwtRegisteredClaimNames.Sub, userInfo.Username));
            claims.Add(new Claim(JwtRegisteredClaimNames.Email, userInfo.EmailAddress));
            claims.Add(new Claim("DateOfJoing", userInfo.DateOfJoing.ToString("yyyy-MM-dd")));
            claims.Add(new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()));
            // Add roles as multiple claims
            foreach (string role in Roles)
            {
                claims.Add(new Claim("Role", role));
            }

            var token = new JwtSecurityToken(_config["Jwt:Issuer"],
                _config["Jwt:Issuer"],
                claims,
                expires: DateTime.Now.AddMinutes(120),
                signingCredentials: credentials);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private UserModel AuthenticateUser(UserModel login)
        {
            UserModel user = null;

            //Validate the User Credentials, Demo Purpose, I have Passed HardCoded User Information
            if (login.Username == "Jignesh")
            {
                user = new UserModel { Username = "Jignesh Trivedi", EmailAddress = "test.btest@gmail.com", DateOfJoing = new DateTime(2010, 08, 02) };
            }
            return user;
        }
    }
}
