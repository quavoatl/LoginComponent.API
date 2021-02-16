using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace LoginComponent.API.Authentication
{
    public class LoginModel
    {

        [Required(ErrorMessage = "Username is required !")]
        public string Username { get; set; }

        [Required(ErrorMessage = "Password is required !")]
        public string Password { get; set; }

        [Required(ErrorMessage = "User type is required !")]
        public bool IsBroker { get; set; }

    }
}
