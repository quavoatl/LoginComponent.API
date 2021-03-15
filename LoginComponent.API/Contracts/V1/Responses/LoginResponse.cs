using System.Collections;
using System.Collections.Generic;

namespace LoginComponent.API.Contracts.V1.Responses
{
    public class LoginResponse
    {
        public IEnumerable<string> Messages { get; set; }
        public bool Success { get; set; }
    }
}