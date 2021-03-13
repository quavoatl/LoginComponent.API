using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace LoginComponent.API.Authentication
{
    public class Response
    {
        public string Status { get; set; }
        public IEnumerable<string> Errors { get; set; }
    }
}