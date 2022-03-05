using System;
using System.Collections.Generic;
using System.Security.Claims;

namespace IdentityAuthAPI
{
    interface IUser
    {
        public string Name { get; }
        Guid GetUserId();

        string GetUserEmail();

        bool IsAuthenticated();

        bool IsInRole(string role);

        IEnumerable<Claim> GetClaimsIdentity();
    }
}
