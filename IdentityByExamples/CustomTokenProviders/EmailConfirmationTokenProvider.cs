using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace IdentityByExamples.CustomTokenProviders
{
    public class EmailConfirmationTokenProvider<TUser> : DataProtectorTokenProvider<TUser> where TUser : class
    {
        public EmailConfirmationTokenProvider(IDataProtectionProvider dataProtectionProvider, IOptions<EmailConfirmationTokenProverOptions> options, ILogger<DataProtectorTokenProvider<TUser>> logger) : base(dataProtectionProvider, options, logger)
        {
        }
    }

    public class EmailConfirmationTokenProverOptions : DataProtectionTokenProviderOptions
    {
    }
}