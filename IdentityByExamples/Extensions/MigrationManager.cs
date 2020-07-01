using IdentityByExamples.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System;

namespace IdentityByExamples.Extensions
{
    public static class MigrationManager
    {
        public static IHost MigrateDatabase(this IHost webHost)
        {
            using var scope = webHost.Services.CreateScope();
            using var appContext = scope.ServiceProvider.GetRequiredService<ApplicationContext>();
            appContext.Database.Migrate();

            return webHost;
        }
    }
}