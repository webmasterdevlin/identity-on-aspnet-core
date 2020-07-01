using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using IdentityByExamples.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;

namespace IdentityByExamples.Controllers
{
    public class HomeController : Controller
    {
        private readonly ApplicationContext _context;

        public HomeController(ApplicationContext context) => _context = context;

        public IActionResult Index() => View();

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error() => View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });

        [Authorize]
        public async Task<IActionResult> Employees()
        {
            var employees = await _context.Employees.ToListAsync();
            return View(employees);
        }
    }
}