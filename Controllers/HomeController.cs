using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using MyWeb2.Models;
using MyWeb2.Data;
using Microsoft.EntityFrameworkCore; 


namespace MyWeb2.Controllers
{
    public class HomeController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly ILogger<HomeController> _logger;

        public HomeController(ApplicationDbContext context, ILogger<HomeController> logger)
        {
            _context = context;
            _logger = logger;
        }

        public async Task<IActionResult> Index(string message = null)
        {
           
            var popularProducts = await _context.Products.Take(4).ToListAsync();
            ViewBag.Message = message; 
            return View(popularProducts); 
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
