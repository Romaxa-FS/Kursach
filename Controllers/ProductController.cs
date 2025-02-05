using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using MyWeb2.Models;
using MyWeb2.Data;
using Microsoft.EntityFrameworkCore; 
using System.Threading.Tasks;

namespace MyWeb2.Controllers
{
    public class ProductController : Controller
    {
        private readonly ApplicationDbContext _context;

        public ProductController(ApplicationDbContext context)
        {
            _context = context; 
        }
        
    public async Task<IActionResult> NewArrivals()
    {
        
        var newProducts = await _context.Products
            .OrderByDescending(p => p.Id) 
            .Take(3)
            .ToListAsync();

        return View(newProducts); 
    }
    public async Task<IActionResult> Catalog(string sortBy, string searchTerm)
{
   
    ViewData["SearchTerm"] = searchTerm;


    var products = await _context.Products.ToListAsync(); 


    if (!string.IsNullOrEmpty(searchTerm))
    {
        products = products.Where(p => p.Title.Contains(searchTerm) || p.Description.Contains(searchTerm)).ToList();
    }


    switch (sortBy)
    {
        case "price_asc":
            products = products.OrderBy(p => p.Price).ToList(); 
            break;
        case "price_desc":
            products = products.OrderByDescending(p => p.Price).ToList(); 
            break;
        case "title":
            products = products.OrderBy(p => p.Title).ToList(); 
            break;
        default:
            products = products.OrderBy(p => p.Title).ToList(); 
            break;
    }

   
    return View(products);
}



        public async Task<IActionResult> Details(int id)
        {
            
            var product = await _context.Products.FindAsync(id);
            if (product == null)
            {
                return NotFound(); 
            }
            return View(product); 
        }
    }
}
