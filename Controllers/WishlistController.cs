using Microsoft.AspNetCore.Mvc;
using MyWeb2.Models;
using MyWeb2.Data;
using MyWeb2.Extensions;
using System.Collections.Generic;
using System.Linq;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using Stripe;
using Stripe.Checkout;
namespace MyWeb2.Controllers
{
[Route("wishlist")]
public class WishlistController : Controller
{
    private readonly ApplicationDbContext _context;

    public WishlistController(ApplicationDbContext context)
    {
        _context = context;
    }

   
   [HttpGet("")]
public async Task<IActionResult> Wishlist()
{
    var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
    var wishlist = new Wishlist();

    if (!string.IsNullOrEmpty(userId))
    {
       
        var wishlistItems = await _context.WishlistItems
            .Include(wi => wi.Product)
            .Where(wi => wi.UserId == userId)
            .ToListAsync();

        wishlist.Items = wishlistItems.Select(wi => new WishlistItem
        {
            ProductId = wi.ProductId,
            Product = wi.Product
        }).ToList();
    }
    else
    {
        
        wishlist = HttpContext.Session.GetObjectFromJson<Wishlist>("Wishlist") ?? new Wishlist();
    }

    return View(wishlist);
}


 [HttpPost("add-to-wishlist")]
public async Task<IActionResult> AddToWishlist(int productId)
{
    var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
    var wishlist = HttpContext.Session.GetObjectFromJson<Wishlist>("Wishlist") ?? new Wishlist();

    if (!string.IsNullOrEmpty(userId))
    {
        var wishlistItem = await _context.WishlistItems
            .FirstOrDefaultAsync(wi => wi.UserId == userId && wi.ProductId == productId);

        if (wishlistItem == null)
        {
            var product = await _context.Products.FindAsync(productId);
            if (product != null)
            {
                wishlistItem = new WishlistItem
                {
                    UserId = userId,
                    ProductId = productId,
                    Product = product
                };
                await _context.WishlistItems.AddAsync(wishlistItem);
                TempData["Message"] = "Товар успешно добавлен в список желаемого.";
            }
        }
        else
        {
            TempData["Message"] = "Этот товар уже в списке желаемого.";
        }

        await _context.SaveChangesAsync();
    }
    else
    {
        var existingItem = wishlist.Items.FirstOrDefault(i => i.ProductId == productId);
        if (existingItem == null)
        {
            var product = await _context.Products.FindAsync(productId);
            if (product != null)
            {
                wishlist.Items.Add(new WishlistItem
                {
                    ProductId = productId,
                    Product = product
                });
                TempData["Message"] = "Товар успешно добавлен в список желаемого.";
            }
        }
        else
        {
            TempData["Message"] = "Этот товар уже в списке желаемого.";
        }

        HttpContext.Session.SetObjectAsJson("Wishlist", wishlist);
    }

   return RedirectToAction("Wishlist", "Wishlist");

}
[HttpPost("remove-from-wishlist")]
public async Task<IActionResult> RemoveFromWishlist(int productId)
{
    var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
    var wishlist = HttpContext.Session.GetObjectFromJson<Wishlist>("Wishlist") ?? new Wishlist();

    if (!string.IsNullOrEmpty(userId))
    {
        
        var wishlistItem = await _context.WishlistItems
            .FirstOrDefaultAsync(wi => wi.UserId == userId && wi.ProductId == productId);

        if (wishlistItem != null)
        {
            _context.WishlistItems.Remove(wishlistItem);
            await _context.SaveChangesAsync();
            TempData["Message"] = "Товар удален из списка желаемого.";
        }
    }
    else
    {
    
        wishlist.Items = wishlist.Items
            .Where(i => i.ProductId != productId)
            .ToList();

        HttpContext.Session.SetObjectAsJson("Wishlist", wishlist);
        TempData["Message"] = "Товар удален из списка желаемого.";
    }

    return RedirectToAction("Wishlist"); 
}
}}