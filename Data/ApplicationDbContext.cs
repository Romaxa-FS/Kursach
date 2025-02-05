using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using MyWeb2.Models;


namespace MyWeb2.Data
{

   public class ApplicationDbContext : IdentityDbContext<ApplicationUser> 
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options)
    {
    }

    public DbSet<WishlistItem> WishlistItems { get; set; }
    public DbSet<Product> Products { get; set; }
    public DbSet<Order> Orders { get; set; }
    public DbSet<CartItem> CartItems { get; set; }
}

    public class ApplicationUser : IdentityUser
    {
       
      public string AvatarPath { get; set; }
    public string ProfileImagePath { get; set; }= "/Images/avatar/gojo.jpg";
        public string DeliveryAddress { get; set; } = "Unknown Address"; 
    public decimal Balance { get; set; } = 0;

    }
   
}


