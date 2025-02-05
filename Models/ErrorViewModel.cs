using System.ComponentModel.DataAnnotations;
namespace MyWeb2.Models;
using Microsoft.AspNetCore.Http;
using MyWeb2.Attributes;
sealed class ErrorViewModelAttribute : System.Attribute
{
    
    readonly string positionalString;
    
    public ErrorViewModelAttribute(string positionalString)
    {
        this.positionalString = positionalString;
    
        throw new System.NotImplementedException();
    }
    
    public string PositionalString
    {
        get { return positionalString; }
    }

    public int NamedInt { get; set; }
}

public class Cart
{
    public List<CartItem> Items { get; set; } = new List<CartItem>();   
  public string OrderComment { get; set; }
    public decimal Subtotal => Items.Sum(item => item.TotalPrice);
    public decimal Tax => Subtotal * 0.13m;

    public decimal DeliveryCost { get; set; } = 600; 


    public decimal TotalAmount => Subtotal + Tax + DeliveryCost;
   public string DeliveryType { get; set; }
   public void AddItem(int productId, int quantity, Product product)
{
    var existingItem = Items.FirstOrDefault(i => i.ProductId == productId);
    if (existingItem != null)
    {
        existingItem.Quantity += quantity;
    }
    else
    {
        Items.Add(new CartItem(productId, quantity, product)); 
    }
}

    public void RemoveItem(int productId)
    {
        var item = Items.FirstOrDefault(i => i.ProductId == productId);
        if (item != null)
        {
            Items.Remove(item);
        }
    }
       public void UpdateItemQuantity(int productId, int quantity)
    {
        var item = Items.FirstOrDefault(i => i.ProductId == productId);
        if (item != null)
        {
            if (quantity > 0)
            {
                item.Quantity = quantity; 
            }
            else
            {
                Items.Remove(item); 
            }
        }
    }
   

}

public class ProfileViewModel
{
    [Required(ErrorMessage = "Name is required.")]
    public string UserName { get; set; }

    [Required(ErrorMessage = "Email is required.")]
    [EmailAddress(ErrorMessage = "Invalid email address.")]
    public string Email { get; set; }

    [DataType(DataType.Password)]
    public string? Password { get; set; }
    public string AvatarPath { get; set; }
    [AllowedExtensions(new[] { ".jpg", ".jpeg", ".png" }, ErrorMessage = "Разрешены только файлы .jpg, .jpeg, .png")]
    public IFormFile? Avatar { get; set; }
    public string DeliveryAddress { get; set; }
    [Range(0, double.MaxValue, ErrorMessage = "Balance cannot be negative.")]
    public decimal Balance { get; set; }
}
public class Wishlist
{
    public List<WishlistItem> Items { get; set; } = new List<WishlistItem>();
}

public class WishlistItem
{
    public int Id { get; set; }
    public string UserId { get; set; }
    public int ProductId { get; set; }
    public virtual Product Product { get; set; }
}
public class Order
{
    public int Id { get; set; }
    public string UserId { get; set; }
    public string Comment { get; set; }
    public DateTime OrderDate { get; set; } = DateTime.Now;
    public string Status { get; set; } = "Processing";
}
public class CartItem
{
    public int Id { get; set; }
    public string UserId { get; set; } 
    public int ProductId { get; set; }
    public int Quantity { get; set; }
    public Product Product { get; set; }
    public decimal TotalPrice => Product.Price * Quantity;
    public CartItem() {}
    public CartItem(int productId, int quantity, Product product)
    {
        ProductId = productId;
        Quantity = quantity;
        Product = product;
    }
    
}

public class Product
{
    public int Id { get; set; }
    public string Title { get; set; }
    public string Description { get; set; }
    public decimal Price { get; set; }
    public string ImagePath { get; set; }

}
public class ErrorViewModel
{
    public string? RequestId { get; set; }

    public bool ShowRequestId => !string.IsNullOrEmpty(RequestId);
}
  public class RegisterViewModel
{
    [Required(ErrorMessage = "Name is required")]
    public string? UserName { get; set; }

    [Required(ErrorMessage = "Email is required")]
    [EmailAddress(ErrorMessage = "Invalid Email Address")]
    public string? Email { get; set; }

    [Required(ErrorMessage = "Password is required")]
    [MinLength(6, ErrorMessage = "Password must be at least 6 characters long")]
    public string? Password { get; set; }

    [Required(ErrorMessage = "Please confirm your password")]
    [Compare("Password", ErrorMessage = "Passwords do not match")]
    public string? ConfirmPassword { get; set; }
}
public class User
{
    public int Id { get; set; }
    public string UserName { get; set; } 
    public string Email { get; set; }
   
}
public class LoginViewModel
{
    [Required(ErrorMessage = "Email is required")]
    [EmailAddress(ErrorMessage = "Invalid Email Address")]
    public string? Email { get; set; }

    [Required(ErrorMessage = "Password is required")]
    [DataType(DataType.Password)]
    public string? Password { get; set; }

    public bool RememberMe { get; set; }
}
public class ForgotPasswordViewModel
{
    [Required(ErrorMessage = "Поле Email обязательно.")]
    [EmailAddress(ErrorMessage = "Некорректный формат email.")]
    public string Email { get; set; }
}

public class ResetPasswordViewModel
{
    [Required]
    public string Token { get; set; }

    [Required]
    [EmailAddress]
    public string Email { get; set; }

    [Required]
    [DataType(DataType.Password)]
    [StringLength(100, ErrorMessage = "Пароль должен содержать как минимум {2} символов.", MinimumLength = 6)]
    public string Password { get; set; }

    [DataType(DataType.Password)]
    [Compare("Password", ErrorMessage = "Пароли не совпадают.")]
    public string ConfirmPassword { get; set; }
}

public class EmailSettings
{
    public string SmtpServer { get; set; }
    public int SmtpPort { get; set; }
    public string SenderName { get; set; }
    public string SenderEmail { get; set; }
    public string SenderPassword { get; set; }
}

public class RegisterModel
{
    public string? UserName { get; set; }
    public string? Email { get; set; }
    public string? Password { get; set; }
}
public class LoginModel
{
    public string? Email { get; set; }
    public string? Password { get; set; }
}