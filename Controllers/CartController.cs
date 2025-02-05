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
using System.Text.Json;
using MimeKit;
using MailKit.Net.Smtp;
namespace MyWeb2.Controllers
{
    [Route("checkout")]
    public class CheckoutController : Controller
    {
        private readonly IConfiguration _configuration;
        private readonly ApplicationDbContext _context;
        private readonly ILogger<AccountController> _logger;

        public CheckoutController(IConfiguration configuration, ApplicationDbContext context, ILogger<AccountController> logger)
        {
            _configuration = configuration;
            _context = context;
             _logger = logger;
        }

                    [HttpPost("create-checkout-session")]
            public async Task<IActionResult> CreateCheckoutSession()
            {
                StripeConfiguration.ApiKey = _configuration["Stripe:SecretKey"];
                
                var options = new SessionCreateOptions
                {
                    PaymentMethodTypes = new List<string> { "card" },
                    LineItems = new List<SessionLineItemOptions> {
                        new SessionLineItemOptions {
                            PriceData = new SessionLineItemPriceDataOptions {
                                Currency = "usd",
                                ProductData = new SessionLineItemPriceDataProductDataOptions {
                                    Name = "Product Name",
                                },
                                UnitAmount = 2000, 
                            },
                            Quantity = 1,
                        },
                    },
                    Mode = "payment",
                    SuccessUrl = Url.Action("Success", "Checkout", null, Request.Scheme),
                    CancelUrl = Url.Action("Cancel", "Checkout", null, Request.Scheme),
                };

                var service = new SessionService();
                Session session = service.Create(options);

               
                var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
                if (!string.IsNullOrEmpty(userId))
                {
                    var cartItems = await _context.CartItems
                        .Where(ci => ci.UserId == userId)
                        .ToListAsync();

                    _context.CartItems.RemoveRange(cartItems);
                    await _context.SaveChangesAsync();
                }
                else
                {
                   
                    HttpContext.Session.Remove("Cart");
                }

                return Json(new { id = session.Id });
            }
[HttpPost("checkout")]
public IActionResult Checkout([FromBody] JsonElement data)
{
    try
    {
        _logger.LogInformation("Получен запрос на оформление заказа: " + data.ToString()); 

        if (!data.TryGetProperty("totalAmount", out JsonElement totalAmountElement) || 
            !decimal.TryParse(totalAmountElement.ToString(), out decimal totalAmount) || 
            totalAmount <= 0)
        {
            _logger.LogWarning("Некорректная сумма оплаты"); 
            return Json(new { success = false, message = "Некорректная сумма оплаты" });
        }

      
        if (!data.TryGetProperty("paymentMethod", out JsonElement paymentMethodElement))
        {
            return Json(new { success = false, message = "Не выбран способ оплаты" });
        }

        string paymentMethod = paymentMethodElement.GetString();
        var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

    
        if (string.IsNullOrEmpty(userId))
        {
            return Json(new { success = false, message = "Пользователь не аутентифицирован" });
        }

        var user = _context.Users.SingleOrDefault(u => u.Id == userId);
        if (user == null)
        {
            return Json(new { success = false, message = "Пользователь не найден" });
        }

     
        if (paymentMethod == "profile-balance")
        {
            if (user.Balance < totalAmount)
            {
                return Json(new { success = false, message = "Недостаточно средств на балансе" });
            }

     
            user.Balance -= totalAmount;
        }
        else if (paymentMethod == "cash")
        {
           
        }
        else
        {
            return Json(new { success = false, message = "Неизвестный способ оплаты" });
        }

     
        var cartItems = _context.CartItems.Where(c => c.UserId == userId).ToList();
        if (cartItems.Any())
        {
            _context.CartItems.RemoveRange(cartItems);
        }

     
        _context.SaveChanges();

  
        SendConfirmationEmail(user.Email, totalAmount);

         return Json(new { success = true, redirectUrl = Url.Action("Success", "Checkout") });
    }
    catch (Exception ex)
    {
        _logger.LogError(ex, "Ошибка при обработке оплаты"); 
        return Json(new { success = false, message = "Ошибка при обработке оплаты: " + ex.Message });
    }
}


 private void SendConfirmationEmail(string recipientEmail, decimal totalAmount)
    {
        var message = new MimeMessage();
        message.From.Add(new MailboxAddress(_configuration["EmailSettings:SenderName"], _configuration["EmailSettings:SenderEmail"]));
        message.To.Add(new MailboxAddress("", recipientEmail));
        message.Subject = "Подтверждение заказа";

        message.Body = new TextPart("plain")
        {
            Text = $"Здравствуйте!\n\nВаш заказ на сумму {totalAmount} был успешно обработан.\nСпасибо за покупку!"
        };

        using (var client = new SmtpClient())
        {
            client.Connect(_configuration["EmailSettings:SmtpServer"], int.Parse(_configuration["EmailSettings:SmtpPort"]), false);
            client.Authenticate(_configuration["EmailSettings:SenderEmail"], _configuration["EmailSettings:SenderPassword"]);
            client.Send(message);
            client.Disconnect(true);
        }
    }

[HttpGet("success")]
    public IActionResult Success()
    {
        return View();
    }



        [HttpGet("cancel")]
        public IActionResult Cancel()
        {
            ViewBag.Message = "Оплата была отменена. Вы можете продолжить покупки.";
            return View();
        }

    }

    [Route("cart")]
    public class CartController : Controller
    {
                private readonly ApplicationDbContext _context;
                private readonly IConfiguration _configuration;

                public CartController(ApplicationDbContext context, IConfiguration configuration)
                {
                    _context = context;
                    _configuration = configuration;
                }

              [HttpGet("")]
public async Task<IActionResult> Cart()
{
    var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
    var cart = new Cart();

    if (!string.IsNullOrEmpty(userId))
    {
        var cartItems = await _context.CartItems
            .Include(ci => ci.Product)
            .Where(ci => ci.UserId == userId)
            .ToListAsync();

        cart.Items = cartItems.Select(ci => new CartItem
        {
            ProductId = ci.ProductId,
            Quantity = ci.Quantity,
            Product = ci.Product
        }).ToList();

  
        var user = await _context.Users.SingleOrDefaultAsync(u => u.Id == userId);
        if (user != null)
        {
            ViewBag.UserName = user.UserName;
            ViewBag.Address = user.DeliveryAddress;
        }
    }
    else
    {
        cart = HttpContext.Session.GetObjectFromJson<Cart>("Cart") ?? new Cart();
    }

 
    cart.DeliveryType = "курьер";
    cart.DeliveryCost = 600;


    decimal tax = 0.13m; 
decimal totalAmount = cart.Subtotal + cart.DeliveryCost + (cart.Subtotal * tax);

    return View(cart);
}


           [HttpPost]
public IActionResult SaveDeliveryOption([FromBody] DeliveryOptionModel model)
{
    var deliveryCost = model.DeliveryOption == "курьер" ? 600 : 150;
    HttpContext.Session.SetString("DeliveryOption", model.DeliveryOption);
    HttpContext.Session.SetInt32("DeliveryCost", deliveryCost);

    return Json(new { success = true });
}

public class DeliveryOptionModel
{
    public string DeliveryOption { get; set; }
}



            [HttpPost("add")]
            public async Task<IActionResult> AddToCart(int productId, int quantity = 1)
            {
                var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
                var cart = HttpContext.Session.GetObjectFromJson<Cart>("Cart") ?? new Cart();
             
                if (!string.IsNullOrEmpty(userId))
                {
                    var cartItem = await _context.CartItems
                        .FirstOrDefaultAsync(ci => ci.UserId == userId && ci.ProductId == productId);

                    if (cartItem != null)
                    {
                        cartItem.Quantity += quantity; 
                        _context.CartItems.Update(cartItem);
                        TempData["Message"] = "Количество товара в корзине успешно обновлено.";
                    }
                    else
                    {
                        var product = await _context.Products.FindAsync(productId);
                        if (product != null)
                        {
                            cartItem = new CartItem
                            {
                                UserId = userId,
                                ProductId = productId,
                                Quantity = quantity,
                                Product = product
                            };
                            await _context.CartItems.AddAsync(cartItem);
                            TempData["Message"] = "Товар успешно добавлен в корзину.";
                        }
                    }

                    await _context.SaveChangesAsync(); 
                }
                else
                {
                
                    var existingItem = cart.Items.FirstOrDefault(i => i.ProductId == productId);
                    if (existingItem != null)
                    {
                        existingItem.Quantity += quantity; 
                    }
                    else
                    {
                        var product = await _context.Products.FindAsync(productId);
                        if (product != null)
                        {
                            cart.Items.Add(new CartItem
                            {
                                ProductId = productId,
                                Quantity = quantity,
                                Product = product
                            });
                        }
                    }

                    HttpContext.Session.SetObjectAsJson("Cart", cart);
                }

                return RedirectToAction("Index", "Cart");
            }
        [HttpPost("update-quantity")]
        public async Task<IActionResult> UpdateQuantity(int productId, int currentQuantity, int change)
        {
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var cart = HttpContext.Session.GetObjectFromJson<Cart>("Cart") ?? new Cart();

            int newQuantity = currentQuantity + change; 

            if (!string.IsNullOrEmpty(userId))
            {
              
                var cartItem = await _context.CartItems.FirstOrDefaultAsync(ci => ci.UserId == userId && ci.ProductId == productId);
                if (cartItem != null)
                {
                 
                    if (newQuantity > 0)
                    {
                        cartItem.Quantity = newQuantity; 
                        _context.CartItems.Update(cartItem);
                        TempData["Message"] = $"Количество товара обновлено до {newQuantity}.";
                    }
                    else
                    {
                        _context.CartItems.Remove(cartItem); 
                        TempData["Message"] = "Товар удален из корзины.";
                    }
                    await _context.SaveChangesAsync();
                }
            }
            else
            {
            
                var item = cart.Items.FirstOrDefault(i => i.ProductId == productId);
                if (item != null)
                {
            
                    if (newQuantity > 0)
                    {
                        item.Quantity = newQuantity;
                        TempData["Message"] = $"Количество товара обновлено до {newQuantity}.";
                    }
                    else
                    {
                        cart.RemoveItem(productId); 
                        TempData["Message"] = "Товар удален из корзины.";
                    }
                }
            }

      
            HttpContext.Session.SetObjectAsJson("Cart", cart);
            return RedirectToAction("Cart");
        }
        [HttpPost("remove")]
        public async Task<IActionResult> RemoveFromCart(int productId)
        {
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

            if (!string.IsNullOrEmpty(userId))
            {
               
                var cartItem = await _context.CartItems
                    .FirstOrDefaultAsync(ci => ci.UserId == userId && ci.ProductId == productId);

                if (cartItem != null)
                {
                    _context.CartItems.Remove(cartItem);
                    await _context.SaveChangesAsync();
                }
            }
            else
            {
               
                var cart = HttpContext.Session.GetObjectFromJson<Cart>("Cart") ?? new Cart();
                cart.RemoveItem(productId);
                HttpContext.Session.SetObjectAsJson("Cart", cart);
            }

            return RedirectToAction("Cart");
        }
        }
        }