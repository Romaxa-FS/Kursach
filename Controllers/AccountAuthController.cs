using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using MyWeb2.Models;
using MyWeb2.Data;
using MyWeb2.Extensions; 
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;

public class AccountController : Controller 
{ 
    private readonly SignInManager<ApplicationUser> _signInManager; 
    private readonly UserManager<ApplicationUser> _userManager; 
    private readonly IConfiguration _configuration; 
    private readonly ApplicationDbContext _context; 
     private readonly IWebHostEnvironment _environment;
private readonly ILogger<AccountController> _logger;


    public AccountController(SignInManager<ApplicationUser> signInManager, UserManager<ApplicationUser> userManager,ILogger<AccountController> logger, IConfiguration configuration, ApplicationDbContext context, IWebHostEnvironment environment)  
    { 
        _context = context; 
        _signInManager = signInManager; 
        _userManager = userManager; 
        _configuration = configuration; 
        _environment = environment;
        _logger = logger;
    }



    [HttpGet]
    public IActionResult Register()
    {
        return View();
    }


 [HttpPost]
public async Task<IActionResult> Register(RegisterViewModel model)
{
    _logger.LogInformation("Начало регистрации пользователя");

    if (!ModelState.IsValid)
    {
        var errors = ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage);
        _logger.LogWarning("Ошибки валидации: {Errors}", string.Join(", ", errors));
        return View(model);
    }

    _logger.LogInformation("Поля формы: UserName = {UserName}, Email = {Email}", model.UserName, model.Email);

   
    var existingUser = await _userManager.FindByEmailAsync(model.Email);
    if (existingUser != null)
    {
        _logger.LogWarning("Попытка регистрации с уже существующим Email: {Email}", model.Email);
        Response.StatusCode = 409; 
        ModelState.AddModelError(string.Empty, "Электронная почта уже используется.");
        return View(model);
    }

   var passwordValidationResult = await _userManager.PasswordValidators[0].ValidateAsync(_userManager, null, model.Password);
    if (!passwordValidationResult.Succeeded)
    {
        var passwordErrors = passwordValidationResult.Errors.Select(e => e.Description).ToList();
        _logger.LogWarning("Пароль не соответствует требованиям: {Errors}", string.Join(", ", passwordErrors));
        Response.StatusCode = 409; 
        foreach (var error in passwordErrors)
        {
            ModelState.AddModelError(string.Empty, error);
        }
        return View(model);
    }
    var user = new ApplicationUser
    {
        UserName = model.UserName,
        Email = model.Email,
        AvatarPath = "/Images/avatar/default-avatar.jpg"
    };
    _logger.LogInformation("Создание пользователя с UserName: {UserName}, Email: {Email}", user.UserName, user.Email);

    var result = await _userManager.CreateAsync(user, model.Password);

    if (result.Succeeded)
    {
        _logger.LogInformation("Пользователь успешно зарегистрирован: {UserName}", model.UserName);

        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, model.UserName),
            new Claim(ClaimTypes.Email, model.Email)
        };

        var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);

        await HttpContext.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            new ClaimsPrincipal(claimsIdentity),
            new AuthenticationProperties
            {
                IsPersistent = true,
                ExpiresUtc = DateTimeOffset.UtcNow.AddDays(30)
            });

        _logger.LogInformation("Пользователь успешно вошел в систему: {UserName}", model.UserName);

        return RedirectToAction("Index", "Home", new { message = "Поздравляю, вы зарегистрированы!" });
    }

    foreach (var error in result.Errors)
    {
        ModelState.AddModelError(string.Empty, error.Description);
        _logger.LogError("Ошибка при создании пользователя: {ErrorDescription}", error.Description);
    }

    _logger.LogWarning("Регистрация пользователя не удалась: {UserName}", model.UserName);
    return View(model);
}



[HttpGet]
public IActionResult Login()
{
    return View();
}


[HttpPost]
[ValidateAntiForgeryToken] 
public async Task<IActionResult> Login(LoginViewModel model)
{
    Console.WriteLine($"Login attempt: Email = {model.Email}, Password = {model.Password}, RememberMe = {model.RememberMe}");

    if (!ModelState.IsValid)
    {
        Console.WriteLine("Model state is invalid.");
        foreach (var error in ModelState.Values.SelectMany(v => v.Errors))
        {
            Console.WriteLine($"Validation error: {error.ErrorMessage}");
        }
        return View(model);
    }

    var user = await _userManager.FindByEmailAsync(model.Email);
    if (user == null)
    {
        Console.WriteLine($"No user found with Email = {model.Email}");
        ModelState.AddModelError(string.Empty, "Неправильный логин или пароль.");
      return View(model);
    }

    Console.WriteLine($"User found: Id = {user.Id}, UserName = {user.UserName}, Email = {user.Email}");

   
    if (string.IsNullOrWhiteSpace(user.UserName))
    {
        Console.WriteLine("UserName is null or empty.");
        ModelState.AddModelError(string.Empty, "Ошибка на стороне сервера. Попробуйте позже.");
        return View(model);
    }

    var isPasswordValid = await _userManager.CheckPasswordAsync(user, model.Password);
    Console.WriteLine($"Password validation result for {user.UserName}: {isPasswordValid}");

    if (!isPasswordValid)
    {
        ModelState.AddModelError(string.Empty, "Неправильный логин или пароль.");
        return View(model);
    }
 

    try
{
    Console.WriteLine($"Attempting sign-in for UserName = {user.UserName}...");
    
    var result = await _signInManager.PasswordSignInAsync(user.UserName, model.Password, model.RememberMe, lockoutOnFailure: false);

    if (result.Succeeded)
    {
        Console.WriteLine($"Sign-in succeeded for UserName = {user.UserName}.");
        

        var cart = HttpContext.Session.GetObjectFromJson<Cart>("Cart") ?? new Cart();
        if (cart.Items.Any())
        {
            foreach (var item in cart.Items)
            {
                _context.CartItems.Add(new CartItem
                {
                    UserId = user.Id,
                    ProductId = item.ProductId,
                    Quantity = item.Quantity
                });
            }
            await _context.SaveChangesAsync();

  
            HttpContext.Session.Remove("Cart");
        }


        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, user.UserName),
            new Claim(ClaimTypes.NameIdentifier, user.Id),
            new Claim(ClaimTypes.Email, user.Email)
        };

        var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);

        await HttpContext.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            new ClaimsPrincipal(claimsIdentity),
            new AuthenticationProperties
            {
                IsPersistent = model.RememberMe,
                ExpiresUtc = DateTime.UtcNow.AddDays(7)
            });

        Console.WriteLine($"Cookies set: {HttpContext.Request.Cookies}");
        
        Console.WriteLine("Успешная авторизация");
        return RedirectToAction("Index", "Home", new { message = "Поздравляю, вы вошли в систему!" });
        
    }
    
    if (result.IsLockedOut)
    {
        Console.WriteLine($"Account locked out for UserName = {user.UserName}.");
        ModelState.AddModelError(string.Empty, "Аккаунт временно заблокирован.");
        return View(model);
    }
    else
    {
        Console.WriteLine($"Sign-in failed for UserName = {user.UserName}.");
        ModelState.AddModelError(string.Empty, "Неправильный логин или пароль.");
        return View(model);
    }
}
catch (Exception ex)
{
    Console.WriteLine($"Exception during sign-in: {ex.Message}");
    ModelState.AddModelError(string.Empty, "Ошибка при попытке входа в систему. Попробуйте позже.");
    return View(model);
}
}
[HttpGet]
public IActionResult ForgotPassword()
{
    return View();
}
[HttpPost]
[ValidateAntiForgeryToken]
public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model, [FromServices] EmailSender emailSender)
{
    if (!ModelState.IsValid)
    {
        return View(model);
    }

    var user = await _userManager.FindByEmailAsync(model.Email);
    if (user == null)
    {
      
        return RedirectToAction("ForgotPasswordConfirmation");
    }

    var token = await _userManager.GeneratePasswordResetTokenAsync(user);
    var resetLink = Url.Action("ResetPassword", "Account", 
        new { token, email = model.Email }, Request.Scheme);

  
    await emailSender.SendEmailAsync(model.Email, "Сброс пароля", 
        $"<p>Для восстановления пароля перейдите по <a href='{resetLink}'>этой ссылке</a>.</p>");

    return RedirectToAction("ForgotPasswordConfirmation");
}

[HttpGet]
public IActionResult ForgotPasswordConfirmation()
{
    return View();
}
[HttpGet]
public IActionResult ResetPassword(string token, string email)
{
    if (token == null || email == null)
    {
        return BadRequest("Невалидный запрос сброса пароля.");
    }

    return View(new ResetPasswordViewModel { Token = token, Email = email });
}
[HttpPost]
[ValidateAntiForgeryToken]
public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
{
    if (!ModelState.IsValid)
    {
      
        Console.WriteLine("ModelState не валиден. Ошибки: " + string.Join(", ", ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage)));
        return View(model);
    }

    var user = await _userManager.FindByEmailAsync(model.Email);
    if (user == null)
    {
 
        Console.WriteLine("Пользователь не найден.");
        return RedirectToAction("ResetPasswordConfirmation");
    }


    var result = await _userManager.ResetPasswordAsync(user, model.Token, model.Password);
    if (result.Succeeded)
    {
        Console.WriteLine("Пароль успешно изменен.");
        return RedirectToAction("ResetPasswordConfirmation");
    }

    foreach (var error in result.Errors)
    {
        ModelState.AddModelError(string.Empty, error.Description);
        Console.WriteLine($"Ошибка сброса пароля: {error.Description}");
    }

    return View(model);
}
[HttpGet]
public IActionResult ResetPasswordConfirmation()
{
    return View();
}


  
    private string GenerateJwtToken(IdentityUser user)
    {
        if (string.IsNullOrEmpty(user.Email) || string.IsNullOrEmpty(user.Id))
        {
        throw new ArgumentException("Некорректные данные для генерации токена.");
        }
        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Email),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(ClaimTypes.NameIdentifier, user.Id)
        };
        var jwtKey = _configuration["Jwt:Key"] ?? throw new ArgumentNullException("Jwt:Key is missing in configuration");
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            issuer: _configuration["Jwt:Issuer"],
            audience: _configuration["Jwt:Audience"],
            claims: claims,
            expires: DateTime.Now.AddMinutes(30),
            signingCredentials: creds
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

  [HttpPost]
[ValidateAntiForgeryToken]
public async Task<IActionResult> Logout()
{
    await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    return RedirectToAction("Index", "Home");
}

[Authorize]
[HttpGet]
public async Task<IActionResult> Profile()
{
   
    if (!User.Identity.IsAuthenticated)
    {
        return RedirectToAction("Login", "Account");
    }
    
    var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
Console.WriteLine($"Пользователь с ID {userId} пытался перейти на профиль.");

    if (userId == null)
    {
        return RedirectToAction("Login", "Account");
    }

    var user = await _userManager.FindByIdAsync(userId);
    if (user == null)
    {
        return NotFound("Пользователь не найден.");
    }

    var model = new ProfileViewModel
    {
        Email = user.Email,
        UserName = user.UserName,
        AvatarPath = user.AvatarPath,
        DeliveryAddress = user.DeliveryAddress,
        Balance = user.Balance
    };

    return View(model);
}


[HttpPost]
[ValidateAntiForgeryToken]
public async Task<IActionResult> Profile(ProfileViewModel model)
{

    Console.WriteLine($"Profile Update Attempt: UserName = {model.UserName}, Email = {model.Email}, Password = {model.Password}, AvatarPath = {model.AvatarPath}");


    if (ModelState.ContainsKey("AvatarPath"))
    {
        ModelState["AvatarPath"].Errors.Clear();
    }

    if (ModelState.IsValid)
    {
   
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        var user = await _context.Users.FindAsync(userId);

        if (user != null)
        {
          
            if (!string.IsNullOrWhiteSpace(model.UserName) && user.UserName != model.UserName)
            {
                user.UserName = model.UserName.Trim();
                Console.WriteLine($"Updating UserName to: {model.UserName}");
            }

          
            if (!string.IsNullOrWhiteSpace(model.Email) && user.Email != model.Email)
            {
                user.Email = model.Email.Trim();
                Console.WriteLine($"Updating Email to: {model.Email}");
            }

  
            if (!string.IsNullOrEmpty(model.Password))
            {
                var token = await _userManager.GeneratePasswordResetTokenAsync(user);
                var passwordUpdateResult = await _userManager.ResetPasswordAsync(user, token, model.Password);

                if (passwordUpdateResult.Succeeded)
                {
                    Console.WriteLine("Password updated successfully.");
                }
                else
                {
                    foreach (var error in passwordUpdateResult.Errors)
                    {
                        Console.WriteLine($"Password update failed: {error.Description}");
                        ModelState.AddModelError(string.Empty, error.Description);
                    }
                }
            }

             if (!string.IsNullOrWhiteSpace(model.DeliveryAddress) && user.DeliveryAddress != model.DeliveryAddress)
            {
                user.DeliveryAddress = model.DeliveryAddress.Trim();
            }
            try
            {
                _context.Users.Update(user);
                await _context.SaveChangesAsync();
                Console.WriteLine("Profile updated successfully in the database.");
                return RedirectToAction("Profile");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Database Update Failed: {ex.Message}");
                ModelState.AddModelError(string.Empty, "Произошла ошибка при сохранении данных в базу.");
            }
        }
        else
        {
            Console.WriteLine("User not found.");
            ModelState.AddModelError(string.Empty, "Пользователь не найден.");
        }
    }

   
    if (!ModelState.IsValid)
    {
        Console.WriteLine("ModelState is not valid.");
        foreach (var state in ModelState)
        {
            Console.WriteLine($"Key: {state.Key}");
            foreach (var error in state.Value.Errors)
            {
                Console.WriteLine($"Error: {error.ErrorMessage}, Exception: {error.Exception?.Message}");
            }
        }
    }

  
    return View(model);
}

[HttpPost]
[ValidateAntiForgeryToken]
public async Task<IActionResult> UploadAvatar(IFormFile avatar)
{
    Console.WriteLine($"Uploading avatar: {avatar?.FileName}");

    if (avatar != null)
    {
        var allowedExtensions = new[] { ".jpg", ".jpeg", ".png" };
        var extension = Path.GetExtension(avatar.FileName)?.ToLowerInvariant();

        if (string.IsNullOrEmpty(extension) || !allowedExtensions.Contains(extension))
        {
            ModelState.AddModelError("Avatar", "Разрешены только файлы формата .jpg, .jpeg, .png");
            return RedirectToAction("Profile");
        }

        var uniqueFileName = Guid.NewGuid() + extension;
        var uploadsFolder = Path.Combine(_environment.WebRootPath, "Images/Avatar");
        var savePath = Path.Combine(uploadsFolder, uniqueFileName);

        try
        {
            if (!Directory.Exists(uploadsFolder))
            {
                Directory.CreateDirectory(uploadsFolder);
            }

            await using (var stream = new FileStream(savePath, FileMode.Create))
            {
                await avatar.CopyToAsync(stream);
            }

            var user = await _context.Users.FindAsync(User.FindFirstValue(ClaimTypes.NameIdentifier));
            if (user != null)
            {
                user.AvatarPath = $"/Images/Avatar/{uniqueFileName}";
                _context.Users.Update(user);
                await _context.SaveChangesAsync();
                Console.WriteLine($"Avatar uploaded and updated in database: {user.AvatarPath}");

           
                var identity = (ClaimsIdentity)User.Identity;
                var avatarClaim = identity.FindFirst("AvatarPath");
                if (avatarClaim != null)
                {
                    identity.RemoveClaim(avatarClaim);
                }
                identity.AddClaim(new Claim("AvatarPath", user.AvatarPath));

                await HttpContext.SignInAsync(User);
            }
            else
            {
                Console.WriteLine("User not found for avatar upload.");
                ModelState.AddModelError(string.Empty, "Пользователь не найден.");
            }

            return RedirectToAction("Profile");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error saving avatar: {ex.Message}");
            ModelState.AddModelError(string.Empty, "Ошибка при сохранении аватара.");
        }
    }
    else
    {
        Console.WriteLine("Avatar file is null or empty.");
        ModelState.AddModelError("Avatar", "Файл не выбран.");
    }

    return RedirectToAction("Profile");
}
[HttpPost]
[ValidateAntiForgeryToken]
public async Task<IActionResult> AddMoney(decimal amount)
{
    Console.WriteLine($"AddMoney: Attempt to add {amount} to user balance");

    if (amount <= 0)
    {
        ModelState.AddModelError(string.Empty, "Сумма должна быть больше нуля.");
        return RedirectToAction("Profile"); 
    }

    var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
    var user = await _userManager.FindByIdAsync(userId);

    if (user != null)
    {
        user.Balance += amount; 
        await _userManager.UpdateAsync(user); 

        Console.WriteLine($"Money added successfully. New balance: {user.Balance}");
        TempData["Message"] = "Баланс успешно пополнен!";
    }
    else
    {
        Console.WriteLine("User not found.");
        ModelState.AddModelError(string.Empty, "Пользователь не найден.");
    }

    return RedirectToAction("Profile");
}
}
