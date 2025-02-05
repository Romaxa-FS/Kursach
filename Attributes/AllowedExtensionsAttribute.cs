using System;
using System.ComponentModel.DataAnnotations;
using System.IO;
using Microsoft.AspNetCore.Http;

namespace MyWeb2.Attributes
{
  public class AllowedExtensionsAttribute : ValidationAttribute
{
    private readonly string[] _extensions;

    public AllowedExtensionsAttribute(string[] extensions)
    {
     
        _extensions = extensions.Select(e => e.ToLowerInvariant()).ToArray();
    }

    protected override ValidationResult IsValid(object value, ValidationContext validationContext)
{
    Console.WriteLine($"Custom Validation: Received value: {value}");

    var file = value as IFormFile;
    if (file != null)
    {
        var extension = Path.GetExtension(file.FileName)?.ToLowerInvariant();
        Console.WriteLine($"Extension being checked: {extension}");

        if (!_extensions.Contains(extension))
        {
            return new ValidationResult($"Разрешены только файлы: {string.Join(", ", _extensions)}");
        }
    }

    return ValidationResult.Success;
}
}
}
