using System.ComponentModel.DataAnnotations;

namespace Fiorello.ViewModels.AccountVMs
{
    public class ForgetPasswordVM
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }
}
