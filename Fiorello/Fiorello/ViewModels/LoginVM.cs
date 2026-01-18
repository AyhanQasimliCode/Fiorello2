using System.ComponentModel.DataAnnotations;

namespace Fiorello.ViewModels.AccountVMs
{
    public class LoginVM
    {
        [Required]
        public string UsernameOrEmail { get; set; }

        [Required]
        [DataType(DataType.Password)]
        public string Password { get; set; }
    }
}
