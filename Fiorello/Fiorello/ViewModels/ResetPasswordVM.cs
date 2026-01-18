using System.ComponentModel.DataAnnotations;

namespace Fiorello.ViewModels.AccountVMs
{
    public class ResetPasswordVM
    {
        [Required]
        [DataType(DataType.Password)]
        public string NewPassword { get; set; }

        [Required]
        [DataType(DataType.Password), Compare(nameof(NewPassword))]
        public string ConfirmPassword { get; set; }

        public string UserId { get; set; }
        public string Token { get; set; }
    }
}
