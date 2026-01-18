using System.ComponentModel.DataAnnotations;

namespace Fiorello.ViewModels.AccountVMs
{
    public class UpdateUserVM
    {
        [Required]
        public string Name { get; set; }

        [Required]
        public string Surname { get; set; }

        [Required]
        public string Username { get; set; }

        [Required]
        public string Email { get; set; }

        [DataType(DataType.Password)]
        public string? OldPassword { get; set; }

        [DataType(DataType.Password)]
        public string? NewPassword { get; set; }

        [DataType(DataType.Password), Compare(nameof(NewPassword))]
        public string? ConfirmPassword { get; set; }
    }
}
