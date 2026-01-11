using System.ComponentModel.DataAnnotations;

namespace Fiorello.Areas.Admin.ViewModels.ProductVM
{
    public class UpdateProductVM
    {

        [Required]
        public string Name { get; set; }
        [Required]
        public string Description { get; set; }
        [Required]
        public decimal Price { get; set; }
        [Required]
        public int CategoryId { get; set; }
        public string MainPhoto { get; set; }
        public IEnumerable<AdditionalPhotoVM> AdditionalPhotos { get; set; }
        public IFormFile? MainImage { get; set; }
        public IEnumerable<IFormFile>? AdditionalImages { get; set; }
    }
}
