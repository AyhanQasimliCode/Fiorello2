namespace Fiorello.Areas.Admin.ViewModels.ProductVM
{
    public class DetailProductVM
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public string Description { get; set; }
        public decimal Price { get; set; }
        public string? CategoryName { get; set; }
        public string? MainPhoto { get; set; }
        public List<string>? AdditionalPhotos { get; set; }
    }
}
