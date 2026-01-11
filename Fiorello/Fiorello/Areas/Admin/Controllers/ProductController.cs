using Fiorello.Areas.Admin.ViewModels.ProductVM;
using Fiorello.Data;
using Fiorello.Helpers;
using Fiorello.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;

namespace Fiorello.Areas.Admin.Controllers
{
    [Area("Admin")]
    public class ProductController : Controller
    {
        private readonly AppDbContext _context;
        private readonly IWebHostEnvironment _webHostEnvironment;

        public ProductController(AppDbContext context, IWebHostEnvironment webHostEnvironment)
        {
            _context = context;
            _webHostEnvironment = webHostEnvironment;
        }

        public async Task<IActionResult> Index()
        {
            var products = await _context.Products
                .Include(p => p.ProductImages)
                .Include(p => p.Category)
                .Select(p => new GetAllProductVM
                {
                    Id = p.Id,
                    Name = p.Name,
                    Price = p.Price,
                    CategoryName = p.Category.Name,
                    MainImage = p.ProductImages.FirstOrDefault(i => i.IsMain).Image
                })
                .OrderByDescending(p => p.Id)
                .ToListAsync();

            return View(products);
        }

        public async Task<IActionResult> Create()
        {
            ViewBag.Categories = await GetAllCategories();
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Create(CreateProductVM request)
        {
            if (!ModelState.IsValid)
            {
                ViewBag.Categories = await GetAllCategories();
                return View(request);
            }

            if (!request.MainImage.ContentType.Contains("image/") || request.MainImage.Length / 1024 > 2048)
            {
                ModelState.AddModelError("MainImage", "Sekil tipi duzgun deyil ve ya olcu 2MB-dan boyukdur!");
                ViewBag.Categories = await GetAllCategories();
                return View(request);
            }

            string mainFileName = Guid.NewGuid() + "_" + request.MainImage.FileName;
            string mainPath = Path.Combine(_webHostEnvironment.WebRootPath, "img", mainFileName);

            using (FileStream stream = new(mainPath, FileMode.Create))
            {
                await request.MainImage.CopyToAsync(stream);
            }

            List<ProductImage> images = new()
            {
                new ProductImage { Image = mainFileName, IsMain = true }
            };

            if (request.AdditionalImages != null)
            {
                foreach (var img in request.AdditionalImages)
                {
                    if (!img.ContentType.Contains("image/") || img.Length / 1024 > 2048)
                    {
                        ModelState.AddModelError("AdditionalImages", "Sekil tipi duzgun deyil ve ya olcu 2MB-dan boyukdur!");
                        ViewBag.Categories = await GetAllCategories();
                        return View(request);
                    }

                    string fileName = Guid.NewGuid() + "_" + img.FileName;
                    string path = Path.Combine(_webHostEnvironment.WebRootPath, "img", fileName);

                    using (FileStream stream = new(path, FileMode.Create))
                    {
                        await img.CopyToAsync(stream);
                    }

                    images.Add(new ProductImage { Image = fileName, IsMain = false });
                }
            }

            Product product = new()
            {
                Name = request.Name,
                Description = request.Description,
                Price = request.Price,
                CategoryId = request.CategoryId,
                ProductImages = images
            };

            await _context.Products.AddAsync(product);
            await _context.SaveChangesAsync();

            return RedirectToAction(nameof(Index));
        }

        public async Task<IActionResult> Update(int? id)
        {
            if (id == null) return BadRequest();

            var product = await _context.Products
                .Include(p => p.ProductImages)
                .FirstOrDefaultAsync(p => p.Id == id);

            if (product == null) return NotFound();

            ViewBag.Categories = await GetAllCategories();

            UpdateProductVM vm = new()
            {
                Name = product.Name,
                Description = product.Description,
                Price = product.Price,
                CategoryId = product.CategoryId,
                MainPhoto = product.ProductImages.FirstOrDefault(i => i.IsMain)?.Image,
                AdditionalPhotos = product.ProductImages
                    .Where(i => !i.IsMain)
                    .Select(i => new AdditionalPhotoVM
                    {
                        Id = i.Id,
                        Image = i.Image
                    })
                    .ToList()
            };

            return View(vm);
        }

        [HttpPost]
        public async Task<IActionResult> Update(int? id, UpdateProductVM request)
        {
            if (id == null) return BadRequest();

            var product = await _context.Products
                .Include(p => p.ProductImages)
                .FirstOrDefaultAsync(p => p.Id == id);

            if (product == null) return NotFound();

            ViewBag.Categories = await GetAllCategories();

            if (!ModelState.IsValid)
            {
                request.MainPhoto = product.ProductImages.FirstOrDefault(i => i.IsMain)?.Image;
                request.AdditionalPhotos = product.ProductImages
                    .Where(i => !i.IsMain)
                    .Select(i => new AdditionalPhotoVM
                    {
                        Id = i.Id,
                        Image = i.Image
                    })
                    .ToList();
                return View(request);
            }

            // MAIN IMAGE
            if (request.MainImage != null)
            {
                if (!request.MainImage.ContentType.Contains("image/") || request.MainImage.Length / 1024 > 2048)
                {
                    ModelState.AddModelError("MainImage", "Sekil tipi duzgun deyil ve ya olcu 2MB-dan boyukdur!");
                    return View(request);
                }

                var oldMain = product.ProductImages.FirstOrDefault(i => i.IsMain);
                if (oldMain != null)
                {
                    string oldPath = Path.Combine(_webHostEnvironment.WebRootPath, "img", oldMain.Image);
                    if (System.IO.File.Exists(oldPath))
                        System.IO.File.Delete(oldPath);
                }

                string fileName = Guid.NewGuid() + "_" + request.MainImage.FileName;
                string path = Path.Combine(_webHostEnvironment.WebRootPath, "img", fileName);

                using (FileStream stream = new(path, FileMode.Create))
                {
                    await request.MainImage.CopyToAsync(stream);
                }

                if (oldMain != null) oldMain.Image = fileName;
            }

            if (request.AdditionalImages != null && request.AdditionalImages.Any())
            {
                var oldImages = product.ProductImages.Where(i => !i.IsMain).ToList();

                foreach (var img in oldImages)
                {
                    string oldPath = Path.Combine(_webHostEnvironment.WebRootPath, "img", img.Image);
                    if (System.IO.File.Exists(oldPath))
                        System.IO.File.Delete(oldPath);
                }

                _context.ProductImages.RemoveRange(oldImages);

                foreach (var img in request.AdditionalImages)
                {
                    string fileName = Guid.NewGuid() + "_" + img.FileName;
                    string path = Path.Combine(_webHostEnvironment.WebRootPath, "img", fileName);

                    using (FileStream stream = new(path, FileMode.Create))
                    {
                        await img.CopyToAsync(stream);
                    }

                    product.ProductImages.Add(new ProductImage
                    {
                        Image = fileName,
                        IsMain = false
                    });
                }
            }

            product.Name = request.Name;
            product.Description = request.Description;
            product.Price = request.Price;
            product.CategoryId = request.CategoryId;

            await _context.SaveChangesAsync();
            return RedirectToAction(nameof(Index));
        }

        public async Task<SelectList> GetAllCategories()
        {
            var categories = await _context.Categories.ToListAsync();
            return new SelectList(categories, "Id", "Name");
        }
        [HttpPost]
        public async Task<IActionResult> DeleteAdditionalImage(int id)
        {
            var image = await _context.ProductImages.FirstOrDefaultAsync(i => i.Id == id);

            if (image == null)
                return Json(new { success = false, message = "Sekil tapilmadı" });

            int count = await _context.ProductImages
                .CountAsync(i => i.ProductId == image.ProductId && !i.IsMain);

            if (count <= 1)
                return Json(new { success = false, message = "En az 1 sekil qalmalıdır" });

            string path = Path.Combine(_webHostEnvironment.WebRootPath, "img", image.Image);
            if (System.IO.File.Exists(path))
                System.IO.File.Delete(path);

            _context.ProductImages.Remove(image);
            await _context.SaveChangesAsync();

            return Json(new { success = true });
        }

    }

}
