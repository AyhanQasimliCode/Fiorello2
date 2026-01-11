using Fiorello.Areas.Admin.ViewModels.CategoryVM;
using Fiorello.Data;
using Fiorello.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace Fiorello.Areas.Admin.Controllers
{
    [Area("Admin")]
    public class CategoryController : Controller
    {
        private readonly AppDbContext _context;

        public CategoryController(AppDbContext context)
        {
            _context = context;
        }
        [HttpGet]
        public async Task<IActionResult> Index()
        {
            IEnumerable<Category> categories = await _context.Categories.ToListAsync();
            IEnumerable<GetAllCategoryVM> getAllCategoryVMs = categories.Select(c => new GetAllCategoryVM()
            {
                Id = c.Id,
                Name = c.Name
            });

            return View(getAllCategoryVMs);
        }
        [HttpGet]
        public IActionResult Create()
        {
            return View();
        }
        [HttpPost]
        public async Task<IActionResult> Create(CreateCategoryVM categoryVM)
        {
            if (!ModelState.IsValid) return View(categoryVM);

            var dbName = await _context.Categories.FirstOrDefaultAsync(m => m.Id == 6);

            if (dbName != null)
            {
                string ctName = dbName.Name.ToLower().Trim();
            }

            string newName = categoryVM.Name.ToLower().Trim();

            bool isExist = await _context.Categories.AnyAsync(c => c.Name.ToUpper().Trim() ==
                                                         categoryVM.Name.ToUpper().Trim());

            if (isExist)
            {
                ModelState.AddModelError("Name", "Bu adda movcuddur!");
                return View(categoryVM); 
            }

            Category category = new Category
            {
                Name = categoryVM.Name.Trim()
            };

            await _context.Categories.AddAsync(category);
            await _context.SaveChangesAsync();

            return RedirectToAction(nameof(Index));
        }
        [HttpGet]
        public async Task<IActionResult> Detail(int id)
        {
            Category category = await _context.Categories
                .FirstOrDefaultAsync(c => c.Id == id);

            if (category == null)
                return NotFound();

            DetailCategoryVM detailCategoryVM = new()
            {
                Id = category.Id,
                Name = category.Name
            };

            return View(detailCategoryVM);
        }
        [HttpGet]
        public async Task<IActionResult> Update(int id)
        {
            Category category = await _context.Categories
                .FirstOrDefaultAsync(c => c.Id == id);

            if (category == null)
                return NotFound();

            UpdateCategoryVM updateCategoryVM = new()
            {
                Id = category.Id,
                Name = category.Name
            };

            return View(updateCategoryVM);
        }
        [HttpPost]
        public async Task<IActionResult> Update(int id, UpdateCategoryVM request)
        {
            if (!ModelState.IsValid)
                return View(request);

            Category category = await _context.Categories
                .FirstOrDefaultAsync(c => c.Id == id);

            if (category == null)
                return NotFound();

            bool isExist = await _context.Categories.AnyAsync(c =>
                c.Name.Trim().ToLower() == request.Name.Trim().ToLower()
                && c.Id != id);

            if (isExist)
            {
                ModelState.AddModelError("Name", "Bu adda movcuddur!");
                return View(request);
            }

            category.Name = request.Name.Trim();

            await _context.SaveChangesAsync();

            return RedirectToAction(nameof(Index));
        }
        [HttpPost]
        public async Task<IActionResult> Delete(int id)
        {
            var category = await _context.Categories.FirstOrDefaultAsync(c => c.Id == id);
            if (category == null) return NotFound();

            _context.Categories.Remove(category);
            await _context.SaveChangesAsync();

            return RedirectToAction(nameof(Index));
        }
    }
}
