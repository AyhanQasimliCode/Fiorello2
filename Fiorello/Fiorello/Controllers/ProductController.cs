using Fiorello.Data;
using Fiorello.Models;
using Fiorello.ViewModels;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace Fiorello.Controllers
{
    public class ProductController : Controller
    {
        private readonly AppDbContext _context;
        public ProductController(AppDbContext context)
        {
            _context = context;
        }
        public async Task<IActionResult> Index()
        {
            var products = await _context.Products.Include(p => p.ProductImages).ToListAsync();
            IEnumerable<Category> categories = await _context.Categories.ToListAsync();

            HomeVM homeVM = new()
            {             
                Products = products,
                Categories = categories
            };
            return View(homeVM);
        }
    }
}
