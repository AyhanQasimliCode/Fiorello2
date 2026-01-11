using Fiorello.Data;
using Fiorello.Models;
using Fiorello.ViewModels;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace Fiorello.Controllers
{
    public class HomeController : Controller
    {
        private readonly AppDbContext _context;
        public HomeController(AppDbContext context)
        {
            _context = context;
        }
        public async Task<IActionResult> Index()
        {
            //HttpContext.Session.SetString("Name", "Mahmud");
            //HttpContext.Response.Cookies.Append("surname", "Rehimli", new CookieOptions() { MaxAge = TimeSpan.FromMinutes(5)});
            //ViewBag.Name = HttpContext.Session.GetString("Name");
            //ViewBag.Surname = HttpContext.Request.Cookies["surname"];

            IEnumerable<Slider> sliders = await _context.Sliders.ToListAsync();
            SliderDetail sliderDetail = await _context.SlidersDetails.FirstOrDefaultAsync();
            var products = await _context.Products.Include(p => p.ProductImages).Take(4).ToListAsync();
            IEnumerable<Category> categories = await _context.Categories.ToListAsync();
            HomeVM homeVM = new()
            {
                Sliders = sliders,
                SliderDetail = sliderDetail,
                Products = products,
                Categories = categories
            };
            ViewBag.ProductCount = await _context.Products.CountAsync();
            return View(homeVM);
        }
        public async Task<IActionResult> LoadMore(int skip)
        {
            var products = await _context.Products.Include(p => p.ProductImages).Skip(skip).Take(4).ToListAsync();
            return PartialView("_ProductPartial", products);
        }
      

    }
}
