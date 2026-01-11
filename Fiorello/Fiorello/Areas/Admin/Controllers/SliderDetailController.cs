using Fiorello.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace Fiorello.Areas.Admin.Controllers
{
    [Area("Admin")]
    public class SliderDetailController : Controller
    {
        private readonly AppDbContext _context;

        public SliderDetailController(AppDbContext context)
        {
            _context = context;
        }
        public async Task<IActionResult> Index()
        {
            var sliders = await _context.SlidersDetails.ToListAsync();
            return View(sliders);
        }
    }
}
