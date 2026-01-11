
using Fiorello.Areas.Admin.ViewModels.CategoryVM;
using Fiorello.Areas.Admin.ViewModels.SliderVM;
using Fiorello.Data;
using Fiorello.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace EntityFrameworkProject.Areas.Admin.Controllers
{
    [Area("Admin")]
    public class SliderController : Controller
    {
        private readonly AppDbContext _context;
        private readonly IWebHostEnvironment _webHostEnvironment;

        public SliderController(AppDbContext context, IWebHostEnvironment webHostEnvironment)
        {
            _context = context;
            _webHostEnvironment = webHostEnvironment;
        }

        [HttpGet]
        public async Task<IActionResult> Index()
        {
            IEnumerable<Slider> sliders = await _context.Sliders.ToListAsync();
            IEnumerable<GetAllSliderVM> getAllSliderVMs = sliders.Select(c => new GetAllSliderVM()
            {
                Id = c.Id,
                Image = c.Image
            });

            return View(getAllSliderVMs);
        }
        public IActionResult Create()
        {
            return View();
        }
        [HttpPost]
        public async Task<IActionResult> Create(CreateSliderVM request)
        {
            if (!ModelState.IsValid) return View();

            foreach (var photo in request.Photos)
            {
                string fileName = Guid.NewGuid().ToString() + "_" + photo.FileName;
                string path = Path.Combine(_webHostEnvironment.WebRootPath, "img", fileName);

                using (FileStream fileStream = new(path, FileMode.Create))
                {
                    await photo.CopyToAsync(fileStream);
                }

                Slider newSlider = new()
                {
                    Image = fileName
                };

                await _context.Sliders.AddAsync(newSlider);
            }

            await _context.SaveChangesAsync();

            return RedirectToAction(nameof(Index));
        }
        public async Task<IActionResult> Detail(int id)
        {
            Slider slider = await _context.Sliders.FirstOrDefaultAsync(s => s.Id == id);

            if (slider == null)
                return NotFound();

            DetailSliderVM detailSliderVM = new()
            {
                Id = slider.Id,
                Image = slider.Image
            };

            return View(detailSliderVM);
        }
        [HttpGet]
        public async Task<IActionResult> Update(int? id)
        {
            if (id is null) return BadRequest();

            Slider slider = await _context.Sliders.FindAsync(id);
            if (slider == null) return NotFound();

            UpdateSliderVM model = new()
            {
                Image = slider.Image
            };

            return View(model);
        }

        [HttpPost]
        public async Task<IActionResult> Update(int? id, UpdateSliderVM request)
        {
            if (id is null) return BadRequest();

            Slider slider = await _context.Sliders.FindAsync(id);
            if (slider == null) return NotFound();

            if (request.NewPhoto != null)
            {
                if (!request.NewPhoto.ContentType.Contains("image/"))
                {
                    ModelState.AddModelError("NewPhoto", "Shekil tipi olmalidir!");
                    request.Image = slider.Image; 
                    return View(request);
                }

                if (request.NewPhoto.Length / 1024 > 2048)
                {
                    ModelState.AddModelError("NewPhoto", "Shekilin olcusu max 2MB ola bilər!");
                    request.Image = slider.Image;
                    return View(request);
                }
                string oldPath = Path.Combine(_webHostEnvironment.WebRootPath, "img", slider.Image);
                if (System.IO.File.Exists(oldPath))
                {
                    System.IO.File.Delete(oldPath);
                }
                string fileName = Guid.NewGuid().ToString() + "_" + request.NewPhoto.FileName;
                string newPath = Path.Combine(_webHostEnvironment.WebRootPath, "img", fileName);

                using (FileStream stream = new(newPath, FileMode.Create))
                {
                    await request.NewPhoto.CopyToAsync(stream);
                }
                slider.Image = fileName;
            }

            await _context.SaveChangesAsync();
            return RedirectToAction(nameof(Index));
        }
        [HttpPost]
        public async Task<IActionResult> Delete(int id)
        {
            Slider? slider = await _context.Sliders.FirstOrDefaultAsync(s => s.Id == id);

            if (slider == null) return NotFound();

            string path = Path.Combine(_webHostEnvironment.WebRootPath, "img", slider.Image);

            if (System.IO.File.Exists(path))
            {
                System.IO.File.Delete(path);
            }

            _context.Sliders.Remove(slider);
            await _context.SaveChangesAsync();

            return RedirectToAction(nameof(Index));
        }
    }
}
