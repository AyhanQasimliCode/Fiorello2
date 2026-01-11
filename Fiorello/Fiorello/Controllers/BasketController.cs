using Fiorello.Data;
using Fiorello.Models;
using Fiorello.ViewModels;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Newtonsoft.Json;

namespace Fiorello.Controllers
{
    public class BasketController : Controller
    {
        private readonly AppDbContext _context;

        public BasketController(AppDbContext context)
        {
            _context = context;
        }

        public async Task<IActionResult> Index()
        {
            List<BasketVM> basket = new();

            if (Request.Cookies["basket"] != null)
            {
                basket = JsonConvert.DeserializeObject<List<BasketVM>>(Request.Cookies["basket"]);
            }

            List<BasketDetailVM> basketDetails = new();

            foreach (var item in basket)
            {
                Product product = await _context.Products.Include(p => p.ProductImages).Include(p => p.Category).FirstOrDefaultAsync(p => p.Id == item.Id);
                if (product != null)
                {
                    basketDetails.Add(new BasketDetailVM
                    {
                        Id = item.Id,
                        Count = item.Count,
                        Image = product.ProductImages.FirstOrDefault(pi => pi.IsMain)?.Image,
                        Name = product.Name,
                        Category = product.Category.Name,
                        Price = product.Price,
                        TotalPrice = product.Price * item.Count
                    });
                }
            }

            return View(basketDetails);
        }

        [HttpPost]
        public IActionResult Add(int id)
        {
            List<BasketVM> basketVMs;

            if (Request.Cookies["basket"] != null)
            {
                basketVMs = JsonConvert.DeserializeObject<List<BasketVM>>(Request.Cookies["basket"]);
            }
            else
            {
                basketVMs = new();
            }

            BasketVM existBasket = basketVMs.FirstOrDefault(x => x.Id == id);

            if (existBasket != null)
            {
                existBasket.Count++;
            }
            else
            {
                basketVMs.Add(new BasketVM
                {
                    Id = id,
                    Count = 1
                });
            }

            Response.Cookies.Append(
                "basket",
                JsonConvert.SerializeObject(basketVMs),
                new CookieOptions
                {
                    HttpOnly = true,
                    Expires = DateTimeOffset.Now.AddDays(7)
                }
            );

            return Ok(new
            {
                count = basketVMs.Sum(x => x.Count)
            });
        }
    }
}
