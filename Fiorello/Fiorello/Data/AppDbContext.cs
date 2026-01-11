using Fiorello.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Fiorello.Data
{
    public class AppDbContext : IdentityDbContext<AppUser>
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
        {

        }
        public DbSet<Slider> Sliders { get; set; }
        public DbSet<SliderDetail> SlidersDetails { get; set; }
        public DbSet<Product> Products { get; set; }
        public DbSet<ProductImage> ProductImages { get; set; }
        public DbSet<Category> Categories { get; set; }
        public DbSet<Blog> Blogs { get; set; }
        public DbSet<Setting> Settings { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);
            modelBuilder.Entity<Blog>().HasData(
                new Blog
                {
                    Id = 1,
                    Image = "blog-feature-img-1.jpg",
                    Title = "Flower Power",
                    Description = "Class aptent taciti sociosqu ad litora torquent per conubia nostra, per.",
                    CreatedDate = new DateTime(2024, 1, 1),
                },
                new Blog
                {
                    Id = 2,
                    Image = "blog-feature-img-2.jpg",
                    Title = "Spring Collection",
                    Description = "Fresh flowers and new inspirations for the spring season.",
                    CreatedDate = new DateTime(2024, 1, 2),
                },
                new Blog
                {
                    Id = 3,
                    Image = "blog-feature-img-3.jpg",
                    Title = "Local Florists",
                    Description = "This is the first post in our blog. Stay tuned for more updates!",
                    CreatedDate = new DateTime(2024, 1, 3),
                },
                new Blog
                {
                    Id = 4,
                    Image = "blog-feature-img-4.jpg",
                    Title = "Flower Beauty",
                    Description = "Discover the beauty of flowers and how they brighten your life.",
                    CreatedDate = new DateTime(2024, 1, 4),
                }
            );
        }


    }
}
