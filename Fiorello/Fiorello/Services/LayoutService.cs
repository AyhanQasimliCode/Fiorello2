using Fiorello.Data;

namespace Fiorello.Services
{
    public class LayoutService
    {
        private readonly AppDbContext _context;

        public LayoutService(AppDbContext context)
        {
            _context = context;
        }

        public async Task<Dictionary<string, string>> GetAllSetting()
        {
            Dictionary<string, string> setting = _context.Settings
                .AsEnumerable()
                .ToDictionary(m => m.Key, m => m.Value);

            return setting;
        }

    }
}
