using Fiorello.Services;
using Microsoft.AspNetCore.Mvc;

namespace Fiorello.ViewComponents
{
    public class FooterViewComponent : ViewComponent
    {
        private readonly LayoutService _layoutService;

        public FooterViewComponent(LayoutService layoutService)
        {
            _layoutService = layoutService;
        }

        public async Task<IViewComponentResult> InvokeAsync()
        {
            Dictionary<string, string> setting = await _layoutService.GetAllSetting();
            return View(setting);
        }
    }
}
