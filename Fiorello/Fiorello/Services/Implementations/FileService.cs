
using Fiorello.Services.Interfaces;

namespace Fiorello.Services.Implementations
{
    public class FileService : IFileService
    {
        public async Task<string> ReadFile(string path)
        {
            using StreamReader streamReader = new(path);
            string emailBody = await streamReader.ReadToEndAsync();

            return emailBody;
        }
    }
}
