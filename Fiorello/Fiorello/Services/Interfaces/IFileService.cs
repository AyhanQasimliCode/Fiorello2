namespace Fiorello.Services.Interfaces
{
    public interface IFileService
    {
        Task<string> ReadFile(string path);
    }
}
