namespace Fiorello.Helpers
{
    public static class Helper
    {
        public static bool CheckFileType(this IFormFile file, string fileType)
        {
            return file.ContentType.Contains(fileType);
        }

        public static bool CheckFileSize(this IFormFile file, int size)
        {
            return file.Length / 1024 > size;
        }

        public static string GenerateFileName(this IFormFile file)
        {
            return Guid.NewGuid().ToString() + "_" + file.FileName;
        }

        public static string GetFilePath(this string root, string folder, string fileName)
        {
            return Path.Combine(root, folder, fileName);
        }

        public static void SaveFile(this IFormFile file, string path)
        {
            using (FileStream fileStream = new(path, FileMode.Create))
            {
                file.CopyTo(fileStream);
            }
        }

        public static void DeleteFile(this string path)
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
    }
}
