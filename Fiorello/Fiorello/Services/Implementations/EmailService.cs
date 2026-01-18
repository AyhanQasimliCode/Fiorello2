using Fiorello.Services.Interfaces;
using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;
using MimeKit.Text;

namespace Fiorello.Services.Implementations
{
    public class EmailService : IEmailService
    {
        private readonly IConfiguration _configuration;

        public EmailService(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public void Send(string to, string subject, string body)
        {
            // create email message
            var email = new MimeMessage();
            email.From.Add(MailboxAddress.Parse(_configuration.GetSection("Smtp:Username").Value));
            email.To.Add(MailboxAddress.Parse($"{to}"));
            email.Subject = subject;
            email.Body = new TextPart(TextFormat.Html) { Text = body };

            // send email
            using var smtp = new SmtpClient();
            smtp.Connect(_configuration.GetSection("Smtp:Server").Value, _configuration.GetValue<int>("Smtp:Port"), SecureSocketOptions.StartTls);
            smtp.Authenticate(_configuration.GetSection("Smtp:Username").Value, _configuration.GetSection("Smtp:Password").Value);
            smtp.Send(email);
            smtp.Disconnect(true);
        }
    }
}
