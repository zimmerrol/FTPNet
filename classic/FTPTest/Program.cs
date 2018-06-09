using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace FTPTest
{
    class Program
    {
        static void Main(string[] args)
        {
            FTPNet.FTP ftp = new FTPNet.FTP();

            ftp.AnswerReadEvent += ftp_AnswerReadEvent;
            ftp.CommandSendEvent += ftp_CommandSendEvent;

            Console.WriteLine("FTPNet test tool");

            Console.WriteLine("Enter server:");

            ftp.Server = Console.ReadLine();
            ftp.Port = 21;
            Console.WriteLine("Enter username:");
            ftp.Username = Console.ReadLine();
            Console.WriteLine("Enter password:");
            ftp.Password = Console.ReadLine();

            //ftp.EncryptionMode = FTPNet.FTP.SSLMode.ImplicitSSL;

            if (!ftp.Connect())
                Main(args);

            ftp.GetSupportedCommands();

            ftp.EncryptionMode = FTPNet.FTP.SSLMode.ExplicitSSL;

            ftp.Login();

            string dir = ftp.PrintWorkingDirectory();
            Console.WriteLine("Current directory: " + dir)

            ftp.ChangeProtectionMode(FTPNet.FTP.DataProtectionMode.Private);

            ftp.EnterPassiveMode();

            //ftp.UploadFile("testtesttest.png", System.IO.File.ReadAllBytes(@"filepath));

            List<FTPNet.IOElement> files = ftp.ListFiles();
            foreach (FTPNet.IOElement item in files)
            {
                Console.WriteLine(item.Name);
            }

            //ftp.UploadFileWithUniqueName(System.IO.File.ReadAllBytes(@"filepath"), true);

            Console.Read();
        }

        static void ftp_CommandSendEvent(string command)
        {
            Console.WriteLine(command);
        }

        static void ftp_AnswerReadEvent(string answer)
        {
            Console.WriteLine(answer);
        }
    }
}
