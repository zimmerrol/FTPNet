using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace FTPNet
{
    public class SimpleFTP
    {
        public string Username { get; set; }
        public string Password { get; set; }
        public string Server { get; set; }

        public FTP UploadFile(string name, byte[] buffer, out bool success, bool binaryMode = false, FTP.SSLMode encryptionMode = FTP.SSLMode.Unencrypted, FTP.SSLValidationMode validationMode = FTP.SSLValidationMode.AcceptAll, FTP nativeFTP = null)
        {
            if (nativeFTP == null)
                nativeFTP = PrepareFTP(encryptionMode, validationMode);

            success = nativeFTP.UploadFile(name, buffer, binaryMode);
            return nativeFTP;
        }

        public FTP UploadFileWithUniqueName(byte[] buffer, out bool success, bool binaryMode = false, FTP.SSLMode encryptionMode = FTP.SSLMode.Unencrypted, FTP.SSLValidationMode validationMode = FTP.SSLValidationMode.AcceptAll, FTP nativeFTP = null)
        {
            if (nativeFTP == null)
                nativeFTP = PrepareFTP(encryptionMode, validationMode);

            if (!nativeFTP.SupportedCommands.Contains("STOU"))
            {
                success = false;
                return nativeFTP;
            }
            //if (encryptionMode == FTP.SSLMode.ExplicitSSL)
            //    ftp.EncryptionMode = encryptionMode;

            success = nativeFTP.UploadFileWithUniqueName(buffer, binaryMode);
            return nativeFTP;
        }

        /// <summary>
        /// Parses the address, connects to the server, logs in, changes the directory and waits for intstruction
        /// </summary>
        /// <returns>Returns the setup client</returns>
        private FTP PrepareFTP(FTP.SSLMode encryptionMode, FTP.SSLValidationMode validationMode)
        {
            FTP ftp = new FTP();
            ftp.Username = Username;
            ftp.Password = Password;

            ftp.CertifacteValidationEvent += ftp_CertifacteValidationEvent;

            if (Server.StartsWith("ftp://"))
                Server = Server.Remove(0, 6);
            if (Server.StartsWith("http://"))
                Server = Server.Remove(0, 7);

            string directory = null;

            if (Server.IndexOf('/') != -1)
            {
                directory = Server.Substring(Server.IndexOf('/'));
                ftp.Server = Server.Remove(Server.IndexOf('/'));
            }
            else
            {
                ftp.Server = Server;
            }

            ftp.ValidationMode = validationMode;

            if (encryptionMode == FTP.SSLMode.ImplicitSSL)
                ftp.EncryptionMode = encryptionMode;

            if (!ftp.Connect())
                throw new SystemException("Could not connect to server.");

            ftp.GetSupportedCommands();

            if (encryptionMode == FTP.SSLMode.ExplicitSSL)
                ftp.EncryptionMode = encryptionMode;

            ftp.Login();

            if (encryptionMode == FTP.SSLMode.ExplicitSSL | encryptionMode == FTP.SSLMode.ImplicitSSL)
            {
                ftp.ChangeProtectionMode(FTP.DataProtectionMode.Private);
            }

            if (directory != null)
                ftp.ChangeWorkingDirectory(directory);

            if (ftp.LoggedIn == false)
                throw new UnauthorizedAccessException("Could not log in.");


            return ftp;
        }

        public event FTP.CertifacteValidationEventHandler CertificateValidationEvent;

        private bool ftp_CertifacteValidationEvent(System.Security.Cryptography.X509Certificates.X509Certificate certificate, System.Security.Cryptography.X509Certificates.X509Chain chain, System.Net.Security.SslPolicyErrors sslPolicyErrors)
        {
            if (CertificateValidationEvent != null)
                return CertificateValidationEvent(certificate, chain, sslPolicyErrors);
            else
                return false;
        }
    }
}
