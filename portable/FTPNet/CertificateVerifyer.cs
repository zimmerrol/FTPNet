using Org.BouncyCastle.Crypto.Tls;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FTPNet
{
    internal class CertificateVerifyer : ICertificateVerifyer
    {
        internal CertifacteValidationEventHandler IsValidHandler;

        internal CertificateVerifyer(CertifacteValidationEventHandler isValidHandler)
        {
            IsValidHandler = isValidHandler;
        }

        public bool IsValid(Org.BouncyCastle.Asn1.X509.X509CertificateStructure[] certs)
        {
            if (IsValidHandler == null)
                return false;

            return IsValidHandler(certs); ;
        }
    }
}
