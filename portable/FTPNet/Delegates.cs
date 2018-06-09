using Org.BouncyCastle.Asn1.X509;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FTPNet
{
    public delegate void CommandSendEventHandler(string command);
    public delegate void AnswerReadEventHandler(string answer);
    public delegate void ConnectedEventHandler();
    public delegate void DisconnectedEventHandler();
    public delegate void LoggedInEventHandler();
    public delegate bool CertifacteValidationEventHandler(X509CertificateStructure[] certificates);
    public delegate void FileDownloadBytesReadDelegate(int readBytes, ulong totalReadBytes, byte[] buffer);
    public delegate void FileDownloadFinished(ulong readBytes);
    public delegate byte[] FileUploadReadInputBytesDelegate(int requestedByteNumber);
    public delegate void FileUploadBytesWrittenDelegate(ulong totalWrittenBytes);
    public delegate void FileUploadFinishedDelegate(bool success);
    public delegate bool IOTaskIsCanceledDelegate();
}
